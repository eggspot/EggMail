using System.Security.Cryptography;
using System.Text;
using Mta.Auth.Arc;
using Mta.Dkim;
using Mta.Dns;
using Mta.Dsn;
using Mta.Host.Ingest;
using Mta.Storage;

namespace Mta.Host.Tests.Inbound;

/// <summary>SPF, DKIM, DMARC and ARC on receipt, with scripted DNS, and what the per-domain DMARC action does with the verdicts (design section 11.5).</summary>
public class InboundVerificationTests : IAsyncLifetime
{
    private InboundFixture _f = null!;

    public async Task InitializeAsync() => _f = await InboundFixture.CreateAsync();

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private async Task SetActionAsync(InboundDmarcAction action, bool globexToo = false)
    {
        await _f.EnableAsync(_f.ExampleOrg, InboundFixture.Acme, action);
        if (globexToo)
        {
            await _f.EnableAsync(_f.ExampleNet, InboundFixture.Globex, action);
        }

        await _f.RefreshConfigAsync();
    }

    private async Task<FakeMta.Reply> DeliverAsync(string message, string to = "support@example.org", string from = "bob@sender.test")
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        return await mta.SendAsync(from, to, message);
    }

    private async Task<InboundMessage> OnlyMessageAsync(Guid tenant = default) => Assert.Single(await _f.StoredAsync(tenant == default ? InboundFixture.Acme : tenant));

    // ------------------------------------------------------------------ the verdicts

    [Fact]
    public async Task An_aligned_spf_pass_gives_a_dmarc_pass_with_the_published_policy()
    {
        _f.PublishSpf("sender.test");
        _f.PublishDmarc("sender.test", "reject");

        Assert.Equal(250, (await DeliverAsync(InboundFixture.Message())).Code);

        InboundMessage m = await OnlyMessageAsync();
        Assert.Equal((InboundVerdict.Pass, InboundVerdict.Pass, "reject"), (m.Auth.Spf, m.Auth.Dmarc, m.Auth.DmarcPolicy));
        string headers = (await _f.RawAsync(m)).Split("\r\n\r\n")[0];
        Assert.Contains("dmarc=pass", headers, StringComparison.Ordinal);
        Assert.Contains("header.from=sender.test", headers, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_aligned_dkim_pass_carries_dmarc_when_spf_fails_and_the_signing_domain_is_recorded()
    {
        _f.PublishSpf("sender.test", authorizeClient: false);
        _f.PublishDmarc("sender.test", "reject");
        string signed = _f.DkimSign(InboundFixture.Message(), "sender.test");

        Assert.Equal(250, (await DeliverAsync(signed)).Code);

        InboundMessage m = await OnlyMessageAsync();
        Assert.Equal((InboundVerdict.Fail, InboundVerdict.Pass, InboundVerdict.Pass), (m.Auth.Spf, m.Auth.Dkim, m.Auth.Dmarc));
        Assert.Equal("sender.test", m.Auth.DkimDomain);
        Assert.Contains("dkim=pass", await _f.RawAsync(m), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_dkim_signature_that_does_not_verify_is_recorded_and_never_rejects_by_itself()
    {
        _f.PublishSpf("sender.test", authorizeClient: false);
        await SetActionAsync(InboundDmarcAction.Reject);
        string tampered = _f.DkimSign(InboundFixture.Message(body: "original"), "sender.test").Replace("original", "tampered", StringComparison.Ordinal);

        Assert.Equal(250, (await DeliverAsync(tampered)).Code);   // no DMARC record: nothing to enforce

        InboundMessage m = await OnlyMessageAsync();
        Assert.Equal((InboundVerdict.Fail, InboundVerdict.Fail, InboundVerdict.None), (m.Auth.Spf, m.Auth.Dkim, m.Auth.Dmarc));
    }

    [Fact]
    public async Task The_helo_name_has_its_own_spf_verdict_and_a_null_sender_is_checked_by_it()
    {
        _f.PublishSpf("mail.sender.test");   // the HELO name's record authorizes the client

        await using FakeMta mta = await _f.ConnectedAsync("mail.sender.test");
        Assert.Equal(250, (await mta.SendAsync("", "support@example.org", InboundFixture.Message(from: "MAILER-DAEMON@mail.sender.test"))).Code);

        InboundMessage m = await OnlyMessageAsync();
        Assert.Equal((InboundVerdict.Pass, InboundVerdict.Pass, "mail.sender.test"), (m.Auth.SpfHelo, m.Auth.Spf, m.Auth.SpfDomain));
        Assert.Contains("smtp.helo=mail.sender.test", await _f.RawAsync(m), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Spf_is_checked_for_the_client_address_of_the_connection_including_a_mapped_ipv6_address()
    {
        _f.Dns.AddTxt("sender.test", "v=spf1 ip4:198.51.100.7 -all");
        _f.ClientIp = System.Net.IPAddress.Parse("::ffff:198.51.100.7");   // an IPv4 client on a dual-stack socket

        Assert.Equal(250, (await DeliverAsync(InboundFixture.Message())).Code);

        InboundMessage m = await OnlyMessageAsync();
        Assert.Equal(InboundVerdict.Pass, m.Auth.Spf);
        Assert.Equal("198.51.100.7", m.RemoteAddress);
    }

    // ------------------------------------------------------------------ the per-domain action

    [Fact]
    public async Task Under_record_only_a_dmarc_failure_is_recorded_and_nothing_else_happens()
    {
        _f.PublishSpf("sender.test", authorizeClient: false);
        _f.PublishDmarc("sender.test", "reject");

        Assert.Equal(250, (await DeliverAsync(InboundFixture.Message())).Code);

        InboundMessage m = await OnlyMessageAsync();
        Assert.Equal((InboundVerdict.Fail, "reject", InboundDmarcDisposition.None), (m.Auth.Dmarc, m.Auth.DmarcPolicy, m.Disposition));
        Assert.DoesNotContain("X-EggMail-Dmarc", await _f.RawAsync(m), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("reject", true)]
    [InlineData("quarantine", true)]
    [InlineData("none", false)]
    public async Task Under_flag_a_failure_of_a_quarantine_or_reject_policy_is_stored_flagged_and_marked(string policy, bool flagged)
    {
        _f.PublishSpf("sender.test", authorizeClient: false);
        _f.PublishDmarc("sender.test", policy);
        await SetActionAsync(InboundDmarcAction.Flag);

        Assert.Equal(250, (await DeliverAsync(InboundFixture.Message())).Code);

        InboundMessage m = await OnlyMessageAsync();
        Assert.Equal(flagged ? InboundDmarcDisposition.Flagged : InboundDmarcDisposition.None, m.Disposition);
        string headers = (await _f.RawAsync(m)).Split("\r\n\r\n")[0];
        Assert.Equal(flagged, headers.Contains("X-EggMail-Dmarc: flagged\r\n", StringComparison.Ordinal));
        Assert.Equal(InboundActionKind.Store, m.ActionKind);   // the route's action still runs: nothing is moved or dropped
    }

    [Fact]
    public async Task Under_reject_a_failure_of_a_reject_policy_is_550_5_7_1_and_a_quarantine_failure_is_flagged()
    {
        _f.PublishSpf("sender.test", authorizeClient: false);
        await SetActionAsync(InboundDmarcAction.Reject);

        _f.PublishDmarc("sender.test", "reject");
        var refused = await DeliverAsync(InboundFixture.Message());
        Assert.Equal((550, "5.7.1"), (refused.Code, refused.Enhanced));
        Assert.Contains("Rejected by the DMARC policy of sender.test", refused.Text);
        Assert.Empty(await _f.StoredAsync(InboundFixture.Acme));

        await using InboundFixture other = await InboundFixture.CreateAsync(beforeStart: f =>
        {
            f.PublishSpf("sender.test", authorizeClient: false);
            f.PublishDmarc("sender.test", "quarantine");
        });
        await other.EnableAsync(other.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await other.RefreshConfigAsync();
        await using FakeMta mta = await other.ConnectedAsync();
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message())).Code);
        Assert.Equal(InboundDmarcDisposition.Flagged, Assert.Single(await other.StoredAsync(InboundFixture.Acme)).Disposition);
    }

    [Fact]
    public async Task A_transaction_is_refused_only_when_every_accepted_recipient_domain_says_reject()
    {
        _f.PublishSpf("sender.test", authorizeClient: false);
        _f.PublishDmarc("sender.test", "reject");
        await SetActionAsync(InboundDmarcAction.Reject);   // Acme: reject; Globex: record_only

        await using (FakeMta mta = await _f.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
            Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
            Assert.Equal(250, (await mta.RcptAsync("anyone@example.net")).Code);
            Assert.Equal(250, (await mta.DataAsync(InboundFixture.Message())).Code);   // nothing is lost for the domain that wanted the message
        }

        InboundMessage acme = await OnlyMessageAsync(InboundFixture.Acme);
        InboundMessage globex = await OnlyMessageAsync(InboundFixture.Globex);
        Assert.Equal(InboundDmarcDisposition.Flagged, acme.Disposition);   // the rejecting domain's copy is stored flagged
        Assert.Equal(InboundDmarcDisposition.None, globex.Disposition);
        Assert.Contains("X-EggMail-Dmarc: flagged", await _f.RawAsync(acme), StringComparison.Ordinal);
        Assert.DoesNotContain("X-EggMail-Dmarc", await _f.RawAsync(globex), StringComparison.Ordinal);

        await SetActionAsync(InboundDmarcAction.Reject, globexToo: true);
        await using (FakeMta mta = await _f.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
            Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
            Assert.Equal(250, (await mta.RcptAsync("anyone@example.net")).Code);
            var reply = await mta.DataAsync(InboundFixture.Message());
            Assert.Equal((550, "5.7.1"), (reply.Code, reply.Enhanced));
        }

        Assert.Single(await _f.StoredAsync(InboundFixture.Acme));   // still only the first transaction's copy
    }

    // ------------------------------------------------------------------ temporary errors

    [Fact]
    public async Task A_temporary_dns_failure_for_the_dmarc_policy_defers_under_reject_and_is_recorded_under_record_only()
    {
        _f.PublishSpf("sender.test", authorizeClient: false);
        _f.Dns.Fail("_dmarc.sender.test", DnsRecordType.TXT);
        await SetActionAsync(InboundDmarcAction.Reject);

        var deferred = await DeliverAsync(InboundFixture.Message());

        Assert.Equal((451, "4.7.0"), (deferred.Code, deferred.Enhanced));
        Assert.Empty(await _f.StoredAsync(InboundFixture.Acme));   // neither accepted unverified nor rejected

        await SetActionAsync(InboundDmarcAction.RecordOnly);
        Assert.Equal(250, (await DeliverAsync(InboundFixture.Message())).Code);
        InboundMessage m = await OnlyMessageAsync();
        Assert.Equal(InboundVerdict.TempError, m.Auth.Dmarc);
        Assert.Equal(InboundDmarcDisposition.None, m.Disposition);
    }

    [Fact]
    public async Task The_temporary_error_defers_only_when_every_accepted_recipient_domain_says_reject()
    {
        _f.Dns.Fail("_dmarc.sender.test", DnsRecordType.TXT);
        await SetActionAsync(InboundDmarcAction.Reject);   // Acme reject, Globex record_only

        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        Assert.Equal(250, (await mta.RcptAsync("anyone@example.net")).Code);

        Assert.Equal(250, (await mta.DataAsync(InboundFixture.Message())).Code);   // a domain that wanted its mail is never delayed by another domain's policy
        Assert.Equal(InboundVerdict.TempError, (await OnlyMessageAsync(InboundFixture.Globex)).Auth.Dmarc);
    }

    [Theory]
    [InlineData("spf")]
    [InlineData("dkim")]
    public async Task A_dmarc_failure_that_depends_on_a_mechanism_that_failed_temporarily_is_deferred_not_rejected(string failing)
    {
        _f.PublishDmarc("sender.test", "reject");
        await SetActionAsync(InboundDmarcAction.Reject);
        string message = InboundFixture.Message();
        if (failing == "spf")
        {
            _f.Dns.Fail("sender.test", DnsRecordType.TXT);   // SPF cannot be evaluated; there is no DKIM signature either
        }
        else
        {
            _f.PublishSpf("sender.test", authorizeClient: false);
            message = _f.DkimSign(message, "sender.test");
            _f.Dns.Fail("s1._domainkey.sender.test", DnsRecordType.TXT);   // the key cannot be fetched: the signature might have been the aligned pass
        }

        var reply = await DeliverAsync(message);

        Assert.Equal((451, "4.7.0"), (reply.Code, reply.Enhanced));
    }

    [Fact]
    public async Task A_verification_that_runs_out_of_time_is_a_temperror_and_defers_under_reject()
    {
        var options = new InboundReceiveOptions { Enabled = true, VerificationTimeout = TimeSpan.FromMilliseconds(250) };
        await using InboundFixture slow = await InboundFixture.CreateAsync(options, wrapDns: _ => new HangingResolver());

        await slow.EnableAsync(slow.ExampleNet, InboundFixture.Globex, InboundDmarcAction.RecordOnly);
        await slow.RefreshConfigAsync();
        await using (FakeMta mta = await slow.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "anyone@example.net", InboundFixture.Message())).Code);
        }

        InboundMessage m = Assert.Single(await slow.StoredAsync(InboundFixture.Globex));
        Assert.Equal((InboundVerdict.TempError, InboundVerdict.None, InboundVerdict.TempError), (m.Auth.Spf, m.Auth.Dkim, m.Auth.Dmarc));   // nothing is signed: DKIM needs no DNS
        Assert.Contains("spf=temperror", await slow.RawAsync(m), StringComparison.Ordinal);

        await slow.EnableAsync(slow.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await slow.RefreshConfigAsync();
        await using (FakeMta mta = await slow.ConnectedAsync())
        {
            var reply = await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message());
            Assert.Equal((451, "4.7.0"), (reply.Code, reply.Enhanced));
        }

        Assert.Empty(await slow.StoredAsync(InboundFixture.Acme));
    }

    private sealed class HangingResolver : IDnsResolver
    {
        public async ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            throw new InvalidOperationException("unreachable");
        }
    }

    // ------------------------------------------------------------------ several From addresses

    [Fact]
    public async Task A_second_from_header_cannot_be_used_to_get_around_a_policy()
    {
        _f.PublishSpf("sender.test");   // the first From domain passes
        _f.PublishDmarc("victim.test", "reject");
        await SetActionAsync(InboundDmarcAction.Reject);
        string message = InboundFixture.Message(extraHeaders: "From: ceo@victim.test\r\n");   // a second From header, naming the protected domain

        var reply = await DeliverAsync(message);

        Assert.Equal((550, "5.7.1"), (reply.Code, reply.Enhanced));
        Assert.Contains("victim.test", reply.Text);
    }

    [Fact]
    public async Task A_message_naming_more_than_three_from_domains_is_refused()
    {
        string message = InboundFixture.Message(extraHeaders: "From: a@one.test\r\nFrom: b@two.test\r\nFrom: c@three.test\r\n");

        var reply = await DeliverAsync(message);

        Assert.Equal((554, "5.6.0"), (reply.Code, reply.Enhanced));
    }

    [Fact]
    public async Task A_message_without_a_usable_from_gets_a_permerror_verdict_and_is_accepted()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", "Subject: no from\r\n\r\nbody\r\n")).Code);

        InboundMessage m = await OnlyMessageAsync();
        Assert.Equal(InboundVerdict.PermError, m.Auth.Dmarc);
        Assert.Contains("dmarc=permerror", await _f.RawAsync(m), StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ ARC

    private string Seal(string message, string sealer, string authenticationResults, string selector = "arc1")
    {
        using RSA key = DkimKeyTools.GenerateRsa2048();
        _f.Dns.AddTxt(DkimKeyTools.GetDnsName(sealer, selector), DkimKeyTools.FormatDnsTxtValue(key));
        using var arc = new ArcSealer(new ArcSealerOptions { Domain = sealer, Selector = selector, Clock = _f.Clock }, key);
        byte[] bytes = Encoding.UTF8.GetBytes(message);
        ArcChainResult chain = new ArcValidator(_f.Dns).ValidateAsync(bytes).AsTask().GetAwaiter().GetResult();
        ArcSealResult sealedSet = arc.Seal(bytes, authenticationResults, chain);
        Assert.True(sealedSet.IsSealed, sealedSet.NotSealedReason);
        return sealedSet.Headers + message;
    }

    [Fact]
    public async Task A_valid_arc_chain_is_recorded_and_changes_nothing_unless_its_last_sealer_is_trusted()
    {
        _f.PublishSpf("sender.test", authorizeClient: false);
        _f.PublishDmarc("sender.test", "reject");
        await SetActionAsync(InboundDmarcAction.Reject);
        string sealedMessage = Seal(InboundFixture.Message(), "forwarder.test", "forwarder.test; dmarc=pass header.from=sender.test");

        var untrusted = await DeliverAsync(sealedMessage);

        Assert.Equal(550, untrusted.Code);   // the chain only proves that its sealers sealed it
    }

    [Fact]
    public async Task A_trusted_last_sealer_that_vouches_for_the_from_domain_turns_a_dmarc_failure_into_a_pass_for_the_decision_only()
    {
        var options = new InboundReceiveOptions { Enabled = true, TrustedArcSealers = ["forwarder.test"] };
        await using InboundFixture f = await InboundFixture.CreateAsync(options);
        f.PublishSpf("sender.test", authorizeClient: false);
        f.PublishDmarc("sender.test", "reject");
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await f.RefreshConfigAsync();
        using RSA key = DkimKeyTools.GenerateRsa2048();
        f.Dns.AddTxt(DkimKeyTools.GetDnsName("forwarder.test", "arc1"), DkimKeyTools.FormatDnsTxtValue(key));
        using var arc = new ArcSealer(new ArcSealerOptions { Domain = "forwarder.test", Selector = "arc1", Clock = f.Clock }, key);
        string message = InboundFixture.Message();
        byte[] bytes = Encoding.UTF8.GetBytes(message);
        ArcChainResult none = await new ArcValidator(f.Dns).ValidateAsync(bytes);
        string sealedMessage = arc.Seal(bytes, "forwarder.test; dmarc=pass header.from=sender.test", none).Headers + message;

        await using FakeMta mta = await f.ConnectedAsync();
        var reply = await mta.SendAsync("bob@sender.test", "support@example.org", sealedMessage);

        Assert.Equal(250, reply.Code);
        InboundMessage m = Assert.Single(await f.StoredAsync(InboundFixture.Acme));
        Assert.Equal((InboundVerdict.Fail, InboundVerdict.Pass, InboundDmarcDisposition.None), (m.Auth.Dmarc, m.Auth.Arc, m.Disposition));   // the original verdict stays recorded
        Assert.Contains("arc=pass", await f.RawAsync(m), StringComparison.Ordinal);

        // A trusted sealer whose own results do not show a pass for the From domain does not vouch for it.
        string unvouched = arc.Seal(bytes, "forwarder.test; dmarc=fail header.from=sender.test", none).Headers + message;
        await using FakeMta again = await f.ConnectedAsync();
        Assert.Equal(550, (await again.SendAsync("bob@sender.test", "support@example.org", unvouched)).Code);
    }

    [Fact]
    public async Task A_trusted_sealer_in_the_middle_of_the_chain_does_not_count_only_the_last_seal_does()
    {
        var options = new InboundReceiveOptions { Enabled = true, TrustedArcSealers = ["first.test"] };
        await using InboundFixture f = await InboundFixture.CreateAsync(options);
        f.PublishSpf("sender.test", authorizeClient: false);
        f.PublishDmarc("sender.test", "reject");
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await f.RefreshConfigAsync();

        string SealWith(string message, string sealer, string results)
        {
            using RSA key = DkimKeyTools.GenerateRsa2048();
            f.Dns.AddTxt(DkimKeyTools.GetDnsName(sealer, "arc1"), DkimKeyTools.FormatDnsTxtValue(key));
            using var arc = new ArcSealer(new ArcSealerOptions { Domain = sealer, Selector = "arc1", Clock = f.Clock }, key);
            byte[] bytes = Encoding.UTF8.GetBytes(message);
            ArcSealResult result = arc.Seal(bytes, results, new ArcValidator(f.Dns).ValidateAsync(bytes).AsTask().GetAwaiter().GetResult());
            Assert.True(result.IsSealed, result.NotSealedReason);
            return result.Headers + message;
        }

        string once = SealWith(InboundFixture.Message(), "first.test", "first.test; dmarc=pass header.from=sender.test");
        string twice = SealWith(once, "second.test", "second.test; dmarc=pass header.from=sender.test");

        await using FakeMta mta = await f.ConnectedAsync();
        var reply = await mta.SendAsync("bob@sender.test", "support@example.org", twice);

        Assert.Equal(550, reply.Code);   // the last seal is second.test, which nobody trusts
    }

    [Fact]
    public async Task A_broken_arc_chain_is_recorded_as_fail_and_a_chain_of_more_than_ten_sets_is_too_long()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        string headers = string.Concat(Enumerable.Range(1, 11).Select(i =>
            $"ARC-Seal: i={i}; a=rsa-sha256; cv={(i == 1 ? "none" : "pass")}; d=hop{i}.test; s=s; t=1; b=YWJj\r\n" +
            $"ARC-Message-Signature: i={i}; a=rsa-sha256; c=relaxed/relaxed; d=hop{i}.test; s=s; h=from; bh=YWJj; b=YWJj\r\n" +
            $"ARC-Authentication-Results: i={i}; hop{i}.test; spf=pass\r\n"));

        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", headers + InboundFixture.Message())).Code);

        InboundMessage m = await OnlyMessageAsync();
        Assert.Equal(InboundVerdict.Fail, m.Auth.Arc);
        string stamped = (await _f.RawAsync(m)).Split("\r\n\r\n")[0];
        Assert.Contains("arc=fail", stamped, StringComparison.Ordinal);
        Assert.Contains("too_long", stamped, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ what the sender cannot forge

    [Fact]
    public async Task An_authentication_results_header_claiming_our_identity_is_removed_and_a_foreign_one_stays()
    {
        string forged = "Authentication-Results: mx.egg.test; dkim=pass header.d=sender.test; spf=pass\r\n" +
                        "Authentication-Results: MX.EGG.TEST.; dmarc=pass\r\n" +
                        "Authentication-Results : mx.egg.test; dmarc=pass\r\n" +
                        "Authentication-Results: upstream.example; dkim=pass header.d=elsewhere.test\r\n";

        Assert.Equal(250, (await DeliverAsync(InboundFixture.Message(extraHeaders: forged))).Code);

        string headers = (await _f.RawAsync(await OnlyMessageAsync())).Split("\r\n\r\n")[0].Replace("\r\n ", " ", StringComparison.Ordinal).Replace("\r\n\t", " ", StringComparison.Ordinal);   // unfolded
        string[] results = headers.Split("\r\n").Where(l => l.StartsWith("Authentication-Results", StringComparison.OrdinalIgnoreCase)).ToArray();
        Assert.Equal(2, results.Length);
        Assert.StartsWith("Authentication-Results: mx.egg.test;", results[0]);   // ours, first
        Assert.Contains("dkim=none", results[0], StringComparison.Ordinal);
        Assert.StartsWith("Authentication-Results: upstream.example;", results[1]);
        Assert.DoesNotContain("dmarc=pass", headers, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_x_eggmail_namespace_is_ours_and_a_forged_flag_or_reputation_header_is_removed()
    {
        string forged = "X-EggMail-Dmarc: flagged\r\nX-EggMail-Reputation: dnsbl=clean.example\r\nx-eggmail-whatever: 1\r\nX-Other: kept\r\n";

        Assert.Equal(250, (await DeliverAsync(InboundFixture.Message(extraHeaders: forged))).Code);

        string headers = (await _f.RawAsync(await OnlyMessageAsync())).Split("\r\n\r\n")[0];
        Assert.DoesNotContain("X-EggMail", headers, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("X-Other: kept", headers, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_hop_marker_is_kept_only_when_its_signature_verifies_for_the_body_and_only_the_highest_survives()
    {
        string body = "Hop body.";
        string bodyHash = ForwardHopMarker.BodyHash(Encoding.UTF8.GetBytes(body + "\r\n"));
        var hops = new ForwardHopMarker(_f.Verp);
        string two = $"X-EggMail-Hops: {hops.CreateValue(2, bodyHash)}\r\n";
        string one = $"X-EggMail-Hops: {hops.CreateValue(1, bodyHash)}\r\n";
        string forged = "X-EggMail-Hops: 9; 0123456789abcdef\r\n";
        string elsewhere = $"X-EggMail-Hops: {hops.CreateValue(1, ForwardHopMarker.BodyHash("another body"u8))}\r\n";   // valid for a different body: the body changed on the way

        Assert.Equal(250, (await DeliverAsync(InboundFixture.Message(body: body, extraHeaders: one + forged + two + elsewhere))).Code);

        string headers = (await _f.RawAsync(await OnlyMessageAsync())).Split("\r\n\r\n")[0];
        string[] markers = headers.Split("\r\n").Where(l => l.StartsWith("X-EggMail-Hops", StringComparison.OrdinalIgnoreCase)).ToArray();
        Assert.Equal([two.TrimEnd()], markers);
    }

    [Fact]
    public async Task A_header_block_the_parser_cannot_record_in_full_is_refused_rather_than_trusted()
    {
        string filler = string.Concat(Enumerable.Range(0, 1100).Select(i => $"X-Filler-{i}: x\r\n"));
        var reply = await DeliverAsync(InboundFixture.Message(extraHeaders: filler + "Authentication-Results: mx.egg.test; dmarc=pass\r\n"));

        Assert.Equal((554, "5.6.0"), (reply.Code, reply.Enhanced));
    }

    [Fact]
    public async Task More_than_25_received_headers_is_554_5_4_6_and_25_is_fine()
    {
        string Hops(int n) => string.Concat(Enumerable.Range(0, n).Select(i => $"Received: from hop{i}.test by hop{i + 1}.test; Fri, 16 Oct 2026 12:00:00 +0000\r\n"));

        Assert.Equal(250, (await DeliverAsync(InboundFixture.Message(extraHeaders: Hops(24)))).Code);   // the one we add makes 25
        Assert.Equal(250, (await DeliverAsync(InboundFixture.Message(extraHeaders: Hops(25)))).Code);   // 25 received from the sender, plus ours: the limit is on what arrives
        var reply = await DeliverAsync(InboundFixture.Message(extraHeaders: Hops(26)));

        Assert.Equal((554, "5.4.6"), (reply.Code, reply.Enhanced));
        Assert.Equal(2, (await _f.StoredAsync(InboundFixture.Acme)).Count);
    }
}
