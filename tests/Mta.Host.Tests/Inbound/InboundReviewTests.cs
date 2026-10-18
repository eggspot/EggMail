using System.Net;
using System.Text;
using Mta.Core;
using Mta.Dkim;
using Mta.Dns;
using Mta.Dsn;
using Mta.Host.Ingest;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;
using Mta.Storage;
using System.Security.Cryptography;
using Mta.Auth.Arc;

namespace Mta.Host.Tests.Inbound;

/// <summary>The findings of the independent review of the receive path, each as a test: forged headers, temporary failures that are not the From domain's, an unusable From, anonymous senders and shared budgets, SPF and DNS limits.</summary>
public class InboundReviewTests
{
    private static string Raw(string headers, string body = "body") => headers + "\r\n" + body + "\r\n";

    private static async Task<string> HeaderBlockOfOnlyMessageAsync(InboundFixture f, Guid tenant) =>
        (await f.RawAsync(Assert.Single(await f.StoredAsync(tenant)))).Split("\r\n\r\n")[0];

    // ------------------------------------------------------------------ 1. forging our header

    [Theory]
    [InlineData(" ; dkim=pass header.d=bank.test; dmarc=pass header.from=bank.test")]
    [InlineData("\t; dkim=pass header.d=bank.test; dmarc=pass header.from=bank.test")]
    public async Task A_message_that_starts_with_white_space_is_refused_so_its_first_line_cannot_continue_our_authentication_results(string firstLine)
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        await using FakeMta mta = await f.ConnectedAsync();

        var reply = await mta.SendAsync("bob@sender.test", "support@example.org", firstLine + "\r\nFrom: bob@sender.test\r\nSubject: x\r\n\r\nbody\r\n");

        Assert.Equal((554, "5.6.0"), (reply.Code, reply.Enhanced));
        Assert.Empty(await f.StoredAsync(InboundFixture.Acme));
    }

    [Fact]
    public async Task Fields_named_like_ours_with_control_characters_or_without_a_colon_are_removed()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        await using FakeMta mta = await f.ConnectedAsync();
        string forged = "X-EggMail-Dmarc\u000B: flagged\r\nAuthentication-Results\u000B: mx.egg.test; dkim=pass header.d=bank.test\r\nX-EggMail-Dmarc flagged\r\nX-Egg\u000CMail-Reputation: dnsbl=clean\r\nAuthentication-Results mx.egg.test; dmarc=pass\r\n";

        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message(extraHeaders: forged))).Code);

        string headers = await HeaderBlockOfOnlyMessageAsync(f, InboundFixture.Acme);
        Assert.DoesNotContain("eggmail", headers, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("bank.test", headers, StringComparison.Ordinal);
        Assert.Single(headers.Split("\r\n"), l => l.StartsWith("Authentication-Results", StringComparison.OrdinalIgnoreCase));   // only ours
    }

    [Fact]
    public void The_stored_copy_cannot_be_composed_from_a_prefix_that_stops_in_the_middle_of_a_line()
    {
        InboundHeaderAnalysis analysis = InboundHeaderAnalysis.Analyze(Encoding.ASCII.GetBytes("From: a@sender.test\r\n\r\nbody\r\n"), ["mx.egg.test"], null);

        Assert.Throws<ArgumentException>(() => analysis.Compose("Authentication-Results: x"u8));
        Assert.Throws<ArgumentException>(() => analysis.Compose(default));
        Assert.NotEmpty(analysis.Compose("X: 1\r\n"u8));
    }

    // ------------------------------------------------------------------ 2. temporary failures count only when they could matter

    [Fact]
    public async Task A_temporary_spf_failure_of_an_unrelated_mail_from_domain_does_not_keep_a_failure_from_being_counted()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        f.PublishDmarc("victim.test", "reject");
        f.Dns.Fail("attacker.test", DnsRecordType.TXT);   // the attacker's own domain "fails" its SPF lookup
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Flag);
        await f.RefreshConfigAsync();
        await using FakeMta mta = await f.ConnectedAsync();

        Assert.Equal(250, (await mta.SendAsync("x@attacker.test", "support@example.org", InboundFixture.Message(from: "ceo@victim.test"))).Code);

        InboundMessage m = Assert.Single(await f.StoredAsync(InboundFixture.Acme));
        Assert.Equal((InboundVerdict.Fail, InboundDmarcDisposition.Flagged), (m.Auth.Dmarc, m.Disposition));   // not "temperror, nothing flagged"
    }

    [Fact]
    public async Task The_same_message_is_refused_under_reject_and_a_temporary_failure_of_an_aligned_domain_still_defers()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        f.PublishDmarc("victim.test", "reject");
        f.Dns.Fail("attacker.test", DnsRecordType.TXT);
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await f.RefreshConfigAsync();

        await using (FakeMta mta = await f.ConnectedAsync())
        {
            var refused = await mta.SendAsync("x@attacker.test", "support@example.org", InboundFixture.Message(from: "ceo@victim.test"));
            Assert.Equal((550, "5.7.1"), (refused.Code, refused.Enhanced));
        }

        f.Dns.Fail("victim.test", DnsRecordType.TXT);   // now the SPF record of the From domain itself cannot be read (the mail from is aligned)
        await using (FakeMta mta = await f.ConnectedAsync())
        {
            var deferred = await mta.SendAsync("x@victim.test", "support@example.org", InboundFixture.Message(from: "ceo@victim.test"));
            Assert.Equal((451, "4.7.0"), (deferred.Code, deferred.Enhanced));
        }
    }

    [Fact]
    public async Task A_dkim_key_that_cannot_be_fetched_matters_only_when_the_signature_is_aligned()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        f.PublishDmarc("victim.test", "reject");
        f.PublishSpf("elsewhere.test", authorizeClient: false);
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await f.RefreshConfigAsync();

        string unaligned = f.DkimSign(InboundFixture.Message(from: "ceo@victim.test"), "other.test");
        f.Dns.Fail("s1._domainkey.other.test", DnsRecordType.TXT);
        await using (FakeMta mta = await f.ConnectedAsync())
        {
            Assert.Equal(550, (await mta.SendAsync("x@elsewhere.test", "support@example.org", unaligned)).Code);   // the failing key is not the From domain's
        }

        string aligned = f.DkimSign(InboundFixture.Message(from: "ceo@victim.test"), "victim.test", "s2");
        f.Dns.Fail("s2._domainkey.victim.test", DnsRecordType.TXT);
        await using (FakeMta mta = await f.ConnectedAsync())
        {
            Assert.Equal(451, (await mta.SendAsync("x@elsewhere.test", "support@example.org", aligned)).Code);
        }
    }

    [Fact]
    public async Task A_temporary_error_of_another_from_domain_is_not_hidden_by_a_failure_under_a_policy_of_none()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        f.PublishDmarc("first.test", "none");
        f.Dns.Fail("_dmarc.second.test", DnsRecordType.TXT);
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await f.RefreshConfigAsync();
        await using FakeMta mta = await f.ConnectedAsync();

        var reply = await mta.SendAsync("x@attacker.test", "support@example.org", InboundFixture.Message(from: "a@first.test", extraHeaders: "From: b@second.test\r\n"));

        Assert.Equal((451, "4.7.0"), (reply.Code, reply.Enhanced));
    }

    /// <summary>Hangs only the lookups of the given names, so one stage runs out of time while the others finish.</summary>
    private sealed class SelectiveHang(StaticDnsResolver inner, Func<string, bool> hang) : IDnsResolver
    {
        public async ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
        {
            if (hang(name))
            {
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }

            return await inner.QueryAsync(name, type, cancellationToken);
        }
    }

    private static InboundReceiveOptions Quick() => new() { Enabled = true, VerificationTimeout = TimeSpan.FromMilliseconds(300) };

    [Fact]
    public async Task A_dkim_stage_that_runs_out_of_time_defers_only_when_the_message_has_an_aligned_signature()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync(Quick(), wrapDns: dns => new SelectiveHang(dns, n => n.Contains("_domainkey", StringComparison.Ordinal)));
        f.PublishDmarc("victim.test", "reject");
        f.PublishSpf("elsewhere.test", authorizeClient: false);
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await f.RefreshConfigAsync();

        string unaligned = f.DkimSign(InboundFixture.Message(from: "ceo@victim.test"), "other.test");
        string aligned = f.DkimSign(InboundFixture.Message(from: "ceo@victim.test"), "victim.test", "s2");

        await using (FakeMta mta = await f.ConnectedAsync())
        {
            Assert.Equal(550, (await mta.SendAsync("x@elsewhere.test", "support@example.org", unaligned)).Code);   // the stage timed out, but nothing it was reading could have helped
        }

        await using (FakeMta mta = await f.ConnectedAsync())
        {
            Assert.Equal(451, (await mta.SendAsync("x@elsewhere.test", "support@example.org", aligned)).Code);
        }
    }

    [Fact]
    public async Task An_arc_stage_that_runs_out_of_time_is_a_temperror_of_arc_and_does_not_defer_a_message_whose_spf_passed()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync(Quick(), wrapDns: dns => new SelectiveHang(dns, n => n.Contains("arc1._domainkey", StringComparison.Ordinal)));
        f.PublishSpf("sender.test");
        f.PublishDmarc("sender.test", "reject");
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await f.RefreshConfigAsync();
        string message = InboundFixture.Message();
        using RSA key = DkimKeyTools.GenerateRsa2048();
        using var sealer = new ArcSealer(new ArcSealerOptions { Domain = "hop.test", Selector = "arc1", Clock = f.Clock }, key);
        byte[] bytes = Encoding.UTF8.GetBytes(message);
        string sealedMessage = sealer.Seal(bytes, "hop.test; spf=pass", new ArcChainResult(ArcChainStatus.None, "none")).Headers + message;
        await using FakeMta mta = await f.ConnectedAsync();

        var reply = await mta.SendAsync("bob@sender.test", "support@example.org", sealedMessage);

        Assert.Equal(250, reply.Code);
        InboundMessage m = Assert.Single(await f.StoredAsync(InboundFixture.Acme));
        Assert.Equal((InboundVerdict.TempError, InboundVerdict.Pass), (m.Auth.Arc, m.Auth.Dmarc));
        Assert.Contains("arc=temperror", await f.RawAsync(m), StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ 3. no usable From

    public static TheoryData<string> UnusableFromHeaders() => new()
    {
        "From: ceo@victim.test <x\r\n",
        "From: ceo (at) victim.test\r\n",
        "From:\r\n",
        "From: undisclosed-recipients:;\r\n",
        "From: x@evil.test, victim@bank..test\r\n",
        "",
    };

    private static string WithoutFrom(string fromHeader) =>
        $"{fromHeader}To: support@example.org\r\nSubject: s\r\nDate: Fri, 16 Oct 2026 12:00:00 +0000\r\nMessage-ID: <{Guid.NewGuid():N}@sender.test>\r\n\r\nbody\r\n";

    [Theory]
    [MemberData(nameof(UnusableFromHeaders))]
    public async Task A_message_without_a_usable_from_is_a_dmarc_failure_for_the_action_table(string fromHeader)
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await f.RefreshConfigAsync();
        string message = WithoutFrom(fromHeader);

        await using (FakeMta mta = await f.ConnectedAsync())
        {
            var refused = await mta.SendAsync("x@sender.test", "support@example.org", message);   // every accepted recipient says reject
            Assert.Equal((554, "5.6.0"), (refused.Code, refused.Enhanced));
        }

        await using (FakeMta mta = await f.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.MailFromAsync("x@sender.test")).Code);
            Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
            Assert.Equal(250, (await mta.RcptAsync("anyone@example.net")).Code);   // Globex records only
            Assert.Equal(250, (await mta.DataAsync(message)).Code);
        }

        Assert.Equal(InboundDmarcDisposition.Flagged, Assert.Single(await f.StoredAsync(InboundFixture.Acme)).Disposition);   // flagged where the domain asked for it
        Assert.Equal(InboundDmarcDisposition.None, Assert.Single(await f.StoredAsync(InboundFixture.Globex)).Disposition);
    }

    // ------------------------------------------------------------------ 4. anonymous senders and shared budgets

    [Fact]
    public async Task A_bounce_or_an_srs_bounce_is_limited_to_one_mebibyte()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        string bounce = $"{f.Verp.CreateLocalPart(InboundFixture.Acme, f.ExampleOrg, f.Clock.Now, "dest.example")}@{InboundFixture.BounceDomain}";
        string srs = new SrsCodec(f.Verp).CreateLocalPart("sender.test", "bob", f.Clock.Now) + "@example.org";
        string big = "Subject: x\r\n\r\n" + new string('x', 1_300_000) + "\r\n";

        foreach (string recipient in new[] { bounce, srs })
        {
            await using FakeMta mta = await f.ConnectedAsync();
            Assert.Equal(552, (await mta.SendAsync("", recipient, big)).Code);
            Assert.Equal(250, (await mta.SendAsync("", recipient, "Subject: x\r\n\r\nsmall\r\n")).Code);   // and the connection goes on
        }
    }

    [Fact]
    public async Task A_message_whose_copies_do_not_fit_the_listeners_memory_share_is_refused_with_452_before_they_are_made()
    {
        // The listener may have 700 KB in flight; the message buffer is counted, and so are the copies the handler makes of it.
        var options = new InboundReceiveOptions { Enabled = true, MaxInFlightBytes = 700_000 };
        await using InboundFixture f = await InboundFixture.CreateAsync(options, listenerMaxInFlightBytes: 700_000);
        await using FakeMta mta = await f.ConnectedAsync();

        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", "Subject: s\r\nFrom: bob@sender.test\r\n\r\n" + new string('x', 50_000) + "\r\n")).Code);
        var refused = await mta.SendAsync("bob@sender.test", "support@example.org", "Subject: s\r\nFrom: bob@sender.test\r\n\r\n" + new string('x', 330_000) + "\r\n");

        Assert.Equal(452, refused.Code);
        Assert.Single(await f.StoredAsync(InboundFixture.Acme));
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", "Subject: s\r\nFrom: bob@sender.test\r\n\r\nsmall again\r\n")).Code);   // everything was given back
    }

    // ------------------------------------------------------------------ 12/13. NAT and internal clients, queries

    [Fact]
    public async Task Spf_is_not_checked_for_an_internal_client_address_unless_the_operator_asks_for_it()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        f.Dns.AddTxt("sender.test", "v=spf1 ip4:10.1.2.3 -all");
        f.ClientIp = IPAddress.Parse("10.1.2.3");
        await using (FakeMta mta = await f.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message())).Code);
        }

        InboundMessage m = Assert.Single(await f.StoredAsync(InboundFixture.Acme));
        Assert.Equal((InboundVerdict.None, InboundVerdict.None), (m.Auth.Spf, m.Auth.SpfHelo));
        Assert.Equal(0, f.Dns.GetQueryCount("sender.test", DnsRecordType.TXT));

        await using InboundFixture lab = await InboundFixture.CreateAsync(new InboundReceiveOptions { Enabled = true, CheckSpfForInternalClients = true });
        lab.Dns.AddTxt("sender.test", "v=spf1 ip4:10.1.2.3 -all");
        lab.ClientIp = IPAddress.Parse("10.1.2.3");
        await using (FakeMta mta = await lab.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message())).Code);
        }

        Assert.Equal(InboundVerdict.Pass, Assert.Single(await lab.StoredAsync(InboundFixture.Acme)).Auth.Spf);
    }

    [Fact]
    public async Task An_internal_client_is_not_looked_up_in_a_blocklist()
    {
        var options = new InboundReceiveOptions { Enabled = true, DnsblZones = ["bl.example"], DnsblReject = true };
        await using InboundFixture f = await InboundFixture.CreateAsync(options, beforeStart: x => x.Dns.AddA("3.2.1.10.bl.example", "127.0.0.2"));
        f.ClientIp = IPAddress.Parse("10.1.2.3");
        await using FakeMta mta = await f.ConnectedAsync();

        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message())).Code);
        Assert.Equal(0, f.Dns.GetQueryCount("3.2.1.10.bl.example", DnsRecordType.A));
    }

    [Fact]
    public async Task The_warning_about_internal_client_addresses_is_written_once_for_the_listener_and_only_off_loopback()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        SmtpSessionContext Session(string remote, string local) => new() { RemoteEndPoint = new IPEndPoint(IPAddress.Parse(remote), 40000), LocalEndPoint = new IPEndPoint(IPAddress.Parse(local), 25), ListenerName = "bounce", Role = ListenerRole.Inbound };
        f.ClientIp = IPAddress.Parse("172.17.0.1");   // the Docker bridge gateway

        await f.Receiver.OnConnectedAsync(Session("172.17.0.1", "127.0.0.1"));   // a loopback listener: nothing to say
        Assert.DoesNotContain(f.LogLines, l => l.Contains("look internal", StringComparison.Ordinal));

        await f.Receiver.OnConnectedAsync(Session("172.17.0.1", "172.17.0.2"));
        await f.Receiver.OnConnectedAsync(Session("172.17.0.1", "172.17.0.2"));

        Assert.Single(f.LogLines, l => l.Contains("look internal", StringComparison.Ordinal) && l.StartsWith("Warning", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_hostile_spf_record_cannot_make_one_message_cost_more_than_the_query_budget()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        var mechanisms = new StringBuilder("v=spf1");
        for (int i = 0; i < 10; i++)
        {
            mechanisms.Append(" mx:m").Append(i).Append(".test");
            for (int k = 0; k < 10; k++)
            {
                f.Dns.AddMx($"m{i}.test", 10, $"h{i}-{k}.test").AddA($"h{i}-{k}.test", "192.0.2.1");
            }
        }

        f.Dns.AddTxt("sender.test", mechanisms + " -all");
        f.Dns.AddTxt("mail.sender.test", mechanisms + " -all");   // the HELO name gets the same
        await using FakeMta mta = await f.ConnectedAsync("mail.sender.test");

        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message())).Code);

        Assert.True(f.Dns.QueryCount <= InboundVerifier.MaxQueriesPerMessage, $"{f.Dns.QueryCount} queries for one message");
        Assert.NotEqual(InboundVerdict.Pass, Assert.Single(await f.StoredAsync(InboundFixture.Acme)).Auth.Spf);   // out of budget is a temporary error, never a pass
    }

    [Fact]
    public async Task Unknown_return_path_looking_names_cost_a_bounded_number_of_storage_lookups_and_a_valid_token_gets_a_temporary_failure_when_they_run_out()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        string token = f.Verp.CreateLocalPart(InboundFixture.Acme, f.ExampleOrg, f.Clock.Now, "dest.example");
        IBounceNamespace bounces = f.Handler;
        int refusedForNow = 0;

        for (int i = 0; i < 300; i++)
        {
            EmailAddress.TryParse($"{token}@bounce.unknown{i}.example", allowUtf8: false, out EmailAddress address);
            try
            {
                Assert.Equal(BounceRecipientClass.NotBounce, await bounces.ClassifyAsync(address, default));
            }
            catch (StorageUnavailableException)
            {
                refusedForNow++;
            }
        }

        Assert.True(refusedForNow > 0);
        EmailAddress.TryParse("b+invalid@bounce.another.example", allowUtf8: false, out EmailAddress noToken);
        Assert.Equal(BounceRecipientClass.NotBounce, await bounces.ClassifyAsync(noToken, default));   // without a token the answer is "not ours" at once, not an error
    }

    // ------------------------------------------------------------------ surviving mutations

    [Fact]
    public async Task The_size_limit_is_inclusive_at_data_and_exceeded_by_one_byte_is_refused()
    {
        var options = new InboundReceiveOptions { Enabled = true, Ceilings = new InboundCeilings(2000, 600, 60, 0, 0, 0) };
        await using InboundFixture f = await InboundFixture.CreateAsync(options);
        string Exactly(int total)
        {
            string head = "Subject: s\r\nFrom: bob@sender.test\r\n\r\n";
            return head + new string('x', total - head.Length - 2) + "\r\n";
        }

        await using FakeMta mta = await f.ConnectedAsync();
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", Exactly(2000))).Code);
        Assert.Equal(552, (await mta.SendAsync("bob@sender.test", "support@example.org", Exactly(2001))).Code);
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test", "SIZE=2000")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
    }

    [Fact]
    public async Task A_blocklist_answer_outside_127_8_is_an_error_and_not_a_hit()
    {
        var options = new InboundReceiveOptions { Enabled = true, DnsblZones = ["bl.example"], DnsblReject = true };
        await using InboundFixture f = await InboundFixture.CreateAsync(options, beforeStart: x => x.Dns.AddA("9.113.0.203.bl.example", "10.0.0.1"));
        await using FakeMta mta = await f.ConnectedAsync();

        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message())).Code);
    }

    [Fact]
    public async Task The_handler_never_authenticates_on_a_port_25_role_even_when_asked_directly()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        await f.Storage.Config.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), InboundFixture.Acme, "acme-user", Mta.Host.Security.PasswordHasher.Hash("s3cret", 2000), true, DateTimeOffset.UtcNow), default);
        SmtpSessionContext Session(ListenerRole role) => new() { RemoteEndPoint = new IPEndPoint(IPAddress.Loopback, 40000), LocalEndPoint = new IPEndPoint(IPAddress.Loopback, 25), ListenerName = "x", Role = role };

        Assert.False((await f.Handler.AuthenticateAsync(Session(ListenerRole.Inbound), "", "acme-user", "s3cret", default)).Success);
        Assert.False((await f.Handler.AuthenticateAsync(Session(ListenerRole.Bounce), "", "acme-user", "s3cret", default)).Success);
        Assert.True((await f.Handler.AuthenticateAsync(Session(ListenerRole.Submission), "", "acme-user", "s3cret", default)).Success);   // the guard is the role, not a broken password path
    }

    [Fact]
    public async Task The_arc_override_does_not_apply_when_the_message_names_several_from_domains()
    {
        var options = new InboundReceiveOptions { Enabled = true, TrustedArcSealers = ["forwarder.test"] };
        await using InboundFixture f = await InboundFixture.CreateAsync(options);
        f.PublishSpf("sender.test", authorizeClient: false);
        f.PublishDmarc("sender.test", "reject");
        f.PublishDmarc("other.test", "reject");
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await f.RefreshConfigAsync();
        using RSA key = DkimKeyTools.GenerateRsa2048();
        f.Dns.AddTxt(DkimKeyTools.GetDnsName("forwarder.test", "arc1"), DkimKeyTools.FormatDnsTxtValue(key));
        using var sealer = new ArcSealer(new ArcSealerOptions { Domain = "forwarder.test", Selector = "arc1", Clock = f.Clock }, key);
        string message = InboundFixture.Message(from: "a@sender.test", extraHeaders: "From: b@other.test\r\n");
        byte[] bytes = Encoding.UTF8.GetBytes(message);
        string sealedMessage = sealer.Seal(bytes, "forwarder.test; dmarc=pass header.from=sender.test", new ArcChainResult(ArcChainStatus.None, "none")).Headers + message;
        await using FakeMta mta = await f.ConnectedAsync();

        Assert.Equal(550, (await mta.SendAsync("bob@sender.test", "support@example.org", sealedMessage)).Code);
    }

    [Fact]
    public async Task A_trusted_sealers_dmarc_pass_for_another_header_from_does_not_vouch_for_this_one()
    {
        var options = new InboundReceiveOptions { Enabled = true, TrustedArcSealers = ["forwarder.test"] };
        await using InboundFixture f = await InboundFixture.CreateAsync(options);
        f.PublishSpf("sender.test", authorizeClient: false);
        f.PublishDmarc("sender.test", "reject");
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await f.RefreshConfigAsync();
        using RSA key = DkimKeyTools.GenerateRsa2048();
        f.Dns.AddTxt(DkimKeyTools.GetDnsName("forwarder.test", "arc1"), DkimKeyTools.FormatDnsTxtValue(key));
        using var sealer = new ArcSealer(new ArcSealerOptions { Domain = "forwarder.test", Selector = "arc1", Clock = f.Clock }, key);
        string message = InboundFixture.Message();
        byte[] bytes = Encoding.UTF8.GetBytes(message);
        string sealedMessage = sealer.Seal(bytes, "forwarder.test; dmarc=pass header.from=elsewhere.test", new ArcChainResult(ArcChainStatus.None, "none")).Headers + message;
        await using FakeMta mta = await f.ConnectedAsync();

        Assert.Equal(550, (await mta.SendAsync("bob@sender.test", "support@example.org", sealedMessage)).Code);
    }

    [Fact]
    public async Task The_stored_recipient_is_in_the_domains_canonical_form_and_a_message_is_one_unit_for_the_rate_limit()
    {
        var options = new InboundReceiveOptions { Enabled = true, Ceilings = new InboundCeilings(25 << 20, 2, 100, 0, 0, 0) };
        await using InboundFixture f = await InboundFixture.CreateAsync(options);
        await f.AddDomainAsync(InboundFixture.Acme, "xn--bcher-kva.example", DomainStatus.Verified);
        Guid books = (await f.Storage.Config.FindDomainByNameAsync("xn--bcher-kva.example", default))!.Id;
        await f.EnableAsync(books, InboundFixture.Acme);
        await f.AddRouteAsync(books, InboundFixture.Acme, 1, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
        await f.RefreshConfigAsync();
        await using FakeMta mta = await f.ConnectedAsync();

        // Three recipients of one domain are one message for a limit of two per minute; the fullwidth and punycode names are the same domain, stored once, in A-label form.
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("a@xn--bcher-kva.example")).Code);
        Assert.Equal(250, (await mta.RcptAsync("b@XN--BCHER-KVA.EXAMPLE")).Code);
        Assert.Equal(250, (await mta.RcptAsync("c@xn--bcher-kva.example")).Code);
        Assert.Equal(250, (await mta.DataAsync(InboundFixture.Message())).Code);
        Assert.Equal(3, (await f.StoredAsync(InboundFixture.Acme)).Count(m => m.EnvelopeTo.EndsWith("@xn--bcher-kva.example", StringComparison.Ordinal)));
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "d@xn--bcher-kva.example", InboundFixture.Message())).Code);   // the second message of the minute
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(450, (await mta.RcptAsync("e@xn--bcher-kva.example")).Code);   // the third is over the limit of two
    }

    [Fact]
    public async Task A_subject_cannot_reorder_the_text_around_it_with_bidirectional_controls()
    {
        InboundHeaderAnalysis analysis = InboundHeaderAnalysis.Analyze(Encoding.UTF8.GetBytes("Subject: invoice ‮txt.exe⁦ now\r\n\r\n"), ["mx.egg.test"], null);

        Assert.Equal("invoice  txt.exe  now", analysis.Subject);
    }
}
