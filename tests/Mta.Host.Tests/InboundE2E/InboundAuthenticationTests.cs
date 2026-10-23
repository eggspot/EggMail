using System.Security.Cryptography;
using System.Text;
using Mta.Auth.Arc;
using Mta.Dkim;
using Mta.Dns;
using Mta.Host.Configuration;
using Mta.Host.Tests.Api;
using Mta.Smtp.Client;
using Mta.Storage;
using MimeKit;
using MimeKit.Cryptography;

namespace Mta.Host.Tests.InboundE2E;

public abstract class InboundAuthenticationTests(LabBackend backend)
{
    private sealed record SpfCase(string Domain, string? Record, DnsRcode? Failure, InboundVerdict Expected);

    private static readonly SpfCase[] SpfCases =
    [
        new("spf-pass.test", "v=spf1 ip4:127.0.0.1 -all", null, InboundVerdict.Pass),
        new("spf-fail.test", "v=spf1 ip4:203.0.113.9 -all", null, InboundVerdict.Fail),
        new("spf-soft.test", "v=spf1 ip4:203.0.113.9 ~all", null, InboundVerdict.SoftFail),
        new("spf-neutral.test", "v=spf1 ip4:203.0.113.9 ?all", null, InboundVerdict.Neutral),
        new("spf-none.test", null, null, InboundVerdict.None),
        new("spf-temp.test", null, DnsRcode.ServerFailure, InboundVerdict.TempError),
        new("spf-perm.test", "v=spf1 bogus-mechanism:x -all", null, InboundVerdict.PermError),
        new("spf-include.test", "v=spf1 include:spf-pass.test -all", null, InboundVerdict.Pass),
        new("spf-redirect.test", "v=spf1 redirect=spf-fail.test", null, InboundVerdict.Fail),
        new("spf-a.test", "v=spf1 a -all", null, InboundVerdict.Pass),
        new("spf-mx.test", "v=spf1 mx -all", null, InboundVerdict.Fail),
    ];

    [Fact]
    public async Task Every_spf_verdict_is_decided_stored_and_read_back_through_the_api_unchanged()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { WithApi = true });
        if (lab is null)
        {
            return;
        }

        lab.Dns.AddA("spf-a.test", "127.0.0.1");
        foreach (SpfCase c in SpfCases)
        {
            if (c.Record is not null)
            {
                lab.Dns.AddTxt(c.Domain, c.Record);
            }

            if (c.Failure is { } rcode)
            {
                lab.Dns.Fail(c.Domain, DnsRecordType.TXT, rcode);
            }
        }

        foreach (SpfCase c in SpfCases)
        {
            var reply = await lab.SendAsync($"bob@{c.Domain}", "support@example.org", InboundLab.Message(from: $"bob@{c.Domain}", subject: c.Domain));
            Assert.True(reply.Code == 250, $"{c.Domain}: {reply}");
        }

        ApiClient api = await lab.Api!.SignedInAsync("alice");
        Reply list = await api.GetAsync("/api/v1/inbound/messages?limit=50");
        Assert.Equal(System.Net.HttpStatusCode.OK, list.Status);
        foreach (SpfCase c in SpfCases)
        {
            InboundMessage stored = (await lab.MessagesAsync(InboundLab.Acme)).Single(m => m.Subject == c.Domain);
            Assert.True(c.Expected == stored.Auth.Spf, $"{c.Domain}: stored {stored.Auth.Spf}, expected {c.Expected}");
            Assert.Equal(c.Domain, stored.Auth.SpfDomain);
            string wire = c.Expected == InboundVerdict.SoftFail ? "softfail" : c.Expected == InboundVerdict.TempError ? "temperror" : c.Expected == InboundVerdict.PermError ? "permerror" : c.Expected.ToString().ToLowerInvariant();
            Reply detail = await api.GetAsync("/api/v1/inbound/messages/" + ApiJson(stored.Id));
            Assert.Equal(System.Net.HttpStatusCode.OK, detail.Status);
            Assert.Equal(wire, detail.Json.GetProperty("auth").GetProperty("spf").GetProperty("result").GetString());
            Assert.Contains($"spf={wire}", await lab.RawAsync(stored), StringComparison.Ordinal);
        }

        Assert.Empty((await lab.MessagesAsync(InboundLab.Acme, new InboundMessageQuery(InboundLab.Acme, Dmarc: InboundVerdict.Pass))));
    }

    private static string ApiJson(Guid id) => id.ToString("N");

    [Fact]
    public async Task Dkim_verdicts_pass_fail_none_and_the_signing_domain_are_stored_for_each_situation()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        lab.PublishSpf("sender.test", authorize: false);
        lab.PublishDmarc("sender.test", "reject");
        lab.PublishSpf("other.test", authorize: false);

        string good = lab.DkimSign(InboundLab.Message(subject: "good", body: "original"), "sender.test");
        string tampered = lab.DkimSign(InboundLab.Message(subject: "tampered", body: "original"), "sender.test").Replace("original", "tampered", StringComparison.Ordinal);
        string unsigned = InboundLab.Message(subject: "unsigned");
        string otherDomain = lab.DkimSign(InboundLab.Message(subject: "unaligned"), "other.test");
        string noKey = lab.DkimSign(InboundLab.Message(subject: "nokey"), "sender.test", "gone");
        lab.Dns.Fail("gone._domainkey.sender.test", DnsRecordType.TXT, DnsRcode.NameError);

        foreach (string m in new[] { good, tampered, unsigned, otherDomain, noKey })
        {
            Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", m)).Code);
        }

        IReadOnlyList<InboundMessage> all = await lab.MessagesAsync(InboundLab.Acme);
        InboundMessage Of(string subject) => all.Single(m => m.Subject == subject);
        Assert.Equal((InboundVerdict.Pass, "sender.test", InboundVerdict.Pass), (Of("good").Auth.Dkim, Of("good").Auth.DkimDomain, Of("good").Auth.Dmarc));
        Assert.Equal((InboundVerdict.Fail, InboundVerdict.Fail), (Of("tampered").Auth.Dkim, Of("tampered").Auth.Dmarc));
        Assert.Equal((InboundVerdict.None, InboundVerdict.Fail), (Of("unsigned").Auth.Dkim, Of("unsigned").Auth.Dmarc));
        Assert.Equal((InboundVerdict.Pass, "other.test", InboundVerdict.Fail), (Of("unaligned").Auth.Dkim, Of("unaligned").Auth.DkimDomain, Of("unaligned").Auth.Dmarc));
        Assert.NotEqual(InboundVerdict.Pass, Of("nokey").Auth.Dkim);
    }

    [Theory]
    [InlineData(DkimCanonicalizationAlgorithm.Simple, DkimCanonicalizationAlgorithm.Simple)]
    [InlineData(DkimCanonicalizationAlgorithm.Relaxed, DkimCanonicalizationAlgorithm.Relaxed)]
    [InlineData(DkimCanonicalizationAlgorithm.Relaxed, DkimCanonicalizationAlgorithm.Simple)]
    public async Task A_signature_made_by_mimekit_verifies_and_a_change_to_the_body_or_a_signed_header_breaks_it(DkimCanonicalizationAlgorithm headerCanon, DkimCanonicalizationAlgorithm bodyCanon)
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        lab.PublishSpf("sender.test", authorize: false);
        lab.PublishDmarc("sender.test", "reject");
        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { DmarcAction = InboundDmarcAction.Reject });
        using RSA key = lab.PublishDkimKey("sender.test", "mk");

        var message = new MimeMessage();
        message.From.Add(new MailboxAddress("Bob", "bob@sender.test"));
        message.To.Add(new MailboxAddress("Support", "support@example.org"));
        message.Subject = "Signed by MimeKit";
        message.Date = new DateTimeOffset(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);
        message.MessageId = "mimekit-1@sender.test";
        message.Body = new TextPart("plain") { Text = "Hello,\r\n\r\n  an indented line \r\nand a trailing blank line\r\n\r\n" };
        using var privateKey = new MemoryStream(Encoding.ASCII.GetBytes(DkimKeyTools.ExportPrivateKeyPem(key)));
        var signer = new MimeKit.Cryptography.DkimSigner(privateKey, "sender.test", "mk", DkimSignatureAlgorithm.RsaSha256)
        {
            HeaderCanonicalizationAlgorithm = headerCanon,
            BodyCanonicalizationAlgorithm = bodyCanon,
        };
        signer.Sign(message, [HeaderId.From, HeaderId.To, HeaderId.Subject, HeaderId.Date, HeaderId.MessageId]);
        string wire = Serialize(message);

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", wire)).Code);
        InboundMessage ok = Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
        Assert.Equal((InboundVerdict.Pass, "sender.test", InboundVerdict.Pass), (ok.Auth.Dkim, ok.Auth.DkimDomain, ok.Auth.Dmarc));

        Assert.Equal(550, (await lab.SendAsync("bob@sender.test", "support@example.org", wire.Replace("Hello,", "Hullo,", StringComparison.Ordinal))).Code);
        Assert.Equal(550, (await lab.SendAsync("bob@sender.test", "support@example.org", wire.Replace("Subject: Signed", "Subject: Resigned", StringComparison.Ordinal))).Code);
        Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
    }

    private static string Serialize(MimeMessage message)
    {
        var options = FormatOptions.Default.Clone();
        options.NewLineFormat = NewLineFormat.Dos;
        using var stream = new MemoryStream();
        message.WriteTo(options, stream);
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private sealed record ActionCase(string Name, string SpfRecord, string? Dmarc, InboundDmarcAction Action, int ExpectedCode, InboundVerdict ExpectedDmarc, InboundDmarcDisposition ExpectedDisposition);

    [Fact]
    public async Task Each_dmarc_action_does_what_the_design_says_with_each_policy()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        const string Pass = "v=spf1 ip4:127.0.0.1 -all";
        const string Fail = "v=spf1 -all";
        ActionCase[] cases =
        [
            new("pass-reject", Pass, "p=reject", InboundDmarcAction.Reject, 250, InboundVerdict.Pass, InboundDmarcDisposition.None),
            new("fail-reject-reject", Fail, "p=reject", InboundDmarcAction.Reject, 550, InboundVerdict.Fail, InboundDmarcDisposition.None),
            new("fail-quarantine-reject", Fail, "p=quarantine", InboundDmarcAction.Reject, 250, InboundVerdict.Fail, InboundDmarcDisposition.Flagged),
            new("fail-none-reject", Fail, "p=none", InboundDmarcAction.Reject, 250, InboundVerdict.Fail, InboundDmarcDisposition.None),
            new("fail-reject-flag", Fail, "p=reject", InboundDmarcAction.Flag, 250, InboundVerdict.Fail, InboundDmarcDisposition.Flagged),
            new("fail-quarantine-flag", Fail, "p=quarantine", InboundDmarcAction.Flag, 250, InboundVerdict.Fail, InboundDmarcDisposition.Flagged),
            new("fail-none-flag", Fail, "p=none", InboundDmarcAction.Flag, 250, InboundVerdict.Fail, InboundDmarcDisposition.None),
            new("fail-reject-record", Fail, "p=reject", InboundDmarcAction.RecordOnly, 250, InboundVerdict.Fail, InboundDmarcDisposition.None),
            new("fail-norecord-reject", Fail, null, InboundDmarcAction.Reject, 250, InboundVerdict.None, InboundDmarcDisposition.None),
            new("softfail-reject-reject", "v=spf1 ~all", "p=reject", InboundDmarcAction.Reject, 550, InboundVerdict.Fail, InboundDmarcDisposition.None),
            new("fail-pct0-reject", Fail, "p=reject; pct=0", InboundDmarcAction.Reject, 250, InboundVerdict.Fail, InboundDmarcDisposition.Flagged),
            new("fail-relaxed-sub", Fail, "p=none; sp=reject", InboundDmarcAction.Reject, 550, InboundVerdict.Fail, InboundDmarcDisposition.None),
        ];

        foreach (ActionCase c in cases)
        {
            string domain = c.Name == "fail-relaxed-sub" ? "relaxedsub.test" : c.Name.Replace("-", "", StringComparison.Ordinal) + ".sender.test";
            string recipientDomain = c.Name.Replace("-", "", StringComparison.Ordinal) + ".example.org";
            Guid id = await lab.AddDomainAsync(InboundLab.Acme, recipientDomain, action: c.Action);
            await lab.AddRouteAsync(id, InboundLab.Acme, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
            string fromDomain = c.Name == "fail-relaxed-sub" ? "www." + domain : domain;
            lab.Dns.AddTxt(domain, c.SpfRecord);
            if (c.Dmarc is not null)
            {
                lab.Dns.AddTxt("_dmarc." + domain, "v=DMARC1; " + c.Dmarc);
            }

            if (c.Name == "fail-relaxed-sub")
            {
                lab.Dns.AddTxt("www." + domain, c.SpfRecord);
            }

            await lab.RefreshAsync();

            var reply = await lab.SendAsync($"bob@{fromDomain}", "x@" + recipientDomain, InboundLab.Message(from: $"bob@{fromDomain}", to: "x@" + recipientDomain, subject: c.Name));
            Assert.True(c.ExpectedCode == reply.Code, $"{c.Name}: {reply}");
            if (c.ExpectedCode == 550)
            {
                Assert.Equal("5.7.1", reply.Enhanced);
                continue;
            }

            InboundMessage stored = (await lab.MessagesAsync(InboundLab.Acme)).Single(m => m.Subject == c.Name);
            Assert.True(c.ExpectedDmarc == stored.Auth.Dmarc, $"{c.Name}: dmarc {stored.Auth.Dmarc}");
            Assert.True(c.ExpectedDisposition == stored.Disposition, $"{c.Name}: disposition {stored.Disposition}");
            string raw = await lab.RawAsync(stored);
            Assert.Equal(c.ExpectedDisposition == InboundDmarcDisposition.Flagged, raw.Contains("\r\nX-EggMail-Dmarc: flagged\r\n", StringComparison.Ordinal));
        }

        IReadOnlyList<InboundMessage> flagged = await lab.MessagesAsync(InboundLab.Acme, new InboundMessageQuery(InboundLab.Acme, DmarcFlagged: true));
        Assert.Equal(["fail-pct0-reject", "fail-quarantine-flag", "fail-quarantine-reject", "fail-reject-flag"], flagged.Select(m => m.Subject!).Order(StringComparer.Ordinal).ToArray());
        await lab.AssertNothingWasSentAsync();
    }

    [Fact]
    public async Task One_transaction_for_several_domains_and_tenants_is_refused_only_when_every_domain_says_reject()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        lab.PublishSpf("sender.test", authorize: false);
        lab.PublishDmarc("sender.test", "reject");
        Guid rejecting = await lab.AddDomainAsync(InboundLab.Acme, "rejecting.example", action: InboundDmarcAction.Reject);
        Guid rejecting2 = await lab.AddDomainAsync(InboundLab.Globex, "rejecting2.example", action: InboundDmarcAction.Reject);
        await lab.AddRouteAsync(rejecting, InboundLab.Acme, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
        await lab.AddRouteAsync(rejecting2, InboundLab.Globex, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { DmarcAction = InboundDmarcAction.Flag });
        await lab.RefreshAsync();

        Assert.Equal(550, (await SendToAsync(lab, "a@rejecting.example", "b@rejecting2.example")).Code);
        Assert.Empty(await lab.MessagesAsync(InboundLab.Acme));
        Assert.Empty(await lab.MessagesAsync(InboundLab.Globex));

        Assert.Equal(250, (await SendToAsync(lab, "a@rejecting.example", "b@rejecting2.example", "support@example.org")).Code);
        InboundMessage[] acme = [.. await lab.MessagesAsync(InboundLab.Acme)];
        Assert.Equal(2, acme.Length);
        Assert.All(acme, m => Assert.Equal(InboundDmarcDisposition.Flagged, m.Disposition));
        InboundMessage globex = Assert.Single(await lab.MessagesAsync(InboundLab.Globex));
        Assert.Equal(InboundDmarcDisposition.Flagged, globex.Disposition);

        await lab.SetSettingsAsync(lab.ExampleNet, InboundLab.Globex, s => s with { DmarcAction = InboundDmarcAction.RecordOnly });
        Assert.Equal(250, (await SendToAsync(lab, "a@rejecting.example", "anyone@example.net")).Code);
        IReadOnlyList<InboundMessage> net = await lab.MessagesAsync(InboundLab.Globex, new InboundMessageQuery(InboundLab.Globex, Recipient: "anyone@example.net"));
        Assert.Equal(InboundDmarcDisposition.None, Assert.Single(net).Disposition);
    }

    private static async Task<Host.Tests.Inbound.FakeMta.Reply> SendToAsync(InboundLab lab, params string[] recipients)
    {
        await using Host.Tests.Inbound.FakeMta mta = await lab.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        foreach (string r in recipients)
        {
            Assert.Equal(250, (await mta.RcptAsync(r)).Code);
        }

        return await mta.DataAsync(InboundLab.Message(to: recipients[0]));
    }

    [Fact]
    public async Task A_sealer_named_in_the_configuration_vouches_for_the_message_and_one_that_is_not_named_does_not()
    {
        var trusting = new LabOptions { Inbound = new InboundSection { Enabled = true, CheckSpfForInternalClients = true, Arc = new InboundArcSection { TrustedSealers = ["forwarder.test"] } } };
        await using InboundLab? lab = await InboundLab.StartAsync(backend, trusting);
        if (lab is null)
        {
            return;
        }

        lab.PublishSpf("sender.test", authorize: false);
        lab.PublishDmarc("sender.test", "reject");
        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { DmarcAction = InboundDmarcAction.Reject });

        string Sealed(string sealer, string results)
        {
            string message = InboundLab.Message();
            using RSA key = lab.PublishDkimKey(sealer, "arc1");
            using var arc = new ArcSealer(new ArcSealerOptions { Domain = sealer, Selector = "arc1", Clock = lab.Clock }, key);
            byte[] bytes = Encoding.UTF8.GetBytes(message);
            ArcChainResult none = new ArcValidator(lab.Dns).ValidateAsync(bytes).AsTask().GetAwaiter().GetResult();
            return arc.Seal(bytes, results, none).Headers + message;
        }

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", Sealed("forwarder.test", "forwarder.test; dmarc=pass header.from=sender.test"))).Code);
        InboundMessage m = Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
        Assert.Equal((InboundVerdict.Fail, InboundVerdict.Pass), (m.Auth.Dmarc, m.Auth.Arc));

        Assert.Equal(550, (await lab.SendAsync("bob@sender.test", "support@example.org", Sealed("stranger.test", "stranger.test; dmarc=pass header.from=sender.test"))).Code);
        Assert.Equal(550, (await lab.SendAsync("bob@sender.test", "support@example.org", Sealed("forwarder.test", "forwarder.test; dmarc=fail header.from=sender.test"))).Code);
        Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
    }

    [Fact]
    public async Task A_resolver_that_never_answers_ends_at_the_configured_budget_as_a_temporary_error_and_reject_defers_the_message()
    {
        var options = new LabOptions
        {
            Inbound = new InboundSection { Enabled = true, CheckSpfForInternalClients = true, Verification = new InboundVerificationSection { Timeout = TimeSpan.FromMilliseconds(400) } },
            WrapDns = dns => new HoldingResolver(dns, name => name == "sender.test"),
        };
        await using InboundLab? lab = await InboundLab.StartAsync(backend, options);
        if (lab is null)
        {
            return;
        }

        lab.Dns.AddTxt("_dmarc.sender.test", "v=DMARC1; p=reject");
        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { DmarcAction = InboundDmarcAction.Reject });

        var deferred = await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message());

        Assert.Equal((451, "4.7.0"), (deferred.Code, deferred.Enhanced));
        Assert.Empty(await lab.MessagesAsync(InboundLab.Acme));
        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { DmarcAction = InboundDmarcAction.RecordOnly });
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message())).Code);
        Assert.Equal(InboundVerdict.TempError, Assert.Single(await lab.MessagesAsync(InboundLab.Acme)).Auth.Spf);
    }
}

public sealed class SqliteInboundAuthenticationTests() : InboundAuthenticationTests(LabBackend.Sqlite);

public sealed class PostgresInboundAuthenticationTests() : InboundAuthenticationTests(LabBackend.Postgres);
