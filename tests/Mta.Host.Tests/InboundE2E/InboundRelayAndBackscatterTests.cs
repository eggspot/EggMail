using System.Text;
using Mta.Host.Configuration;
using Mta.Host.Tests.Inbound;
using Mta.Storage;

namespace Mta.Host.Tests.InboundE2E;

public abstract class InboundRelayAndBackscatterTests(LabBackend backend)
{
    [Fact]
    public async Task No_recipient_outside_the_routes_is_accepted_whatever_the_sender_claims_or_how_the_address_is_written()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        lab.PublishSpf("example.org", authorize: false);
        string[] hostile =
        [
            "victim@gmail.test",
            "victim@GMAIL.TEST",
            "<victim@gmail.test>",
            "@example.org:victim@gmail.test",
            "victim%gmail.test@example.org",
            "gmail.test!victim@example.org",
            "victim@gmail.test@example.org",
            "\"victim@gmail.test\"@example.org",
            "support@example.org@gmail.test",
            "support@example.org.gmail.test",
            "support@evilexample.org",
            "support@example.org.evil.test",
            "support@sub.example.org",
            "postmaster@gmail.test",
            "support@[127.0.0.1]",
            "support@[IPv6:::1]",
            "nobody@example.org",
            "support@bounces.egg.test",
        ];

        foreach (string recipient in hostile)
        {
            foreach (string sender in new[] { "ceo@example.org", "bob@sender.test", "" })
            {
                await using FakeMta mta = await lab.ConnectedAsync();
                FakeMta.Reply mail = await mta.MailFromAsync(sender);
                Assert.Equal(250, mail.Code);
                FakeMta.Reply rcpt = await mta.CommandAsync($"RCPT TO:<{recipient}>");
                Assert.True(rcpt.Code is >= 500 and < 600, $"{recipient} from '{sender}': {rcpt}");
            }
        }

        Assert.Empty(await lab.MessagesAsync(InboundLab.Acme));
        Assert.Empty(await lab.MessagesAsync(InboundLab.Globex));
        await lab.AssertNothingWasSentAsync();
    }

    [Fact]
    public async Task A_sender_claiming_a_local_domain_without_authenticating_is_an_outside_sender_whose_mail_is_checked_stored_for_the_recipient_and_never_relayed()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        lab.PublishSpf("example.org", authorize: false);
        lab.PublishDmarc("example.org", "reject");
        await using FakeMta mta = await lab.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("ceo@example.org")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        Assert.Equal(550, (await mta.RcptAsync("victim@gmail.test")).Code);
        Assert.Equal(250, (await mta.DataAsync(InboundLab.Message(from: "ceo@example.org", subject: "From the CEO"))).Code);

        InboundMessage stored = Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
        Assert.Equal(("support@example.org", InboundVerdict.Fail, InboundVerdict.Fail), (stored.EnvelopeTo, stored.Auth.Spf, stored.Auth.Dmarc));
        await lab.AssertNothingWasSentAsync();
    }

    [Fact]
    public async Task Auth_in_any_form_does_not_make_a_sender_a_submitter_on_the_inbound_port()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { Mode = Mta.Smtp.Server.ListenerMode.StartTls });
        if (lab is null)
        {
            return;
        }

        foreach (bool tls in new[] { false, true })
        {
            await using FakeMta mta = await lab.ConnectAsync();
            await mta.EhloAsync("mail.sender.test");
            if (tls)
            {
                Assert.True(await mta.StartTlsAsync());
                await mta.EhloAsync("mail.sender.test");
            }

            Assert.Equal(502, (await mta.CommandAsync("AUTH PLAIN AGJvYgBwYXNz")).Code);
            Assert.Equal(502, (await mta.CommandAsync("AUTH LOGIN")).Code);
            Assert.Equal(502, (await mta.CommandAsync("AUTH CRAM-MD5")).Code);
            Assert.Equal(250, (await mta.MailFromAsync("ceo@example.org", "AUTH=ceo@example.org")).Code);
            FakeMta.Reply external = await mta.RcptAsync("victim@gmail.test");
            Assert.Equal((550, "5.7.1"), (external.Code, external.Enhanced));
        }

        await lab.AssertNothingWasSentAsync();
    }

    [Fact]
    public async Task A_message_to_a_forward_route_creates_no_outbound_mail_by_itself_and_what_the_message_says_never_changes_where_it_goes()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        string message = InboundLab.Message(to: "billing-1@example.org", extraHeaders: "Bcc: victim@gmail.test\r\nResent-To: victim2@gmail.test\r\nX-Original-To: victim3@gmail.test\r\nReply-To: victim4@gmail.test\r\nReturn-Path: <victim5@gmail.test>\r\n",
            body: "Please forward to victim6@gmail.test\r\n");

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "billing-1@example.org", message)).Code);

        InboundMessage stored = Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
        Assert.Equal((InboundActionKind.Forward, lab.BillingRoute), (stored.ActionKind, stored.RouteId));
        Assert.Equal("billing-1@example.org", stored.EnvelopeTo);
        await lab.AssertNothingWasSentAsync();
    }

    private static string Hops(int count) => string.Concat(Enumerable.Range(0, count).Select(i => $"Received: from hop{i}.test by hop{i + 1}.test; Fri, 16 Oct 2026 12:00:00 +0000\r\n"));

    [Fact]
    public async Task Nothing_is_ever_sent_to_anybody_because_of_a_message_that_was_refused_ignored_or_dropped()
    {
        var options = new LabOptions { Inbound = new InboundSection { Enabled = true, CheckSpfForInternalClients = true, MaxRecipients = 2, MaxMessageSize = 20_000 } };
        await using InboundLab? lab = await InboundLab.StartAsync(backend, options);
        if (lab is null)
        {
            return;
        }

        lab.PublishSpf("sender.test", authorize: false);
        lab.PublishDmarc("sender.test", "reject");
        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { DmarcAction = InboundDmarcAction.Reject, MaxStoredBytes = 1 });

        const string Victim = "victim@innocent.test";
        string Sized(int total) => InboundLab.Message(from: Victim, body: new string('x', total) + "\r\n");

        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { MaxStoredBytes = null });
        Assert.Equal(550, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message())).Code);
        Assert.Equal(550, (await lab.SendAsync(Victim, "nobody@example.org", Sized(10))).Code);
        Assert.Equal(550, (await lab.SendAsync(Victim, "x@gmail.test", Sized(10))).Code);
        Assert.Equal(552, (await lab.SendAsync(Victim, "anyone@example.net", Sized(10), "SIZE=999999")).Code);
        Assert.Equal(552, (await lab.SendAsync(Victim, "anyone@example.net", Sized(30_000))).Code);
        await using (FakeMta mta = await lab.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.MailFromAsync(Victim)).Code);
            Assert.Equal(250, (await mta.RcptAsync("anyone@example.net")).Code);
            Assert.Equal(250, (await mta.RcptAsync("someone@example.net")).Code);
            Assert.Equal(452, (await mta.RcptAsync("third@example.net")).Code);
            await mta.CommandAsync("RSET");
        }

        Assert.Equal(554, (await lab.SendAsync(Victim, "anyone@example.net", Hops(26) + InboundLab.Message(from: Victim))).Code);
        Assert.Equal(554, (await lab.SendAsync(Victim, "anyone@example.net", " Subject: starts with a space\r\n\r\nbody\r\n")).Code);
        Assert.Equal(250, (await lab.SendAsync(Victim, "anyone@example.net", "Subject: no from\r\n\r\nbody\r\n")).Code);
        string token = lab.BounceLocalPart();
        string tampered = token[..^1] + (token[^1] == 'a' ? 'b' : 'a');
        Assert.Equal(550, (await lab.SendAsync("", $"{tampered}@{InboundLab.BounceDomain}", InboundLab.Dsn("x@y.test", "z@dest.example"))).Code);
        Assert.Equal(550, (await lab.SendAsync(Victim, $"{lab.Srs.CreateLocalPart("sender.test", "bob", lab.Clock.UtcNow)}@example.org", Sized(10))).Code);
        Assert.Equal(550, (await lab.SendAsync("", $"{lab.Srs.CreateLocalPart("sender.test", "bob", lab.Clock.UtcNow.AddDays(-40))}@example.org", Sized(10))).Code);
        Assert.Equal(250, (await lab.SendAsync("", $"{lab.Srs.CreateLocalPart("sender.test", "bob", lab.Clock.UtcNow)}@example.org", InboundLab.Dsn("x@y.test", "z@dest.example"))).Code);
        Guid unverified = await lab.AddDomainAsync(InboundLab.Acme, "unverified.example", status: DomainStatus.Pending);
        await lab.AddRouteAsync(unverified, InboundLab.Acme, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
        await lab.RefreshAsync();
        Assert.Equal(450, (await lab.SendAsync(Victim, "x@unverified.example", Sized(10))).Code);

        Assert.Equal(["no from"], (await lab.MessagesAsync(InboundLab.Globex)).Select(m => m.Subject ?? "no from").ToArray());
        Assert.Empty(await lab.MessagesAsync(InboundLab.Acme));
        await lab.AssertNothingWasSentAsync();
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(InboundLab.Acme, Victim, default));
    }

    [Fact]
    public async Task A_signed_bounce_is_processed_as_before_next_to_the_inbound_path_and_a_forged_one_changes_nothing()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        string token = lab.BounceLocalPart();
        string address = $"{token}@{InboundLab.BounceDomain}";
        string sent = await lab.RecordAMessageDeliveredToAsync("gone@dest.example");
        await using FakeMta mta = await lab.ConnectedAsync();

        Assert.Equal(250, (await mta.SendAsync("", address, InboundLab.Dsn(address, "gone@dest.example", sent))).Code);
        Assert.True(await lab.Storage.Config.IsSuppressedAsync(InboundLab.Acme, "gone@dest.example", default));
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(InboundLab.Globex, "gone@dest.example", default));
        Assert.Empty(await lab.MessagesAsync(InboundLab.Acme));

        string sentElsewhere = await lab.RecordAMessageDeliveredToAsync("other@elsewhere.example");
        Assert.Equal(250, (await mta.SendAsync("", address, InboundLab.Dsn(address, "other@elsewhere.example", sentElsewhere))).Code);
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(InboundLab.Acme, "other@elsewhere.example", default));

        string forged = token[..^2] + "zz";
        FakeMta.Reply refused = await mta.SendAsync("", $"{forged}@{InboundLab.BounceDomain}", InboundLab.Dsn(address, "forged@dest.example"));
        Assert.Equal((550, "5.1.1"), (refused.Code, refused.Enhanced));
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(InboundLab.Acme, "forged@dest.example", default));
        await mta.CommandAsync("RSET");
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", $"postmaster@{InboundLab.BounceDomain}", InboundLab.Message(to: "postmaster@bounces.egg.test"))).Code);
        Assert.Empty(await lab.MessagesAsync(InboundLab.Acme));
        Assert.Empty(await lab.MessagesAsync(InboundLab.Globex));

        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "after the bounce"))).Code);
        Assert.Equal("after the bounce", Assert.Single(await lab.MessagesAsync(InboundLab.Acme)).Subject);
    }

    [Fact]
    public async Task A_report_over_a_mebibyte_from_a_stranger_is_refused_and_the_same_report_from_the_null_sender_is_read_from_its_head()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        string address = $"{lab.BounceLocalPart()}@{InboundLab.BounceDomain}";
        string padding = new string('p', 1_200_000);
        string sent = await lab.RecordAMessageDeliveredToAsync("gone@dest.example");
        string dsn = InboundLab.Dsn(address, "gone@dest.example", sent).Replace("--BB--", padding + "\r\n--BB--", StringComparison.Ordinal);

        Assert.Equal(552, (await lab.SendAsync("stranger@sender.test", address, dsn)).Code);
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(InboundLab.Acme, "gone@dest.example", default));
        Assert.Equal(250, (await lab.SendAsync("", address, dsn)).Code);
        Assert.True(await lab.Storage.Config.IsSuppressedAsync(InboundLab.Acme, "gone@dest.example", default));
    }

    [Fact]
    public async Task Without_a_bounce_domain_there_is_no_bounce_namespace_and_the_domain_names_are_ordinary_unknown_domains()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { BounceDomain = null });
        if (lab is null)
        {
            return;
        }

        await using FakeMta mta = await lab.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        FakeMta.Reply r = await mta.RcptAsync($"postmaster@{InboundLab.BounceDomain}");
        Assert.Equal((550, "5.7.1"), (r.Code, r.Enhanced));
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
    }
}

public sealed class SqliteInboundRelayAndBackscatterTests() : InboundRelayAndBackscatterTests(LabBackend.Sqlite);

public sealed class PostgresInboundRelayAndBackscatterTests() : InboundRelayAndBackscatterTests(LabBackend.Postgres);
