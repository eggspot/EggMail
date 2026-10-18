using System.Text;
using Mta.Host.Configuration;
using Mta.Host.Tests.Inbound;
using Mta.Storage;

namespace Mta.Host.Tests.InboundE2E;

/// <summary>
/// The two abuse regressions of an MX that accepts mail from anybody, through a real runtime and real stores: the server is never an open relay (no recipient is accepted that is not a mailbox of a
/// route, and nothing received becomes outbound mail except through a route a tenant made), and it never produces backscatter (nothing is sent to anyone because of a message it refused, ignored or
/// dropped). The oracle for "nothing was sent" is the outbound queue and the webhook outbox of the real store (<see cref="InboundLab.AssertNothingWasSentAsync"/>). Also: the bounce (VERP) path on the
/// same port keeps working next to the inbound path.
/// </summary>
public abstract class InboundRelayAndBackscatterTests(LabBackend backend)
{
    // ------------------------------------------------------------------ open relay

    [Fact]
    public async Task No_recipient_outside_the_routes_is_accepted_whatever_the_sender_claims_or_how_the_address_is_written()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        lab.PublishSpf("example.org", authorize: false);   // the claimed local domain publishes SPF that does not authorize us-as-a-client
        string[] hostile =
        [
            "victim@gmail.test",                         // plainly external
            "victim@GMAIL.TEST",
            "<victim@gmail.test>",                      // (the brackets are added again by the client: a nested form)
            "@example.org:victim@gmail.test",            // source route (RFC 5321 4.1.1.3, obsolete): the relay-through-me form
            "victim%gmail.test@example.org",             // the percent hack
            "gmail.test!victim@example.org",             // the bang path
            "victim@gmail.test@example.org",             // two at signs
            "\"victim@gmail.test\"@example.org",         // a quoted local part that looks like an address
            "support@example.org@gmail.test",
            "support@example.org.gmail.test",            // a name that merely starts with ours
            "support@evilexample.org",
            "support@example.org.evil.test",
            "support@sub.example.org",                   // a subdomain is not the domain
            "postmaster@gmail.test",
            "support@[127.0.0.1]",                       // an address literal
            "support@[IPv6:::1]",
            "nobody@example.org",                        // ours, but no route
            "support@bounces.egg.test",                  // the bounce domain, not a token
        ];

        foreach (string recipient in hostile)
        {
            foreach (string sender in new[] { "ceo@example.org", "bob@sender.test", "" })
            {
                await using FakeMta mta = await lab.ConnectedAsync();
                FakeMta.Reply mail = await mta.MailFromAsync(sender);
                Assert.Equal(250, mail.Code);   // MAIL FROM costs nothing: the claim of a local sender is neither believed nor refused here
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
        Assert.Equal(("support@example.org", InboundVerdict.Fail, InboundVerdict.Fail), (stored.EnvelopeTo, stored.Auth.Spf, stored.Auth.Dmarc));   // SPF says what it is: this client is not authorized
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
            // The AUTH parameter of MAIL FROM names an identity the sender claims; it is not a login.
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

        // Headers and a body that ask for a copy somewhere else: Bcc, Resent-To, X-Original-To, Reply-To, a forwarding instruction in the text.
        string message = InboundLab.Message(to: "billing-1@example.org", extraHeaders: "Bcc: victim@gmail.test\r\nResent-To: victim2@gmail.test\r\nX-Original-To: victim3@gmail.test\r\nReply-To: victim4@gmail.test\r\nReturn-Path: <victim5@gmail.test>\r\n",
            body: "Please forward to victim6@gmail.test\r\n");

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "billing-1@example.org", message)).Code);

        InboundMessage stored = Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
        Assert.Equal((InboundActionKind.Forward, lab.BillingRoute), (stored.ActionKind, stored.RouteId));
        Assert.Equal("billing-1@example.org", stored.EnvelopeTo);
        // The receive path only stores it (pending); the route's targets are the route's, fixed by the tenant, and nothing was queued while the message was received.
        await lab.AssertNothingWasSentAsync();
    }

    // ------------------------------------------------------------------ backscatter

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

        // Every way a message is refused on this port, with a return path that is a real, forgeable address of a third party (the one that would receive a bounce).
        const string Victim = "victim@innocent.test";
        string Sized(int total) => InboundLab.Message(from: Victim, body: new string('x', total) + "\r\n");

        // 1. DMARC reject after DATA. (The stored-bytes limit of 1 byte is for step 5; this domain refuses at RCPT once it holds a message, so use example.net first.)
        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { MaxStoredBytes = null });
        Assert.Equal(550, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message())).Code);
        // 2. Unknown mailbox, unknown domain, relay attempt (at RCPT).
        Assert.Equal(550, (await lab.SendAsync(Victim, "nobody@example.org", Sized(10))).Code);
        Assert.Equal(550, (await lab.SendAsync(Victim, "x@gmail.test", Sized(10))).Code);
        // 3. Too big, declared and actual.
        Assert.Equal(552, (await lab.SendAsync(Victim, "anyone@example.net", Sized(10), "SIZE=999999")).Code);
        Assert.Equal(552, (await lab.SendAsync(Victim, "anyone@example.net", Sized(30_000))).Code);
        // 4. Too many recipients.
        await using (FakeMta mta = await lab.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.MailFromAsync(Victim)).Code);
            Assert.Equal(250, (await mta.RcptAsync("anyone@example.net")).Code);
            Assert.Equal(250, (await mta.RcptAsync("someone@example.net")).Code);
            Assert.Equal(452, (await mta.RcptAsync("third@example.net")).Code);
            await mta.CommandAsync("RSET");
        }

        // 5. Too many hops, a message that starts with white space, no usable From, a header block that cannot be recorded.
        Assert.Equal(554, (await lab.SendAsync(Victim, "anyone@example.net", Hops(26) + InboundLab.Message(from: Victim))).Code);
        Assert.Equal(554, (await lab.SendAsync(Victim, "anyone@example.net", " Subject: starts with a space\r\n\r\nbody\r\n")).Code);
        Assert.Equal(250, (await lab.SendAsync(Victim, "anyone@example.net", "Subject: no from\r\n\r\nbody\r\n")).Code);   // accepted, recorded as a permerror: not a refusal
        // 6. Unknown, tampered and stale bounce and SRS addresses.
        string token = lab.BounceLocalPart();
        string tampered = token[..^1] + (token[^1] == 'a' ? 'b' : 'a');
        Assert.Equal(550, (await lab.SendAsync("", $"{tampered}@{InboundLab.BounceDomain}", InboundLab.Dsn("x@y.test", "z@dest.example"))).Code);
        Assert.Equal(550, (await lab.SendAsync(Victim, $"{lab.Srs.CreateLocalPart("sender.test", "bob", lab.Clock.UtcNow)}@example.org", Sized(10))).Code);   // an SRS address from a sender
        Assert.Equal(550, (await lab.SendAsync("", $"{lab.Srs.CreateLocalPart("sender.test", "bob", lab.Clock.UtcNow.AddDays(-40))}@example.org", Sized(10))).Code);   // a stale one
        // 7. A valid SRS bounce is dropped: acknowledged, never relayed to the original sender, and never answered.
        Assert.Equal(250, (await lab.SendAsync("", $"{lab.Srs.CreateLocalPart("sender.test", "bob", lab.Clock.UtcNow)}@example.org", InboundLab.Dsn("x@y.test", "z@dest.example"))).Code);
        // 8. A message to a disabled, unverified or suspended domain is deferred, not bounced.
        Guid unverified = await lab.AddDomainAsync(InboundLab.Acme, "unverified.example", status: DomainStatus.Pending);
        await lab.AddRouteAsync(unverified, InboundLab.Acme, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
        await lab.RefreshAsync();
        Assert.Equal(450, (await lab.SendAsync(Victim, "x@unverified.example", Sized(10))).Code);

        // What was stored is the one message that was accepted for the tenant that wanted it; and not a byte was sent to the forged return path, to the sender, or to anybody.
        Assert.Equal(["no from"], (await lab.MessagesAsync(InboundLab.Globex)).Select(m => m.Subject ?? "no from").ToArray());
        Assert.Empty(await lab.MessagesAsync(InboundLab.Acme));
        await lab.AssertNothingWasSentAsync();
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(InboundLab.Acme, Victim, default));
    }

    // ------------------------------------------------------------------ the bounce path on the same port

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
        await using FakeMta mta = await lab.ConnectedAsync();

        // A real report: accepted, the address is suppressed for the tenant that sent the original (an effect on the config store, not an inbound message).
        Assert.Equal(250, (await mta.SendAsync("", address, InboundLab.Dsn(address, "gone@dest.example"))).Code);
        Assert.True(await lab.Storage.Config.IsSuppressedAsync(InboundLab.Acme, "gone@dest.example", default));
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(InboundLab.Globex, "gone@dest.example", default));
        Assert.Empty(await lab.MessagesAsync(InboundLab.Acme));

        // The same report for an address the token was not made for (version 2 tokens are bound to the destination domain) does not suppress it.
        Assert.Equal(250, (await mta.SendAsync("", address, InboundLab.Dsn(address, "other@elsewhere.example"))).Code);
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(InboundLab.Acme, "other@elsewhere.example", default));

        // A forged token never reaches the processor, and the bounce path is not a way to store mail: postmaster at the bounce domain is accepted and dropped.
        string forged = token[..^2] + "zz";
        FakeMta.Reply refused = await mta.SendAsync("", $"{forged}@{InboundLab.BounceDomain}", InboundLab.Dsn(address, "forged@dest.example"));
        Assert.Equal((550, "5.1.1"), (refused.Code, refused.Enhanced));
        Assert.False(await lab.Storage.Config.IsSuppressedAsync(InboundLab.Acme, "forged@dest.example", default));
        await mta.CommandAsync("RSET");
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", $"postmaster@{InboundLab.BounceDomain}", InboundLab.Message(to: "postmaster@bounces.egg.test"))).Code);
        Assert.Empty(await lab.MessagesAsync(InboundLab.Acme));
        Assert.Empty(await lab.MessagesAsync(InboundLab.Globex));

        // Inbound mail on the same connection still works, as a transaction of its own.
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
        string dsn = InboundLab.Dsn(address, "gone@dest.example").Replace("--BB--", padding + "\r\n--BB--", StringComparison.Ordinal);

        Assert.Equal(552, (await lab.SendAsync("stranger@sender.test", address, dsn)).Code);   // not a report (not from the null sender): the anonymous port does not take more than a mebibyte of it
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
