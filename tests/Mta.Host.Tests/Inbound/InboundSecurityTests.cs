using System.Text;
using Mta.Dsn;
using Mta.Smtp.Server;
using Mta.Storage;

namespace Mta.Host.Tests.Inbound;

/// <summary>
/// The regressions of design section 11.12: no open relay, no backscatter, the bounce and SRS paths still work (and are not subject to the inbound policies),
/// a transaction has one kind, and the smuggling and STARTTLS-injection defenses hold on the new listener role.
/// </summary>
public class InboundSecurityTests : IAsyncLifetime
{
    private InboundFixture _f = null!;

    public async Task InitializeAsync() => _f = await InboundFixture.CreateAsync();

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private string BounceLocalPart(string destination = "dest.example") => _f.Verp.CreateLocalPart(InboundFixture.Acme, _f.ExampleOrg, _f.Clock.Now, destination);

    private SrsCodec Srs => new(_f.Verp);

    private static string Dsn(string to, string finalRecipient) =>
        $"From: MAILER-DAEMON@remote.example\r\nTo: {to}\r\nSubject: Undelivered Mail Returned to Sender\r\nAuto-Submitted: auto-replied\r\n" +
        "Content-Type: multipart/report; report-type=delivery-status; boundary=\"BB\"\r\n\r\n" +
        "--BB\r\nContent-Type: text/plain\r\n\r\nCould not deliver.\r\n" +
        $"--BB\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; remote.example\r\n\r\nFinal-Recipient: rfc822; {finalRecipient}\r\nAction: failed\r\nStatus: 5.1.1\r\nDiagnostic-Code: smtp; 550 5.1.1 No such user\r\n\r\n" +
        "--BB\r\nContent-Type: text/rfc822-headers\r\n\r\nMessage-ID: <orig@egg.test>\r\nSubject: x\r\n\r\n--BB--\r\n";

    private async Task<int> QueuedDeliveriesAsync() =>
        (await _f.Storage.Deliveries.ClaimAsync("probe", 100, DateTimeOffset.UtcNow.AddHours(1), TimeSpan.FromMinutes(1), default)).Count;

    // ------------------------------------------------------------------ open relay

    [Fact]
    public async Task The_listener_offers_no_auth_and_refuses_it()
    {
        await using FakeMta mta = await _f.ConnectAsync();
        var ehlo = await mta.EhloAsync();
        Assert.DoesNotContain(ehlo.Lines, l => l.Contains("AUTH", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(ehlo.Lines, l => l.Contains("SIZE", StringComparison.Ordinal));
        var auth = await mta.CommandAsync("AUTH PLAIN AGFjbWUtdXNlcgBzM2NyZXQ=");
        Assert.Equal(502, auth.Code);
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(550, (await mta.RcptAsync("anyone@gmail.com")).Code);
    }

    [Fact]
    public async Task An_external_recipient_after_a_valid_one_is_refused_and_only_the_valid_recipient_gets_the_message()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        Assert.Equal((550, "5.7.1"), ((await mta.RcptAsync("victim@gmail.com")) is var r ? (r.Code, r.Enhanced) : default));
        Assert.Equal(250, (await mta.DataAsync(InboundFixture.Message())).Code);

        InboundMessage m = Assert.Single(await _f.StoredAsync(InboundFixture.Acme));
        Assert.Equal("support@example.org", m.EnvelopeTo);
        Assert.Equal(0, await QueuedDeliveriesAsync());   // nothing was queued for delivery to anybody
    }

    [Fact]
    public async Task A_mail_from_of_a_local_domain_without_authentication_is_an_external_sender_verified_and_never_relayed()
    {
        _f.Dns.AddTxt("example.org", "v=spf1 ip4:198.51.100.1 -all");   // our own domain's SPF does not authorize the client
        await using FakeMta mta = await _f.ConnectedAsync();

        var reply = await mta.SendAsync("ceo@example.org", "support@example.org", InboundFixture.Message(from: "ceo@example.org"));

        Assert.Equal(250, reply.Code);   // accepted like any other external sender
        InboundMessage m = Assert.Single(await _f.StoredAsync(InboundFixture.Acme));
        Assert.Equal(InboundVerdict.Fail, m.Auth.Spf);   // and verified: the identity is not proof of anything
        Assert.Contains("spf=fail", await _f.RawAsync(m));
        Assert.Equal(0, await QueuedDeliveriesAsync());

        // It cannot be used to reach anybody else either.
        Assert.Equal(250, (await mta.MailFromAsync("ceo@example.org")).Code);
        Assert.Equal(550, (await mta.RcptAsync("someone@gmail.com")).Code);
    }

    [Fact]
    public async Task Refusals_in_the_dialog_create_no_message_of_any_kind()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(550, (await mta.RcptAsync("nobody@example.org")).Code);
        Assert.Equal(550, (await mta.RcptAsync("x@gmail.com")).Code);
        Assert.Equal(450, (await mta.RcptAsync("x@pending.example")).Code);

        Assert.Equal(0, await QueuedDeliveriesAsync());
        Assert.Empty(await _f.StoredAsync(InboundFixture.Acme));
    }

    [Fact]
    public async Task A_message_refused_after_data_creates_no_bounce_either()
    {
        await _f.EnableAsync(_f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await _f.RefreshConfigAsync();
        _f.PublishSpf("sender.test", authorizeClient: false);
        _f.PublishDmarc("sender.test", "reject");
        await using FakeMta mta = await _f.ConnectedAsync();

        var reply = await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message());

        Assert.Equal((550, "5.7.1"), (reply.Code, reply.Enhanced));
        Assert.Equal(0, await QueuedDeliveriesAsync());
        Assert.Empty(await _f.StoredAsync(InboundFixture.Acme));
    }

    // ------------------------------------------------------------------ the bounce path

    [Fact]
    public async Task A_signed_bounce_address_at_the_shared_bounce_domain_is_accepted_and_the_report_is_processed_as_before()
    {
        string local = BounceLocalPart();
        await using FakeMta mta = await _f.ConnectedAsync();

        var reply = await mta.SendAsync("", $"{local}@{InboundFixture.BounceDomain}", Dsn($"{local}@{InboundFixture.BounceDomain}", "gone@dest.example"));

        Assert.Equal(250, reply.Code);
        Assert.True(await _f.Storage.Config.IsSuppressedAsync(InboundFixture.Acme, "gone@dest.example", default));
        Assert.Empty(await _f.StoredAsync(InboundFixture.Acme));   // a bounce is not an inbound message
    }

    [Fact]
    public async Task A_bounce_is_not_refused_for_the_dmarc_policy_of_its_sender_and_no_inbound_policy_applies()
    {
        _f.PublishDmarc("remote.example", "reject");   // the MAILER-DAEMON's own domain publishes reject, and SPF fails
        string local = BounceLocalPart();
        await using FakeMta mta = await _f.ConnectedAsync();

        var reply = await mta.SendAsync("MAILER-DAEMON@remote.example", $"{local}@{InboundFixture.BounceDomain}", Dsn($"{local}@{InboundFixture.BounceDomain}", "gone@dest.example"));

        Assert.Equal(250, reply.Code);
        Assert.True(await _f.Storage.Config.IsSuppressedAsync(InboundFixture.Acme, "gone@dest.example", default));
    }

    [Fact]
    public async Task Postmaster_and_abuse_at_the_shared_bounce_domain_are_accepted_without_a_token()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync($"postmaster@{InboundFixture.BounceDomain}")).Code);
        Assert.Equal(250, (await mta.RcptAsync($"Abuse@{InboundFixture.BounceDomain}")).Code);
    }

    [Theory]
    [InlineData("b+invalidtoken@bounces.egg.test")]
    [InlineData("anyone@bounces.egg.test")]
    [InlineData("support@bounces.egg.test")]
    [InlineData("postmaster@bounce.dedicated.example")]   // postmaster exists at the shared bounce domain only
    [InlineData("b+invalidtoken@bounce.dedicated.example")]
    [InlineData("anyone@bounce.dedicated.example")]
    public async Task An_address_in_the_bounce_namespace_that_is_none_of_the_accepted_forms_is_550_5_1_1_and_never_an_inbound_recipient(string recipient)
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);

        var r = await mta.RcptAsync(recipient);

        Assert.Equal((550, "5.1.1"), (r.Code, r.Enhanced));
        Assert.Equal("No such user here", r.Text.Split(' ', 2)[1]);
    }

    [Fact]
    public async Task A_signed_token_at_a_verified_return_path_host_is_accepted_and_at_an_unverified_one_it_is_not_a_bounce_address()
    {
        string local = _f.Verp.CreateLocalPart(InboundFixture.Acme, _f.ExampleOrg, _f.Clock.Now, "dest.example");
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);

        Assert.Equal(250, (await mta.RcptAsync($"{local}@bounce.dedicated.example")).Code);

        // bounce.registered-only.example is not the verified return-path host of any domain: just an unknown domain.
        var unverified = await mta.RcptAsync($"{local}@bounce.registered-only.example");
        Assert.Equal((550, "5.7.1"), (unverified.Code, unverified.Enhanced));
    }

    [Fact]
    public async Task Without_a_bounce_domain_nothing_in_the_bounce_namespace_exists()
    {
        await using InboundFixture none = await InboundFixture.CreateAsync(bounceDomain: false);
        await using FakeMta mta = await none.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        var r = await mta.RcptAsync($"{BounceLocalPart()}@{InboundFixture.BounceDomain}");
        Assert.Equal((550, "5.7.1"), (r.Code, r.Enhanced));
    }

    // ------------------------------------------------------------------ one kind per transaction

    [Fact]
    public async Task A_bounce_recipient_and_an_inbound_recipient_cannot_share_a_transaction_in_either_order()
    {
        string bounce = $"{BounceLocalPart()}@{InboundFixture.BounceDomain}";
        await using FakeMta mta = await _f.ConnectedAsync();

        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync(bounce)).Code);
        var first = await mta.RcptAsync("support@example.org");
        Assert.Equal((452, "4.5.3"), (first.Code, first.Enhanced));
        await mta.CommandAsync("RSET");

        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        var second = await mta.RcptAsync(bounce);
        Assert.Equal((452, "4.5.3"), (second.Code, second.Enhanced));

        // The transaction that has the inbound recipient goes on, and so does a fresh one for the bounce address.
        Assert.Equal(250, (await mta.DataAsync(InboundFixture.Message())).Code);
        Assert.Equal(250, (await mta.SendAsync("", bounce, Dsn(bounce, "gone@dest.example"))).Code);
    }

    [Fact]
    public async Task An_srs_recipient_and_an_inbound_or_bounce_recipient_cannot_share_a_transaction()
    {
        string srs = Srs.CreateLocalPart("sender.test", "bob", _f.Clock.Now) + "@example.org";
        await using FakeMta mta = await _f.ConnectedAsync();

        Assert.Equal(250, (await mta.MailFromAsync("")).Code);
        Assert.Equal(250, (await mta.RcptAsync(srs)).Code);
        Assert.Equal(452, (await mta.RcptAsync("support@example.org")).Code);
        Assert.Equal(452, (await mta.RcptAsync($"{BounceLocalPart()}@{InboundFixture.BounceDomain}")).Code);
    }

    // ------------------------------------------------------------------ SRS

    [Fact]
    public async Task A_valid_srs_bounce_from_the_null_sender_is_accepted_and_dropped_without_a_stored_message_or_a_reply_message()
    {
        string srs = Srs.CreateLocalPart("sender.test", "bob", _f.Clock.Now) + "@example.org";
        using var capture = new MeterCapture("Mta.Inbound");
        await using FakeMta mta = await _f.ConnectedAsync();

        var reply = await mta.SendAsync("", srs, "From: MAILER-DAEMON@elsewhere.test\r\nSubject: Undelivered\r\n\r\nbody\r\n");

        Assert.Equal(250, reply.Code);
        Assert.Empty(await _f.StoredAsync(InboundFixture.Acme));
        Assert.Equal(0, await QueuedDeliveriesAsync());   // never relayed to the original sender
        Assert.True(capture.Sum("mta.inbound.recipients", ("outcome", "srs_bounce")) >= 1);   // other tests in the process count too
    }

    [Fact]
    public async Task An_srs_address_with_a_wrong_hash_a_stale_age_a_sender_or_the_srs1_form_is_550_5_1_1()
    {
        string valid = Srs.CreateLocalPart("sender.test", "bob", _f.Clock.Now);
        string forged = valid[..5] + (valid[5] == 'a' ? 'b' : 'a') + valid[6..];   // the first character of the hash is changed
        string stale = Srs.CreateLocalPart("sender.test", "bob", _f.Clock.Now.AddDays(-40));
        await using FakeMta mta = await _f.ConnectedAsync();

        Assert.Equal(250, (await mta.MailFromAsync("")).Code);
        foreach (string local in new[] { forged, stale, "SRS1=abcdefgh=example.org==abcdefgh=ab=sender.test=bob", "srs0=" })
        {
            var r = await mta.RcptAsync(local + "@example.org");
            Assert.Equal((550, "5.1.1"), (r.Code, r.Enhanced));
        }

        await mta.CommandAsync("RSET");
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);   // a valid address, but not from the null sender
        var fromSender = await mta.RcptAsync(valid + "@example.org");
        Assert.Equal((550, "5.1.1"), (fromSender.Code, fromSender.Enhanced));
        await mta.CommandAsync("RSET");

        Assert.Equal(250, (await mta.MailFromAsync("")).Code);
        Assert.Equal(550, (await mta.RcptAsync(valid.Replace("SRS0=", "srs0=x", StringComparison.Ordinal) + "@example.net")).Code);   // example.net has a catch-all route, but an SRS address is never an inbound recipient
    }

    [Fact]
    public async Task An_srs_address_at_a_domain_that_is_not_inbound_enabled_is_relay_denied()
    {
        string valid = Srs.CreateLocalPart("sender.test", "bob", _f.Clock.Now);
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("")).Code);
        var r = await mta.RcptAsync(valid + "@registered-only.example");
        Assert.Equal((550, "5.7.1"), (r.Code, r.Enhanced));
    }

    // ------------------------------------------------------------------ smuggling and STARTTLS injection

    [Fact]
    public async Task A_bare_lf_in_the_data_closes_the_connection_and_stores_nothing()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        Assert.Equal(354, (await mta.CommandAsync("DATA")).Code);

        await mta.SendRawAsync("Subject: x\r\n\r\nline one\nMAIL FROM:<evil@sender.test>\r\n.\r\n");
        var reply = await mta.ReadReplyAsync();

        Assert.Equal(500, reply.Code);
        Assert.True(await mta.IsClosedByServerAsync());
        Assert.Empty(await _f.StoredAsync(InboundFixture.Acme));
    }

    [Theory]
    [InlineData("Subject: x\r\n\r\nbody\r\n.\nMAIL FROM:<evil@sender.test>\r\nRCPT TO:<x@example.org>\r\nDATA\r\nsmuggled\r\n.\r\n")]
    [InlineData("Subject: x\r\n\r\nbody\r\n\r.\r\n")]
    [InlineData("Subject: x\r\n\r\nbody\r\n.\r\n\rsmuggled\r\n")]
    public async Task Smuggling_sequences_are_never_taken_for_the_end_of_the_message(string payload)
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        Assert.Equal(354, (await mta.CommandAsync("DATA")).Code);

        await mta.SendRawAsync(payload);
        // Either the connection is closed with 500, or the (well-formed) first message is accepted and the rest is not run as commands.
        _ = await TryReadAsync(mta);

        IReadOnlyList<InboundMessage> stored = await _f.StoredAsync(InboundFixture.Acme);
        Assert.True(stored.Count <= 1);
        Assert.DoesNotContain(stored, m => m.EnvelopeFrom == "evil@sender.test");
        Assert.Equal(0, await QueuedDeliveriesAsync());
    }

    private static async Task<FakeMta.Reply?> TryReadAsync(FakeMta mta)
    {
        try
        {
            return await mta.ReadReplyAsync();
        }
        catch (EndOfStreamException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    [Fact]
    public async Task A_bare_lf_in_a_bdat_chunk_closes_the_connection_and_stores_nothing()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        const string body = "Subject: x\r\n\r\nline\nbare\r\n";
        await mta.SendRawAsync($"BDAT {body.Length} LAST\r\n{body}");

        var reply = await TryReadAsync(mta);

        Assert.True(reply is null || reply.Code == 500);
        Assert.Empty(await _f.StoredAsync(InboundFixture.Acme));
    }

    [Fact]
    public async Task A_bdat_message_is_stored_like_a_data_message()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        string body = InboundFixture.Message();
        await mta.SendRawAsync($"BDAT {body.Length} LAST\r\n{body}");

        Assert.Equal(250, (await mta.ReadReplyAsync()).Code);
        InboundMessage m = Assert.Single(await _f.StoredAsync(InboundFixture.Acme));
        Assert.EndsWith("Hi there.\r\n", await _f.RawAsync(m));
    }

    [Fact]
    public async Task Plaintext_sent_behind_starttls_is_never_executed()
    {
        await using InboundFixture tls = await InboundFixture.CreateAsync(mode: ListenerMode.StartTls);
        await using FakeMta mta = await tls.ConnectedAsync();

        await mta.SendRawAsync("STARTTLS\r\nMAIL FROM:<evil@sender.test>\r\n");
        _ = await TryReadAsync(mta);

        Assert.True(await mta.IsClosedByServerAsync());
        Assert.Empty(await tls.StoredAsync(InboundFixture.Acme));
    }

    [Fact]
    public async Task Starttls_is_offered_but_never_required_and_the_tls_session_is_recorded()
    {
        await using InboundFixture tls = await InboundFixture.CreateAsync(mode: ListenerMode.StartTls);

        await using (FakeMta plain = await tls.ConnectAsync())
        {
            var ehlo = await plain.EhloAsync();
            Assert.Contains(ehlo.Lines, l => l.Contains("STARTTLS", StringComparison.Ordinal));
            Assert.Equal(250, (await plain.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message(subject: "plain"))).Code);
        }

        await using (FakeMta secure = await tls.ConnectAsync())
        {
            Assert.Equal(250, (await secure.EhloAsync()).Code);
            Assert.True(await secure.StartTlsAsync());
            var ehlo = await secure.EhloAsync();
            Assert.DoesNotContain(ehlo.Lines, l => l.Contains("STARTTLS", StringComparison.Ordinal));
            Assert.Equal(250, (await secure.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message(subject: "encrypted"))).Code);
        }

        IReadOnlyList<InboundMessage> stored = await tls.StoredAsync(InboundFixture.Acme);
        InboundMessage plainMessage = Assert.Single(stored, m => m.Subject == "plain");
        InboundMessage secureMessage = Assert.Single(stored, m => m.Subject == "encrypted");
        Assert.False(plainMessage.TlsUsed);
        Assert.True(secureMessage.TlsUsed);
        string raw = await tls.RawAsync(secureMessage);
        Assert.Contains("ESMTPS", raw);
        Assert.Contains("TLS", raw.Split("\r\n\r\n")[0], StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ header injection through the dialog

    [Fact]
    public async Task Odd_recipient_shapes_never_reach_a_route_by_accident()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);

        foreach (string path in new[] { "postmaster", "support", "support@", "@example.org", "support@example.org@gmail.com", "<support@example.org>", "support@[203.0.113.1]" })
        {
            var r = await mta.CommandAsync($"RCPT TO:<{path}>");
            Assert.NotEqual(250, r.Code);
        }
    }

    [Fact]
    public async Task A_helo_name_with_control_or_header_characters_is_refused_by_the_parser_and_the_stored_record_has_a_clean_name()
    {
        await using FakeMta mta = await _f.ConnectAsync();
        Assert.Equal(501, (await mta.CommandAsync("EHLO evil(x);y<z>")).Code);
        Assert.Equal(250, (await mta.CommandAsync("EHLO [IPv6:2001:db8::1]")).Code);   // an address literal is a legal name

        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message())).Code);

        InboundMessage m = Assert.Single(await _f.StoredAsync(InboundFixture.Acme));
        Assert.Equal("[IPv6:2001:db8::1]", m.Helo);
        string headers = (await _f.RawAsync(m)).Split("\r\n\r\n")[0];
        Assert.Equal(1, headers.Split("\r\n").Count(l => l.StartsWith("Received:", StringComparison.Ordinal)));
        Assert.Equal(1, headers.Split("\r\n").Count(l => l.StartsWith("Authentication-Results:", StringComparison.Ordinal)));
    }
}
