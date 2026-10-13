using System.Text;
using Mta.Core;
using Mta.Dkim;
using Mta.Dsn;
using Mta.Mime;
using Mta.Smtp.Protocol;
using Mta.Storage;
using Mta.Tls;
using Mta.Tls.MtaSts;
using Mta.Tls.TlsRpt;

namespace Mta.Delivery.Tests;

/// <summary>
/// 8-bit bodies (RFC 6152) and internationalized mail (RFC 6531/6533) through the whole outbound pipeline against a loopback
/// receiving server that does or does not advertise 8BITMIME and SMTPUTF8.
/// </summary>
public class EightBitAndInternationalDeliveryTests
{
    private const string AsciiHeaders = "From: sender@example.org\r\nTo: rcpt@dest.example\r\nSubject: Hello\r\nMessage-ID: <t@example.org>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n";
    private const string Utf8Text = "Grüße aus München, a longer line that is mostly plain ASCII text.\r\nZweite Zeile mit Gedankenstrich\r\n";

    private static byte[] EightBitMessage(string headers = AsciiHeaders) =>
        Encoding.UTF8.GetBytes(headers + "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + Utf8Text);

    private static byte[] AsciiMessage() => Encoding.ASCII.GetBytes(AsciiHeaders + "\r\nplain body\r\n");

    private static void AllowBounces(DeliveryFixture f) => f.Dns.AddMx("example.org", 10, "mx.example.org").AddA("mx.example.org", "127.0.0.1");

    private sealed class IdentityProtector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => plaintext.ToArray();
        public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose) => protectedData.ToArray();
    }

    private static async Task AddDkimKeyAsync(DeliveryFixture f)
    {
        using var rsa = DkimKeyTools.GenerateRsa2048();
        var now = DateTimeOffset.UtcNow;
        var domainId = Ids.New();
        await f.Storage.Config.UpsertDomainAsync(new DomainRecord(domainId, DeliveryFixture.Tenant, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        await f.Storage.Config.AddDkimKeyAsync(new Mta.Storage.DkimKeyRecord(Ids.New(), domainId, "egg1", rsa.ExportPkcs8PrivateKey(), DkimKeyTools.ExportPublicKeyBase64(rsa), now, true, null), default);
        f.Dns.AddTxt("egg1._domainkey.example.org", DkimKeyTools.FormatDnsTxtValue(rsa));
    }

    private static DeliveryFixture Signed(bool eightBitMime = true, bool smtpUtf8 = true) =>
        new(dkim: s => new ConfigDkimSignerProvider(s.Storage.Config, new IdentityProtector(), s.Clock), eightBitMime: eightBitMime, smtpUtf8: smtpUtf8);

    // ------------------------------------------------------------------ 8BITMIME

    [Fact]
    public async Task An_8bit_body_is_declared_with_BODY_8BITMIME_and_sent_unchanged_when_the_server_offers_it()
    {
        await using var f = new DeliveryFixture();
        byte[] raw = EightBitMessage();
        var id = await f.EnqueueRawAsync(raw, ["rcpt@dest.example"]);

        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        var msg = Assert.Single(f.Remote.Messages);
        Assert.Equal(SmtpBodyType.EightBitMime, msg.BodyType);
        Assert.False(msg.SmtpUtf8);
        Assert.Equal(raw, msg.Body);
    }

    [Fact]
    public async Task An_ascii_message_is_sent_without_any_extension_parameter()
    {
        await using var f = new DeliveryFixture();
        var id = await f.EnqueueRawAsync(AsciiMessage(), ["rcpt@dest.example"]);

        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        var msg = Assert.Single(f.Remote.Messages);
        Assert.Equal(SmtpBodyType.SevenBit, msg.BodyType);
        Assert.False(msg.SmtpUtf8);
    }

    [Fact]
    public async Task An_8bit_body_is_converted_to_quoted_printable_for_a_server_without_8BITMIME()
    {
        await using var f = new DeliveryFixture(eightBitMime: false);
        var id = await f.EnqueueRawAsync(EightBitMessage(), ["rcpt@dest.example"]);

        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        var msg = Assert.Single(f.Remote.Messages);
        Assert.Equal(SmtpBodyType.SevenBit, msg.BodyType);
        Assert.False(MessageInspector.HasEightBitBody(msg.Body));
        string text = Encoding.ASCII.GetString(msg.Body);
        Assert.Contains("Content-Transfer-Encoding: quoted-printable\r\n", text, StringComparison.Ordinal);
        Assert.Contains("Subject: Hello\r\n", text, StringComparison.Ordinal);
        var parsed = MimeMessage.Parse(msg.Body);
        Assert.Equal(Utf8Text, Encoding.UTF8.GetString(parsed.Root.GetDecodedBytes()));
    }

    [Fact]
    public async Task The_converted_message_is_dkim_signed_over_the_bytes_that_are_sent()
    {
        await using var f = Signed(eightBitMime: false);
        await AddDkimKeyAsync(f);
        var id = await f.EnqueueRawAsync(EightBitMessage(), ["rcpt@dest.example"]);

        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        var msg = Assert.Single(f.Remote.Messages);
        Assert.StartsWith("DKIM-Signature:", Encoding.ASCII.GetString(msg.Body), StringComparison.Ordinal);
        Assert.False(MessageInspector.HasEightBitBody(msg.Body));
        var result = Assert.Single(await new DkimVerifier(f.Dns).VerifyAsync(msg.Body));
        Assert.Equal(DkimStatus.Pass, result.Status);

        // A signature made over the 8-bit original would not survive the conversion: changing the body must break this one.
        byte[] tampered = (byte[])msg.Body.Clone();
        int at = Encoding.ASCII.GetString(tampered).IndexOf("Gr=C3=BC", StringComparison.Ordinal);
        tampered[at + 2] = (byte)'X';
        Assert.Equal(DkimStatus.Fail, Assert.Single(await new DkimVerifier(f.Dns).VerifyAsync(tampered)).Status);
    }

    [Fact]
    public async Task The_unconverted_8bit_message_is_signed_too_and_verifies()
    {
        await using var f = Signed();
        await AddDkimKeyAsync(f);
        var id = await f.EnqueueRawAsync(EightBitMessage(), ["rcpt@dest.example"]);

        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        var msg = Assert.Single(f.Remote.Messages);
        Assert.Equal(SmtpBodyType.EightBitMime, msg.BodyType);
        Assert.Equal(DkimStatus.Pass, Assert.Single(await new DkimVerifier(f.Dns).VerifyAsync(msg.Body)).Status);
    }

    [Fact]
    public async Task A_conversion_after_an_unreachable_first_mx_is_signed_and_verifies()
    {
        // The preferred MX does not answer, the backup lacks 8BITMIME: the message is converted and signed for the host that does answer.
        await using var f = Signed(eightBitMime: false);
        await AddDkimKeyAsync(f);
        f.Dns.AddMx("dual.example", 5, "down.dual.example").AddA("down.dual.example", "127.0.0.2").AddMx("dual.example", 10, "mx.dest.example");
        var id = await f.EnqueueRawAsync(EightBitMessage(), ["rcpt@dual.example"]);

        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        var msg = Assert.Single(f.Remote.Messages);
        Assert.Equal(DkimStatus.Pass, Assert.Single(await new DkimVerifier(f.Dns).VerifyAsync(msg.Body)).Status);
    }

    [Fact]
    public async Task A_message_that_cannot_be_made_7bit_is_bounced_with_a_clear_reason_and_the_recipient_is_not_suppressed()
    {
        await using var f = new DeliveryFixture(eightBitMime: false);
        AllowBounces(f);
        // An embedded message whose own header fields are 8-bit: RFC 2045 forbids encoding it as a whole and header downgrading is out of scope.
        byte[] raw = Encoding.UTF8.GetBytes(AsciiHeaders + "MIME-Version: 1.0\r\nContent-Type: message/rfc822\r\n\r\nFrom: jürgen@example.org\r\nSubject: Grüße\r\n\r\nGrüße\r\n");
        var id = await f.EnqueueRawAsync(raw, ["rcpt@dest.example"]);

        var events = await f.WaitForEventAsync(id, MessageEventType.Bounced);

        var bounced = events.Single(e => e.Type == MessageEventType.Bounced);
        Assert.Equal("5.6.1", bounced.EnhancedCode);
        Assert.Contains("8BITMIME", bounced.Message, StringComparison.Ordinal);
        Assert.Contains("header", bounced.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(await f.Storage.Config.IsSuppressedAsync(DeliveryFixture.Tenant, "rcpt@dest.example", default));
        await DeliveryFixture.WaitAsync(() => f.Remote.Messages.Any(m => m.Recipients.Contains("sender@example.org")));
        Assert.DoesNotContain(f.Remote.Messages, m => m.Recipients.Contains("rcpt@dest.example"));
        var dsn = f.Remote.Messages.First(m => m.Recipients.Contains("sender@example.org"));
        Assert.Contains("Status: 5.6.1", Encoding.UTF8.GetString(dsn.Body), StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ SMTPUTF8

    [Fact]
    public async Task Utf8_headers_with_ascii_addresses_are_sent_with_SMTPUTF8()
    {
        await using var f = new DeliveryFixture();
        string headers = "From: Jürgen <sender@example.org>\r\nTo: rcpt@dest.example\r\nSubject: Grüße\r\nMessage-ID: <u@example.org>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n";
        byte[] raw = EightBitMessage(headers);
        var id = await f.EnqueueRawAsync(raw, ["rcpt@dest.example"]);

        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        var msg = Assert.Single(f.Remote.Messages);
        Assert.True(msg.SmtpUtf8);
        Assert.Equal(SmtpBodyType.EightBitMime, msg.BodyType);
        Assert.Equal(raw, msg.Body);
    }

    [Fact]
    public async Task Utf8_headers_are_never_sent_to_a_server_without_SMTPUTF8_and_bounce_with_5_6_9()
    {
        await using var f = new DeliveryFixture(smtpUtf8: false);
        AllowBounces(f);
        string headers = "From: Jürgen <sender@example.org>\r\nTo: rcpt@dest.example\r\nSubject: Grüße\r\nMessage-ID: <u@example.org>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n";
        var id = await f.EnqueueRawAsync(EightBitMessage(headers), ["rcpt@dest.example"]);

        var events = await f.WaitForEventAsync(id, MessageEventType.Bounced);

        var bounced = events.Single(e => e.Type == MessageEventType.Bounced);
        Assert.Equal("5.6.9", bounced.EnhancedCode);
        Assert.Contains("SMTPUTF8", bounced.Message, StringComparison.Ordinal);
        await DeliveryFixture.WaitAsync(() => f.Remote.Messages.Any(m => m.Recipients.Contains("sender@example.org")));
        Assert.DoesNotContain(f.Remote.Messages, m => m.Recipients.Contains("rcpt@dest.example"));
    }

    [Fact]
    public async Task A_second_mx_that_offers_SMTPUTF8_takes_the_message_the_first_mx_could_not()
    {
        if (!System.Net.Sockets.Socket.OSSupportsIPv6)
        {
            return;   // the second server listens on the IPv6 loopback address, on the same port
        }

        await using var f = new DeliveryFixture(smtpUtf8: false);
        var second = new RemoteServer();
        await using var secondServer = new Mta.Smtp.Server.SmtpServer(new Mta.Smtp.Server.SmtpServerOptions
        {
            Hostname = "mx2.dual.example",
            Listeners = [new Mta.Smtp.Server.SmtpListenerOptions { Name = "mx2", BindAddress = System.Net.IPAddress.IPv6Loopback, Port = f.Port, Mode = Mta.Smtp.Server.ListenerMode.Plain, AuthRequired = false, Role = Mta.Smtp.Server.ListenerRole.Bounce }],
        }, second);
        secondServer.Start();
        f.Dns.AddMx("dual.example", 10, "mx1.dual.example").AddA("mx1.dual.example", "127.0.0.1")
            .AddMx("dual.example", 20, "mx2.dual.example").AddAaaa("mx2.dual.example", "::1");
        string headers = "From: Jürgen <sender@example.org>\r\nTo: rcpt@dual.example\r\nSubject: Grüße\r\nMessage-ID: <d@example.org>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n";
        var id = await f.EnqueueRawAsync(EightBitMessage(headers), ["rcpt@dual.example"]);

        var events = await f.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.DoesNotContain(events, e => e.Type == MessageEventType.Bounced);
        Assert.Empty(f.Remote.Messages);
        var msg = Assert.Single(second.Messages);
        Assert.True(msg.SmtpUtf8);
        Assert.Equal("mx2.dual.example", events.Single(e => e.Type == MessageEventType.Delivered).MxHost);
    }

    [Fact]
    public async Task The_message_bounces_when_every_mx_that_answers_lacks_the_extension_but_waits_when_one_is_unreachable()
    {
        await using var f = new DeliveryFixture(smtpUtf8: false);
        AllowBounces(f);
        f.Dns.AddMx("flaky.example", 10, "mx1.flaky.example").AddA("mx1.flaky.example", "127.0.0.1")
            .AddMx("flaky.example", 20, "mx2.flaky.example").AddA("mx2.flaky.example", "127.0.0.9");   // nothing listens there
        string headers = "From: Jürgen <sender@example.org>\r\nTo: rcpt@flaky.example\r\nSubject: Grüße\r\nMessage-ID: <d@example.org>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n";
        var id = await f.EnqueueRawAsync(EightBitMessage(headers), ["rcpt@flaky.example"]);

        var events = await f.WaitForEventAsync(id, MessageEventType.Deferred);

        Assert.DoesNotContain(events, e => e.Type == MessageEventType.Bounced);   // not final: the second host may take it later
        Assert.Empty(f.Remote.Messages);
    }

    [Fact]
    public async Task The_persisted_smtputf8_flag_alone_makes_delivery_require_the_extension()
    {
        await using var f = new DeliveryFixture(smtpUtf8: false);
        AllowBounces(f);
        // The stored flag says the headers are internationalized even though this copy of the bytes is ASCII: it is believed.
        var id = await f.EnqueueRawAsync(AsciiMessage(), ["rcpt@dest.example"], smtpUtf8: true);

        var events = await f.WaitForEventAsync(id, MessageEventType.Bounced);

        Assert.Equal("5.6.9", events.Single(e => e.Type == MessageEventType.Bounced).EnhancedCode);
    }

    [Fact]
    public async Task An_internationalized_recipient_is_sent_with_SMTPUTF8_when_the_server_offers_it()
    {
        await using var f = new DeliveryFixture();
        var id = await f.EnqueueRawAsync(AsciiMessage(), ["пользователь@dest.example"]);

        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        var msg = Assert.Single(f.Remote.Messages);
        Assert.True(msg.SmtpUtf8);
        Assert.Equal(["пользователь@dest.example"], msg.Recipients);
    }

    [Fact]
    public async Task Without_SMTPUTF8_the_ascii_recipients_are_delivered_and_the_internationalized_one_gets_a_global_status_bounce()
    {
        await using var f = new DeliveryFixture(smtpUtf8: false);
        AllowBounces(f);
        var id = await f.EnqueueRawAsync(AsciiMessage(), ["plain@dest.example", "пользователь@dest.example"]);

        var events = await f.WaitForEventAsync(id, MessageEventType.Bounced);
        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        var bounced = events.Single(e => e.Type == MessageEventType.Bounced);
        Assert.Equal("пользователь@dest.example", bounced.Recipient);
        Assert.Equal("5.6.7", bounced.EnhancedCode);
        Assert.False(await f.Storage.Config.IsSuppressedAsync(DeliveryFixture.Tenant, "пользователь@dest.example", default));
        var delivered = f.Remote.Messages.Single(m => m.Recipients.Contains("plain@dest.example"));
        Assert.Equal(["plain@dest.example"], delivered.Recipients);
        Assert.False(delivered.SmtpUtf8);

        await DeliveryFixture.WaitAsync(() => f.Remote.Messages.Any(m => m.Recipients.Contains("sender@example.org")));
        var dsn = f.Remote.Messages.First(m => m.Recipients.Contains("sender@example.org"));
        Assert.Equal(string.Empty, dsn.Sender);
        Assert.Equal(SmtpBodyType.EightBitMime, dsn.BodyType);   // UTF-8 in the machine-readable part
        var parsed = MimeMessage.Parse(dsn.Body);
        var status = parsed.Root.Children[1];
        Assert.Equal("message/global-delivery-status", status.ContentType.MimeType);
        Assert.Contains("Final-Recipient: utf-8; пользователь@dest.example", Encoding.UTF8.GetString(status.Body.Span), StringComparison.Ordinal);
        var report = InboundReportParser.Parse(dsn.Body);
        Assert.Contains(report.Recipients, r => r.FinalRecipient == "пользователь@dest.example" && r.IsPermanentFailure);
    }

    [Fact]
    public async Task Without_SMTPUTF8_and_8BITMIME_the_global_status_report_is_converted_to_7bit_and_still_parses()
    {
        await using var f = new DeliveryFixture(smtpUtf8: false, eightBitMime: false);
        AllowBounces(f);
        var id = await f.EnqueueRawAsync(AsciiMessage(), ["пользователь@dest.example"]);

        await f.WaitForEventAsync(id, MessageEventType.Bounced);

        await DeliveryFixture.WaitAsync(() => f.Remote.Messages.Any(m => m.Recipients.Contains("sender@example.org")));
        var dsn = f.Remote.Messages.First(m => m.Recipients.Contains("sender@example.org"));
        Assert.Equal(SmtpBodyType.SevenBit, dsn.BodyType);
        Assert.False(MessageInspector.HasEightBitBody(dsn.Body));
        var report = InboundReportParser.Parse(dsn.Body);
        Assert.Contains(report.Recipients, r => r.FinalRecipient == "пользователь@dest.example" && r.IsPermanentFailure && r.Status == "5.6.7");
    }

    [Fact]
    public async Task An_internationalized_sender_is_refused_by_a_server_without_SMTPUTF8_but_a_bounce_address_makes_it_deliverable()
    {
        await using (var refused = new DeliveryFixture(smtpUtf8: false))
        {
            var id = await refused.EnqueueRawAsync(AsciiMessage(), ["rcpt@dest.example"], from: "пользователь@example.org");
            var events = await refused.WaitForEventAsync(id, MessageEventType.Bounced);
            Assert.Equal("5.6.7", events.Single(e => e.Type == MessageEventType.Bounced).EnhancedCode);
        }

        // With a bounce domain the envelope sender is a signed ASCII bounce address, so no extension is needed at all.
        var verp = new VerpCodec(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey() }, 1);
        await using var f = new DeliveryFixture(o => new DeliveryOptions { Owner = o.Owner, Hostname = o.Hostname, RemotePort = o.RemotePort, IdlePoll = o.IdlePoll, ExpirySweepInterval = o.ExpirySweepInterval, BounceDomain = "bounces.egg.test" }, verp: verp, smtpUtf8: false);
        var id2 = await f.EnqueueRawAsync(AsciiMessage(), ["rcpt@dest.example"], from: "пользователь@example.org");
        await f.WaitForEventAsync(id2, MessageEventType.Delivered);
        var msg = Assert.Single(f.Remote.Messages);
        Assert.EndsWith("@bounces.egg.test", msg.Sender, StringComparison.Ordinal);
        Assert.False(msg.SmtpUtf8);
    }

    [Fact]
    public async Task An_internationalized_bounce_domain_is_used_in_its_ascii_form_without_SMTPUTF8()
    {
        var verp = new VerpCodec(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey() }, 1);
        await using var f = new DeliveryFixture(o => new DeliveryOptions { Owner = o.Owner, Hostname = o.Hostname, RemotePort = o.RemotePort, IdlePoll = o.IdlePoll, ExpirySweepInterval = o.ExpirySweepInterval, BounceDomain = "bounces.пример.test" }, verp: verp, smtpUtf8: false);
        var id = await f.EnqueueRawAsync(AsciiMessage(), ["rcpt@dest.example"]);

        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        var msg = Assert.Single(f.Remote.Messages);
        Assert.EndsWith("@bounces.xn--e1afmkfd.test", msg.Sender, StringComparison.Ordinal);
        Assert.False(msg.SmtpUtf8);
    }

    [Fact]
    public async Task An_internationalized_domain_with_an_ascii_local_part_travels_as_ascii_and_needs_no_SMTPUTF8()
    {
        await using var f = new DeliveryFixture(smtpUtf8: false);
        f.Dns.AddMx("xn--e1afmkfd.example", 10, "mx.dest.example");
        var id = await f.EnqueueRawAsync(AsciiMessage(), ["user@пример.example"]);

        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        var msg = Assert.Single(f.Remote.Messages);
        Assert.Equal(["user@xn--e1afmkfd.example"], msg.Recipients);
        Assert.False(msg.SmtpUtf8);
    }

    // ------------------------------------------------------------------ TLS-RPT sending address

    private sealed class FixedPolicyFetcher(string body) : IMtaStsPolicyFetcher
    {
        public ValueTask<MtaStsFetchResult> FetchAsync(string domain, CancellationToken cancellationToken = default)
        {
            Assert.True(MtaStsPolicyParser.TryParse(body, out var policy, out string? error), error);
            return ValueTask.FromResult(new MtaStsFetchResult(policy, MtaStsFetchFailure.None, null));
        }
    }

    [Theory]
    [InlineData("enforce", "mx.dest.example")]   // the handshake is refused by the client: the address is carried by the failure
    [InlineData("enforce", "other.example")]     // the host is not in the policy, no connection is made: the address the OS would use
    public async Task Tls_rpt_failure_records_carry_the_real_sending_address(string mode, string policyMx)
    {
        var collector = new TlsRptCollector();
        var fetcher = new FixedPolicyFetcher($"version: STSv1\nmode: {mode}\nmx: {policyMx}\nmax_age: 86400\n");
        await using var f = new DeliveryFixture(serverTls: true, tlsReports: collector,
            tlsResolver: dns => new OutboundTlsPolicyResolver(new MtaStsPolicyStore(dns, fetcher, new InMemoryMtaStsCache(SystemClock.Instance), SystemClock.Instance), null));
        f.Dns.AddTxt("_mta-sts.dest.example", "v=STSv1; id=1");
        await f.EnqueueRawAsync(AsciiMessage(), ["rcpt@dest.example"]);

        await DeliveryFixture.WaitAsync(() => collector.Snapshot().Any(d => d.Policies.Any(p => p.FailureCount > 0)));

        var detail = collector.Snapshot().SelectMany(d => d.Policies).SelectMany(p => p.FailureDetails).First();
        Assert.Equal("127.0.0.1", detail.SendingMtaIp);
    }
}
