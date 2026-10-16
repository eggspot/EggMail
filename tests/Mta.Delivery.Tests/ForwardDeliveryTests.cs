using System.Text;
using Mta.Core;
using Mta.Dkim;
using Mta.Dsn;
using Mta.Smtp.Protocol;
using Mta.Storage;

namespace Mta.Delivery.Tests;

/// <summary>
/// The delivery-engine rules for source Forward (decision 95, design section 11.7) through the whole outbound pipeline: the envelope is kept, the body is never converted, the signature is the route
/// domain's and only that, and a failure produces no bounce message of any kind.
/// </summary>
[Collection("delivery-pipeline")]
public class ForwardDeliveryTests
{
    private const string RouteDomain = "example.org";
    private const string Srs = "SRS0=abcdefgh=aa=other.test=alice@example.org";

    private sealed class IdentityProtector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => plaintext.ToArray();
        public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose) => protectedData.ToArray();
    }

    private static DeliveryFixture Fixture(bool eightBitMime = true, bool withVerp = true) =>
        new(
            o => new DeliveryOptions { Owner = o.Owner, Hostname = o.Hostname, RemotePort = o.RemotePort, IdlePoll = o.IdlePoll, ExpirySweepInterval = o.ExpirySweepInterval, BounceDomain = "bounces.egg.test", GenerateDsnForSmtpSubmissions = true, GenerateDsnForApiSubmissions = true },
            dkim: s => new ConfigDkimSignerProvider(s.Storage.Config, new IdentityProtector(), s.Clock),
            verp: withVerp ? new VerpCodec(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey() }, 1) : null,
            eightBitMime: eightBitMime);

    private static async Task<System.Security.Cryptography.RSA> AddKeyAsync(DeliveryFixture f)
    {
        var rsa = DkimKeyTools.GenerateRsa2048();
        var now = DateTimeOffset.UtcNow;
        var domainId = Ids.New();
        await f.Storage.Config.UpsertDomainAsync(new DomainRecord(domainId, DeliveryFixture.Tenant, RouteDomain, DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        await f.Storage.Config.AddDkimKeyAsync(new Mta.Storage.DkimKeyRecord(Ids.New(), domainId, "egg1", rsa.ExportPkcs8PrivateKey(), DkimKeyTools.ExportPublicKeyBase64(rsa), now, true, null), default);
        f.Dns.AddTxt("egg1._domainkey." + RouteDomain, DkimKeyTools.FormatDnsTxtValue(rsa));
        return rsa;
    }

    private const string ForeignHeaders = "Received: by relay\r\nFrom: Alice <alice@other.test>\r\nTo: bob@dest.example\r\nSubject: Hello\r\nMessage-ID: <orig@other.test>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n";

    [Fact]
    public async Task A_forward_keeps_its_srs_envelope_while_other_mail_gets_the_bounce_address()
    {
        await using var f = Fixture();
        byte[] raw = Encoding.ASCII.GetBytes(ForeignHeaders + "\r\nbody\r\n");

        var forward = await f.EnqueueRawAsync(raw, ["rcpt@dest.example"], from: Srs, source: MessageSource.Forward);
        await f.WaitForEventAsync(forward, MessageEventType.Delivered);
        var api = await f.EnqueueRawAsync(raw, ["rcpt2@dest.example"], from: "sender@example.org", source: MessageSource.Api);
        await f.WaitForEventAsync(api, MessageEventType.Delivered);

        Assert.Equal(Srs, f.Remote.Messages.Single(m => m.Recipients[0] == "rcpt@dest.example").Sender);
        Assert.EndsWith("@bounces.egg.test", f.Remote.Messages.Single(m => m.Recipients[0] == "rcpt2@dest.example").Sender);
    }

    [Fact]
    public async Task A_forward_with_the_null_reverse_path_stays_null()
    {
        await using var f = Fixture();
        var now = DateTimeOffset.UtcNow;
        var id = Ids.New(now);
        await f.Storage.Intake.AcceptAsync(new AcceptedMessage
        {
            MessageId = id, TenantId = DeliveryFixture.Tenant, Source = MessageSource.Forward, EnvelopeFrom = EmailAddress.Null,
            Recipients = [new AcceptedRecipient(Ids.New(now), EmailAddress.Parse("rcpt@dest.example"))], Raw = Encoding.ASCII.GetBytes(ForeignHeaders + "\r\nbody\r\n"),
            ReceivedAt = now, ExpiresAt = now.AddDays(1), SendingDomain = RouteDomain,
        }, default);
        f.Engine.Wake();

        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Equal(string.Empty, Assert.Single(f.Remote.Messages).Sender);
    }

    [Fact]
    public async Task A_forward_is_never_converted_to_7_bit_for_a_server_without_8bitmime()
    {
        await using var f = Fixture(eightBitMime: false);
        byte[] raw = Encoding.UTF8.GetBytes(ForeignHeaders + "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nGrüße aus München\r\n");

        var forward = await f.EnqueueRawAsync(raw, ["rcpt@dest.example"], from: Srs, source: MessageSource.Forward);
        var events = await f.WaitForEventAsync(forward, MessageEventType.Bounced);

        Assert.Empty(f.Remote.Messages);   // nothing was sent, converted or not
        Assert.Equal("5.6.1", events.Single(e => e.Type == MessageEventType.Bounced).EnhancedCode);

        // The same message from an ordinary source is converted and delivered, as before.
        var ordinary = await f.EnqueueRawAsync(raw, ["rcpt2@dest.example"], source: MessageSource.Smtp);
        await f.WaitForEventAsync(ordinary, MessageEventType.Delivered);
        Assert.Single(f.Remote.Messages);
    }

    [Fact]
    public async Task A_forward_to_a_server_with_8bitmime_arrives_byte_for_byte()
    {
        await using var f = Fixture();
        byte[] raw = Encoding.UTF8.GetBytes(ForeignHeaders + "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nGrüße aus München\r\n" + new string('x', 5000) + "\r\n");

        var forward = await f.EnqueueRawAsync(raw, ["rcpt@dest.example"], from: Srs, source: MessageSource.Forward);
        await f.WaitForEventAsync(forward, MessageEventType.Delivered);

        Assert.Equal(raw, Assert.Single(f.Remote.Messages).Body);   // no key for the route's domain: unsigned, and so unchanged
    }

    [Fact]
    public async Task A_forward_is_signed_with_the_route_domain_only_and_the_original_signature_stays_byte_identical()
    {
        await using var f = Fixture();
        using var rsa = await AddKeyAsync(f);
        const string original = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=other.test; s=sel; h=from:to:subject; bh=AAAA; b=BBBB\r\n";
        byte[] raw = Encoding.ASCII.GetBytes(original + ForeignHeaders + "\r\nbody\r\n");

        var forward = await f.EnqueueRawAsync(raw, ["rcpt@dest.example"], from: Srs, source: MessageSource.Forward, sendingDomain: RouteDomain);
        await f.WaitForEventAsync(forward, MessageEventType.Delivered);

        byte[] body = Assert.Single(f.Remote.Messages).Body;
        string text = Encoding.ASCII.GetString(body);
        // One signature was added, on top, with the route's domain; the original header is where it was, untouched, and nothing names the From domain as the signer.
        Assert.StartsWith("DKIM-Signature:", text, StringComparison.Ordinal);
        Assert.Contains("d=example.org", text[..text.IndexOf("\r\n", StringComparison.Ordinal)], StringComparison.Ordinal);
        Assert.EndsWith(Encoding.ASCII.GetString(raw), text, StringComparison.Ordinal);
        Assert.Equal(2, System.Text.RegularExpressions.Regex.Matches(text, "(?im)^DKIM-Signature:").Count);
        Assert.DoesNotContain("d=other.test; s=egg1", text, StringComparison.Ordinal);
        DkimVerificationResult added = (await new DkimVerifier(f.Dns).VerifyAsync(body)).First(r => r.Domain == RouteDomain);
        Assert.Equal(DkimStatus.Pass, added.Status);
    }

    [Fact]
    public async Task A_forward_that_fails_produces_no_bounce_message_of_any_kind_even_with_every_option_on()
    {
        await using var f = Fixture();
        f.Remote.OnRecipient = _ => SmtpReply.Create(550, "5.1.1", "no such user");
        var forward = await f.EnqueueRawAsync(Encoding.ASCII.GetBytes(ForeignHeaders + "\r\nbody\r\n"), ["rcpt@dest.example"], from: Srs, source: MessageSource.Forward);

        await f.WaitForEventAsync(forward, MessageEventType.Bounced);

        // The bounce of an ordinary message is queued before its failure is recorded, so by the time the event exists a bounce would be in the queue.
        QueueStats stats = await f.Storage.Deliveries.GetQueueStatsAsync(default);
        Assert.Equal(0, stats.Queued + stats.Deferred + stats.Leased);
    }
}
