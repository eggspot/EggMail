using System.Text;
using Mta.Core;
using Mta.Dsn;
using Mta.Host.Ingest;
using Mta.Storage;
using Mta.Storage.InMemory;
using Mta.Webhooks;

namespace Mta.Host.Tests;

/// <summary>
/// The bounce listener is open to the internet and a bounce address is in the Return-Path of every message, so anyone who received one message
/// holds a valid token. What a report that arrives under a token may do must therefore be limited by what the token was issued for: the
/// destination domain of the message. Otherwise a stranger could get any address suppressed for a tenant (docs/decisions.md 92).
/// </summary>
internal static class BounceProcessorMetricsProbe
{
    public static void Touch() => System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(typeof(BounceMetrics).TypeHandle);
}

public class BounceTrustTests : IAsyncLifetime
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    private const string BounceDomain = "bounces.egg.test";

    private InMemoryStorage _storage = null!;
    private VerpCodec _verp = null!;
    private BounceProcessor _bounces = null!;

    public async Task InitializeAsync()
    {
        _storage = new InMemoryStorage(new StorageOptions());
        await _storage.InitializeAsync(default);
        await _storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, DateTimeOffset.UtcNow, false), default);
        _verp = new VerpCodec(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey() }, 1);
        _bounces = new BounceProcessor(_verp, _storage.Config, _storage.Stats, new StorageWebhookPublisher(_storage), SystemClock.Instance, history: _storage.History);
    }

    public async Task DisposeAsync() => await _storage.DisposeAsync();

    private string LocalPart(string? destinationDomain) => _verp.CreateLocalPart(TenantId, Ids.New(), DateTimeOffset.UtcNow, destinationDomain);

    private static byte[] Dsn(string to, string finalRecipient, string? originalRecipient = null, string status = "5.1.1")
    {
        string original = originalRecipient is null ? "" : $"Original-Recipient: rfc822;{originalRecipient}\r\n";
        return Encoding.ASCII.GetBytes(
            $"From: MAILER-DAEMON@remote.example\r\nTo: {to}\r\nSubject: Undelivered Mail Returned to Sender\r\nAuto-Submitted: auto-replied\r\n" +
            "Content-Type: multipart/report; report-type=delivery-status; boundary=\"BB\"\r\n\r\n" +
            "--BB\r\nContent-Type: text/plain\r\n\r\nCould not deliver.\r\n" +
            $"--BB\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; remote.example\r\n\r\nFinal-Recipient: rfc822; {finalRecipient}\r\n{original}Action: failed\r\nStatus: {status}\r\nDiagnostic-Code: smtp; 550 {status} No such user\r\n\r\n" +
            "--BB\r\nContent-Type: text/rfc822-headers\r\n\r\nMessage-ID: <orig@egg.test>\r\nSubject: x\r\n\r\n--BB--\r\n");
    }

    private static byte[] Complaint(string recipient) =>
        Encoding.ASCII.GetBytes(
            "From: fbl@isp.example\r\nTo: x@bounces.egg.test\r\nSubject: FW: spam\r\nContent-Type: multipart/report; report-type=feedback-report; boundary=\"FF\"\r\n\r\n" +
            "--FF\r\nContent-Type: text/plain\r\n\r\nAbuse report.\r\n" +
            $"--FF\r\nContent-Type: message/feedback-report\r\n\r\nFeedback-Type: abuse\r\nUser-Agent: SomeISP/1.0\r\nVersion: 1\r\nOriginal-Rcpt-To: <{recipient}>\r\n\r\n" +
            "--FF\r\nContent-Type: message/rfc822\r\n\r\nFrom: news@example.org\r\nMessage-ID: <orig@egg.test>\r\nSubject: Offer\r\n\r\nbody\r\n--FF--\r\n");

    private async Task<bool> SuppressedAsync(string address) => await _storage.Config.IsSuppressedAsync(TenantId, address, default);

    private async Task<int> WebhookItemsAsync() => (await _storage.Webhooks.ClaimDueAsync("w", 100, DateTimeOffset.UtcNow.AddSeconds(1), TimeSpan.FromMinutes(1), default)).Count;

    [Fact]
    public async Task A_report_naming_an_address_in_the_destination_domain_suppresses_it()
    {
        string local = LocalPart("dest.example");

        BounceOutcome outcome = await _bounces.ProcessAsync(local, Dsn(local + "@" + BounceDomain, "gone@dest.example"), default);

        Assert.Equal(BounceOutcome.Bounce, outcome);
        Assert.True(await SuppressedAsync("gone@dest.example"));
    }

    [Fact]
    public async Task A_forged_report_naming_somebody_elses_address_changes_nothing_even_with_a_valid_token()
    {
        // The attacker received one message from this tenant to dest.example, so holds a genuine token bound to dest.example.
        string local = LocalPart("dest.example");

        await _bounces.ProcessAsync(local, Dsn(local + "@" + BounceDomain, "victim@customer.example"), default);

        Assert.False(await SuppressedAsync("victim@customer.example"));
        Assert.Equal(0, await WebhookItemsAsync());
    }

    [Fact]
    public async Task Ignored_reports_are_counted_by_kind()
    {
        BounceProcessorMetricsProbe.Touch();
        using var capture = new MeterCapture("Mta.Bounce");
        string local = LocalPart("dest.example");

        await _bounces.ProcessAsync(local, Dsn(local + "@" + BounceDomain, "victim@customer.example"), default);
        await _bounces.ProcessAsync(local, Complaint("victim@customer.example"), default);
        await _bounces.ProcessAsync(local, Dsn(local + "@" + BounceDomain, "gone@dest.example"), default);   // acted on: not counted

        Assert.Equal(1, capture.Sum("mta.bounce.reports.ignored", ("kind", "bounce")));
        Assert.Equal(1, capture.Sum("mta.bounce.reports.ignored", ("kind", "complaint")));
    }

    [Fact]
    public async Task A_forged_complaint_naming_an_address_in_another_domain_changes_nothing()
    {
        string local = LocalPart("dest.example");

        BounceOutcome outcome = await _bounces.ProcessAsync(local, Complaint("victim@customer.example"), default);

        Assert.Equal(BounceOutcome.Complaint, outcome);
        Assert.False(await SuppressedAsync("victim@customer.example"));
        Assert.Equal(0, await WebhookItemsAsync());
    }

    [Fact]
    public async Task A_complaint_about_an_address_in_the_destination_domain_still_suppresses_it()
    {
        string local = LocalPart("dest.example");

        await _bounces.ProcessAsync(local, Complaint("reader@dest.example"), default);

        Assert.True(await SuppressedAsync("reader@dest.example"));
    }

    [Fact]
    public async Task A_forwarded_message_is_suppressed_under_the_address_it_was_sent_to_not_the_forwarding_target()
    {
        // alice@dest.example forwards to alice@mailbox.example, whose server sends the report: Final-Recipient is the target, Original-Recipient the address we used.
        string local = LocalPart("dest.example");

        await _bounces.ProcessAsync(local, Dsn(local + "@" + BounceDomain, "alice@mailbox.example", originalRecipient: "alice@dest.example"), default);

        Assert.True(await SuppressedAsync("alice@dest.example"));
        Assert.False(await SuppressedAsync("alice@mailbox.example"));
    }

    [Fact]
    public async Task A_forwarded_report_without_the_original_recipient_is_ignored_rather_than_guessed()
    {
        string local = LocalPart("dest.example");

        await _bounces.ProcessAsync(local, Dsn(local + "@" + BounceDomain, "alice@mailbox.example"), default);

        Assert.False(await SuppressedAsync("alice@mailbox.example"));
        Assert.False(await SuppressedAsync("alice@dest.example"));
    }

    [Fact]
    public async Task The_destination_domain_is_compared_case_insensitively_and_in_a_label_form()
    {
        string local = LocalPart("Bücher.example");

        await _bounces.ProcessAsync(local, Dsn(local + "@" + BounceDomain, "Gone@XN--BCHER-KVA.EXAMPLE"), default);

        Assert.True(await SuppressedAsync("gone@xn--bcher-kva.example"));
    }

    [Fact]
    public async Task A_token_issued_before_destinations_were_bound_keeps_working_while_it_is_in_flight()
    {
        string local = LocalPart(destinationDomain: null);   // version 1: no destination in the token

        await _bounces.ProcessAsync(local, Dsn(local + "@" + BounceDomain, "gone@dest.example"), default);

        Assert.True(await SuppressedAsync("gone@dest.example"));
    }
}
