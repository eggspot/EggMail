using System.Text;
using Mta.Core;
using Mta.Dsn;
using Mta.Host.Ingest;
using Mta.Host.Submission;
using Mta.Mime;
using Mta.Policy;
using Mta.Storage;
using Mta.Storage.InMemory;
using Mta.Webhooks;

namespace Mta.Host.Tests;

/// <summary>
/// A bounce address is bound to a destination domain, not an address, so a recipient at <c>dest.example</c> holds a token that verifies for every
/// <c>dest.example</c> address (decision 92). With per-message history a report is acted on only when the address it names is a recorded recipient of the
/// message it quotes; anything else is ignored: no suppression, no webhook, no statistics (decision 112, gap G3).
/// </summary>
[Collection("bounce-history")]   // the ignored-report counter is a process-wide static instrument; AsyncReportHistoryTests also produces these reasons
public class BounceHistoryConfirmationTests : IAsyncLifetime
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    private const string BounceDomain = "bounces.egg.test";

    private InMemoryStorage _storage = null!;
    private VerpCodec _verp = null!;
    private BounceProcessor _bounces = null!;
    private SubmissionService _submission = null!;

    public async Task InitializeAsync()
    {
        var options = new StorageOptions { History = new HistoryOptions { Mode = HistoryMode.Full } };
        _storage = new InMemoryStorage(options);
        await _storage.InitializeAsync(default);
        var now = DateTimeOffset.UtcNow;
        await _storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, now, false), default);
        await _storage.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), TenantId, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        await _storage.Config.UpsertWebhookEndpointAsync(
            new WebhookEndpointRecord(Ids.New(), TenantId, "https://hooks.example/x", [1, 2, 3], [WebhookEventFactory.Bounced, WebhookEventFactory.Complained], true, null, null, now, null), default);
        _verp = new VerpCodec(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey() }, 1);
        _bounces = new BounceProcessor(_verp, _storage.Config, _storage.Stats, new StorageWebhookPublisher(_storage), SystemClock.Instance, history: _storage.History);
        _submission = new SubmissionService(_storage, SystemClock.Instance, new SenderPolicy(), options, new SubmissionOptions { MessageIdDomain = "egg.test", DomainCacheTtl = TimeSpan.Zero });
    }

    public async Task DisposeAsync() => await _storage.DisposeAsync();

    /// <summary>Submits a message to <paramref name="recipients"/> and returns its id and the Message-ID header the server stored.</summary>
    private async Task<(Guid Id, string MessageIdHeader)> SendAsync(params string[] recipients)
    {
        string raw = $"From: Acme <news@example.org>\r\nTo: {string.Join(", ", recipients)}\r\nSubject: Hi\r\n\r\nbody\r\n";
        SubmissionResult result = await _submission.SubmitAsync(new SubmissionRequest
        {
            Tenant = (await _storage.Config.GetTenantAsync(TenantId, default))!,
            Source = MessageSource.Api,
            EnvelopeFrom = EmailAddress.Parse("news@example.org"),
            Recipients = [.. recipients.Select(r => EmailAddress.Parse(r))],
            Message = Encoding.ASCII.GetBytes(raw),
        }, default);
        Assert.Equal(SubmissionStatus.Accepted, result.Status);
        byte[] stored = (await _storage.Deliveries.GetRawAsync(result.MessageId, default))!;
        return (result.MessageId, MimeMessage.Parse(stored).Headers.GetFirstValue("Message-ID")!);
    }

    private string LocalPart(string? destinationDomain = "dest.example") => _verp.CreateLocalPart(TenantId, Ids.New(), DateTimeOffset.UtcNow, destinationDomain);

    private static byte[] Dsn(string local, string finalRecipient, string? messageId, string? originalRecipient = null)
    {
        string original = originalRecipient is null ? "" : $"Original-Recipient: rfc822;{originalRecipient}\r\n";
        string returned = messageId is null ? "" : $"--BB\r\nContent-Type: text/rfc822-headers\r\n\r\nMessage-ID: {messageId}\r\nSubject: Hi\r\n\r\n";
        return Encoding.ASCII.GetBytes(
            $"From: MAILER-DAEMON@remote.example\r\nTo: {local}@{BounceDomain}\r\nSubject: Undelivered Mail Returned to Sender\r\nAuto-Submitted: auto-replied\r\n" +
            "Content-Type: multipart/report; report-type=delivery-status; boundary=\"BB\"\r\n\r\n" +
            "--BB\r\nContent-Type: text/plain\r\n\r\nCould not deliver.\r\n" +
            $"--BB\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; remote.example\r\n\r\nFinal-Recipient: rfc822; {finalRecipient}\r\n{original}Action: failed\r\nStatus: 5.1.1\r\nDiagnostic-Code: smtp; 550 5.1.1 No such user\r\n\r\n" +
            returned + "--BB--\r\n");
    }

    private static byte[] Complaint(string local, string recipient, string messageId) =>
        Encoding.ASCII.GetBytes(
            $"From: fbl@isp.example\r\nTo: {local}@{BounceDomain}\r\nSubject: FW: spam\r\nContent-Type: multipart/report; report-type=feedback-report; boundary=\"FF\"\r\n\r\n" +
            "--FF\r\nContent-Type: text/plain\r\n\r\nAbuse report.\r\n" +
            $"--FF\r\nContent-Type: message/feedback-report\r\n\r\nFeedback-Type: abuse\r\nUser-Agent: SomeISP/1.0\r\nVersion: 1\r\nOriginal-Rcpt-To: <{recipient}>\r\n\r\n" +
            $"--FF\r\nContent-Type: message/rfc822\r\n\r\nFrom: news@example.org\r\nMessage-ID: {messageId}\r\nSubject: Hi\r\n\r\nbody\r\n--FF--\r\n");

    private async Task<bool> SuppressedAsync(string address) => await _storage.Config.IsSuppressedAsync(TenantId, address, default);

    private async Task<int> WebhookItemsAsync() => (await _storage.Webhooks.ClaimDueAsync("w", 100, DateTimeOffset.UtcNow.AddSeconds(1), TimeSpan.FromMinutes(1), default)).Count;

    private async Task<IEnumerable<MessageEventType>> EventTypesAsync(Guid id) => (await _storage.History.GetEventsAsync(TenantId, id, default)).Select(e => e.Type);

    [Fact]
    public async Task A_report_about_a_recipient_of_the_quoted_message_suppresses_it_and_is_attached()
    {
        var (id, header) = await SendAsync("gone@dest.example");

        Assert.Equal(BounceOutcome.Bounce, await _bounces.ProcessAsync(LocalPart(), Dsn(LocalPart(), "Gone@Dest.Example", header), default));

        Assert.True(await SuppressedAsync("gone@dest.example"));
        Assert.Contains(MessageEventType.Bounced, await EventTypesAsync(id));
        Assert.Equal(1, await WebhookItemsAsync());
    }

    [Fact]
    public async Task A_forged_report_naming_another_address_in_the_same_domain_changes_nothing()
    {
        // The attacker received a message to dest.example, so holds a genuine token for dest.example and the genuine Message-ID of that message.
        var (id, header) = await SendAsync("attacker@dest.example");
        string local = LocalPart();

        await _bounces.ProcessAsync(local, Dsn(local, "victim@dest.example", header), default);
        await _bounces.ProcessAsync(local, Complaint(local, "victim@dest.example", header), default);

        Assert.False(await SuppressedAsync("victim@dest.example"));
        Assert.Equal(0, await WebhookItemsAsync());
        Assert.Equal([MessageEventType.Queued], await EventTypesAsync(id));
    }

    [Fact]
    public async Task A_report_that_quotes_no_message_id_or_an_unknown_one_changes_nothing()
    {
        await SendAsync("gone@dest.example");
        string local = LocalPart();

        await _bounces.ProcessAsync(local, Dsn(local, "gone@dest.example", messageId: null), default);           // an attacker can always leave the original out
        await _bounces.ProcessAsync(local, Dsn(local, "gone@dest.example", "<never.sent@egg.test>"), default);

        Assert.False(await SuppressedAsync("gone@dest.example"));
        Assert.Equal(0, await WebhookItemsAsync());
    }

    [Fact]
    public async Task Ignored_reports_are_counted_by_reason()
    {
        BounceProcessorMetricsProbe.Touch();
        using var capture = new MeterCapture("Mta.Bounce");
        var (_, header) = await SendAsync("reader@dest.example");
        string local = LocalPart();

        await _bounces.ProcessAsync(local, Dsn(local, "victim@dest.example", header), default);
        await _bounces.ProcessAsync(local, Complaint(local, "victim@dest.example", header), default);
        await _bounces.ProcessAsync(local, Dsn(local, "reader@dest.example", messageId: null), default);
        await _bounces.ProcessAsync(local, Complaint(local, "reader@dest.example", header), default);   // confirmed: not counted

        Assert.Equal(1, capture.Sum("mta.bounce.reports.ignored", ("kind", "bounce"), ("reason", "not_in_history")));
        Assert.Equal(1, capture.Sum("mta.bounce.reports.ignored", ("kind", "complaint"), ("reason", "not_in_history")));
        Assert.Equal(1, capture.Sum("mta.bounce.reports.ignored", ("kind", "bounce"), ("reason", "no_message_id")));
        Assert.True(await SuppressedAsync("reader@dest.example"));
    }

    [Fact]
    public async Task A_forwarded_message_is_confirmed_through_the_original_recipient()
    {
        // alice@dest.example forwards to bob@dest.example (same provider, not a recipient of ours): Final-Recipient is the target, Original-Recipient the address we used.
        var (id, header) = await SendAsync("alice@dest.example");
        string local = LocalPart();

        await _bounces.ProcessAsync(local, Dsn(local, "bob@dest.example", header, originalRecipient: "alice@dest.example"), default);

        Assert.True(await SuppressedAsync("alice@dest.example"));
        Assert.False(await SuppressedAsync("bob@dest.example"));
        MessageEvent bounce = (await _storage.History.GetEventsAsync(TenantId, id, default)).Single(e => e.Type == MessageEventType.Bounced);
        Assert.Equal("alice@dest.example", bounce.Recipient);
    }

    [Fact]
    public async Task A_token_issued_before_destinations_were_bound_keeps_its_old_behaviour()
    {
        string local = LocalPart(destinationDomain: null);

        await _bounces.ProcessAsync(local, Dsn(local, "gone@dest.example", messageId: null), default);

        Assert.True(await SuppressedAsync("gone@dest.example"));
    }

    [Fact]
    public async Task A_history_failure_while_confirming_is_a_temporary_failure_not_an_ignored_report()
    {
        var (_, header) = await SendAsync("gone@dest.example");
        var bounces = new BounceProcessor(_verp, _storage.Config, _storage.Stats, new StorageWebhookPublisher(_storage), SystemClock.Instance, history: new FailingHistory());
        string local = LocalPart();

        await Assert.ThrowsAsync<IOException>(async () => await bounces.ProcessAsync(local, Dsn(local, "gone@dest.example", header), default));

        Assert.False(await SuppressedAsync("gone@dest.example"));
    }

    [Fact]
    public async Task A_report_naming_an_address_outside_the_destination_domain_is_ignored_before_the_history_is_asked()
    {
        var (id, header) = await SendAsync("victim@customer.example");
        string local = LocalPart();   // a token for dest.example

        await _bounces.ProcessAsync(local, Dsn(local, "victim@customer.example", header), default);

        Assert.False(await SuppressedAsync("victim@customer.example"));
        Assert.Equal([MessageEventType.Queued], await EventTypesAsync(id));
    }

    [Theory]
    [InlineData(HistoryMode.Full, 7, 5, true)]
    [InlineData(HistoryMode.Full, 18, 5, true)]       // a bounce address issued at the last attempt, five days after receipt, lives until day 19
    [InlineData(HistoryMode.Full, 19, 5, false)]
    [InlineData(HistoryMode.Full, 14, 0, false)]
    [InlineData(HistoryMode.Full, 0, 5, false)]       // kept forever
    [InlineData(HistoryMode.StatsOnly, 7, 5, false)]  // nothing is confirmed against the history
    public void A_history_shorter_than_a_bounce_address_can_be_used_is_warned_about_at_start(HistoryMode mode, int metadataDays, int queueDays, bool warned)
    {
        string? warning = BounceProcessor.RetentionWarning(mode, metadataDays, TimeSpan.FromDays(queueDays));

        Assert.Equal(warned, warning is not null);
        if (warned)
        {
            Assert.Contains($"Retention:MetadataDays ({metadataDays})", warning);
        }
    }

    private sealed class FailingHistory : IHistoryStore
    {
        public ValueTask<Guid?> AttachReportAsync(Guid tenantId, string messageIdHeader, AsyncReport report, CancellationToken cancellationToken) => throw new IOException("history unavailable");

        public ValueTask<Page<MessageSummary>> SearchAsync(MessageQuery query, CancellationToken cancellationToken) => throw new NotSupportedException();

        public ValueTask<MessageDetail?> GetAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken) => throw new NotSupportedException();

        public ValueTask<IReadOnlyList<MessageEvent>> GetEventsAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken) => throw new NotSupportedException();

        public ValueTask<byte[]?> GetRetainedRawAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
