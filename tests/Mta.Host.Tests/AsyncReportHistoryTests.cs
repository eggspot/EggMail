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
/// Asynchronous bounces and complaints (a remote server accepted the message and reported a problem later) are attached to the history of the message they are about:
/// the verified VERP token names the tenant, the <c>Message-ID</c> in the returned headers finds the message. <c>History:Mode</c> decides whether anything is recorded per message.
/// </summary>
[Collection("bounce-history")]   // shares the process-wide ignored-report counter with BounceHistoryConfirmationTests
public class AsyncReportHistoryTests
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    private static readonly Guid OtherTenantId = Guid.Parse("b0000000-0000-7000-8000-000000000002");

    private sealed class Rig : IAsyncDisposable
    {
        public required InMemoryStorage Storage { get; init; }
        public required BounceProcessor Bounces { get; init; }
        public required SubmissionService Submission { get; init; }
        public required VerpCodec Verp { get; init; }

        public static async Task<Rig> CreateAsync(HistoryMode mode)
        {
            var options = new StorageOptions { History = new HistoryOptions { Mode = mode } };
            var storage = new InMemoryStorage(options);
            await storage.InitializeAsync(default);
            var now = DateTimeOffset.UtcNow;
            foreach (Guid tenant in new[] { TenantId, OtherTenantId })
            {
                await storage.Config.UpsertTenantAsync(new Tenant(tenant, "T" + tenant.ToString("N")[..4], "t" + tenant.ToString("N")[..4], true, now, false), default);
                await storage.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), tenant, tenant == TenantId ? "example.org" : "other.example", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
            }

            var verp = new VerpCodec(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey() }, 1);
            return new Rig
            {
                Storage = storage,
                Verp = verp,
                Bounces = new BounceProcessor(verp, storage.Config, storage.Stats, new StorageWebhookPublisher(storage), SystemClock.Instance, history: mode == HistoryMode.Full ? storage.History : null),
                Submission = new SubmissionService(storage, SystemClock.Instance, new SenderPolicy(), options, new SubmissionOptions { MessageIdDomain = "egg.test", DomainCacheTtl = TimeSpan.Zero }),
            };
        }

        public async ValueTask DisposeAsync() => await Storage.DisposeAsync();

        /// <summary>Submits a message from the tenant's domain with the given Message-ID header (or a generated one) and returns its id and the header the server stored.</summary>
        public async Task<(Guid Id, string MessageIdHeader)> SubmitAsync(Guid tenant, string? messageId, string[]? tags = null, string to = "gone@dest.example")
        {
            string domain = tenant == TenantId ? "example.org" : "other.example";
            string raw = $"From: Acme <news@{domain}>\r\nTo: {to}\r\nSubject: Hi\r\n" + (messageId is null ? "" : $"Message-ID: {messageId}\r\n") + "\r\nbody\r\n";
            var tenantRecord = (await Storage.Config.GetTenantAsync(tenant, default))!;
            SubmissionResult result = await Submission.SubmitAsync(new SubmissionRequest
            {
                Tenant = tenantRecord,
                Source = MessageSource.Api,
                EnvelopeFrom = EmailAddress.Parse($"news@{domain}"),
                Recipients = [EmailAddress.Parse(to)],
                Message = Encoding.ASCII.GetBytes(raw),
                Tags = tags,
            }, default);
            Assert.Equal(SubmissionStatus.Accepted, result.Status);
            byte[] stored = (await Storage.Deliveries.GetRawAsync(result.MessageId, default))!;
            return (result.MessageId, MimeMessage.Parse(stored).Headers.GetFirstValue("Message-ID")!);
        }

        public async Task DeliverAsync()
        {
            foreach (ClaimedDelivery d in await Storage.Deliveries.ClaimAsync("t", 100, DateTimeOffset.UtcNow.AddSeconds(1), TimeSpan.FromMinutes(1), default))
            {
                await Storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = DateTimeOffset.UtcNow, SmtpCode = 250 }, default);
            }
        }

        public async Task<BounceOutcome> SendDsnAsync(Guid tenant, string originalMessageId, string recipient = "gone@dest.example")
        {
            string address = Verp.CreateAddress(tenant, Ids.New(), "bounces.egg.test", DateTimeOffset.UtcNow, "dest.example");
            byte[] dsn = DsnBuilder.Build(new DsnRequest
            {
                ReportingMta = "mx.remote.example",
                To = EmailAddress.Parse(address),
                Action = DsnAction.Failed,
                ArrivalDate = DateTimeOffset.UtcNow,
                Now = DateTimeOffset.UtcNow,
                OriginalMessage = Encoding.ASCII.GetBytes($"Message-ID: {originalMessageId}\r\nSubject: x\r\n\r\nbody\r\n"),
                Recipients = [new DsnRecipient(EmailAddress.Parse(recipient), "5.1.1", "550 5.1.1 No such user")],
            });
            return await Bounces.ProcessAsync(address[..address.IndexOf('@')], dsn, default);
        }

        public async Task<BounceOutcome> SendComplaintAsync(Guid tenant, string originalMessageId, string recipient = "gone@dest.example")
        {
            string address = Verp.CreateAddress(tenant, Ids.New(), "bounces.egg.test", DateTimeOffset.UtcNow, "dest.example");
            string arf = $"From: fbl@isp.example\r\nTo: {address}\r\nSubject: FW: spam\r\nContent-Type: multipart/report; report-type=feedback-report; boundary=\"FF\"\r\n\r\n" +
                "--FF\r\nContent-Type: text/plain\r\n\r\nAbuse report.\r\n" +
                $"--FF\r\nContent-Type: message/feedback-report\r\n\r\nFeedback-Type: abuse\r\nUser-Agent: SomeISP/1.0\r\nVersion: 1\r\nOriginal-Rcpt-To: <{recipient}>\r\n\r\n" +
                $"--FF\r\nContent-Type: message/rfc822\r\n\r\nFrom: news@example.org\r\nMessage-ID: {originalMessageId}\r\nSubject: Offer\r\n\r\nbody\r\n--FF--\r\n";
            return await Bounces.ProcessAsync(address[..address.IndexOf('@')], Encoding.ASCII.GetBytes(arf), default);
        }

        public async Task<IReadOnlyList<MessageEvent>> EventsAsync(Guid tenant, Guid id) => await Storage.History.GetEventsAsync(tenant, id, default);
    }

    [Fact]
    public async Task A_bounce_that_arrives_after_delivery_is_attached_to_the_message_history()
    {
        await using Rig rig = await Rig.CreateAsync(HistoryMode.Full);
        var (id, header) = await rig.SubmitAsync(TenantId, messageId: null);   // the server generates the Message-ID
        await rig.DeliverAsync();
        Assert.Equal("delivered", (await rig.Storage.History.GetAsync(TenantId, id, default))!.Summary.Status);

        Assert.Equal(BounceOutcome.Bounce, await rig.SendDsnAsync(TenantId, header));

        var events = await rig.EventsAsync(TenantId, id);
        Assert.Equal([MessageEventType.Queued, MessageEventType.Delivered, MessageEventType.Bounced], events.Select(e => e.Type));
        MessageEvent bounce = events[^1];
        Assert.Equal(("gone@dest.example", "5.1.1"), (bounce.Recipient, bounce.EnhancedCode));
        Assert.Contains("No such user", bounce.Message);
        Assert.Equal("bounced", (await rig.Storage.History.GetAsync(TenantId, id, default))!.Summary.Status);
        Assert.True(await rig.Storage.Config.IsSuppressedAsync(TenantId, "gone@dest.example", default));   // the suppression still happens
    }

    [Fact]
    public async Task The_webhook_of_an_attached_report_names_the_message()
    {
        await using Rig rig = await Rig.CreateAsync(HistoryMode.Full);
        var endpoint = new WebhookEndpointRecord(Ids.New(), TenantId, "https://hooks.example/x", [1, 2, 3], [WebhookEventFactory.Bounced, WebhookEventFactory.Complained], true, null, null, DateTimeOffset.UtcNow, null);
        await rig.Storage.Config.UpsertWebhookEndpointAsync(endpoint, default);
        var (id, header) = await rig.SubmitAsync(TenantId, "<client.chosen.id@example.org>");
        Assert.Equal("<client.chosen.id@example.org>", header);
        await rig.DeliverAsync();

        await rig.SendDsnAsync(TenantId, "<CLIENT.chosen.ID@example.org>");   // servers fold case
        await rig.SendDsnAsync(TenantId, "<nobody@elsewhere.example>");        // a message this server never sent: not confirmed, no webhook (decision 112)

        var item = Assert.Single(await rig.Storage.Webhooks.ClaimDueAsync("w", 10, DateTimeOffset.UtcNow.AddSeconds(1), TimeSpan.FromMinutes(1), default));
        Assert.Contains($"\"message_id\":\"{Ids.ToCompact(id)}\"", item.PayloadJson, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_complaint_is_attached_to_the_message_and_marks_a_delivered_message_complained()
    {
        await using Rig rig = await Rig.CreateAsync(HistoryMode.Full);
        var (id, header) = await rig.SubmitAsync(TenantId, messageId: null, to: "reader@dest.example");
        await rig.DeliverAsync();

        Assert.Equal(BounceOutcome.Complaint, await rig.SendComplaintAsync(TenantId, header, "reader@dest.example"));

        var events = await rig.EventsAsync(TenantId, id);
        MessageEvent complaint = events.Single(e => e.Type == MessageEventType.Complained);
        Assert.Equal(("reader@dest.example", "abuse"), (complaint.Recipient, complaint.Message));
        Assert.Equal("complained", (await rig.Storage.History.GetAsync(TenantId, id, default))!.Summary.Status);
    }

    [Fact]
    public async Task A_report_with_the_token_of_another_tenant_is_not_attached_to_this_tenants_message()
    {
        await using Rig rig = await Rig.CreateAsync(HistoryMode.Full);
        var (id, header) = await rig.SubmitAsync(TenantId, messageId: null);
        await rig.DeliverAsync();

        // A different tenant's valid token quotes our Message-ID: it can only ever look among its own messages.
        await rig.SendDsnAsync(OtherTenantId, header);

        Assert.Equal([MessageEventType.Queued, MessageEventType.Delivered], (await rig.EventsAsync(TenantId, id)).Select(e => e.Type));
        Assert.Empty(await rig.EventsAsync(OtherTenantId, id));
        Assert.Equal("delivered", (await rig.Storage.History.GetAsync(TenantId, id, default))!.Summary.Status);
    }

    [Fact]
    public async Task With_stats_only_history_the_report_still_suppresses_and_publishes_but_stores_no_per_message_record()
    {
        await using Rig rig = await Rig.CreateAsync(HistoryMode.StatsOnly);
        var endpoint = new WebhookEndpointRecord(Ids.New(), TenantId, "https://hooks.example/x", [1, 2, 3], [WebhookEventFactory.Bounced], true, null, null, DateTimeOffset.UtcNow, null);
        await rig.Storage.Config.UpsertWebhookEndpointAsync(endpoint, default);
        var (id, header) = await rig.SubmitAsync(TenantId, messageId: null, tags: ["welcome"]);
        await rig.DeliverAsync();

        Assert.Equal(BounceOutcome.Bounce, await rig.SendDsnAsync(TenantId, header));

        Assert.True(await rig.Storage.Config.IsSuppressedAsync(TenantId, "gone@dest.example", default));
        var item = Assert.Single(await rig.Storage.Webhooks.ClaimDueAsync("w", 10, DateTimeOffset.UtcNow.AddSeconds(1), TimeSpan.FromMinutes(1), default));
        Assert.Contains("\"message_id\":null", item.PayloadJson);
        Assert.Empty(await rig.EventsAsync(TenantId, id));
        Assert.Empty((await rig.Storage.History.SearchAsync(new MessageQuery(), default)).Items);
        Assert.Null(await rig.Storage.History.GetAsync(TenantId, id, default));
    }

    [Fact]
    public async Task Tags_given_at_submission_are_stored_with_the_history_only_when_it_is_recorded()
    {
        await using Rig full = await Rig.CreateAsync(HistoryMode.Full);
        var (id, _) = await full.SubmitAsync(TenantId, messageId: null, tags: ["welcome", "welcome", "autumn"]);
        Assert.Equal(["welcome", "autumn"], (await full.Storage.History.GetAsync(TenantId, id, default))!.Summary.Tags);
        Assert.Null((await full.Storage.History.GetAsync(TenantId, (await full.SubmitAsync(TenantId, null)).Id, default))!.Summary.Tags);

        await using Rig statsOnly = await Rig.CreateAsync(HistoryMode.StatsOnly);
        var (other, _) = await statsOnly.SubmitAsync(TenantId, messageId: null, tags: ["welcome"]);
        Assert.Null(await statsOnly.Storage.History.GetAsync(TenantId, other, default));
    }

    [Fact]
    public async Task A_message_id_the_client_supplied_is_the_one_a_returned_bounce_finds()
    {
        await using Rig rig = await Rig.CreateAsync(HistoryMode.Full);
        var (id, _) = await rig.SubmitAsync(TenantId, "<Mixed.Case.7@Example.ORG>");
        await rig.DeliverAsync();
        await rig.SendDsnAsync(TenantId, "<mixed.case.7@example.org>");
        Assert.Contains(await rig.EventsAsync(TenantId, id), e => e.Type == MessageEventType.Bounced);
    }
}
