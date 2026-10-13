using Mta.Core;
using Mta.Dsn;
using Mta.Policy;
using Mta.Storage;
using Mta.Webhooks;

namespace Mta.Host.Ingest;

/// <summary>Publishes an event to the webhook endpoints of a tenant (implemented over the storage outbox).</summary>
public interface IWebhookPublisher
{
    ValueTask PublishAsync(Guid tenantId, WebhookEventDraft draft, DateTimeOffset now, CancellationToken cancellationToken);
}

/// <summary>What the processor concluded about an inbound message to the bounce domain.</summary>
public enum BounceOutcome
{
    /// <summary>Not a recognisable report, or the token did not verify; dropped.</summary>
    Ignored,

    /// <summary>A delivery status notification was processed.</summary>
    Bounce,

    /// <summary>A spam complaint was processed.</summary>
    Complaint,
}

/// <summary>
/// Handles mail that arrives on the bounce listener. The recipient is a signed VERP address; only its token (tenant, domain, age)
/// is trusted for correlation. What the body says decides what happens to the addresses it names: a permanent failure that the reply
/// classifier attributes to the recipient suppresses it, a complaint suppresses it as a complaint, and both are published as webhooks.
/// <para>With per-message history (<c>History:Mode=Full</c>) the bounce or complaint is also attached to the message it is about: the returned headers carry the original
/// <c>Message-ID</c>, which is looked up among the message history of the tenant named by the verified token (<see cref="IHistoryStore.AttachReportAsync"/>). The message id found
/// goes into the webhook payload. With <c>StatsOnly</c> no per-message record is stored, so nothing is attached.</para>
/// </summary>
public sealed class BounceProcessor
{
    private static readonly TimeSpan MaxTokenAge = TimeSpan.FromDays(14);

    private readonly VerpCodec _verp;
    private readonly IConfigStore _config;
    private readonly IStatsStore _stats;
    private readonly IWebhookPublisher _webhooks;
    private readonly IClock _clock;
    private readonly ReplyClassifier _classifier;
    private readonly IMtaLog _log;
    private readonly IHistoryStore? _history;

    public BounceProcessor(VerpCodec verp, IConfigStore config, IStatsStore stats, IWebhookPublisher webhooks, IClock clock, IMtaLog? log = null, ReplyClassifier? classifier = null, IHistoryStore? history = null)
    {
        _history = history;
        _verp = verp;
        _config = config;
        _stats = stats;
        _webhooks = webhooks;
        _clock = clock;
        _classifier = classifier ?? ReplyClassifier.Default;
        _log = log ?? NullMtaLog.Instance;
    }

    /// <summary>True if <paramref name="localPart"/> is a bounce address token that verifies now.</summary>
    public bool IsValidBounceAddress(string localPart) => _verp.TryDecode(localPart, _clock.UtcNow, MaxTokenAge, out _);

    public async ValueTask<BounceOutcome> ProcessAsync(string recipientLocalPart, ReadOnlyMemory<byte> message, CancellationToken ct)
    {
        var now = _clock.UtcNow;
        if (!_verp.TryDecode(recipientLocalPart, now, MaxTokenAge, out var token))
        {
            return BounceOutcome.Ignored;
        }

        var tenant = await _config.GetTenantAsync(token.TenantId, ct).ConfigureAwait(false);
        if (tenant is null)
        {
            return BounceOutcome.Ignored;
        }

        var report = InboundReportParser.Parse(message);
        switch (report.Kind)
        {
            case InboundReportKind.DeliveryStatus:
                await HandleBounceAsync(tenant, report, now, ct).ConfigureAwait(false);
                return BounceOutcome.Bounce;
            case InboundReportKind.FeedbackReport:
                await HandleComplaintAsync(tenant, report, now, ct).ConfigureAwait(false);
                return BounceOutcome.Complaint;
            default:
                return BounceOutcome.Ignored;
        }
    }

    private async Task HandleBounceAsync(Tenant tenant, InboundReport report, DateTimeOffset now, CancellationToken ct)
    {
        foreach (var r in report.Recipients.Where(r => r.IsPermanentFailure))
        {
            string? address = r.FinalRecipient ?? r.OriginalRecipient;
            if (!EmailAddress.TryParse(address, allowUtf8: true, out var parsed))
            {
                continue;
            }

            int code = ParseCode(r.DiagnosticCode);
            var remote = new RemoteReply(code == 0 ? 550 : code, r.Status, r.DiagnosticCode);
            bool recipientProblem = _classifier.Classify(remote, SmtpStage.EndOfData).Class.ShouldSuppressRecipient();
            if (recipientProblem)
            {
                await _config.AddSuppressionAsync(new SuppressionRecord(tenant.Id, parsed.ToString().ToLowerInvariant(), SuppressionReason.HardBounce, "async-bounce", now, null), ct).ConfigureAwait(false);
            }

            Guid? messageId = await AttachAsync(tenant.Id, report.OriginalMessageId, new AsyncReport(MessageEventType.Bounced, now, parsed.ToString().ToLowerInvariant(), code == 0 ? null : code, r.Status, r.DiagnosticCode), ct).ConfigureAwait(false);
            var draft = WebhookEventFactory.ForInboundReport(WebhookEventFactory.Bounced, now, parsed.ToString(), report.OriginalMessageId, r.Status, r.DiagnosticCode, null, messageId);
            await _webhooks.PublishAsync(tenant.Id, draft, now, ct).ConfigureAwait(false);
            _stats.Add(new StatKey(HourStart(now), tenant.Id, string.Empty, parsed.Domain.ToLowerInvariant()), StatCounter.HardBounce);
        }
    }

    private async Task HandleComplaintAsync(Tenant tenant, InboundReport report, DateTimeOffset now, CancellationToken ct)
    {
        if (!EmailAddress.TryParse(report.ArfOriginalRecipient, allowUtf8: true, out var parsed))
        {
            _log.Write(MtaLogLevel.Information, "bounce", "complaint without a usable original recipient was ignored");
            return;
        }

        // Only abuse-type feedback counts as a complaint; "not-spam" and virus reports do not suppress.
        if (report.FeedbackType is "abuse" or "fraud")
        {
            await _config.AddSuppressionAsync(new SuppressionRecord(tenant.Id, parsed.ToString().ToLowerInvariant(), SuppressionReason.Complaint, "feedback-loop", now, null), ct).ConfigureAwait(false);
        }

        Guid? messageId = await AttachAsync(tenant.Id, report.OriginalMessageId, new AsyncReport(MessageEventType.Complained, now, parsed.ToString().ToLowerInvariant(), null, null, report.FeedbackType), ct).ConfigureAwait(false);
        var draft = WebhookEventFactory.ForInboundReport(WebhookEventFactory.Complained, now, parsed.ToString(), report.OriginalMessageId, null, null, report.FeedbackType, messageId);
        await _webhooks.PublishAsync(tenant.Id, draft, now, ct).ConfigureAwait(false);
        _stats.Add(new StatKey(HourStart(now), tenant.Id, string.Empty, parsed.Domain.ToLowerInvariant()), StatCounter.Complained);
    }

    /// <summary>Attaches the report to the message's history. Never fails the bounce handling: a history problem is logged and the suppression and webhook still happen.</summary>
    private async Task<Guid?> AttachAsync(Guid tenantId, string? originalMessageId, AsyncReport report, CancellationToken ct)
    {
        if (_history is null || string.IsNullOrWhiteSpace(originalMessageId))
        {
            return null;
        }

        try
        {
            return await _history.AttachReportAsync(tenantId, originalMessageId, report, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Write(MtaLogLevel.Warning, "bounce", "could not attach an asynchronous report to the message history", ex);
            return null;
        }
    }

    private static DateTimeOffset HourStart(DateTimeOffset t) => new(t.Year, t.Month, t.Day, t.Hour, 0, 0, TimeSpan.Zero);

    private static int ParseCode(string? diagnostic)
    {
        if (diagnostic is { Length: >= 3 } d && int.TryParse(d.AsSpan(0, 3), out int code) && code is >= 200 and < 600)
        {
            return code;
        }

        return 0;
    }
}
