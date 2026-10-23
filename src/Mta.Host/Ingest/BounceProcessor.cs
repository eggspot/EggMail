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
/// <c>Message-ID</c>, which is looked up among the message history of the tenant named by the verified token (<see cref="IHistoryStore.AttachReportAsync"/>). The address the
/// report names must be a recipient of that message, or the report is ignored (decision 112). The message id found goes into the webhook payload. With <c>StatsOnly</c> no
/// per-message record is stored: nothing is attached and the destination domain of the token is the only check.</para>
/// </summary>
public sealed class BounceProcessor
{
    /// <summary>The longest a bounce address is accepted after it was issued; <see cref="Mta.Host.Hosting.VerpKeyRotation"/> keeps a retired key at least this long.</summary>
    public static readonly TimeSpan MaxTokenAge = TimeSpan.FromDays(14);

    private readonly VerpCodec _verp;
    private readonly IConfigStore _config;
    private readonly IStatsStore _stats;
    private readonly IWebhookPublisher _webhooks;
    private readonly IClock _clock;
    private readonly ReplyClassifier _classifier;
    private readonly IMtaLog _log;
    private readonly IHistoryStore? _history;

    /// <param name="history">The tenant's per-message history when it is recorded (<c>History:Mode=Full</c>), which reports are then confirmed against; null with <c>StatsOnly</c>.</param>
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

    /// <summary>
    /// The startup warning when per-message history can end before a bounce address of its message expires: the history counts from when the message
    /// was received, the bounce address from its delivery attempt, which can be up to <paramref name="queueMaxLifetime"/> later. A report that arrives after
    /// its message left the history cannot be confirmed and is ignored (decision 112). Null when there is nothing to warn about.
    /// </summary>
    public static string? RetentionWarning(HistoryMode mode, int metadataDays, TimeSpan queueMaxLifetime)
    {
        double needed = Math.Ceiling((MaxTokenAge + queueMaxLifetime).TotalDays);
        return mode == HistoryMode.Full && metadataDays > 0 && metadataDays < needed
            ? $"Retention:MetadataDays ({metadataDays}) is shorter than the {needed:0} days a message's bounce address can be used ({MaxTokenAge.TotalDays:0} days after a delivery attempt, which can come up to Queue:MaxLifetime after the message was received): a bounce or complaint that arrives after its message left the history cannot be confirmed and is ignored."
            : null;
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
                await HandleBounceAsync(tenant, token, report, now, ct).ConfigureAwait(false);
                return BounceOutcome.Bounce;
            case InboundReportKind.FeedbackReport:
                await HandleComplaintAsync(tenant, token, report, now, ct).ConfigureAwait(false);
                return BounceOutcome.Complaint;
            default:
                return BounceOutcome.Ignored;
        }
    }

    /// <summary>
    /// The address a report is about, and the message it is about when that is known. A candidate counts only when it parses and, when the token is
    /// bound to a destination domain, lies in that domain: anyone who received a message holds a valid token (it is in the Return-Path), so without
    /// this a forged report could name any address and have it suppressed for the tenant (decision 92). A forwarded message is reported by the final
    /// server with the forwarding target as Final-Recipient; the Original-Recipient field is what names the address the message was sent to, so it is
    /// a candidate as well.
    /// <para>With per-message history the candidate must also be a recorded recipient of the message whose <c>Message-ID</c> the report quotes, which
    /// closes the residual of decision 92 (a holder of a token for <c>gmail.com</c> naming another <c>gmail.com</c> address). A report that cannot be
    /// confirmed is ignored: no suppression, no webhook, no statistics (decision 112). The confirmation is the attachment of the report to the
    /// message's history, so a storage failure is not swallowed here: it fails the SMTP transaction with a temporary error and the remote retries.</para>
    /// </summary>
    private async ValueTask<(EmailAddress Address, Guid? MessageId)?> ChooseRecipientAsync(
        Guid tenantId, VerpToken token, string kind, string? originalMessageId, Func<string, AsyncReport> report, CancellationToken ct, params string?[] candidates)
    {
        var inDomain = new List<EmailAddress>(candidates.Length);
        bool outside = false;
        foreach (string? candidate in candidates)
        {
            if (!EmailAddress.TryParse(candidate, allowUtf8: true, out var parsed) || inDomain.Any(a => Key(a) == Key(parsed)))
            {
                continue;   // unusable, or the same address again (Final-Recipient and Original-Recipient are often equal)
            }

            switch (_verp.CheckDestination(token, parsed.Domain))
            {
                case VerpDestinationCheck.Unbound:   // a token issued before destinations were bound: the first usable address, as before, without confirmation
                    return (parsed, await AttachAsync(tenantId, originalMessageId, report(Key(parsed)), ct).ConfigureAwait(false));
                case VerpDestinationCheck.Match:
                    inDomain.Add(parsed);
                    break;
                default:
                    outside = true;
                    break;
            }
        }

        if (inDomain.Count == 0)
        {
            if (outside)
            {
                Ignore(kind, "outside_destination_domain", "it names an address outside the domain its bounce address was issued for");
            }

            return null;
        }

        if (_history is null)
        {
            return (inDomain[0], null);
        }

        if (string.IsNullOrWhiteSpace(originalMessageId))
        {
            Ignore(kind, "no_message_id", "it quotes no Message-ID, so the history cannot confirm the address it names");
            return null;
        }

        foreach (EmailAddress address in inDomain)
        {
            Guid? messageId = await _history.AttachReportAsync(tenantId, originalMessageId, report(Key(address)), ct).ConfigureAwait(false);
            if (messageId is not null)
            {
                return (address, messageId);
            }
        }

        Ignore(kind, "not_in_history", "the message history does not show the address it names as a recipient of the message it quotes");
        return null;
    }

    private void Ignore(string kind, string reason, string why)
    {
        BounceMetrics.ReportsIgnored.Add(1, new KeyValuePair<string, object?>("kind", kind), new KeyValuePair<string, object?>("reason", reason));
        _log.Write(MtaLogLevel.Information, "bounce", $"{kind} ignored: {why}");
    }

    private static string Key(EmailAddress address) => address.ToString().ToLowerInvariant();

    private async Task HandleBounceAsync(Tenant tenant, VerpToken token, InboundReport report, DateTimeOffset now, CancellationToken ct)
    {
        foreach (var r in report.Recipients.Where(r => r.IsPermanentFailure))
        {
            int code = ParseCode(r.DiagnosticCode);
            var chosen = await ChooseRecipientAsync(
                tenant.Id, token, "bounce", report.OriginalMessageId, address => new AsyncReport(MessageEventType.Bounced, now, address, code == 0 ? null : code, r.Status, r.DiagnosticCode), ct,
                r.FinalRecipient, r.OriginalRecipient).ConfigureAwait(false);
            if (chosen is not { } found)
            {
                continue;
            }

            var (parsed, messageId) = found;

            var remote = new RemoteReply(code == 0 ? 550 : code, r.Status, r.DiagnosticCode);
            bool recipientProblem = _classifier.Classify(remote, SmtpStage.EndOfData).Class.ShouldSuppressRecipient();
            if (recipientProblem)
            {
                await _config.AddSuppressionAsync(new SuppressionRecord(tenant.Id, Key(parsed), SuppressionReason.HardBounce, "async-bounce", now, null), ct).ConfigureAwait(false);
            }

            var draft = WebhookEventFactory.ForInboundReport(WebhookEventFactory.Bounced, now, parsed.ToString(), report.OriginalMessageId, r.Status, r.DiagnosticCode, null, messageId);
            await _webhooks.PublishAsync(tenant.Id, draft, now, ct).ConfigureAwait(false);
            _stats.Add(new StatKey(HourStart(now), tenant.Id, string.Empty, parsed.Domain.ToLowerInvariant()), StatCounter.HardBounce);
        }
    }

    private async Task HandleComplaintAsync(Tenant tenant, VerpToken token, InboundReport report, DateTimeOffset now, CancellationToken ct)
    {
        var chosen = await ChooseRecipientAsync(
            tenant.Id, token, "complaint", report.OriginalMessageId, address => new AsyncReport(MessageEventType.Complained, now, address, null, null, report.FeedbackType), ct,
            report.ArfOriginalRecipient).ConfigureAwait(false);
        if (chosen is not { } found)
        {
            if (!EmailAddress.TryParse(report.ArfOriginalRecipient, allowUtf8: true, out _))
            {
                _log.Write(MtaLogLevel.Information, "bounce", "complaint without a usable original recipient was ignored");
            }

            return;
        }

        var (parsed, messageId) = found;

        // Only abuse-type feedback counts as a complaint; "not-spam" and virus reports do not suppress.
        if (report.FeedbackType is "abuse" or "fraud")
        {
            await _config.AddSuppressionAsync(new SuppressionRecord(tenant.Id, Key(parsed), SuppressionReason.Complaint, "feedback-loop", now, null), ct).ConfigureAwait(false);
        }

        var draft = WebhookEventFactory.ForInboundReport(WebhookEventFactory.Complained, now, parsed.ToString(), report.OriginalMessageId, null, null, report.FeedbackType, messageId);
        await _webhooks.PublishAsync(tenant.Id, draft, now, ct).ConfigureAwait(false);
        _stats.Add(new StatKey(HourStart(now), tenant.Id, string.Empty, parsed.Domain.ToLowerInvariant()), StatCounter.Complained);
    }

    /// <summary>Attaches the report of a token issued before destinations were bound to the message's history, best effort: a history problem is logged and the suppression and webhook still happen.</summary>
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
