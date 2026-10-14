using System.Diagnostics;
using Mta.Core;
using Mta.Storage;

namespace Mta.Delivery;

/// <summary>
/// The spans of the delivery side of a message's trace (<see cref="MessageTrace"/>): the wait in the queue before the first attempt and one
/// span per delivery group. Everything is guarded by <see cref="MessageTrace.IsEnabled"/>, so a deployment without a trace exporter pays one
/// volatile read per group and allocates nothing.
/// </summary>
internal static class DeliveryTracing
{
    /// <summary>Starts the span of one delivery group (all recipients of one message at one destination domain); null when tracing is off.</summary>
    public static Activity? StartAttempt(IReadOnlyList<ClaimedDelivery> group)
    {
        if (!MessageTrace.IsEnabled)
        {
            return null;
        }

        ClaimedDelivery first = group[0];
        if (first.Attempt == 0)
        {
            // The time between acceptance and the first claim, emitted now that it is over (its start time is the acceptance time).
            using Activity? wait = MessageTrace.Start(MessageTrace.QueueWaitSpan, first.MessageId, ActivityKind.Internal, first.CreatedAt);
        }

        Activity? span = MessageTrace.Start(MessageTrace.DeliveryAttemptSpan, first.MessageId, ActivityKind.Internal);
        if (span is not null)
        {
            span.SetTag("mta.tenant.id", Ids.ToCompact(first.TenantId));
            span.SetTag("mta.delivery.attempt", first.Attempt + 1);
            span.SetTag("mta.delivery.recipients", group.Count);
            span.SetTag("mta.recipient.domain", first.RecipientDomain);
            span.SetTag("mta.delivery.source", first.Source.ToString());
        }

        return span;
    }

    /// <summary>Adds the result of one recipient to the running attempt span as an event; a permanent failure marks the span as an error.</summary>
    public static void AddResult(DeliveryAttempt attempt)
    {
        if (Activity.Current is not { } span || !ReferenceEquals(span.Source, MessageTrace.Source))
        {
            return;
        }

        var tags = new ActivityTagsCollection { { "mta.delivery.outcome", attempt.Outcome.ToString().ToLowerInvariant() } };
        if (attempt.SmtpCode is int code) { tags["mta.smtp.code"] = code; }
        if (attempt.EnhancedCode is not null) { tags["mta.smtp.enhanced_code"] = attempt.EnhancedCode; }
        if (attempt.MxHost is not null) { tags["mta.mx.host"] = attempt.MxHost; }
        if (attempt.Tls is { } tls) { tags["mta.tls.used"] = tls.Used; }
        span.AddEvent(new ActivityEvent("recipient.result", tags: tags));
        if (attempt.Outcome == DeliveryOutcome.Failed)
        {
            // Never the server's free-text reply: it echoes recipient addresses and leaves the box with the span. Codes only.
            span.SetStatus(ActivityStatusCode.Error, attempt.EnhancedCode ?? (attempt.SmtpCode is int smtp ? "smtp " + smtp : "failed"));
        }
    }
}
