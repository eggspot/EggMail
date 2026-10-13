using System.Diagnostics;
using Mta.Core;
using Mta.Storage;

namespace Mta.Webhooks;

/// <summary>
/// The webhook span of a message's trace (<see cref="MessageTrace"/>). The outbox stores no trace context, so the message is recovered from the
/// event payload (<c>data.message_id</c>) and only when a trace exporter is attached; events that are not about a message (an endpoint that was
/// disabled) start a trace of their own.
/// </summary>
internal static class WebhookTracing
{
    public static Activity? Start(WebhookOutboxItem item)
    {
        if (!MessageTrace.IsEnabled)
        {
            return null;
        }

        Activity? span = MessageIdOf(item.PayloadJson) is { } messageId
            ? MessageTrace.Start(MessageTrace.WebhookDeliverSpan, messageId, ActivityKind.Client)
            : MessageTrace.StartUnattached(MessageTrace.WebhookDeliverSpan, ActivityKind.Client);
        if (span is not null)
        {
            span.SetTag("mta.webhook.event_type", item.EventType);
            span.SetTag("mta.webhook.attempt", item.Attempt + 1);
            span.SetTag("mta.tenant.id", Ids.ToCompact(item.TenantId));
        }

        return span;
    }

    /// <summary>Records the receiver's answer: the status code, and an error status with the reason class when the call did not succeed.</summary>
    public static void Finish(Activity? span, int? statusCode, string? errorClass)
    {
        if (span is null)
        {
            return;
        }

        if (statusCode is int code)
        {
            span.SetTag("http.response.status_code", code);
        }

        if (errorClass is not null)
        {
            span.SetTag("mta.webhook.error", errorClass);
            span.SetStatus(ActivityStatusCode.Error, errorClass);
        }

        span.Stop();   // the span covers the HTTP call, not the bookkeeping that follows
    }

    private const string MessageIdKey = "\"message_id\":\"";

    /// <summary>
    /// The <c>data.message_id</c> of an event payload (32 hex digits), found by a scan instead of a JSON parse: this runs for every webhook while a
    /// trace exporter is attached, before the sampling decision is known. Our own payloads are compact; a payload without the key is not about a message.
    /// </summary>
    internal static Guid? MessageIdOf(string payloadJson)
    {
        int at = payloadJson.IndexOf(MessageIdKey, StringComparison.Ordinal);
        if (at < 0 || payloadJson.Length < at + MessageIdKey.Length + 32)
        {
            return null;
        }

        return Guid.TryParseExact(payloadJson.AsSpan(at + MessageIdKey.Length, 32), "N", out Guid messageId) ? messageId : null;
    }
}
