using System.Diagnostics;
using System.Text.Json;
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
            span.SetTag("mta.webhook.endpoint_id", Ids.ToCompact(item.EndpointId));
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

    private static Guid? MessageIdOf(string payloadJson)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(payloadJson);
            if (document.RootElement.TryGetProperty("data", out JsonElement data)
                && data.ValueKind == JsonValueKind.Object
                && data.TryGetProperty("message_id", out JsonElement id)
                && id.ValueKind == JsonValueKind.String
                && Guid.TryParseExact(id.GetString(), "N", out Guid messageId))
            {
                return messageId;
            }
        }
        catch (JsonException)
        {
        }

        return null;
    }
}
