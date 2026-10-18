using System.Text.Json;
using Mta.Core;
using Mta.Storage;

namespace Mta.Webhooks;

/// <summary>Builds webhook event payloads for delivery outcomes. The event id doubles as the receiver's idempotency key.</summary>
public static class WebhookEventFactory
{
    public const string Delivered = "message.delivered";
    public const string Deferred = "message.deferred";
    public const string Bounced = "message.bounced";
    public const string Expired = "message.expired";
    public const string Suppressed = "message.suppressed";
    public const string Complained = "message.complained";
    public const string Cancelled = "message.cancelled";
    public const string EndpointDisabled = "webhook.endpoint.disabled";

    /// <summary>The payload type of a received message posted by an inbound <c>webhook</c> route (design section 11.7). Sent by the route action itself, never fanned out through subscriptions, so it is not an event type an endpoint can subscribe to.</summary>
    public const string InboundMessageReceived = "inbound.message.received";

    /// <summary>A route action gave up (attempts used up, route deleted, a permanent failure): published to the tenant's endpoints that subscribe to it (or to <c>*</c>).</summary>
    public const string InboundActionFailed = "inbound.action.failed";

    /// <summary>The inbound event types an endpoint can subscribe to.</summary>
    public static IReadOnlyList<string> InboundEventTypes { get; } = [InboundActionFailed];

    public static IReadOnlyList<string> AllEventTypes { get; } = [Delivered, Deferred, Bounced, Expired, Suppressed, Complained, Cancelled];

    public static string? EventTypeFor(DeliveryOutcome outcome) => outcome switch
    {
        DeliveryOutcome.Delivered => Delivered,
        DeliveryOutcome.Deferred => Deferred,
        DeliveryOutcome.Failed => Bounced,
        DeliveryOutcome.Expired => Expired,
        DeliveryOutcome.Suppressed => Suppressed,
        _ => null,
    };

    /// <summary>Creates the draft for a delivery attempt, or null when the outcome has no public event (switch aborts; a cancellation is published through <see cref="ForCancelled"/>, by the cancel itself, not by an attempt).</summary>
    public static WebhookEventDraft? ForAttempt(ClaimedDelivery delivery, DeliveryAttempt attempt)
    {
        string? type = EventTypeFor(attempt.Outcome);
        if (type is null)
        {
            return null;
        }

        var id = Ids.New(attempt.At);
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteString("id", $"evt_{Ids.ToCompact(id)}");
            w.WriteString("type", type);
            w.WriteString("timestamp", attempt.At.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture));
            w.WriteStartObject("data");
            w.WriteString("message_id", Ids.ToCompact(delivery.MessageId));
            w.WriteString("delivery_id", Ids.ToCompact(delivery.DeliveryId));
            w.WriteString("from", delivery.EnvelopeFrom.ToString());
            w.WriteString("recipient", delivery.Recipient.ToString());
            w.WriteNumber("attempt", delivery.Attempt + 1);
            if (attempt.SmtpCode is int code) { w.WriteNumber("smtp_code", code); }
            if (attempt.EnhancedCode is not null) { w.WriteString("enhanced_code", attempt.EnhancedCode); }
            if (attempt.Message is not null) { w.WriteString("response", attempt.Message); }
            if (attempt.MxHost is not null) { w.WriteString("mx_host", attempt.MxHost); }
            if (attempt.NextAttemptAt is DateTimeOffset next) { w.WriteString("next_attempt_at", next.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture)); }
            if (attempt.PossibleDuplicate || delivery.PossibleDuplicate) { w.WriteBoolean("possible_duplicate", true); }
            if (attempt.Tls is { } tls)
            {
                w.WriteStartObject("tls");
                w.WriteBoolean("used", tls.Used);
                if (tls.Version is not null) { w.WriteString("version", tls.Version); }
                if (tls.CipherSuite is not null) { w.WriteString("cipher", tls.CipherSuite); }
                w.WriteBoolean("verified", tls.Verified);
                w.WriteEndObject();
            }

            w.WriteEndObject();
            w.WriteEndObject();
        }

        return new WebhookEventDraft(id, type, System.Text.Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length));
    }

    /// <summary>
    /// The <c>message.cancelled</c> event for one recipient that was cancelled before delivery (<c>POST /messages/{id}/cancel</c>). Same envelope and member names as the
    /// other <c>message.*</c> events; <c>attempt</c> is the number of attempts that were made (0 when none), and <c>possible_duplicate</c> is present when an earlier
    /// attempt's outcome was unknown, so the message may nevertheless have reached the recipient's server.
    /// </summary>
    public static WebhookEventDraft ForCancelled(CancelledDeliveryInfo cancelled)
    {
        ArgumentNullException.ThrowIfNull(cancelled);
        var id = Ids.New(cancelled.At);
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteString("id", $"evt_{Ids.ToCompact(id)}");
            w.WriteString("type", Cancelled);
            w.WriteString("timestamp", cancelled.At.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture));
            w.WriteStartObject("data");
            w.WriteString("message_id", Ids.ToCompact(cancelled.MessageId));
            w.WriteString("delivery_id", Ids.ToCompact(cancelled.DeliveryId));
            w.WriteString("from", cancelled.EnvelopeFrom);
            w.WriteString("recipient", cancelled.Recipient);
            w.WriteNumber("attempt", cancelled.Attempt);
            if (cancelled.PossibleDuplicate) { w.WriteBoolean("possible_duplicate", true); }
            w.WriteEndObject();
            w.WriteEndObject();
        }

        return new WebhookEventDraft(id, Cancelled, System.Text.Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length));
    }

    /// <summary>The <c>inbound.action.failed</c> event: a route action of a received message ended in <c>failed</c>. <paramref name="error"/> is a short code, never a URL or a response body.</summary>
    public static WebhookEventDraft InboundActionFailedEvent(Guid inboundId, Guid? routeId, string action, string error, int attempts, DateTimeOffset at, int suppressed = 0)
    {
        var id = Ids.New(at);
        string json = JsonSerializer.Serialize(new
        {
            id = $"evt_{Ids.ToCompact(id)}",
            type = InboundActionFailed,
            timestamp = at.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture),
            data = suppressed > 0
                ? (object)new { inbound_id = Ids.ToCompact(inboundId), route_id = routeId is { } route ? Ids.ToCompact(route) : null, action, error, attempts, suppressed }
                : new { inbound_id = Ids.ToCompact(inboundId), route_id = routeId is { } route2 ? Ids.ToCompact(route2) : null, action, error, attempts },
        });
        return new WebhookEventDraft(id, InboundActionFailed, json);
    }

    public static WebhookEventDraft EndpointDisabledEvent(Guid endpointId, string url, string reason, DateTimeOffset at)
    {
        var id = Ids.New(at);
        string json = JsonSerializer.Serialize(new
        {
            id = $"evt_{Ids.ToCompact(id)}",
            type = EndpointDisabled,
            timestamp = at.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture),
            data = new { endpoint_id = Ids.ToCompact(endpointId), url, reason },
        });
        return new WebhookEventDraft(id, EndpointDisabled, json);
    }

    /// <summary>
    /// Creates the draft for an event learned from an inbound report: an asynchronous bounce (a remote server accepted the message and
    /// bounced it later) or a spam complaint.
    /// </summary>
    public static WebhookEventDraft ForInboundReport(string eventType, DateTimeOffset at, string? recipient, string? originalMessageId, string? status, string? diagnostic, string? feedbackType, Guid? messageId = null)
    {
        var id = Ids.New(at);
        string json = JsonSerializer.Serialize(new
        {
            id = $"evt_{Ids.ToCompact(id)}",
            type = eventType,
            timestamp = at.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture),
            data = new
            {
                message_id = messageId is { } known ? Ids.ToCompact(known) : null,
                recipient,
                original_message_id = originalMessageId,
                enhanced_code = status,
                response = diagnostic,
                feedback_type = feedbackType,
                asynchronous = true,
            },
        });
        return new WebhookEventDraft(id, eventType, json);
    }
}
