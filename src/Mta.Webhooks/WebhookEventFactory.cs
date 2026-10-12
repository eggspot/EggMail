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
    public const string EndpointDisabled = "webhook.endpoint.disabled";

    public static IReadOnlyList<string> AllEventTypes { get; } = [Delivered, Deferred, Bounced, Expired, Suppressed, Complained];

    public static string? EventTypeFor(DeliveryOutcome outcome) => outcome switch
    {
        DeliveryOutcome.Delivered => Delivered,
        DeliveryOutcome.Deferred => Deferred,
        DeliveryOutcome.Failed => Bounced,
        DeliveryOutcome.Expired => Expired,
        DeliveryOutcome.Suppressed => Suppressed,
        _ => null,
    };

    /// <summary>Creates the draft for a delivery attempt, or null when the outcome has no public event (cancellations, switch aborts).</summary>
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
}
