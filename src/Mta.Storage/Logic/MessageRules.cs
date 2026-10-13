using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Mta.Storage.Logic;

/// <summary>Per-message status text kept on the history index and used by <see cref="MessageQuery.Status"/>.</summary>
public static class MessageStatus
{
    public const string Queued = "queued";
    public const string Deferred = "deferred";
    public const string Delivered = "delivered";
    public const string Partial = "partial";
    public const string Bounced = "bounced";
    public const string Expired = "expired";
    public const string Suppressed = "suppressed";
    public const string Cancelled = "cancelled";
    public const string Complained = "complained";

    /// <summary>
    /// The status after an asynchronous report attached to an already final message: a bounce that arrives after a recipient was accepted makes a delivered
    /// message bounced (one recipient) or partial (several); a complaint makes a delivered or partial message complained. Anything else keeps its status.
    /// </summary>
    public static string AfterReport(string current, int recipientCount, MessageEventType type) => type switch
    {
        MessageEventType.Bounced when current == Delivered => recipientCount <= 1 ? Bounced : Partial,
        MessageEventType.Complained when current is Delivered or Partial => Complained,
        _ => current,
    };

    /// <summary>The status after a deferral or a final event for one recipient.</summary>
    /// <param name="current">Status before the event.</param>
    /// <param name="recipientCount">Recipients of the message.</param>
    /// <param name="finalCount">Final recipients including this event.</param>
    /// <param name="deliveredCount">Delivered recipients including this event.</param>
    /// <param name="failedCount">Bounced recipients including this event.</param>
    /// <param name="finalKind">For a final event, the status word of the outcome; null for a deferral.</param>
    public static string Next(string current, int recipientCount, int finalCount, int deliveredCount, int failedCount, string? finalKind)
    {
        if (finalKind is null)
        {
            return finalCount >= recipientCount ? current : Deferred;
        }

        if (finalCount < recipientCount)
        {
            return current;
        }

        if (deliveredCount >= recipientCount)
        {
            return Delivered;
        }

        if (deliveredCount > 0)
        {
            return Partial;
        }

        return failedCount > 0 ? Bounced : finalKind;
    }

    /// <summary>Status word for a final outcome, or null when the outcome is not final.</summary>
    public static string? FinalKind(MessageEventType type) => type switch
    {
        MessageEventType.Delivered => Delivered,
        MessageEventType.Bounced => Bounced,
        MessageEventType.Expired => Expired,
        MessageEventType.Suppressed => Suppressed,
        MessageEventType.Cancelled => Cancelled,
        _ => null,
    };
}

/// <summary>How accepted content is reduced to what is stored (Content:* options).</summary>
public static class ContentRules
{
    /// <summary>Whether this accept records content at all.</summary>
    public static bool ShouldRecord(StorageOptions options, AcceptedMessage message) =>
        options.History.Mode == HistoryMode.Full && message.Content is not null;

    /// <summary>Applies <c>Content:StoreSubject</c> and <c>Content:MaxStoredBodyBytes</c>.</summary>
    public static MessageContent Prepare(StorageOptions options, MessageContent content)
    {
        ContentOptions c = options.Content;
        string? text = Truncate(content.Text, c.MaxStoredBodyBytes, out bool t1);
        string? html = Truncate(content.Html, c.MaxStoredBodyBytes, out bool t2);
        return new MessageContent(c.StoreSubject ? content.Subject : null, text, html, content.Attachments, content.Truncated || t1 || t2);
    }

    /// <summary>Truncates to at most <paramref name="maxBytes"/> UTF-8 bytes without splitting a character.</summary>
    public static string? Truncate(string? value, int maxBytes, out bool truncated)
    {
        truncated = false;
        if (value is null || Encoding.UTF8.GetByteCount(value) <= maxBytes)
        {
            return value;
        }

        truncated = true;
        int end = Math.Min(value.Length, maxBytes);
        while (end > 0 && Encoding.UTF8.GetByteCount(value.AsSpan(0, end)) > maxBytes)
        {
            end--;
        }

        if (end > 0 && char.IsHighSurrogate(value[end - 1]))
        {
            end--;
        }

        return value[..end];
    }
}

/// <summary>Webhook endpoint subscription matching and the JSON list columns.</summary>
public static class WebhookSubscriptions
{
    /// <summary>An endpoint receives an event when its list contains the event type or the wildcard "*". An empty list receives nothing.</summary>
    public static bool Matches(IReadOnlyList<string> subscribed, string eventType)
    {
        for (int i = 0; i < subscribed.Count; i++)
        {
            string s = subscribed[i];
            if (s == "*" || string.Equals(s, eventType, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}

[JsonSerializable(typeof(TlsInfo))]
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(List<AttachmentInfo>))]
[JsonSerializable(typeof(AttachmentInfo[]))]
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class StorageJsonContext : JsonSerializerContext
{
}

/// <summary>JSON helpers for the list-valued and nested columns (source generated, no reflection).</summary>
public static class StorageJson
{
    public static string SerializeStrings(IReadOnlyList<string> values) => JsonSerializer.Serialize(values.ToArray(), StorageJsonContext.Default.StringArray);

    public static List<string> DeserializeStrings(string? json) =>
        string.IsNullOrEmpty(json) ? [] : JsonSerializer.Deserialize(json, StorageJsonContext.Default.ListString) ?? [];

    public static string SerializeAttachments(IReadOnlyList<AttachmentInfo> values) => JsonSerializer.Serialize(values.ToArray(), StorageJsonContext.Default.AttachmentInfoArray);

    public static List<AttachmentInfo> DeserializeAttachments(string? json) =>
        string.IsNullOrEmpty(json) ? [] : JsonSerializer.Deserialize(json, StorageJsonContext.Default.ListAttachmentInfo) ?? [];

    public static string? SerializeTls(TlsInfo? tls) => tls is null ? null : JsonSerializer.Serialize(tls, StorageJsonContext.Default.TlsInfo);

    public static TlsInfo? DeserializeTls(string? json) =>
        string.IsNullOrEmpty(json) ? null : JsonSerializer.Deserialize(json, StorageJsonContext.Default.TlsInfo);

    /// <summary>The <c>tags</c> column: a JSON array, or null when there are no tags.</summary>
    public static string? SerializeTags(IReadOnlyList<string>? tags) => tags is { Count: > 0 } ? SerializeStrings(tags) : null;

    /// <summary>The tags of a stored column value (empty for null).</summary>
    public static IReadOnlyList<string> DeserializeTags(string? json) => DeserializeStrings(json);
}

/// <summary>
/// The form in which a <c>Message-ID</c> header is stored and looked up: without angle brackets and white space, lower case. A returned bounce quotes the
/// header of the original message, and some servers fold or re-case it, so both sides are normalized the same way.
/// </summary>
public static class MessageIdKey
{
    public const int MaxLength = 998;

    /// <summary>The key for a header value, or null when it is empty or longer than <see cref="MaxLength"/>.</summary>
    public static string? Normalize(string? headerValue)
    {
        if (headerValue is null)
        {
            return null;
        }

        string v = headerValue.Trim();
        int open = v.IndexOf('<', StringComparison.Ordinal);
        int close = open < 0 ? -1 : v.IndexOf('>', open + 1);
        if (open >= 0 && close > open)
        {
            v = v[(open + 1)..close];   // the first <id>, without a trailing comment or folding around it
        }

        v = string.Concat(v.Where(c => !char.IsWhiteSpace(c)));   // an id has no white space; a folded header may have gained some
        return v.Length is 0 or > MaxLength ? null : v.ToLowerInvariant();
    }
}

/// <summary>Opaque pagination cursors.</summary>
public static class Cursors
{
    public static string Encode(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value)).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    public static bool TryDecode(string? cursor, out string value)
    {
        value = "";
        if (string.IsNullOrEmpty(cursor))
        {
            return false;
        }

        try
        {
            string b64 = cursor.Replace('-', '+').Replace('_', '/');
            b64 = b64.PadRight(b64.Length + ((4 - (b64.Length % 4)) % 4), '=');
            value = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>History cursor: the (day, message id) of the last returned row.</summary>
    public static string EncodeHistory(int day, Guid messageId) => Encode(day.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" + messageId.ToString("D"));

    public static bool TryDecodeHistory(string? cursor, out int day, out Guid messageId)
    {
        day = 0;
        messageId = default;
        if (!TryDecode(cursor, out string raw))
        {
            return false;
        }

        int colon = raw.IndexOf(':');
        return colon > 0
            && int.TryParse(raw.AsSpan(0, colon), System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out day)
            && Guid.TryParse(raw.AsSpan(colon + 1), out messageId);
    }
}
