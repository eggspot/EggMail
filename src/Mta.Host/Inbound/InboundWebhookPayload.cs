using System.Globalization;
using System.Text;
using System.Text.Json;
using Mta.Core;
using Mta.Mime;
using Mta.Storage;
using Mta.Storage.Logic;
using Mta.Webhooks;

namespace Mta.Host.Inbound;

/// <summary>Size limits of the webhook payload formats (<c>Inbound:Webhook:*</c>).</summary>
/// <param name="MaxTextBytes">The text and the HTML part are each cut at this many bytes.</param>
/// <param name="MaxRawMessageBytes">The largest message sent as <c>raw_mime</c>.</param>
/// <param name="ApiBaseUrl">Prefix of the paths in the payload; null or empty: the bare paths.</param>
public sealed record InboundWebhookLimits(int MaxTextBytes, long MaxRawMessageBytes, string? ApiBaseUrl);

/// <summary>
/// The bodies a route's <c>webhook</c> action posts (design section 11.7). Everything in a received message is attacker-controlled: the payload is built with a JSON writer (values are
/// escaped strings, non-ASCII becomes <c>\uXXXX</c>), the <c>raw_mime</c> header values are percent-encoded ASCII, and nothing from the message is ever put into a URL or a header name.
/// </summary>
public static class InboundWebhookPayload
{
    /// <summary>Most headers/addresses/references listed, and the total characters of the listed headers (the payload must stay far below what a receiver, a retry or the signature window can take).</summary>
    public const int MaxListedHeaderChars = 256 * 1024;
    public const int MaxAddressesPerField = 100;
    public const int MaxReferences = 50;
    public const int MaxAttachmentsListed = 200;

    /// <summary>The <c>webhook-id</c> of an inbound message: <c>evt_&lt;inbound id&gt;</c> for the first generation, <c>evt_&lt;inbound id&gt;-&lt;n&gt;</c> after the n-th manual retry (design section 11.7).</summary>
    public static string WebhookId(Guid inboundId, int retryGeneration) =>
        retryGeneration <= 0 ? "evt_" + Ids.ToCompact(inboundId) : "evt_" + Ids.ToCompact(inboundId) + "-" + retryGeneration.ToString(CultureInfo.InvariantCulture);

    /// <summary>The path of the stored message in the API (raw download), prefixed with the configured base URL.</summary>
    public static string RawPath(Guid inboundId, string? baseUrl) => Join(baseUrl, "/api/v1/inbound/messages/" + Ids.ToCompact(inboundId) + "/raw");

    public static string AttachmentPath(Guid inboundId, int index, string? baseUrl) =>
        Join(baseUrl, "/api/v1/inbound/messages/" + Ids.ToCompact(inboundId) + "/attachments/" + index.ToString(CultureInfo.InvariantCulture));

    private static string Join(string? baseUrl, string path) => string.IsNullOrEmpty(baseUrl) ? path : baseUrl.TrimEnd('/') + path;

    /// <summary>The JSON document of the <c>json</c> format. A message the MIME parser cannot read yields the envelope and verdicts with <c>"parse_failed": true</c> and no content fields.</summary>
    public static byte[] BuildJson(InboundMessage message, ReadOnlyMemory<byte> raw, string webhookId, InboundWebhookLimits limits)
    {
        InboundMessageContent? content = null;
        bool parseFailed = false;
        try
        {
            content = InboundContentReader.Read(raw, limits.MaxTextBytes);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            parseFailed = true;
        }

        using var stream = new MemoryStream(4096);
        using (var w = new Utf8JsonWriter(stream))
        {
            w.WriteStartObject();
            w.WriteString("id", webhookId);
            w.WriteString("type", WebhookEventFactory.InboundMessageReceived);
            w.WriteString("timestamp", Time(message.ReceivedAt));
            w.WriteStartObject("data");
            w.WriteString("inbound_id", Ids.ToCompact(message.Id));
            Str(w, "domain", message.Domain);
            if (message.RouteId is { } routeId) { w.WriteString("route_id", Ids.ToCompact(routeId)); } else { w.WriteNull("route_id"); }
            w.WriteString("received_at", Time(message.ReceivedAt));
            w.WriteNumber("size", message.Size);
            w.WriteBoolean("dmarc_flagged", message.Disposition == InboundDmarcDisposition.Flagged);
            if (message.RetryGeneration > 0) { w.WriteNumber("retry_generation", message.RetryGeneration); }

            w.WriteStartObject("connection");
            Str(w, "remote_ip", message.RemoteAddress);
            Str(w, "helo", message.Helo);
            w.WriteBoolean("tls", message.TlsUsed);
            w.WriteEndObject();

            w.WriteStartObject("envelope");
            Str(w, "from", message.EnvelopeFrom);
            Str(w, "to", message.EnvelopeTo);
            w.WriteEndObject();

            WriteAuth(w, message.Auth);
            WriteMessage(w, content, parseFailed, message.Subject);
            WriteAttachments(w, message.Id, content, limits.ApiBaseUrl);
            w.WriteString("raw_url", RawPath(message.Id, limits.ApiBaseUrl));
            w.WriteEndObject();
            w.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static void WriteAuth(Utf8JsonWriter w, InboundAuthResults auth)
    {
        w.WriteStartObject("auth");
        w.WriteStartObject("spf");
        w.WriteString("result", InboundNames.Of(auth.Spf));
        Str(w, "domain", auth.SpfDomain);
        w.WriteEndObject();
        w.WriteStartObject("spf_helo");
        w.WriteString("result", InboundNames.Of(auth.SpfHelo));
        w.WriteEndObject();
        w.WriteStartObject("dkim");
        w.WriteString("result", InboundNames.Of(auth.Dkim));
        Str(w, "domain", auth.DkimDomain);
        w.WriteEndObject();
        w.WriteStartObject("dmarc");
        w.WriteString("result", InboundNames.Of(auth.Dmarc));
        Str(w, "policy", auth.DmarcPolicy);
        w.WriteEndObject();
        w.WriteStartObject("arc");
        w.WriteString("result", InboundNames.Of(auth.Arc));
        w.WriteEndObject();
        w.WriteEndObject();
    }

    private static void WriteMessage(Utf8JsonWriter w, InboundMessageContent? content, bool parseFailed, string? recordedSubject)
    {
        w.WriteStartObject("message");
        if (content is null)
        {
            Str(w, "subject", recordedSubject);
            w.WriteBoolean("parse_failed", parseFailed);
            w.WriteEndObject();
            return;
        }

        string? Header(string name) => content.Headers.FirstOrDefault(h => string.Equals(h.Name, name, StringComparison.OrdinalIgnoreCase))?.Value;

        Str(w, "message_id", Header("Message-ID"));
        Str(w, "subject", Header("Subject") ?? recordedSubject);
        Str(w, "from", Header("From"));
        WriteAddresses(w, "to", content, "To");
        WriteAddresses(w, "cc", content, "Cc");
        if (Addresses(content, "Reply-To") is { Count: > 0 } replyTo) { Str(w, "reply_to", string.Join(", ", replyTo)); } else { w.WriteNull("reply_to"); }
        Str(w, "date", Header("Date"));
        Str(w, "in_reply_to", Header("In-Reply-To"));
        w.WriteStartArray("references");
        if (Header("References") is { Length: > 0 } references)
        {
            int listed = 0;
            foreach (string token in references.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries))
            {
                if (listed++ == MaxReferences) { break; }
                w.WriteStringValue(Safe(token.Length > 998 ? token[..998] : token));
            }
        }

        w.WriteEndArray();
        Str(w, "text", content.Text);
        Str(w, "html", content.Html);

        bool truncated = content.Truncated;
        w.WriteStartArray("headers");
        int chars = 0;
        foreach (InboundHeaderField header in content.Headers)
        {
            chars += header.Name.Length + header.Value.Length;
            if (chars > MaxListedHeaderChars)
            {
                truncated = true;
                break;
            }

            w.WriteStartObject();
            w.WriteString("name", Safe(header.Name));
            w.WriteString("value", Safe(header.Value));
            w.WriteEndObject();
        }

        w.WriteEndArray();
        w.WriteBoolean("truncated", truncated);
        w.WriteEndObject();
    }

    private static void WriteAddresses(Utf8JsonWriter w, string field, InboundMessageContent content, string header)
    {
        w.WriteStartArray(field);
        foreach (string address in Addresses(content, header))
        {
            w.WriteStringValue(Safe(address));
        }

        w.WriteEndArray();
    }

    private static List<string> Addresses(InboundMessageContent content, string header)
    {
        var result = new List<string>();
        if (content.Message is not { } message || !message.Headers.TryGetFirst(header, out MimeHeader field))
        {
            return result;
        }

        foreach (Mailbox mailbox in AddressList.Parse(field).Mailboxes)
        {
            if (result.Count == MaxAddressesPerField) { break; }
            string text = mailbox.ToString();
            result.Add(text.Length > 400 ? text[..400] : text);
        }

        return result;
    }

    private static void WriteAttachments(Utf8JsonWriter w, Guid inboundId, InboundMessageContent? content, string? baseUrl)
    {
        w.WriteStartArray("attachments");
        if (content is not null)
        {
            foreach (InboundAttachment attachment in content.Attachments.Take(MaxAttachmentsListed))
            {
                w.WriteStartObject();
                w.WriteNumber("index", attachment.Index);
                Str(w, "filename", attachment.FileName);
                Str(w, "content_type", attachment.ContentType);
                w.WriteNumber("size", attachment.Size);
                Str(w, "content_id", attachment.ContentId);
                w.WriteString("disposition", attachment.Disposition);
                w.WriteString("url", AttachmentPath(inboundId, attachment.Index, baseUrl));
                w.WriteEndObject();
            }
        }

        w.WriteEndArray();
    }

    private static void Str(Utf8JsonWriter w, string name, string? value)
    {
        if (value is null) { w.WriteNull(name); } else { w.WriteString(name, Safe(value)); }
    }

    private static string Time(DateTimeOffset at) => at.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    /// <summary>The string with every unpaired surrogate replaced by U+FFFD (the JSON writer refuses invalid UTF-16, and a hostile message must not be able to make the payload unbuildable).</summary>
    internal static string Safe(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
            {
                i++;
            }
            else if (char.IsSurrogate(c))
            {
                return Repair(value);
            }
        }

        return value;
    }

    private static string Repair(string value)
    {
        var sb = new StringBuilder(value.Length);
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
            {
                sb.Append(c).Append(value[++i]);
            }
            else
            {
                sb.Append(char.IsSurrogate(c) ? '�' : c);
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// The <c>EggMail-*</c> request headers of the <c>raw_mime</c> format: the id, the envelope, the client address and the verdicts, each value percent-encoded (UTF-8) to printable ASCII,
    /// so a hostile envelope address or verdict domain cannot inject a header or break the framing.
    /// </summary>
    public static List<KeyValuePair<string, string>> RawHeaders(InboundMessage message) =>
    [
        new("EggMail-Inbound-Id", Ids.ToCompact(message.Id)),
        new("EggMail-Envelope-From", EncodeHeaderValue(message.EnvelopeFrom)),
        new("EggMail-Envelope-To", EncodeHeaderValue(message.EnvelopeTo)),
        new("EggMail-Remote-Ip", EncodeHeaderValue(message.RemoteAddress)),
        new("EggMail-Spf", InboundNames.Of(message.Auth.Spf)),
        new("EggMail-Dkim", InboundNames.Of(message.Auth.Dkim)),
        new("EggMail-Dmarc", InboundNames.Of(message.Auth.Dmarc)),
        new("EggMail-Arc", InboundNames.Of(message.Auth.Arc)),
        new("EggMail-Dmarc-Flagged", message.Disposition == InboundDmarcDisposition.Flagged ? "true" : "false"),
    ];

    /// <summary>
    /// Percent-encodes the UTF-8 bytes of <paramref name="value"/> except the characters that are safe in a header value of any HTTP implementation
    /// (letters, digits and <c>- . _ ~ @ + : , ; = ! $ ' ( ) * /</c>); control characters, spaces, quotes, angle brackets, percent signs and everything non-ASCII are encoded. Cut at 1024 characters.
    /// </summary>
    public static string EncodeHeaderValue(string value)
    {
        if (value.Length > 1024)
        {
            value = value[..1024];
        }

        var sb = new StringBuilder(value.Length + 8);
        foreach (byte b in Encoding.UTF8.GetBytes(Safe(value)))
        {
            if (b is (>= (byte)'A' and <= (byte)'Z') or (>= (byte)'a' and <= (byte)'z') or (>= (byte)'0' and <= (byte)'9') || "-._~@+:,;=!$'()*/".Contains((char)b, StringComparison.Ordinal) && b < 0x80)
            {
                sb.Append((char)b);
            }
            else
            {
                sb.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
            }
        }

        return sb.ToString();
    }
}
