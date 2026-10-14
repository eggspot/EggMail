using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Mta.Core;
using Mta.Mime;

namespace Mta.Dsn;

public enum DsnAction : byte
{
    Failed = 0,
    Delayed,
    Delivered,
    Relayed,
    Expanded,
}

public enum DsnReturnContent : byte
{
    /// <summary>Return only the headers of the original message (RFC 3461 RET=HDRS; the safe default).</summary>
    Headers = 0,

    /// <summary>Return the whole message, truncated to <see cref="DsnRequest.MaxReturnedBytes"/>.</summary>
    Full,
}

public sealed record DsnRecipient(
    EmailAddress Address,
    string Status,
    string? DiagnosticCode = null,
    string? RemoteMta = null,
    DateTimeOffset? LastAttempt = null,
    DateTimeOffset? WillRetryUntil = null,
    string? OriginalRecipient = null);

/// <summary>Everything needed to build a delivery status notification (RFC 3464, with the internationalization of RFC 6533).</summary>
public sealed class DsnRequest
{
    /// <summary>Host name of the reporting MTA (our hostname).</summary>
    public required string ReportingMta { get; init; }

    /// <summary>The original envelope sender, who receives the notification.</summary>
    public required EmailAddress To { get; init; }

    public required DsnAction Action { get; init; }
    public required IReadOnlyList<DsnRecipient> Recipients { get; init; }
    public required DateTimeOffset ArrivalDate { get; init; }
    public required DateTimeOffset Now { get; init; }
    public ReadOnlyMemory<byte> OriginalMessage { get; init; }
    public DsnReturnContent ReturnContent { get; init; } = DsnReturnContent.Headers;
    public int MaxReturnedBytes { get; init; } = 64 * 1024;
    public string? OriginalEnvelopeId { get; init; }

    /// <summary>Local part of the From address; defaults to <c>mailer-daemon</c>.</summary>
    public string FromLocalPart { get; init; } = "mailer-daemon";

    /// <summary>Deterministic boundary and Message-ID suffix for tests; random when null.</summary>
    public string? UniqueToken { get; init; }
}

/// <summary>
/// Builds RFC 3464 delivery status notifications as <c>multipart/report; report-type=delivery-status</c> with a human-readable
/// part, a machine-readable status part and the returned original (headers or truncated full message). The result is
/// marked <c>Auto-Submitted: auto-replied</c> (RFC 3834) and sent with the null return path by the caller, so it can never
/// cause a bounce loop.
/// <para>
/// When anything in the report is not ASCII (an internationalized recipient address, UTF-8 diagnostic text, or a returned original
/// with UTF-8 header fields) the report uses the internationalized forms of RFC 6533: the status part is
/// <c>message/global-delivery-status</c> with UTF-8 field values and the <c>utf-8</c> address type for non-ASCII addresses, the returned
/// headers are <c>message/global-headers</c> and a returned full message is <c>message/global</c>. ASCII addresses keep the
/// <c>rfc822</c> type, so a report about plain recipients is what RFC 3464 describes. The human-readable part is base64 when it is not
/// ASCII; the machine-readable parts are 8-bit UTF-8 (the delivery processor sends them with <c>BODY=8BITMIME</c>, or converts them for
/// servers without it). A report whose header section holds UTF-8 (the sender's address is internationalized) must be queued as an
/// SMTPUTF8 message by the caller.
/// </para>
/// </summary>
public static class DsnBuilder
{
    public static byte[] Build(DsnRequest r)
    {
        ArgumentOutOfRangeException.ThrowIfZero(r.Recipients.Count);
        string token = r.UniqueToken ?? Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();
        string boundary = "=_dsn_" + token;
        string from = $"{r.FromLocalPart}@{Sanitize(r.ReportingMta)}";
        var (subject, intro) = Describe(r);
        var original = r.OriginalMessage.Span;
        bool originalUtf8Headers = !original.IsEmpty && MessageInspector.HasValidUtf8Headers(original);
        bool global = originalUtf8Headers
            || r.Recipients.Any(NeedsUtf8)
            || (r.OriginalEnvelopeId is { } envelopeId && !Ascii.IsValid(envelopeId))
            || !Ascii.IsValid(r.ReportingMta);

        var sb = new StringBuilder(2048);
        sb.Append("From: Mail Delivery System <").Append(from).Append(">\r\n");
        sb.Append("To: <").Append(Sanitize(r.To.ToString())).Append(">\r\n");
        sb.Append("Subject: ").Append(subject).Append("\r\n");
        sb.Append("Date: ").Append(Rfc5322Date(r.Now)).Append("\r\n");
        sb.Append("Message-ID: <dsn-").Append(token).Append('@').Append(Sanitize(r.ReportingMta)).Append(">\r\n");
        sb.Append("Auto-Submitted: auto-replied\r\n");
        sb.Append("MIME-Version: 1.0\r\n");
        sb.Append("Content-Type: multipart/report; report-type=delivery-status;\r\n\tboundary=\"").Append(boundary).Append("\"\r\n\r\n");
        sb.Append("This is a MIME-encapsulated message.\r\n\r\n");

        // Part 1: human readable.
        string human = BuildHuman(r, intro);
        sb.Append("--").Append(boundary).Append("\r\n");
        sb.Append("Content-Type: text/plain; charset=utf-8\r\n");
        if (Ascii.IsValid(human))
        {
            sb.Append("Content-Transfer-Encoding: 7bit\r\n\r\n").Append(human);
        }
        else
        {
            sb.Append("Content-Transfer-Encoding: base64\r\n\r\n");
            // 76 characters per line, CRLF explicitly (Base64FormattingOptions.InsertLineBreaks uses the platform's line break, which can be a bare LF).
            string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(human));
            for (int i = 0; i < encoded.Length; i += 76)
            {
                sb.Append(encoded, i, Math.Min(76, encoded.Length - i)).Append("\r\n");
            }
        }

        // Part 2: machine readable.
        sb.Append("\r\n--").Append(boundary).Append("\r\n");
        if (global)
        {
            sb.Append("Content-Type: message/global-delivery-status\r\nContent-Transfer-Encoding: 8bit\r\n\r\n");
        }
        else
        {
            sb.Append("Content-Type: message/delivery-status\r\n\r\n");
        }

        sb.Append("Reporting-MTA: dns; ").Append(Sanitize(r.ReportingMta)).Append("\r\n");
        if (r.OriginalEnvelopeId is not null)
        {
            sb.Append("Original-Envelope-Id: ").Append(Sanitize(r.OriginalEnvelopeId)).Append("\r\n");
        }

        sb.Append("Arrival-Date: ").Append(Rfc5322Date(r.ArrivalDate)).Append("\r\n");
        foreach (var rcpt in r.Recipients)
        {
            sb.Append("\r\n");
            if (rcpt.OriginalRecipient is not null)
            {
                string originalRecipient = Sanitize(rcpt.OriginalRecipient);
                sb.Append("Original-Recipient: ").Append(AddressType(originalRecipient)).Append("; ").Append(originalRecipient).Append("\r\n");
            }

            string finalRecipient = Sanitize(rcpt.Address.ToString());
            sb.Append("Final-Recipient: ").Append(AddressType(finalRecipient)).Append("; ").Append(finalRecipient).Append("\r\n");
            sb.Append("Action: ").Append(r.Action.ToString().ToLowerInvariant()).Append("\r\n");
            sb.Append("Status: ").Append(Sanitize(rcpt.Status)).Append("\r\n");
            if (rcpt.RemoteMta is not null)
            {
                sb.Append("Remote-MTA: dns; ").Append(Sanitize(rcpt.RemoteMta)).Append("\r\n");
            }

            if (rcpt.DiagnosticCode is not null)
            {
                sb.Append("Diagnostic-Code: smtp; ").Append(Fold(Sanitize(rcpt.DiagnosticCode))).Append("\r\n");
            }

            if (rcpt.LastAttempt is { } last)
            {
                sb.Append("Last-Attempt-Date: ").Append(Rfc5322Date(last)).Append("\r\n");
            }

            if (r.Action == DsnAction.Delayed && rcpt.WillRetryUntil is { } until)
            {
                sb.Append("Will-Retry-Until: ").Append(Rfc5322Date(until)).Append("\r\n");
            }
        }

        // Part 3: original message or its headers.
        bool full = r.ReturnContent == DsnReturnContent.Full;
        byte[] returned = Truncate(original, r.MaxReturnedBytes, headersOnly: !full);
        string returnedType = full
            ? (originalUtf8Headers ? "message/global" : "message/rfc822")
            : (originalUtf8Headers ? "message/global-headers" : "text/rfc822-headers");
        sb.Append("\r\n--").Append(boundary).Append("\r\n");
        sb.Append("Content-Type: ").Append(returnedType).Append("\r\nContent-Transfer-Encoding: 8bit\r\n\r\n");

        // The report text is UTF-8 (ASCII unless it is internationalized); the returned original goes in byte for byte.
        var output = new MemoryStream(sb.Length + returned.Length + 128);
        output.Write(Encoding.UTF8.GetBytes(sb.ToString()));
        output.Write(returned);
        if (returned.Length == 0 || returned[^1] != (byte)'\n')
        {
            output.Write("\r\n"u8);
        }

        output.Write(Encoding.UTF8.GetBytes("\r\n--" + boundary + "--\r\n"));
        return output.ToArray();
    }

    private static bool NeedsUtf8(DsnRecipient rcpt) =>
        !Ascii.IsValid(rcpt.Address.ToString())
        || (rcpt.OriginalRecipient is { } o && !Ascii.IsValid(o))
        || (rcpt.DiagnosticCode is { } d && !Ascii.IsValid(d))
        || (rcpt.RemoteMta is { } m && !Ascii.IsValid(m));

    /// <summary>RFC 6533 section 3.2: addresses that are not ASCII use the <c>utf-8</c> address type, the rest stay <c>rfc822</c>.</summary>
    private static string AddressType(string address) => Ascii.IsValid(address) ? "rfc822" : "utf-8";

    private static (string Subject, string Intro) Describe(DsnRequest r) => r.Action switch
    {
        DsnAction.Failed => ("Undelivered Mail Returned to Sender", "This is the mail system at host {0}.\r\n\r\nI'm sorry to have to inform you that your message could not be delivered to one or more recipients. It was not accepted by the destination mail system, and no further delivery attempts will be made.\r\n"),
        DsnAction.Delayed => ("Delayed Mail (still being retried)", "This is the mail system at host {0}.\r\n\r\nYour message has not been delivered yet. This is only a warning: delivery will keep being attempted and you do not need to resend it.\r\n"),
        DsnAction.Delivered => ("Successful Mail Delivery Report", "This is the mail system at host {0}.\r\n\r\nYour message was delivered to the recipients listed below.\r\n"),
        _ => ("Mail Delivery Status Report", "This is the mail system at host {0}.\r\n\r\nThis is a delivery status report for your message.\r\n"),
    };

    private static string BuildHuman(DsnRequest r, string intro)
    {
        var sb = new StringBuilder(512);
        sb.Append(string.Format(CultureInfo.InvariantCulture, intro, Sanitize(r.ReportingMta)));
        sb.Append("\r\nRecipients:\r\n");
        foreach (var rcpt in r.Recipients)
        {
            sb.Append("  <").Append(Sanitize(rcpt.Address.ToString())).Append(">: ").Append(Sanitize(rcpt.Status));
            if (rcpt.DiagnosticCode is not null)
            {
                sb.Append(" (").Append(Sanitize(rcpt.DiagnosticCode)).Append(')');
            }

            sb.Append("\r\n");
        }

        return sb.ToString();
    }

    /// <summary>
    /// Replaces control characters (CR, LF, NUL, tab and the other C0/C1 controls) and the bidirectional formatting characters with a space, so
    /// values cannot inject header fields or reorder the text a person reads (diagnostic text comes from remote servers).
    /// </summary>
    private static string Sanitize(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            sb.Append(char.IsControl(c) || IsBidiControl(c) ? ' ' : c);
        }

        return sb.ToString().Trim();
    }

    private static bool IsBidiControl(char c) => c is '\u061C' or '\u200E' or '\u200F' || c is >= '\u202A' and <= '\u202E' || c is >= '\u2066' and <= '\u2069';

    /// <summary>At most 900 characters, never ending inside a surrogate pair.</summary>
    private static string Fold(string s)
    {
        if (s.Length <= 900)
        {
            return s;
        }

        return char.IsHighSurrogate(s[899]) ? s[..899] : s[..900];
    }

    private static string Rfc5322Date(DateTimeOffset d) => d.UtcDateTime.ToString("ddd, dd MMM yyyy HH:mm:ss '+0000'", CultureInfo.InvariantCulture);

    private static byte[] Truncate(ReadOnlySpan<byte> original, int max, bool headersOnly)
    {
        int end = original.Length;
        if (headersOnly)
        {
            int idx = original.IndexOf("\r\n\r\n"u8);
            end = idx >= 0 ? idx + 2 : original.Length;
        }

        if (end > max)
        {
            // Cut at a line boundary so the returned part stays well-formed.
            int cut = original[..max].LastIndexOf((byte)'\n');
            end = cut >= 0 ? cut + 1 : max;
            while (cut < 0 && end > 0 && (original[end] & 0xC0) == 0x80)
            {
                end--;   // a line longer than the limit: do not cut a UTF-8 sequence in half
            }
        }

        return original[..end].ToArray();
    }
}
