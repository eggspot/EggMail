using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Mta.Core;

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

/// <summary>Everything needed to build a delivery status notification (RFC 3464).</summary>
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
/// part, a <c>message/delivery-status</c> part and the returned original (headers or truncated full message). The result is
/// marked <c>Auto-Submitted: auto-replied</c> (RFC 3834) and sent with the null return path by the caller, so it can never
/// cause a bounce loop.
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
        bool ascii = human.All(c => c < 128);
        sb.Append("--").Append(boundary).Append("\r\n");
        sb.Append("Content-Type: text/plain; charset=utf-8\r\n");
        if (ascii)
        {
            sb.Append("Content-Transfer-Encoding: 7bit\r\n\r\n").Append(human);
        }
        else
        {
            sb.Append("Content-Transfer-Encoding: base64\r\n\r\n");
            sb.Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(human), Base64FormattingOptions.InsertLineBreaks).Replace("\n", "\r\n", StringComparison.Ordinal)).Append("\r\n");
        }

        // Part 2: machine readable.
        sb.Append("\r\n--").Append(boundary).Append("\r\n");
        sb.Append("Content-Type: message/delivery-status\r\n\r\n");
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
                sb.Append("Original-Recipient: rfc822; ").Append(Sanitize(rcpt.OriginalRecipient)).Append("\r\n");
            }

            sb.Append("Final-Recipient: rfc822; ").Append(Sanitize(rcpt.Address.ToString())).Append("\r\n");
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
        sb.Append("\r\n--").Append(boundary).Append("\r\n");
        var original = r.OriginalMessage.Span;
        if (r.ReturnContent == DsnReturnContent.Full)
        {
            sb.Append("Content-Type: message/rfc822\r\nContent-Transfer-Encoding: 8bit\r\n\r\n");
            AppendLatin1(sb, Truncate(original, r.MaxReturnedBytes, headersOnly: false));
        }
        else
        {
            sb.Append("Content-Type: text/rfc822-headers\r\nContent-Transfer-Encoding: 8bit\r\n\r\n");
            AppendLatin1(sb, Truncate(original, r.MaxReturnedBytes, headersOnly: true));
        }

        sb.Append("\r\n--").Append(boundary).Append("--\r\n");
        return Encoding.Latin1.GetBytes(Latin1Safe(sb.ToString()));
    }

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

    /// <summary>Strips CR, LF and NUL so values cannot inject header fields (diagnostic text comes from remote servers).</summary>
    private static string Sanitize(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            sb.Append(c is '\r' or '\n' or '\0' or '\t' ? ' ' : c);
        }

        return sb.ToString().Trim();
    }

    private static string Fold(string s)
    {
        if (s.Length <= 900)
        {
            return s;
        }

        return s[..900];
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
        }

        return original[..end].ToArray();
    }

    private static void AppendLatin1(StringBuilder sb, byte[] data)
    {
        sb.Append(Encoding.Latin1.GetString(data));
        if (data.Length == 0 || data[^1] != (byte)'\n')
        {
            sb.Append("\r\n");
        }
    }

    /// <summary>The message is assembled as text; any char above Latin-1 (from non-ASCII addresses) is replaced to keep the 8bit encoding honest.</summary>
    private static string Latin1Safe(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            sb.Append(c > 255 ? '?' : c);
        }

        return sb.ToString();
    }
}
