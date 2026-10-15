using System.Buffers;
using System.Text;
using System.Text.Unicode;

namespace Mta.Mime;

/// <summary>An attachment (or inline resource) found in a message; the content itself is not kept.</summary>
/// <param name="FileName">File name from Content-Disposition or Content-Type, control characters removed, or null.</param>
/// <param name="ContentType">Lower-case "type/subtype".</param>
/// <param name="Size">Decoded size in bytes.</param>
/// <param name="ContentId">Content-ID without angle brackets, or null.</param>
/// <param name="IsInline">True for inline dispositions and for resources referenced by Content-ID.</param>
public sealed record AttachmentInfo(string? FileName, string ContentType, long Size, string? ContentId, bool IsInline);

/// <summary>What <see cref="MessageContentExtractor"/> found in a message; the data stored for message history.</summary>
public readonly struct ExtractedContent
{
    internal ExtractedContent(
        string? subject,
        string? textBody,
        string? htmlBody,
        IReadOnlyList<AttachmentInfo> attachments,
        bool textTruncated,
        bool htmlTruncated,
        bool subjectTruncated,
        MimeAnomaly anomalies,
        ReadOnlyMemory<byte>? textBodyUtf8 = null,
        ReadOnlyMemory<byte>? htmlBodyUtf8 = null)
    {
        TextBodyUtf8 = textBodyUtf8;
        HtmlBodyUtf8 = htmlBodyUtf8;
        Subject = subject;
        TextBody = textBody;
        HtmlBody = htmlBody;
        Attachments = attachments;
        TextTruncated = textTruncated;
        HtmlTruncated = htmlTruncated;
        SubjectTruncated = subjectTruncated;
        Anomalies = anomalies;
    }

    /// <summary>The decoded Subject (RFC 2047 words decoded, control characters replaced by spaces), or null when absent.</summary>
    public string? Subject { get; }

    /// <summary>The first text/plain body part as UTF-16 text, or null.</summary>
    public string? TextBody { get; }

    /// <summary>The first text/html body part as UTF-16 text (not sanitized), or null.</summary>
    public string? HtmlBody { get; }

    /// <summary>
    /// Only when asked for (<c>bodiesAsUtf8</c>): the text body as the UTF-8 bytes it already is in the message (a slice of the parsed message's memory), in which
    /// case <see cref="TextBody"/> is null. Set only for a body that needs no decoding and no cutting, so the bytes are exactly the UTF-8 of the string
    /// <see cref="TextBody"/> would have been.
    /// </summary>
    public ReadOnlyMemory<byte>? TextBodyUtf8 { get; }

    /// <summary>Like <see cref="TextBodyUtf8"/> for the HTML body.</summary>
    public ReadOnlyMemory<byte>? HtmlBodyUtf8 { get; }

    /// <summary>All attachments and inline resources in document order.</summary>
    public IReadOnlyList<AttachmentInfo> Attachments { get; }

    /// <summary>True when the text body was cut at the size limit.</summary>
    public bool TextTruncated { get; }

    /// <summary>True when the HTML body was cut at the size limit.</summary>
    public bool HtmlTruncated { get; }

    /// <summary>True when the subject was cut at <see cref="MessageContentExtractor.MaxSubjectChars"/>.</summary>
    public bool SubjectTruncated { get; }

    /// <summary>True when anything (subject, text or HTML) was cut.</summary>
    public bool IsTruncated => TextTruncated || HtmlTruncated || SubjectTruncated;

    /// <summary>All parsing anomalies of the message.</summary>
    public MimeAnomaly Anomalies { get; }
}

/// <summary>
/// Extracts what the message history stores (decision 12): decoded subject, text and HTML body, and an attachment index.
/// Never throws for message content; hostile structure only produces fewer results and anomaly flags.
/// </summary>
public static class MessageContentExtractor
{
    /// <summary>The default for <c>Content:MaxStoredBodyBytes</c> (256 KiB).</summary>
    public const int DefaultMaxStoredBodyBytes = 256 * 1024;

    /// <summary>Longest subject kept, in UTF-16 code units.</summary>
    public const int MaxSubjectChars = 2048;

    /// <summary>
    /// Extracts the content of <paramref name="raw"/>. Each body is limited to <paramref name="maxBodyBytes"/> bytes of UTF-8
    /// (cut on a character boundary, with the matching truncation flag set).
    /// </summary>
    public static ExtractedContent Extract(ReadOnlyMemory<byte> raw, int maxBodyBytes = DefaultMaxStoredBodyBytes, MimeLimits? limits = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxBodyBytes);
        return Extract(MimeMessage.Parse(raw, limits ?? MimeLimits.Default), maxBodyBytes);
    }

    /// <summary>
    /// Extracts the content of a message that was already parsed (parse once, use many times: the submission path checks the sender,
    /// repairs the headers and extracts the history content from one parse). The result is identical to
    /// <see cref="Extract(ReadOnlyMemory{byte}, int, MimeLimits?)"/> on <see cref="MimeMessage.Raw"/> with the limits the message was parsed with.
    /// </summary>
    public static ExtractedContent Extract(MimeMessage message, int maxBodyBytes = DefaultMaxStoredBodyBytes) => Extract(message, maxBodyBytes, bodiesAsUtf8: false);

    /// <summary>
    /// Like <see cref="Extract(MimeMessage, int)"/>; with <paramref name="bodiesAsUtf8"/> a text or HTML body that is already valid UTF-8 in the message and needs
    /// no decoding is returned as that memory (<see cref="ExtractedContent.TextBodyUtf8"/>) instead of as a new string, which is twice the size and a copy.
    /// Everything else, and everything else about the result, is the same.
    /// </summary>
    public static ExtractedContent Extract(MimeMessage message, int maxBodyBytes, bool bodiesAsUtf8)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentOutOfRangeException.ThrowIfNegative(maxBodyBytes);
        var limits = message.Limits;
        var an = message.Anomalies;

        string? subject = null;
        bool subjectTruncated = false;
        if (message.Headers.TryGetFirst(HeaderId.Subject, out var subjectHeader))
        {
            string decoded = Rfc2047.DecodeCore(subjectHeader.GetValue(limits.MaxHeaderValueBytes), ref an);
            subject = SanitizeLine(decoded, out subjectTruncated);
        }

        string? text = null;
        string? html = null;
        ReadOnlyMemory<byte>? textUtf8 = null;
        ReadOnlyMemory<byte>? htmlUtf8 = null;
        bool textTruncated = false;
        bool htmlTruncated = false;
        List<AttachmentInfo>? attachments = null;

        // A single-part message (the common case) needs neither a stack nor an attachment list.
        Stack<MimePart>? stack = null;
        var part = message.Root;
        while (true)
        {
            if (part.IsMultipart)
            {
                stack ??= new Stack<MimePart>();
                for (int i = part.Children.Count - 1; i >= 0; i--)
                {
                    stack.Push(part.Children[i]);
                }
            }
            else
            {
                var ct = part.ContentType;
                bool markedAttachment = part.Disposition is { IsAttachment: true };
                if (!markedAttachment && ct.IsText && ct.MediaSubtype == "plain" && text is null && textUtf8 is null)
                {
                    if (bodiesAsUtf8 && part.TryGetVerbatimUtf8Text(maxBodyBytes, ref an, out var textBytes))
                    {
                        textUtf8 = textBytes;
                    }
                    else
                    {
                        text = ReadText(part, maxBodyBytes, ref an, out textTruncated);
                    }
                }
                else if (!markedAttachment && ct.IsText && ct.MediaSubtype == "html" && html is null && htmlUtf8 is null)
                {
                    if (bodiesAsUtf8 && part.TryGetVerbatimUtf8Text(maxBodyBytes, ref an, out var htmlBytes))
                    {
                        htmlUtf8 = htmlBytes;
                    }
                    else
                    {
                        html = ReadText(part, maxBodyBytes, ref an, out htmlTruncated);
                    }
                }
                else
                {
                    string? contentId = part.ContentId;
                    bool inline = part.Disposition is { IsInline: true } || (contentId is not null && !markedAttachment);
                    string? fileName = part.FileName;
                    (attachments ??= []).Add(new AttachmentInfo(
                        fileName is null ? null : SanitizeLine(fileName, out _),
                        ct.MimeType,
                        part.GetDecodedLength(),
                        contentId,
                        inline));
                }
            }

            if (stack is null || stack.Count == 0)
            {
                break;
            }

            part = stack.Pop();
        }

        return new ExtractedContent(subject, text, html, (IReadOnlyList<AttachmentInfo>?)attachments ?? [], textTruncated, htmlTruncated, subjectTruncated, an, textUtf8, htmlUtf8);
    }

    private static string ReadText(MimePart part, int maxBodyBytes, ref MimeAnomaly an, out bool truncated)
    {
        // A decoded character takes at most 4 UTF-8 bytes but usually fewer bytes than its source encoding;
        // read up to maxBodyBytes source bytes, then clamp the UTF-8 size of the text.
        string text = part.GetText(maxBodyBytes, out truncated, ref an);
        if (text.AsSpan().Contains('\0'))
        {
            text = text.Replace("\0", string.Empty, StringComparison.Ordinal);
        }

        if (Encoding.UTF8.GetByteCount(text) > maxBodyBytes)
        {
            truncated = true;
            byte[] buffer = ArrayPool<byte>.Shared.Rent(Math.Max(1, maxBodyBytes));
            try
            {
                Utf8.FromUtf16(text, buffer.AsSpan(0, maxBodyBytes), out int charsRead, out _, replaceInvalidSequences: true, isFinalBlock: false);
                text = text[..charsRead];
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        return text;
    }

    /// <summary>Replaces each run of control characters (including CR, LF, TAB and NUL) with one space, trims, and caps the length.</summary>
    private static string SanitizeLine(string value, out bool truncated)
    {
        truncated = false;
        bool dirty = false;
        foreach (char c in value)
        {
            if (char.IsControl(c))
            {
                dirty = true;
                break;
            }
        }

        if (value.Length > MaxSubjectChars)
        {
            value = value[..MaxSubjectChars];
            if (char.IsHighSurrogate(value[^1]))
            {
                value = value[..^1];
            }

            truncated = true;
            dirty = true;
        }

        if (!dirty)
        {
            return value.Trim();
        }

        // Each run of control characters becomes one space.
        var sb = new System.Text.StringBuilder(value.Length);
        bool inRun = false;
        foreach (char c in value)
        {
            if (char.IsControl(c))
            {
                if (!inRun)
                {
                    sb.Append(' ');
                }

                inRun = true;
            }
            else
            {
                sb.Append(c);
                inRun = false;
            }
        }

        return sb.ToString().Trim();
    }
}
