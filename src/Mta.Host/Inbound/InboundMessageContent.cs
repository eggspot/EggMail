using System.Text;
using Mta.Mime;

namespace Mta.Host.Inbound;

/// <summary>One header field of a received message, decoded for display (RFC 2047 words decoded, control characters replaced).</summary>
public sealed record InboundHeaderField(string Name, string Value);

/// <summary>An attachment or inline resource of a received message; <see cref="Part"/> gives its bytes on demand.</summary>
public sealed record InboundAttachment(int Index, string? FileName, string ContentType, long Size, string? ContentId, string Disposition, MimePart Part);

/// <summary>What the API shows of a received message: headers, the first text and HTML bodies (bounded) and the attachment index.</summary>
public sealed class InboundMessageContent
{
    public required IReadOnlyList<InboundHeaderField> Headers { get; init; }

    public string? Text { get; init; }

    public string? Html { get; init; }

    public bool Truncated { get; init; }

    public required IReadOnlyList<InboundAttachment> Attachments { get; init; }

    /// <summary>The parse tree the attachment parts belong to (kept alive by the parts; here for clarity of ownership).</summary>
    internal MimeMessage? Message { get; init; }
}

/// <summary>
/// Reads a stored inbound message for the API and for the webhook payload. The stored copy is hostile input: parsing is bounded by <see cref="MimeLimits"/>, the
/// bodies are cut at a caller-given size, nothing is sanitized beyond control characters (the dashboard renders HTML in a sandbox, the API only returns text),
/// and a message the parser cannot make sense of yields fewer fields, never an exception.
/// </summary>
public static class InboundContentReader
{
    /// <summary>Most header fields returned and the longest value of one (a message with more is cut, not refused).</summary>
    public const int MaxHeaders = 200;

    public const int MaxHeaderValueChars = 8 * 1024;

    public static InboundMessageContent Read(ReadOnlyMemory<byte> raw, int maxBodyBytes)
    {
        MimeMessage message = MimeMessage.Parse(raw, MimeLimits.Default);

        var headers = new List<InboundHeaderField>(Math.Min(message.Headers.Count, MaxHeaders));
        foreach (MimeHeader header in message.Headers)
        {
            if (headers.Count == MaxHeaders)
            {
                break;
            }

            headers.Add(new InboundHeaderField(Clean(header.Name, 200), Clean(header.GetDecodedValue(MaxHeaderValueChars * 4), MaxHeaderValueChars)));
        }

        string? text = null;
        string? html = null;
        bool truncated = false;
        var attachments = new List<InboundAttachment>();
        // The same walk (into multiparts only: an embedded message is one opaque attachment) and the same classification as MessageContentExtractor, so the
        // index here is the index of its attachment list.
        var stack = new Stack<MimePart>();
        stack.Push(message.Root);
        while (stack.Count > 0)
        {
            MimePart part = stack.Pop();
            if (part.IsMultipart)
            {
                for (int i = part.Children.Count - 1; i >= 0; i--)
                {
                    stack.Push(part.Children[i]);
                }

                continue;
            }

            ContentType ct = part.ContentType;
            bool markedAttachment = part.Disposition is { IsAttachment: true };
            if (!markedAttachment && ct.IsText && ct.MediaSubtype == "plain" && text is null)
            {
                text = ReadBody(part, maxBodyBytes, ref truncated);
            }
            else if (!markedAttachment && ct.IsText && ct.MediaSubtype == "html" && html is null)
            {
                html = ReadBody(part, maxBodyBytes, ref truncated);
            }
            else
            {
                string? contentId = part.ContentId;
                bool inline = part.Disposition is { IsInline: true } || (contentId is not null && !markedAttachment);
                string? fileName = part.FileName;
                attachments.Add(new InboundAttachment(attachments.Count, fileName is null ? null : Clean(fileName, 255), ct.MimeType, part.GetDecodedLength(), contentId, inline ? "inline" : "attachment", part));
            }
        }

        return new InboundMessageContent { Headers = headers, Text = text, Html = html, Truncated = truncated, Attachments = attachments, Message = message };
    }

    private static string ReadBody(MimePart part, int maxBodyBytes, ref bool truncated)
    {
        string body = part.GetText(maxBodyBytes, out bool cut);
        truncated |= cut;
        if (body.Contains('\0', StringComparison.Ordinal))
        {
            body = body.Replace("\0", string.Empty, StringComparison.Ordinal);
        }

        if (Encoding.UTF8.GetByteCount(body) > maxBodyBytes)
        {
            truncated = true;
            int keep = Math.Min(body.Length, maxBodyBytes);
            while (keep > 0 && Encoding.UTF8.GetByteCount(body.AsSpan(0, keep)) > maxBodyBytes)
            {
                keep = (int)(keep * 0.9);
            }

            if (keep > 0 && char.IsHighSurrogate(body[keep - 1]))
            {
                keep--;
            }

            body = body[..keep];
        }

        return body;
    }

    /// <summary>
    /// Control characters become a space, the length is bounded: a value shown or put in a header is a single line. Characters that change how text is displayed without being visible are removed:
    /// the bidirectional controls (U+202A to U+202E, U+2066 to U+2069, the marks U+200E, U+200F, U+061C), zero-width characters (U+200B to U+200D, U+2060, U+FEFF) and the line and paragraph
    /// separators U+2028 and U+2029 (every <c>Cf</c>, <c>Zl</c> and <c>Zp</c> character). A right-to-left override in an attachment name turns <c>invoice\u202Egpj.exe</c> into <c>invoiceexe.jpg</c> on screen.
    /// </summary>
    private static string Clean(string value, int max)
    {
        value = StripInvisible(value);
        if (value.Length > max)
        {
            value = value[..max];
            if (value.Length > 0 && char.IsHighSurrogate(value[^1]))
            {
                value = value[..^1];
            }
        }

        bool dirty = false;
        foreach (char c in value)
        {
            if (char.IsControl(c))
            {
                dirty = true;
                break;
            }
        }

        if (!dirty)
        {
            return value.Trim();
        }

        var sb = new StringBuilder(value.Length);
        bool lastSpace = false;
        foreach (char c in value)
        {
            if (char.IsControl(c))
            {
                if (!lastSpace)
                {
                    sb.Append(' ');
                }

                lastSpace = true;
            }
            else
            {
                sb.Append(c);
                lastSpace = false;
            }
        }

        return sb.ToString().Trim();
    }

    /// <summary>
    /// Removes format characters (Unicode category Cf: direction overrides and isolates, zero-width space, word joiner, BOM, the invisible tag characters
    /// U+E0000 to U+E007F) and the line and paragraph separators. Read per code point, so the tag characters, which are surrogate pairs, are caught. The
    /// joiners ZWNJ and ZWJ and the soft hyphen are kept: Persian and Indic text and emoji sequences need them, and they cannot reorder or hide text.
    /// A lone surrogate is kept as it is (storage cleans it).
    /// </summary>
    internal static string StripInvisible(string value)
    {
        StringBuilder? sb = null;
        for (int i = 0; i < value.Length;)
        {
            bool decoded = Rune.DecodeFromUtf16(value.AsSpan(i), out Rune rune, out int length) == System.Buffers.OperationStatus.Done;
            if (decoded && IsInvisibleFormatting(rune))
            {
                sb ??= new StringBuilder(value.Length).Append(value, 0, i);
            }
            else
            {
                sb?.Append(value, i, length);
            }

            i += length;
        }

        return sb?.ToString() ?? value;
    }

    private static bool IsInvisibleFormatting(Rune rune) =>
        rune.Value is not (0x00AD or 0x200C or 0x200D)
        && Rune.GetUnicodeCategory(rune) is System.Globalization.UnicodeCategory.Format or System.Globalization.UnicodeCategory.LineSeparator or System.Globalization.UnicodeCategory.ParagraphSeparator;

    /// <summary>
    /// A file name that is safe as the <c>filename</c> parameter of a <c>Content-Disposition</c> header: ASCII letters, digits and <c>. _ - ( ) space</c>,
    /// at most 100 characters, no path, never empty. The original name is only in the JSON.
    /// </summary>
    public static string SafeDownloadName(string? fileName, string fallback)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return fallback;
        }

        string leaf = fileName[(Math.Max(fileName.LastIndexOf('/'), fileName.LastIndexOf('\\')) + 1)..];
        var sb = new StringBuilder(Math.Min(leaf.Length, 100));
        foreach (char c in leaf)
        {
            if (sb.Length == 100)
            {
                break;
            }

            sb.Append(c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '.' or '_' or '-' or '(' or ')' or ' ' ? c : '_');
        }

        string name = sb.ToString().Trim().TrimStart('.');
        return name.Length == 0 ? fallback : name;
    }
}
