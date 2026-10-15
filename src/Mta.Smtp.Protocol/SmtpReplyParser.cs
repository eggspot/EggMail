using System.Buffers;
using System.Text;

namespace Mta.Smtp.Protocol;

public enum ReplyParseStatus : byte
{
    NeedMoreData,
    Ok,

    /// <summary>Malformed reply (bad code, inconsistent codes, bare CR, too long, too many lines).</summary>
    Invalid,
}

/// <summary>Client-side parser for (possibly multi-line) SMTP replies. Lenient about LF-only line ends, strict about everything else.</summary>
public static class SmtpReplyParser
{
    public const int MaxLineLength = 4096;
    public const int MaxLines = 200;

    // The enhanced status codes that nearly every reply carries, shared instead of allocated for each reply.
    private static readonly string[] CommonEnhanced =
    [
        "2.0.0", "2.1.0", "2.1.5", "2.6.0", "2.7.0", "2.8.0", "4.0.0", "4.2.0", "4.2.2", "4.3.0", "4.4.1", "4.4.2", "4.7.0", "5.0.0", "5.1.1", "5.1.2", "5.2.1", "5.2.2",
        "5.3.4", "5.4.1", "5.5.0", "5.5.1", "5.7.0", "5.7.1",
    ];

    public static ReplyParseStatus TryParse(in ReadOnlySequence<byte> buffer, out SmtpReply? reply, out SequencePosition consumed)
    {
        reply = null;
        consumed = buffer.Start;
        var reader = new SequenceReader<byte>(buffer);
        string? firstLine = null;
        List<string>? moreLines = null;   // only multi-line replies need a list
        int lineCount = 0;
        int code = -1;
        string? enhanced = null;

        while (true)
        {
            if (!reader.TryReadTo(out ReadOnlySequence<byte> lineSeq, (byte)'\n', advancePastDelimiter: true))
            {
                return buffer.Length > MaxLineLength * 2L ? ReplyParseStatus.Invalid : ReplyParseStatus.NeedMoreData;
            }

            if (lineSeq.Length > MaxLineLength || lineCount >= MaxLines)
            {
                return ReplyParseStatus.Invalid;
            }

            // The usual line sits in one segment and is read in place; only a line split across segments is copied.
            byte[]? rented = null;
            ReadOnlySpan<byte> line;
            if (lineSeq.IsSingleSegment)
            {
                line = lineSeq.FirstSpan;
            }
            else
            {
                rented = ArrayPool<byte>.Shared.Rent((int)lineSeq.Length);
                lineSeq.CopyTo(rented);
                line = rented.AsSpan(0, (int)lineSeq.Length);
            }

            try
            {
                if (line.Length > 0 && line[^1] == '\r')
                {
                    line = line[..^1];
                }

                if (line.IndexOf((byte)'\r') >= 0 || line.IndexOf((byte)0) >= 0 || line.Length < 3)
                {
                    return ReplyParseStatus.Invalid;
                }

                if (!(char.IsAsciiDigit((char)line[0]) && char.IsAsciiDigit((char)line[1]) && char.IsAsciiDigit((char)line[2])))
                {
                    return ReplyParseStatus.Invalid;
                }

                int thisCode = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
                if (thisCode < 200 || thisCode > 599)
                {
                    return ReplyParseStatus.Invalid;
                }

                if (code >= 0 && thisCode != code)
                {
                    return ReplyParseStatus.Invalid;
                }

                code = thisCode;
                bool last;
                ReadOnlySpan<byte> text;
                if (line.Length == 3)
                {
                    last = true;
                    text = default;
                }
                else if (line[3] == ' ')
                {
                    last = true;
                    text = line[4..];
                }
                else if (line[3] == '-')
                {
                    last = false;
                    text = line[4..];
                }
                else
                {
                    return ReplyParseStatus.Invalid;
                }

                if (TryStripEnhanced(text, code, out ReadOnlySpan<byte> enhancedBytes, out ReadOnlySpan<byte> rest))
                {
                    enhanced ??= EnhancedText(enhancedBytes);
                    text = rest;
                }

                string t = text.IsEmpty ? string.Empty : Encoding.UTF8.GetString(text);
                if (lineCount == 0)
                {
                    firstLine = t;
                }
                else
                {
                    (moreLines ??= [firstLine!]).Add(t);
                }

                lineCount++;
                if (last)
                {
                    reply = moreLines is null ? SmtpReply.FromWire(code, enhanced, firstLine!) : new SmtpReply(code, enhanced, moreLines);
                    consumed = reader.Position;
                    return ReplyParseStatus.Ok;
                }
            }
            finally
            {
                if (rented is not null)
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }
        }
    }

    private static string EnhancedText(ReadOnlySpan<byte> bytes)
    {
        foreach (string known in CommonEnhanced)
        {
            if (known.Length == bytes.Length && Ascii.Equals(bytes, known))
            {
                return known;
            }
        }

        return Encoding.ASCII.GetString(bytes);
    }

    /// <summary>If <paramref name="text"/> starts with an enhanced status code (class matching the reply class), splits it off.</summary>
    private static bool TryStripEnhanced(ReadOnlySpan<byte> text, int code, out ReadOnlySpan<byte> enhanced, out ReadOnlySpan<byte> rest)
    {
        enhanced = default;
        rest = text;
        if (text.Length < 5) { return false; }
        byte cls = text[0];
        if (cls != (byte)('0' + code / 100) || (cls != '2' && cls != '4' && cls != '5') || text[1] != '.') { return false; }
        int i = 2;
        int d1 = 0;
        while (i < text.Length && char.IsAsciiDigit((char)text[i]) && d1 < 4) { i++; d1++; }
        if (d1 == 0 || i >= text.Length || text[i] != '.') { return false; }
        i++;
        int d2 = 0;
        while (i < text.Length && char.IsAsciiDigit((char)text[i]) && d2 < 4) { i++; d2++; }
        if (d2 == 0 || (i < text.Length && text[i] != ' ')) { return false; }
        enhanced = text[..i];
        rest = i < text.Length ? text[(i + 1)..] : default;
        return true;
    }

    /// <summary>If <paramref name="text"/> starts with an enhanced status code (class matching the reply class), strips it.</summary>
    internal static bool TryStripEnhanced(ref string text, int code, out string? enhanced)
    {
        enhanced = null;
        if (text.Length < 5) { return false; }
        char cls = text[0];
        if (cls != (char)('0' + code / 100) || (cls != '2' && cls != '4' && cls != '5') || text[1] != '.') { return false; }
        int i = 2;
        int d1 = 0;
        while (i < text.Length && char.IsAsciiDigit(text[i]) && d1 < 4) { i++; d1++; }
        if (d1 == 0 || i >= text.Length || text[i] != '.') { return false; }
        i++;
        int d2 = 0;
        while (i < text.Length && char.IsAsciiDigit(text[i]) && d2 < 4) { i++; d2++; }
        if (d2 == 0 || (i < text.Length && text[i] != ' ')) { return false; }
        enhanced = text[..i];
        text = i < text.Length ? text[(i + 1)..] : "";
        return true;
    }
}
