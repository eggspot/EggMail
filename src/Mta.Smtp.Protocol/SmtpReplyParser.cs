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

    public static ReplyParseStatus TryParse(in ReadOnlySequence<byte> buffer, out SmtpReply? reply, out SequencePosition consumed)
    {
        reply = null;
        consumed = buffer.Start;
        var reader = new SequenceReader<byte>(buffer);
        var lines = new List<string>(2);
        int code = -1;
        string? enhanced = null;

        while (true)
        {
            if (!reader.TryReadTo(out ReadOnlySequence<byte> lineSeq, (byte)'\n', advancePastDelimiter: true))
            {
                return buffer.Length > MaxLineLength * 2L ? ReplyParseStatus.Invalid : ReplyParseStatus.NeedMoreData;
            }

            if (lineSeq.Length > MaxLineLength || lines.Count >= MaxLines)
            {
                return ReplyParseStatus.Invalid;
            }

            byte[] rented = ArrayPool<byte>.Shared.Rent((int)lineSeq.Length);
            try
            {
                lineSeq.CopyTo(rented);
                var line = rented.AsSpan(0, (int)lineSeq.Length);
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

                string t = Encoding.UTF8.GetString(text);
                if (TryStripEnhanced(ref t, code, out string? enh))
                {
                    enhanced ??= enh;
                }

                lines.Add(t);
                if (last)
                {
                    reply = new SmtpReply(code, enhanced, lines);
                    consumed = reader.Position;
                    return ReplyParseStatus.Ok;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
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
