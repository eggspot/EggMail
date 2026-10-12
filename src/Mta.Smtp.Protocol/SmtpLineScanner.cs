using System.Buffers;

namespace Mta.Smtp.Protocol;

public enum LineStatus : byte
{
    /// <summary>No complete line yet.</summary>
    Incomplete,
    Ok,
    TooLong,

    /// <summary>A LF without a preceding CR (SMTP smuggling vector): the connection must be closed.</summary>
    BareLf,

    /// <summary>A CR not followed by LF inside a line.</summary>
    BareCr,
}

/// <summary>
/// Reads command lines. Only CRLF terminates a line (decision 4, smuggling defense): a bare LF or a bare CR is an error,
/// never silently accepted.
/// </summary>
public static class SmtpLineScanner
{
    /// <summary>
    /// Tries to extract the first line. <paramref name="line"/> excludes the CRLF; <paramref name="consumed"/> includes it.
    /// <paramref name="scratch"/> (at least <paramref name="maxLineLength"/> bytes) is used only when the line spans segments.
    /// </summary>
    public static LineStatus TryGetLine(in ReadOnlySequence<byte> buffer, int maxLineLength, Span<byte> scratch, out ReadOnlySpan<byte> line, out int consumed)
    {
        line = default;
        consumed = 0;
        if (buffer.IsEmpty)
        {
            return LineStatus.Incomplete;
        }

        ReadOnlySpan<byte> first = buffer.FirstSpan;
        var status = Scan(first, maxLineLength, out int lineLen);
        if (status == LineStatus.Ok)
        {
            line = first[..lineLen];
            consumed = lineLen + 2;
            return LineStatus.Ok;
        }

        if (status != LineStatus.Incomplete || buffer.IsSingleSegment)
        {
            return status;
        }

        // The line crosses segment boundaries: copy at most maxLineLength + 1 bytes and rescan contiguous.
        int take = (int)Math.Min(buffer.Length, maxLineLength + 1L);
        if (scratch.Length < take)
        {
            take = scratch.Length;
        }

        buffer.Slice(0, take).CopyTo(scratch);
        var combined = scratch[..take];
        status = Scan(combined, maxLineLength, out lineLen);
        if (status == LineStatus.Ok)
        {
            line = combined[..lineLen];
            consumed = lineLen + 2;
        }

        return status;
    }

    private static LineStatus Scan(ReadOnlySpan<byte> span, int maxLineLength, out int lineLength)
    {
        lineLength = 0;
        int lf = span.IndexOf((byte)'\n');
        if (lf < 0)
        {
            // Everything so far must be free of bare CR except a trailing CR that may be the first half of CRLF.
            int cr = span.IndexOf((byte)'\r');
            if (cr >= 0 && cr != span.Length - 1)
            {
                return LineStatus.BareCr;
            }

            return span.Length + 1 > maxLineLength ? LineStatus.TooLong : LineStatus.Incomplete;
        }

        if (lf == 0 || span[lf - 1] != '\r')
        {
            return LineStatus.BareLf;
        }

        if (lf + 1 > maxLineLength)
        {
            return LineStatus.TooLong;
        }

        if (span[..(lf - 1)].IndexOf((byte)'\r') >= 0)
        {
            return LineStatus.BareCr;
        }

        lineLength = lf - 1;
        return LineStatus.Ok;
    }
}
