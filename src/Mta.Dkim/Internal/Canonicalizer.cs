namespace Mta.Dkim.Internal;

/// <summary>RFC 6376 section 3.4 canonicalization, written incrementally into a <see cref="HashSink"/>.</summary>
internal static class Canonicalizer
{
    /// <summary>
    /// Canonicalizes one header field (name, colon, value, folded continuation lines; a single trailing CRLF is optional on input).
    /// With <paramref name="appendCrlf"/> the output ends in CRLF; the DKIM-Signature header being signed or verified is hashed without it.
    /// </summary>
    public static void WriteHeader(ReadOnlySpan<byte> field, bool relaxed, bool appendCrlf, ref HashSink sink)
    {
        if (field.Length >= 2 && field[^2] == (byte)'\r' && field[^1] == (byte)'\n')
        {
            field = field.Slice(0, field.Length - 2);
        }

        if (!relaxed)
        {
            sink.Write(field);
            if (appendCrlf) { sink.WriteCrlf(); }
            return;
        }

        int colon = field.IndexOf((byte)':');
        if (colon < 0)
        {
            // Not a well formed field; canonicalize the whole line as a name so the result is deterministic.
            WriteLowerTrimmed(field, ref sink);
            sink.Write((byte)':');
            if (appendCrlf) { sink.WriteCrlf(); }
            return;
        }

        WriteLowerTrimmed(field.Slice(0, colon), ref sink);
        sink.Write((byte)':');

        var value = field.Slice(colon + 1);
        bool pendingSpace = false;
        bool wroteAny = false;
        for (int i = 0; i < value.Length; i++)
        {
            byte c = value[i];
            if (c == (byte)'\r' && i + 1 < value.Length && value[i + 1] == (byte)'\n')
            {
                // Unfold: drop the CRLF; the whitespace after it is handled as ordinary whitespace.
                i++;
                continue;
            }

            if (c == (byte)' ' || c == (byte)'\t')
            {
                pendingSpace = true;
                continue;
            }

            if (pendingSpace && wroteAny) { sink.Write((byte)' '); }
            pendingSpace = false;
            wroteAny = true;
            sink.Write(c);
        }

        if (appendCrlf) { sink.WriteCrlf(); }
    }

    private static void WriteLowerTrimmed(ReadOnlySpan<byte> name, ref HashSink sink)
    {
        int end = name.Length;
        while (end > 0 && (name[end - 1] == (byte)' ' || name[end - 1] == (byte)'\t')) { end--; }
        for (int i = 0; i < end; i++)
        {
            sink.Write(HeaderTable.Lower(name[i]));
        }
    }

    /// <summary>
    /// Canonicalizes the message body. Simple: trailing empty lines removed, an empty body becomes CRLF, a missing final CRLF is added.
    /// Relaxed: additionally trailing whitespace per line is removed and whitespace runs collapse to one SP; an empty body stays empty.
    /// </summary>
    public static void WriteBody(ReadOnlySpan<byte> body, bool relaxed, ref HashSink sink)
    {
        int pendingBlankLines = 0;
        bool wroteAny = false;

        while (!body.IsEmpty)
        {
            int idx = body.IndexOf("\r\n"u8);
            ReadOnlySpan<byte> line;
            bool terminated;
            if (idx >= 0)
            {
                line = body.Slice(0, idx);
                body = body.Slice(idx + 2);
                terminated = true;
            }
            else
            {
                line = body;
                body = default;
                terminated = false;
            }

            bool blank = relaxed ? line.IndexOfAnyExcept((byte)' ', (byte)'\t') < 0 : line.IsEmpty;
            if (blank)
            {
                if (terminated) { pendingBlankLines++; }
                continue;
            }

            for (; pendingBlankLines > 0; pendingBlankLines--) { sink.WriteCrlf(); }
            if (relaxed) { WriteRelaxedLine(line, ref sink); }
            else { sink.Write(line); }

            sink.WriteCrlf();
            wroteAny = true;
        }

        if (!wroteAny && !relaxed)
        {
            sink.WriteCrlf();
        }
    }

    private static void WriteRelaxedLine(ReadOnlySpan<byte> line, ref HashSink sink)
    {
        int firstWsp = line.IndexOfAny((byte)' ', (byte)'\t');
        if (firstWsp < 0)
        {
            sink.Write(line);
            return;
        }

        bool pendingSpace = false;
        while (!line.IsEmpty)
        {
            int nonWsp = line.IndexOfAnyExcept((byte)' ', (byte)'\t');
            if (nonWsp < 0) { return; } // trailing whitespace is dropped
            if (nonWsp > 0)
            {
                pendingSpace = true;
                line = line.Slice(nonWsp);
            }

            int run = line.IndexOfAny((byte)' ', (byte)'\t');
            if (run < 0) { run = line.Length; }
            if (pendingSpace) { sink.Write((byte)' '); pendingSpace = false; }
            sink.Write(line.Slice(0, run));
            line = line.Slice(run);
            // Whatever follows the run (if anything) starts with whitespace, handled in the next iteration.
        }
    }
}
