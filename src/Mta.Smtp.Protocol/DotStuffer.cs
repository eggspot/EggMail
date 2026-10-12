using System.Buffers;

namespace Mta.Smtp.Protocol;

/// <summary>
/// Outbound DATA encoder (RFC 5321 §4.5.2): doubles a leading dot on each line and appends the terminator.
/// The message must already use CRLF line endings: this encoder never invents line endings and refuses bare CR/LF
/// (the client-side smuggling defense: never emit a bare CR/LF).
/// </summary>
public struct DotStuffer
{
    private bool _atLineStart;
    private bool _afterCr;
    private bool _wroteAnything;
    private bool _endsWithCrlf;

    public DotStuffer()
    {
        _atLineStart = true;
        _afterCr = false;
        _wroteAnything = false;
        _endsWithCrlf = true;
    }

    /// <summary>
    /// Encodes one chunk. Returns false (and writes nothing further) if the chunk contains a bare CR, a bare LF, or NUL.
    /// </summary>
    public bool Write(ReadOnlySpan<byte> chunk, IBufferWriter<byte> output)
    {
        int runStart = 0;
        for (int i = 0; i < chunk.Length; i++)
        {
            byte b = chunk[i];
            if (_afterCr)
            {
                if (b != '\n') { return false; }
                _afterCr = false;
                _atLineStart = true;
                _endsWithCrlf = true;
                continue;
            }

            if (b == '\r')
            {
                _afterCr = true;
                _endsWithCrlf = false;
                continue;
            }

            if (b == '\n' || b == 0)
            {
                return false;
            }

            if (_atLineStart && b == '.')
            {
                // Emit pending run plus an extra dot.
                output.Write(chunk[runStart..i]);
                output.Write("."u8);
                runStart = i;
            }

            _atLineStart = false;
            _endsWithCrlf = false;
        }

        if (chunk.Length > runStart)
        {
            output.Write(chunk[runStart..]);
        }

        _wroteAnything |= chunk.Length > 0;
        return true;
    }

    /// <summary>Writes the end-of-data marker. Adds a CRLF first if the message did not end with one.</summary>
    public bool Complete(IBufferWriter<byte> output)
    {
        if (_afterCr) { return false; }
        if (!_endsWithCrlf || !_wroteAnything)
        {
            output.Write("\r\n"u8);
        }

        output.Write(".\r\n"u8);
        return true;
    }
}
