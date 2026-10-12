using System.Buffers;
using System.Security.Cryptography;

namespace Mta.Auth.Arc;

/// <summary>Buffered byte sink feeding an <see cref="IncrementalHash"/>; the canonicalizers write into it.</summary>
internal ref struct ArcHashSink
{
    private readonly IncrementalHash _hash;
    private readonly Span<byte> _buffer;
    private int _position;

    public ArcHashSink(IncrementalHash hash, Span<byte> scratch)
    {
        _hash = hash;
        _buffer = scratch;
        _position = 0;
    }

    public void Write(byte value)
    {
        if (_position == _buffer.Length) { Flush(); }
        _buffer[_position++] = value;
    }

    public void Write(ReadOnlySpan<byte> data)
    {
        if (data.Length <= _buffer.Length - _position)
        {
            data.CopyTo(_buffer.Slice(_position));
            _position += data.Length;
            return;
        }

        Flush();
        if (data.Length >= _buffer.Length)
        {
            _hash.AppendData(data);
        }
        else
        {
            data.CopyTo(_buffer);
            _position = data.Length;
        }
    }

    public void WriteCrlf() => Write("\r\n"u8);

    public void Flush()
    {
        if (_position > 0)
        {
            _hash.AppendData(_buffer.Slice(0, _position));
            _position = 0;
        }
    }
}

/// <summary>Per-thread cache of one SHA-256 <see cref="IncrementalHash"/> so hashing does not allocate a native hash per message.</summary>
internal static class ArcSha256
{
    [ThreadStatic]
    private static IncrementalHash? t_cached;

    public static IncrementalHash Rent() => Interlocked.Exchange(ref t_cached, null) ?? IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

    /// <summary>Finishes the hash into <paramref name="destination"/> (32 bytes) and keeps the instance for reuse.</summary>
    public static void FinishAndReturn(IncrementalHash hash, Span<byte> destination)
    {
        hash.GetHashAndReset(destination);
        t_cached = hash;
    }

    /// <summary>Gives the instance back without producing a hash (after an error); the state is reset.</summary>
    public static void Abandon(IncrementalHash hash)
    {
        hash.GetHashAndReset(stackalloc byte[32]);
        t_cached = hash;
    }
}

/// <summary>RFC 6376 section 3.4 canonicalization (header and body, simple and relaxed), shared by the AMS and the ARC-Seal.</summary>
internal static class ArcCanonicalizer
{
    /// <summary>
    /// Canonicalizes one header field (name, colon, value, folded continuation lines; a single trailing CRLF is optional on input).
    /// The output ends in CRLF only with <paramref name="appendCrlf"/>.
    /// </summary>
    public static void WriteHeader(ReadOnlySpan<byte> field, bool relaxed, bool appendCrlf, ref ArcHashSink sink)
    {
        if (field.Length >= 2 && field[^2] == (byte)'\r' && field[^1] == (byte)'\n') { field = field.Slice(0, field.Length - 2); }

        if (!relaxed)
        {
            sink.Write(field);
            if (appendCrlf) { sink.WriteCrlf(); }
            return;
        }

        int colon = field.IndexOf((byte)':');
        if (colon < 0)
        {
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
                i++; // unfold: the CRLF disappears, the whitespace after it is ordinary whitespace
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

    private static void WriteLowerTrimmed(ReadOnlySpan<byte> name, ref ArcHashSink sink)
    {
        int end = name.Length;
        while (end > 0 && (name[end - 1] == (byte)' ' || name[end - 1] == (byte)'\t')) { end--; }
        for (int i = 0; i < end; i++) { sink.Write(ArcHeaderIndex.Lower(name[i])); }
    }

    /// <summary>
    /// Canonicalizes the message body. Simple: trailing empty lines removed, an empty body becomes CRLF, a missing final CRLF is added.
    /// Relaxed: additionally trailing whitespace per line is removed and whitespace runs collapse to one SP; an empty body stays empty.
    /// </summary>
    public static void WriteBody(ReadOnlySpan<byte> body, bool relaxed, ref ArcHashSink sink)
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

        if (!wroteAny && !relaxed) { sink.WriteCrlf(); }
    }

    private static void WriteRelaxedLine(ReadOnlySpan<byte> line, ref ArcHashSink sink)
    {
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
        }
    }

    /// <summary>Computes the body hash (SHA-256) of the message body.</summary>
    public static void HashBody(ReadOnlySpan<byte> body, bool relaxed, Span<byte> hash)
    {
        var h = ArcSha256.Rent();
        try
        {
            Span<byte> scratch = stackalloc byte[1024];
            var sink = new ArcHashSink(h, scratch);
            WriteBody(body, relaxed, ref sink);
            sink.Flush();
        }
        catch
        {
            ArcSha256.Abandon(h);
            throw;
        }

        ArcSha256.FinishAndReturn(h, hash);
    }
}

/// <summary>A growable byte buffer backed by <see cref="ArrayPool{T}"/>. A mutable struct: keep it in one local and always dispose it; never copy.</summary>
internal struct ArcBuffer : IDisposable
{
    private byte[] _array;
    private int _length;

    public ArcBuffer(int initialCapacity)
    {
        _array = ArrayPool<byte>.Shared.Rent(initialCapacity);
        _length = 0;
    }

    public readonly int Length => _length;

    public readonly ReadOnlySpan<byte> WrittenSpan => _array.AsSpan(0, _length);

    public void Append(ReadOnlySpan<byte> data)
    {
        Ensure(data.Length);
        data.CopyTo(_array.AsSpan(_length));
        _length += data.Length;
    }

    public void Append(byte value)
    {
        Ensure(1);
        _array[_length++] = value;
    }

    public void AppendAscii(ReadOnlySpan<char> text)
    {
        Ensure(text.Length);
        for (int i = 0; i < text.Length; i++) { _array[_length + i] = (byte)text[i]; }
        _length += text.Length;
    }

    private void Ensure(int extra)
    {
        if (_array.Length - _length >= extra) { return; }
        var bigger = ArrayPool<byte>.Shared.Rent(Math.Max(_array.Length * 2, _length + extra));
        Buffer.BlockCopy(_array, 0, bigger, 0, _length);
        ArrayPool<byte>.Shared.Return(_array);
        _array = bigger;
    }

    public void Dispose()
    {
        var a = _array;
        _array = [];
        _length = 0;
        if (a.Length > 0) { ArrayPool<byte>.Shared.Return(a); }
    }
}
