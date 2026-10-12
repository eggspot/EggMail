using System.Buffers;
using System.Security.Cryptography;

namespace Mta.Dkim.Internal;

/// <summary>
/// Buffered byte sink used by the canonicalizers. It feeds an <see cref="IncrementalHash"/> (the hot path, no per-message
/// allocation besides the caller's scratch buffer) or, for diagnostics and tests, an <see cref="ArrayBufferWriter{T}"/>.
/// It can cap the number of bytes that reach the target (the DKIM <c>l=</c> tag) while still counting every canonical byte.
/// </summary>
internal ref struct HashSink
{
    private readonly IncrementalHash? _hash;
    private readonly ArrayBufferWriter<byte>? _capture;
    private readonly Span<byte> _buffer;
    private int _position;
    private long _remaining;

    public HashSink(IncrementalHash hash, Span<byte> scratch, long limit = long.MaxValue)
    {
        _hash = hash;
        _capture = null;
        _buffer = scratch;
        _position = 0;
        _remaining = limit;
        TotalCanonicalBytes = 0;
    }

    public HashSink(ArrayBufferWriter<byte> capture, Span<byte> scratch)
    {
        _hash = null;
        _capture = capture;
        _buffer = scratch;
        _position = 0;
        _remaining = long.MaxValue;
        TotalCanonicalBytes = 0;
    }

    /// <summary>Every canonical byte written, including those dropped by the limit.</summary>
    public long TotalCanonicalBytes { get; private set; }

    public void Write(byte value)
    {
        TotalCanonicalBytes++;
        if (_remaining <= 0) { return; }
        _remaining--;
        if (_position == _buffer.Length) { Flush(); }
        _buffer[_position++] = value;
    }

    public void Write(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) { return; }
        TotalCanonicalBytes += data.Length;
        if (_remaining <= 0) { return; }
        if (data.Length > _remaining) { data = data.Slice(0, (int)_remaining); }
        _remaining -= data.Length;

        if (data.Length <= _buffer.Length - _position)
        {
            data.CopyTo(_buffer.Slice(_position));
            _position += data.Length;
            return;
        }

        Flush();
        if (data.Length >= _buffer.Length)
        {
            Emit(data);
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
            Emit(_buffer.Slice(0, _position));
            _position = 0;
        }
    }

    private readonly void Emit(ReadOnlySpan<byte> data)
    {
        if (_hash is not null) { _hash.AppendData(data); }
        else { _capture!.Write(data); }
    }
}

/// <summary>Per-thread cache of one SHA-256 <see cref="IncrementalHash"/> so the signing and verification hot path does not allocate a new native hash per message.</summary>
internal static class Sha256Pool
{
    [ThreadStatic]
    private static IncrementalHash? t_cached;

    public static IncrementalHash Rent() => Interlocked.Exchange(ref t_cached, null) ?? IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

    /// <summary>Returns the hash for reuse. The hash must already be reset (GetHashAndReset / GetCurrentHash after Reset).</summary>
    public static void Return(IncrementalHash hash) => t_cached = hash;

    /// <summary>Finishes the hash into <paramref name="destination"/> (32 bytes) and returns it to the pool.</summary>
    public static void FinishAndReturn(IncrementalHash hash, Span<byte> destination)
    {
        hash.GetHashAndReset(destination);
        Return(hash);
    }
}
