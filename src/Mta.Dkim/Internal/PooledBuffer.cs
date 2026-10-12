using System.Buffers;

namespace Mta.Dkim.Internal;

/// <summary>A growable byte buffer backed by <see cref="ArrayPool{T}"/>. A mutable struct: keep it in one local and always dispose it; never copy.</summary>
internal struct PooledBuffer : IDisposable
{
    private byte[] _array;
    private int _length;

    public PooledBuffer(int initialCapacity)
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
