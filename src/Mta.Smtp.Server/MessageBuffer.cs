using System.Buffers;

namespace Mta.Smtp.Server;

/// <summary>
/// Accumulates an incoming message in pooled segments (no large contiguous allocation, no LOH pressure for big
/// messages) and exposes it as a <see cref="ReadOnlySequence{T}"/>. Implements <see cref="IBufferWriter{T}"/> so the
/// DATA scanner can write into it directly. Must be disposed to return the arrays.
/// </summary>
public sealed class MessageBuffer : IBufferWriter<byte>, IDisposable
{
    public const int SegmentSize = 16 * 1024;
    private const int MaxSegmentSize = 1024 * 1024;

    private Segment? _head;
    private Segment? _tail;
    private long _length;
    private bool _disposed;

    public long Length => _length;

    /// <summary>Bytes of pooled memory currently held (>= <see cref="Length"/>).</summary>
    public long Capacity { get; private set; }

    public void Advance(int count)
    {
        if (_tail is null || count < 0 || _tail.Written + count > _tail.Array.Length)
        {
            throw new InvalidOperationException("Advance past the end of the buffer.");
        }

        _tail.Written += count;
        _length += count;
    }

    public Memory<byte> GetMemory(int sizeHint = 0) => EnsureSpace(sizeHint).Array.AsMemory(_tail!.Written);

    public Span<byte> GetSpan(int sizeHint = 0) => EnsureSpace(sizeHint).Array.AsSpan(_tail!.Written);

    private Segment EnsureSpace(int sizeHint)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (sizeHint < 1)
        {
            sizeHint = 1;
        }

        if (_tail is not null && _tail.Array.Length - _tail.Written >= sizeHint)
        {
            return _tail;
        }

        // Grow geometrically (16 KiB, then double up to 1 MiB) so large messages use few segments.
        int size = _tail is null ? SegmentSize : Math.Min(MaxSegmentSize, Math.Max(SegmentSize, _tail.Array.Length * 2));
        size = Math.Max(size, sizeHint);
        var seg = new Segment(ArrayPool<byte>.Shared.Rent(size), _tail is null ? 0 : _tail.RunningIndex + _tail.Written);
        Capacity += seg.Array.Length;
        if (_tail is null)
        {
            _head = seg;
        }
        else
        {
            _tail.SetNext(seg);
        }

        _tail = seg;
        return seg;
    }

    public ReadOnlySequence<byte> AsSequence()
    {
        if (_head is null || _tail is null || _length == 0)
        {
            return ReadOnlySequence<byte>.Empty;
        }

        return new ReadOnlySequence<byte>(_head, 0, _tail, _tail.Written);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        for (var s = _head; s is not null; s = (Segment?)s.Next)
        {
            ArrayPool<byte>.Shared.Return(s.Array);
        }

        _head = _tail = null;
        _length = 0;
        Capacity = 0;
    }

    private sealed class Segment : ReadOnlySequenceSegment<byte>
    {
        public readonly byte[] Array;
        private int _written;

        public Segment(byte[] array, long runningIndex)
        {
            Array = array;
            RunningIndex = runningIndex;
        }

        public int Written
        {
            get => _written;
            set
            {
                _written = value;
                Memory = Array.AsMemory(0, value);
            }
        }

        public void SetNext(Segment next) => Next = next;
    }
}
