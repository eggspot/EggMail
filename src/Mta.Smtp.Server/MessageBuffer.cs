using System.Buffers;

namespace Mta.Smtp.Server;

/// <summary>
/// Accumulates an incoming message in pooled segments (no large contiguous allocation, no LOH pressure for big
/// messages) and exposes it as a <see cref="ReadOnlySequence{T}"/>. Implements <see cref="IBufferWriter{T}"/> so the
/// DATA scanner can write into it directly. Must be disposed to return the arrays. A disposed buffer can be used again after <see cref="Reset"/>
/// (a session keeps one for all its messages, and with it the object of the first segment).
/// </summary>
public sealed class MessageBuffer : IBufferWriter<byte>, IDisposable
{
    public const int SegmentSize = 16 * 1024;
    private const int MaxSegmentSize = 1024 * 1024;

    private Segment? _head;
    private Segment? _tail;
    private Segment? _spare;   // the first segment object of the previous use, kept to be filled again
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
        long runningIndex = _tail is null ? 0 : _tail.RunningIndex + _tail.Written;
        Segment seg;
        if (_tail is null && _spare is not null)
        {
            seg = _spare;
            _spare = null;
            seg.Start(ArrayPool<byte>.Shared.Rent(size), runningIndex);
        }
        else
        {
            seg = new Segment(ArrayPool<byte>.Shared.Rent(size), runningIndex);
        }

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

        if (ReferenceEquals(_head, _tail))
        {
            // The usual message fits one segment: a plain array sequence, no segment objects to walk or to allocate.
            return new ReadOnlySequence<byte>(_head.Array, 0, _head.Written);
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
        Segment? first = _head;
        for (var s = _head; s is not null; s = (Segment?)s.Next)
        {
            ArrayPool<byte>.Shared.Return(s.Array);
        }

        _head = _tail = null;
        _length = 0;
        Capacity = 0;
        if (first is not null)
        {
            // Every segment object but the first one is garbage; the first has no array and no link any more and waits for the next use.
            first.Clear();
            _spare = first;
        }
    }

    /// <summary>Makes a disposed buffer usable again (it holds no memory until something is written).</summary>
    public void Reset()
    {
        if (!_disposed)
        {
            throw new InvalidOperationException("Only a disposed buffer can be reset.");
        }

        _disposed = false;
    }

    private sealed class Segment : ReadOnlySequenceSegment<byte>
    {
        public byte[] Array;
        private int _written;

        public Segment(byte[] array, long runningIndex)
        {
            Array = array;
            RunningIndex = runningIndex;
        }

        public void Start(byte[] array, long runningIndex)
        {
            Array = array;
            RunningIndex = runningIndex;
            _written = 0;
            Next = null;
            Memory = default;
        }

        /// <summary>Drops the array and the link (the array has been returned to its pool).</summary>
        public void Clear()
        {
            Array = null!;
            _written = 0;
            Next = null;
            Memory = default;
            RunningIndex = 0;
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
