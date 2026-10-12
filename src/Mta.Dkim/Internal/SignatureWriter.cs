namespace Mta.Dkim.Internal;

/// <summary>
/// Writes a DKIM-Signature header into a <see cref="PooledBuffer"/>, folding lines at 78 columns with CRLF + TAB. Folding only ever
/// happens where folding whitespace is legal: before a tag, or inside a tag value that allows it (h=, bh=, b=).
/// </summary>
internal ref struct SignatureWriter
{
    private const int MaxLine = 78;

    private readonly ref PooledBuffer _buffer;
    private int _lineStart;

    public SignatureWriter(ref PooledBuffer buffer)
    {
        _buffer = ref buffer;
        _lineStart = buffer.Length;
    }

    private readonly int Column => _buffer.Length - _lineStart;

    /// <summary>Appends text exactly as given; the caller guarantees it contains no line break.</summary>
    public void Raw(scoped ReadOnlySpan<byte> text)
    {
        if (text.SequenceEqual("\r\n"u8))
        {
            _buffer.Append(text);
            _lineStart = _buffer.Length;
            return;
        }

        _buffer.Append(text);
    }

    /// <summary>Appends a complete tag (for example <c>d=example.com;</c>) separated from the previous one by a space, or by a fold when it does not fit.</summary>
    public void Token(scoped ReadOnlySpan<char> text)
    {
        if (Column + 1 + text.Length > MaxLine) { Fold(); }
        else { _buffer.Append((byte)' '); }
        _buffer.AppendAscii(text);
    }

    /// <summary>Like <see cref="Token"/> but folds first unless at least <paramref name="roomAfter"/> more columns remain, so a value that follows starts on the same line.</summary>
    public void TokenKeepingRoom(scoped ReadOnlySpan<char> text, int roomAfter)
    {
        if (Column + 1 + text.Length + roomAfter > MaxLine) { Fold(); }
        else { _buffer.Append((byte)' '); }
        _buffer.AppendAscii(text);
    }

    /// <summary>Appends an indivisible piece of a tag value, folding before it when it does not fit.</summary>
    public void Segment(scoped ReadOnlySpan<byte> text)
    {
        if (Column + text.Length > MaxLine && Column > 1) { Fold(); }
        _buffer.Append(text);
    }

    /// <summary>Appends a base64 value, splitting it across lines as needed.</summary>
    public void Value(scoped ReadOnlySpan<byte> base64)
    {
        while (!base64.IsEmpty)
        {
            int room = MaxLine - Column;
            if (room < 4 && base64.Length > room)
            {
                Fold();
                room = MaxLine - Column;
            }

            int take = Math.Min(room, base64.Length);
            _buffer.Append(base64.Slice(0, take));
            base64 = base64.Slice(take);
            if (!base64.IsEmpty) { Fold(); }
        }
    }

    private void Fold()
    {
        _buffer.Append("\r\n\t"u8);
        _lineStart = _buffer.Length - 1;
    }
}
