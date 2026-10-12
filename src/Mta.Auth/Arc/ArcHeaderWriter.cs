namespace Mta.Auth.Arc;

/// <summary>
/// Writes an ARC header into an <see cref="ArcBuffer"/>, folding lines at 78 columns with CRLF + TAB. Folding only happens where folding
/// whitespace is legal: before a tag, inside a tag value that allows it (h=, bh=, b=), and between words of an Authentication-Results body
/// outside quoted strings.
/// </summary>
internal ref struct ArcHeaderWriter
{
    private const int MaxLine = 78;

    private readonly ref ArcBuffer _buffer;
    private int _lineStart;

    public ArcHeaderWriter(ref ArcBuffer buffer)
    {
        _buffer = ref buffer;
        _lineStart = buffer.Length;
    }

    private readonly int Column => _buffer.Length - _lineStart;

    /// <summary>Appends text exactly as given; the caller guarantees it contains no line break (except a lone CRLF at the very end).</summary>
    public void Raw(scoped ReadOnlySpan<byte> text)
    {
        _buffer.Append(text);
        if (text.SequenceEqual("\r\n"u8)) { _lineStart = _buffer.Length; }
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

    /// <summary>Appends an indivisible ASCII piece of a tag value, folding before it when it does not fit.</summary>
    public void Segment(scoped ReadOnlySpan<char> text)
    {
        if (Column + text.Length > MaxLine && Column > 1) { Fold(); }
        _buffer.AppendAscii(text);
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

    /// <summary>
    /// Appends an Authentication-Results body: whitespace runs outside quoted strings collapse to one space, and a fold replaces a space
    /// when the next word would pass column 78. Quoted strings are never split.
    /// </summary>
    public void AuthenticationResultsBody(string body)
    {
        int i = 0;
        bool first = true;
        while (i < body.Length)
        {
            while (i < body.Length && body[i] is ' ' or '\t') { i++; }
            if (i >= body.Length) { break; }
            int start = i;
            bool inQuote = false;
            while (i < body.Length && (inQuote || body[i] is not (' ' or '\t')))
            {
                if (inQuote && body[i] == '\\' && i + 1 < body.Length) { i++; }
                else if (body[i] == '"') { inQuote = !inQuote; }
                i++;
            }

            var word = body.AsSpan(start, i - start);
            if (first) { _buffer.Append((byte)' '); }
            else if (Column + 1 + word.Length > MaxLine) { Fold(); }
            else { _buffer.Append((byte)' '); }
            _buffer.AppendAscii(word);
            first = false;
        }
    }

    private void Fold()
    {
        _buffer.Append("\r\n\t"u8);
        _lineStart = _buffer.Length - 1;
    }
}
