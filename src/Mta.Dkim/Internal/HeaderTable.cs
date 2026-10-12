using System.Buffers;

namespace Mta.Dkim.Internal;

/// <summary>One header field located inside the raw message: all bytes from the first name byte through the end of the last folded line, including the terminating CRLF (when present).</summary>
internal readonly struct HeaderField
{
    public HeaderField(int start, int length, int nameLength, int colonOffset)
    {
        Start = start;
        Length = length;
        NameLength = nameLength;
        ColonOffset = colonOffset;
    }

    /// <summary>Offset of the first byte of the field within the message.</summary>
    public int Start { get; }

    /// <summary>Length of the field in bytes including its terminating CRLF when it has one.</summary>
    public int Length { get; }

    /// <summary>Length of the field name with trailing whitespace before the colon trimmed; 0 when the line is not a valid field.</summary>
    public int NameLength { get; }

    /// <summary>Offset of the colon relative to <see cref="Start"/>, or -1 when the line has no colon.</summary>
    public int ColonOffset { get; }
}

/// <summary>
/// Splits the header section of a raw (CRLF line ended) message into fields without copying and without decoding.
/// DKIM needs the exact bytes of every field, so this works on raw bytes only. Backed by a pooled array; dispose to return it.
/// Do not copy a live instance (it owns the rented array).
/// </summary>
internal struct HeaderTable : IDisposable
{
    private HeaderField[]? _fields;

    /// <summary>Number of fields found.</summary>
    public int Count { get; private set; }

    /// <summary>Offset of the first body byte (after the blank line), or the message length when there is no body.</summary>
    public int BodyOffset { get; private set; }

    /// <summary>True when the field limit was exceeded; <see cref="Count"/> then covers only the fields found before the limit.</summary>
    public bool TooManyFields { get; private set; }

    public readonly HeaderField this[int index] => _fields![index];

    public static HeaderTable Parse(ReadOnlySpan<byte> message, int maxFields)
    {
        var table = new HeaderTable { _fields = ArrayPool<HeaderField>.Shared.Rent(32) };
        table.Scan(message, maxFields);
        return table;
    }

    private void Scan(ReadOnlySpan<byte> message, int maxFields)
    {
        int pos = 0;
        int fieldStart = -1;
        int count = 0;
        var crlf = "\r\n"u8;

        while (true)
        {
            if (pos >= message.Length)
            {
                // Header section ran to the end of the message without a blank line: there is no body.
                if (fieldStart >= 0 && !Add(message, ref count, fieldStart, pos, maxFields)) { return; }
                Count = count;
                BodyOffset = message.Length;
                return;
            }

            int rel = message.Slice(pos).IndexOf(crlf);
            int lineEnd = rel < 0 ? message.Length : pos + rel;
            int next = rel < 0 ? message.Length : lineEnd + 2;

            if (lineEnd == pos)
            {
                // Blank line: end of the header section.
                if (fieldStart >= 0 && !Add(message, ref count, fieldStart, pos, maxFields)) { return; }
                Count = count;
                BodyOffset = next;
                return;
            }

            byte first = message[pos];
            if ((first == (byte)' ' || first == (byte)'\t') && fieldStart >= 0)
            {
                // Continuation line of the current field.
                pos = next;
                continue;
            }

            if (fieldStart >= 0 && !Add(message, ref count, fieldStart, pos, maxFields)) { return; }
            fieldStart = pos;
            pos = next;
        }
    }

    private bool Add(ReadOnlySpan<byte> message, ref int count, int start, int end, int maxFields)
    {
        if (count >= maxFields)
        {
            TooManyFields = true;
            Count = count;
            BodyOffset = message.Length;
            return false;
        }

        if (count == _fields!.Length)
        {
            var bigger = ArrayPool<HeaderField>.Shared.Rent(count * 2);
            Array.Copy(_fields, bigger, count);
            ArrayPool<HeaderField>.Shared.Return(_fields);
            _fields = bigger;
        }

        var raw = message.Slice(start, end - start);
        int colon = raw.IndexOf((byte)':');
        int nameLength = 0;
        if (colon > 0)
        {
            nameLength = colon;
            while (nameLength > 0 && (raw[nameLength - 1] == (byte)' ' || raw[nameLength - 1] == (byte)'\t')) { nameLength--; }
            for (int i = 0; i < nameLength; i++)
            {
                byte b = raw[i];
                if (b <= 0x20 || b >= 0x7F) { nameLength = 0; break; }
            }
        }

        _fields[count++] = new HeaderField(start, end - start, nameLength, colon);
        return true;
    }

    /// <summary>True when the field name equals <paramref name="asciiName"/> ignoring ASCII case.</summary>
    public readonly bool NameEquals(ReadOnlySpan<byte> message, int index, ReadOnlySpan<byte> asciiName)
    {
        var f = _fields![index];
        return f.NameLength == asciiName.Length && AsciiEqualsIgnoreCase(message.Slice(f.Start, f.NameLength), asciiName);
    }

    /// <summary>True when the field name equals <paramref name="asciiName"/> ignoring ASCII case.</summary>
    public readonly bool NameEquals(ReadOnlySpan<byte> message, int index, ReadOnlySpan<char> asciiName)
    {
        var f = _fields![index];
        if (f.NameLength != asciiName.Length) { return false; }
        var name = message.Slice(f.Start, f.NameLength);
        for (int i = 0; i < name.Length; i++)
        {
            if (Lower(name[i]) != Lower((byte)asciiName[i])) { return false; }
        }

        return true;
    }

    /// <summary>The field's bytes including the terminating CRLF when present.</summary>
    public readonly ReadOnlySpan<byte> Raw(ReadOnlySpan<byte> message, int index)
    {
        var f = _fields![index];
        return message.Slice(f.Start, f.Length);
    }

    internal static bool AsciiEqualsIgnoreCase(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length) { return false; }
        for (int i = 0; i < a.Length; i++)
        {
            if (Lower(a[i]) != Lower(b[i])) { return false; }
        }

        return true;
    }

    internal static byte Lower(byte b) => b is >= (byte)'A' and <= (byte)'Z' ? (byte)(b | 0x20) : b;

    public void Dispose()
    {
        var f = _fields;
        _fields = null;
        Count = 0;
        if (f is not null) { ArrayPool<HeaderField>.Shared.Return(f); }
    }
}
