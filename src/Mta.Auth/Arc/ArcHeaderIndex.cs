using System.Buffers;

namespace Mta.Auth.Arc;

/// <summary>One header field located inside the raw message: all bytes from the first name byte through the end of the last folded line, including the CRLF when present.</summary>
internal readonly struct ArcHeaderField
{
    public ArcHeaderField(int start, int length, int nameLength, int colonOffset)
    {
        Start = start;
        Length = length;
        NameLength = nameLength;
        ColonOffset = colonOffset;
    }

    public int Start { get; }

    public int Length { get; }

    /// <summary>Length of the field name with trailing whitespace before the colon trimmed; 0 when the line is not a valid field.</summary>
    public int NameLength { get; }

    /// <summary>Offset of the colon relative to <see cref="Start"/>, or -1.</summary>
    public int ColonOffset { get; }
}

/// <summary>
/// Splits the header section of a raw (CRLF line ended) message into fields without copying and without decoding. ARC, like DKIM,
/// hashes the exact bytes of the fields. Backed by a pooled array: dispose it, and never copy a live instance.
/// </summary>
internal struct ArcHeaderIndex : IDisposable
{
    private ArcHeaderField[]? _fields;

    public int Count { get; private set; }

    /// <summary>Offset of the first body byte, or the message length when there is no body.</summary>
    public int BodyOffset { get; private set; }

    /// <summary>True when the field limit was exceeded.</summary>
    public bool TooManyFields { get; private set; }

    public readonly ArcHeaderField this[int index] => _fields![index];

    public static ArcHeaderIndex Parse(ReadOnlySpan<byte> message, int maxFields)
    {
        var index = new ArcHeaderIndex { _fields = ArrayPool<ArcHeaderField>.Shared.Rent(32) };
        index.Scan(message, maxFields);
        return index;
    }

    private void Scan(ReadOnlySpan<byte> message, int maxFields)
    {
        int pos = 0;
        int fieldStart = -1;
        int count = 0;
        while (true)
        {
            if (pos >= message.Length)
            {
                if (fieldStart >= 0 && !Add(message, ref count, fieldStart, pos, maxFields)) { return; }
                Count = count;
                BodyOffset = message.Length;
                return;
            }

            int rel = message.Slice(pos).IndexOf("\r\n"u8);
            int lineEnd = rel < 0 ? message.Length : pos + rel;
            int next = rel < 0 ? message.Length : lineEnd + 2;

            if (lineEnd == pos)
            {
                if (fieldStart >= 0 && !Add(message, ref count, fieldStart, pos, maxFields)) { return; }
                Count = count;
                BodyOffset = next;
                return;
            }

            byte first = message[pos];
            if ((first == (byte)' ' || first == (byte)'\t') && fieldStart >= 0)
            {
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
            var bigger = ArrayPool<ArcHeaderField>.Shared.Rent(count * 2);
            Array.Copy(_fields, bigger, count);
            ArrayPool<ArcHeaderField>.Shared.Return(_fields);
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
                if (raw[i] <= 0x20 || raw[i] >= 0x7F) { nameLength = 0; break; }
            }
        }

        _fields[count++] = new ArcHeaderField(start, end - start, nameLength, colon);
        return true;
    }

    /// <summary>True when the field name equals <paramref name="asciiName"/> (given in lower case) ignoring ASCII case.</summary>
    public readonly bool NameEquals(ReadOnlySpan<byte> message, int index, ReadOnlySpan<byte> asciiName)
    {
        var f = _fields![index];
        return f.NameLength == asciiName.Length && EqualsIgnoreCase(message.Slice(f.Start, f.NameLength), asciiName);
    }

    /// <summary>True when the field name equals <paramref name="asciiName"/> (given in lower case) ignoring ASCII case.</summary>
    public readonly bool NameEquals(ReadOnlySpan<byte> message, int index, string asciiName)
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

    /// <summary>The field's bytes without the terminating CRLF.</summary>
    public readonly ReadOnlySpan<byte> RawWithoutCrlf(ReadOnlySpan<byte> message, int index)
    {
        var raw = Raw(message, index);
        return raw.Length >= 2 && raw[^2] == (byte)'\r' && raw[^1] == (byte)'\n' ? raw.Slice(0, raw.Length - 2) : raw;
    }

    internal static bool EqualsIgnoreCase(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
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
        if (f is not null) { ArrayPool<ArcHeaderField>.Shared.Return(f); }
    }
}
