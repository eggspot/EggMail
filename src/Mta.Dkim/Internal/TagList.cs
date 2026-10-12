using System.Buffers;
using System.Buffers.Text;
using System.Text;

namespace Mta.Dkim.Internal;

/// <summary>One <c>name=value</c> entry of a DKIM tag list. All offsets are relative to the span that was parsed.</summary>
internal readonly struct TagEntry
{
    public TagEntry(int nameStart, int nameLength, int valueStart, int valueLength, int rawValueStart, int rawValueEnd)
    {
        NameStart = nameStart;
        NameLength = nameLength;
        ValueStart = valueStart;
        ValueLength = valueLength;
        RawValueStart = rawValueStart;
        RawValueEnd = rawValueEnd;
    }

    public int NameStart { get; }

    public int NameLength { get; }

    /// <summary>Start of the value with surrounding whitespace (including folding) trimmed.</summary>
    public int ValueStart { get; }

    public int ValueLength { get; }

    /// <summary>First byte after the <c>=</c>; with <see cref="RawValueEnd"/> this is the value including all surrounding whitespace.</summary>
    public int RawValueStart { get; }

    /// <summary>Offset of the terminating <c>;</c>, or the end of the input.</summary>
    public int RawValueEnd { get; }
}

/// <summary>
/// RFC 6376 section 3.2 tag-list parser shared by DKIM-Signature headers and DNS key records. It is deliberately
/// allocation free, never throws, caps the number of tags, rejects duplicate tags and control/non-ASCII bytes.
/// </summary>
internal static class TagListParser
{
    /// <summary>Parses <paramref name="input"/> starting at <paramref name="start"/>. On failure <paramref name="error"/> is a constant description.</summary>
    public static bool TryParse(ReadOnlySpan<byte> input, int start, Span<TagEntry> entries, out int count, out string? error)
    {
        count = 0;
        error = null;
        int pos = start;

        while (true)
        {
            pos = SkipWhitespace(input, pos);
            if (pos >= input.Length) { return true; }

            if (input[pos] == (byte)';')
            {
                // Tolerate empty tag specs such as ";;" or a trailing ";".
                pos++;
                continue;
            }

            int nameStart = pos;
            if (!IsAlpha(input[pos]))
            {
                error = "invalid tag name";
                return false;
            }

            pos++;
            while (pos < input.Length && (IsAlpha(input[pos]) || IsDigit(input[pos]) || input[pos] == (byte)'_')) { pos++; }
            int nameEnd = pos;

            pos = SkipWhitespace(input, pos);
            if (pos >= input.Length || input[pos] != (byte)'=')
            {
                error = "tag is missing '='";
                return false;
            }

            pos++;
            int rawStart = pos;
            int semicolon = input.Slice(pos).IndexOf((byte)';');
            int rawEnd = semicolon < 0 ? input.Length : pos + semicolon;

            for (int i = rawStart; i < rawEnd; i++)
            {
                byte b = input[i];
                if ((b >= 0x21 && b <= 0x7E) || b == (byte)' ' || b == (byte)'\t' || b == (byte)'\r' || b == (byte)'\n') { continue; }
                error = "invalid character in tag value";
                return false;
            }

            int vs = rawStart;
            int ve = rawEnd;
            while (vs < ve && IsWhitespace(input[vs])) { vs++; }
            while (ve > vs && IsWhitespace(input[ve - 1])) { ve--; }

            var name = input.Slice(nameStart, nameEnd - nameStart);
            for (int i = 0; i < count; i++)
            {
                if (input.Slice(entries[i].NameStart, entries[i].NameLength).SequenceEqual(name))
                {
                    error = "duplicate tag";
                    return false;
                }
            }

            if (count == entries.Length)
            {
                error = "too many tags";
                return false;
            }

            entries[count++] = new TagEntry(nameStart, nameEnd - nameStart, vs, ve - vs, rawStart, rawEnd);
            pos = semicolon < 0 ? input.Length : rawEnd + 1;
        }
    }

    /// <summary>Finds a tag by its (case sensitive) name.</summary>
    public static bool TryFind(ReadOnlySpan<byte> input, ReadOnlySpan<TagEntry> entries, ReadOnlySpan<byte> name, out TagEntry entry)
    {
        for (int i = 0; i < entries.Length; i++)
        {
            if (input.Slice(entries[i].NameStart, entries[i].NameLength).SequenceEqual(name))
            {
                entry = entries[i];
                return true;
            }
        }

        entry = default;
        return false;
    }

    public static ReadOnlySpan<byte> Value(ReadOnlySpan<byte> input, in TagEntry entry) => input.Slice(entry.ValueStart, entry.ValueLength);

    internal static bool IsWhitespace(byte b) => b == (byte)' ' || b == (byte)'\t' || b == (byte)'\r' || b == (byte)'\n';

    private static int SkipWhitespace(ReadOnlySpan<byte> input, int pos)
    {
        while (pos < input.Length && IsWhitespace(input[pos])) { pos++; }
        return pos;
    }

    private static bool IsAlpha(byte b) => (uint)((b | 0x20) - 'a') <= 'z' - 'a';

    private static bool IsDigit(byte b) => (uint)(b - '0') <= 9;

    /// <summary>Parses a non-negative decimal of at most <paramref name="maxDigits"/> digits (no sign, no whitespace).</summary>
    public static bool TryParseDecimal(ReadOnlySpan<byte> value, int maxDigits, out long result)
    {
        result = 0;
        if (value.IsEmpty || value.Length > maxDigits) { return false; }
        long acc = 0;
        foreach (byte b in value)
        {
            if (!IsDigit(b)) { return false; }
            acc = (acc * 10) + (b - '0');
        }

        result = acc;
        return true;
    }

    /// <summary>
    /// Decodes a base64 value that may contain folding whitespace. Fails (never throws) on invalid characters, bad padding or
    /// when more than <paramref name="maxDecodedBytes"/> bytes would result.
    /// </summary>
    public static bool TryDecodeBase64(ReadOnlySpan<byte> value, int maxDecodedBytes, out byte[] decoded)
    {
        decoded = [];
        int maxEncoded = ((maxDecodedBytes + 2) / 3 * 4) + 4;
        byte[]? rented = null;
        Span<byte> compact = value.Length <= 1024 ? stackalloc byte[value.Length] : (rented = ArrayPool<byte>.Shared.Rent(value.Length)).AsSpan(0, value.Length);
        try
        {
            int n = 0;
            foreach (byte b in value)
            {
                if (IsWhitespace(b)) { continue; }
                if (n >= maxEncoded) { return false; }
                compact[n++] = b;
            }

            if (n == 0) { return true; }
            if ((n & 3) != 0) { return false; }

            var buffer = new byte[(n / 4 * 3)];
            if (Base64.DecodeFromUtf8(compact.Slice(0, n), buffer, out _, out int written, isFinalBlock: true) != OperationStatus.Done) { return false; }
            if (written > maxDecodedBytes) { return false; }
            decoded = written == buffer.Length ? buffer : buffer.AsSpan(0, written).ToArray();
            return true;
        }
        finally
        {
            if (rented is not null) { ArrayPool<byte>.Shared.Return(rented); }
        }
    }

    /// <summary>Returns the value with all whitespace (including folding) removed. The parser has already restricted values to printable ASCII.</summary>
    public static string CompactAscii(ReadOnlySpan<byte> value)
    {
        Span<char> buffer = value.Length <= 512 ? stackalloc char[value.Length] : new char[value.Length];
        int n = 0;
        foreach (byte b in value)
        {
            if (!IsWhitespace(b)) { buffer[n++] = (char)b; }
        }

        return new string(buffer.Slice(0, n));
    }

    /// <summary>Decodes dkim-quoted-printable (RFC 6376 section 2.11) after removing folding whitespace.</summary>
    public static bool TryDecodeQuotedPrintable(ReadOnlySpan<byte> value, out string decoded)
    {
        decoded = string.Empty;
        Span<byte> buffer = value.Length <= 512 ? stackalloc byte[value.Length] : new byte[value.Length];
        int n = 0;
        for (int i = 0; i < value.Length; i++)
        {
            byte b = value[i];
            if (IsWhitespace(b)) { continue; }
            if (b == (byte)'=')
            {
                if (i + 2 >= value.Length) { return false; }
                int hi = HexValue(value[i + 1]);
                int lo = HexValue(value[i + 2]);
                if (hi < 0 || lo < 0) { return false; }
                buffer[n++] = (byte)((hi << 4) | lo);
                i += 2;
            }
            else
            {
                buffer[n++] = b;
            }
        }

        try
        {
            decoded = new UTF8Encoding(false, true).GetString(buffer.Slice(0, n));
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static int HexValue(byte b) => b switch
    {
        >= (byte)'0' and <= (byte)'9' => b - '0',
        >= (byte)'A' and <= (byte)'F' => b - 'A' + 10,
        >= (byte)'a' and <= (byte)'f' => b - 'a' + 10,
        _ => -1,
    };
}
