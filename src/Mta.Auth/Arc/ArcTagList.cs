using System.Buffers;
using System.Text;

namespace Mta.Auth.Arc;

/// <summary>One <c>name=value</c> item of a tag-value list, as offsets into the parsed input.</summary>
internal readonly struct ArcTag
{
    public ArcTag(int nameStart, int nameLength, int valueStart, int valueLength, int rawValueStart, int rawValueEnd)
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

    /// <summary>Start of the value with folding whitespace trimmed from both ends.</summary>
    public int ValueStart { get; }

    public int ValueLength { get; }

    /// <summary>Offset just after the <c>=</c>: everything from here up to <see cref="RawValueEnd"/> is removed when the signature is stripped of its <c>b=</c> value.</summary>
    public int RawValueStart { get; }

    /// <summary>Offset of the terminating <c>;</c>, or the end of the input.</summary>
    public int RawValueEnd { get; }
}

/// <summary>
/// Strict tag-value list parser (RFC 6376 section 3.2 as used by RFC 8617 section 4.1): tag names are case-sensitive, a tag may appear
/// once, an empty tag is only allowed after the last <c>;</c>, and values are printable ASCII with folding whitespace.
/// </summary>
internal static class ArcTagList
{
    public const int MaxTags = 24;

    public static bool TryParse(ReadOnlySpan<byte> input, int start, Span<ArcTag> tags, out int count, out string? error)
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
                error = "empty tag";
                return false;
            }

            int nameStart = pos;
            if (!IsNameStart(input[pos])) { error = "invalid tag name"; return false; }
            while (pos < input.Length && IsNameChar(input[pos])) { pos++; }
            int nameLength = pos - nameStart;
            pos = SkipWhitespace(input, pos);
            if (pos >= input.Length || input[pos] != (byte)'=') { error = "tag without '='"; return false; }
            pos++;

            int rawStart = pos;
            while (pos < input.Length && input[pos] != (byte)';')
            {
                byte c = input[pos];
                if (!(c is >= 0x21 and <= 0x7E or (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n'))
                {
                    error = "invalid character in tag value";
                    return false;
                }

                pos++;
            }

            int rawEnd = pos;
            int vs = rawStart;
            int ve = rawEnd;
            while (vs < ve && IsWhitespace(input[vs])) { vs++; }
            while (ve > vs && IsWhitespace(input[ve - 1])) { ve--; }

            var name = input.Slice(nameStart, nameLength);
            for (int i = 0; i < count; i++)
            {
                if (input.Slice(tags[i].NameStart, tags[i].NameLength).SequenceEqual(name)) { error = "duplicate tag"; return false; }
            }

            if (count == tags.Length || count >= MaxTags) { error = "too many tags"; return false; }
            tags[count++] = new ArcTag(nameStart, nameLength, vs, ve - vs, rawStart, rawEnd);

            if (pos < input.Length) { pos++; } // the ';'
        }
    }

    public static bool TryFind(ReadOnlySpan<byte> input, ReadOnlySpan<ArcTag> tags, ReadOnlySpan<byte> name, out ArcTag tag)
    {
        foreach (var t in tags)
        {
            if (input.Slice(t.NameStart, t.NameLength).SequenceEqual(name))
            {
                tag = t;
                return true;
            }
        }

        tag = default;
        return false;
    }

    public static ReadOnlySpan<byte> Value(ReadOnlySpan<byte> input, in ArcTag tag) => input.Slice(tag.ValueStart, tag.ValueLength);

    /// <summary>The value with all folding whitespace removed, as ASCII text.</summary>
    public static string CompactAscii(ReadOnlySpan<byte> value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (byte b in value)
        {
            if (!IsWhitespace(b)) { sb.Append((char)b); }
        }

        return sb.ToString();
    }

    /// <summary>Parses a decimal number of 1 to 18 digits (no sign, no leading zeros unless the value is 0).</summary>
    public static bool TryParseNumber(ReadOnlySpan<byte> value, out long number)
    {
        number = 0;
        if (value.Length is 0 or > 18) { return false; }
        if (value.Length > 1 && value[0] == (byte)'0') { return false; }
        foreach (byte b in value)
        {
            if (b is < (byte)'0' or > (byte)'9') { return false; }
            number = number * 10 + (b - '0');
        }

        return true;
    }

    /// <summary>Decodes base64 that may contain folding whitespace. Fails on anything else or when the result exceeds <paramref name="maxBytes"/>.</summary>
    public static bool TryDecodeBase64(ReadOnlySpan<byte> value, int maxBytes, out byte[] bytes)
    {
        bytes = [];
        if (value.Length > maxBytes * 2) { return false; }
        char[] chars = ArrayPool<char>.Shared.Rent(Math.Max(value.Length, 4));
        try
        {
            int n = 0;
            foreach (byte b in value)
            {
                if (IsWhitespace(b)) { continue; }
                if (b >= 0x80) { return false; }
                chars[n++] = (char)b;
            }

            if (n == 0 || n % 4 != 0) { return false; }
            var buffer = new byte[n / 4 * 3];
            if (!Convert.TryFromBase64Chars(chars.AsSpan(0, n), buffer, out int written) || written > maxBytes) { return false; }
            bytes = written == buffer.Length ? buffer : buffer.AsSpan(0, written).ToArray();
            return true;
        }
        finally
        {
            ArrayPool<char>.Shared.Return(chars);
        }
    }

    public static bool IsWhitespace(byte b) => b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n';

    public static int SkipWhitespace(ReadOnlySpan<byte> input, int pos)
    {
        while (pos < input.Length && IsWhitespace(input[pos])) { pos++; }
        return pos;
    }

    private static bool IsNameStart(byte b) => b is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z';

    private static bool IsNameChar(byte b) => IsNameStart(b) || b is >= (byte)'0' and <= (byte)'9' or (byte)'_';
}
