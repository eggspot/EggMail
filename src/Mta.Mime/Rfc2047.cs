using System.Buffers;
using System.Text;

namespace Mta.Mime;

/// <summary>
/// RFC 2047 encoded-word decoding and encoding. Decoding is lenient and bounded: whitespace between adjacent
/// encoded words is dropped (section 6.2), words of the same charset are decoded together so a character split
/// across words survives, unknown charsets fall back to UTF-8 / windows-1252, malformed words are kept literally.
/// Output of decoding is faithful and may contain control characters; callers that store or re-emit it must sanitize.
/// </summary>
public static class Rfc2047
{
    private const int MaxEncodedWordLength = 75;
    private const int MaxCharsetLength = 64;
    private const int MaxPlainWordLength = 900;

    [ThreadStatic]
    private static StringBuilder? s_cache;

    /// <summary>Decodes all encoded words in an unstructured value. Returns the same instance when there is nothing to decode.</summary>
    public static string Decode(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (!text.Contains("=?", StringComparison.Ordinal))
        {
            return text;
        }

        var an = MimeAnomaly.None;
        return DecodeCore(text, ref an);
    }

    /// <summary>Decodes all encoded words in <paramref name="text"/>; <paramref name="anomalies"/> receives malformed-word and charset flags.</summary>
    public static string Decode(ReadOnlySpan<char> text, out MimeAnomaly anomalies)
    {
        anomalies = MimeAnomaly.None;
        return DecodeCore(text, ref anomalies);
    }

    internal static string DecodeCore(ReadOnlySpan<char> text, ref MimeAnomaly anomalies)
    {
        if (!text.Contains("=?", StringComparison.Ordinal))
        {
            return text.ToString();
        }

        var sb = s_cache ?? new StringBuilder(text.Length);
        s_cache = null;
        sb.Clear();
        var run = new Run();
        try
        {
            int pos = 0;
            int heldStart = -1;
            int heldEnd = -1;
            while (pos < text.Length)
            {
                int rel = text[pos..].IndexOf("=?", StringComparison.Ordinal);
                if (rel < 0)
                {
                    run.Flush(sb, ref anomalies);
                    EmitHeld(sb, text, ref heldStart, ref heldEnd);
                    sb.Append(text[pos..]);
                    break;
                }

                int w = pos + rel;
                if (w > pos)
                {
                    var literal = text[pos..w];
                    if (run.Active && IsAllWhitespace(literal))
                    {
                        if (heldStart < 0)
                        {
                            heldStart = pos;
                        }

                        heldEnd = w;
                    }
                    else
                    {
                        run.Flush(sb, ref anomalies);
                        EmitHeld(sb, text, ref heldStart, ref heldEnd);
                        sb.Append(literal);
                    }
                }

                if (TryParseWord(text[w..], out int wordLength, out var charset, out char encoding, out var payload)
                    && run.TryAppend(charset, encoding, payload, sb, ref anomalies))
                {
                    heldStart = -1;
                    heldEnd = -1;
                    pos = w + wordLength;
                }
                else
                {
                    run.Flush(sb, ref anomalies);
                    EmitHeld(sb, text, ref heldStart, ref heldEnd);
                    sb.Append("=?");
                    anomalies |= MimeAnomaly.InvalidEncodedWord;
                    pos = w + 2;
                }
            }

            run.Flush(sb, ref anomalies);
            EmitHeld(sb, text, ref heldStart, ref heldEnd);
            return sb.ToString();
        }
        finally
        {
            run.Dispose();
            if (sb.Capacity <= 16 * 1024)
            {
                s_cache = sb;
            }
        }
    }

    private static void EmitHeld(StringBuilder sb, ReadOnlySpan<char> text, ref int heldStart, ref int heldEnd)
    {
        if (heldStart >= 0)
        {
            sb.Append(text[heldStart..heldEnd]);
            heldStart = -1;
            heldEnd = -1;
        }
    }

    private static bool IsAllWhitespace(ReadOnlySpan<char> s)
    {
        foreach (char c in s)
        {
            if (c is not (' ' or '\t' or '\r' or '\n'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Parses one encoded word at the start of <paramref name="s"/> (which must begin with <c>=?</c>). The charset is
    /// returned without any RFC 2231 language suffix.
    /// </summary>
    private static bool TryParseWord(ReadOnlySpan<char> s, out int length, out ReadOnlySpan<char> charset, out char encoding, out ReadOnlySpan<char> payload)
    {
        length = 0;
        charset = default;
        encoding = default;
        payload = default;
        int i = 2;
        int csStart = i;
        while (i < s.Length && s[i] != '?')
        {
            char c = s[i];
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or ':' or '+' or '*') || i - csStart > MaxCharsetLength)
            {
                return false;
            }

            i++;
        }

        if (i >= s.Length || i == csStart)
        {
            return false;
        }

        charset = s[csStart..i];
        int star = charset.IndexOf('*');
        if (star >= 0)
        {
            charset = charset[..star];
            if (charset.IsEmpty)
            {
                return false;
            }
        }

        i++; // '?'
        if (i + 1 >= s.Length || s[i + 1] != '?')
        {
            return false;
        }

        encoding = char.ToUpperInvariant(s[i]);
        if (encoding is not ('B' or 'Q'))
        {
            return false;
        }

        i += 2;
        int payloadStart = i;
        while (i < s.Length)
        {
            char c = s[i];
            if (c == '?')
            {
                if (i + 1 < s.Length && s[i + 1] == '=')
                {
                    payload = s[payloadStart..i];
                    length = i + 2;
                    return true;
                }

                return false;
            }

            if (c <= ' ' || c > '~')
            {
                return false;
            }

            i++;
        }

        return false;
    }

    /// <summary>Decodes a single encoded word (<c>=?utf-8?Q?...?=</c>). Returns false when <paramref name="word"/> is not exactly one valid encoded word.</summary>
    public static bool TryDecodeWord(ReadOnlySpan<char> word, out string text)
    {
        text = string.Empty;
        if (!word.StartsWith("=?", StringComparison.Ordinal) || !TryParseWord(word, out int len, out _, out _, out _) || len != word.Length)
        {
            return false;
        }

        var an = MimeAnomaly.None;
        text = DecodeCore(word, ref an);
        return (an & MimeAnomaly.InvalidEncodedWord) == 0;
    }

    /// <summary>A run of adjacent encoded words with the same charset, decoded together.</summary>
    private struct Run
    {
        private byte[]? _bytes;
        private int _length;
        private string? _charset;

        public readonly bool Active => _charset is not null;

        public bool TryAppend(ReadOnlySpan<char> charset, char encoding, ReadOnlySpan<char> payload, StringBuilder sb, ref MimeAnomaly anomalies)
        {
            // Convert payload to bytes first; a payload that is not decodable invalidates the word.
            byte[]? rented = null;
            Span<byte> ascii = payload.Length <= 512 ? stackalloc byte[512] : (rented = ArrayPool<byte>.Shared.Rent(payload.Length));
            try
            {
                for (int i = 0; i < payload.Length; i++)
                {
                    ascii[i] = (byte)payload[i];
                }

                var src = ascii[..payload.Length];
                int max = encoding == 'B' ? Base64Decoder.GetMaxDecodedLength(src.Length) : src.Length + 1;
                EnsureCapacity(_length + max);
                int n;
                if (encoding == 'B')
                {
                    var dec = new Base64Decoder();
                    n = dec.Decode(src, _bytes.AsSpan(_length));
                    n += dec.Finish(_bytes.AsSpan(_length + n));
                    if ((dec.Anomalies & MimeAnomaly.MalformedBase64) != 0)
                    {
                        // Tolerate missing padding but reject garbage inside the word.
                        if (!IsWellFormedBase64Payload(src))
                        {
                            return false;
                        }
                    }
                }
                else
                {
                    n = DecodeQ(src, _bytes.AsSpan(_length));
                }

                string normalized = NormalizeCharset(charset);
                if (_charset is not null && !string.Equals(_charset, normalized, StringComparison.Ordinal))
                {
                    // Keep the bytes just decoded: flush the previous run first, then restart with them.
                    var fresh = _bytes.AsSpan(_length, n).ToArray();
                    Flush(sb, ref anomalies);
                    EnsureCapacity(fresh.Length);
                    fresh.CopyTo(_bytes.AsSpan());
                    _length = fresh.Length;
                }
                else
                {
                    _length += n;
                }

                _charset = normalized;
                return true;
            }
            finally
            {
                if (rented is not null)
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }
        }

        public void Flush(StringBuilder sb, ref MimeAnomaly anomalies)
        {
            if (_charset is null)
            {
                return;
            }

            string text = MimeCharsets.Decode(_bytes.AsSpan(0, _length), _charset, ref anomalies);
            sb.Append(text);
            _charset = null;
            _length = 0;
        }

        public void Dispose()
        {
            if (_bytes is not null)
            {
                ArrayPool<byte>.Shared.Return(_bytes);
                _bytes = null;
            }
        }

        private void EnsureCapacity(int needed)
        {
            if (_bytes is null)
            {
                _bytes = ArrayPool<byte>.Shared.Rent(Math.Max(needed, 256));
            }
            else if (_bytes.Length < needed)
            {
                var bigger = ArrayPool<byte>.Shared.Rent(Math.Max(needed, _bytes.Length * 2));
                Buffer.BlockCopy(_bytes, 0, bigger, 0, _length);
                ArrayPool<byte>.Shared.Return(_bytes);
                _bytes = bigger;
            }
        }

        private static string NormalizeCharset(ReadOnlySpan<char> charset) => charset.ToString().ToLowerInvariant();

        private static bool IsWellFormedBase64Payload(ReadOnlySpan<byte> src)
        {
            foreach (byte b in src)
            {
                if (!(char.IsAsciiLetterOrDigit((char)b) || b is (byte)'+' or (byte)'/' or (byte)'='))
                {
                    return false;
                }
            }

            return true;
        }

        private static int DecodeQ(ReadOnlySpan<byte> src, Span<byte> dst)
        {
            int n = 0;
            for (int i = 0; i < src.Length; i++)
            {
                byte b = src[i];
                if (b == '_')
                {
                    dst[n++] = (byte)' ';
                }
                else if (b == '=' && i + 2 < src.Length && IsHex(src[i + 1]) && IsHex(src[i + 2]))
                {
                    dst[n++] = (byte)((HexVal(src[i + 1]) << 4) | HexVal(src[i + 2]));
                    i += 2;
                }
                else
                {
                    dst[n++] = b;
                }
            }

            return n;
        }

        private static bool IsHex(byte b) => char.IsAsciiHexDigit((char)b);

        private static int HexVal(byte b) => b <= (byte)'9' ? b - '0' : (b | 0x20) - 'a' + 10;
    }

    // ---------------------------------------------------------------- encoding

    /// <summary>True when <paramref name="text"/> cannot be written as plain header text (non-ASCII, control characters or a lookalike of an encoded word).</summary>
    public static bool RequiresEncoding(ReadOnlySpan<char> text)
    {
        foreach (char c in text)
        {
            if ((c < ' ' && c != '\t') || c > '~')
            {
                return true;
            }
        }

        return text.Contains("=?", StringComparison.Ordinal);
    }

    /// <summary>
    /// Encodes <paramref name="value"/> for use in an unstructured field or phrase. ASCII words stay as they are; the span
    /// from the first to the last word that needs it becomes a sequence of encoded words of at most 75 characters,
    /// separated by single spaces, so the result can be folded at those spaces. The default charset is UTF-8.
    /// Returns the same instance when nothing needs encoding. Line folding is the caller's job (<see cref="HeaderFolder"/>).
    /// </summary>
    /// <param name="value">The text.</param>
    /// <param name="charset">The charset of the encoded words (default UTF-8).</param>
    /// <param name="encodeLongWords">Also encode ASCII words longer than 900 characters so that they can be folded (right for
    /// free text such as Subject; wrong for values with their own syntax such as URLs).</param>
    /// <exception cref="ArgumentException">The charset is stateful or wide (ISO-2022, UTF-7, UTF-16, UTF-32).</exception>
    public static string Encode(string value, Encoding? charset = null, bool encodeLongWords = true)
    {
        ArgumentNullException.ThrowIfNull(value);
        charset ??= Encoding.UTF8;
        int first = -1;
        int last = -1;
        int i = 0;
        while (i < value.Length)
        {
            while (i < value.Length && value[i] is ' ' or '\t')
            {
                i++;
            }

            int start = i;
            while (i < value.Length && value[i] is not (' ' or '\t'))
            {
                i++;
            }

            if (i > start)
            {
                var word = value.AsSpan(start, i - start);
                if (RequiresEncoding(word) || (encodeLongWords && word.Length > MaxPlainWordLength))
                {
                    if (first < 0)
                    {
                        first = start;
                    }

                    last = i;
                }
            }
        }

        if (first < 0)
        {
            return value;
        }

        var sb = new StringBuilder(value.Length * 2);
        sb.Append(value, 0, first);
        AppendEncodedGroup(sb, value.AsSpan(first, last - first), charset);
        sb.Append(value, last, value.Length - last);
        return sb.ToString();
    }

    /// <summary>Encodes the whole of <paramref name="text"/> as one or more encoded words (even when it is plain ASCII).</summary>
    public static string EncodeWords(string text, Encoding? charset = null)
    {
        ArgumentNullException.ThrowIfNull(text);
        var sb = new StringBuilder(text.Length * 2);
        AppendEncodedGroup(sb, text, charset ?? Encoding.UTF8);
        return sb.ToString();
    }

    private static void AppendEncodedGroup(StringBuilder sb, ReadOnlySpan<char> text, Encoding charset)
    {
        int cp = charset.CodePage;
        if ((cp is >= 50220 and <= 50229) || cp is 65000 or 1200 or 1201 or 12000 or 12001)
        {
            throw new ArgumentException("Stateful or wide charsets cannot be used for encoded words.", nameof(charset));
        }

        string charsetName = cp == 65001 ? "utf-8" : charset.WebName;
        string prefixB = $"=?{charsetName}?B?";
        string prefixQ = $"=?{charsetName}?Q?";
        int overhead = prefixB.Length + 2;
        int capacity = MaxEncodedWordLength - overhead; // payload characters per word

        // Pass 1: encode runes to bytes, remembering rune boundaries so words never split a character.
        byte[] all = ArrayPool<byte>.Shared.Rent(Math.Max(16, text.Length * 4 + 8));
        int[] ends = ArrayPool<int>.Shared.Rent(Math.Max(16, text.Length + 1));
        try
        {
            int total = 0;
            int runeCount = 0;
            Span<byte> scratch = stackalloc byte[16];
            Span<char> chars = stackalloc char[2];
            foreach (var rune in text.EnumerateRunes())
            {
                int cn = rune.EncodeToUtf16(chars);
                int n = charset.GetBytes(chars[..cn], scratch);
                scratch[..n].CopyTo(all.AsSpan(total));
                total += n;
                ends[runeCount++] = total;
            }

            // Choose Q when it is shorter overall, else B.
            long qLen = 0;
            for (int k = 0; k < total; k++)
            {
                qLen += IsQSafe(all[k]) || all[k] == (byte)' ' ? 1 : 3;
            }

            long bLen = (total + 2) / 3 * 4;
            bool useQ = qLen < bLen;
            string prefix = useQ ? prefixQ : prefixB;

            int ri = 0;
            int pos = 0;
            bool firstWord = true;
            while (pos < total)
            {
                // Greedily take runes while the encoded size fits.
                int wordEnd = pos;
                int cost = 0;
                int startRune = ri;
                while (ri < runeCount)
                {
                    int runeStart = ri == 0 ? 0 : ends[ri - 1];
                    int runeEnd = ends[ri];
                    int runeCost;
                    if (useQ)
                    {
                        runeCost = 0;
                        for (int k = runeStart; k < runeEnd; k++)
                        {
                            runeCost += IsQSafe(all[k]) ? 1 : 3;
                        }

                        if (cost + runeCost > capacity)
                        {
                            break;
                        }

                        cost += runeCost;
                    }
                    else
                    {
                        int bytes = runeEnd - pos;
                        if ((bytes + 2) / 3 * 4 > capacity)
                        {
                            break;
                        }
                    }

                    wordEnd = runeEnd;
                    ri++;
                }

                if (ri == startRune)
                {
                    // A single character that does not fit (cannot happen with 63 payload characters and <= 4 byte characters, defensive).
                    wordEnd = ends[ri++];
                }

                if (!firstWord)
                {
                    sb.Append(' ');
                }

                firstWord = false;
                sb.Append(prefix);
                var slice = all.AsSpan(pos, wordEnd - pos);
                if (useQ)
                {
                    foreach (byte b in slice)
                    {
                        if (b == ' ')
                        {
                            sb.Append('_');
                        }
                        else if (IsQSafe(b))
                        {
                            sb.Append((char)b);
                        }
                        else
                        {
                            sb.Append('=').Append(HexUpper(b >> 4)).Append(HexUpper(b & 0xF));
                        }
                    }
                }
                else
                {
                    sb.Append(Convert.ToBase64String(slice));
                }

                sb.Append("?=");
                pos = wordEnd;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(all);
            ArrayPool<int>.Shared.Return(ends);
        }
    }

    private static char HexUpper(int v) => (char)(v < 10 ? '0' + v : 'A' + v - 10);

    private static bool IsQSafe(byte b) =>
        (b >= (byte)'0' && b <= (byte)'9') || (b >= (byte)'A' && b <= (byte)'Z') || (b >= (byte)'a' && b <= (byte)'z')
        || b is (byte)'!' or (byte)'*' or (byte)'+' or (byte)'-' or (byte)'/';
}
