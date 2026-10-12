using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Mta.Mime;

/// <summary>A resolved MIME parameter (RFC 2045 / RFC 2231).</summary>
/// <param name="Name">Attribute name, lower-cased, without RFC 2231 section markers.</param>
/// <param name="Value">Decoded value.</param>
/// <param name="Charset">Charset announced by an RFC 2231 extended value, if any.</param>
/// <param name="Language">Language announced by an RFC 2231 extended value, if any.</param>
public readonly record struct MimeParameter(string Name, string Value, string? Charset = null, string? Language = null);

/// <summary>An ordered, case-insensitive parameter list with RFC 2231 continuations and extended values already resolved.</summary>
public sealed class ParameterList : IReadOnlyList<MimeParameter>
{
    private readonly MimeParameter[] _items;

    /// <summary>An empty list.</summary>
    public static ParameterList Empty { get; } = new([]);

    internal ParameterList(MimeParameter[] items) => _items = items;

    /// <inheritdoc />
    public int Count => _items.Length;

    /// <inheritdoc />
    public MimeParameter this[int index] => _items[index];

    /// <summary>The value of the named parameter (case-insensitive), or null.</summary>
    public string? this[string name] => TryGetValue(name, out var v) ? v : null;

    /// <summary>Looks up a parameter by name (case-insensitive).</summary>
    public bool TryGetValue(string name, [NotNullWhen(true)] out string? value)
    {
        ArgumentNullException.ThrowIfNull(name);
        foreach (var p in _items)
        {
            if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                value = p.Value;
                return true;
            }
        }

        value = null;
        return false;
    }

    /// <inheritdoc />
    public IEnumerator<MimeParameter> GetEnumerator() => ((IEnumerable<MimeParameter>)_items).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

/// <summary>
/// The Content-Type header (RFC 2045 section 5): media type, subtype and parameters. Parsing is lenient and never
/// throws; an unparsable value yields <c>application/octet-stream</c> with <see cref="MimeAnomaly.InvalidContentType"/>.
/// </summary>
public sealed class ContentType
{
    /// <summary>The default when no Content-Type header is present: <c>text/plain</c> (charset US-ASCII).</summary>
    public static ContentType Default { get; } = new("text", "plain", ParameterList.Empty, MimeAnomaly.None);

    /// <summary>The default inside multipart/digest: <c>message/rfc822</c>.</summary>
    public static ContentType DigestDefault { get; } = new("message", "rfc822", ParameterList.Empty, MimeAnomaly.None);

    /// <summary>What an unparsable Content-Type is replaced by.</summary>
    public static ContentType OctetStream { get; } = new("application", "octet-stream", ParameterList.Empty, MimeAnomaly.InvalidContentType);

    internal ContentType(string mediaType, string subtype, ParameterList parameters, MimeAnomaly anomalies)
    {
        MediaType = mediaType;
        MediaSubtype = subtype;
        Parameters = parameters;
        Anomalies = anomalies;
    }

    /// <summary>Creates a content type from parts. The type and subtype must be RFC 2045 tokens.</summary>
    public ContentType(string mediaType, string subtype)
        : this(Validate(mediaType), Validate(subtype), ParameterList.Empty, MimeAnomaly.None)
    {
    }

    /// <summary>Lower-case top-level type ("text", "multipart", "image" ...).</summary>
    public string MediaType { get; }

    /// <summary>Lower-case subtype ("plain", "html", "mixed" ...).</summary>
    public string MediaSubtype { get; }

    /// <summary>Parameters in source order.</summary>
    public ParameterList Parameters { get; }

    /// <summary>Anomalies noticed while parsing.</summary>
    public MimeAnomaly Anomalies { get; }

    /// <summary>"type/subtype" in lower case.</summary>
    public string MimeType => MediaType + "/" + MediaSubtype;

    /// <summary>True for <c>multipart/*</c>.</summary>
    public bool IsMultipart => MediaType == "multipart";

    /// <summary>True for <c>text/*</c>.</summary>
    public bool IsText => MediaType == "text";

    /// <summary>True for <c>message/rfc822</c> (and the legacy <c>message/global</c>).</summary>
    public bool IsEmbeddedMessage => MediaType == "message" && MediaSubtype is "rfc822" or "global";

    /// <summary>The multipart boundary parameter, or null.</summary>
    public string? Boundary => Parameters["boundary"];

    /// <summary>The charset parameter (lower-cased, as written), or null.</summary>
    public string? Charset => Parameters["charset"]?.Trim().ToLowerInvariant();

    /// <summary>The <c>name</c> parameter (obsolete way to carry a file name), or null.</summary>
    public string? Name => Parameters["name"];

    /// <summary>Case-insensitive test against "type/subtype"; a subtype of "*" matches any.</summary>
    public bool Matches(string mediaType, string subtype) =>
        string.Equals(MediaType, mediaType, StringComparison.OrdinalIgnoreCase)
        && (subtype == "*" || string.Equals(MediaSubtype, subtype, StringComparison.OrdinalIgnoreCase));

    /// <summary>Parses a Content-Type value. Never throws; <c>null</c> or empty yields <see cref="Default"/>.</summary>
    public static ContentType Parse(string? value, MimeLimits? limits = null)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Default;
        }

        return Parse(value.AsSpan(), limits ?? MimeLimits.Default);
    }

    /// <summary>Parses a Content-Type value.</summary>
    public static ContentType Parse(ReadOnlySpan<char> value, MimeLimits limits)
    {
        int pos = 0;
        var an = MimeAnomaly.None;
        FieldScanner.SkipCfws(value, ref pos);
        string type = FieldScanner.ReadToken(value, ref pos);
        FieldScanner.SkipCfws(value, ref pos);
        if (type.Length == 0 || pos >= value.Length || value[pos] != '/')
        {
            return OctetStream;
        }

        pos++;
        FieldScanner.SkipCfws(value, ref pos);
        string subtype = FieldScanner.ReadToken(value, ref pos);
        if (subtype.Length == 0 || type.Length > 127 || subtype.Length > 127)
        {
            return OctetStream;
        }

        var parameters = ParameterParser.Parse(value, pos, limits, ref an);
        return new ContentType(type.ToLowerInvariant(), subtype.ToLowerInvariant(), parameters, an);
    }

    /// <summary>Returns "type/subtype" followed by the parameters, quoted and RFC 2231-encoded as needed (unfolded).</summary>
    public string ToHeaderValue()
    {
        var sb = new StringBuilder(MimeType);
        foreach (var p in Parameters)
        {
            ParameterFormatter.Append(sb, p.Name, p.Value);
        }

        return sb.ToString();
    }

    /// <inheritdoc />
    public override string ToString() => ToHeaderValue();

    private static string Validate(string token)
    {
        ArgumentNullException.ThrowIfNull(token);
        if (token.Length == 0 || token.Length > 127 || !FieldScanner.IsToken(token))
        {
            throw new ArgumentException("Not an RFC 2045 token: " + token, nameof(token));
        }

        return token.ToLowerInvariant();
    }
}

/// <summary>The Content-Disposition header (RFC 2183).</summary>
public sealed class ContentDisposition
{
    internal ContentDisposition(string disposition, ParameterList parameters)
    {
        Disposition = disposition;
        Parameters = parameters;
    }

    /// <summary>Lower-case disposition type ("attachment", "inline" or an extension token).</summary>
    public string Disposition { get; }

    /// <summary>Parameters (filename, size, dates ...).</summary>
    public ParameterList Parameters { get; }

    /// <summary>True for "attachment".</summary>
    public bool IsAttachment => Disposition == "attachment";

    /// <summary>True for "inline".</summary>
    public bool IsInline => Disposition == "inline";

    /// <summary>The <c>filename</c> parameter, or null.</summary>
    public string? FileName => Parameters["filename"];

    /// <summary>The <c>size</c> parameter if it is a valid non-negative integer.</summary>
    public long? Size => long.TryParse(Parameters["size"], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long n) ? n : null;

    /// <summary>Parses a Content-Disposition value. Returns null when no disposition token is present.</summary>
    public static ContentDisposition? Parse(string? value, MimeLimits? limits = null)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var span = value.AsSpan();
        int pos = 0;
        var an = MimeAnomaly.None;
        FieldScanner.SkipCfws(span, ref pos);
        string disposition = FieldScanner.ReadToken(span, ref pos);
        if (disposition.Length == 0)
        {
            return null;
        }

        var parameters = ParameterParser.Parse(span, pos, limits ?? MimeLimits.Default, ref an);
        return new ContentDisposition(disposition.ToLowerInvariant(), parameters);
    }
}

/// <summary>Low-level scanning helpers for structured header values (tokens, quoted strings, comments).</summary>
internal static class FieldScanner
{
    private const int MaxCommentDepth = 32;

    public static bool IsTokenChar(char c) =>
        c > ' ' && c != 127 && c is not ('(' or ')' or '<' or '>' or '@' or ',' or ';' or ':' or '\\' or '"' or '/' or '[' or ']' or '?' or '=');

    public static bool IsToken(ReadOnlySpan<char> s)
    {
        if (s.IsEmpty)
        {
            return false;
        }

        foreach (char c in s)
        {
            if (!IsTokenChar(c))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Skips linear whitespace and (nested) comments. Always makes progress or stops at a non-CFWS character.</summary>
    public static void SkipCfws(ReadOnlySpan<char> s, ref int pos)
    {
        while (pos < s.Length)
        {
            char c = s[pos];
            if (c is ' ' or '\t' or '\r' or '\n')
            {
                pos++;
            }
            else if (c == '(')
            {
                SkipComment(s, ref pos);
            }
            else
            {
                return;
            }
        }
    }

    /// <summary>Skips a comment starting at <c>(</c> (nested, with quoted pairs). An unterminated comment consumes the rest.</summary>
    public static void SkipComment(ReadOnlySpan<char> s, ref int pos)
    {
        int depth = 0;
        while (pos < s.Length)
        {
            char c = s[pos++];
            if (c == '\\' && pos < s.Length)
            {
                pos++;
            }
            else if (c == '(')
            {
                if (++depth > MaxCommentDepth)
                {
                    // Pathological nesting: give up on the rest of the value.
                    pos = s.Length;
                    return;
                }
            }
            else if (c == ')' && --depth == 0)
            {
                return;
            }
        }
    }

    public static string ReadToken(ReadOnlySpan<char> s, ref int pos)
    {
        int start = pos;
        while (pos < s.Length && IsTokenChar(s[pos]))
        {
            pos++;
        }

        return s[start..pos].ToString();
    }

    /// <summary>Reads a quoted-string starting at the opening quote; resolves quoted pairs. An unterminated string consumes the rest.</summary>
    public static string ReadQuoted(ReadOnlySpan<char> s, ref int pos)
    {
        pos++; // opening quote
        int start = pos;
        bool hasEscape = false;
        while (pos < s.Length && s[pos] != '"')
        {
            if (s[pos] == '\\' && pos + 1 < s.Length)
            {
                hasEscape = true;
                pos++;
            }

            pos++;
        }

        var raw = s[start..Math.Min(pos, s.Length)];
        if (pos < s.Length)
        {
            pos++; // closing quote
        }

        if (!hasEscape)
        {
            return raw.ToString();
        }

        var sb = new StringBuilder(raw.Length);
        for (int i = 0; i < raw.Length; i++)
        {
            if (raw[i] == '\\' && i + 1 < raw.Length)
            {
                i++;
            }

            sb.Append(raw[i]);
        }

        return sb.ToString();
    }
}

/// <summary>Parses the <c>; name=value</c> parameter tail of a structured header and resolves RFC 2231.</summary>
internal static class ParameterParser
{
    private const int MaxContinuationIndex = 255;

    private struct Fragment
    {
        public string Name;
        public int Index; // -1: no section number
        public bool Extended;
        public string Value;
    }

    public static ParameterList Parse(ReadOnlySpan<char> s, int pos, MimeLimits limits, ref MimeAnomaly an)
    {
        List<Fragment>? fragments = null;
        while (pos < s.Length)
        {
            int before = pos;
            FieldScanner.SkipCfws(s, ref pos);
            if (pos >= s.Length)
            {
                break;
            }

            if (s[pos] == ';')
            {
                pos++;
                continue;
            }

            int nameStart = pos;
            while (pos < s.Length && s[pos] is not (';' or '=' or ' ' or '\t' or '\r' or '\n' or '('))
            {
                pos++;
            }

            var rawName = s[nameStart..pos];
            FieldScanner.SkipCfws(s, ref pos);
            if (pos < s.Length && s[pos] == '=')
            {
                pos++;
                FieldScanner.SkipCfws(s, ref pos);
                string value;
                if (pos < s.Length && s[pos] == '"')
                {
                    value = FieldScanner.ReadQuoted(s, ref pos);
                }
                else
                {
                    value = ReadUnquotedValue(s, ref pos);
                }

                if (rawName.Length > 0)
                {
                    if (fragments is { Count: var c } && c >= limits.MaxParameters)
                    {
                        an |= MimeAnomaly.TooManyParameters;
                        break;
                    }

                    fragments ??= new List<Fragment>(4);
                    fragments.Add(MakeFragment(rawName, value));
                }
            }
            else if (pos == before)
            {
                pos++;
            }
        }

        return fragments is null ? ParameterList.Empty : new ParameterList(Resolve(fragments, ref an));
    }

    /// <summary>Reads up to the next semicolon; a parenthesis preceded by white space starts a comment, which is dropped.</summary>
    private static string ReadUnquotedValue(ReadOnlySpan<char> s, ref int pos)
    {
        int start = pos;
        StringBuilder? sb = null;
        int copyFrom = start;
        while (pos < s.Length && s[pos] != ';')
        {
            if (s[pos] == '(' && pos > start && s[pos - 1] is ' ' or '\t')
            {
                sb ??= new StringBuilder();
                sb.Append(s[copyFrom..pos]);
                FieldScanner.SkipComment(s, ref pos);
                copyFrom = pos;
            }
            else
            {
                pos++;
            }
        }

        if (sb is null)
        {
            return s[start..pos].Trim().ToString();
        }

        sb.Append(s[copyFrom..pos]);
        return sb.ToString().Trim();
    }

    private static Fragment MakeFragment(ReadOnlySpan<char> rawName, string value)
    {
        var frag = new Fragment { Index = -1, Value = value };
        int star = rawName.IndexOf('*');
        if (star <= 0)
        {
            frag.Name = rawName.ToString().ToLowerInvariant();
            return frag;
        }

        var baseName = rawName[..star];
        var rest = rawName[(star + 1)..];
        bool extended = false;
        if (rest.Length > 0 && rest[^1] == '*')
        {
            extended = true;
            rest = rest[..^1];
        }

        int index = -1;
        if (rest.Length > 0)
        {
            if (rest.Length > 3 || !int.TryParse(rest, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out index) || index > MaxContinuationIndex)
            {
                // Not a valid section marker: keep the literal name.
                frag.Name = rawName.ToString().ToLowerInvariant();
                return frag;
            }
        }
        else
        {
            // "name*": an extended value without section number.
            extended = true;
        }

        frag.Name = baseName.ToString().ToLowerInvariant();
        frag.Index = index;
        frag.Extended = extended;
        return frag;
    }

    private static MimeParameter[] Resolve(List<Fragment> fragments, ref MimeAnomaly an)
    {
        var result = new List<MimeParameter>(fragments.Count);
        var done = new bool[fragments.Count];
        for (int i = 0; i < fragments.Count; i++)
        {
            if (done[i])
            {
                continue;
            }

            string name = fragments[i].Name;
            // Collect the group.
            int simpleIndex = -1;
            List<Fragment>? sections = null;
            for (int j = i; j < fragments.Count; j++)
            {
                if (done[j] || !string.Equals(fragments[j].Name, name, StringComparison.Ordinal))
                {
                    continue;
                }

                done[j] = true;
                var f = fragments[j];
                if (f.Index < 0 && !f.Extended)
                {
                    if (simpleIndex < 0)
                    {
                        simpleIndex = j;
                    }
                }
                else
                {
                    (sections ??= []).Add(f.Index < 0 ? f with { Index = 0 } : f);
                }
            }

            if (sections is null)
            {
                string raw = fragments[simpleIndex].Value;
                string v = raw.Contains("=?", StringComparison.Ordinal) ? Rfc2047.DecodeCore(raw, ref an) : raw;
                result.Add(new MimeParameter(name, v));
                continue;
            }

            result.Add(ResolveSections(name, sections, ref an));
        }

        return result.ToArray();
    }

    private static MimeParameter ResolveSections(string name, List<Fragment> sections, ref MimeAnomaly an)
    {
        // Stable insertion sort by index (<= 64 entries).
        for (int a = 1; a < sections.Count; a++)
        {
            var cur = sections[a];
            int b = a - 1;
            while (b >= 0 && sections[b].Index > cur.Index)
            {
                sections[b + 1] = sections[b];
                b--;
            }

            sections[b + 1] = cur;
        }

        var bytes = new List<byte>(64);
        string? charset = null;
        string? language = null;
        int expected = sections[0].Index;
        if (expected != 0)
        {
            an |= MimeAnomaly.InvalidParameterContinuation;
        }

        bool first = true;
        foreach (var section in sections)
        {
            if (section.Index < expected)
            {
                an |= MimeAnomaly.InvalidParameterContinuation; // duplicate section number: first one wins
                continue;
            }

            if (section.Index > expected)
            {
                an |= MimeAnomaly.InvalidParameterContinuation; // gap: stop, do not invent data
                break;
            }

            expected++;
            string value = section.Value;
            if (section.Extended)
            {
                if (first)
                {
                    int q1 = value.IndexOf('\'');
                    int q2 = q1 < 0 ? -1 : value.IndexOf('\'', q1 + 1);
                    if (q2 >= 0)
                    {
                        charset = value[..q1];
                        language = value[(q1 + 1)..q2];
                        value = value[(q2 + 1)..];
                        if (charset.Length == 0)
                        {
                            charset = null;
                        }

                        if (language.Length == 0)
                        {
                            language = null;
                        }
                    }
                }

                PercentDecode(value, bytes);
            }
            else
            {
                bytes.AddRange(Encoding.UTF8.GetBytes(value));
            }

            first = false;
        }

        string text = MimeCharsets.Decode(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(bytes), charset, ref an);
        return new MimeParameter(name, text, charset?.ToLowerInvariant(), language);
    }

    private static void PercentDecode(string value, List<byte> output)
    {
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (c == '%' && i + 2 < value.Length && char.IsAsciiHexDigit(value[i + 1]) && char.IsAsciiHexDigit(value[i + 2]))
            {
                output.Add((byte)((HexVal(value[i + 1]) << 4) | HexVal(value[i + 2])));
                i += 2;
            }
            else if (c < 0x80)
            {
                output.Add((byte)c);
            }
            else
            {
                output.AddRange(Encoding.UTF8.GetBytes(c.ToString()));
            }
        }
    }

    private static int HexVal(char c) => c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;
}

/// <summary>Formats MIME parameters, using quoted-strings and RFC 2231 encoding with continuations as needed.</summary>
internal static class ParameterFormatter
{
    private const int SectionPayload = 40;

    /// <summary>Appends <c>; name=value</c> (the separator is a semicolon and a space; fold points follow it).</summary>
    public static void Append(StringBuilder sb, string name, string value)
    {
        bool ascii = true;
        bool token = value.Length > 0;
        foreach (char c in value)
        {
            if (c is < ' ' or > '~')
            {
                ascii = false;
                break;
            }

            if (!FieldScanner.IsTokenChar(c))
            {
                token = false;
            }
        }

        if (ascii && value.Length <= 60)
        {
            sb.Append("; ").Append(name).Append('=');
            if (token)
            {
                sb.Append(value);
            }
            else
            {
                AppendQuoted(sb, value);
            }

            return;
        }

        // RFC 2231: encode as UTF-8 percent-escapes, split into sections of limited size so lines can be folded.
        var bytes = Encoding.UTF8.GetBytes(value);
        var encoded = new StringBuilder(bytes.Length * 2);
        var sections = new List<string>();
        Span<byte> buf = stackalloc byte[4];
        foreach (var rune in value.EnumerateRunes())
        {
            int n = rune.EncodeToUtf8(buf);
            var piece = new StringBuilder(12);
            for (int i = 0; i < n; i++)
            {
                byte b = buf[i];
                if (char.IsAsciiLetterOrDigit((char)b) || b is (byte)'.' or (byte)'-' or (byte)'_' or (byte)'~')
                {
                    piece.Append((char)b);
                }
                else
                {
                    piece.Append('%').Append("0123456789ABCDEF"[b >> 4]).Append("0123456789ABCDEF"[b & 0xF]);
                }
            }

            if (encoded.Length + piece.Length > SectionPayload)
            {
                sections.Add(encoded.ToString());
                encoded.Clear();
            }

            encoded.Append(piece);
        }

        if (encoded.Length > 0 || sections.Count == 0)
        {
            sections.Add(encoded.ToString());
        }

        if (sections.Count == 1)
        {
            sb.Append("; ").Append(name).Append("*=utf-8''").Append(sections[0]);
            return;
        }

        for (int i = 0; i < sections.Count; i++)
        {
            sb.Append("; ").Append(name).Append('*').Append(i.ToString(System.Globalization.CultureInfo.InvariantCulture)).Append("*=");
            if (i == 0)
            {
                sb.Append("utf-8''");
            }

            sb.Append(sections[i]);
        }
    }

    private static void AppendQuoted(StringBuilder sb, string value)
    {
        sb.Append('"');
        foreach (char c in value)
        {
            if (c is '"' or '\\')
            {
                sb.Append('\\');
            }

            sb.Append(c);
        }

        sb.Append('"');
    }
}
