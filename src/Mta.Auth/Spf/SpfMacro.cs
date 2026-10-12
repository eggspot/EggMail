using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Mta.Auth.Spf;

/// <summary>Which grammar a macro string is parsed with (RFC 7208 section 7.1).</summary>
public enum SpfMacroKind
{
    /// <summary>A <c>domain-spec</c>: macro string ending in a top label or a macro; no spaces; the macros <c>c</c>, <c>r</c> and <c>t</c> are not allowed.</summary>
    DomainSpec,

    /// <summary>An <c>explain-string</c> (the content of an explanation TXT record): spaces allowed, all macro letters allowed.</summary>
    Explanation,

    /// <summary>The value of an unknown modifier: a plain <c>macro-string</c>.</summary>
    ModifierValue,
}

/// <summary>The values the SPF macros expand to for one evaluation step (RFC 7208 section 7.2).</summary>
public sealed record SpfMacroContext
{
    /// <summary>Creates a context.</summary>
    /// <param name="sender">The full sender mailbox (<c>%{s}</c>); the local part defaults to <c>postmaster</c> when absent.</param>
    /// <param name="domain">The current domain being evaluated (<c>%{d}</c>).</param>
    /// <param name="clientIp">The SMTP client address (<c>%{i}</c>, <c>%{c}</c>, <c>%{v}</c>).</param>
    /// <param name="heloDomain">The HELO/EHLO domain (<c>%{h}</c>).</param>
    public SpfMacroContext(string sender, string domain, IPAddress clientIp, string heloDomain)
    {
        ArgumentNullException.ThrowIfNull(clientIp);
        sender ??= string.Empty;
        int at = sender.LastIndexOf('@');
        string local = at > 0 ? sender[..at] : "postmaster";
        LocalPart = local;
        SenderDomain = at >= 0 ? sender[(at + 1)..] : sender;
        Sender = at > 0 ? sender : local + "@" + SenderDomain;
        Domain = domain ?? string.Empty;
        ClientIp = clientIp.IsIPv4MappedToIPv6 ? clientIp.MapToIPv4() : clientIp;
        HeloDomain = heloDomain ?? string.Empty;
    }

    /// <summary>The full sender mailbox (<c>%{s}</c>), with <c>postmaster</c> substituted for a missing local part.</summary>
    public string Sender { get; }

    /// <summary>The local part of the sender (<c>%{l}</c>).</summary>
    public string LocalPart { get; }

    /// <summary>The domain of the sender (<c>%{o}</c>).</summary>
    public string SenderDomain { get; }

    /// <summary>The current domain (<c>%{d}</c>).</summary>
    public string Domain { get; }

    /// <summary>The client address, with IPv4-mapped IPv6 addresses converted to IPv4.</summary>
    public IPAddress ClientIp { get; }

    /// <summary>The HELO/EHLO domain (<c>%{h}</c>).</summary>
    public string HeloDomain { get; }

    /// <summary>The validated domain name of the client (<c>%{p}</c>); <c>unknown</c> when none validated.</summary>
    public string ValidatedDomain { get; init; } = "unknown";

    /// <summary>The name of the receiving host (<c>%{r}</c>).</summary>
    public string ReceivingHostName { get; init; } = "unknown";

    /// <summary>The time for <c>%{t}</c>.</summary>
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UnixEpoch;
}

/// <summary>
/// A parsed SPF macro string (RFC 7208 section 7). Parsing validates the whole grammar up front so evaluation
/// never meets a syntax error; expansion is size-bounded.
/// </summary>
public sealed class SpfMacroString
{
    private const string LetterChars = "slodiphcrtv";
    private const string DelimiterChars = ".-+,/_=";

    private readonly Segment[] _segments;

    private SpfMacroString(string source, Segment[] segments, bool usesValidatedDomain, bool usesExplanationOnly)
    {
        Source = source;
        _segments = segments;
        UsesValidatedDomainName = usesValidatedDomain;
        UsesExplanationOnlyMacros = usesExplanationOnly;
    }

    /// <summary>The text this macro string was parsed from.</summary>
    public string Source { get; }

    /// <summary>True when the string contains <c>%{p}</c>, whose value needs DNS lookups to compute.</summary>
    public bool UsesValidatedDomainName { get; }

    /// <summary>True when the string contains a macro that is only valid in explanations (<c>c</c>, <c>r</c>, <c>t</c>).</summary>
    public bool UsesExplanationOnlyMacros { get; }

    /// <summary>True when the string has no macros at all.</summary>
    public bool IsLiteral => _segments.All(s => s.Letter == '\0');

    /// <inheritdoc />
    public override string ToString() => Source;

    /// <summary>Parses a macro string. Never throws; <paramref name="error"/> describes the first syntax error.</summary>
    public static bool TryParse(string? text, SpfMacroKind kind, [NotNullWhen(true)] out SpfMacroString? macro, [NotNullWhen(false)] out string? error)
    {
        macro = null;
        error = null;
        if (text is null)
        {
            error = "missing macro string";
            return false;
        }

        var segments = new List<Segment>();
        var literal = new StringBuilder();
        bool usesP = false;
        bool usesExpOnly = false;
        bool endsWithMacro = false;

        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c != '%')
            {
                bool ok = c is >= '\x21' and <= '\x7E' || (c == ' ' && kind == SpfMacroKind.Explanation);
                if (!ok)
                {
                    error = $"illegal character U+{(int)c:X4} in macro string";
                    return false;
                }

                literal.Append(c);
                endsWithMacro = false;
                continue;
            }

            if (++i >= text.Length)
            {
                error = "dangling % in macro string";
                return false;
            }

            char next = text[i];
            switch (next)
            {
                case '%':
                    literal.Append('%');
                    endsWithMacro = true;
                    break;
                case '_':
                    literal.Append(' ');
                    endsWithMacro = true;
                    break;
                case '-':
                    literal.Append("%20");
                    endsWithMacro = true;
                    break;
                case '{':
                    {
                        if (!TryParseMacro(text, ref i, kind, out Segment seg, out error))
                        {
                            return false;
                        }

                        if (literal.Length > 0)
                        {
                            segments.Add(Segment.ForLiteral(literal.ToString()));
                            literal.Clear();
                        }

                        segments.Add(seg);
                        char lower = char.ToLowerInvariant(seg.Letter);
                        usesP |= lower == 'p';
                        usesExpOnly |= lower is 'c' or 'r' or 't';
                        endsWithMacro = true;
                        break;
                    }

                default:
                    error = "invalid macro escape %" + next;
                    return false;
            }
        }

        if (literal.Length > 0)
        {
            segments.Add(Segment.ForLiteral(literal.ToString()));
        }

        if (kind == SpfMacroKind.DomainSpec)
        {
            if (text.Length == 0)
            {
                error = "empty domain-spec";
                return false;
            }

            if (!endsWithMacro && !EndsWithTopLabel(text))
            {
                error = "domain-spec does not end in a top label";
                return false;
            }
        }

        macro = new SpfMacroString(text, segments.ToArray(), usesP, usesExpOnly);
        return true;
    }

    /// <summary>Parses a <c>domain-spec</c>.</summary>
    public static bool TryParseDomainSpec(string? text, [NotNullWhen(true)] out SpfMacroString? macro, [NotNullWhen(false)] out string? error) =>
        TryParse(text, SpfMacroKind.DomainSpec, out macro, out error);

    /// <summary>
    /// Expands the macros. Returns false when the expansion would exceed <paramref name="maxLength"/> characters.
    /// </summary>
    public bool TryExpand(SpfMacroContext context, int maxLength, [NotNullWhen(true)] out string? result)
    {
        ArgumentNullException.ThrowIfNull(context);
        result = null;
        var sb = new StringBuilder();
        foreach (Segment seg in _segments)
        {
            if (seg.Letter == '\0')
            {
                sb.Append(seg.Literal);
            }
            else
            {
                string value = ExpandMacro(seg, context);
                if (char.IsAsciiLetterUpper(seg.Letter))
                {
                    value = UrlEscape(value);
                }

                sb.Append(value);
            }

            if (sb.Length > maxLength)
            {
                return false;
            }
        }

        result = sb.ToString();
        return true;
    }

    /// <summary>
    /// Expands a domain-spec into a domain name: expansion, removal of one trailing dot, truncation from the left to 253
    /// characters (RFC 7208 section 7.3) and a syntax check (non-empty labels of at most 63 printable ASCII characters).
    /// </summary>
    public bool TryExpandDomain(SpfMacroContext context, int maxLength, [NotNullWhen(true)] out string? domain)
    {
        domain = null;
        if (!TryExpand(context, maxLength, out string? expanded))
        {
            return false;
        }

        return SpfDomainName.TryNormalizeExpanded(expanded, out domain);
    }

    private static bool TryParseMacro(string text, ref int i, SpfMacroKind kind, out Segment segment, [NotNullWhen(false)] out string? error)
    {
        segment = default;
        error = null;
        int pos = i + 1; // after '{'
        if (pos >= text.Length)
        {
            error = "unterminated macro";
            return false;
        }

        char letter = text[pos++];
        if (LetterChars.IndexOf(char.ToLowerInvariant(letter), StringComparison.Ordinal) < 0)
        {
            error = "unknown macro letter " + letter;
            return false;
        }

        if (kind != SpfMacroKind.Explanation && char.ToLowerInvariant(letter) is 'c' or 'r' or 't')
        {
            error = $"macro %{{{letter}}} is only allowed in explanations";
            return false;
        }

        int digits = -1;
        int digitStart = pos;
        while (pos < text.Length && char.IsAsciiDigit(text[pos]))
        {
            pos++;
        }

        if (pos > digitStart)
        {
            ReadOnlySpan<char> d = text.AsSpan(digitStart, pos - digitStart);
            digits = d.Length > 4 ? 9999 : int.Parse(d, NumberStyles.None, CultureInfo.InvariantCulture);
            if (digits == 0)
            {
                error = "macro transformer digit count must not be zero";
                return false;
            }
        }

        bool reverse = false;
        if (pos < text.Length && (text[pos] == 'r' || text[pos] == 'R'))
        {
            reverse = true;
            pos++;
        }

        int delimStart = pos;
        while (pos < text.Length && DelimiterChars.Contains(text[pos]))
        {
            pos++;
        }

        string delimiters = pos > delimStart ? text[delimStart..pos] : ".";
        if (pos >= text.Length || text[pos] != '}')
        {
            error = "malformed macro";
            return false;
        }

        i = pos; // at '}'
        segment = new Segment(null, letter, digits, reverse, delimiters);
        return true;
    }

    private static bool EndsWithTopLabel(string text)
    {
        // domain-end = "." toplabel [ "." ]
        string t = text.EndsWith('.') ? text[..^1] : text;
        int dot = t.LastIndexOf('.');
        if (dot < 0)
        {
            return false;
        }

        ReadOnlySpan<char> label = t.AsSpan(dot + 1);
        if (label.Length == 0 || label[0] == '-' || label[^1] == '-')
        {
            return false;
        }

        bool allDigits = true;
        foreach (char c in label)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c == '-'))
            {
                return false;
            }

            if (!char.IsAsciiDigit(c))
            {
                allDigits = false;
            }
        }

        return !allDigits;
    }

    private static string ExpandMacro(Segment seg, SpfMacroContext ctx)
    {
        string raw = char.ToLowerInvariant(seg.Letter) switch
        {
            's' => ctx.Sender,
            'l' => ctx.LocalPart,
            'o' => ctx.SenderDomain,
            'd' => ctx.Domain,
            'i' => FormatIpForMacro(ctx.ClientIp),
            'p' => ctx.ValidatedDomain,
            'v' => ctx.ClientIp.AddressFamily == AddressFamily.InterNetwork ? "in-addr" : "ip6",
            'h' => ctx.HeloDomain,
            'c' => ctx.ClientIp.ToString(),
            'r' => ctx.ReceivingHostName,
            _ => ctx.Timestamp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), // 't'
        };

        if (seg.Digits < 0 && !seg.Reverse && seg.Delimiters == ".")
        {
            return raw;
        }

        string[] parts = raw.Split(seg.Delimiters.ToCharArray());
        if (seg.Reverse)
        {
            Array.Reverse(parts);
        }

        int take = seg.Digits >= 0 ? Math.Min(seg.Digits, parts.Length) : parts.Length;
        return string.Join('.', parts, parts.Length - take, take);
    }

    private static string FormatIpForMacro(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            return ip.ToString();
        }

        Span<byte> bytes = stackalloc byte[16];
        ip.TryWriteBytes(bytes, out _);
        var sb = new StringBuilder(63);
        for (int i = 0; i < 16; i++)
        {
            if (i > 0)
            {
                sb.Append('.');
            }

            sb.Append(HexLower(bytes[i] >> 4)).Append('.').Append(HexLower(bytes[i] & 0xF));
        }

        return sb.ToString();
    }

    private static char HexLower(int v) => (char)(v < 10 ? '0' + v : 'a' + v - 10);

    private static string UrlEscape(string value)
    {
        StringBuilder? sb = null;
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            bool unreserved = char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~';
            if (unreserved)
            {
                sb?.Append(c);
                continue;
            }

            sb ??= new StringBuilder(value.Length + 8).Append(value, 0, i);
            int len = char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]) ? 2 : 1;
            foreach (byte b in Encoding.UTF8.GetBytes(value.AsSpan(i, len).ToString()))
            {
                sb.Append('%').Append("0123456789ABCDEF"[b >> 4]).Append("0123456789ABCDEF"[b & 0xF]);
            }

            i += len - 1;
        }

        return sb?.ToString() ?? value;
    }

    private readonly record struct Segment(string? Literal, char Letter, int Digits, bool Reverse, string Delimiters)
    {
        public static Segment ForLiteral(string text) => new(text, '\0', -1, false, ".");
    }
}

/// <summary>Domain-name checks used by the SPF evaluator.</summary>
public static class SpfDomainName
{
    /// <summary>The maximum length of a domain name in presentation form.</summary>
    public const int MaxLength = 253;

    /// <summary>
    /// Normalises a macro-expanded domain: removes one trailing dot, drops leftmost labels until at most 253 characters
    /// remain, lower-cases, and requires non-empty labels of at most 63 printable ASCII characters.
    /// </summary>
    public static bool TryNormalizeExpanded(string expanded, [NotNullWhen(true)] out string? domain)
    {
        domain = null;
        string d = expanded;
        if (d.EndsWith('.'))
        {
            d = d[..^1];
        }

        while (d.Length > MaxLength)
        {
            int dot = d.IndexOf('.');
            if (dot < 0)
            {
                return false;
            }

            d = d[(dot + 1)..];
        }

        if (d.Length == 0)
        {
            return false;
        }

        int labelLen = 0;
        foreach (char c in d)
        {
            if (c == '.')
            {
                if (labelLen == 0)
                {
                    return false;
                }

                labelLen = 0;
                continue;
            }

            if (c is < '\x21' or > '\x7E' || ++labelLen > 63)
            {
                return false;
            }
        }

        if (labelLen == 0)
        {
            return false;
        }

        domain = d.ToLowerInvariant();
        return true;
    }

    /// <summary>
    /// Validates the domain an SPF check starts from (RFC 7208 section 4.3): a host name with non-empty labels of
    /// at most 63 characters whose last label is not purely numeric (so IP-address literals are rejected).
    /// </summary>
    public static bool TryNormalizeCheckDomain(string? domain, [NotNullWhen(true)] out string? normalized)
    {
        normalized = null;
        if (string.IsNullOrEmpty(domain))
        {
            return false;
        }

        string d = domain.EndsWith('.') ? domain[..^1] : domain;
        if (!Mta.Core.EmailAddress.IsValidHostName(d))
        {
            return false;
        }

        int dot = d.LastIndexOf('.');
        ReadOnlySpan<char> top = d.AsSpan(dot + 1);
        bool numeric = true;
        foreach (char c in top)
        {
            if (!char.IsAsciiDigit(c))
            {
                numeric = false;
                break;
            }
        }

        if (numeric)
        {
            return false;
        }

        normalized = d.ToLowerInvariant();
        return true;
    }
}
