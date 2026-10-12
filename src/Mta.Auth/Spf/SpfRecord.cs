using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Mta.Auth.Spf;

/// <summary>The kind of an SPF mechanism (RFC 7208 section 5).</summary>
public enum SpfMechanismKind
{
    /// <summary><c>all</c>: always matches.</summary>
    All,

    /// <summary><c>include:domain</c>: matches when the included policy passes.</summary>
    Include,

    /// <summary><c>a[:domain][/cidr]</c>: matches when the client is an address of the domain.</summary>
    A,

    /// <summary><c>mx[:domain][/cidr]</c>: matches when the client is an address of one of the domain's mail exchangers.</summary>
    Mx,

    /// <summary><c>ptr[:domain]</c>: matches when the client's validated reverse name is in the domain (discouraged).</summary>
    Ptr,

    /// <summary><c>ip4:network[/prefix]</c>.</summary>
    Ip4,

    /// <summary><c>ip6:network[/prefix]</c>.</summary>
    Ip6,

    /// <summary><c>exists:domain</c>: matches when the (macro-expanded) name has an A record.</summary>
    Exists,
}

/// <summary>One SPF mechanism with its parsed arguments.</summary>
public sealed class SpfMechanism
{
    internal SpfMechanism(SpfMechanismKind kind, string text, SpfMacroString? domain, IPAddress? network, int ip4Prefix, int ip6Prefix)
    {
        Kind = kind;
        Text = text;
        Domain = domain;
        Network = network;
        Ip4Prefix = ip4Prefix;
        Ip6Prefix = ip6Prefix;
    }

    /// <summary>The mechanism kind.</summary>
    public SpfMechanismKind Kind { get; }

    /// <summary>The mechanism as written, without its qualifier (for example <c>ip4:192.0.2.0/24</c>).</summary>
    public string Text { get; }

    /// <summary>The domain-spec argument; null when absent (a, mx, ptr then use the current domain).</summary>
    public SpfMacroString? Domain { get; }

    /// <summary>The network of an <c>ip4</c> or <c>ip6</c> mechanism.</summary>
    public IPAddress? Network { get; }

    /// <summary>The IPv4 prefix length: the <c>ip4</c> mask, or the first CIDR of <c>a</c>/<c>mx</c> (default 32).</summary>
    public int Ip4Prefix { get; }

    /// <summary>The IPv6 prefix length: the <c>ip6</c> mask, or the second CIDR of <c>a</c>/<c>mx</c> (default 128).</summary>
    public int Ip6Prefix { get; }
}

/// <summary>A qualifier plus a mechanism.</summary>
/// <param name="Qualifier">The qualifier (default <see cref="SpfQualifier.Pass"/>).</param>
/// <param name="Mechanism">The mechanism.</param>
public sealed record SpfDirective(SpfQualifier Qualifier, SpfMechanism Mechanism)
{
    /// <summary>The result produced when this directive matches.</summary>
    public SpfResult MatchResult => Qualifier switch
    {
        SpfQualifier.Fail => SpfResult.Fail,
        SpfQualifier.SoftFail => SpfResult.SoftFail,
        SpfQualifier.Neutral => SpfResult.Neutral,
        _ => SpfResult.Pass,
    };
}

/// <summary>A modifier that is not <c>redirect</c> or <c>exp</c>; evaluators ignore it.</summary>
/// <param name="Name">The modifier name (case preserved).</param>
/// <param name="Value">The raw value.</param>
public sealed record SpfUnknownModifier(string Name, string Value);

/// <summary>A parsed SPF record (RFC 7208 section 4.5 and 12).</summary>
public sealed class SpfRecord
{
    private SpfRecord(string text, IReadOnlyList<SpfDirective> directives, SpfMacroString? redirect, SpfMacroString? explanation, IReadOnlyList<SpfUnknownModifier> unknown)
    {
        Text = text;
        Directives = directives;
        Redirect = redirect;
        Explanation = explanation;
        UnknownModifiers = unknown;
    }

    /// <summary>The record text.</summary>
    public string Text { get; }

    /// <summary>The directives in evaluation order.</summary>
    public IReadOnlyList<SpfDirective> Directives { get; }

    /// <summary>The <c>redirect=</c> domain-spec, or null.</summary>
    public SpfMacroString? Redirect { get; }

    /// <summary>The <c>exp=</c> domain-spec, or null.</summary>
    public SpfMacroString? Explanation { get; }

    /// <summary>Modifiers other than redirect and exp.</summary>
    public IReadOnlyList<SpfUnknownModifier> UnknownModifiers { get; }

    /// <summary>True when the record has an <c>all</c> mechanism (which makes <c>redirect</c> ignored).</summary>
    public bool HasAllMechanism => Directives.Any(d => d.Mechanism.Kind == SpfMechanismKind.All);

    /// <summary>True when the TXT text is an SPF version 1 record (starts with <c>v=spf1</c> followed by a space or the end).</summary>
    public static bool IsSpfRecord([NotNullWhen(true)] string? text) =>
        text is not null
        && text.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)
        && (text.Length == 6 || text[6] == ' ');

    /// <summary>Parses an SPF record. Never throws; on a syntax error <paramref name="error"/> says why.</summary>
    /// <param name="text">The (concatenated) TXT record text.</param>
    /// <param name="maxLength">Records longer than this many characters are rejected.</param>
    /// <param name="record">The parsed record.</param>
    /// <param name="error">The reason for failure.</param>
    public static bool TryParse(string? text, int maxLength, [NotNullWhen(true)] out SpfRecord? record, [NotNullWhen(false)] out string? error)
    {
        record = null;
        error = null;
        if (!IsSpfRecord(text))
        {
            error = "not an SPF version 1 record";
            return false;
        }

        if (text.Length > maxLength)
        {
            error = "SPF record too long";
            return false;
        }

        var directives = new List<SpfDirective>();
        var unknown = new List<SpfUnknownModifier>();
        SpfMacroString? redirect = null;
        SpfMacroString? exp = null;

        foreach (string term in text[6..].Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!TryParseTerm(term, directives, unknown, ref redirect, ref exp, out error))
            {
                return false;
            }
        }

        record = new SpfRecord(text, directives, redirect, exp, unknown);
        return true;
    }

    private static bool TryParseTerm(
        string term,
        List<SpfDirective> directives,
        List<SpfUnknownModifier> unknown,
        ref SpfMacroString? redirect,
        ref SpfMacroString? exp,
        [NotNullWhen(false)] out string? error)
    {
        error = null;
        if (term[0] is '+' or '-' or '~' or '?')
        {
            return TryParseDirective(term, directives, out error);
        }

        // name *( ALPHA / DIGIT / "-" / "_" / "." ) followed by "=" is a modifier.
        int nameEnd = 0;
        if (char.IsAsciiLetter(term[0]))
        {
            nameEnd = 1;
            while (nameEnd < term.Length && (char.IsAsciiLetterOrDigit(term[nameEnd]) || term[nameEnd] is '-' or '_' or '.'))
            {
                nameEnd++;
            }
        }

        if (nameEnd > 0 && nameEnd < term.Length && term[nameEnd] == '=')
        {
            string name = term[..nameEnd];
            string value = term[(nameEnd + 1)..];
            if (name.Equals("redirect", StringComparison.OrdinalIgnoreCase))
            {
                if (redirect is not null)
                {
                    error = "duplicate redirect modifier";
                    return false;
                }

                if (!SpfMacroString.TryParseDomainSpec(value, out redirect, out string? e))
                {
                    error = "redirect: " + e;
                    return false;
                }

                return true;
            }

            if (name.Equals("exp", StringComparison.OrdinalIgnoreCase))
            {
                if (exp is not null)
                {
                    error = "duplicate exp modifier";
                    return false;
                }

                if (!SpfMacroString.TryParseDomainSpec(value, out exp, out string? e))
                {
                    error = "exp: " + e;
                    return false;
                }

                return true;
            }

            if (!SpfMacroString.TryParse(value, SpfMacroKind.ModifierValue, out _, out string? err))
            {
                error = $"modifier {name}: {err}";
                return false;
            }

            unknown.Add(new SpfUnknownModifier(name, value));
            return true;
        }

        return TryParseDirective(term, directives, out error);
    }

    private static bool TryParseDirective(string term, List<SpfDirective> directives, [NotNullWhen(false)] out string? error)
    {
        error = null;
        var qualifier = SpfQualifier.Pass;
        string body = term;
        switch (term[0])
        {
            case '+': body = term[1..]; break;
            case '-': qualifier = SpfQualifier.Fail; body = term[1..]; break;
            case '~': qualifier = SpfQualifier.SoftFail; body = term[1..]; break;
            case '?': qualifier = SpfQualifier.Neutral; body = term[1..]; break;
        }

        int nameEnd = body.AsSpan().IndexOfAny(':', '/');
        if (nameEnd < 0)
        {
            nameEnd = body.Length;
        }

        string name = body[..nameEnd].ToLowerInvariant();
        string rest = body[nameEnd..]; // starts with ':' or '/' or is empty

        SpfMechanism? mechanism;
        switch (name)
        {
            case "all":
                if (rest.Length != 0)
                {
                    error = "'all' takes no arguments";
                    return false;
                }

                mechanism = new SpfMechanism(SpfMechanismKind.All, body, null, null, 32, 128);
                break;

            case "include":
            case "exists":
                {
                    if (rest.Length < 2 || rest[0] != ':')
                    {
                        error = name + " requires a domain-spec";
                        return false;
                    }

                    if (!SpfMacroString.TryParseDomainSpec(rest[1..], out SpfMacroString? spec, out string? e))
                    {
                        error = $"{name}: {e}";
                        return false;
                    }

                    mechanism = new SpfMechanism(name == "include" ? SpfMechanismKind.Include : SpfMechanismKind.Exists, body, spec, null, 32, 128);
                    break;
                }

            case "a":
            case "mx":
                {
                    if (!TryParseDomainAndDualCidr(rest, name, out SpfMacroString? spec, out int p4, out int p6, out error))
                    {
                        return false;
                    }

                    mechanism = new SpfMechanism(name == "a" ? SpfMechanismKind.A : SpfMechanismKind.Mx, body, spec, null, p4, p6);
                    break;
                }

            case "ptr":
                {
                    SpfMacroString? spec = null;
                    if (rest.Length > 0)
                    {
                        if (rest[0] != ':' || rest.Length < 2)
                        {
                            error = "ptr: malformed argument";
                            return false;
                        }

                        if (!SpfMacroString.TryParseDomainSpec(rest[1..], out spec, out string? e))
                        {
                            error = "ptr: " + e;
                            return false;
                        }
                    }

                    mechanism = new SpfMechanism(SpfMechanismKind.Ptr, body, spec, null, 32, 128);
                    break;
                }

            case "ip4":
                {
                    if (!TryParseNetwork(rest, AddressFamily.InterNetwork, out IPAddress? net, out int prefix, out error))
                    {
                        return false;
                    }

                    mechanism = new SpfMechanism(SpfMechanismKind.Ip4, body, null, net, prefix, 128);
                    break;
                }

            case "ip6":
                {
                    if (!TryParseNetwork(rest, AddressFamily.InterNetworkV6, out IPAddress? net, out int prefix, out error))
                    {
                        return false;
                    }

                    mechanism = new SpfMechanism(SpfMechanismKind.Ip6, body, null, net, 32, prefix);
                    break;
                }

            default:
                error = "unknown mechanism '" + (name.Length > 32 ? name[..32] : name) + "'";
                return false;
        }

        directives.Add(new SpfDirective(qualifier, mechanism));
        return true;
    }

    private static bool TryParseDomainAndDualCidr(
        string rest,
        string mechanismName,
        out SpfMacroString? spec,
        out int ip4Prefix,
        out int ip6Prefix,
        [NotNullWhen(false)] out string? error)
    {
        spec = null;
        ip4Prefix = 32;
        ip6Prefix = 128;
        error = null;
        if (rest.Length == 0)
        {
            return true;
        }

        string domainPart = string.Empty;
        string cidrPart = rest;
        if (rest[0] == ':')
        {
            int slash = FindCidrStart(rest);
            domainPart = slash < 0 ? rest[1..] : rest[1..slash];
            cidrPart = slash < 0 ? string.Empty : rest[slash..];
            if (domainPart.Length == 0)
            {
                error = mechanismName + ": empty domain-spec";
                return false;
            }

            if (!SpfMacroString.TryParseDomainSpec(domainPart, out spec, out string? e))
            {
                error = $"{mechanismName}: {e}";
                return false;
            }
        }

        if (cidrPart.Length == 0)
        {
            return true;
        }

        // dual-cidr-length = [ "/" ip4-cidr ] [ "//" ip6-cidr ]
        if (cidrPart[0] != '/')
        {
            error = mechanismName + ": malformed argument";
            return false;
        }

        string v6Part = string.Empty;
        string v4Part = string.Empty;
        int dbl = cidrPart.IndexOf("//", StringComparison.Ordinal);
        if (dbl == 0)
        {
            v6Part = cidrPart[2..];
        }
        else if (dbl > 0)
        {
            v4Part = cidrPart[1..dbl];
            v6Part = cidrPart[(dbl + 2)..];
        }
        else
        {
            v4Part = cidrPart[1..];
        }

        if ((dbl != 0 && !TryParsePrefix(v4Part, 32, out ip4Prefix)) || (dbl >= 0 && !TryParsePrefix(v6Part, 128, out ip6Prefix)))
        {
            error = mechanismName + ": invalid CIDR length";
            return false;
        }

        return true;
    }

    /// <summary>Index of the first '/' not inside a macro's braces, or -1.</summary>
    private static int FindCidrStart(string s)
    {
        int depth = 0;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '{')
            {
                depth++;
            }
            else if (c == '}' && depth > 0)
            {
                depth--;
            }
            else if (c == '/' && depth == 0)
            {
                return i;
            }
        }

        return -1;
    }

    private static bool TryParseNetwork(string rest, AddressFamily family, [NotNullWhen(true)] out IPAddress? network, out int prefix, [NotNullWhen(false)] out string? error)
    {
        network = null;
        prefix = family == AddressFamily.InterNetwork ? 32 : 128;
        error = null;
        string label = family == AddressFamily.InterNetwork ? "ip4" : "ip6";
        if (rest.Length < 2 || rest[0] != ':')
        {
            error = label + " requires a network";
            return false;
        }

        string body = rest[1..];
        int slash = body.IndexOf('/');
        string addr = slash < 0 ? body : body[..slash];
        if (slash >= 0 && !TryParsePrefix(body[(slash + 1)..], family == AddressFamily.InterNetwork ? 32 : 128, out prefix))
        {
            error = label + ": invalid CIDR length";
            return false;
        }

        if (!TryParseIp(addr, family, out network))
        {
            error = label + ": invalid address";
            return false;
        }

        return true;
    }

    /// <summary>Parses a CIDR length: digits without leading zeros, at most <paramref name="max"/>.</summary>
    internal static bool TryParsePrefix(string text, int max, out int prefix)
    {
        prefix = 0;
        if (text.Length is 0 or > 3 || (text.Length > 1 && text[0] == '0'))
        {
            return false;
        }

        foreach (char c in text)
        {
            if (!char.IsAsciiDigit(c))
            {
                return false;
            }
        }

        prefix = int.Parse(text, NumberStyles.None, CultureInfo.InvariantCulture);
        return prefix <= max;
    }

    internal static bool TryParseIp(string text, AddressFamily family, [NotNullWhen(true)] out IPAddress? address)
    {
        address = null;
        if (family == AddressFamily.InterNetwork)
        {
            // Strict dotted quad: four decimal numbers 0-255 without leading zeros.
            string[] parts = text.Split('.');
            if (parts.Length != 4)
            {
                return false;
            }

            Span<byte> bytes = stackalloc byte[4];
            for (int i = 0; i < 4; i++)
            {
                string p = parts[i];
                if (p.Length is 0 or > 3 || (p.Length > 1 && p[0] == '0'))
                {
                    return false;
                }

                foreach (char c in p)
                {
                    if (!char.IsAsciiDigit(c))
                    {
                        return false;
                    }
                }

                int v = int.Parse(p, NumberStyles.None, CultureInfo.InvariantCulture);
                if (v > 255)
                {
                    return false;
                }

                bytes[i] = (byte)v;
            }

            address = new IPAddress(bytes);
            return true;
        }

        if (text.Length is 0 or > 45 || !text.Contains(':'))
        {
            return false;
        }

        foreach (char c in text)
        {
            if (!(char.IsAsciiHexDigit(c) || c is ':' or '.'))
            {
                return false;
            }
        }

        if (IPAddress.TryParse(text, out IPAddress? parsed) && parsed.AddressFamily == AddressFamily.InterNetworkV6)
        {
            address = parsed;
            return true;
        }

        return false;
    }
}
