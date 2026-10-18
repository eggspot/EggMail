using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;

namespace Mta.Core;

/// <summary>
/// An RFC 5321 mailbox (local-part@domain). The domain is stored lower-cased in A-label (ASCII) form when it is
/// a host name; address literals ("[192.0.2.1]") are kept verbatim. The local part is preserved as written.
/// </summary>
public readonly record struct EmailAddress
{
    public string LocalPart { get; }

    /// <summary>Domain in lower-case A-label form, or an address literal including brackets.</summary>
    public string Domain { get; }

    /// <summary>True when any part was non-ASCII (SMTPUTF8 required to transmit it unchanged).</summary>
    public bool IsInternational { get; }

    /// <summary>
    /// True when the address cannot be written to the wire in ASCII, i.e. its local part has non-ASCII characters: a transaction that
    /// names it needs the SMTPUTF8 extension (RFC 6531). Narrower than <see cref="IsInternational"/>: the domain is always held in
    /// A-label form, so an internationalized domain with an ASCII local part travels as plain ASCII.
    /// </summary>
    public bool RequiresSmtpUtf8 => LocalPart is not null && !System.Text.Ascii.IsValid(LocalPart);

    public bool IsAddressLiteral => Domain.Length > 0 && Domain[0] == '[';

    /// <summary>The null reverse-path (<c>&lt;&gt;</c>) used by bounces.</summary>
    public static EmailAddress Null => default;

    public bool IsNull => LocalPart is null || (LocalPart.Length == 0 && Domain is null or { Length: 0 });

    private EmailAddress(string localPart, string domain, bool international)
    {
        LocalPart = localPart;
        Domain = domain;
        IsInternational = international;
    }

    public const int MaxLocalPartLength = 64;
    public const int MaxDomainLength = 255;
    public const int MaxPathLength = 256;

    /// <summary>Parses a mailbox such as <c>user@example.com</c> (no angle brackets).</summary>
    public static bool TryParse(ReadOnlySpan<char> mailbox, bool allowUtf8, out EmailAddress address)
    {
        address = default;
        if (!TryParseParts(mailbox, allowUtf8, out ReadOnlySpan<char> local, out string? domain, out bool international))
        {
            return false;
        }

        address = new EmailAddress(local.ToString(), domain, international);
        return true;
    }

    /// <summary>
    /// Parses <paramref name="mailbox"/> exactly like <see cref="TryParse(ReadOnlySpan{char}, bool, out EmailAddress)"/> but returns only the normalized domain, so
    /// a caller that does not need the local part (the sender check on the <c>From</c> header) does not allocate a string for it.
    /// </summary>
    public static bool TryParseDomain(ReadOnlySpan<char> mailbox, bool allowUtf8, [NotNullWhen(true)] out string? domain) =>
        TryParseParts(mailbox, allowUtf8, out _, out domain, out _);

    /// <summary>
    /// Parses with a small memo of recent results: the same text, for example the sender of every message of a connection, gives back
    /// the address parsed before instead of new strings. The result is identical to <see cref="TryParse(ReadOnlySpan{char}, bool, out EmailAddress)"/>.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<char> mailbox, bool allowUtf8, EmailAddressCache? cache, out EmailAddress address) =>
        cache is null ? TryParse(mailbox, allowUtf8, out address) : cache.TryParse(mailbox, allowUtf8, out address);

    private static bool TryParseParts(ReadOnlySpan<char> mailbox, bool allowUtf8, out ReadOnlySpan<char> local, [NotNullWhen(true)] out string? domain, out bool international)
    {
        local = default;
        domain = null;
        international = false;
        if (mailbox.Length == 0 || mailbox.Length > MaxPathLength)
        {
            return false;
        }

        int at = FindDomainSeparator(mailbox);
        if (at <= 0 || at == mailbox.Length - 1)
        {
            return false;
        }

        ReadOnlySpan<char> localPart = mailbox[..at];
        ReadOnlySpan<char> domainPart = mailbox[(at + 1)..];
        if (!IsValidLocalPart(localPart, allowUtf8, out bool intlLocal))
        {
            return false;
        }

        if (!TryNormalizeDomain(domainPart, allowUtf8, out domain, out bool intlDomain))
        {
            return false;
        }

        local = localPart;
        international = intlLocal || intlDomain;
        return true;
    }

    public static EmailAddress Parse(string mailbox, bool allowUtf8 = true) =>
        TryParse(mailbox, allowUtf8, out var a) ? a : throw new FormatException($"Invalid mailbox: {mailbox}");

    /// <summary>Index of the '@' that separates local part and domain (last '@' outside quotes).</summary>
    private static int FindDomainSeparator(ReadOnlySpan<char> s)
    {
        bool quoted = false;
        int last = -1;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (quoted)
            {
                if (c == '\\') { i++; }
                else if (c == '"') { quoted = false; }
            }
            else if (c == '"') { quoted = true; }
            else if (c == '@') { last = i; }
        }

        return quoted ? -1 : last;
    }

    private static bool IsAtext(char c, bool allowUtf8) =>
        char.IsAsciiLetterOrDigit(c)
        || "!#$%&'*+-/=?^_`{|}~".Contains(c)
        || (allowUtf8 && c > 0x7F && IsPermittedNonAscii(c));

    /// <summary>
    /// RFC 6531 allows any non-ASCII character in an internationalized local part. Characters that no real address contains and that only serve to
    /// forge text are refused: C1 controls, the Unicode line and paragraph separators (they end a line in logs and in some parsers) and the bidirectional
    /// overrides and isolates (they reorder what a person reads). Zero-width joiners stay: some scripts need them.
    /// </summary>
    private static bool IsPermittedNonAscii(char c) =>
        !char.IsControl(c)
        && c is not ('\u2028' or '\u2029')
        && !(c >= '\u202A' && c <= '\u202E')
        && !(c >= '\u2066' && c <= '\u2069');

    internal static bool IsValidLocalPart(ReadOnlySpan<char> local, bool allowUtf8, out bool international)
    {
        international = false;
        if (local.Length == 0)
        {
            return false;
        }

        // An unpaired surrogate is not text (UTF-8 cannot encode it, and it would be replaced differently by every consumer): never part of an address.
        for (int i = 0; i < local.Length; i++)
        {
            if (char.IsSurrogate(local[i]))
            {
                if (!char.IsHighSurrogate(local[i]) || i + 1 >= local.Length || !char.IsLowSurrogate(local[i + 1]))
                {
                    return false;
                }

                i++;
            }
        }

        // Octet length limit (64) applies to the UTF-8 encoding for SMTPUTF8 addresses.
        if (Encoding.UTF8.GetByteCount(local) > MaxLocalPartLength)
        {
            return false;
        }

        if (local[0] == '"')
        {
            if (local.Length < 2 || local[^1] != '"')
            {
                return false;
            }

            for (int i = 1; i < local.Length - 1; i++)
            {
                char c = local[i];
                if (c == '\\')
                {
                    if (++i >= local.Length - 1) { return false; }
                    c = local[i];
                    if (c < 32 && c != '\t' || c == 127) { return false; }
                }
                else if (c == '"' || c < 32 || c == 127)
                {
                    return false;
                }

                if (c > 0x7F)
                {
                    if (!allowUtf8 || !IsPermittedNonAscii(c)) { return false; }
                    international = true;
                }
            }

            return true;
        }

        // Dot-string: atext *("." atext)
        bool prevDot = true;
        foreach (char c in local)
        {
            if (c == '.')
            {
                if (prevDot) { return false; }
                prevDot = true;
                continue;
            }

            if (!IsAtext(c, allowUtf8)) { return false; }
            if (c > 0x7F) { international = true; }
            prevDot = false;
        }

        return !prevDot;
    }

    internal static bool TryNormalizeDomain(ReadOnlySpan<char> domain, bool allowUtf8, [NotNullWhen(true)] out string? normalized, out bool international)
    {
        normalized = null;
        international = false;
        if (domain.Length == 0 || domain.Length > MaxDomainLength)
        {
            return false;
        }

        if (domain[0] == '[')
        {
            if (domain[^1] != ']' || domain.Length < 4) { return false; }
            ReadOnlySpan<char> inner = domain[1..^1];
            if (inner.StartsWith("IPv6:", StringComparison.OrdinalIgnoreCase))
            {
                if (!System.Net.IPAddress.TryParse(inner[5..], out var v6) ||
                    v6.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6) { return false; }
            }
            else if (!System.Net.IPAddress.TryParse(inner, out var v4) ||
                     v4.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
                     inner.Count('.') != 3)
            {
                return false;
            }

            normalized = domain.ToString();
            return true;
        }

        bool nonAscii = false;
        foreach (char c in domain)
        {
            if (c > 0x7F) { nonAscii = true; break; }
        }

        if (!nonAscii)
        {
            // The usual case: an ASCII host name. Validated and looked up as characters; a name seen before is not allocated again.
            if (!IsValidHostName(domain)) { return false; }
            ReadOnlySpan<char> trimmed = domain.TrimEnd('.');
            if (trimmed.Length == 0) { return false; }
            normalized = DomainNames.Intern(trimmed);
            return true;
        }

        if (!allowUtf8) { return false; }
        international = true;
        string ascii;
        try
        {
            ascii = new IdnMapping { UseStd3AsciiRules = false, AllowUnassigned = false }.GetAscii(domain.ToString());
        }
        catch (ArgumentException)
        {
            return false;
        }

        if (!IsValidHostName(ascii)) { return false; }
        normalized = ascii.ToLowerInvariant().TrimEnd('.');
        return normalized.Length > 0;
    }

    /// <summary>Validates an ASCII host name (labels of letters, digits and hyphen; underscore tolerated in labels).</summary>
    public static bool IsValidHostName(ReadOnlySpan<char> name)
    {
        if (name.Length > 0 && name[^1] == '.') { name = name[..^1]; }
        if (name.Length == 0 || name.Length > 253) { return false; }
        int labelStart = 0;
        for (int i = 0; i <= name.Length; i++)
        {
            if (i == name.Length || name[i] == '.')
            {
                int len = i - labelStart;
                if (len == 0 || len > 63) { return false; }
                if (name[labelStart] == '-' || name[i - 1] == '-') { return false; }
                labelStart = i + 1;
            }
            else
            {
                char c = name[i];
                if (!(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_')) { return false; }
            }
        }

        return true;
    }

    public override string ToString() => IsNull ? string.Empty : string.Create(CultureInfo.InvariantCulture, $"{LocalPart}@{Domain}");

    /// <summary>The address as it appears in an SMTP path: <c>&lt;local@domain&gt;</c>, or <c>&lt;&gt;</c> for the null path.</summary>
    public string ToPath() => IsNull ? "<>" : $"<{ToString()}>";
}
