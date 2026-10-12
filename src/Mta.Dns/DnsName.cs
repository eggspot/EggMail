using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Mta.Dns;

/// <summary>
/// Domain-name helpers. The canonical form used everywhere in this library is lower-case ASCII (A-labels for
/// internationalized names) without a trailing dot; the root name is the empty string.
/// </summary>
public static class DnsName
{
    private const string HexDigits = "0123456789abcdef";

    // UseStd3AsciiRules stays off on purpose: '_' is required by _dmarc, _domainkey, _mta-sts, _25._tcp and so on.
    private static readonly IdnMapping Idn = new() { AllowUnassigned = false, UseStd3AsciiRules = false };

    /// <summary>
    /// Normalizes <paramref name="name"/>: IDNA (UTS #46 via <see cref="IdnMapping"/>) for non-ASCII input, ASCII
    /// lower-casing, one trailing dot removed. Fails (false) for empty labels, labels over 63 bytes, names over 253
    /// characters, and bytes outside printable ASCII (space, controls, backslash). The root ("" or ".") is valid.
    /// </summary>
    public static bool TryNormalize(string? name, [NotNullWhen(true)] out string? normalized)
    {
        normalized = null;
        if (name is null)
        {
            return false;
        }

        if (name.Length > 4 * 1024)
        {
            return false;
        }

        string work = name;
        if (!IsAscii(work))
        {
            if (work.Length > 0 && work[^1] == '.')
            {
                work = work[..^1];
            }

            try
            {
                work = Idn.GetAscii(work);
            }
            catch (ArgumentException)
            {
                return false;
            }
        }

        if (work.Length > 0 && work[^1] == '.')
        {
            work = work[..^1];
        }

        if (work.Length > DnsWire.MaxNamePresentationLength)
        {
            return false;
        }

        bool changed = !ReferenceEquals(work, name);
        int labelStart = 0;
        for (int i = 0; i <= work.Length; i++)
        {
            if (i == work.Length || work[i] == '.')
            {
                int labelLength = i - labelStart;
                if (work.Length > 0 && (labelLength == 0 || labelLength > DnsWire.MaxLabelLength))
                {
                    return false;
                }

                labelStart = i + 1;
                continue;
            }

            char c = work[i];
            if (c is < '!' or > '~' or '\\')
            {
                return false;
            }

            if (c is >= 'A' and <= 'Z')
            {
                changed = true;
            }
        }

        normalized = changed ? work.ToLowerInvariant() : work;
        return true;
    }

    /// <summary>Like <see cref="TryNormalize"/> but throws <see cref="ArgumentException"/> for an invalid name.</summary>
    public static string Normalize(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return TryNormalize(name, out var n) ? n : throw new ArgumentException($"'{Truncate(name)}' is not a valid DNS name.", nameof(name));
    }

    public static bool IsValid(string? name) => TryNormalize(name, out _);

    /// <summary>True if <paramref name="name"/> equals <paramref name="ancestor"/> or lies below it (label boundary aware). False if either is invalid.</summary>
    public static bool IsSubdomainOf(string? name, string? ancestor)
    {
        if (!TryNormalize(name, out var n) || !TryNormalize(ancestor, out var a))
        {
            return false;
        }

        if (a.Length == 0 || string.Equals(n, a, StringComparison.Ordinal))
        {
            return true;
        }

        return n.Length > a.Length
            && n[n.Length - a.Length - 1] == '.'
            && n.EndsWith(a, StringComparison.Ordinal);
    }

    /// <summary>The parent name ("mail.example.com" gives "example.com"); null for the root or an invalid name.</summary>
    public static string? GetParent(string? name)
    {
        if (!TryNormalize(name, out var n) || n.Length == 0)
        {
            return null;
        }

        int dot = n.IndexOf('.');
        return dot < 0 ? string.Empty : n[(dot + 1)..];
    }

    /// <summary>
    /// The reverse-lookup (PTR) name: "4.3.2.1.in-addr.arpa" for IPv4, 32 reversed nibbles + ".ip6.arpa" for IPv6.
    /// IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are treated as the IPv4 address.
    /// </summary>
    public static string ReverseArpaName(IPAddress address) => ReverseName(address, address.AddressFamily == AddressFamily.InterNetworkV6 && !address.IsIPv4MappedToIPv6 ? "ip6.arpa" : "in-addr.arpa");

    /// <summary>
    /// The reversed-address name below <paramref name="zone"/>, the form used by DNS blocklists
    /// (<c>ReverseName(1.2.3.4, "zen.example.org")</c> is "4.3.2.1.zen.example.org").
    /// </summary>
    public static string ReverseName(IPAddress address, string zone)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(zone);
        zone = Normalize(zone);

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            Span<byte> b = stackalloc byte[4];
            address.TryWriteBytes(b, out _);
            string head = $"{b[3]}.{b[2]}.{b[1]}.{b[0]}";
            return zone.Length == 0 ? head : $"{head}.{zone}";
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            throw new ArgumentException("Only IPv4 and IPv6 addresses can be reversed.", nameof(address));
        }

        Span<byte> bytes = stackalloc byte[16];
        address.TryWriteBytes(bytes, out _);
        int zoneExtra = zone.Length == 0 ? 0 : zone.Length + 1;
        int length = 32 * 2 - 1 + zoneExtra;
        return string.Create(length, (bytes.ToArray(), zone), static (dest, state) =>
        {
            var (raw, z) = state;
            int pos = 0;
            for (int i = 15; i >= 0; i--)
            {
                dest[pos++] = HexDigits[raw[i] & 0xF];
                dest[pos++] = '.';
                dest[pos++] = HexDigits[raw[i] >> 4];
                if (pos < dest.Length)
                {
                    dest[pos++] = '.';
                }
            }

            if (z.Length > 0)
            {
                z.AsSpan().CopyTo(dest[pos..]);
            }
        });
    }

    /// <summary>The DANE TLSA owner name: "_25._tcp.mail.example.com" (RFC 6698 §3).</summary>
    public static string TlsaName(string host, int port, string protocol = "tcp")
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, ushort.MaxValue);
        string h = Normalize(host);
        return $"_{port.ToString(CultureInfo.InvariantCulture)}._{protocol.ToLowerInvariant()}.{h}";
    }

    private static bool IsAscii(string s)
    {
        foreach (char c in s)
        {
            if (c > '\u007f')
            {
                return false;
            }
        }

        return true;
    }

    private static string Truncate(string s) => s.Length <= 64 ? s : s[..64] + "...";
}
