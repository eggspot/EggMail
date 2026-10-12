using System.Net;
using System.Net.Sockets;

namespace Mta.Webhooks;

/// <summary>
/// SSRF protection for webhook delivery (OWASP SSRF cheat sheet): resolve the host, reject addresses in internal ranges,
/// and connect only to a validated address (so a DNS rebinding answer cannot redirect the connection afterwards).
/// A per-tenant allowlist of networks can permit internal endpoints explicitly.
/// </summary>
public static class SsrfGuard
{
    /// <summary>True when connecting to <paramref name="address"/> is permitted without an allowlist entry.</summary>
    public static bool IsPubliclyRoutable(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            Span<byte> b = stackalloc byte[4];
            address.TryWriteBytes(b, out _);
            return !IsDeniedV4(b);
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            Span<byte> b = stackalloc byte[16];
            address.TryWriteBytes(b, out _);
            return !IsDeniedV6(b);
        }

        return false;
    }

    private static bool IsDeniedV4(ReadOnlySpan<byte> b)
    {
        byte a = b[0], c = b[1];
        return a == 0                                            // 0.0.0.0/8 "this network"
            || a == 10                                           // private
            || a == 127                                          // loopback
            || (a == 100 && c >= 64 && c <= 127)                 // 100.64/10 carrier-grade NAT
            || (a == 169 && c == 254)                            // link-local incl. cloud metadata 169.254.169.254
            || (a == 172 && c >= 16 && c <= 31)                  // private
            || (a == 192 && c == 168)                            // private
            || (a == 192 && c == 0 && b[2] == 0)                 // 192.0.0.0/24 IETF protocol assignments
            || (a == 192 && c == 0 && b[2] == 2)                 // documentation
            || (a == 198 && (c == 18 || c == 19))                // benchmarking
            || (a == 198 && c == 51 && b[2] == 100)              // documentation
            || (a == 203 && c == 0 && b[2] == 113)               // documentation
            || a >= 224;                                         // multicast, reserved, broadcast
    }

    private static bool IsDeniedV6(ReadOnlySpan<byte> b)
    {
        bool allZeroPrefix = true;
        for (int i = 0; i < 15; i++)
        {
            if (b[i] != 0) { allZeroPrefix = false; break; }
        }

        if (allZeroPrefix && (b[15] == 0 || b[15] == 1))
        {
            return true; // :: and ::1
        }

        if ((b[0] & 0xFE) == 0xFC) { return true; }              // fc00::/7 unique local
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) { return true; } // fe80::/10 link-local
        if (b[0] == 0xFF) { return true; }                       // ff00::/8 multicast
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) { return true; } // 2001:db8::/32 documentation
        if (b[0] == 0x20 && b[1] == 0x02) { return IsDeniedV4(b.Slice(2, 4)); }           // 6to4 embeds an IPv4 address
        if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B)                   // 64:ff9b::/96 NAT64 embeds IPv4
        {
            return IsDeniedV4(b.Slice(12, 4));
        }

        return false;
    }

    /// <summary>
    /// Resolves <paramref name="host"/> and returns the addresses that are allowed (public, or inside an allowlisted network).
    /// Returns an empty list if none is acceptable.
    /// </summary>
    public static async ValueTask<IReadOnlyList<IPAddress>> ResolveAllowedAsync(
        string host,
        Func<string, CancellationToken, ValueTask<IPAddress[]>> resolve,
        IReadOnlyList<IpNetwork> allowlist,
        CancellationToken ct)
    {
        IPAddress[] addresses;
        if (IPAddress.TryParse(host.Trim('[', ']'), out var literal))
        {
            addresses = [literal];
        }
        else
        {
            addresses = await resolve(host, ct).ConfigureAwait(false);
        }

        var ok = new List<IPAddress>(addresses.Length);
        foreach (var a in addresses)
        {
            if (IsPubliclyRoutable(a) || allowlist.Any(n => n.Contains(a)))
            {
                ok.Add(a);
            }
        }

        return ok;
    }
}

/// <summary>An IP network in CIDR form.</summary>
public readonly struct IpNetwork
{
    private readonly byte[] _prefix;
    private readonly int _bits;

    public IpNetwork(IPAddress address, int prefixLength)
    {
        if (address.IsIPv4MappedToIPv6) { address = address.MapToIPv4(); }
        _prefix = address.GetAddressBytes();
        if (prefixLength < 0 || prefixLength > _prefix.Length * 8)
        {
            throw new ArgumentOutOfRangeException(nameof(prefixLength));
        }

        _bits = prefixLength;
    }

    public static IpNetwork Parse(string cidr)
    {
        int slash = cidr.IndexOf('/');
        var ip = IPAddress.Parse(slash < 0 ? cidr : cidr[..slash]);
        int bits = slash < 0 ? (ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128) : int.Parse(cidr[(slash + 1)..], System.Globalization.CultureInfo.InvariantCulture);
        return new IpNetwork(ip, bits);
    }

    public override string ToString() => $"{new IPAddress(_prefix)}/{_bits}";

    public bool Contains(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) { address = address.MapToIPv4(); }
        byte[] b = address.GetAddressBytes();
        if (b.Length != _prefix.Length) { return false; }
        int full = _bits / 8;
        for (int i = 0; i < full; i++)
        {
            if (b[i] != _prefix[i]) { return false; }
        }

        int rem = _bits % 8;
        if (rem == 0) { return true; }
        int mask = 0xFF << (8 - rem) & 0xFF;
        return (b[full] & mask) == (_prefix[full] & mask);
    }
}
