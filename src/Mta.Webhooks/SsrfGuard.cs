using System.Net;
using System.Net.Sockets;
using Mta.Core;

namespace Mta.Webhooks;

/// <summary>
/// SSRF protection for webhook delivery (OWASP SSRF cheat sheet): resolve the host, reject addresses in internal ranges,
/// and connect only to a validated address (so a DNS rebinding answer cannot redirect the connection afterwards).
/// A per-tenant allowlist of networks can permit internal endpoints explicitly.
/// </summary>
public static class SsrfGuard
{
    /// <summary>True when connecting to <paramref name="address"/> is permitted without an allowlist entry (the one classification of <see cref="NetworkAddresses"/>).</summary>
    public static bool IsPubliclyRoutable(IPAddress address) => NetworkAddresses.IsPubliclyRoutable(address);

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
