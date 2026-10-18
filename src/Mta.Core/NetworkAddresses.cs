using System.Net;
using System.Net.Sockets;

namespace Mta.Core;

/// <summary>
/// The one place that decides whether an IP address is on the public Internet. Every guard that keeps a server-side request away from internal
/// networks (webhook delivery, the MTA-STS and TLS-RPT fetchers, MX and relay host resolution) uses this classification, so the three of them
/// cannot drift apart.
/// <para>Addresses that embed an IPv4 address (IPv4-mapped <c>::ffff:a.b.c.d</c>, IPv4-compatible <c>::a.b.c.d</c>, IPv4-translated
/// <c>::ffff:0:a.b.c.d</c>, NAT64 <c>64:ff9b::/96</c>, 6to4 <c>2002::/16</c>) are classified by the embedded address; Teredo
/// (<c>2001::/32</c>) and the local-use NAT64 prefix (<c>64:ff9b:1::/48</c>) hide or translate an address and are never public.</para>
/// </summary>
public static class NetworkAddresses
{
    /// <summary>True when the address is none of: internal network (loopback, private, link-local including cloud metadata, CGNAT, unique-local, site-local), unspecified, multicast, reserved, or documentation/benchmarking space.</summary>
    public static bool IsPubliclyRoutable(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return Classify(address) == AddressClass.Public;
    }

    /// <summary>
    /// True for the addresses of internal networks: loopback, unspecified, private (RFC 1918), link-local (including 169.254.169.254, the cloud
    /// metadata address), carrier-grade NAT, IPv6 unique-local, site-local and link-local, and addresses that embed one of those. Documentation,
    /// benchmarking and multicast space is not "internal" (it is simply not a destination).
    /// </summary>
    public static bool IsInternalNetwork(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return Classify(address) == AddressClass.Internal;
    }

    /// <summary>
    /// True when a mail server must not connect to the address of a mail host that the recipient's domain names: everything that is not public
    /// (internal networks, multicast and reserved space, Teredo, benchmarking, the deprecated and translating IPv6 forms) except the documentation ranges
    /// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, 3fff::/20). Those are never routed on the Internet and nobody runs a network of their own in them
    /// by accident, so they are left alone: they are what documentation and tests use for "a public mail server", and a connection to them reaches nothing.
    /// </summary>
    public static bool IsForbiddenMailTarget(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        AddressClass c = Classify(address);
        return c is AddressClass.Internal or AddressClass.Reserved;
    }

    private enum AddressClass : byte
    {
        Public,
        Internal,
        Reserved,
        Documentation,
    }

    private static AddressClass Classify(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        Span<byte> b = stackalloc byte[16];
        if (!address.TryWriteBytes(b, out int written))
        {
            return AddressClass.Reserved;
        }

        return written == 4 ? ClassifyV4(b[..4]) : ClassifyV6(b);
    }

    private static AddressClass ClassifyV4(ReadOnlySpan<byte> b)
    {
        byte a = b[0], c = b[1];
        if (a == 0 || a == 10 || a == 127                          // this network, private, loopback
            || (a == 100 && c >= 64 && c <= 127)                   // 100.64/10 carrier-grade NAT
            || (a == 169 && c == 254)                              // link-local, cloud metadata 169.254.169.254
            || (a == 172 && c >= 16 && c <= 31)                    // private
            || (a == 192 && c == 168)                              // private
            || (a == 192 && c == 0 && b[2] == 0))                  // 192.0.0.0/24 IETF protocol assignments
        {
            return AddressClass.Internal;
        }

        if ((a == 192 && c == 0 && b[2] == 2)                      // documentation
            || (a == 198 && c == 51 && b[2] == 100)                // documentation
            || (a == 203 && c == 0 && b[2] == 113))                // documentation
        {
            return AddressClass.Documentation;
        }

        if ((a == 192 && c == 88 && b[2] == 99)                    // 6to4 relay anycast, deprecated
            || (a == 198 && (c == 18 || c == 19))                  // benchmarking
            || a >= 224)                                           // multicast, reserved, broadcast
        {
            return AddressClass.Reserved;
        }

        return AddressClass.Public;
    }

    private static AddressClass ClassifyV6(ReadOnlySpan<byte> b)
    {
        bool zeroHigh96 = true;
        for (int i = 0; i < 12; i++)
        {
            if (b[i] != 0) { zeroHigh96 = false; break; }
        }

        if (zeroHigh96)
        {
            // ::/96: the unspecified address, ::1, and the deprecated IPv4-compatible form ::a.b.c.d. None of them is a destination.
            AddressClass embedded = ClassifyV4(b.Slice(12, 4));
            return embedded == AddressClass.Internal ? AddressClass.Internal : AddressClass.Reserved;
        }

        if ((b[0] & 0xFE) == 0xFC) { return AddressClass.Internal; }                        // fc00::/7 unique local
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) { return AddressClass.Internal; }       // fe80::/10 link-local
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0xC0) { return AddressClass.Internal; }       // fec0::/10 site-local (deprecated, still routed inside some networks)
        if (b[0] == 0xFF) { return AddressClass.Reserved; }                                 // ff00::/8 multicast

        if (b[0] == 0x20 && b[1] == 0x01)
        {
            if (b[2] == 0x00 && b[3] == 0x00) { return AddressClass.Reserved; }             // 2001::/32 Teredo: a tunnel to an address the packet does not show
            if (b[2] == 0x0D && b[3] == 0xB8) { return AddressClass.Documentation; }         // 2001:db8::/32 documentation
        }

        if (b[0] == 0x3F && b[1] == 0xFF && (b[2] & 0xF0) == 0) { return AddressClass.Documentation; }    // 3fff::/20 documentation (RFC 9637)
        if (b[0] == 0x01 && b[1] == 0x00 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0) { return AddressClass.Reserved; } // 100::/64 discard-only

        if (b[0] == 0x20 && b[1] == 0x02)
        {
            return ClassifyV4(b.Slice(2, 4));                                     // 2002::/16 6to4 embeds the IPv4 address
        }

        if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B)
        {
            bool zeroMiddle = true;
            for (int i = 4; i < 12; i++)
            {
                if (b[i] != 0) { zeroMiddle = false; break; }
            }

            if (zeroMiddle)
            {
                return ClassifyV4(b.Slice(12, 4));                                // 64:ff9b::/96 NAT64
            }

            if (b[4] == 0x00 && b[5] == 0x01)
            {
                return AddressClass.Reserved;                                               // 64:ff9b:1::/48 local-use NAT64 (RFC 8215)
            }
        }

        if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 && b[8] == 0xFF && b[9] == 0xFF && b[10] == 0 && b[11] == 0)
        {
            return ClassifyV4(b.Slice(12, 4));                                    // ::ffff:0:a.b.c.d IPv4-translated (SIIT)
        }

        return AddressClass.Public;
    }
}
