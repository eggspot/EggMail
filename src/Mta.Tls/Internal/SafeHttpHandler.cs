using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;

namespace Mta.Tls;

/// <summary>Creates the default <see cref="HttpMessageHandler"/> for requests whose target is attacker-influenced.</summary>
internal static class SafeHttpHandler
{
    /// <summary>
    /// A handler with no redirects, no cookies, no proxy, no automatic decompression, TLS 1.2+ and strict certificate
    /// validation (the platform default). Unless <paramref name="allowNonPublicAddresses"/> is set, connections to
    /// loopback, private, link-local and other non-public addresses are refused after DNS resolution.
    /// </summary>
    public static SocketsHttpHandler Create(TimeSpan connectTimeout, bool allowNonPublicAddresses)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            AutomaticDecompression = DecompressionMethods.None,
            MaxResponseHeadersLength = 16,
            ConnectTimeout = connectTimeout,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30),
            SslOptions = { EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13 },
        };

        if (!allowNonPublicAddresses)
        {
            handler.ConnectCallback = ConnectToPublicAddressAsync;
        }

        return handler;
    }

    private static async ValueTask<Stream> ConnectToPublicAddressAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        IPAddress[] addresses = await System.Net.Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);
        Exception? last = null;
        foreach (IPAddress address in addresses)
        {
            if (!PublicAddressGuard.IsPublic(address))
            {
                last = new HttpRequestException("Refusing to connect to a non-public address.");
                continue;
            }

            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), cancellationToken).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception ex)
            {
                socket.Dispose();
                last = ex;
            }
        }

        throw new HttpRequestException("No usable public address for the host.", last);
    }
}

/// <summary>Classifies IP addresses as publicly routable (safe SSRF targets) or not.</summary>
internal static class PublicAddressGuard
{
    public static bool IsPublic(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
        {
            return false;
        }

        Span<byte> b = stackalloc byte[16];
        if (!address.TryWriteBytes(b, out int written))
        {
            return false;
        }

        if (written == 4)
        {
            return !(b[0] == 0
                || b[0] == 10
                || (b[0] == 100 && b[1] is >= 64 and <= 127)
                || b[0] == 127
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 172 && b[1] is >= 16 and <= 31)
                || (b[0] == 192 && b[1] == 0 && b[2] == 0)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 198 && b[1] is 18 or 19)
                || b[0] >= 224);
        }

        if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast || address.IsIPv6UniqueLocal)
        {
            return false;
        }

        // Addresses that embed an IPv4 address inherit that address's classification: IPv4-compatible (::a.b.c.d),
        // NAT64 (64:ff9b::/96) and 6to4 (2002::/16).
        bool zeroPrefix = true;
        for (int i = 0; i < 12; i++)
        {
            zeroPrefix &= b[i] == 0;
        }

        if (zeroPrefix)
        {
            return IsPublic(new IPAddress(b.Slice(12, 4)));
        }

        if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && b[4..12].IndexOfAnyExcept((byte)0) < 0)
        {
            return IsPublic(new IPAddress(b.Slice(12, 4)));
        }

        if (b[0] == 0x20 && b[1] == 0x02)
        {
            return IsPublic(new IPAddress(b.Slice(2, 4)));
        }

        // The 2001:db8::/32 documentation range is not a valid delivery target either.
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)
        {
            return false;
        }

        return true;
    }
}
