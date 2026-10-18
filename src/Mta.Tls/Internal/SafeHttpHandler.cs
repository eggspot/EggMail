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

/// <summary>Classifies IP addresses as publicly routable (safe SSRF targets) or not, with the classification every other guard uses.</summary>
internal static class PublicAddressGuard
{
    public static bool IsPublic(IPAddress address) => Mta.Core.NetworkAddresses.IsPubliclyRoutable(address);
}
