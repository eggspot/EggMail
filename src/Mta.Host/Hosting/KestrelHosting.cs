using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Mta.Host.Configuration;

namespace Mta.Host.Hosting;

/// <summary>The Kestrel listeners of the dashboard and API (design section 7.3).</summary>
public static class KestrelHosting
{
    /// <summary>TLS 1.2 is the minimum and 1.3 is on (design 7.3); never "whatever the operating system still allows".</summary>
    public const SslProtocols HttpsProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;

    /// <summary>The server limit on a request body: at least 64 MiB, and never below what the API itself allows for a sending endpoint.</summary>
    public static long RequestBodyLimit(ApiSection api) => Math.Max(64L * 1024 * 1024, Math.Max(api.MaxSendBodyBytes, api.MaxBodyBytes));

    /// <summary>Applies the HTTPS settings: protocol floor and the certificate chosen by name from the certificate store.</summary>
    public static void ConfigureHttps(HttpsConnectionAdapterOptions https, Func<string?, X509Certificate2?> selectCertificate)
    {
        https.SslProtocols = HttpsProtocols;
        https.ServerCertificateSelector = (_, name) => selectCertificate(name);
    }

    public static void Configure(KestrelServerOptions kestrel, MtaConfig config, Func<string?, X509Certificate2?> selectCertificate)
    {
        var bind = IPAddress.Parse(config.Dashboard.BindAddress);
        kestrel.Listen(bind, config.Dashboard.HttpPort);
        if (config.Dashboard.HttpsEnabled)
        {
            kestrel.Listen(bind, config.Dashboard.HttpsPort, l => l.UseHttps(https => ConfigureHttps(https, selectCertificate)));
        }

        kestrel.Limits.MaxRequestBodySize = RequestBodyLimit(config.Api);
    }
}
