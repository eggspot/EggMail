using System.Net;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Mta.Host.Configuration;
using Mta.Host.Tls;
using Mta.Smtp.Server;

namespace Mta.Host.Hosting;

/// <summary>The Kestrel listeners of the dashboard and API (design section 7.3).</summary>
public static class KestrelHosting
{
    /// <summary>The server limit on a request body: at least 64 MiB, and never below what the API itself allows for a sending endpoint.</summary>
    public static long RequestBodyLimit(ApiSection api) => Math.Max(64L * 1024 * 1024, Math.Max(api.MaxSendBodyBytes, api.MaxBodyBytes));

    /// <summary>
    /// Plain HTTP for probes and, when enabled, HTTPS served from the certificate store (<see cref="HttpsCertificateSelection.UseCertificateStore"/>, which
    /// also fixes the protocol floor at TLS 1.2 with 1.3 on).
    /// </summary>
    public static void Configure(KestrelServerOptions kestrel, MtaConfig config, IServerCertificateProvider certificates)
    {
        var bind = IPAddress.Parse(config.Dashboard.BindAddress);
        kestrel.Listen(bind, config.Dashboard.HttpPort);
        if (config.Dashboard.HttpsEnabled)
        {
            kestrel.Listen(bind, config.Dashboard.HttpsPort, l => l.UseCertificateStore(certificates));
        }

        kestrel.Limits.MaxRequestBodySize = RequestBodyLimit(config.Api);
    }
}
