using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Mta.Smtp.Server;

namespace Mta.Host.Tls;

/// <summary>Serves the dashboard/API HTTPS listener from the certificate store, the same way the SMTP listeners are served.</summary>
public static class HttpsCertificateSelection
{
    /// <summary>
    /// Serves HTTPS with the certificate <paramref name="certificates"/> picks for the client's SNI name at every handshake (so a renewed
    /// certificate is used by the next connection without a restart) and sends the intermediate certificates with it. A plain
    /// <c>ServerCertificateSelector</c> returns the bare leaf, and strict clients that cannot fetch intermediates fail the chain
    /// (ACME-issued leaves are signed by an intermediate that is not in any client's trust store).
    /// </summary>
    public static ListenOptions UseCertificateStore(this ListenOptions listen, IServerCertificateProvider certificates)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        return listen.UseHttps(new TlsHandshakeCallbackOptions
        {
            OnConnection = context =>
            {
                var chain = certificates.GetContext(context.ClientHelloInfo.ServerName)
                    ?? throw new AuthenticationException("No server certificate available.");
                return ValueTask.FromResult(new SslServerAuthenticationOptions
                {
                    ServerCertificateContext = chain,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11],
                    ClientCertificateRequired = false,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                });
            },
        });
    }
}
