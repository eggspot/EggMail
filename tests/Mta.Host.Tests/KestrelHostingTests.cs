using System.Net.Http;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Smtp.Server;

namespace Mta.Host.Tests;

public class KestrelHostingTests
{
    private sealed class OneCertificate(X509Certificate2 certificate) : IServerCertificateProvider
    {
        public string? RequestedName { get; private set; }

        public X509Certificate2? GetCertificate(string? serverName)
        {
            RequestedName = serverName;
            return certificate;
        }
    }

    [Fact]
    public void The_request_limit_never_undercuts_what_the_api_allows_for_a_send()
    {
        Assert.Equal(64L * 1024 * 1024, KestrelHosting.RequestBodyLimit(new ApiSection()));
        Assert.Equal(100L * 1024 * 1024, KestrelHosting.RequestBodyLimit(new ApiSection { MaxSendBodyBytes = 100L * 1024 * 1024 }));
    }

    [Fact]
    public async Task The_configured_listeners_serve_the_store_certificate_over_TLS_1_2_and_TLS_1_3_and_apply_the_body_limit()
    {
        using X509Certificate2 certificate = SelfSigned("localhost");
        var provider = new OneCertificate(certificate);
        var config = new MtaConfig
        {
            Dashboard = new DashboardSection { BindAddress = "127.0.0.1", HttpPort = 0, HttpsPort = 0, HttpsEnabled = true },
            Api = new ApiSection { MaxSendBodyBytes = 100L * 1024 * 1024 },
        };
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k => KestrelHosting.Configure(k, config, provider));
        await using WebApplication app = builder.Build();
        app.MapGet("/ping", () => "pong");
        await app.StartAsync();
        try
        {
            string https = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single(a => a.StartsWith("https:", StringComparison.Ordinal))
                .Replace("127.0.0.1", "localhost", StringComparison.Ordinal);   // a host name, so the client sends SNI
            // The .NET TLS client has no TLS 1.3 on macOS (SecureTransport); the server side is what is under test.
            foreach (SslProtocols protocol in OperatingSystem.IsMacOS() ? new[] { SslProtocols.Tls12 } : new[] { SslProtocols.Tls12, SslProtocols.Tls13 })
            {
                using var handler = new SocketsHttpHandler { SslOptions = { EnabledSslProtocols = protocol, RemoteCertificateValidationCallback = (_, _, _, _) => true } };
                using var http = new HttpClient(handler);
                Assert.Equal("pong", await http.GetStringAsync(https + "/ping"));
            }

            Assert.Equal("localhost", provider.RequestedName);
            Assert.Equal(100L * 1024 * 1024, app.Services.GetRequiredService<IOptions<KestrelServerOptions>>().Value.Limits.MaxRequestBodySize);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    private static X509Certificate2 SelfSigned(string name)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        using X509Certificate2 created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pfx), null);
    }
}
