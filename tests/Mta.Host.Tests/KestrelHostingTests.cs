using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Mta.Host.Hosting;

namespace Mta.Host.Tests;

public class KestrelHostingTests
{
    [Fact]
    public void Https_is_pinned_to_TLS_1_2_and_1_3()
    {
        var options = new HttpsConnectionAdapterOptions();
        Assert.Equal(SslProtocols.None, options.SslProtocols);   // the framework default would be whatever the operating system still allows

        KestrelHosting.ConfigureHttps(options, _ => null);

        Assert.Equal(SslProtocols.Tls12 | SslProtocols.Tls13, options.SslProtocols);
        Assert.NotNull(options.ServerCertificateSelector);
    }

    [Fact]
    public async Task The_configured_listener_serves_the_selected_certificate_over_TLS_1_2_and_TLS_1_3()
    {
        using X509Certificate2 certificate = SelfSigned("localhost");
        string? requestedName = null;
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0, l => l.UseHttps(https => KestrelHosting.ConfigureHttps(https, name =>
        {
            requestedName = name;
            return certificate;
        }))));
        await using WebApplication app = builder.Build();
        app.MapGet("/ping", () => "pong");
        await app.StartAsync();
        try
        {
            string address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single().Replace("127.0.0.1", "localhost", StringComparison.Ordinal);   // a host name, so the client sends SNI
            // The .NET TLS client has no TLS 1.3 on macOS (SecureTransport); the server side is what is under test.
            foreach (SslProtocols protocol in OperatingSystem.IsMacOS() ? new[] { SslProtocols.Tls12 } : new[] { SslProtocols.Tls12, SslProtocols.Tls13 })
            {
                using var handler = new SocketsHttpHandler
                {
                    SslOptions = { EnabledSslProtocols = protocol, RemoteCertificateValidationCallback = (_, _, _, _) => true },
                };
                using var http = new HttpClient(handler);
                Assert.Equal("pong", await http.GetStringAsync(address + "/ping"));
            }

            Assert.Equal("localhost", requestedName);
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
