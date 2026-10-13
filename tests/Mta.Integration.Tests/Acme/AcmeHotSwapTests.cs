using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Mta.Dns;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Tls;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.Sqlite;

namespace Mta.Integration.Tests.Acme;

/// <summary>What a TLS client saw when it connected: the served leaf, whether the served chain leads to the CA root, and whether the name matched.</summary>
internal sealed record TlsObservation(string Thumbprint, bool ChainsToRoot, bool NameMatches);

/// <summary>
/// ACME on a real runtime: the renewal loop and the database poller run as the host runs them, the SMTP STARTTLS listener and an HTTPS listener
/// (as <c>mta</c> configures Kestrel) serve whatever is in the store, and a client verifies the served chain against the CA's root.
/// First run serves the self-signed certificate; once the order completes the poller swaps in the ACME certificate without a restart;
/// a renewal replaces it again.
/// </summary>
public sealed class AcmeHotSwapTests : IAsyncLifetime
{
    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-acme-swap-").FullName;
    private readonly string _host = AcmeTestNames.Unique();
    private readonly AdvanceableClock _clock = new(DateTimeOffset.UtcNow);
    private readonly RecordingLog _log = new();
    private readonly CancellationTokenSource _stop = new();
    private readonly ChallengeServerDns _dns = new();
    private EggMailRuntime _runtime = null!;
    private WebApplication? _https;
    private int _smtpPort;
    private int _httpsPort;
    private X509Certificate2Collection _roots = null!;
    private Task _certificateLoop = Task.CompletedTask;
    private Task _renewalLoop = Task.CompletedTask;

    public async Task InitializeAsync()
    {
        if (Pebble.UnavailableReason is not null)
        {
            return;
        }

        var config = new MtaConfig
        {
            Hostname = _host,
            Storage = new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _dir, StatsFlushInterval = TimeSpan.Zero } },
            Tls = new TlsSection { PollInterval = TimeSpan.FromMilliseconds(50), ReportingEnabled = false },
            Acme = new AcmeSection
            {
                Enabled = true,
                DirectoryUrl = Pebble.Directory,
                Email = "ops@acme-test.example",
                Domains = [_host],
                PropagationDelay = TimeSpan.Zero,
                CheckInterval = TimeSpan.FromHours(1),
            },
            Smtp = new SmtpSection
            {
                Listeners = new Dictionary<string, ListenerSection>
                {
                    ["submission"] = new() { Port = 0, BindAddress = "127.0.0.1", Mode = ListenerMode.StartTls, AuthRequired = true },
                },
            },
        };
        var storage = SqliteStorage.Create(config.Storage, _clock);
        await storage.InitializeAsync(default);
        var transport = Pebble.CreateTransport();
        _runtime = await EggMailRuntime.CreateAsync(config, storage, _clock, _log, default, new StaticDnsResolver(), new CertesOrderRunner(transport), _dns);
        _roots = await Pebble.FetchRootsAsync();

        _runtime.SmtpServer.Start();
        _smtpPort = _runtime.SmtpServer.LocalEndPoints["submission"].Port;

        // The dashboard/API HTTPS listener, configured through the same call Cli.cs uses.
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0, l => l.UseCertificateStore(_runtime.Certificates)));
        _https = builder.Build();
        _https.MapGet("/", () => "dashboard");
        await _https.StartAsync();
        _httpsPort = new Uri(_https.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First()).Port;
    }

    public async Task DisposeAsync()
    {
        await _stop.CancelAsync();
        try { await Task.WhenAll(_certificateLoop, _renewalLoop).WaitAsync(TimeSpan.FromSeconds(30)); } catch (OperationCanceledException) { }
        if (_https is not null)
        {
            await _https.DisposeAsync();
        }

        if (Pebble.UnavailableReason is null)
        {
            await _runtime.SmtpServer.StopAsync(TimeSpan.FromSeconds(2));
            await _runtime.DisposeAsync();
            await _runtime.Storage.DisposeAsync();
        }

        _dns.Dispose();
        Directory.Delete(_dir, recursive: true);
    }

    [PebbleFact]
    public async Task The_issued_certificate_is_swapped_into_the_smtp_and_https_listeners_and_a_renewal_replaces_it()
    {
        // 1. Before ACME has done anything the first-run self-signed certificate is served, and it does not chain to the CA.
        Assert.True(_runtime.Certificates.UsingSelfSignedOnly);
        TlsObservation selfSigned = await ProbeSmtpAsync();
        Assert.False(selfSigned.ChainsToRoot);
        string selfSignedThumbprint = selfSigned.Thumbprint;

        // 2. Start the loops the host runs (CertificateService): the renewal service orders at once, the poller notices the new row.
        _certificateLoop = Task.Run(() => _runtime.Certificates.RunAsync(_stop.Token));
        _renewalLoop = Task.Run(() => _runtime.Acme!.RunAsync(_stop.Token));
        var row = await WaitForCertificateAsync(c => c.Source == "acme");
        await WaitUntilServedAsync(row.Thumbprint);

        // 3. Both listeners now present the ACME certificate with a chain a client can verify (so the intermediate is sent too).
        foreach (TlsObservation seen in new[] { await ProbeSmtpAsync(), await ProbeHttpsAsync() })
        {
            Assert.Equal(row.Thumbprint, seen.Thumbprint);
            Assert.NotEqual(selfSignedThumbprint, seen.Thumbprint);
            Assert.True(seen.ChainsToRoot, "the served chain does not lead to the CA root (intermediate not sent?)");
            Assert.True(seen.NameMatches);
        }

        Assert.False(_runtime.Certificates.UsingSelfSignedOnly);
        Assert.Equal("acme", _runtime.Certificates.Describe().First(c => c.Subjects.Contains(_host)).Source);

        // 4. A renewal (here the dashboard's "request a certificate" for the configured names, so the clock the provider uses for expiry stays
        //    honest: Pebble picks a 90 or a 6 day profile at random, and a jump in time would make the short one look expired) orders a new
        //    certificate that replaces the row, and the listeners follow without a restart.
        Assert.True(await _runtime.Acme!.RequestAsync([_host], default).WaitAsync(TimeSpan.FromMinutes(2)), string.Join('\n', _log.Lines));
        var renewed = Assert.Single(await _runtime.Storage.Config.GetCertificatesAsync(default), c => c.Source == "acme");
        Assert.Equal(row.Id, renewed.Id);
        Assert.NotEqual(row.Thumbprint, renewed.Thumbprint);
        await WaitUntilServedAsync(renewed.Thumbprint);

        foreach (TlsObservation seen in new[] { await ProbeSmtpAsync(), await ProbeHttpsAsync() })
        {
            Assert.Equal(renewed.Thumbprint, seen.Thumbprint);
            Assert.True(seen.ChainsToRoot);
        }
    }

    [PebbleFact]
    public async Task A_failed_renewal_keeps_serving_the_current_certificate()
    {
        _certificateLoop = Task.Run(() => _runtime.Certificates.RunAsync(_stop.Token));
        _renewalLoop = Task.Run(() => _runtime.Acme!.RunAsync(_stop.Token));
        var row = await WaitForCertificateAsync(c => c.Source == "acme");
        await WaitUntilServedAsync(row.Thumbprint);

        // The CA is fine but the DNS provider is not: the renewal order fails, is recorded, and nothing changes for the listeners.
        _clock.Advance((row.NotAfter - row.NotBefore) * 0.7);
        var failing = new SilentDns();
        var service = new AcmeRenewalService(_runtime.Storage.Config, _runtime.Secrets, new CertesOrderRunner(Pebble.CreateTransport()), failing,
            _runtime.Config.Acme, _clock, _log);
        Assert.False(await service.CheckOnceAsync(default).WaitAsync(TimeSpan.FromMinutes(2)));

        var renewal = Assert.Single(await _runtime.Storage.Config.GetAcmeRenewalsAsync(default));
        Assert.Equal("failed", renewal.Status);
        Assert.Equal(row.Thumbprint, Assert.Single(await _runtime.Storage.Config.GetCertificatesAsync(default), c => c.Source == "acme").Thumbprint);
        await _runtime.Certificates.ReloadAsync(force: true, default);
        Assert.Equal(row.Thumbprint, (await ProbeSmtpAsync()).Thumbprint);
        Assert.Equal(row.Thumbprint, (await ProbeHttpsAsync()).Thumbprint);
    }

    // ---------------------------------------------------------------------------------------------------------------------------------

    private async Task<CertificateRecord> WaitForCertificateAsync(Func<CertificateRecord, bool> predicate)
    {
        var deadline = DateTime.UtcNow.AddMinutes(2);
        while (DateTime.UtcNow < deadline)
        {
            var match = (await _runtime.Storage.Config.GetCertificatesAsync(default)).FirstOrDefault(predicate);
            if (match is not null)
            {
                return match;
            }

            await Task.Delay(25);
        }

        throw new TimeoutException("no matching certificate was stored:\n" + string.Join('\n', _log.Lines));
    }

    /// <summary>Waits until the provider (which polls the store) serves the certificate; polling has a generous deadline, it asserts nothing about time.</summary>
    private async Task WaitUntilServedAsync(string thumbprint)
    {
        var deadline = DateTime.UtcNow.AddMinutes(1);
        while (DateTime.UtcNow < deadline)
        {
            if (_runtime.Certificates.GetCertificate(_host)?.Thumbprint == thumbprint)
            {
                return;
            }

            await Task.Delay(25);
        }

        throw new TimeoutException($"the provider never served {thumbprint}");
    }

    private async Task<TlsObservation> ProbeSmtpAsync()
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, _smtpPort);
        var stream = tcp.GetStream();
        Assert.StartsWith("220", await ReadReplyAsync(stream));
        await WriteAsync(stream, "EHLO probe.example\r\n");
        string ehlo = await ReadReplyAsync(stream);
        Assert.Contains("STARTTLS", ehlo);
        await WriteAsync(stream, "STARTTLS\r\n");
        Assert.StartsWith("220", await ReadReplyAsync(stream));

        TlsObservation? seen = null;
        using var ssl = new SslStream(stream, false, (_, certificate, chain, errors) =>
        {
            seen = Observe(certificate, chain, errors);
            return true;
        });
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = _host });
        return seen!;
    }

    private async Task<TlsObservation> ProbeHttpsAsync()
    {
        TlsObservation? seen = null;
        var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (_, ct) =>
            {
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                await socket.ConnectAsync(IPAddress.Loopback, _httpsPort, ct);
                return new NetworkStream(socket, ownsSocket: true);
            },
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
                {
                    seen = Observe(certificate, chain, errors);
                    return true;
                },
            },
        };
        using var http = new HttpClient(handler);
        // HTTP/2 is negotiated through ALPN, which the handshake callback has to offer.
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://{_host}:{_httpsPort}/") { Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionOrLower };
        using var response = await http.SendAsync(request);
        Assert.Equal(HttpVersion.Version20, response.Version);
        Assert.Equal("dashboard", await response.Content.ReadAsStringAsync());
        return seen!;
    }

    private TlsObservation Observe(X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors) =>
        new(new X509Certificate2(certificate!).Thumbprint,
            Pebble.ChainsTo(chain!, certificate!, _roots),
            (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0);

    private static async Task WriteAsync(Stream stream, string text) => await stream.WriteAsync(Encoding.ASCII.GetBytes(text));

    /// <summary>Reads one (possibly multi-line) SMTP reply byte by byte, so nothing past it is consumed before the TLS handshake.</summary>
    private static async Task<string> ReadReplyAsync(Stream stream)
    {
        var all = new StringBuilder();
        var line = new StringBuilder();
        var one = new byte[1];
        while (true)
        {
            if (await stream.ReadAsync(one) == 0)
            {
                throw new EndOfStreamException(all.ToString());
            }

            line.Append((char)one[0]);
            if (one[0] != '\n')
            {
                continue;
            }

            all.Append(line);
            bool last = line.Length >= 4 && line[3] == ' ';
            line.Clear();
            if (last)
            {
                return all.ToString();
            }
        }
    }
}
