using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Mta.Core;
using Mta.Host.Tls;
using Xunit.Sdk;

namespace Mta.Integration.Tests.Acme;

/// <summary>
/// Where the Pebble test CA (github.com/letsencrypt/pebble) and its challenge test server are, from the environment. Unset means the ACME tests
/// are reported as skipped; CI starts both containers (see <c>.github/workflows/ci.yml</c> and docs/development.md).
/// </summary>
internal static class Pebble
{
    /// <summary>The ACME directory, for example <c>https://localhost:14000/dir</c>. Required.</summary>
    public const string DirectoryVariable = "EGGMAIL_TEST_ACME_DIRECTORY";

    /// <summary>The challenge test server's management API (<c>pebble-challtestsrv</c>), default <c>http://localhost:8055</c>.</summary>
    public const string ChallengeServerVariable = "EGGMAIL_TEST_ACME_CHALLTESTSRV";

    /// <summary>Pebble's management API (the issuing roots), default <c>https://&lt;directory host&gt;:15000</c>.</summary>
    public const string ManagementVariable = "EGGMAIL_TEST_ACME_MANAGEMENT";

    /// <summary>PEM file of the CA that signed Pebble's own HTTPS certificate (<c>test/certs/pebble.minica.pem</c> in the Pebble image). Default: system trust.</summary>
    public const string TlsCaFileVariable = "EGGMAIL_TEST_ACME_CA_FILE";

    public static string? UnavailableReason =>
        string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(DirectoryVariable))
            ? $"{DirectoryVariable} is not set: start Pebble and pebble-challtestsrv (docs/development.md, 'ACME tests') to run the ACME integration tests"
            : null;

    public static string Directory => Environment.GetEnvironmentVariable(DirectoryVariable)!;

    public static Uri ChallengeServer => new(Environment.GetEnvironmentVariable(ChallengeServerVariable) is { Length: > 0 } v ? v : "http://localhost:8055");

    public static Uri Management => new(Environment.GetEnvironmentVariable(ManagementVariable) is { Length: > 0 } v ? v : $"https://{new Uri(Directory).Host}:15000");

    /// <summary>A handler that trusts Pebble's HTTPS certificate (through the CA file when given) and nothing else special.</summary>
    public static SocketsHttpHandler CreateTransport()
    {
        var handler = new SocketsHttpHandler { ConnectTimeout = TimeSpan.FromSeconds(10) };
        if (Environment.GetEnvironmentVariable(TlsCaFileVariable) is { Length: > 0 } file)
        {
            var anchors = new X509Certificate2Collection();
            anchors.ImportFromPemFile(file);
            handler.SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, certificate, chain, _) => certificate is not null && chain is not null && ChainsTo(chain, certificate, anchors),
            };
        }

        return handler;
    }

    /// <summary>Does <paramref name="certificate"/> chain to one of <paramref name="anchors"/>, using the certificates the peer presented as intermediates?</summary>
    public static bool ChainsTo(X509Chain presented, X509Certificate certificate, X509Certificate2Collection anchors)
    {
        using var custom = new X509Chain();
        custom.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        custom.ChainPolicy.CustomTrustStore.AddRange(anchors);
        custom.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        foreach (var element in presented.ChainElements)
        {
            custom.ChainPolicy.ExtraStore.Add(element.Certificate);
        }

        return custom.Build(new X509Certificate2(certificate));
    }

    /// <summary>Pebble answers requests without a User-Agent with 400, like real ACME servers are allowed to.</summary>
    public static HttpClient NewClient(HttpMessageHandler handler)
    {
        var http = new HttpClient(handler, disposeHandler: false);
        http.DefaultRequestHeaders.UserAgent.ParseAdd("EggMail-tests/1.0");
        return http;
    }

    /// <summary>Overrides the renewal information Pebble answers for a certificate it issued (its management API). <paramref name="ariResponse"/> may be any text, even invalid JSON.</summary>
    public static async Task SetRenewalInfoAsync(string certificatePem, string ariResponse)
    {
        using var http = NewClient(CreateTransport());
        using var response = await http.PostAsJsonAsync(new Uri(Management, "/set-renewal-info/"), new { Certificate = certificatePem, ARIResponse = ariResponse });
        response.EnsureSuccessStatusCode();
    }

    /// <summary>A renewal information body for Pebble: the suggested window in RFC 3339.</summary>
    public static string Window(DateTimeOffset start, DateTimeOffset end) =>
        $"{{\"suggestedWindow\":{{\"start\":\"{start.UtcDateTime:yyyy-MM-dd'T'HH:mm:ss'Z'}\",\"end\":\"{end.UtcDateTime:yyyy-MM-dd'T'HH:mm:ss'Z'}\"}}}}";

    /// <summary>The certificate Pebble issues from (its current root; Pebble generates new ones at every start).</summary>
    public static async Task<X509Certificate2Collection> FetchRootsAsync()
    {
        using var http = NewClient(CreateTransport());
        var roots = new X509Certificate2Collection();
        roots.ImportFromPem(await http.GetStringAsync(new Uri(Management, "/roots/0")));
        return roots;
    }
}

/// <summary>A <c>[Fact]</c> that is reported as skipped when Pebble is not configured (and, optionally, when no PostgreSQL is available).</summary>
public sealed class PebbleFactAttribute : FactAttribute
{
    public bool RequiresPostgres { get; init; }

    public override string Skip
    {
        get => base.Skip ?? Pebble.UnavailableReason ?? (RequiresPostgres ? Mta.Storage.Postgres.Tests.PostgresTestServer.UnavailableReason : null)!;
        set => base.Skip = value;
    }
}

/// <summary>
/// DNS-01 challenge records in <c>pebble-challtestsrv</c>, the DNS server Pebble validates against. A deliberately independent
/// <see cref="IDnsChallengeProvider"/>: it is test code, so the production Cloudflare provider is not what is under test here.
/// Several values at one name are kept (the wildcard plus base-name order), as the interface requires.
/// </summary>
internal class ChallengeServerDns : IDnsChallengeProvider, IDisposable
{
    private readonly HttpClient _http = new() { BaseAddress = Pebble.ChallengeServer };

    public ConcurrentQueue<(string Fqdn, string Value)> Created { get; } = new();

    public ConcurrentQueue<string> Deleted { get; } = new();

    public virtual async ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken cancellationToken)
    {
        using var response = await _http.PostAsJsonAsync("/set-txt", new { host = Dotted(fqdn), value }, cancellationToken);
        response.EnsureSuccessStatusCode();
        Created.Enqueue((fqdn, value));
        return fqdn;
    }

    public virtual async ValueTask DeleteTxtAsync(string handle, CancellationToken cancellationToken)
    {
        // The server clears every value at the name, which is right here: records are removed after the whole order is done.
        using var response = await _http.PostAsJsonAsync("/clear-txt", new { host = Dotted(handle) }, cancellationToken);
        response.EnsureSuccessStatusCode();
        Deleted.Enqueue(handle);
    }

    private static string Dotted(string name) => name.EndsWith('.') ? name : name + ".";

    public void Dispose() => _http.Dispose();
}

/// <summary>A challenge provider that publishes nothing: validation must fail at the CA.</summary>
internal sealed class SilentDns : IDnsChallengeProvider
{
    public int Requests;

    public ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref Requests);
        return ValueTask.FromResult(fqdn);
    }

    public ValueTask DeleteTxtAsync(string handle, CancellationToken cancellationToken) => ValueTask.CompletedTask;
}

/// <summary>Records every request the ACME client makes (method, URL and, for POSTs, the decoded JWS payload) and passes it on.</summary>
internal sealed class RecordingHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
{
    private readonly ConcurrentQueue<(string Method, string Url, string Payload)> _requests = new();

    public IReadOnlyList<(string Method, string Url, string Payload)> Requests => [.. _requests];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string payload = "";
        if (request.Content is not null)
        {
            string body = await request.Content.ReadAsStringAsync(cancellationToken);
            try
            {
                using var jws = JsonDocument.Parse(body);
                payload = Encoding.UTF8.GetString(Base64UrlDecode(jws.RootElement.GetProperty("payload").GetString()!));
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or FormatException or InvalidOperationException)
            {
            }
        }

        if (payload.Contains("\"replaces\"", StringComparison.Ordinal))
        {
            // Pebble 2.10.1 (wfe/wfe.go, FinalizeOrder) records which order issued a certificate in a goroutine AFTER it has marked the order valid, so for
            // a moment the certificate can be downloaded and its renewal information fetched while a `replaces` order naming it is answered "could not find
            // an order for the given certificate" (serverInternal). On a loaded CI runner that moment was long enough to fail ARI tests in two runs of ten.
            // The product treats a server error as a server error (a test pins that), so the emulator gets a second to finish.
            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
        }

        var response = await base.SendAsync(request, cancellationToken);
        // A request the CA bounced with badNonce is repeated by the client with a fresh nonce; it is one request, not two.
        if (response.StatusCode == HttpStatusCode.BadRequest)
        {
            await response.Content.LoadIntoBufferAsync(cancellationToken);
            if ((await response.Content.ReadAsStringAsync(cancellationToken)).Contains(":badNonce", StringComparison.Ordinal))
            {
                return response;
            }
        }

        _requests.Enqueue((request.Method.Method, request.RequestUri!.ToString(), payload));
        return response;
    }

    /// <summary>POSTs to the directory's endpoint <paramref name="resource"/> (<c>newAccount</c>, <c>newOrder</c>, …) matching <paramref name="payloadFilter"/>.</summary>
    public int CountPosts(string endpointUrl, Func<string, bool>? payloadFilter = null) =>
        _requests.Count(r => r.Method == "POST" && r.Url == endpointUrl && (payloadFilter?.Invoke(r.Payload) ?? true));

    private static byte[] Base64UrlDecode(string text)
    {
        string s = text.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }
}

/// <summary>Throws what HttpClient throws when its timeout elapses.</summary>
internal sealed class TimingOutHandler : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        throw new TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout of 100 seconds elapsing.", new TimeoutException());
}

/// <summary>A clock tests move forward; monotonic <see cref="Timestamp"/> follows it.</summary>
internal sealed class AdvanceableClock(DateTimeOffset start) : IClock
{
    private long _ticks = start.UtcTicks;
    private readonly long _startTicks = start.UtcTicks;

    public DateTimeOffset UtcNow => new(Interlocked.Read(ref _ticks), TimeSpan.Zero);

    public long Timestamp => (long)((Interlocked.Read(ref _ticks) - _startTicks) / (double)TimeSpan.TicksPerSecond * System.Diagnostics.Stopwatch.Frequency) + System.Diagnostics.Stopwatch.Frequency;

    public void Advance(TimeSpan by) => Interlocked.Add(ref _ticks, by.Ticks);
}

internal static class AcmeTestNames
{
    /// <summary>A fresh DNS name, so tests running in parallel (and reruns against a long-lived Pebble) never share authorizations.</summary>
    public static string Unique(string label = "mx") => $"{label}-{Guid.NewGuid().ToString("N")[..10]}.acme-test.example";
}
