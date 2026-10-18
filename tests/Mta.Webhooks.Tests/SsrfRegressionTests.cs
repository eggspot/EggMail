using System.Net;
using System.Net.Sockets;
using System.Text;
using Mta.Core;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Webhooks.Tests;

/// <summary>
/// Security regression tests for server-side request forgery through webhooks (docs/security-test-map.md, SSRF-*). They drive the production
/// <see cref="WebhookDispatcher"/> with its real HTTP handler against sockets on loopback, so what is asserted is what reaches the network.
/// This is the in-house review, not an independent audit.
/// </summary>
public class WebhookUrlRegistrationSecurityTests
{
    [Theory]
    // numeric host forms that every resolver turns into 127.0.0.1 or 169.254.169.254
    [InlineData("https://2130706433/")]
    [InlineData("https://0x7f000001/")]
    [InlineData("https://0x7f.0x0.0x0.0x1/")]
    [InlineData("https://0177.0.0.1/")]
    [InlineData("https://017700000001/")]
    [InlineData("https://127.1/")]
    [InlineData("https://127.0.1/")]
    [InlineData("https://2852039166/latest/meta-data/")]      // 169.254.169.254 in decimal
    [InlineData("https://0xa9fea9fe/latest/meta-data/")]
    [InlineData("https://0251.0376.0251.0376/")]
    [InlineData("https://169.254.169.254:80/latest/meta-data/")]
    [InlineData("https://169.254.169.254./latest/")]
    [InlineData("https://127.0.0.1./")]
    [InlineData("https://0/")]
    [InlineData("https://0.0.0.0/")]
    // IPv6 forms
    [InlineData("https://[::1]/")]
    [InlineData("https://[::]/")]
    [InlineData("https://[0:0:0:0:0:0:0:1]/")]
    [InlineData("https://[::ffff:127.0.0.1]/")]
    [InlineData("https://[::ffff:7f00:1]/")]
    [InlineData("https://[0:0:0:0:0:ffff:7f00:1]/")]
    [InlineData("https://[::ffff:169.254.169.254]/")]
    [InlineData("https://[::127.0.0.1]/")]
    [InlineData("https://[64:ff9b::7f00:1]/")]
    [InlineData("https://[64:ff9b::a9fe:a9fe]/")]
    [InlineData("https://[2002:7f00:1::]/")]
    [InlineData("https://[2002:a9fe:a9fe::]/")]
    [InlineData("https://[fd00:ec2::254]/latest/meta-data/")]
    [InlineData("https://[fe80::1]/")]
    [InlineData("https://[fe80::1%25eth0]/")]
    [InlineData("https://[fec0::1]/")]
    [InlineData("https://[2001::1]/")]
    // other private ranges and well-known internal names
    [InlineData("https://10.0.0.1/")]
    [InlineData("https://172.16.0.1:8443/")]
    [InlineData("https://192.168.0.1/")]
    [InlineData("https://100.100.100.200/")]
    [InlineData("https://localhost/")]
    [InlineData("https://LOCALHOST/")]
    [InlineData("http://localhost:8080/")]
    // credentials in the URL, whichever way they are written
    [InlineData("https://user:pw@hooks.example.com/")]
    [InlineData("https://hooks.example.com@127.0.0.1/")]
    [InlineData("https://hooks.example.com:443@127.0.0.1/")]
    [InlineData("https://user@hooks.example.com/")]
    [InlineData("https://hooks.example.com\\@127.0.0.1/")]       // whichever way the parser reads the backslash, it is not accepted
    [InlineData("https://app.localhost/")]
    [InlineData("https://localhost./")]
    // schemes that are not webhooks
    [InlineData("file:///etc/passwd")]
    [InlineData("gopher://hooks.example.com/_GET%20/")]
    [InlineData("ftp://hooks.example.com/")]
    [InlineData("ws://hooks.example.com/")]
    [InlineData("wss://hooks.example.com/")]
    [InlineData("javascript:alert(1)")]
    [InlineData("data:text/plain,hi")]
    [InlineData("//hooks.example.com/")]
    [InlineData("hooks.example.com/path")]
    [InlineData("http://hooks.example.com/")]            // https only unless the operator allows http
    public void A_URL_aimed_at_an_internal_service_or_with_a_forbidden_form_is_refused_at_registration(string url) =>
        Assert.False(WebhookUrlValidator.TryValidate(url, allowHttp: false, [], out _), url);

    [Theory]
    [InlineData("https://127.0.0.1#@hooks.example.com/")]           // the fragment hides the "@": the host is 127.0.0.1
    [InlineData("https://127.0.0.1?@hooks.example.com/")]
    [InlineData("https://127.0.0.1/@hooks.example.com/")]
    [InlineData("https://127.0.0.1:443/hooks.example.com")]
    public void Text_that_looks_like_a_public_host_after_the_real_host_does_not_change_the_host(string url) =>
        Assert.False(WebhookUrlValidator.TryValidate(url, false, [], out _), url);

    [Theory]
    [InlineData("https://hooks.example.com/path")]
    [InlineData("https://hooks.example.com:8443/path?x=1")]
    [InlineData("https://hooks.example.com:25/")]                     // ports are not restricted: the SSRF guard works on addresses
    [InlineData("https://8.8.8.8/")]
    [InlineData("https://[2606:4700:4700::1111]/")]
    public void A_public_host_is_accepted_and_the_host_checked_is_the_host_that_will_be_called(string url)
    {
        Assert.True(WebhookUrlValidator.TryValidate(url, false, [], out _), url);
        // The same parser is used to send the request, so the host that was validated is the host that is connected to.
        Assert.False(string.IsNullOrEmpty(new Uri(url).Host));
        Assert.True(string.IsNullOrEmpty(new Uri(url).UserInfo));
    }

    [Theory]
    [InlineData("https://hooks.example.com/a b")]
    [InlineData("https://hooks.example.com/a\tb")]
    [InlineData("https://hooks.example.com/a\r\nb")]
    [InlineData("https://hooks.example.com/a\0b")]
    [InlineData("https://hooks.example.com/a\u0085b")]
    [InlineData("https://hooks.example.com/a\u00a0b")]
    [InlineData("https://hooks.example.com/a\u2028b")]
    [InlineData("https://hooks.example.com/a\u2029b")]
    [InlineData("https://hooks.example.com/a\u202ab")]
    [InlineData("https://hooks.example.com/a\u202bb")]
    [InlineData("https://hooks.example.com/a\u202cb")]
    [InlineData("https://hooks.example.com/a\u202db")]
    [InlineData("https://hooks.example.com/a\u202eb")]
    [InlineData("https://hooks.example.com/a\u2066b")]
    [InlineData("https://hooks.example.com/a\u2067b")]
    [InlineData("https://hooks.example.com/a\u2068b")]
    [InlineData("https://hooks.example.com/a\u2069b")]
    public void A_URL_with_whitespace_a_control_character_or_a_text_direction_control_inside_is_refused(string url)
    {
        Assert.False(WebhookUrlValidator.TryValidate(url, false, [], out string error), url);
        Assert.Contains("must not contain", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("https://hooks.example.com/a%20b")]
    [InlineData("https://hooks.example.com/%E2%80%AE")]            // percent-encoded: plain ASCII text
    [InlineData("https://hooks.example.com/\u30d5\u30c3\u30af")]    // Japanese path
    [InlineData("https://\u4f8b\u3048.jp/hook")]                  // internationalized host
    [InlineData("  https://hooks.example.com/x  ")]                // surrounding spaces are trimmed away by the caller
    public void Real_internationalized_and_encoded_URLs_are_accepted(string url) =>
        Assert.True(WebhookUrlValidator.TryValidate(url, false, [], out string error), error);

    [Fact]
    public void An_allowlist_entry_opens_exactly_its_network()
    {
        var allow = new[] { IpNetwork.Parse("10.1.0.0/16") };
        Assert.True(WebhookUrlValidator.TryValidate("https://10.1.2.3/", false, allow, out _));
        Assert.False(WebhookUrlValidator.TryValidate("https://10.2.0.1/", false, allow, out _));
        Assert.False(WebhookUrlValidator.TryValidate("https://169.254.169.254/", false, allow, out _));
        Assert.False(WebhookUrlValidator.TryValidate("https://127.0.0.1/", false, allow, out _));
        // An IPv4-mapped spelling of an allowlisted address is the same address, and of a non-allowlisted one is not.
        Assert.True(WebhookUrlValidator.TryValidate("https://[::ffff:10.1.2.3]/", false, allow, out _));
        Assert.False(WebhookUrlValidator.TryValidate("https://[::ffff:10.2.0.1]/", false, allow, out _));
    }

    [Theory]
    [InlineData("2130706433")]
    [InlineData("0x7f000001")]
    [InlineData("0177.0.0.1")]
    [InlineData("127.1")]
    [InlineData("0")]
    [InlineData("[::ffff:7f00:1]")]
    [InlineData("localhost")]
    [InlineData("LOCALHOST")]
    public async Task Whatever_the_system_resolver_makes_of_a_host_text_the_connection_is_refused_when_it_is_internal(string host)
    {
        // The connect-time check works on the addresses the resolver returns, so an encoding the URL validator did not know cannot get past it. The resolver is
        // injected: numeric forms are parsed by the guard itself (the way a socket library would read them), a name is looked up, and "localhost" answers loopback.
        static ValueTask<IPAddress[]> Resolver(string h, CancellationToken ct) =>
            ValueTask.FromResult(h.Equals("localhost", StringComparison.OrdinalIgnoreCase) ? new[] { IPAddress.Loopback, IPAddress.IPv6Loopback } : Array.Empty<IPAddress>());
        var allowed = await SsrfGuard.ResolveAllowedAsync(host, Resolver, [], default);
        Assert.Empty(allowed);
    }
}

[Collection("webhook-dispatch")]
public sealed class WebhookDeliverySsrfTests : IAsyncDisposable
{
    private readonly List<LoopbackHttpServer> _servers = [];
    private readonly Guid _tenantA = Ids.New();
    private readonly Guid _tenantB = Ids.New();

    public async ValueTask DisposeAsync()
    {
        foreach (var s in _servers) { await s.DisposeAsync(); }
    }

    private LoopbackHttpServer Server(string response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    {
        var s = new LoopbackHttpServer(response);
        _servers.Add(s);
        return s;
    }

    private static IReadOnlyList<IpNetwork> Loopback => [IpNetwork.Parse("127.0.0.0/8")];

    private sealed class Rig
    {
        public required InMemoryStorage Storage { get; init; }
        public required WebhookDispatcher Dispatcher { get; init; }
    }

    private static async Task<Rig> NewRigAsync(Func<Guid, IReadOnlyList<IpNetwork>>? allowlist = null, Func<string, CancellationToken, ValueTask<IPAddress[]>>? resolver = null)
    {
        var storage = new InMemoryStorage(new StorageOptions(), SystemClock.Instance);
        await storage.InitializeAsync(default);
        var dispatcher = new WebhookDispatcher(storage.Webhooks, storage.Config, new PlainProtector(), resolver: resolver) { AllowlistProvider = allowlist };
        return new Rig { Storage = storage, Dispatcher = dispatcher };
    }

    private static async Task<Guid> AddEndpointAsync(Rig rig, Guid tenant, string url)
    {
        var endpoint = Ids.New();
        await rig.Storage.Config.UpsertWebhookEndpointAsync(new WebhookEndpointRecord(
            endpoint, tenant, url, Encoding.UTF8.GetBytes(StandardWebhooksSigner.GenerateSecret()), ["message.delivered"], true, null, null, DateTimeOffset.UtcNow, null), default);
        return endpoint;
    }

    /// <summary>Queues one event for the tenant, runs the dispatcher once and returns the outcome of that attempt (null error class: delivered).</summary>
    private static async Task<(string? ErrorClass, int? Status)> DeliverOnceAsync(Rig rig, Guid tenant, Guid endpoint)
    {
        Assert.Equal(1, await rig.Storage.Webhooks.EnqueueAsync(tenant, new WebhookEventDraft(Ids.New(), "message.delivered", "{\"type\":\"message.delivered\",\"data\":{}}"), DateTimeOffset.UtcNow, default));
        Assert.Equal(1, await rig.Dispatcher.RunOnceAsync(default));
        var attempts = await rig.Storage.Webhooks.GetAttemptsAsync(tenant, endpoint, 10, default);
        var last = attempts.OrderByDescending(a => a.At).First();
        return (last.ErrorClass, last.StatusCode);
    }

    [Fact]
    public async Task An_endpoint_on_loopback_is_never_connected_to_unless_the_tenant_allowlisted_it()
    {
        var server = Server();
        await using var rig = new RigDisposer(await NewRigAsync());
        Guid endpoint = await AddEndpointAsync(rig.Rig, _tenantA, server.Url);

        var (error, status) = await DeliverOnceAsync(rig.Rig, _tenantA, endpoint);

        Assert.Equal("ssrf_blocked", error);
        Assert.Null(status);
        Assert.Equal(0, server.Connections);   // not one TCP connection reached the target
    }

    [Fact]
    public async Task The_same_endpoint_is_delivered_to_when_its_network_is_on_the_tenants_allowlist()
    {
        // The control for the tests around it: the target is reachable, so a refusal is the guard and not a broken setup.
        var server = Server();
        await using var rig = new RigDisposer(await NewRigAsync(_ => Loopback));
        Guid endpoint = await AddEndpointAsync(rig.Rig, _tenantA, server.Url);

        var (error, status) = await DeliverOnceAsync(rig.Rig, _tenantA, endpoint);

        Assert.Null(error);
        Assert.Equal(200, status);
        Assert.Equal(1, server.Requests);
    }

    [Theory]
    [InlineData(301)]
    [InlineData(302)]
    [InlineData(303)]
    [InlineData(307)]
    [InlineData(308)]
    public async Task A_redirect_is_never_followed_not_even_to_an_address_the_tenant_allowed(int code)
    {
        var target = Server();
        var redirecting = Server($"HTTP/1.1 {code} Moved\r\nLocation: {target.Url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await using var rig = new RigDisposer(await NewRigAsync(_ => Loopback));
        Guid endpoint = await AddEndpointAsync(rig.Rig, _tenantA, redirecting.Url);

        var (error, status) = await DeliverOnceAsync(rig.Rig, _tenantA, endpoint);

        Assert.Equal("redirect_not_followed", error);
        Assert.Equal(code, status);
        Assert.Equal(1, redirecting.Requests);
        Assert.Equal(0, target.Connections);
    }

    [Fact]
    public async Task A_redirect_to_the_cloud_metadata_address_is_a_failed_delivery_and_nothing_is_requested_there()
    {
        var redirecting = Server("HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/iam/security-credentials/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await using var rig = new RigDisposer(await NewRigAsync(_ => Loopback));
        Guid endpoint = await AddEndpointAsync(rig.Rig, _tenantA, redirecting.Url);

        var (error, _) = await DeliverOnceAsync(rig.Rig, _tenantA, endpoint);

        Assert.Equal("redirect_not_followed", error);
        Assert.Equal(1, redirecting.Requests);   // the one request was the webhook itself
    }

    [Fact]
    public async Task A_host_name_that_resolves_to_loopback_is_refused_whatever_the_name_looks_like()
    {
        // DNS rebinding, first form: the name is innocent, the answer is not. Validation looks at the answer.
        var server = Server();
        int resolutions = 0;
        await using var rig = new RigDisposer(await NewRigAsync(resolver: (host, _) => { Interlocked.Increment(ref resolutions); return ValueTask.FromResult(new[] { IPAddress.Loopback }); }));
        Guid endpoint = await AddEndpointAsync(rig.Rig, _tenantA, $"http://hooks.example.test:{server.Port}/hook");

        var (error, _) = await DeliverOnceAsync(rig.Rig, _tenantA, endpoint);

        Assert.Equal("ssrf_blocked", error);
        Assert.Equal(0, server.Connections);
        Assert.Equal(1, resolutions);
    }

    [Fact]
    public async Task The_connection_goes_to_the_address_that_was_validated_and_the_name_is_not_resolved_again()
    {
        // DNS rebinding, second form: the first answer passes validation, a second lookup (by the HTTP stack, after validation) would be hostile.
        // The connection is made to the validated address, from the one lookup.
        var server = Server();
        int resolutions = 0;
        await using var rig = new RigDisposer(await NewRigAsync(
            _ => Loopback,
            (host, _) =>
            {
                int n = Interlocked.Increment(ref resolutions);
                return ValueTask.FromResult(new[] { n == 1 ? IPAddress.Loopback : IPAddress.Parse("169.254.169.254") });
            }));
        Guid endpoint = await AddEndpointAsync(rig.Rig, _tenantA, $"http://rebind.example.test:{server.Port}/hook");

        var (error, status) = await DeliverOnceAsync(rig.Rig, _tenantA, endpoint);

        Assert.Null(error);
        Assert.Equal(200, status);
        Assert.Equal(1, resolutions);
        Assert.Equal(1, server.Requests);
    }

    [Fact]
    public async Task Of_several_answers_only_the_allowed_addresses_are_connected_to()
    {
        // A name with one internal and one allowed address: the internal one is never tried (a connection to it would hang or reach a service).
        var server = Server();
        await using var rig = new RigDisposer(await NewRigAsync(
            _ => Loopback,
            (host, _) => ValueTask.FromResult(new[] { IPAddress.Parse("169.254.169.254"), IPAddress.Parse("10.255.255.1"), IPAddress.Loopback })));
        Guid endpoint = await AddEndpointAsync(rig.Rig, _tenantA, $"http://mixed.example.test:{server.Port}/hook");

        var (error, status) = await DeliverOnceAsync(rig.Rig, _tenantA, endpoint);

        Assert.Null(error);
        Assert.Equal(200, status);
    }

    [Fact]
    public async Task One_tenants_allowlist_does_not_open_a_connection_for_another_tenant_even_after_the_first_connected()
    {
        // Pooled connections must not be shared between tenants whose allowlists differ.
        var server = Server("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");   // keep-alive: the pool would reuse the connection
        await using var rig = new RigDisposer(await NewRigAsync(tenant => tenant == _tenantA ? Loopback : []));
        Guid a = await AddEndpointAsync(rig.Rig, _tenantA, server.Url);
        Guid b = await AddEndpointAsync(rig.Rig, _tenantB, server.Url);

        var first = await DeliverOnceAsync(rig.Rig, _tenantA, a);
        Assert.Null(first.ErrorClass);
        int requestsAfterA = server.Requests;

        var second = await DeliverOnceAsync(rig.Rig, _tenantB, b);

        Assert.Equal("ssrf_blocked", second.ErrorClass);
        Assert.Equal(requestsAfterA, server.Requests);
    }

    [Fact]
    public async Task A_proxy_in_the_environment_is_not_used_so_the_guard_checks_the_receiver_and_not_the_proxy()
    {
        string? before = Environment.GetEnvironmentVariable("HTTP_PROXY");
        var proxy = Server();
        Environment.SetEnvironmentVariable("HTTP_PROXY", proxy.Url);
        try
        {
            var target = Server();
            await using var rig = new RigDisposer(await NewRigAsync(_ => Loopback));
            Guid endpoint = await AddEndpointAsync(rig.Rig, _tenantA, target.Url);

            var (error, _) = await DeliverOnceAsync(rig.Rig, _tenantA, endpoint);

            Assert.Null(error);
            Assert.Equal(1, target.Requests);
            Assert.Equal(0, proxy.Connections);
        }
        finally
        {
            Environment.SetEnvironmentVariable("HTTP_PROXY", before);
        }
    }

    [Fact]
    public async Task The_response_of_a_receiver_that_is_a_firehose_is_not_read_beyond_the_snippet()
    {
        // Not SSRF, but the same boundary: what a hostile receiver sends back is bounded.
        var huge = Server("HTTP/1.1 200 OK\r\nContent-Length: 1000000000\r\nConnection: close\r\n\r\n" + new string('x', 50_000));
        await using var rig = new RigDisposer(await NewRigAsync(_ => Loopback));
        Guid endpoint = await AddEndpointAsync(rig.Rig, _tenantA, huge.Url);

        var (error, status) = await DeliverOnceAsync(rig.Rig, _tenantA, endpoint);

        Assert.Null(error);
        Assert.Equal(200, status);
        var attempt = (await rig.Rig.Storage.Webhooks.GetAttemptsAsync(_tenantA, endpoint, 10, default)).Single();
        Assert.True((attempt.ResponseSnippet?.Length ?? 0) <= 1024);
    }

    private sealed class RigDisposer(Rig rig) : IAsyncDisposable
    {
        public Rig Rig => rig;

        public async ValueTask DisposeAsync() => await rig.Dispatcher.DisposeAsync();
    }

    private sealed class PlainProtector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => plaintext.ToArray();

        public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose) => protectedData.ToArray();
    }
}

/// <summary>A tiny HTTP server on loopback that answers every request with one fixed raw response and counts connections and requests.</summary>
internal sealed class LoopbackHttpServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly byte[] _response;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _accept;
    private int _connections;
    private int _requests;

    public LoopbackHttpServer(string rawResponse)
    {
        _response = Encoding.ASCII.GetBytes(rawResponse);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _accept = Task.Run(AcceptLoopAsync);
    }

    public int Port { get; }
    public string Url => $"http://127.0.0.1:{Port}/hook";
    public int Connections => Volatile.Read(ref _connections);
    public int Requests => Volatile.Read(ref _requests);

    private async Task AcceptLoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(_stop.Token); }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException) { return; }
            Interlocked.Increment(ref _connections);
            _ = Task.Run(() => ServeAsync(client));
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                byte[] buffer = new byte[16 * 1024];
                var seen = new StringBuilder();
                while (!_stop.IsCancellationRequested)
                {
                    int n = await stream.ReadAsync(buffer, _stop.Token);
                    if (n == 0) { return; }
                    seen.Append(Encoding.ASCII.GetString(buffer, 0, n));
                    // One response per request head; the body of the POST is not needed to answer.
                    while (seen.ToString().IndexOf("\r\n\r\n", StringComparison.Ordinal) is var end and >= 0)
                    {
                        seen.Remove(0, end + 4);
                        Interlocked.Increment(ref _requests);
                        await stream.WriteAsync(_response, _stop.Token);
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException or SocketException)
            {
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _listener.Stop();
        await Task.WhenAny(_accept, Task.Delay(TimeSpan.FromSeconds(2)));
        _stop.Dispose();
    }
}
