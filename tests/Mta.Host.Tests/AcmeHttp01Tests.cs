using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Host.Tests.Api;
using Mta.Host.Tls;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests;

/// <summary>A logger that keeps its lines.</summary>
internal sealed class HttpListLog : IMtaLog
{
    private readonly List<string> _lines = [];

    public IReadOnlyList<string> Lines
    {
        get
        {
            lock (_lines)
            {
                return [.. _lines];
            }
        }
    }

    public bool IsEnabled(MtaLogLevel level) => true;

    public void Write(MtaLogLevel level, string source, string message, Exception? exception = null)
    {
        lock (_lines)
        {
            _lines.Add($"{level} {source}: {message}");
        }
    }
}

/// <summary>The built-in HTTP-01 listener (decision 87): it answers a published token and refuses everything else.</summary>
public class AcmeHttpChallengeListenerTests : IAsyncLifetime
{
    private const string Token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
    private const string KeyAuthorization = Token + ".nP1qzpXGymHBrUEepNY9HCsQk7K8KhOypaEmZMolbBo";

    private sealed class Responder : IHttpChallengeResponder
    {
        public int Lookups;

        public ValueTask<string?> FindKeyAuthorizationAsync(string token, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Lookups);
            return ValueTask.FromResult(token == Token ? KeyAuthorization : null);
        }
    }

    private readonly Responder _responder = new();
    private readonly HttpListLog _log = new();
    private readonly CancellationTokenSource _stop = new();
    private AcmeHttpChallengeListener _listener = null!;
    private Task _serving = Task.CompletedTask;

    public Task InitializeAsync()
    {
        _listener = new AcmeHttpChallengeListener(_responder, "127.0.0.1", 0, log: _log);
        Assert.Null(_listener.TryBind());
        _serving = _listener.ServeAsync(_stop.Token);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await _stop.CancelAsync();
        await _listener.DisposeAsync();
        await _serving.WaitAsync(TimeSpan.FromSeconds(30));
    }

    /// <summary>Sends the raw bytes and returns everything the server answers until it closes the connection.</summary>
    private async Task<string> SendAsync(string request)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _listener.Port);
        var stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request));
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer).WaitAsync(TimeSpan.FromSeconds(30));
        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    private static string StatusLine(string response) => response.Split("\r\n")[0];

    private static string Body(string response) => response[(response.IndexOf("\r\n\r\n", StringComparison.Ordinal) + 4)..];

    [Fact]
    public async Task A_published_token_is_answered_with_exactly_its_key_authorization()
    {
        string response = await SendAsync($"GET /.well-known/acme-challenge/{Token} HTTP/1.1\r\nHost: mail.example.com\r\nUser-Agent: Mozilla/5.0 (compatible; Let's Encrypt validation server)\r\nAccept: */*\r\n\r\n");

        Assert.Equal("HTTP/1.1 200 OK", StatusLine(response));
        Assert.Equal(KeyAuthorization, Body(response));
        Assert.Contains($"Content-Length: {KeyAuthorization.Length}\r\n", response);
        Assert.Contains("Content-Type: application/octet-stream\r\n", response);
        Assert.Contains("Connection: close\r\n", response);
        Assert.Contains(_log.Lines, l => l.Contains("answered the ACME HTTP-01 challenge", StringComparison.Ordinal));
    }

    [Fact]
    public async Task HTTP_1_0_and_HEAD_are_answered_too_and_HEAD_has_no_body()
    {
        string old = await SendAsync($"GET /.well-known/acme-challenge/{Token} HTTP/1.0\r\n\r\n");
        Assert.Equal(KeyAuthorization, Body(old));

        string head = await SendAsync($"HEAD /.well-known/acme-challenge/{Token} HTTP/1.1\r\nHost: x\r\n\r\n");
        Assert.Equal("HTTP/1.1 200 OK", StatusLine(head));
        Assert.Contains($"Content-Length: {KeyAuthorization.Length}\r\n", head);
        Assert.Equal("", Body(head));
    }

    [Theory]
    [InlineData("GET / HTTP/1.1\r\nHost: x\r\n\r\n", "404")]
    [InlineData("GET /index.html HTTP/1.1\r\n\r\n", "404")]
    [InlineData("GET /.well-known/acme-challenge/ HTTP/1.1\r\n\r\n", "404")]
    [InlineData("GET /.well-known/acme-challenge HTTP/1.1\r\n\r\n", "404")]
    [InlineData("GET /.well-known/ HTTP/1.1\r\n\r\n", "404")]
    [InlineData("GET /.well-known/security.txt HTTP/1.1\r\n\r\n", "404")]
    [InlineData("GET /.well-known/acme-challenge/unknown-token-0123456789 HTTP/1.1\r\n\r\n", "404")]
    [InlineData("GET /.well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA?x=1 HTTP/1.1\r\n\r\n", "404")]
    [InlineData("GET /.well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA/ HTTP/1.1\r\n\r\n", "404")]
    [InlineData("GET /.well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA/extra HTTP/1.1\r\n\r\n", "404")]
    [InlineData("GET /.well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA%00 HTTP/1.1\r\n\r\n", "404")]
    [InlineData("GET /.well-known/acme-challenge/../../etc/passwd HTTP/1.1\r\n\r\n", "404")]
    [InlineData("GET /.well-known/acme-challenge/%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1\r\n\r\n", "404")]
    [InlineData("GET //.well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA HTTP/1.1\r\n\r\n", "404")]
    [InlineData("GET /.WELL-KNOWN/ACME-CHALLENGE/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA HTTP/1.1\r\n\r\n", "404")]
    [InlineData("GET http://mail.example.com/.well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA HTTP/1.1\r\n\r\n", "404")]
    [InlineData("GET * HTTP/1.1\r\n\r\n", "404")]
    [InlineData("POST /.well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA HTTP/1.1\r\nContent-Length: 0\r\n\r\n", "405")]
    [InlineData("PUT /.well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA HTTP/1.1\r\n\r\n", "405")]
    [InlineData("DELETE /.well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA HTTP/1.1\r\n\r\n", "405")]
    [InlineData("OPTIONS * HTTP/1.1\r\n\r\n", "405")]
    [InlineData("CONNECT mail.example.com:443 HTTP/1.1\r\n\r\n", "405")]
    [InlineData("get /.well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA HTTP/1.1\r\n\r\n", "405")]
    [InlineData("GET /.well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA HTTP/2.0\r\n\r\n", "400")]
    [InlineData("GET /.well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA\r\n\r\n", "400")]
    [InlineData("GET  /x  HTTP/1.1\r\n\r\n", "400")]
    [InlineData("\r\n\r\n", "400")]
    [InlineData("\u0016\u0003\u0001\u0002\u0000\u0001\u0000\u0001ü\u0003\u0003\r\n\r\n", "400")]
    public async Task Everything_but_a_published_token_is_refused_without_a_body(string request, string status)
    {
        string response = await SendAsync(request);

        Assert.StartsWith($"HTTP/1.1 {status} ", response);
        Assert.Equal("", Body(response));
        Assert.Contains("Content-Length: 0\r\n", response);
        Assert.DoesNotContain(KeyAuthorization, response);
    }

    [Fact]
    public async Task An_oversized_request_head_is_refused()
    {
        string response = await SendAsync("GET /.well-known/acme-challenge/x HTTP/1.1\r\nX-Padding: " + new string('a', 20_000) + "\r\n\r\n");

        Assert.StartsWith("HTTP/1.1 431 ", response);
    }

    [Fact]
    public async Task A_request_body_is_never_read_and_a_token_is_not_answered_to_a_non_GET()
    {
        string response = await SendAsync($"POST /.well-known/acme-challenge/{Token} HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello");

        Assert.StartsWith("HTTP/1.1 405 ", response);
        Assert.Contains("Allow: GET, HEAD\r\n", response);
        Assert.DoesNotContain(KeyAuthorization, response);
    }

    [Fact]
    public async Task Only_a_token_of_plausible_shape_reaches_the_lookup()
    {
        await SendAsync("GET /.well-known/acme-challenge/short HTTP/1.1\r\n\r\n");
        await SendAsync("GET /.well-known/acme-challenge/has.dots.in.it.0123456789 HTTP/1.1\r\n\r\n");
        await SendAsync("GET /.well-known/acme-challenge/" + new string('a', 300) + " HTTP/1.1\r\n\r\n");
        await SendAsync("GET /.well-known/acme-challenge/../x HTTP/1.1\r\n\r\n");
        Assert.Equal(0, _responder.Lookups);

        await SendAsync("GET /.well-known/acme-challenge/some-plausible-unknown-token HTTP/1.1\r\n\r\n");
        Assert.Equal(1, _responder.Lookups);
    }

    [Fact]
    public async Task A_silent_or_resetting_client_is_dropped_and_the_listener_keeps_serving()
    {
        using (var idle = new TcpClient())
        {
            await idle.ConnectAsync(IPAddress.Loopback, _listener.Port);
        }

        using (var half = new TcpClient())
        {
            await half.ConnectAsync(IPAddress.Loopback, _listener.Port);
            await half.GetStream().WriteAsync(Encoding.ASCII.GetBytes("GET /.well-known/acme-chal"));
        }

        Assert.Equal(KeyAuthorization, Body(await SendAsync($"GET /.well-known/acme-challenge/{Token} HTTP/1.1\r\n\r\n")));
    }
}

/// <summary>Binding the port: what happens, and what the operator is told, when it cannot be bound.</summary>
public class AcmeHttpChallengeListenerBindTests
{
    private sealed class NoToken : IHttpChallengeResponder
    {
        public ValueTask<string?> FindKeyAuthorizationAsync(string token, CancellationToken cancellationToken) => ValueTask.FromResult<string?>(null);
    }

    [Fact]
    public async Task A_port_in_use_is_an_actionable_message_that_stops_orders_and_is_retried()
    {
        var challenges = new Http01Challenges(new InMemoryStorage(new StorageOptions()).Config);
        challenges.ExpectListener();
        await using var occupant = new AcmeHttpChallengeListener(new NoToken(), "127.0.0.1", 0);
        Assert.Null(occupant.TryBind());
        var log = new HttpListLog();
        await using var listener = new AcmeHttpChallengeListener(new NoToken(), "127.0.0.1", occupant.Port, challenges, log, retryInterval: TimeSpan.FromMilliseconds(20));

        string? problem = listener.TryBind();

        Assert.NotNull(problem);
        Assert.Contains("already in use", problem);
        Assert.Contains($"port {occupant.Port}", problem);
        Assert.Contains("Acme:Http01ListenPort", problem);
        Assert.Contains("DNS-01", problem);
        Assert.False(listener.IsListening);
        Assert.Equal(problem, await challenges.WaitUntilReadyAsync(TimeSpan.FromSeconds(1), default));

        // Once the port is free the listener's own retry loop binds it and orders can start again.
        using var stop = new CancellationTokenSource();
        Task run = listener.RunAsync(stop.Token);
        await occupant.DisposeAsync();
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!listener.IsListening && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        Assert.True(listener.IsListening, string.Join('\n', log.Lines));
        Assert.Null(await challenges.WaitUntilReadyAsync(TimeSpan.FromSeconds(1), default));
        Assert.Contains(log.Lines, l => l.StartsWith("Error acme: ACME HTTP-01:", StringComparison.Ordinal));   // logged loudly once, not every retry
        Assert.Single(log.Lines, l => l.StartsWith("Error acme:", StringComparison.Ordinal));
        await stop.CancelAsync();
        await run.WaitAsync(TimeSpan.FromSeconds(30));
    }

    [Fact]
    public async Task An_order_waits_for_the_first_attempt_to_bind_and_does_not_wait_forever()
    {
        var challenges = new Http01Challenges(new InMemoryStorage(new StorageOptions()).Config);
        Assert.Null(await challenges.WaitUntilReadyAsync(TimeSpan.FromMilliseconds(10), default));   // no listener expected (DNS-01 deployments, tests): nothing to wait for

        challenges.ExpectListener();
        Assert.Contains("has not started", await challenges.WaitUntilReadyAsync(TimeSpan.FromMilliseconds(50), default));

        await using var listener = new AcmeHttpChallengeListener(new NoToken(), "127.0.0.1", 0, challenges);
        Task<string?> waiting = challenges.WaitUntilReadyAsync(TimeSpan.FromMinutes(1), default).AsTask();
        Assert.Null(listener.TryBind());
        Assert.Null(await waiting.WaitAsync(TimeSpan.FromSeconds(30)));
    }

    [Fact]
    public async Task An_address_that_is_not_an_address_is_a_message_not_a_crash()
    {
        await using var listener = new AcmeHttpChallengeListener(new NoToken(), "localhost", 0);

        Assert.Contains("Acme:Http01BindAddress", listener.TryBind());
    }

    private sealed class OneToken : IHttpChallengeResponder
    {
        public const string Token = "oneToken-0123456789abcdef";

        public ValueTask<string?> FindKeyAuthorizationAsync(string token, CancellationToken cancellationToken) => ValueTask.FromResult<string?>(token == Token ? "answer-" + Token : null);
    }

    private static async Task<string> GetAsync(IPAddress address, int port)
    {
        using var client = new TcpClient(address.AddressFamily);
        await client.ConnectAsync(address, port);
        var stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes($"GET {AcmeHttpChallengeListener.PathPrefix}{OneToken.Token} HTTP/1.1\r\n\r\n"));
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer).WaitAsync(TimeSpan.FromSeconds(30));
        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    [Fact]
    public async Task The_default_address_answers_over_IPv4_and_over_IPv6_when_the_host_has_it()
    {
        await using var listener = new AcmeHttpChallengeListener(new OneToken(), "::", 0);
        Assert.Null(listener.TryBind());
        using var stop = new CancellationTokenSource();
        Task serving = listener.ServeAsync(stop.Token);

        Assert.EndsWith("answer-" + OneToken.Token, await GetAsync(IPAddress.Loopback, listener.Port));
        if (Socket.OSSupportsIPv6)
        {
            Assert.EndsWith("answer-" + OneToken.Token, await GetAsync(IPAddress.IPv6Loopback, listener.Port));
        }

        await stop.CancelAsync();
        await serving.WaitAsync(TimeSpan.FromSeconds(30));
    }

    [Fact]
    public async Task A_listener_that_stops_after_binding_tells_the_store_and_a_new_bind_clears_it()
    {
        var challenges = new Http01Challenges(new InMemoryStorage(new StorageOptions()).Config);
        challenges.ExpectListener();
        await using var listener = new AcmeHttpChallengeListener(new OneToken(), "127.0.0.1", 0, challenges, retryInterval: TimeSpan.FromMilliseconds(10));
        Assert.Null(listener.TryBind());
        Assert.Null(await challenges.WaitUntilReadyAsync(TimeSpan.FromSeconds(1), default));
        using var stop = new CancellationTokenSource();
        Task serving = listener.ServeAsync(stop.Token);

        listener.Close();   // the socket fails under the running listener (not a shutdown)
        await serving.WaitAsync(TimeSpan.FromSeconds(30));

        Assert.False(listener.IsListening);
        string? reason = await challenges.WaitUntilReadyAsync(TimeSpan.FromSeconds(1), default);
        Assert.NotNull(reason);   // orders wait instead of asking the CA to connect to a closed port
        Assert.Contains("stopped", reason);

        Task run = listener.RunAsync(stop.Token);   // the retry loop binds again
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!listener.IsListening && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        Assert.True(listener.IsListening);
        Assert.Null(await challenges.WaitUntilReadyAsync(TimeSpan.FromSeconds(1), default));
        await stop.CancelAsync();
        await run.WaitAsync(TimeSpan.FromSeconds(30));
    }
}

/// <summary>The limits of the listener: per client address, the request head timeout, a failing lookup, what a log line may contain.</summary>
public class AcmeHttpChallengeListenerLimitTests
{
    private sealed class Throwing : IHttpChallengeResponder
    {
        public bool Throw = true;

        public ValueTask<string?> FindKeyAuthorizationAsync(string token, CancellationToken cancellationToken) =>
            Throw ? throw new InvalidOperationException("the store exploded") : ValueTask.FromResult<string?>("fine");
    }

    private static async Task<string> RequestAsync(int port, string request)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        var stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request));
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer).WaitAsync(TimeSpan.FromSeconds(30));
        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    [Fact]
    public async Task One_client_address_cannot_hold_more_than_its_share_of_connections_and_gets_them_back()
    {
        await using var listener = new AcmeHttpChallengeListener(new Throwing { Throw = false }, "127.0.0.1", 0, maxConnectionsPerAddress: 2,
            headTimeout: TimeSpan.FromMinutes(1), requestTimeout: TimeSpan.FromMinutes(2));
        Assert.Null(listener.TryBind());
        using var stop = new CancellationTokenSource();
        Task serving = listener.ServeAsync(stop.Token);

        using var first = new TcpClient();
        using var second = new TcpClient();
        await first.ConnectAsync(IPAddress.Loopback, listener.Port);
        await second.ConnectAsync(IPAddress.Loopback, listener.Port);   // two silent connections: the allowance of this address

        // The third is closed at once without an answer (the accept loop takes connections in order, so the first two are counted by now).
        using (var third = new TcpClient())
        {
            await third.ConnectAsync(IPAddress.Loopback, listener.Port);
            var stream = third.GetStream();
            int read;
            try
            {
                read = await stream.ReadAsync(new byte[16]).AsTask().WaitAsync(TimeSpan.FromSeconds(30));
            }
            catch (IOException)
            {
                read = 0;   // a reset is a closed connection too
            }

            Assert.Equal(0, read);
        }

        // Releasing one gives the allowance back: a real request is answered (polled, the release is asynchronous).
        first.Dispose();
        string answer = "";
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!answer.Contains("200 OK", StringComparison.Ordinal) && DateTime.UtcNow < deadline)
        {
            try
            {
                answer = await RequestAsync(listener.Port, $"GET {AcmeHttpChallengeListener.PathPrefix}anyplausibletoken0123456789 HTTP/1.1\r\n\r\n");
            }
            catch (IOException)
            {
                answer = "";   // refused while the allowance is still taken
            }

            await Task.Delay(10);
        }

        Assert.Contains("200 OK", answer);
        await stop.CancelAsync();
        await serving.WaitAsync(TimeSpan.FromSeconds(30));
    }

    [Fact]
    public async Task A_client_that_does_not_send_its_request_in_time_is_dropped_without_an_answer()
    {
        await using var listener = new AcmeHttpChallengeListener(new Throwing { Throw = false }, "127.0.0.1", 0, headTimeout: TimeSpan.FromMilliseconds(100));
        Assert.Null(listener.TryBind());
        using var stop = new CancellationTokenSource();
        Task serving = listener.ServeAsync(stop.Token);

        using var slow = new TcpClient();
        await slow.ConnectAsync(IPAddress.Loopback, listener.Port);
        var stream = slow.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes("GET /.well-known/acme-chall"));   // never finishes the request line
        int read;
        try
        {
            read = await stream.ReadAsync(new byte[16]).AsTask().WaitAsync(TimeSpan.FromSeconds(30));   // a generous bound, only a hang fails
        }
        catch (IOException)
        {
            read = 0;
        }

        Assert.Equal(0, read);   // closed, nothing sent
        Assert.Contains("200 OK", await RequestAsync(listener.Port, $"GET {AcmeHttpChallengeListener.PathPrefix}anyplausibletoken0123456789 HTTP/1.1\r\n\r\n"));
        await stop.CancelAsync();
        await serving.WaitAsync(TimeSpan.FromSeconds(30));
    }

    [Fact]
    public async Task A_lookup_that_fails_is_a_503_and_the_listener_keeps_serving()
    {
        var responder = new Throwing();
        var log = new HttpListLog();
        await using var listener = new AcmeHttpChallengeListener(responder, "127.0.0.1", 0, log: log);
        Assert.Null(listener.TryBind());
        using var stop = new CancellationTokenSource();
        Task serving = listener.ServeAsync(stop.Token);

        string failed = await RequestAsync(listener.Port, $"GET {AcmeHttpChallengeListener.PathPrefix}anyplausibletoken0123456789 HTTP/1.1\r\n\r\n");

        Assert.StartsWith("HTTP/1.1 503 ", failed);
        Assert.DoesNotContain("exploded", failed);   // nothing of the failure reaches the peer
        Assert.Contains(log.Lines, l => l.Contains("exploded", StringComparison.Ordinal));   // but the log has it
        responder.Throw = false;
        Assert.StartsWith("HTTP/1.1 200 ", await RequestAsync(listener.Port, $"GET {AcmeHttpChallengeListener.PathPrefix}anyplausibletoken0123456789 HTTP/1.1\r\n\r\n"));
        await stop.CancelAsync();
        await serving.WaitAsync(TimeSpan.FromSeconds(30));
    }

    [Fact]
    public void A_logged_request_target_is_printable_ASCII_and_short()
    {
        string printable = AcmeHttpChallengeListener.Printable("/x\r\nINFO forged line\u0000\u001b[31m\u00e9\u4e2d");

        Assert.DoesNotContain('\r', printable);
        Assert.DoesNotContain('\n', printable);
        Assert.All(printable, c => Assert.InRange(c, ' ', '~'));
        Assert.Equal(83, AcmeHttpChallengeListener.Printable(new string('a', 500)).Length);
        Assert.EndsWith("...", AcmeHttpChallengeListener.Printable(new string('a', 500)));
    }
}

/// <summary>The challenge store that every replica answers from: a token published by one is found by another through the config store.</summary>
public class Http01ChallengesTests
{
    private const string TokenA = "token-a-0123456789abcdefghij";
    private const string TokenB = "token-b-0123456789abcdefghij";
    private static readonly DateTimeOffset T0 = new(2026, 10, 15, 8, 0, 0, TimeSpan.Zero);

    private readonly TestClock _clock = new(T0);
    private readonly InMemoryStorage _storage;

    public Http01ChallengesTests() => _storage = new InMemoryStorage(new StorageOptions(), _clock);

    private Http01Challenges Replica(IConfigStore? config = null) => new(config ?? _storage.Config, _clock, refreshInterval: TimeSpan.Zero);

    [Fact]
    public async Task A_token_published_by_one_replica_is_answered_by_another_and_gone_after_removal()
    {
        var leader = Replica();
        var other = Replica();

        Assert.Null(await other.FindKeyAuthorizationAsync(TokenA, default));
        await leader.PublishAsync("default", TokenA, "ka-a", default);
        await leader.PublishAsync("default", TokenB, "ka-b", default);

        Assert.Equal("ka-a", await other.FindKeyAuthorizationAsync(TokenA, default));   // never published in this process: read from the store
        Assert.Equal("ka-b", await other.FindKeyAuthorizationAsync(TokenB, default));

        await leader.RemoveAsync("default", TokenA, default);
        Assert.Null(await other.FindKeyAuthorizationAsync(TokenA, default));
        Assert.Null(await leader.FindKeyAuthorizationAsync(TokenA, default));
        Assert.Equal("ka-b", await other.FindKeyAuthorizationAsync(TokenB, default));

        await leader.RemoveAsync("default", TokenB, default);
        Assert.Null((await _storage.Config.GetAcmeRenewalsAsync(default)).Single().ChallengeStateJson);   // nothing left behind
    }

    [Fact]
    public async Task Publishing_changes_only_the_challenge_state_of_the_renewal_row()
    {
        var row = new AcmeRenewalRecord("default", "ordering", T0, T0.AddMinutes(5), 2, "earlier error", null, "{\"ari\":1}");
        await _storage.Config.UpsertAcmeRenewalAsync(row, default);

        await Replica().PublishAsync("default", TokenA, "ka-a", default);

        var after = Assert.Single(await _storage.Config.GetAcmeRenewalsAsync(default));
        Assert.Equal(row with { ChallengeStateJson = after.ChallengeStateJson }, after);
        Assert.NotNull(after.ChallengeStateJson);
    }

    [Fact]
    public async Task Tokens_of_different_certificates_are_kept_apart_and_all_answered()
    {
        var leader = Replica();
        await leader.PublishAsync("default", TokenA, "ka-a", default);
        await leader.PublishAsync("acme:other.example", TokenB, "ka-b", default);

        var other = Replica();
        Assert.Equal("ka-a", await other.FindKeyAuthorizationAsync(TokenA, default));
        Assert.Equal("ka-b", await other.FindKeyAuthorizationAsync(TokenB, default));
        await leader.RemoveAsync("default", TokenA, default);
        Assert.Equal("ka-b", await Replica().FindKeyAuthorizationAsync(TokenB, default));
    }

    [Fact]
    public async Task A_token_nobody_removed_stops_being_answered_after_its_lifetime()
    {
        await Replica().PublishAsync("default", TokenA, "ka-a", default);
        var other = Replica();
        Assert.Equal("ka-a", await other.FindKeyAuthorizationAsync(TokenA, default));

        _clock.Advance(Http01Challenges.TokenLifetime + TimeSpan.FromSeconds(1));

        Assert.Null(await other.FindKeyAuthorizationAsync(TokenA, default));
        Assert.Null(await Replica().FindKeyAuthorizationAsync(TokenA, default));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{}")]
    [InlineData("{\"http01\":null}")]
    [InlineData("{\"http01\":[{\"t\":\"token-a-0123456789abcdefghij\",\"k\":\"x\",\"u\":9223372036854775807}]}")]   // a timestamp no clock reaches: refused, not a crash
    [InlineData("[1,2,3]")]
    public async Task A_damaged_challenge_state_answers_nothing_and_does_not_break_publishing(string stored)
    {
        await _storage.Config.UpsertAcmeRenewalAsync(new AcmeRenewalRecord("default", "ordering", T0, null, 0, null, stored, null), default);

        Assert.Null(await Replica().FindKeyAuthorizationAsync(TokenA, default));
        var replica = Replica();
        await replica.PublishAsync("default", TokenB, "ka-b", default);
        Assert.Equal("ka-b", await Replica().FindKeyAuthorizationAsync(TokenB, default));
    }

    [Fact]
    public async Task Tokens_that_are_not_tokens_never_reach_the_store_and_guesses_read_it_at_most_once_per_interval()
    {
        var counting = CountingConfig.Wrap(_storage.Config);
        var counter = (CountingConfig)(object)counting;
        var replica = new Http01Challenges(counting, _clock, refreshInterval: TimeSpan.FromHours(1));

        foreach (string bad in new[] { "", "short", "has space in it 0123456789", "../../../etc/passwd", new string('a', 257), "dots.are.not.base64url.0123" })
        {
            Assert.Null(await replica.FindKeyAuthorizationAsync(bad, default));
        }

        Assert.Equal(0, counter.Reads);

        for (int i = 0; i < 200; i++)
        {
            Assert.Null(await replica.FindKeyAuthorizationAsync($"guess-{i:D4}-0123456789abcdef", default));
        }

        Assert.Equal(1, counter.Reads);   // one snapshot serves every guess within the interval
    }

    [Fact]
    public async Task While_the_store_is_down_the_replica_that_ordered_still_answers()
    {
        var failing = CountingConfig.Wrap(_storage.Config);
        var counter = (CountingConfig)(object)failing;
        var leader = new Http01Challenges(failing, _clock, refreshInterval: TimeSpan.Zero);
        await leader.PublishAsync("default", TokenA, "ka-a", default);

        counter.Fail = true;

        Assert.Equal("ka-a", await leader.FindKeyAuthorizationAsync(TokenA, default));   // from memory
        Assert.Null(await leader.FindKeyAuthorizationAsync(TokenB, default));   // unknown, and the failed read is not an exception for the listener
    }

    [Fact]
    public async Task Publishing_something_that_is_not_a_token_is_refused()
    {
        await Assert.ThrowsAsync<AcmeException>(async () => await Replica().PublishAsync("default", "../x", "ka", default));
    }

    /// <summary>Counts the renewal-state reads and can make them fail.</summary>
    public class CountingConfig : DispatchProxy
    {
        private IConfigStore _inner = null!;
        private int _reads;

        public int Reads => Volatile.Read(ref _reads);

        public bool Fail { get; set; }

        public static IConfigStore Wrap(IConfigStore inner)
        {
            var proxy = Create<IConfigStore, CountingConfig>();
            ((CountingConfig)(object)proxy)._inner = inner;
            return proxy;
        }

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            if (targetMethod!.Name == nameof(IConfigStore.GetAcmeRenewalsAsync))
            {
                Interlocked.Increment(ref _reads);
                if (Fail)
                {
                    throw new InvalidOperationException("the database is unavailable");
                }
            }

            try
            {
                return targetMethod.Invoke(_inner, args);
            }
            catch (TargetInvocationException ex)
            {
                throw ex.InnerException ?? ex;
            }
        }
    }
}

/// <summary>
/// The renewal service with HTTP-01 and EAB, against a scripted CA (no network): which challenge is chosen, what an order carries, and how a
/// problem with the listener, a wildcard name or the CA shows up (renewal state, log, and the dashboard warnings).
/// </summary>
public class AcmeRenewalHttp01ServiceTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 15, 8, 0, 0, TimeSpan.Zero);
    private const string Host = "mail.http01.example";

    private readonly TestClock _clock = new(T0);
    private readonly InMemoryStorage _storage;
    private readonly ScriptedCa _ca;
    private readonly HttpListLog _log = new();

    public AcmeRenewalHttp01ServiceTests()
    {
        _storage = new InMemoryStorage(new StorageOptions(), _clock);
        _ca = new ScriptedCa(_clock);
    }

    private sealed class AnyDns : IDnsChallengeProvider
    {
        public ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken cancellationToken) => ValueTask.FromResult("h");

        public ValueTask DeleteTxtAsync(string handle, CancellationToken cancellationToken) => ValueTask.CompletedTask;
    }

    private AcmeRenewalService Service(AcmeSection? options = null, bool dns = false, IHttpChallengePublisher? http = null) => new(
        _storage.Config, new TestProtector(), _ca, dns ? new AnyDns() : null,
        options ?? Options(), _clock, _log, random: () => 0.5, http: http ?? new Http01Challenges(_storage.Config, _clock));

    private static AcmeSection Options(AcmeChallengeMode challenge = AcmeChallengeMode.Auto, string[]? domains = null, string? directory = null, string? eabKeyId = null, string? eabKey = null, string? eabFile = null) => new()
    {
        Enabled = true, Email = "ops@http01.example", Domains = [.. domains ?? [Host]], Challenge = challenge, Directory = directory,
        EabKeyId = eabKeyId, EabHmacKey = eabKey, EabHmacKeyFile = eabFile, UseRenewalInfo = false, PropagationDelay = TimeSpan.Zero,
    };

    private async Task<AcmeRenewalRecord> RenewalAsync() => Assert.Single(await _storage.Config.GetAcmeRenewalsAsync(default));

    [Theory]
    [InlineData(AcmeChallengeMode.Auto, false, AcmeChallengeType.Http01)]
    [InlineData(AcmeChallengeMode.Auto, true, AcmeChallengeType.Dns01)]
    [InlineData(AcmeChallengeMode.Http01, true, AcmeChallengeType.Http01)]
    [InlineData(AcmeChallengeMode.Http01, false, AcmeChallengeType.Http01)]
    [InlineData(AcmeChallengeMode.Dns01, true, AcmeChallengeType.Dns01)]
    public async Task The_challenge_is_DNS_01_with_a_DNS_provider_unless_told_otherwise_else_HTTP_01(AcmeChallengeMode mode, bool dns, AcmeChallengeType expected)
    {
        Assert.True(await Service(Options(mode), dns).CheckOnceAsync(default));

        var order = Assert.Single(_ca.Orders);
        Assert.Equal(expected, order.Challenge);
        Assert.Equal("default", order.CertificateName);
        Assert.NotNull(order.Http);
    }

    [Fact]
    public async Task DNS_01_without_a_DNS_provider_is_a_recorded_failure_that_names_the_setting()
    {
        Assert.False(await Service(Options(AcmeChallengeMode.Dns01)).CheckOnceAsync(default));

        var renewal = await RenewalAsync();
        Assert.Equal("failed", renewal.Status);
        Assert.Contains("Acme:CloudflareApiToken", renewal.LastError);
        Assert.Empty(_ca.Orders);
    }

    [Theory]
    [InlineData(AcmeChallengeMode.Auto)]
    [InlineData(AcmeChallengeMode.Http01)]
    public async Task A_wildcard_name_needs_DNS_01_and_the_CA_is_not_asked(AcmeChallengeMode mode)
    {
        Assert.False(await Service(Options(mode, ["*.http01.example", "http01.example"])).CheckOnceAsync(default));

        var renewal = await RenewalAsync();
        Assert.Equal(("failed", 1), (renewal.Status, renewal.Failures));
        Assert.Contains("*.http01.example", renewal.LastError);
        Assert.Contains("wildcard", renewal.LastError);
        Assert.Contains("DNS-01", renewal.LastError);
        Assert.Contains("Acme:CloudflareApiToken", renewal.LastError);
        Assert.Empty(_ca.Orders);
    }

    [Fact]
    public async Task A_wildcard_name_is_fine_with_a_DNS_provider()
    {
        Assert.True(await Service(Options(AcmeChallengeMode.Auto, ["*.http01.example", "http01.example"]), dns: true).CheckOnceAsync(default));

        Assert.Equal(AcmeChallengeType.Dns01, Assert.Single(_ca.Orders).Challenge);
    }

    [Fact]
    public async Task A_listener_that_cannot_bind_stops_the_order_before_the_CA_is_asked_and_the_order_follows_once_it_can()
    {
        var http = new Http01Challenges(_storage.Config, _clock);
        http.ExpectListener();
        await using var occupant = new AcmeHttpChallengeListener(http, "127.0.0.1", 0);
        Assert.Null(occupant.TryBind());   // holds the port
        await using var listener = new AcmeHttpChallengeListener(http, "127.0.0.1", occupant.Port, http);
        Assert.NotNull(listener.TryBind());
        var service = Service(http: http);

        Assert.False(await service.CheckOnceAsync(default));

        var renewal = await RenewalAsync();
        Assert.Equal(("failed", 1), (renewal.Status, renewal.Failures));
        Assert.Contains("already in use", renewal.LastError);
        Assert.Equal(T0.AddMinutes(5), renewal.NextAttemptAt);   // soon: the CA was not asked, so there is nothing to protect
        Assert.Empty(_ca.Orders);
        Assert.Contains(_log.Lines, l => l.StartsWith("Error acme:", StringComparison.Ordinal) && l.Contains("already in use", StringComparison.Ordinal));

        Assert.False(await service.CheckOnceAsync(default));   // inside the wait
        await occupant.DisposeAsync();
        Assert.Null(listener.TryBind());
        _clock.Advance(TimeSpan.FromMinutes(6));
        Assert.True(await service.CheckOnceAsync(default));

        Assert.Equal(("issued", 0), ((await RenewalAsync()).Status, (await RenewalAsync()).Failures));
        Assert.Single(_ca.Orders);
    }

    [Fact]
    public async Task External_account_binding_is_sent_with_the_first_order_only()
    {
        var service = Service(Options(eabKeyId: "kid-1", eabKey: "c2VjcmV0"));

        Assert.True(await service.CheckOnceAsync(default));
        var first = Assert.Single(_ca.Orders);
        Assert.Equal(("kid-1", "c2VjcmV0"), (first.EabKeyId, first.EabHmacKey));

        _clock.Advance(TimeSpan.FromDays(70));   // renewal: the account exists, the binding is not repeated
        Assert.True(await service.CheckOnceAsync(default));
        var second = _ca.Orders[1];
        Assert.NotNull(second.AccountKeyPem);
        Assert.Null(second.EabKeyId);
        Assert.Null(second.EabHmacKey);
    }

    [Fact]
    public async Task The_EAB_key_can_come_from_a_file_and_a_missing_file_is_a_recorded_failure()
    {
        string file = Path.Combine(Path.GetTempPath(), "eggmail-eab-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(file, "  ZmlsZXNlY3JldA\n");
        try
        {
            Assert.True(await Service(Options(eabKeyId: "kid-2", eabFile: file)).CheckOnceAsync(default));
            Assert.Equal("ZmlsZXNlY3JldA", Assert.Single(_ca.Orders).EabHmacKey);
        }
        finally
        {
            File.Delete(file);
        }

        var other = new TestClock(T0);
        var storage = new InMemoryStorage(new StorageOptions(), other);
        var service = new AcmeRenewalService(storage.Config, new TestProtector(), _ca, null, Options(eabKeyId: "kid-2", eabFile: file + ".missing"), other, _log, http: new Http01Challenges(storage.Config, other));
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal("failed", Assert.Single(await storage.Config.GetAcmeRenewalsAsync(default)).Status);
    }

    [Fact]
    public async Task Without_EAB_nothing_is_sent_and_the_email_is_the_account_contact()
    {
        Assert.True(await Service().CheckOnceAsync(default));

        var order = Assert.Single(_ca.Orders);
        Assert.Null(order.EabKeyId);
        Assert.Null(order.EabHmacKey);
        Assert.Equal("ops@http01.example", order.Email);
    }

    [Theory]
    [InlineData("LetsEncrypt", "https://acme-v02.api.letsencrypt.org/directory")]
    [InlineData("letsencrypt", "https://acme-v02.api.letsencrypt.org/directory")]
    [InlineData("LetsEncryptStaging", "https://acme-staging-v02.api.letsencrypt.org/directory")]
    [InlineData("lets-encrypt-staging", "https://acme-staging-v02.api.letsencrypt.org/directory")]
    [InlineData("ZeroSsl", "https://acme.zerossl.com/v2/DV90")]
    [InlineData("https://ca.example/acme/directory", "https://ca.example/acme/directory")]
    [InlineData(null, "https://acme-v02.api.letsencrypt.org/directory")]
    public async Task The_CA_is_Lets_Encrypt_unless_a_name_or_URL_says_otherwise_and_the_account_belongs_to_that_directory(string? directory, string expected)
    {
        Assert.True(await Service(Options(directory: directory)).CheckOnceAsync(default));

        Assert.Equal(expected, Assert.Single(_ca.Orders).DirectoryUrl);
        Assert.Equal(expected, (await _storage.Config.GetAcmeAccountAsync(expected, default))!.DirectoryUrl);
    }

    [Fact]
    public async Task Staging_and_production_do_not_share_an_account()
    {
        Assert.True(await Service(Options(directory: "LetsEncryptStaging")).CheckOnceAsync(default));
        var staging = await _storage.Config.GetAcmeAccountAsync(AcmeSection.LetsEncryptStagingDirectoryUrl, default);
        Assert.NotNull(staging);
        Assert.Null(await _storage.Config.GetAcmeAccountAsync(AcmeSection.LetsEncryptDirectoryUrl, default));
    }

    [Fact]
    public async Task An_unknown_directory_name_is_a_recorded_failure_that_lists_the_names()
    {
        Assert.False(await Service(Options(directory: "Letsencrypt-ish")).CheckOnceAsync(default));

        Assert.Contains("LetsEncryptStaging", (await RenewalAsync()).LastError);
        Assert.Empty(_ca.Orders);
    }

    [Fact]
    public async Task Internationalized_names_are_ordered_and_stored_in_their_ASCII_form()
    {
        Assert.True(await Service(Options(domains: ["Mail.Bücher.Example.", "mail.bücher.example", "müller.example"])).CheckOnceAsync(default));

        Assert.Equal(["mail.xn--bcher-kva.example", "xn--mller-kva.example"], Assert.Single(_ca.Orders).Domains);
        var certificate = Assert.Single(await _storage.Config.GetCertificatesAsync(default));
        Assert.Equal(["mail.xn--bcher-kva.example", "xn--mller-kva.example"], certificate.Subjects);
        Assert.False(await Service(Options(domains: ["mail.bücher.example", "müller.example"])).CheckOnceAsync(default));   // the same names, written differently: nothing to renew
        Assert.Single(_ca.Orders);
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("192.0.2.10")]
    [InlineData("mail_server.example")]
    [InlineData("a*.example.com")]
    [InlineData("")]
    public void Names_that_are_not_public_host_names_are_refused(string name)
    {
        Assert.Null(AcmeNames.TryNormalize(name, out string? error));
        Assert.NotNull(error);
    }

    [Fact]
    public async Task A_failing_order_raises_acme_failing_with_the_error_and_the_next_attempt_and_issuing_clears_it()
    {
        var contributor = new CertificateHealthContributor(_storage, _clock, new MtaConfig { Acme = Options() });
        var selfSigned = CertificateMaterial.CreateSelfSigned(Host, new TestProtector(), T0);
        await _storage.Config.UpsertCertificateAsync(selfSigned, default);

        // Before the first attempt: pending, and the self-signed certificate is what is served.
        var before = (await contributor.CheckAsync(default)).Warnings;
        var pending = Assert.Single(before, w => w.Code == "acme_pending");
        Assert.Contains(Host, pending.Message);
        Assert.Contains("self-signed", pending.Message);
        Assert.Contains(before, w => w.Code == "self_signed_certificate");
        Assert.DoesNotContain(before, w => w.Code == "acme_failing");

        _ca.FailWith = new AcmeException("Authorization for " + Host + " ended as Invalid: Timeout during connect (likely firewall problem)");
        var service = Service();
        Assert.False(await service.CheckOnceAsync(default));

        var failing = (await contributor.CheckAsync(default)).Warnings;
        var warning = Assert.Single(failing, w => w.Code == "acme_failing");
        Assert.Contains("failed 1 time in a row", warning.Message);
        Assert.Contains("the CA could not validate the challenge", warning.Message);
        Assert.DoesNotContain("firewall", warning.Message);   // the error text is for the admin view and the log
        Assert.Contains("Next attempt: 2026-10-15 08:10 UTC", warning.Message);
        Assert.Contains("self-signed", warning.Message);
        Assert.DoesNotContain(failing, w => w.Code == "acme_pending");   // one banner for the state, not two

        // Backed off: the next attempt is later and the count grows; the warning follows the stored state.
        _clock.Advance(TimeSpan.FromMinutes(11));
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Contains("failed 2 times in a row", Assert.Single((await contributor.CheckAsync(default)).Warnings, w => w.Code == "acme_failing").Message);

        // Recovery: issued, the warnings are gone (the self-signed one too: an ACME certificate is active now).
        _ca.FailWith = null;
        _clock.Advance(TimeSpan.FromMinutes(25));
        Assert.True(await service.CheckOnceAsync(default));
        var after = (await contributor.CheckAsync(default)).Warnings;
        Assert.DoesNotContain(after, w => w.Code.StartsWith("acme_", StringComparison.Ordinal));
        Assert.DoesNotContain(after, w => w.Code == "self_signed_certificate");
    }

    [Fact]
    public async Task A_renewal_that_fails_keeps_the_certificate_and_says_until_when()
    {
        var contributor = new CertificateHealthContributor(_storage, _clock, new MtaConfig { Acme = Options() });
        var service = Service();
        Assert.True(await service.CheckOnceAsync(default));
        _clock.Advance(TimeSpan.FromDays(70));
        _ca.FailWith = new AcmeException("ACME server error: rate limit");

        Assert.False(await service.CheckOnceAsync(default));

        var warning = Assert.Single((await contributor.CheckAsync(default)).Warnings, w => w.Code == "acme_failing");
        Assert.Contains("The previous certificate stays in use until 2027-01-13", warning.Message);
        Assert.Contains("the CA refused the request", warning.Message);
        Assert.DoesNotContain("rate limit", warning.Message);
        Assert.Single(await _storage.Config.GetCertificatesAsync(default));   // the old certificate is untouched
    }

    [Fact]
    public async Task The_next_check_comes_when_a_failed_order_is_due_again_not_only_at_the_hourly_interval()
    {
        var service = Service();
        Assert.Equal(TimeSpan.FromHours(1), await service.NextCheckDelayAsync(default));   // nothing failed

        _ca.FailWith = new AcmeException("ACME server error: try later");
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(TimeSpan.FromMinutes(10), await service.NextCheckDelayAsync(default));   // the first back-off

        _clock.Advance(TimeSpan.FromMinutes(9) + TimeSpan.FromSeconds(50));
        Assert.Equal(TimeSpan.FromSeconds(30), await service.NextCheckDelayAsync(default));   // not a busy loop

        _clock.Advance(TimeSpan.FromMinutes(5));
        Assert.Equal(TimeSpan.FromSeconds(30), await service.NextCheckDelayAsync(default));   // overdue: soon

        _ca.FailWith = null;
        Assert.True(await service.CheckOnceAsync(default));
        Assert.Equal(TimeSpan.FromHours(1), await service.NextCheckDelayAsync(default));   // issued: the regular interval again

        // A back-off longer than the interval does not stretch it.
        await _storage.Config.UpsertAcmeRenewalAsync(new AcmeRenewalRecord("other", "failed", _clock.UtcNow, _clock.UtcNow.AddHours(6), 9, "x", null, null), default);
        Assert.Equal(TimeSpan.FromHours(1), await service.NextCheckDelayAsync(default));
    }

    [Fact]
    public async Task The_warning_never_carries_the_error_text_the_directory_or_credentials()
    {
        const string Error = "ACME server error: https://user:hunter2@ca.example/dir?token=abc123 said\r\nsecret line\t" + "xxxxxxxxxx";
        await _storage.Config.UpsertAcmeRenewalAsync(new AcmeRenewalRecord("default", "failed", T0, T0.AddHours(1), 4, Error, null, null), default);
        var config = new MtaConfig { Acme = new AcmeSection { Enabled = true, Domains = [Host], DirectoryUrl = "https://user:hunter2@ca.example/dir?token=abc123" } };

        var warnings = (await new CertificateHealthContributor(_storage, _clock, config).CheckAsync(default)).Warnings;

        string message = Assert.Single(warnings, w => w.Code == "acme_failing").Message;
        foreach (string leaked in new[] { "hunter2", "abc123", "ca.example", "secret line", "user:" })
        {
            Assert.DoesNotContain(leaked, message);
        }

        Assert.DoesNotContain('\n', message);
        Assert.Contains("failed 4 times in a row", message);
        Assert.Contains("the CA refused the request", message);

        // The pending text does not name the CA's directory either.
        await _storage.Config.UpsertAcmeRenewalAsync(new AcmeRenewalRecord("default", "ordering", T0, null, 0, null, null, null), default);
        string pending = Assert.Single((await new CertificateHealthContributor(_storage, _clock, config).CheckAsync(default)).Warnings, w => w.Code == "acme_pending").Message;
        Assert.DoesNotContain("hunter2", pending);
        Assert.DoesNotContain("ca.example", pending);
    }

    [Theory]
    [InlineData("ACME HTTP-01: :: port 80 is already in use (a web server or proxy on this host?). Stop what uses it", "the port for the HTTP-01 challenge could not be bound")]
    [InlineData("ACME HTTP-01: this process is not allowed to listen on :: port 80. Ports below 1024", "the port for the HTTP-01 challenge could not be bound")]
    [InlineData("ACME HTTP-01: cannot listen on :: port 80: x. Set Acme:Http01BindAddress", "the port for the HTTP-01 challenge could not be bound")]
    [InlineData("'*.example.com' is a wildcard name, which only DNS-01 can prove", "a wildcard name needs DNS-01")]
    [InlineData("The order includes the wildcard name *.example.com, which only DNS-01 can prove", "a wildcard name needs DNS-01")]
    [InlineData("This CA requires external account binding: set Acme:EabKeyId", "the CA needs or refused external account binding")]
    [InlineData("ACME server error: External account binding failed", "the CA needs or refused external account binding")]
    [InlineData("Authorization for mx.example.com ended as Invalid: Timeout during connect", "the CA could not validate the challenge")]
    [InlineData("The ACME server did not answer in time.", "the CA could not be reached")]
    [InlineData("The ACME server could not be reached or answered unexpectedly: Connection refused", "the CA could not be reached")]
    [InlineData("ACME server error: rateLimited", "the CA refused the request")]
    [InlineData("ACME error: bad thing", "the CA refused the request")]
    [InlineData("dns timeout", "the order failed")]
    [InlineData(null, "the order failed")]
    public void Failures_are_sorted_into_a_few_categories(string? error, string expected) => Assert.Equal(expected, AcmeFailureCategory.Describe(error));

    [Fact]
    public async Task A_failed_record_nobody_retries_is_neither_a_banner_nor_a_reason_to_wake_up()
    {
        var config = new MtaConfig { Acme = Options() };
        var contributor = new CertificateHealthContributor(_storage, _clock, config);
        var service = Service();

        // A dashboard request for names that were never issued: failed, recorded, and not retried by CheckOnceAsync (no certificate, not the configured set).
        Assert.True(await service.CheckOnceAsync(default));   // the configured certificate is issued first
        _ca.FailWith = new AcmeException("ACME server error: no");
        Assert.False(await service.RequestAsync(["orphan.http01.example"], default));
        var orphan = Assert.Single(await _storage.Config.GetAcmeRenewalsAsync(default), r => r.CertificateName.StartsWith("acme:", StringComparison.Ordinal));
        Assert.Equal("failed", orphan.Status);

        // The configured certificate is fine, so nothing is failing that anybody retries.
        var warnings = (await contributor.CheckAsync(default)).Warnings;
        Assert.DoesNotContain(warnings, w => w.Code.StartsWith("acme_", StringComparison.Ordinal));
        Assert.Equal(TimeSpan.FromHours(1), await service.NextCheckDelayAsync(default));   // the orphan's back-off does not make every replica poll

        // The admin view still has the record.
        Assert.Contains(await _storage.Config.GetAcmeRenewalsAsync(default), r => r.CertificateName == orphan.CertificateName && r.LastError == "ACME server error: no");

        // A failing configured certificate does show, next to the orphan: one banner, about the configured one.
        _ca.FailWith = new AcmeException("ACME server error: later");
        _clock.Advance(TimeSpan.FromDays(70));
        Assert.False(await service.CheckOnceAsync(default));
        string message = Assert.Single((await contributor.CheckAsync(default)).Warnings, w => w.Code == "acme_failing").Message;
        Assert.DoesNotContain("more certificate", message);
        Assert.NotEqual(TimeSpan.FromHours(1), await service.NextCheckDelayAsync(default));
    }

    [Fact]
    public void A_request_does_not_print_the_account_key_or_the_EAB_key()
    {
        var request = new AcmeOrderRequest("https://ca.example/dir", "ops@example.com", ["a.example"], "-----BEGIN PRIVATE KEY-----SECRETKEY", TimeSpan.Zero,
            EabKeyId: "kid-1", EabHmacKey: "HMACSECRET-_abc");

        string text = request.ToString();

        Assert.DoesNotContain("SECRETKEY", text);
        Assert.DoesNotContain("HMACSECRET", text);
        Assert.DoesNotContain("ops@example.com", text);
        Assert.Contains("a.example", text);
    }

    [Fact]
    public async Task No_acme_warning_when_acme_is_off()
    {
        await _storage.Config.UpsertAcmeRenewalAsync(new AcmeRenewalRecord("default", "failed", T0, T0.AddHours(1), 4, "old", null, null), default);

        var warnings = (await new CertificateHealthContributor(_storage, _clock, new MtaConfig()).CheckAsync(default)).Warnings;

        Assert.DoesNotContain(warnings, w => w.Code.StartsWith("acme_", StringComparison.Ordinal));
    }

    /// <summary>A CA that issues 90-day self-signed certificates, can be told to fail, and keeps the orders it saw.</summary>
    private sealed class ScriptedCa(TestClock clock) : IAcmeOrderRunner
    {
        public List<AcmeOrderRequest> Orders { get; } = [];

        public Exception? FailWith { get; set; }

        public async Task<AcmeIssuedCertificate> IssueAsync(AcmeOrderRequest request, IDnsChallengeProvider dns, CancellationToken cancellationToken)
        {
            Orders.Add(request);
            if (FailWith is not null)
            {
                throw FailWith;
            }

            if (request.AccountKeyPem is null && request.AccountCreated is { } created)
            {
                await created(new AcmeAccountCreated("-----BEGIN PRIVATE KEY-----\nQUNNRQ==\n-----END PRIVATE KEY-----", "https://ca.example/acct/1"), cancellationToken);
            }

            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var req = new CertificateRequest("CN=" + request.Domains[0], key, HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();
            foreach (string d in request.Domains)
            {
                san.AddDnsName(d);
            }

            req.CertificateExtensions.Add(san.Build());
            using X509Certificate2 cert = req.CreateSelfSigned(clock.UtcNow.AddMinutes(-5), clock.UtcNow.AddDays(90));
            return new AcmeIssuedCertificate(cert.ExportCertificatePem(), key.ExportPkcs8PrivateKey(), "-----BEGIN PRIVATE KEY-----\nQUNNRQ==\n-----END PRIVATE KEY-----", "https://ca.example/acct/1", cert.NotAfter.ToUniversalTime());
        }
    }
}
