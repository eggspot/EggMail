using System.Net;
using System.Net.Sockets;
using Mta.Tls.MtaSts;
using Mta.Tls.TlsRpt;

namespace Mta.Tls.Tests;

/// <summary>
/// Security regression tests (docs/security-test-map.md, SSRF-6 and SSRF-7): the MTA-STS policy fetch and the TLS-RPT report upload go to
/// addresses that the recipient's DNS chooses, so the default handler must never connect to an internal address, whatever the URL says.
/// Real sockets on loopback count the connections that would have been made. This is the in-house review, not an independent audit.
/// </summary>
public sealed class OutboundHttpSsrfTests
{
    /// <summary>Accepts connections on a loopback port and only counts them.</summary>
    private sealed class CountingListener : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private int _accepted;
        private readonly Task _loop;

        public CountingListener()
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _loop = Task.Run(async () =>
            {
                while (true)
                {
                    try
                    {
                        using TcpClient c = await _listener.AcceptTcpClientAsync();
                        Interlocked.Increment(ref _accepted);
                    }
                    catch (Exception ex) when (ex is ObjectDisposedException or SocketException or InvalidOperationException)
                    {
                        return;
                    }
                }
            });
        }

        public int Port { get; }

        public int Accepted => Volatile.Read(ref _accepted);

        public void Dispose()
        {
            _listener.Stop();
            _loop.Wait(TimeSpan.FromSeconds(5));
        }
    }

    private static readonly TlsRptEndpoint Unused = new(TlsRptEndpointKind.Https, "https://unused.example/", null);

    private static TlsRptReport Report()
    {
        var collector = new TlsRptCollector(new Support.TestClock());
        collector.RecordSuccess("example.com", TlsRptPolicyDescriptor.NoPolicy, "mx.example.com");
        return new TlsRptReportBuilder(new TlsRptReportOptions { OrganizationName = "o", ContactInfo = "c@example.com", SubmitterDomain = "s.example" }).Build(collector.Snapshot().Single());
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("[::1]")]
    [InlineData("[::ffff:127.0.0.1]")]
    [InlineData("[::ffff:7f00:1]")]
    [InlineData("localhost")]
    [InlineData("2130706433")]
    [InlineData("0x7f000001")]
    [InlineData("127.1")]
    public async Task A_report_endpoint_in_the_recipients_DNS_that_points_to_this_machine_is_never_connected_to(string host)
    {
        using var listener = new CountingListener();
        using var sender = new TlsRptHttpsSender();

        var result = await sender.SendAsync(new TlsRptEndpoint(TlsRptEndpointKind.Https, $"https://{host}:{listener.Port}/report", null), Report());

        Assert.False(result.Success);
        Assert.Equal(0, listener.Accepted);
    }

    [Fact]
    public async Task The_same_endpoint_is_connected_to_only_when_the_operator_allows_non_public_addresses()
    {
        // Control: the listener is reachable, so the zero above is the guard.
        using var listener = new CountingListener();
        using var sender = new TlsRptHttpsSender(options: new TlsRptHttpsSenderOptions { AllowNonPublicAddresses = true });

        var result = await sender.SendAsync(new TlsRptEndpoint(TlsRptEndpointKind.Https, $"https://127.0.0.1:{listener.Port}/report", null), Report());

        Assert.False(result.Success);   // there is no TLS server behind the listener
        Assert.True(listener.Accepted >= 1);
    }

    [Theory]
    [InlineData("http://reports.example.com/x")]
    [InlineData("file:///etc/passwd")]
    [InlineData("gopher://reports.example.com/")]
    public async Task Only_https_report_endpoints_are_posted_to(string uri)
    {
        using var sender = new TlsRptHttpsSender();
        var result = await sender.SendAsync(new TlsRptEndpoint(TlsRptEndpointKind.Https, uri, null), Report());
        Assert.False(result.Success);
        Assert.Equal("endpoint is not an https URI", result.Error);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("10.0.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("2130706433")]
    [InlineData("[::ffff:7f00:1]")]
    [InlineData("localhost")]
    [InlineData("a b")]
    [InlineData("example.com/../../x")]
    [InlineData("example.com\r\nHost: evil")]
    public async Task A_policy_domain_that_is_an_address_or_carries_control_text_is_not_fetched(string domain)
    {
        using var fetcher = new MtaStsPolicyFetcher();

        var result = await fetcher.FetchAsync(domain);

        Assert.False(result.IsSuccess);
    }

    [Theory]
    [InlineData("http://127.0.0.1")]
    [InlineData("http://[::1]")]
    [InlineData("http://169.254.169.254")]
    [InlineData("http://[fd00:ec2::254]")]
    [InlineData("http://[64:ff9b::7f00:1]")]
    [InlineData("http://[2002:a9fe:a9fe::]")]
    [InlineData("http://10.0.0.1")]
    [InlineData("http://192.168.1.1")]
    [InlineData("http://localhost")]
    public async Task The_default_handler_refuses_internal_targets_before_connecting(string origin)
    {
        using var listener = new CountingListener();
        using SocketsHttpHandler handler = SafeHttpHandler.Create(TimeSpan.FromSeconds(5), allowNonPublicAddresses: false);
        using var client = new HttpClient(handler);
        Uri target = new UriBuilder(origin) { Port = listener.Port, Path = "/" }.Uri;

        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(target));
        Assert.Equal(0, listener.Accepted);
    }

    [Fact]
    public void The_default_handler_never_follows_redirects_uses_no_proxy_and_asks_for_TLS_1_2_or_later()
    {
        using SocketsHttpHandler handler = SafeHttpHandler.Create(TimeSpan.FromSeconds(5), allowNonPublicAddresses: false);

        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseProxy);
        Assert.False(handler.UseCookies);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
        Assert.NotNull(handler.ConnectCallback);
        Assert.Equal(System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, handler.SslOptions.EnabledSslProtocols);
        Assert.True(handler.MaxResponseHeadersLength <= 16);
    }

    [Fact]
    public async Task A_proxy_in_the_environment_is_not_used_for_the_policy_fetch()
    {
        string? before = Environment.GetEnvironmentVariable("HTTPS_PROXY");
        using var proxy = new CountingListener();
        Environment.SetEnvironmentVariable("HTTPS_PROXY", $"http://127.0.0.1:{proxy.Port}");
        try
        {
            using SocketsHttpHandler handler = SafeHttpHandler.Create(TimeSpan.FromSeconds(5), allowNonPublicAddresses: false);
            using var client = new HttpClient(handler);
            // Whatever happens to the request (no network in the test), it must not go through the configured proxy.
            try { await client.GetAsync("https://127.0.0.1:9/"); } catch (HttpRequestException) { }
            Assert.Equal(0, proxy.Accepted);
        }
        finally
        {
            Environment.SetEnvironmentVariable("HTTPS_PROXY", before);
        }
    }
}
