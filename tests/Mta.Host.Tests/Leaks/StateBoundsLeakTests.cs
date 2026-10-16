using System.Net;
using Mta.Policy;
using Mta.Smtp.Client;
using Mta.TestSupport;
using Xunit.Abstractions;

namespace Mta.Host.Tests.Leaks;

/// <summary>
/// Accelerated lifecycle, leaks: per-key state that lives in memory for as long as the process does. A mail server meets a new destination domain,
/// MX host or relay all day for weeks, so every table keyed by one has to forget idle keys. Each test feeds thousands of distinct keys through the
/// real component on a virtual clock (a virtual day in a few thousand iterations) and requires the number of tracked keys to stop growing: a table
/// that never forgets would grow by the size of a batch every batch.
/// </summary>
[Collection(LeakCollection.Name)]
public sealed class StateBoundsLeakTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Leak_destination_throttle_forgets_idle_destinations()
    {
        var clock = new VirtualClock();
        var throttle = new DestinationThrottle(clock, new DestinationThrottleOptions { IdleEviction = TimeSpan.FromMinutes(15), SweepInterval = TimeSpan.FromMinutes(1) });
        int n = 0;

        using var probe = new LeakProbe(output.WriteLine);
        probe.Track("tracked destinations", () => throttle.TrackedKeyCount, absolute: 90);   // a sweep runs every minute: the table swings by a minute of new keys
        LeakReport report = await probe.RunAsync(_ =>
        {
            // One new destination a second, so a batch of 2,000 spans 33 virtual minutes: more than the idle time.
            clock.Advance(TimeSpan.FromSeconds(1));
            var key = new ThrottleKey($"domain{Interlocked.Increment(ref n)}.example");
            ThrottleResult result = throttle.TryAcquire(key);
            Assert.True(result.Acquired);
            result.Lease!.Report(ThrottleSignal.Success);
            result.Lease.Dispose();
        }, Accelerated.Scaled(2000));
        report.AssertNoGrowth();
        Assert.InRange(throttle.TrackedKeyCount, 1, 1100);   // about 15 minutes of keys, not 8,000
    }

    [Fact]
    public async Task Leak_route_health_forgets_idle_mx_hosts()
    {
        var clock = new VirtualClock();
        var health = new RouteHealth(clock, new RouteHealthOptions { IdleEviction = TimeSpan.FromHours(1) });
        int n = 0;

        using var probe = new LeakProbe(output.WriteLine);
        probe.Track("tracked MX hosts and routes", () => health.TrackedCount, absolute: 400);
        LeakReport report = await probe.RunAsync(_ =>
        {
            // A new MX host every 3 seconds (1,200 an hour); one in five fails once, the way a bad host does.
            clock.Advance(TimeSpan.FromSeconds(3));
            int i = Interlocked.Increment(ref n);
            var key = RouteHealthKey.ForMxHost($"mx{i}.example");
            Assert.Equal(RouteAdmission.Allowed, health.TryAdmit(key));
            if (i % 5 == 0)
            {
                health.ReportFailure(key, "connect timed out");
            }
            else
            {
                health.ReportSuccess(key);
            }
        }, Accelerated.Scaled(2000));
        report.AssertNoGrowth();
        Assert.InRange(health.TrackedCount, 1, 3000);   // about an hour of hosts (1,200), not 8,000
    }

    [Fact]
    public async Task Leak_outbound_connection_pool_never_holds_more_idle_connections_than_its_ceiling()
    {
        // Many different targets (a pool key is the host, address, port, TLS policy and credentials) all answered by one server.
        await using var server = new PoolPeer();
        var clock = new VirtualClock();
        await using var pool = new SmtpConnectionPool(
            new SmtpClientOptions { HeloName = "client.test", BannerTimeout = TimeSpan.FromSeconds(60), CommandTimeout = TimeSpan.FromSeconds(60) },
            clock, maxIdlePerTarget: 1, maxIdleTotal: 8);
        int n = 0;

        using var probe = new LeakProbe(output.WriteLine);
        probe.TrackArrayPoolBalance();
        probe.Track("idle pooled connections", () => pool.IdleConnections, absolute: 0);
        probe.Track("server sessions open", () => server.ActiveConnections, absolute: 4);
        LeakReport report = await probe.RunAsync(async _ =>
        {
            var target = new SmtpRemoteTarget { Host = $"mx{Interlocked.Increment(ref n)}.example", Address = IPAddress.Loopback, Port = server.Port, Tls = SmtpTlsPolicy.Disabled };
            await using PooledConnection lease = await pool.RentAsync(target);
            Assert.Equal(220, lease.Connection.Banner.Code);
        }, Accelerated.Scaled(150));
        report.AssertNoGrowth();
        Assert.InRange(pool.IdleConnections, 0, 8);
    }

    /// <summary>A server that greets and answers QUIT/RSET/NOOP; nothing else is needed to rent and return connections.</summary>
    private sealed class PoolPeer : IAsyncDisposable
    {
        private readonly Mta.Smtp.Server.SmtpServer _server;

        public PoolPeer()
        {
            _server = new Mta.Smtp.Server.SmtpServer(new Mta.Smtp.Server.SmtpServerOptions
            {
                Hostname = "mx.pool.test",
                MaxConnectionsPerIp = 10_000,
                Listeners = [new Mta.Smtp.Server.SmtpListenerOptions { Name = "mx", BindAddress = IPAddress.Loopback, Port = 0, Mode = Mta.Smtp.Server.ListenerMode.Plain, AuthRequired = false, Role = Mta.Smtp.Server.ListenerRole.Bounce }],
            }, new NullHandler());
            _server.Start();
            Port = _server.LocalEndPoints["mx"].Port;
        }

        public int Port { get; }

        public int ActiveConnections => _server.ActiveConnections;

        public ValueTask DisposeAsync() => _server.DisposeAsync();
    }

    private sealed class NullHandler : Mta.Smtp.Server.ISmtpServerHandler
    {
        public ValueTask<Mta.Smtp.Protocol.SmtpReply?> OnConnectedAsync(Mta.Smtp.Server.SmtpSessionContext session, CancellationToken ct) => ValueTask.FromResult<Mta.Smtp.Protocol.SmtpReply?>(null);

        public ValueTask<Mta.Smtp.Server.SmtpAuthResult> AuthenticateAsync(Mta.Smtp.Server.SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct) =>
            ValueTask.FromResult(Mta.Smtp.Server.SmtpAuthResult.Failed);

        public ValueTask<Mta.Smtp.Protocol.SmtpReply> OnMailFromAsync(Mta.Smtp.Server.SmtpSessionContext session, Mta.Smtp.Server.MailFromInfo mail, CancellationToken ct) =>
            ValueTask.FromResult(Mta.Smtp.Protocol.SmtpReplies.SenderOk);

        public ValueTask<Mta.Smtp.Protocol.SmtpReply> OnRcptToAsync(Mta.Smtp.Server.SmtpSessionContext session, Mta.Smtp.Server.MailFromInfo mail, Mta.Core.EmailAddress recipient, Mta.Smtp.Protocol.RcptParameters p, CancellationToken ct) =>
            ValueTask.FromResult(Mta.Smtp.Protocol.SmtpReplies.RecipientOk);

        public ValueTask<Mta.Smtp.Protocol.SmtpReply> OnMessageAsync(Mta.Smtp.Server.SmtpMessage message, CancellationToken ct) =>
            ValueTask.FromResult(Mta.Smtp.Protocol.SmtpReply.Create(250, "2.0.0", "Queued"));

        public void OnDisconnected(Mta.Smtp.Server.SmtpSessionContext session)
        {
        }
    }
}
