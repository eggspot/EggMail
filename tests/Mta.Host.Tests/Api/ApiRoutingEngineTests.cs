using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Mta.Core;
using Mta.Delivery;
using Mta.Dns;
using Mta.Dsn;
using Mta.Host.Api;
using Mta.Policy;
using Mta.Smtp.Client;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Tls;

namespace Mta.Host.Tests.Api;

/// <summary>
/// The whole chain: an administrator changes relay routes and TLS policies through the HTTP API, the notifier asks the real delivery engine to reload, and the
/// next delivery follows the change. No test sleeps; it waits for the engine's reload counter and for stored events.
/// </summary>
[Collection("api")]
public class ApiRoutingEngineTests : IAsyncLifetime
{
    private sealed class Sink : ISmtpServerHandler
    {
        public int Accepted;

        public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken ct) => ValueTask.FromResult<SmtpReply?>(null);

        public ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct) => ValueTask.FromResult(SmtpAuthResult.Failed);

        public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.SenderOk);

        public ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters parameters, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.RecipientOk);

        public ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
        {
            Interlocked.Increment(ref Accepted);
            return ValueTask.FromResult(SmtpReply.Create(250, "2.0.0", "Accepted"));
        }

        public void OnDisconnected(SmtpSessionContext session)
        {
        }
    }

    private sealed class EngineNotifier : IRoutingConfigNotifier
    {
        public DeliveryEngine? Engine;

        public void Changed() => Engine?.RequestConfigRefresh();
    }

    private readonly Sink _sink = new();
    private readonly EngineNotifier _notifier = new();
    private readonly CancellationTokenSource _stop = new();
    private SmtpServer _server = null!;
    private ApiFixture _f = null!;
    private ApiClient _admin = null!;
    private DeliveryEngine _engine = null!;
    private DeliveryServices _services = null!;
    private Task _run = Task.CompletedTask;
    private int _port;

    public async Task InitializeAsync()
    {
        _server = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "mx.dest.example",
            Listeners = [new SmtpListenerOptions { Name = "mx", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce }],
        }, _sink);
        _server.Start();
        _port = _server.LocalEndPoints["mx"].Port;

        _f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureServices = s => s.AddSingleton<IRoutingConfigNotifier>(_notifier) });
        _admin = await _f.SignedInAsync("root");

        var dns = new StaticDnsResolver();
        dns.AddMx("dest.example", 10, "mx.dest.example").AddA("mx.dest.example", "127.0.0.1");
        var clock = SystemClock.Instance;
        var options = new DeliveryOptions { Owner = "test", Hostname = "egg.test", RemotePort = _port, IdlePoll = TimeSpan.FromMilliseconds(30), ConfigRefreshInterval = TimeSpan.FromHours(1), BounceDomain = null };
        _services = new DeliveryServices
        {
            Storage = _f.Storage,
            Clock = clock,
            Mx = new MxResolver(dns, new MxResolverOptions { ExcludeSpecialAddresses = false }),
            Tls = new OutboundTlsPolicyResolver(null, null),
            TlsPolicies = new TlsPolicyTable(OutboundTlsConfiguration.Default),
            Pool = new SmtpConnectionPool(new SmtpClientOptions { HeloName = "egg.test", ConnectTimeout = TimeSpan.FromSeconds(5) }, clock),
            Routes = new RoutePlanner(new RouteHealth(clock)) { DirectMxAvailable = false },
            Throttle = new DestinationThrottle(clock),
            Limits = new SendingLimits(clock, null, null),
            Retry = new RetrySchedule(),
            Secrets = _f.Protector,
        };
        _engine = new DeliveryEngine(new DeliveryProcessor(_services, options, new DsnService(_f.Storage, clock, options)), _services, options);
        _notifier.Engine = _engine;
        _run = Task.Run(() => _engine.RunAsync(_stop.Token));
        await Wait(() => _engine.ConfigRefreshCount >= 1);
    }

    public async Task DisposeAsync()
    {
        await _stop.CancelAsync();
        try { await _run; } catch (OperationCanceledException) { }
        await _services.Pool.DisposeAsync();
        await _server.DisposeAsync();
        await _f.DisposeAsync();
    }

    private static async Task Wait(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "condition not met in time");
            await Task.Delay(10);
        }
    }

    private async Task<Guid> EnqueueAsync(string to)
    {
        var now = DateTimeOffset.UtcNow;
        var id = Ids.New(now);
        await _f.Storage.Intake.AcceptAsync(new AcceptedMessage
        {
            MessageId = id,
            TenantId = ApiFixture.TenantAId,
            Source = MessageSource.Smtp,
            EnvelopeFrom = EmailAddress.Parse("sender@example.com"),
            Recipients = [new AcceptedRecipient(Ids.New(now), EmailAddress.Parse(to))],
            Raw = System.Text.Encoding.ASCII.GetBytes($"From: sender@example.com\r\nTo: {to}\r\nSubject: Hi\r\nMessage-ID: <{Guid.NewGuid():N}@example.com>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n\r\nBody\r\n"),
            ReceivedAt = now,
            ExpiresAt = now.AddDays(5),
            SendingDomain = "example.com",
        }, default);
        _engine.Wake();
        return id;
    }

    private async Task<IReadOnlyList<MessageEvent>> WaitForEventAsync(Guid id, MessageEventType type)
    {
        IReadOnlyList<MessageEvent> events = [];
        await Wait(() =>
        {
            events = _f.Storage.History.GetEventsAsync(ApiFixture.TenantAId, id, default).AsTask().Result;
            return events.Any(e => e.Type == type);
        });
        return events;
    }

    [Fact]
    public async Task A_relay_created_through_the_api_carries_the_next_delivery_and_deleting_it_stops_that()
    {
        long before = _engine.ConfigRefreshCount;
        Reply created = await _admin.PostAsync("/api/v1/admin/relay-routes", new
        {
            name = "backup",
            host = "mx.dest.example",
            port = _port,
            tlsMode = "none",
            domains = new[] { "dest.example" },
        });
        Assert.Equal(HttpStatusCode.Created, created.Status);
        // The notifier asked for a reload. The interval is an hour, so only the request can explain a reload within this test.
        await Wait(() => _engine.ConfigRefreshCount >= before + 1);
        long afterRequest = _engine.ConfigRefreshCount;

        var id = await EnqueueAsync("rcpt@dest.example");
        var events = await WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.Equal("backup", events.Single(e => e.Type == MessageEventType.Delivered).Route);
        Assert.Equal(1, _sink.Accepted);

        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync("/api/v1/admin/relay-routes/" + created.Str("id"))).Status);
        await Wait(() => _engine.ConfigRefreshCount > afterRequest);
        await EnqueueAsync("other@dest.example");
        await Wait(() => _f.Storage.Deliveries.GetQueueStatsAsync(default).AsTask().Result is { Queued: 1, Leased: 0 } s && s.OldestDueAt > DateTimeOffset.UtcNow);
        Assert.Equal(1, _sink.Accepted); // no route any more: held, nothing sent
    }

    [Fact]
    public async Task A_tls_policy_created_through_the_api_makes_the_next_delivery_require_tls()
    {
        _services.Routes.DirectMxAvailable = true;
        long before = _engine.ConfigRefreshCount;
        Reply created = await _admin.PostAsync("/api/v1/admin/tls-policies", new { domainPattern = "dest.example", level = "encrypt" });
        Assert.Equal(HttpStatusCode.Created, created.Status);
        await Wait(() => _engine.ConfigRefreshCount >= before + 1);

        var refused = await EnqueueAsync("a@dest.example");
        await WaitForEventAsync(refused, MessageEventType.Deferred); // the sink offers no STARTTLS
        Assert.Equal(0, _sink.Accepted);

        before = _engine.ConfigRefreshCount;
        Assert.Equal("may", (await _admin.PatchAsync("/api/v1/admin/tls-policies/" + created.Str("id"), new { level = "may" })).Str("level"));
        await Wait(() => _engine.ConfigRefreshCount >= before + 1);
        var accepted = await EnqueueAsync("b@dest.example");
        var events = await WaitForEventAsync(accepted, MessageEventType.Delivered);
        Assert.Equal("direct", events.Single(e => e.Type == MessageEventType.Delivered).Route);
        Assert.Equal(1, _sink.Accepted);
    }
}
