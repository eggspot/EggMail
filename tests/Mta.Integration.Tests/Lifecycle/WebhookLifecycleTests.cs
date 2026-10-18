using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Mta.Core;
using Mta.Host.Ingest;
using Mta.Storage;
using Mta.TestSupport;
using Mta.Webhooks;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>
/// The webhook dispatcher over days of virtual time, on each storage backend: the real <see cref="WebhookDispatcher"/>, the real outbox and attempt log, the real
/// <see cref="EndpointDisabledNotifier"/>, a scripted HTTP receiver, and a virtual clock the test moves. Proves the retry ladder instants, the endpoint auto-disable rule, re-enabling, replay,
/// the retention of the outbox and of the attempt log, and that the SSRF guard looks at the address again on every attempt; it does not exercise a real network or a real receiver.
/// </summary>
public abstract class WebhookLifecycleTests(LifecycleBackend backend) : IAsyncLifetime
{
    private static readonly Guid TenantId = LifecycleHarness.TenantId;
    private readonly VirtualClock _clock = new();
    private readonly RecordingLog _log = new();
    private readonly List<IStorage> _storages = [];
    private readonly List<WebhookDispatcher> _dispatchers = [];
    private bool Unavailable => backend.Unavailable;

    public Task InitializeAsync() => backend.PrepareAsync();

    public async Task DisposeAsync()
    {
        foreach (var d in _dispatchers)
        {
            await d.DisposeAsync();
        }

        foreach (var s in _storages)
        {
            await s.DisposeAsync();
        }

        await backend.CleanupAsync();
    }

    /// <summary>The documented ladder after the first, immediate attempt (docs/decisions.md item 16): 5 s, 5 m, 30 m, 2 h, 5 h, 10 h, 10 h.</summary>
    private static readonly TimeSpan[] DocumentedLadder = [TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(30), TimeSpan.FromHours(2), TimeSpan.FromHours(5), TimeSpan.FromHours(10), TimeSpan.FromHours(10)];

    /// <summary>A receiver that answers per URL and records every request with the virtual instant it was made at.</summary>
    private sealed class ScriptedReceiver(IClock clock) : HttpMessageHandler
    {
        public ConcurrentQueue<(string Url, string Body, DateTimeOffset At)> Requests { get; } = new();

        public Func<string, HttpStatusCode> Status { get; set; } = _ => HttpStatusCode.OK;

        public bool Hang { get; set; }

        public int Count(string urlPart) => Requests.Count(r => r.Url.Contains(urlPart, StringComparison.Ordinal));

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string url = request.RequestUri!.ToString();
            string body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
            Requests.Enqueue((url, body, clock.UtcNow));
            if (Hang)
            {
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }

            return new HttpResponseMessage(Status(url)) { Content = new StringContent("answer from the receiver") };
        }
    }

    private sealed class PlainProtector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => plaintext.ToArray();

        public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose) => protectedData.ToArray();
    }

    private sealed record Fixture(IStorage Storage, WebhookDispatcher Dispatcher, ScriptedReceiver Receiver, VirtualClock Clock)
    {
        public async Task<int> RunAsync()
        {
            int total = 0;
            int n;
            while ((n = await Dispatcher.RunOnceAsync(default)) > 0)
            {
                total += n;
            }

            return total;
        }

        public async Task<Guid> AddEndpointAsync(string name, params string[] types)
        {
            var endpoint = new WebhookEndpointRecord(Ids.New(), TenantId, $"https://hooks.example/{name}", Encoding.UTF8.GetBytes(StandardWebhooksSigner.GenerateSecret()), types, true, null, null, Clock.UtcNow, null);
            await Storage.Config.UpsertWebhookEndpointAsync(endpoint, default);
            return endpoint.Id;
        }

        public async Task<int> EnqueueAsync(string type = WebhookEventFactory.Delivered) =>
            await Storage.Webhooks.EnqueueAsync(TenantId, new WebhookEventDraft(Ids.New(), type, "{\"type\":\"" + type + "\",\"data\":{}}"), Clock.UtcNow, default);

        public async Task<IReadOnlyList<WebhookAttemptRecord>> AttemptsAsync(Guid endpointId) =>
            (await Storage.Webhooks.GetAttemptsAsync(TenantId, endpointId, 1000, default)).OrderBy(a => a.At).ToList();

        public async Task<WebhookEndpointRecord> EndpointAsync(Guid id) => (await Storage.Config.GetWebhookEndpointAsync(id, default))!;

        /// <summary>Moves time forward in steps (maintenance runs once per virtual day, as the host's maintenance service does) and runs the dispatcher after every step.</summary>
        public async Task AdvanceAsync(TimeSpan by, TimeSpan step, Func<Task>? after = null)
        {
            DateTimeOffset end = Clock.UtcNow + by;
            while (Clock.UtcNow < end)
            {
                long day = Clock.UtcNow.UtcTicks / TimeSpan.TicksPerDay;
                Clock.Advance(TimeSpan.FromTicks(Math.Min(step.Ticks, (end - Clock.UtcNow).Ticks)));
                if (Clock.UtcNow.UtcTicks / TimeSpan.TicksPerDay != day)
                {
                    await Storage.Maintenance.RunAsync(Clock.UtcNow, default);
                }

                await RunAsync();
                if (after is not null)
                {
                    await after();
                }
            }
        }
    }

    private async Task<Fixture> NewFixtureAsync(Func<StorageOptions, StorageOptions>? options = null, WebhookOptions? webhookOptions = null, Func<string, CancellationToken, ValueTask<IPAddress[]>>? resolver = null, ScriptedReceiver? receiver = null, bool useRealHttp = false)
    {
        StorageOptions o = backend.NewStorageOptions();
        if (options is not null)
        {
            o = options(o);
        }

        IStorage storage = backend.CreateStorage(o, _clock);
        _storages.Add(storage);
        await storage.InitializeAsync(default);
        await storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, _clock.UtcNow, false), default);
        receiver ??= new ScriptedReceiver(_clock);
        var dispatcher = new WebhookDispatcher(storage.Webhooks, storage.Config, new PlainProtector(), webhookOptions ?? new WebhookOptions { PollInterval = TimeSpan.FromMilliseconds(10) },
            _clock, _log, new EndpointDisabledNotifier(storage, _clock, _log), resolver, useRealHttp ? null : receiver);
        _dispatchers.Add(dispatcher);
        return new Fixture(storage, dispatcher, receiver, _clock);
    }

    [Fact]
    public void The_default_options_are_the_documented_ones()
    {
        var options = new WebhookOptions();
        Assert.Equal(DocumentedLadder, options.RetrySchedule);
        Assert.Equal(TimeSpan.FromSeconds(15), options.Timeout);
        Assert.Equal(TimeSpan.FromDays(5), options.DisableAfter);
        var retention = new RetentionOptions();
        Assert.Equal(7, retention.WebhookOutboxDays);
        Assert.Equal(7, retention.WebhookAttemptLogDays);
    }

    [Fact]
    public async Task A_failing_receiver_gets_exactly_the_documented_attempts_at_exactly_the_documented_instants_and_then_none()
    {
        if (Unavailable)
        {
            return;
        }

        var f = await NewFixtureAsync();
        f.Receiver.Status = _ => HttpStatusCode.InternalServerError;
        Guid endpoint = await f.AddEndpointAsync("ladder", WebhookEventFactory.Delivered);
        DateTimeOffset t0 = f.Clock.UtcNow;
        Assert.Equal(1, await f.EnqueueAsync());

        Assert.Equal(1, await f.Dispatcher.RunOnceAsync(default));   // the first attempt is immediate
        TimeSpan elapsed = TimeSpan.Zero;
        foreach (TimeSpan delay in DocumentedLadder)
        {
            f.Clock.Advance(delay - TimeSpan.FromSeconds(1));
            Assert.Equal(0, await f.Dispatcher.RunOnceAsync(default));   // not yet
            f.Clock.Advance(TimeSpan.FromSeconds(1));
            Assert.Equal(1, await f.Dispatcher.RunOnceAsync(default));
            elapsed += delay;
            Assert.Equal(t0 + elapsed, f.Clock.UtcNow);
        }

        var attempts = await f.AttemptsAsync(endpoint);
        Assert.Equal(DocumentedLadder.Length + 1, attempts.Count);   // 8 in all
        Assert.Equal(t0, attempts[0].At);
        for (int i = 0; i < DocumentedLadder.Length; i++)
        {
            Assert.Equal(DocumentedLadder[i], attempts[i + 1].At - attempts[i].At);
        }

        Assert.All(attempts, a => { Assert.Equal(500, a.StatusCode); Assert.Equal("http_500", a.ErrorClass); });

        // The ladder is over: the item is failed for good, however much time passes.
        f.Clock.Advance(TimeSpan.FromDays(10));
        Assert.Equal(0, await f.RunAsync());
        Assert.Equal(DocumentedLadder.Length + 1, (await f.AttemptsAsync(endpoint)).Count);
        Assert.Equal(DocumentedLadder.Length + 1, f.Receiver.Requests.Count);
        // 27.6 hours of failure is less than the 5 days an endpoint may fail for: it stays enabled.
        Assert.True((await f.EndpointAsync(endpoint)).Enabled);
    }

    [Fact]
    public async Task A_throttling_answer_adds_a_minute_a_timeout_is_classified_and_the_ladder_goes_on_after_both()
    {
        if (Unavailable)
        {
            return;
        }

        var f = await NewFixtureAsync(webhookOptions: new WebhookOptions { Timeout = TimeSpan.FromMilliseconds(150), PollInterval = TimeSpan.FromMilliseconds(10) });
        Guid endpoint = await f.AddEndpointAsync("slow", WebhookEventFactory.Delivered);
        await f.EnqueueAsync();
        f.Receiver.Hang = true;
        Assert.Equal(1, await f.Dispatcher.RunOnceAsync(default));
        f.Receiver.Hang = false;
        f.Receiver.Status = _ => HttpStatusCode.TooManyRequests;
        f.Clock.Advance(DocumentedLadder[0]);
        Assert.Equal(1, await f.Dispatcher.RunOnceAsync(default));

        // Throttled: the next attempt waits the ladder's 5 minutes plus the extra minute.
        f.Clock.Advance(DocumentedLadder[1]);
        Assert.Equal(0, await f.Dispatcher.RunOnceAsync(default));
        f.Clock.Advance(new WebhookOptions().ThrottleExtraDelay);
        f.Receiver.Status = _ => HttpStatusCode.OK;
        Assert.Equal(1, await f.Dispatcher.RunOnceAsync(default));

        var attempts = await f.AttemptsAsync(endpoint);
        Assert.Equal(["timeout", "throttled", null], attempts.Select(a => a.ErrorClass));
        Assert.Equal(200, attempts[2].StatusCode);
        Assert.Equal(0, await f.RunAsync());
    }

    [Fact]
    public async Task A_gone_answer_disables_the_endpoint_at_once_and_tells_the_tenants_other_endpoint_exactly_once()
    {
        if (Unavailable)
        {
            return;
        }

        var f = await NewFixtureAsync();
        f.Receiver.Status = url => url.EndsWith("/gone", StringComparison.Ordinal) ? HttpStatusCode.Gone : HttpStatusCode.OK;
        Guid gone = await f.AddEndpointAsync("gone", WebhookEventFactory.Delivered);
        await f.AddEndpointAsync("observer", WebhookEventFactory.EndpointDisabled);
        await f.EnqueueAsync();
        await f.RunAsync();

        var endpoint = await f.EndpointAsync(gone);
        Assert.False(endpoint.Enabled);
        Assert.Contains("410", endpoint.DisabledReason);
        Assert.Equal(f.Clock.UtcNow, endpoint.DisabledAt);
        Assert.Equal(1, f.Receiver.Count("/gone"));   // not retried
        Assert.Equal(1, f.Receiver.Count("/observer"));
        Assert.Contains("\"webhook.endpoint.disabled\"", f.Receiver.Requests.Single(r => r.Url.EndsWith("/observer", StringComparison.Ordinal)).Body);

        await f.AdvanceAsync(TimeSpan.FromDays(3), TimeSpan.FromHours(6));
        Assert.Equal(1, f.Receiver.Count("/gone"));
        Assert.Equal(1, f.Receiver.Count("/observer"));
    }

    [Fact]
    public async Task An_endpoint_that_fails_continuously_is_disabled_at_the_first_failure_after_five_days_not_before_and_the_tenant_is_told_once()
    {
        if (Unavailable)
        {
            return;
        }

        var f = await NewFixtureAsync();
        f.Receiver.Status = url => url.EndsWith("/down", StringComparison.Ordinal) ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK;
        Guid down = await f.AddEndpointAsync("down", WebhookEventFactory.Delivered);
        await f.AddEndpointAsync("observer", WebhookEventFactory.EndpointDisabled);
        DateTimeOffset t0 = f.Clock.UtcNow;
        DateTimeOffset? disabledAt = null;
        DateTimeOffset nextEvent = t0;

        // A new event every 6 hours for 8 days; the dispatcher runs every 30 minutes.
        await f.AdvanceAsync(TimeSpan.FromDays(8), TimeSpan.FromMinutes(30), async () =>
        {
            if (f.Clock.UtcNow >= nextEvent && (await f.EndpointAsync(down)).Enabled)
            {
                await f.EnqueueAsync();
                nextEvent += TimeSpan.FromHours(6);
                await f.RunAsync();
            }

            var e = await f.EndpointAsync(down);
            if (!e.Enabled && disabledAt is null)
            {
                disabledAt = e.DisabledAt;
            }
        });

        Assert.NotNull(disabledAt);
        // "Failing since" is the first failed attempt (t0); the endpoint goes at the first failed attempt five days later, never before.
        Assert.True(disabledAt >= t0 + TimeSpan.FromDays(5), $"disabled after {disabledAt - t0}");
        Assert.True(disabledAt <= t0 + TimeSpan.FromDays(5) + TimeSpan.FromHours(6), $"disabled after {disabledAt - t0}, more than one event interval late");
        var failed = await f.EndpointAsync(down);
        Assert.Contains("Failing continuously since", failed.DisabledReason);

        // Nothing more is sent to it, the items still waiting are failed without a request, and the observer heard once.
        int calls = f.Receiver.Count("/down");
        await f.AdvanceAsync(TimeSpan.FromDays(2), TimeSpan.FromHours(1));
        Assert.Equal(calls, f.Receiver.Count("/down"));
        Assert.Equal(1, f.Receiver.Count("/observer"));
        Assert.Contains((await f.AttemptsAsync(down)).TakeLast(3), a => a.ErrorClass == "endpoint_unavailable" || a.ErrorClass == "http_503");
    }

    [Fact]
    public async Task An_endpoint_that_succeeds_now_and_then_is_never_disabled_however_long_the_failures_in_between_and_one_that_stops_answering_for_five_days_is()
    {
        if (Unavailable)
        {
            return;
        }

        var f = await NewFixtureAsync();
        bool failing = true;
        f.Receiver.Status = _ => failing ? HttpStatusCode.BadGateway : HttpStatusCode.OK;
        Guid endpoint = await f.AddEndpointAsync("flaky", WebhookEventFactory.Delivered);

        // 40 days: 4.5 days of failures, then a success (that clears the failing-since mark), again and again.
        for (int cycle = 0; cycle < Accelerated.Scaled(8); cycle++)
        {
            failing = true;
            DateTimeOffset failureStarted = f.Clock.UtcNow;
            await f.EnqueueAsync();
            await f.RunAsync();
            Assert.NotNull((await f.EndpointAsync(endpoint)).FailingSince);
            await f.AdvanceAsync(TimeSpan.FromDays(4.5), TimeSpan.FromHours(1), async () =>
            {
                if ((f.Clock.UtcNow - failureStarted).Ticks % TimeSpan.TicksPerHour == 0 && (f.Clock.UtcNow - failureStarted).Hours % 6 == 0)
                {
                    await f.EnqueueAsync();
                }
            });
            Assert.True((await f.EndpointAsync(endpoint)).Enabled, $"disabled in cycle {cycle}");

            failing = false;
            await f.EnqueueAsync();
            await f.RunAsync();
            var healthy = await f.EndpointAsync(endpoint);
            Assert.True(healthy.Enabled);
            Assert.Null(healthy.FailingSince);
        }

        // Now it really stops answering: disabled once five days of failures are on record.
        failing = true;
        DateTimeOffset since = f.Clock.UtcNow;
        await f.EnqueueAsync();
        await f.RunAsync();
        await f.AdvanceAsync(TimeSpan.FromDays(5) + TimeSpan.FromHours(12), TimeSpan.FromHours(1), async () =>
        {
            if ((f.Clock.UtcNow - since).Hours % 6 == 0)
            {
                await f.EnqueueAsync();
            }
        });
        Assert.False((await f.EndpointAsync(endpoint)).Enabled);
        Assert.True((await f.EndpointAsync(endpoint)).DisabledAt >= since + TimeSpan.FromDays(5));
    }

    [Fact]
    public async Task Re_enabling_an_endpoint_delivers_new_events_leaves_the_old_failed_ones_alone_and_a_replay_sends_one_of_them()
    {
        if (Unavailable)
        {
            return;
        }

        var f = await NewFixtureAsync();
        f.Receiver.Status = _ => HttpStatusCode.Gone;
        Guid endpoint = await f.AddEndpointAsync("recovering", WebhookEventFactory.Delivered);
        await f.EnqueueAsync();
        await f.RunAsync();
        Assert.False((await f.EndpointAsync(endpoint)).Enabled);
        var oldAttempt = Assert.Single(await f.AttemptsAsync(endpoint));

        // While it is disabled, new events are not even queued for it.
        Assert.Equal(0, await f.EnqueueAsync());

        // The owner re-enables it (what PATCH /v1/webhooks/{id} does: enabled again, reason and failing-since cleared) after the receiver was fixed.
        f.Receiver.Status = _ => HttpStatusCode.OK;
        f.Clock.Advance(TimeSpan.FromDays(2));
        await f.Storage.Config.UpsertWebhookEndpointAsync((await f.EndpointAsync(endpoint)) with { Enabled = true, DisabledReason = null, DisabledAt = null, FailingSince = null }, default);
        Assert.Equal(1, await f.EnqueueAsync());
        await f.RunAsync();
        var attempts = await f.AttemptsAsync(endpoint);
        Assert.Equal(2, attempts.Count);
        Assert.Equal(200, attempts[1].StatusCode);
        Assert.Equal(1, f.Receiver.Requests.Count(r => r.Body.Contains("message.delivered", StringComparison.Ordinal) && r.At == f.Clock.UtcNow));

        // The event that failed with 410 stays failed ...
        await f.AdvanceAsync(TimeSpan.FromDays(2), TimeSpan.FromHours(12));
        Assert.Equal(2, (await f.AttemptsAsync(endpoint)).Count);

        // ... until someone replays it.
        Assert.True(await f.Storage.Webhooks.ReplayAsync(TenantId, oldAttempt.OutboxId, f.Clock.UtcNow, default));
        await f.RunAsync();
        attempts = await f.AttemptsAsync(endpoint);
        Assert.Equal(3, attempts.Count);
        Assert.Equal(200, attempts[2].StatusCode);
        Assert.Equal(oldAttempt.OutboxId, attempts[2].OutboxId);
        Assert.False(await f.Storage.Webhooks.ReplayAsync(TenantId, Guid.NewGuid(), f.Clock.UtcNow, default));
    }

    [Fact]
    public async Task The_outbox_and_the_attempt_log_are_kept_for_their_retention_days_and_then_removed_while_unfinished_items_stay()
    {
        if (Unavailable)
        {
            return;
        }

        var f = await NewFixtureAsync();
        f.Receiver.Status = url => url.EndsWith("/bad", StringComparison.Ordinal) ? HttpStatusCode.InternalServerError : HttpStatusCode.OK;
        Guid good = await f.AddEndpointAsync("good", WebhookEventFactory.Delivered);
        Guid bad = await f.AddEndpointAsync("bad", WebhookEventFactory.Expired);

        // Day 0: three events delivered to the good endpoint (the first two will be probed for existence later: a replay of a row that is gone does nothing), one failing event for the bad one.
        for (int i = 0; i < 3; i++)
        {
            await f.EnqueueAsync();
        }

        await f.EnqueueAsync(WebhookEventFactory.Expired);
        await f.RunAsync();
        var delivered = await f.AttemptsAsync(good);
        Assert.Equal(3, delivered.Count);
        Guid keptRow = delivered[0].OutboxId;
        Guid goneRow = delivered[1].OutboxId;
        Guid laterRow = delivered[2].OutboxId;

        // Day 6.9: everything is still there.
        await f.AdvanceAsync(TimeSpan.FromDays(6.9), TimeSpan.FromHours(12));
        Assert.Equal(3, (await f.AttemptsAsync(good)).Count);
        Assert.True(await f.Storage.Webhooks.ReplayAsync(TenantId, keptRow, f.Clock.UtcNow, default));   // the row exists
        await f.RunAsync();   // the replayed delivery is a new attempt, which restarts that row's clock

        // A failing item that is still on its ladder when the other rows age out.
        await f.AdvanceAsync(TimeSpan.FromDays(1), TimeSpan.FromHours(6), async () => await f.RunAsync());
        await f.EnqueueAsync(WebhookEventFactory.Expired);
        await f.RunAsync();
        var pendingAttempts = (await f.AttemptsAsync(bad)).Count;

        // Day 7.9+: the day-0 attempts are older than 7 days and the day-0 rows are gone; the replayed row and the recent ones are not.
        await f.AdvanceAsync(TimeSpan.FromDays(0.25), TimeSpan.FromHours(6));
        var remaining = await f.AttemptsAsync(good);
        Assert.DoesNotContain(remaining, a => a.OutboxId == goneRow && a.At < f.Clock.UtcNow - TimeSpan.FromDays(7));
        Assert.DoesNotContain(remaining, a => a.OutboxId == laterRow);
        Assert.Contains(remaining, a => a.OutboxId == keptRow);   // the replay's attempt is from day 6.9
        Assert.False(await f.Storage.Webhooks.ReplayAsync(TenantId, goneRow, f.Clock.UtcNow, default), "the finished outbox row should have been removed after 7 days");
        Assert.True((await f.AttemptsAsync(bad)).Count >= pendingAttempts, "the attempt log of an item that is still being retried must not shrink");

        // Much later everything has aged out, including the item that failed for good.
        await f.AdvanceAsync(TimeSpan.FromDays(12), TimeSpan.FromHours(12));
        Assert.Empty(await f.AttemptsAsync(good));
        Assert.Empty(await f.AttemptsAsync(bad));
        Assert.False(await f.Storage.Webhooks.ReplayAsync(TenantId, keptRow, f.Clock.UtcNow, default));
    }

    [Fact]
    public async Task With_unlimited_retention_the_outbox_and_the_attempt_log_are_never_cleaned()
    {
        if (Unavailable)
        {
            return;
        }

        var f = await NewFixtureAsync(o => new StorageOptions
        {
            Backend = o.Backend,
            Sqlite = o.Sqlite,
            Postgres = o.Postgres,
            Retention = new RetentionOptions { WebhookOutboxDays = 0, WebhookAttemptLogDays = 0 },
        });
        Guid endpoint = await f.AddEndpointAsync("good", WebhookEventFactory.Delivered);
        await f.EnqueueAsync();
        await f.RunAsync();
        var first = Assert.Single(await f.AttemptsAsync(endpoint));

        await f.AdvanceAsync(TimeSpan.FromDays(60), TimeSpan.FromDays(1));
        Assert.Contains(await f.AttemptsAsync(endpoint), a => a.OutboxId == first.OutboxId);
        Assert.True(await f.Storage.Webhooks.ReplayAsync(TenantId, first.OutboxId, f.Clock.UtcNow, default));
    }

    // The real HTTP handler with its SSRF guard: the address a host name resolves to is judged again at every attempt.

    [Fact]
    public async Task The_ssrf_guard_judges_the_resolved_address_again_at_every_attempt_whatever_it_resolved_to_before()
    {
        if (Unavailable)
        {
            return;
        }

        using var receiver = new LoopbackReceiver();
        int port = receiver.Port;
        IPAddress[] resolved = [IPAddress.Loopback];
        var f = await NewFixtureAsync(resolver: (_, _) => ValueTask.FromResult(resolved), useRealHttp: true,
            webhookOptions: new WebhookOptions { AllowHttp = true, Timeout = TimeSpan.FromSeconds(10), PollInterval = TimeSpan.FromMilliseconds(10) });
        f.Dispatcher.AllowlistProvider = _ => [IpNetwork.Parse("127.0.0.0/8")];   // the tenant allowed its own loopback receiver
        var ep = new WebhookEndpointRecord(Ids.New(), TenantId, $"http://receiver.example:{port}/hook", Encoding.UTF8.GetBytes(StandardWebhooksSigner.GenerateSecret()), [WebhookEventFactory.Delivered], true, null, null, f.Clock.UtcNow, null);
        await f.Storage.Config.UpsertWebhookEndpointAsync(ep, default);

        await f.EnqueueAsync();
        await f.RunAsync();
        Assert.True(receiver.Hits == 1, string.Join(";", (await f.AttemptsAsync(ep.Id)).Select(a => a.ErrorClass + a.StatusCode)));

        // The name now resolves to the cloud metadata address and then to a private address, neither on the allowlist: refused before any connection is made, on every retry.
        foreach (string target in new[] { "169.254.169.254", "10.0.0.5", "192.168.1.1", "100.64.0.1" })
        {
            resolved = [IPAddress.Parse(target)];
            await f.EnqueueAsync();
            f.Clock.Advance(TimeSpan.FromHours(1));
            await f.RunAsync();
            f.Clock.Advance(TimeSpan.FromHours(1));
            await f.RunAsync();
        }

        Assert.Equal(1, receiver.Hits);
        var attempts = await f.AttemptsAsync(ep.Id);
        Assert.Equal(200, attempts[0].StatusCode);
        Assert.Contains(attempts.Skip(1), a => a.ErrorClass == "ssrf_blocked");
        Assert.DoesNotContain(attempts.Skip(1), a => a.StatusCode is not null);

        // A name that resolves to both a public and a blocked address is not judged by its first answer: a mix is allowed only through the allowed one.
        resolved = [IPAddress.Parse("169.254.169.254"), IPAddress.Loopback];
        await f.EnqueueAsync();
        await f.RunAsync();
        Assert.Equal(2, receiver.Hits);   // only the allowlisted address was connected to
    }

    /// <summary>A bare HTTP receiver on the IPv4 loopback address that answers 200 and closes the connection, so every attempt connects again and passes the guard again.</summary>
    private sealed class LoopbackReceiver : IDisposable
    {
        private readonly System.Net.Sockets.TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly ConcurrentQueue<string> _hits = new();

        public LoopbackReceiver()
        {
            _listener.Start();
            _ = Task.Run(AcceptAsync);
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public int Hits => _hits.Count;

        private async Task AcceptAsync()
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                    _ = Task.Run(async () =>
                    {
                        using (client)
                        {
                            var stream = client.GetStream();
                            var buffer = new byte[8192];
                            int total = 0;
                            while (total < buffer.Length)
                            {
                                int n = await stream.ReadAsync(buffer.AsMemory(total), _stop.Token);
                                if (n == 0)
                                {
                                    return;
                                }

                                total += n;
                                if (Encoding.ASCII.GetString(buffer, 0, total).Contains("\r\n\r\n", StringComparison.Ordinal))
                                {
                                    break;
                                }
                            }

                            _hits.Enqueue(Encoding.ASCII.GetString(buffer, 0, Math.Min(total, 64)));
                            await stream.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"u8.ToArray(), _stop.Token);
                        }
                    });
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or System.Net.Sockets.SocketException or IOException)
            {
            }
        }

        public void Dispose()
        {
            _stop.Cancel();
            _listener.Stop();
        }
    }
}

public sealed class WebhookLifecycleOnSqlite() : WebhookLifecycleTests(new SqliteLifecycleBackend());

public sealed class WebhookLifecycleOnPostgres() : WebhookLifecycleTests(new PostgresLifecycleBackend());
