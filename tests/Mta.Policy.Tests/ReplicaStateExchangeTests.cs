using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Policy.Tests;

/// <summary>
/// Replicas on one database share the per-destination ceilings and tell each other what remote destinations did. The coordination here is the in-memory implementation
/// (the same contract the PostgreSQL one passes in its conformance suite); two "replicas" are two throttles, two breaker sets and two exchanges over one coordination.
/// </summary>
public class ReplicaStateExchangeTests
{
    private static readonly ThrottleKey Gmail = new("gmail.com");

    private static DestinationThrottleOptions Throttle(int connections = 20, double perMinute = 600, int initialConnections = 20, double initialRate = 600) => new()
    {
        Defaults = new ThrottleLimits(connections, perMinute, 100),
        InitialConcurrentConnections = initialConnections,
        InitialMessagesPerMinute = initialRate,
        MinMessagesPerMinute = 6,
    };

    private sealed class Replica
    {
        public Replica(string id, IReplicaCoordination coordination, FakeClock clock, DestinationThrottleOptions? throttle = null)
        {
            Throttle = new DestinationThrottle(clock, throttle ?? ReplicaStateExchangeTests.Throttle());
            Health = new RouteHealth(clock);
            Exchange = new ReplicaStateExchange(coordination, id, clock, Throttle, Health);
        }

        public DestinationThrottle Throttle { get; }

        public RouteHealth Health { get; }

        public ReplicaStateExchange Exchange { get; }
    }

    private static (FakeClock Clock, IReplicaCoordination Coordination) Setup() => (new FakeClock(), new InMemoryReplicaCoordination());

    [Fact]
    public async Task Alone_a_replica_keeps_the_full_ceilings()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        await a.Exchange.ExchangeAsync(default);

        Assert.Equal((0, 1), (a.Exchange.ReplicaIndex, a.Exchange.ReplicaCount));
        Assert.True(a.Throttle.TryAcquire(Gmail).Acquired);
        var snap = a.Throttle.GetSnapshot(Gmail)!;
        Assert.Equal((20, 600d), (snap.ConcurrencyCeiling, snap.MessagesPerMinuteCeiling));
    }

    [Fact]
    public async Task The_connection_and_rate_ceilings_are_shared_out_so_the_replicas_together_stay_within_them()
    {
        var (clock, coordination) = Setup();
        var replicas = new[] { new Replica("a", coordination, clock), new Replica("b", coordination, clock), new Replica("c", coordination, clock) };
        foreach (var r in replicas)
        {
            await r.Exchange.ExchangeAsync(default);
        }

        foreach (var r in replicas)
        {
            await r.Exchange.ExchangeAsync(default);   // the first beats did not yet see the later ones
        }

        var leases = new List<ThrottleLease>();
        var snapshots = new List<ThrottleSnapshot>();
        foreach (var r in replicas)
        {
            // Take every connection the replica will give: together they must not exceed the ceiling of 20.
            while (r.Throttle.TryAcquire(Gmail) is { Acquired: true } got)
            {
                leases.Add(got.Lease);
            }

            snapshots.Add(r.Throttle.GetSnapshot(Gmail)!);
        }

        Assert.Equal([7, 7, 6], snapshots.Select(s => s.ConcurrencyCeiling));   // 20 = 7 + 7 + 6: the first ranks take the remainder
        Assert.Equal(20, leases.Count);
        Assert.Equal([200d, 200d, 200d], snapshots.Select(s => s.MessagesPerMinuteCeiling));
        Assert.Equal([3, 3, 3], replicas.Select(r => r.Exchange.ReplicaCount));
        Assert.Equal([0, 1, 2], replicas.Select(r => r.Exchange.ReplicaIndex));
    }

    [Fact]
    public async Task A_destination_already_in_use_is_rescaled_when_a_replica_joins_and_again_when_it_leaves()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        await a.Exchange.ExchangeAsync(default);
        a.Throttle.TryAcquire(Gmail).Lease!.Dispose();
        Assert.Equal((20, 600d), (a.Throttle.GetSnapshot(Gmail)!.ConcurrencyLimit, a.Throttle.GetSnapshot(Gmail)!.MessagesPerMinute));

        var b = new Replica("b", coordination, clock);
        await b.Exchange.ExchangeAsync(default);
        await a.Exchange.ExchangeAsync(default);
        var halved = a.Throttle.GetSnapshot(Gmail)!;
        Assert.Equal((10, 10, 300d, 300d), (halved.ConcurrencyCeiling, halved.ConcurrencyLimit, halved.MessagesPerMinuteCeiling, halved.MessagesPerMinute));

        await b.Exchange.LeaveAsync(default);
        await a.Exchange.ExchangeAsync(default);
        var whole = a.Throttle.GetSnapshot(Gmail)!;
        Assert.Equal((20, 20, 600d, 600d), (whole.ConcurrencyCeiling, whole.ConcurrencyLimit, whole.MessagesPerMinuteCeiling, whole.MessagesPerMinute));
    }

    [Fact]
    public async Task A_replica_that_stops_beating_loses_its_share_after_the_liveness_window()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        var b = new Replica("b", coordination, clock);
        await b.Exchange.ExchangeAsync(default);
        await a.Exchange.ExchangeAsync(default);
        Assert.Equal(2, a.Exchange.ReplicaCount);

        clock.Advance(TimeSpan.FromSeconds(19));
        await a.Exchange.ExchangeAsync(default);
        Assert.Equal(2, a.Exchange.ReplicaCount);   // within the window

        clock.Advance(TimeSpan.FromSeconds(2));
        await a.Exchange.ExchangeAsync(default);
        Assert.Equal(1, a.Exchange.ReplicaCount);
        Assert.Equal(20, a.Throttle.GetSnapshot(Gmail)?.ConcurrencyCeiling ?? 20);
    }

    [Fact]
    public async Task A_slowdown_told_by_a_destination_slows_it_down_on_the_other_replicas_once()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        var b = new Replica("b", coordination, clock);
        await a.Exchange.ExchangeAsync(default);
        await b.Exchange.ExchangeAsync(default);
        await a.Exchange.ExchangeAsync(default);
        b.Throttle.TryAcquire(Gmail).Lease!.Dispose();   // b tracks the destination, at its full (shared) rate
        double before = b.Throttle.GetSnapshot(Gmail)!.MessagesPerMinute;

        a.Throttle.Report(Gmail, ThrottleSignal.Throttled);   // "421 too many connections" to replica a only
        await a.Exchange.ExchangeAsync(default);
        await b.Exchange.ExchangeAsync(default);

        var slowed = b.Throttle.GetSnapshot(Gmail)!;
        Assert.Equal(before / 2, slowed.MessagesPerMinute);
        Assert.True(slowed.Penalized);

        // The same signal is read at every exchange until it ends; it must not halve again once the cooldown is over, and it is not echoed back.
        clock.Advance(TimeSpan.FromSeconds(70));   // both keep beating, so the shares stay as they are
        await a.Exchange.ExchangeAsync(default);
        await b.Exchange.ExchangeAsync(default);
        Assert.Equal(before / 2, b.Throttle.GetSnapshot(Gmail)!.MessagesPerMinute);
        var drained = new List<(ThrottleKey, DateTimeOffset)>();
        b.Throttle.DrainSlowdowns(drained);
        Assert.Empty(drained);
    }

    [Fact]
    public async Task A_slowdown_for_a_destination_the_replica_has_not_used_yet_is_remembered_for_when_it_does()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        var b = new Replica("b", coordination, clock);
        await a.Exchange.ExchangeAsync(default);
        await b.Exchange.ExchangeAsync(default);
        a.Throttle.Report(new ThrottleKey("big.example", "route-1"), ThrottleSignal.Throttled);
        await a.Exchange.ExchangeAsync(default);
        await b.Exchange.ExchangeAsync(default);

        var snap = b.Throttle.GetSnapshot(new ThrottleKey("big.example", "route-1"));
        Assert.NotNull(snap);
        Assert.True(snap.Penalized);
        Assert.Null(b.Throttle.GetSnapshot(new ThrottleKey("big.example")));   // the route is part of the key
    }

    [Fact]
    public async Task A_circuit_one_replica_opened_is_open_on_the_others_until_the_same_time_and_then_probed()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        var b = new Replica("b", coordination, clock);
        await a.Exchange.ExchangeAsync(default);
        await b.Exchange.ExchangeAsync(default);
        var mx = RouteHealthKey.ForMxHost("mx.down.example");
        for (int i = 0; i < 5; i++)
        {
            a.Health.ReportFailure(mx, "connect timeout");
        }

        Assert.Equal(CircuitState.Open, a.Health.GetSnapshot(mx).State);
        Assert.Equal(RouteAdmission.Allowed, b.Health.TryAdmit(mx));   // b has not heard yet

        await a.Exchange.ExchangeAsync(default);
        await b.Exchange.ExchangeAsync(default);

        var seen = b.Health.GetSnapshot(mx);
        Assert.Equal(CircuitState.Open, seen.State);
        Assert.Equal(a.Health.GetSnapshot(mx).RetryAt, seen.RetryAt);
        Assert.Equal(RouteAdmission.Rejected, b.Health.TryAdmit(mx, out DateTimeOffset retryAt));
        Assert.Equal(seen.RetryAt, retryAt);
        var echoed = new List<(RouteHealthKey, DateTimeOffset, TimeSpan)>();
        b.Health.DrainOpened(echoed);
        Assert.Empty(echoed);   // adopted, not passed on

        clock.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));
        Assert.Equal(RouteAdmission.Probe, b.Health.TryAdmit(mx));   // whichever replica gets there first probes; a probe that fails opens it for longer for everyone
        b.Health.ReportFailure(mx, "still down");
        await b.Exchange.ExchangeAsync(default);
        await a.Exchange.ExchangeAsync(default);
        Assert.Equal(b.Health.GetSnapshot(mx).RetryAt, a.Health.GetSnapshot(mx).RetryAt);
        Assert.True(a.Health.GetSnapshot(mx).RetryAt > clock.UtcNow + TimeSpan.FromMinutes(9));   // cooldown doubled
    }

    [Fact]
    public async Task A_circuit_that_has_already_ended_is_not_adopted()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        var b = new Replica("b", coordination, clock);
        await a.Exchange.ExchangeAsync(default);
        await b.Exchange.ExchangeAsync(default);
        var route = RouteHealthKey.ForRoute("relay-1");
        for (int i = 0; i < 5; i++)
        {
            a.Health.ReportFailure(route);
        }

        await a.Exchange.ExchangeAsync(default);
        clock.Advance(TimeSpan.FromMinutes(6));
        await b.Exchange.ExchangeAsync(default);

        Assert.Equal(CircuitState.Closed, b.Health.GetSnapshot(route).State);
        Assert.Equal(0, b.Health.TrackedCount);
    }

    [Fact]
    public async Task A_failed_exchange_keeps_the_signals_for_the_next_one_and_the_last_share()
    {
        var (clock, coordination) = Setup();
        var flaky = new FlakyCoordination(coordination);
        var a = new Replica("a", flaky, clock);
        var b = new Replica("b", coordination, clock);
        await a.Exchange.ExchangeAsync(default);
        await b.Exchange.ExchangeAsync(default);
        await a.Exchange.ExchangeAsync(default);
        Assert.Equal(2, a.Exchange.ReplicaCount);

        a.Throttle.Report(Gmail, ThrottleSignal.Throttled);
        flaky.FailPublish = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => a.Exchange.ExchangeAsync(default));
        Assert.Equal(2, a.Exchange.ReplicaCount);   // the share did not fall back to "alone"
        flaky.FailPublish = false;
        await a.Exchange.ExchangeAsync(default);
        await b.Exchange.ExchangeAsync(default);

        Assert.True(b.Throttle.GetSnapshot(Gmail)!.Penalized);
    }

    [Fact]
    public async Task Leaving_removes_the_replica_and_its_signals()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        var b = new Replica("b", coordination, clock);
        await a.Exchange.ExchangeAsync(default);
        a.Throttle.Report(Gmail, ThrottleSignal.Throttled);
        await a.Exchange.ExchangeAsync(default);
        await a.Exchange.LeaveAsync(default);
        await b.Exchange.ExchangeAsync(default);

        Assert.Equal(1, b.Exchange.ReplicaCount);
        Assert.Null(b.Throttle.GetSnapshot(Gmail));
    }

    [Fact]
    public void Options_must_have_a_liveness_window_longer_than_the_interval()
    {
        var (clock, coordination) = Setup();
        var throttle = new DestinationThrottle(clock);
        var health = new RouteHealth(clock);
        Assert.Throws<ArgumentException>(() => new ReplicaStateExchange(coordination, "a", clock, throttle, health, new ReplicaStateExchangeOptions { Interval = TimeSpan.FromSeconds(10), LiveFor = TimeSpan.FromSeconds(10) }));
        Assert.Throws<ArgumentException>(() => new ReplicaStateExchange(coordination, " ", clock, throttle, health));
    }

    private sealed class FlakyCoordination(IReplicaCoordination inner) : IReplicaCoordination
    {
        public bool FailPublish { get; set; }

        public ValueTask<IReadOnlyList<string>> HeartbeatAsync(string replicaId, DateTimeOffset now, TimeSpan liveFor, CancellationToken ct) => inner.HeartbeatAsync(replicaId, now, liveFor, ct);

        public ValueTask LeaveAsync(string replicaId, CancellationToken ct) => inner.LeaveAsync(replicaId, ct);

        public ValueTask PublishSignalsAsync(IReadOnlyList<PeerSignal> signals, DateTimeOffset now, CancellationToken ct) =>
            FailPublish ? throw new InvalidOperationException("database unavailable") : inner.PublishSignalsAsync(signals, now, ct);

        public ValueTask<IReadOnlyList<PeerSignal>> GetSignalsAsync(string replicaId, DateTimeOffset now, CancellationToken ct) => inner.GetSignalsAsync(replicaId, now, ct);

        public ValueTask<IReadOnlyList<AuthFailureCount>> GetAuthFailuresAsync(IReadOnlyList<string> keyHashes, long minBucket, CancellationToken ct) => inner.GetAuthFailuresAsync(keyHashes, minBucket, ct);

        public ValueTask AddAuthFailuresAsync(IReadOnlyList<string> keyHashes, long bucket, long pruneBeforeBucket, CancellationToken ct) => inner.AddAuthFailuresAsync(keyHashes, bucket, pruneBeforeBucket, ct);

        public ValueTask ClearAuthFailuresAsync(IReadOnlyList<string> keyHashes, CancellationToken ct) => inner.ClearAuthFailuresAsync(keyHashes, ct);
    }
}
