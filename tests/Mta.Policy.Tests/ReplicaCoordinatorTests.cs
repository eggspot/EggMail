using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Policy.Tests;

/// <summary>
/// Replicas on one database share the per-destination ceilings and tell each other what remote destinations did. The coordination here is the in-memory implementation
/// (the same contract the PostgreSQL one passes in its conformance suite); two "replicas" are two throttles, two breaker sets and two coordinators over one coordination.
/// </summary>
public class ReplicaCoordinatorTests
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
        public Replica(string name, IReplicaCoordination coordination, FakeClock clock, DestinationThrottleOptions? throttle = null, ReplicaCoordinatorOptions? options = null)
        {
            Throttle = new DestinationThrottle(clock, throttle ?? ReplicaCoordinatorTests.Throttle());
            Health = new RouteHealth(clock);
            Coordinator = new ReplicaCoordinator(coordination, name, clock, Throttle, Health, options);
        }

        public DestinationThrottle Throttle { get; }

        public RouteHealth Health { get; }

        public ReplicaCoordinator Coordinator { get; }
    }

    private static (FakeClock Clock, IReplicaCoordination Coordination) Setup()
    {
        var clock = new FakeClock();
        return (clock, new InMemoryReplicaCoordination(clock));
    }

    private static void Fail(Replica replica, RouteHealthKey key, int times = 5)
    {
        for (int i = 0; i < times; i++)
        {
            replica.Health.ReportFailure(key, "connect timeout");
        }
    }

    [Fact]
    public async Task Alone_a_replica_keeps_the_full_ceilings()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        await a.Coordinator.RunOnceAsync(default);

        Assert.Equal((0, 1), (a.Coordinator.ReplicaIndex, a.Coordinator.ReplicaCount));
        Assert.True(a.Throttle.TryAcquire(Gmail).Acquired);
        var snap = a.Throttle.GetSnapshot(Gmail)!;
        Assert.Equal((20, 600d), (snap.ConcurrencyCeiling, snap.MessagesPerMinuteCeiling));
    }

    [Fact]
    public async Task The_connection_and_rate_ceilings_are_shared_out_so_the_replicas_together_stay_within_them()
    {
        var (clock, coordination) = Setup();
        var replicas = new[] { new Replica("a", coordination, clock), new Replica("b", coordination, clock), new Replica("c", coordination, clock) };
        for (int round = 0; round < 2; round++)   // the first beats did not yet see the later ones
        {
            foreach (var r in replicas)
            {
                await r.Coordinator.RunOnceAsync(default);
            }
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
        Assert.Equal([3, 3, 3], replicas.Select(r => r.Coordinator.ReplicaCount));
        Assert.Equal([0, 1, 2], replicas.Select(r => r.Coordinator.ReplicaIndex));
    }

    [Fact]
    public async Task A_destination_already_in_use_is_rescaled_when_a_replica_joins_and_again_when_it_leaves()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        await a.Coordinator.RunOnceAsync(default);
        a.Throttle.TryAcquire(Gmail).Lease!.Dispose();
        Assert.Equal((20, 600d), (a.Throttle.GetSnapshot(Gmail)!.ConcurrencyLimit, a.Throttle.GetSnapshot(Gmail)!.MessagesPerMinute));

        var b = new Replica("b", coordination, clock);
        await b.Coordinator.RunOnceAsync(default);
        await a.Coordinator.RunOnceAsync(default);
        var halved = a.Throttle.GetSnapshot(Gmail)!;
        Assert.Equal((10, 10, 300d, 300d), (halved.ConcurrencyCeiling, halved.ConcurrencyLimit, halved.MessagesPerMinuteCeiling, halved.MessagesPerMinute));

        await b.Coordinator.LeaveAsync(default);
        await a.Coordinator.RunOnceAsync(default);
        var whole = a.Throttle.GetSnapshot(Gmail)!;
        Assert.Equal((20, 20, 600d, 600d), (whole.ConcurrencyCeiling, whole.ConcurrencyLimit, whole.MessagesPerMinuteCeiling, whole.MessagesPerMinute));
    }

    [Fact]
    public async Task A_replica_that_stops_beating_loses_its_share_after_the_liveness_window()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        var b = new Replica("b", coordination, clock);
        await b.Coordinator.RunOnceAsync(default);
        await a.Coordinator.RunOnceAsync(default);
        a.Throttle.TryAcquire(Gmail).Lease!.Dispose();   // a tracks the destination
        Assert.Equal(2, a.Coordinator.ReplicaCount);
        Assert.Equal(10, a.Throttle.GetSnapshot(Gmail)!.ConcurrencyCeiling);

        clock.Advance(TimeSpan.FromSeconds(19));
        await a.Coordinator.RunOnceAsync(default);
        Assert.Equal(2, a.Coordinator.ReplicaCount);   // within the window
        Assert.Equal(10, a.Throttle.GetSnapshot(Gmail)!.ConcurrencyCeiling);

        clock.Advance(TimeSpan.FromSeconds(2));
        await a.Coordinator.RunOnceAsync(default);
        Assert.Equal(1, a.Coordinator.ReplicaCount);
        Assert.Equal(20, a.Throttle.GetSnapshot(Gmail)!.ConcurrencyCeiling);
    }

    [Fact]
    public async Task A_replica_count_that_flaps_never_ratchets_a_penalized_limit_up()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock, Throttle(connections: 7, initialConnections: 7));
        var others = new[] { new Replica("b", coordination, clock, Throttle(connections: 7, initialConnections: 7)), new Replica("c", coordination, clock, Throttle(connections: 7, initialConnections: 7)) };
        await a.Coordinator.RunOnceAsync(default);
        a.Throttle.TryAcquire(Gmail).Lease!.Dispose();
        a.Throttle.Report(Gmail, ThrottleSignal.Throttled);   // halved: 3 of 7
        int penalized = a.Throttle.GetSnapshot(Gmail)!.ConcurrencyLimit;
        Assert.Equal(3, penalized);

        for (int flap = 0; flap < 5; flap++)
        {
            foreach (var o in others)
            {
                await o.Coordinator.RunOnceAsync(default);
            }

            await a.Coordinator.RunOnceAsync(default);   // 3 replicas: ceilings of 3, 2, 2
            foreach (var o in others)
            {
                await o.Coordinator.LeaveAsync(default);
            }

            await a.Coordinator.RunOnceAsync(default);   // alone again
        }

        Assert.Equal(penalized, a.Throttle.GetSnapshot(Gmail)!.ConcurrencyLimit);
    }

    [Fact]
    public async Task A_slowdown_told_by_a_destination_slows_it_down_on_the_other_replicas_once()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        var b = new Replica("b", coordination, clock);
        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);
        await a.Coordinator.RunOnceAsync(default);
        b.Throttle.TryAcquire(Gmail).Lease!.Dispose();   // b tracks the destination, at its full (shared) rate
        double before = b.Throttle.GetSnapshot(Gmail)!.MessagesPerMinute;

        a.Throttle.Report(Gmail, ThrottleSignal.Throttled);   // "421 too many connections" to replica a only
        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);

        var slowed = b.Throttle.GetSnapshot(Gmail)!;
        Assert.Equal(before / 2, slowed.MessagesPerMinute);
        Assert.True(slowed.Penalized);

        // The same signal is read at every round until it ends; it must not halve again once the cooldown is over, and it is not echoed back.
        clock.Advance(TimeSpan.FromSeconds(70));   // both keep beating, so the shares stay as they are
        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);
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
        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);
        a.Throttle.Report(new ThrottleKey("big.example", "route-1"), ThrottleSignal.Throttled);
        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);

        var snap = b.Throttle.GetSnapshot(new ThrottleKey("big.example", "route-1"));
        Assert.NotNull(snap);
        Assert.True(snap.Penalized);
        Assert.Null(b.Throttle.GetSnapshot(new ThrottleKey("big.example")));   // the route is part of the key
    }

    [Fact]
    public async Task An_mx_host_one_replica_found_down_is_skipped_by_the_others_until_the_same_time_and_then_probed()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        var b = new Replica("b", coordination, clock);
        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);
        var mx = RouteHealthKey.ForMxHost("mx.down.example");
        Fail(a, mx);

        Assert.Equal(CircuitState.Open, a.Health.GetSnapshot(mx).State);
        Assert.Equal(RouteAdmission.Allowed, b.Health.TryAdmit(mx));   // b has not heard yet

        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);

        var seen = b.Health.GetSnapshot(mx);
        Assert.Equal(CircuitState.Open, seen.State);
        Assert.Equal(a.Health.GetSnapshot(mx).RetryAt, seen.RetryAt);
        Assert.Equal(RouteAdmission.Rejected, b.Health.TryAdmit(mx, out DateTimeOffset retryAt));
        Assert.Equal(seen.RetryAt, retryAt);
        var echoed = new List<(RouteHealthKey, DateTimeOffset, TimeSpan)>();
        b.Health.DrainOpened(echoed);
        Assert.Empty(echoed);   // adopted, not passed on

        clock.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));
        Assert.Equal(RouteAdmission.Probe, b.Health.TryAdmit(mx));   // whichever replica gets there first probes
    }

    [Fact]
    public async Task What_a_replica_adopts_of_a_peers_circuit_never_exceeds_the_base_cooldown_however_long_the_peer_backs_off()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        var b = new Replica("b", coordination, clock);
        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);
        var mx = RouteHealthKey.ForMxHost("mx.down.example");
        Fail(a, mx);
        // The peer's probes fail again and again: its cooldown doubles to 10, 20 and 40 minutes.
        for (int i = 0; i < 3; i++)
        {
            clock.Advance(a.Health.GetSnapshot(mx).RetryAt!.Value - clock.UtcNow + TimeSpan.FromSeconds(1));
            Assert.Equal(RouteAdmission.Probe, a.Health.TryAdmit(mx));
            a.Health.ReportFailure(mx, "still down");
        }

        Assert.True(a.Health.GetSnapshot(mx).RetryAt > clock.UtcNow + TimeSpan.FromMinutes(39));
        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);

        Assert.Equal(CircuitState.Open, b.Health.GetSnapshot(mx).State);
        Assert.True(b.Health.GetSnapshot(mx).RetryAt <= clock.UtcNow + TimeSpan.FromMinutes(5));
    }

    [Fact]
    public async Task A_route_is_never_opened_by_a_peer_so_one_sick_replica_cannot_take_a_relay_out_of_every_plan()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        var b = new Replica("b", coordination, clock);
        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);
        var relay = RouteHealthKey.ForRoute("relay-1");
        Fail(a, relay);
        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);

        Assert.Equal(CircuitState.Open, a.Health.GetSnapshot(relay).State);
        Assert.Equal(CircuitState.Closed, b.Health.GetSnapshot(relay).State);
        Assert.Equal(0, b.Health.TrackedCount);
    }

    [Fact]
    public async Task A_host_this_replica_just_connected_to_is_not_opened_by_a_peers_failures()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        var b = new Replica("b", coordination, clock);
        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);
        var mx = RouteHealthKey.ForMxHost("mx.flaky.example");
        b.Health.ReportSuccess(mx);   // b reached it a moment ago, and never had a failure for it
        Fail(a, mx);

        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);
        Assert.Equal(CircuitState.Closed, b.Health.GetSnapshot(mx).State);

        // Two minutes later with no success of its own, b believes its peer.
        clock.Advance(TimeSpan.FromSeconds(125));
        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);
        Assert.Equal(CircuitState.Open, b.Health.GetSnapshot(mx).State);
    }

    [Fact]
    public async Task A_circuit_that_has_already_ended_is_not_adopted()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        var b = new Replica("b", coordination, clock);
        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);
        var mx = RouteHealthKey.ForMxHost("mx.back.example");
        Fail(a, mx);

        await a.Coordinator.RunOnceAsync(default);
        clock.Advance(TimeSpan.FromMinutes(6));
        await b.Coordinator.RunOnceAsync(default);

        Assert.Equal(CircuitState.Closed, b.Health.GetSnapshot(mx).State);
        Assert.Equal(0, b.Health.TrackedCount);
    }

    [Fact]
    public async Task A_failed_round_keeps_the_signals_for_the_next_one_and_the_last_share()
    {
        var (clock, coordination) = Setup();
        var flaky = new FlakyCoordination(coordination);
        var a = new Replica("a", flaky, clock);
        var b = new Replica("b", coordination, clock);
        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);
        await a.Coordinator.RunOnceAsync(default);
        Assert.Equal(2, a.Coordinator.ReplicaCount);

        a.Throttle.Report(Gmail, ThrottleSignal.Throttled);
        flaky.FailPublish = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => a.Coordinator.RunOnceAsync(default));
        Assert.Equal(2, a.Coordinator.ReplicaCount);   // the share did not fall back to "alone"
        flaky.FailPublish = false;
        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);

        Assert.True(b.Throttle.GetSnapshot(Gmail)!.Penalized);
    }

    [Fact]
    public async Task Signals_that_could_not_be_published_are_kept_once_per_key_and_dropped_when_they_have_ended()
    {
        var (clock, coordination) = Setup();
        var flaky = new FlakyCoordination(coordination) { FailPublish = true };
        var a = new Replica("a", flaky, clock);
        var b = new Replica("b", coordination, clock);
        var mx = RouteHealthKey.ForMxHost("mx.down.example");
        Fail(a, mx);
        a.Throttle.Report(Gmail, ThrottleSignal.Throttled);
        for (int i = 0; i < 20; i++)
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => a.Coordinator.RunOnceAsync(default));   // twenty failed rounds, still one signal per key
        }

        flaky.FailPublish = false;
        await a.Coordinator.RunOnceAsync(default);
        await b.Coordinator.RunOnceAsync(default);
        Assert.Equal(2, (await coordination.GetSignalsAsync("b", default)).Count);

        // Signals that did not get through before they ended are dropped, not published stale.
        var late = new Replica("late", flaky, clock);
        var mx2 = RouteHealthKey.ForMxHost("mx.other.example");
        Fail(late, mx2);
        flaky.FailPublish = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => late.Coordinator.RunOnceAsync(default));
        clock.Advance(TimeSpan.FromMinutes(6));
        flaky.FailPublish = false;
        await late.Coordinator.RunOnceAsync(default);
        Assert.DoesNotContain(await coordination.GetSignalsAsync("b", default), s => s.Signal.Key == mx2.ToString());
    }

    [Fact]
    public async Task A_round_that_takes_longer_than_the_timeout_fails_with_a_timeout_and_the_next_one_works()
    {
        var (clock, coordination) = Setup();
        var slow = new FlakyCoordination(coordination) { HangHeartbeat = true };
        var a = new Replica("a", slow, clock, options: new ReplicaCoordinatorOptions { CallTimeout = TimeSpan.FromMilliseconds(100) });

        await Assert.ThrowsAsync<TimeoutException>(() => a.Coordinator.RunOnceAsync(default));
        slow.HangHeartbeat = false;
        await a.Coordinator.RunOnceAsync(default);
        Assert.Equal(1, a.Coordinator.ReplicaCount);
    }

    [Fact]
    public async Task Leaving_removes_the_replica_and_its_signals()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);
        var b = new Replica("b", coordination, clock);
        await a.Coordinator.RunOnceAsync(default);
        a.Throttle.Report(Gmail, ThrottleSignal.Throttled);
        await a.Coordinator.RunOnceAsync(default);
        await a.Coordinator.LeaveAsync(default);
        await b.Coordinator.RunOnceAsync(default);

        Assert.Equal(1, b.Coordinator.ReplicaCount);
        Assert.Null(b.Throttle.GetSnapshot(Gmail));
    }

    [Fact]
    public void Without_a_coordinator_nothing_is_kept_for_peers()
    {
        // One process (SQLite): the throttle and the breakers are never drained, so they must not accumulate what they would pass on.
        var clock = new FakeClock();
        var throttle = new DestinationThrottle(clock, Throttle());
        var health = new RouteHealth(clock);
        for (int i = 0; i < 6000; i++)
        {
            throttle.Report(new ThrottleKey("d" + i + ".example"), ThrottleSignal.Throttled);
            for (int f = 0; f < 5; f++)
            {
                health.ReportFailure(RouteHealthKey.ForMxHost("mx" + i + ".example"));
            }

            health.ReportSuccess(RouteHealthKey.ForMxHost("ok" + i + ".example"));
        }

        var slowdowns = new List<(ThrottleKey, DateTimeOffset)>();
        var opened = new List<(RouteHealthKey, DateTimeOffset, TimeSpan)>();
        throttle.DrainSlowdowns(slowdowns);
        health.DrainOpened(opened);
        Assert.Empty(slowdowns);
        Assert.Empty(opened);
    }

    [Fact]
    public async Task With_a_coordinator_what_is_kept_for_peers_is_bounded()
    {
        var (clock, coordination) = Setup();
        var a = new Replica("a", coordination, clock);   // attaching the coordinator turns the sharing on
        for (int i = 0; i < 6000; i++)
        {
            a.Throttle.Report(new ThrottleKey("d" + i + ".example"), ThrottleSignal.Throttled);
            for (int f = 0; f < 5; f++)
            {
                a.Health.ReportFailure(RouteHealthKey.ForMxHost("mx" + i + ".example"));
            }
        }

        var slowdowns = new List<(ThrottleKey, DateTimeOffset)>();
        var opened = new List<(RouteHealthKey, DateTimeOffset, TimeSpan)>();
        a.Throttle.DrainSlowdowns(slowdowns);
        a.Health.DrainOpened(opened);
        Assert.InRange(slowdowns.Count, 1, 4096);
        Assert.InRange(opened.Count, 1, 4096);
        await a.Coordinator.DisposeAsync();
    }

    [Fact]
    public void Options_must_have_a_liveness_window_longer_than_the_interval()
    {
        var (clock, coordination) = Setup();
        var throttle = new DestinationThrottle(clock);
        var health = new RouteHealth(clock);
        Assert.Throws<ArgumentException>(() => new ReplicaCoordinator(coordination, "a", clock, throttle, health, new ReplicaCoordinatorOptions { Interval = TimeSpan.FromSeconds(10), LiveFor = TimeSpan.FromSeconds(10) }));
        Assert.Throws<ArgumentException>(() => new ReplicaCoordinator(coordination, " ", clock, throttle, health));
    }

    private sealed class FlakyCoordination(IReplicaCoordination inner) : IReplicaCoordination
    {
        public bool FailPublish { get; set; }

        public bool HangHeartbeat { get; set; }

        public async ValueTask<IReadOnlyList<string>> HeartbeatAsync(string replicaName, TimeSpan liveFor, CancellationToken ct)
        {
            if (HangHeartbeat)
            {
                await Task.Delay(Timeout.Infinite, ct);
            }

            return await inner.HeartbeatAsync(replicaName, liveFor, ct);
        }

        public ValueTask LeaveAsync(string replicaName, CancellationToken ct) => inner.LeaveAsync(replicaName, ct);

        public ValueTask PublishSignalsAsync(string replicaName, IReadOnlyList<PeerSignal> signals, CancellationToken ct) =>
            FailPublish ? throw new InvalidOperationException("database unavailable") : inner.PublishSignalsAsync(replicaName, signals, ct);

        public ValueTask<IReadOnlyList<ReceivedPeerSignal>> GetSignalsAsync(string replicaName, CancellationToken ct) => inner.GetSignalsAsync(replicaName, ct);

        public ValueTask<IReadOnlyList<AuthFailureCount>> GetAuthFailuresAsync(IReadOnlyList<string> keyDigests, long minBucket, CancellationToken ct) => inner.GetAuthFailuresAsync(keyDigests, minBucket, ct);

        public ValueTask AddAuthFailuresAsync(IReadOnlyList<string> keyDigests, long bucket, long pruneBeforeBucket, CancellationToken ct) => inner.AddAuthFailuresAsync(keyDigests, bucket, pruneBeforeBucket, ct);

        public ValueTask ClearAuthFailuresAsync(IReadOnlyList<string> keyDigests, CancellationToken ct) => inner.ClearAuthFailuresAsync(keyDigests, ct);
    }
}
