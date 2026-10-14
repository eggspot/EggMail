namespace Mta.Storage.Tests;

/// <summary>
/// What replicas on one database exchange (<see cref="IReplicaCoordination"/>): liveness, signals about remote destinations and the failed-login counts.
/// The in-memory and PostgreSQL backends run it; SQLite is one process by design and offers no coordination.
/// </summary>
public abstract class ReplicaCoordinationConformance : StorageTestBase
{
    private IReplicaCoordination Replicas => Storage.Replicas ?? throw new InvalidOperationException("this backend has no replica coordination");

    private static readonly TimeSpan LiveFor = TimeSpan.FromSeconds(20);

    [Fact]
    public async Task Heartbeats_list_the_live_replicas_in_ordinal_order_and_a_silent_one_drops_out()
    {
        Assert.Equal(["b"], await Replicas.HeartbeatAsync("b", Clock.UtcNow, LiveFor, default));
        Assert.Equal(["a", "b"], await Replicas.HeartbeatAsync("a", Clock.UtcNow, LiveFor, default));
        Assert.Equal(["a", "b", "c"], await Replicas.HeartbeatAsync("c", Clock.UtcNow, LiveFor, default));

        // "b" stops beating: after the liveness window the others no longer count it, and it is forgotten altogether only after minutes.
        Clock.Advance(TimeSpan.FromSeconds(15));
        await Replicas.HeartbeatAsync("a", Clock.UtcNow, LiveFor, default);
        Clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(["a", "c"], await Replicas.HeartbeatAsync("c", Clock.UtcNow, LiveFor, default));
        Assert.Equal(["a", "c"], await Replicas.HeartbeatAsync("a", Clock.UtcNow, LiveFor, default));
    }

    [Fact]
    public async Task A_replica_that_leaves_is_gone_at_once_together_with_its_signals()
    {
        await Replicas.HeartbeatAsync("a", Clock.UtcNow, LiveFor, default);
        await Replicas.HeartbeatAsync("b", Clock.UtcNow, LiveFor, default);
        await Replicas.PublishSignalsAsync([Signal(PeerSignalKind.CircuitOpened, "mx:mail.example", "b", 300)], Clock.UtcNow, default);
        Assert.Single(await Replicas.GetSignalsAsync("a", Clock.UtcNow, default));

        await Replicas.LeaveAsync("b", default);

        Assert.Equal(["a"], await Replicas.HeartbeatAsync("a", Clock.UtcNow, LiveFor, default));
        Assert.Empty(await Replicas.GetSignalsAsync("a", Clock.UtcNow, default));
    }

    [Fact]
    public async Task Signals_reach_the_other_replicas_only_while_valid_and_a_newer_one_replaces_the_older()
    {
        await Replicas.HeartbeatAsync("a", Clock.UtcNow, LiveFor, default);
        await Replicas.HeartbeatAsync("b", Clock.UtcNow, LiveFor, default);
        await Replicas.PublishSignalsAsync([Signal(PeerSignalKind.CircuitOpened, "mx:mail.example", "a", 300), Signal(PeerSignalKind.DestinationSlowedDown, "big.example", "a", 60)], Clock.UtcNow, default);

        Assert.Empty(await Replicas.GetSignalsAsync("a", Clock.UtcNow, default));   // never one's own
        var seen = await Replicas.GetSignalsAsync("b", Clock.UtcNow, default);
        Assert.Equal([(PeerSignalKind.CircuitOpened, "mx:mail.example"), (PeerSignalKind.DestinationSlowedDown, "big.example")], seen.OrderBy(s => s.Kind).Select(s => (s.Kind, s.Key)));
        Assert.All(seen, s => Assert.Equal("a", s.ReplicaId));

        // The same kind and key again replaces the earlier one (longer cooldown after a failed probe).
        Clock.Advance(TimeSpan.FromSeconds(10));
        await Replicas.PublishSignalsAsync([Signal(PeerSignalKind.CircuitOpened, "mx:mail.example", "a", 600)], Clock.UtcNow, default);
        var replaced = (await Replicas.GetSignalsAsync("b", Clock.UtcNow, default)).Single(s => s.Kind == PeerSignalKind.CircuitOpened);
        Assert.Equal(Clock.UtcNow.AddSeconds(600), replaced.Until);
        Assert.Equal(600L * TimeSpan.TicksPerSecond, replaced.Value);

        // After its end a signal is not delivered any more.
        Clock.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal([PeerSignalKind.CircuitOpened], (await Replicas.GetSignalsAsync("b", Clock.UtcNow, default)).Select(s => s.Kind));
        Clock.Advance(TimeSpan.FromSeconds(600));
        Assert.Empty(await Replicas.GetSignalsAsync("b", Clock.UtcNow, default));
    }

    [Fact]
    public async Task Signals_published_by_two_replicas_for_one_key_are_kept_apart()
    {
        await Replicas.PublishSignalsAsync([Signal(PeerSignalKind.CircuitOpened, "mx:mail.example", "a", 300), Signal(PeerSignalKind.CircuitOpened, "mx:mail.example", "b", 120)], Clock.UtcNow, default);
        var seenByC = await Replicas.GetSignalsAsync("c", Clock.UtcNow, default);
        Assert.Equal(["a", "b"], seenByC.Select(s => s.ReplicaId));
        Assert.Equal(["b"], (await Replicas.GetSignalsAsync("a", Clock.UtcNow, default)).Select(s => s.ReplicaId));
    }

    [Fact]
    public async Task Failed_logins_add_up_across_callers_per_key_and_bucket_and_old_buckets_are_pruned()
    {
        await Replicas.AddAuthFailuresAsync(["ip-1", "user-1"], 100, 90, default);
        await Replicas.AddAuthFailuresAsync(["ip-1"], 100, 90, default);
        await Replicas.AddAuthFailuresAsync(["ip-1", "ip-1"], 101, 90, default);   // a repeated key counts once per call
        await Replicas.AddAuthFailuresAsync(["ip-2"], 95, 90, default);

        var counts = await Replicas.GetAuthFailuresAsync(["ip-1", "user-1"], 0, default);
        Assert.Equal([("ip-1", 100L, 2L), ("ip-1", 101L, 1L), ("user-1", 100L, 1L)], counts.Select(c => (c.KeyHash, c.Bucket, c.Count)));
        Assert.Equal([("ip-1", 101L, 1L)], (await Replicas.GetAuthFailuresAsync(["ip-1"], 101, default)).Select(c => (c.KeyHash, c.Bucket, c.Count)));
        Assert.Empty(await Replicas.GetAuthFailuresAsync([], 0, default));

        // Adding with a later prune point deletes what is older, for every key.
        await Replicas.AddAuthFailuresAsync(["ip-3"], 120, 98, default);
        Assert.Empty(await Replicas.GetAuthFailuresAsync(["ip-2"], 0, default));
        Assert.Equal(3, (await Replicas.GetAuthFailuresAsync(["ip-1", "user-1"], 0, default)).Count);
    }

    [Fact]
    public async Task A_cleared_key_starts_again_and_other_keys_are_untouched()
    {
        await Replicas.AddAuthFailuresAsync(["user-1", "user-2"], 100, 90, default);
        await Replicas.AddAuthFailuresAsync(["user-1"], 101, 90, default);
        await Replicas.ClearAuthFailuresAsync(["user-1"], default);
        await Replicas.ClearAuthFailuresAsync([], default);

        Assert.Empty(await Replicas.GetAuthFailuresAsync(["user-1"], 0, default));
        Assert.Single(await Replicas.GetAuthFailuresAsync(["user-2"], 0, default));
    }

    [Fact]
    public async Task Concurrent_failures_from_many_callers_are_all_counted()
    {
        await Task.WhenAll(Enumerable.Range(0, 40).Select(i => Task.Run(() => Replicas.AddAuthFailuresAsync(["shared", i % 2 == 0 ? "even" : "odd"], 100, 90, default).AsTask())));
        var counts = (await Replicas.GetAuthFailuresAsync(["shared", "even", "odd"], 0, default)).ToDictionary(c => c.KeyHash, c => c.Count);
        Assert.Equal((40L, 20L, 20L), (counts["shared"], counts["even"], counts["odd"]));
    }

    private PeerSignal Signal(PeerSignalKind kind, string key, string replica, int validSeconds) =>
        new(kind, key, replica, Clock.UtcNow, Clock.UtcNow.AddSeconds(validSeconds), validSeconds * TimeSpan.TicksPerSecond);
}
