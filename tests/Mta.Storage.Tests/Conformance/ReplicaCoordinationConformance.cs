namespace Mta.Storage.Tests;

/// <summary>
/// What replicas on one database exchange (<see cref="IReplicaCoordination"/>): liveness, signals about remote destinations and the failed-login counts.
/// The in-memory and PostgreSQL backends run it; SQLite is one process by design and offers no coordination. Time is the storage's own (the test clock for the in-memory
/// backend, the database server's for PostgreSQL), so a test that needs time to pass says so with <see cref="PassTimeAsync"/> and asserts only in the direction that
/// passing time can never reverse.
/// </summary>
public abstract class ReplicaCoordinationConformance : StorageTestBase
{
    private IReplicaCoordination Replicas => Storage.Replicas ?? throw new InvalidOperationException("this backend has no replica coordination");

    private static readonly TimeSpan Forever = TimeSpan.FromHours(1);

    /// <summary>Lets <paramref name="by"/> pass on the clock the backend under test uses.</summary>
    protected abstract Task PassTimeAsync(TimeSpan by);

    [Fact]
    public async Task Heartbeats_list_the_live_replicas_in_ordinal_order()
    {
        Assert.Equal(["b"], await Replicas.HeartbeatAsync("b", Forever, default));
        Assert.Equal(["a", "b"], await Replicas.HeartbeatAsync("a", Forever, default));
        Assert.Equal(["a", "b", "c"], await Replicas.HeartbeatAsync("c", Forever, default));
        Assert.Equal(["a", "b", "c"], await Replicas.HeartbeatAsync("b", Forever, default));
    }

    [Fact]
    public async Task A_replica_that_stopped_beating_drops_out_of_the_live_set_after_the_liveness_window()
    {
        await Replicas.HeartbeatAsync("a", Forever, default);
        await Replicas.HeartbeatAsync("b", Forever, default);

        // The margins are seconds, not milliseconds: "b" is live only if the two round trips of its own heartbeat (the insert, then the select) take less
        // than the window, and on a loaded CI runner 100 ms was not enough (the list came back empty). "a" being too old can only get truer with delay.
        await PassTimeAsync(TimeSpan.FromMilliseconds(2500));
        Assert.Equal(["b"], await Replicas.HeartbeatAsync("b", TimeSpan.FromSeconds(2), default));   // "a" beat more than 2 s ago, "b" just now
        Assert.Equal(["a", "b"], await Replicas.HeartbeatAsync("b", Forever, default));              // still known, just not live
    }

    [Fact]
    public async Task A_replica_that_leaves_is_gone_at_once_together_with_its_signals()
    {
        await Replicas.HeartbeatAsync("a", Forever, default);
        await Replicas.HeartbeatAsync("b", Forever, default);
        await Replicas.PublishSignalsAsync("b", [Signal(PeerSignalKind.CircuitOpened, "mx:mail.example", 300)], default);
        Assert.Single(await Replicas.GetSignalsAsync("a", default));

        await Replicas.LeaveAsync("b", default);

        Assert.Equal(["a"], await Replicas.HeartbeatAsync("a", Forever, default));
        Assert.Empty(await Replicas.GetSignalsAsync("a", default));
    }

    [Fact]
    public async Task Signals_reach_the_other_replicas_with_what_is_left_of_their_validity()
    {
        await Replicas.PublishSignalsAsync("a", [Signal(PeerSignalKind.CircuitOpened, "mx:mail.example", 300), Signal(PeerSignalKind.DestinationSlowedDown, "big.example", 60)], default);

        Assert.Empty(await Replicas.GetSignalsAsync("a", default));   // never one's own
        var seen = await Replicas.GetSignalsAsync("b", default);
        Assert.Equal([(PeerSignalKind.CircuitOpened, "mx:mail.example"), (PeerSignalKind.DestinationSlowedDown, "big.example")], seen.OrderBy(s => s.Signal.Kind).Select(s => (s.Signal.Kind, s.Signal.Key)));
        Assert.All(seen, s => Assert.Equal("a", s.ReplicaName));
        var opened = seen.Single(s => s.Signal.Kind == PeerSignalKind.CircuitOpened).Signal;
        Assert.InRange(opened.ValidFor, TimeSpan.FromSeconds(290), TimeSpan.FromSeconds(300));
        Assert.Equal(TimeSpan.FromSeconds(300), opened.Cooldown);
        Assert.Equal(TimeSpan.Zero, seen.Single(s => s.Signal.Kind == PeerSignalKind.DestinationSlowedDown).Signal.Cooldown);
    }

    [Fact]
    public async Task A_newer_publication_replaces_the_older_one_and_is_told_apart_by_its_raised_time()
    {
        await Replicas.PublishSignalsAsync("a", [Signal(PeerSignalKind.CircuitOpened, "mx:mail.example", 300)], default);
        var first = Assert.Single(await Replicas.GetSignalsAsync("b", default));

        await PassTimeAsync(TimeSpan.FromMilliseconds(20));
        await Replicas.PublishSignalsAsync("a", [new PeerSignal(PeerSignalKind.CircuitOpened, "mx:mail.example", TimeSpan.FromSeconds(900), TimeSpan.FromSeconds(600))], default);

        var second = Assert.Single(await Replicas.GetSignalsAsync("b", default));
        Assert.True(second.RaisedAt > first.RaisedAt);
        Assert.Equal(TimeSpan.FromSeconds(600), second.Signal.Cooldown);
        Assert.True(second.Signal.ValidFor > TimeSpan.FromSeconds(600));
    }

    [Fact]
    public async Task A_signal_is_not_delivered_after_it_ended()
    {
        await Replicas.PublishSignalsAsync("a", [new PeerSignal(PeerSignalKind.DestinationSlowedDown, "short.example", TimeSpan.FromMilliseconds(100), TimeSpan.Zero), Signal(PeerSignalKind.DestinationSlowedDown, "long.example", 3600)], default);

        await PassTimeAsync(TimeSpan.FromMilliseconds(300));

        Assert.Equal(["long.example"], (await Replicas.GetSignalsAsync("b", default)).Select(s => s.Signal.Key));
    }

    [Fact]
    public async Task Signals_published_by_two_replicas_for_one_key_are_kept_apart()
    {
        await Replicas.PublishSignalsAsync("a", [Signal(PeerSignalKind.CircuitOpened, "mx:mail.example", 300)], default);
        await Replicas.PublishSignalsAsync("b", [Signal(PeerSignalKind.CircuitOpened, "mx:mail.example", 120)], default);
        Assert.Equal(["a", "b"], (await Replicas.GetSignalsAsync("c", default)).Select(s => s.ReplicaName));
        Assert.Equal(["b"], (await Replicas.GetSignalsAsync("a", default)).Select(s => s.ReplicaName));
    }

    [Fact]
    public async Task Failed_logins_add_up_across_callers_per_key_and_bucket_and_old_buckets_are_pruned()
    {
        await Replicas.AddAuthFailuresAsync(["ip-1", "user-1"], 100, 90, default);
        await Replicas.AddAuthFailuresAsync(["ip-1"], 100, 90, default);
        await Replicas.AddAuthFailuresAsync(["ip-1", "ip-1"], 101, 90, default);   // a repeated key counts once per call
        await Replicas.AddAuthFailuresAsync(["ip-2"], 95, 90, default);

        var counts = await Replicas.GetAuthFailuresAsync(["ip-1", "user-1"], 0, default);
        Assert.Equal([("ip-1", 100L, 2L), ("ip-1", 101L, 1L), ("user-1", 100L, 1L)], counts.Select(c => (c.KeyDigest, c.Bucket, c.Count)));
        Assert.Equal([("ip-1", 101L, 1L)], (await Replicas.GetAuthFailuresAsync(["ip-1"], 101, default)).Select(c => (c.KeyDigest, c.Bucket, c.Count)));
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
    public async Task Concurrent_failures_and_clears_from_many_callers_are_all_counted_and_never_deadlock()
    {
        await Task.WhenAll(Enumerable.Range(0, 40).Select(i => Task.Run(() => Replicas.AddAuthFailuresAsync(["shared", i % 2 == 0 ? "even" : "odd"], 100, 90, default).AsTask())));
        var counts = (await Replicas.GetAuthFailuresAsync(["shared", "even", "odd"], 0, default)).ToDictionary(c => c.KeyDigest, c => c.Count);
        Assert.Equal((40L, 20L, 20L), (counts["shared"], counts["even"], counts["odd"]));

        // Clears of overlapping key sets in opposite orders, together with failures and pruning.
        await Task.WhenAll(Enumerable.Range(0, 40).Select(i => Task.Run(async () =>
        {
            await Replicas.ClearAuthFailuresAsync(i % 2 == 0 ? ["even", "odd"] : ["odd", "even"], default);
            await Replicas.AddAuthFailuresAsync(["shared"], 100 + i, 95, default);
        })));
        Assert.Empty(await Replicas.GetAuthFailuresAsync(["even", "odd"], 0, default));
    }

    private static PeerSignal Signal(PeerSignalKind kind, string key, int validSeconds) =>
        new(kind, key, TimeSpan.FromSeconds(validSeconds), kind == PeerSignalKind.CircuitOpened ? TimeSpan.FromSeconds(validSeconds) : TimeSpan.Zero);
}
