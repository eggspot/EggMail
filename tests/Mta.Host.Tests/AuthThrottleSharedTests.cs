using Mta.Core;
using Mta.Host.Security;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests;

/// <summary>The failed-login budget is shared by replicas on one database (the in-memory coordination stands for it; PostgreSQL passes the same contract in its conformance suite).</summary>
public class AuthThrottleSharedTests
{
    private sealed class TestClock : IClock
    {
        public DateTimeOffset Now { get; set; } = new(2026, 10, 12, 8, 0, 0, TimeSpan.Zero);

        public DateTimeOffset UtcNow => Now;

        public long Timestamp => Now.Ticks;
    }

    private static AuthThrottle Replica(TestClock clock, IReplicaCoordination? shared, int maxFailures = 5) =>
        new(clock, maxFailures, TimeSpan.FromMinutes(15), shared: shared);

    [Fact]
    public async Task The_budget_is_for_all_replicas_together()
    {
        var clock = new TestClock();
        var shared = new InMemoryReplicaCoordination();
        var a = Replica(clock, shared);
        var b = Replica(clock, shared);

        // An attacker alternates between the replicas: five failures in all lock the address out on both, not five on each.
        for (int i = 0; i < 5; i++)
        {
            Assert.Null(await (i % 2 == 0 ? a : b).CheckAsync(default, "203.0.113.9", "user:alice"));
            await (i % 2 == 0 ? a : b).RecordFailureAsync(default, "203.0.113.9", "user:alice");
        }

        Assert.NotNull(await a.CheckAsync(default, "203.0.113.9"));
        Assert.NotNull(await b.CheckAsync(default, "203.0.113.9"));
        Assert.NotNull(await b.CheckAsync(default, "198.51.100.1", "user:alice"));   // the user name is locked wherever it comes from
        Assert.Null(await b.CheckAsync(default, "198.51.100.1", "user:bob"));
    }

    [Fact]
    public async Task Without_a_shared_store_each_process_counts_on_its_own()
    {
        var clock = new TestClock();
        var a = Replica(clock, null);
        var b = Replica(clock, null);
        for (int i = 0; i < 5; i++)
        {
            await a.RecordFailureAsync(default, "203.0.113.9");
        }

        Assert.NotNull(await a.CheckAsync(default, "203.0.113.9"));
        Assert.Null(await b.CheckAsync(default, "203.0.113.9"));
        Assert.False(a.IsShared);
    }

    [Fact]
    public async Task A_success_on_one_replica_clears_the_user_everywhere_but_not_the_address()
    {
        var clock = new TestClock();
        var shared = new InMemoryReplicaCoordination();
        var a = Replica(clock, shared);
        var b = Replica(clock, shared);
        for (int i = 0; i < 5; i++)
        {
            await a.RecordFailureAsync(default, "ip-1", "user:alice");
            await b.RecordFailureAsync(default, "ip-2", "user:bob");
        }

        await a.RecordSuccessAsync(default, "user:bob");

        Assert.Null(await b.CheckAsync(default, "user:bob"));
        Assert.NotNull(await b.CheckAsync(default, "ip-2"));
        Assert.NotNull(await b.CheckAsync(default, "user:alice"));
    }

    [Fact]
    public async Task The_lockout_ends_as_the_oldest_failures_age_out_with_the_resolution_of_one_bucket()
    {
        var clock = new TestClock();
        var shared = new InMemoryReplicaCoordination();
        var a = Replica(clock, shared, maxFailures: 3);
        var b = Replica(clock, shared, maxFailures: 3);
        await a.RecordFailureAsync(default, "ip-1");
        clock.Now = clock.Now.AddMinutes(5);
        await b.RecordFailureAsync(default, "ip-1");
        await a.RecordFailureAsync(default, "ip-1");

        // Three failures, the oldest five minutes ago: locked until the oldest leaves the window (15 minutes, plus the up to one minute its bucket is wide).
        TimeSpan wait = (await b.CheckAsync(default, "ip-1"))!.Value;
        Assert.InRange(wait.TotalMinutes, 10, 11.1);

        clock.Now = clock.Now.AddMinutes(11.5);
        Assert.Null(await a.CheckAsync(default, "ip-1"));   // two left, below the budget of three
        clock.Now = clock.Now.AddMinutes(10);
        Assert.Null(await a.CheckAsync(default, "ip-1"));
    }

    [Fact]
    public async Task A_database_that_cannot_be_reached_falls_back_to_the_counts_of_this_process()
    {
        var clock = new TestClock();
        var broken = new BrokenCoordination();
        var a = Replica(clock, broken, maxFailures: 3);
        Assert.Null(await a.CheckAsync(default, "ip-1"));
        for (int i = 0; i < 3; i++)
        {
            await a.RecordFailureAsync(default, "ip-1");   // does not throw
        }

        Assert.NotNull(await a.CheckAsync(default, "ip-1"));
        await a.RecordSuccessAsync(default, "ip-1");
        Assert.Null(await a.CheckAsync(default, "ip-1"));
    }

    [Fact]
    public async Task Keys_are_stored_as_digests_in_one_case_and_the_same_key_in_any_case_is_the_same_budget()
    {
        var clock = new TestClock();
        var recording = new RecordingCoordination();
        var a = Replica(clock, recording);
        await a.RecordFailureAsync(default, "user:Alice@Example.COM", "2001:DB8::1");
        await a.RecordFailureAsync(default, "user:alice@example.com");

        Assert.All(recording.Keys, k => Assert.Matches("^[0-9A-F]{64}$", k));
        Assert.DoesNotContain(recording.Keys, k => k.Contains("alice", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(2, recording.Keys.Count(k => k == recording.Keys[0]));   // both spellings of the user name hit one counter
    }

    private sealed class BrokenCoordination : IReplicaCoordination
    {
        private static InvalidOperationException Down() => new("database unavailable");

        public ValueTask<IReadOnlyList<string>> HeartbeatAsync(string replicaId, DateTimeOffset now, TimeSpan liveFor, CancellationToken ct) => throw Down();

        public ValueTask LeaveAsync(string replicaId, CancellationToken ct) => throw Down();

        public ValueTask PublishSignalsAsync(IReadOnlyList<PeerSignal> signals, DateTimeOffset now, CancellationToken ct) => throw Down();

        public ValueTask<IReadOnlyList<PeerSignal>> GetSignalsAsync(string replicaId, DateTimeOffset now, CancellationToken ct) => throw Down();

        public ValueTask<IReadOnlyList<AuthFailureCount>> GetAuthFailuresAsync(IReadOnlyList<string> keyHashes, long minBucket, CancellationToken ct) => throw Down();

        public ValueTask AddAuthFailuresAsync(IReadOnlyList<string> keyHashes, long bucket, long pruneBeforeBucket, CancellationToken ct) => throw Down();

        public ValueTask ClearAuthFailuresAsync(IReadOnlyList<string> keyHashes, CancellationToken ct) => throw Down();
    }

    private sealed class RecordingCoordination : IReplicaCoordination
    {
        public List<string> Keys { get; } = [];

        public ValueTask<IReadOnlyList<string>> HeartbeatAsync(string replicaId, DateTimeOffset now, TimeSpan liveFor, CancellationToken ct) => throw new NotSupportedException();

        public ValueTask LeaveAsync(string replicaId, CancellationToken ct) => throw new NotSupportedException();

        public ValueTask PublishSignalsAsync(IReadOnlyList<PeerSignal> signals, DateTimeOffset now, CancellationToken ct) => throw new NotSupportedException();

        public ValueTask<IReadOnlyList<PeerSignal>> GetSignalsAsync(string replicaId, DateTimeOffset now, CancellationToken ct) => throw new NotSupportedException();

        public ValueTask<IReadOnlyList<AuthFailureCount>> GetAuthFailuresAsync(IReadOnlyList<string> keyHashes, long minBucket, CancellationToken ct) => throw new NotSupportedException();

        public ValueTask AddAuthFailuresAsync(IReadOnlyList<string> keyHashes, long bucket, long pruneBeforeBucket, CancellationToken ct)
        {
            Keys.AddRange(keyHashes);
            return ValueTask.CompletedTask;
        }

        public ValueTask ClearAuthFailuresAsync(IReadOnlyList<string> keyHashes, CancellationToken ct) => throw new NotSupportedException();
    }
}
