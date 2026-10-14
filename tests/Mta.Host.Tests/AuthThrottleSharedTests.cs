using System.Security.Cryptography;
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

    private static readonly byte[] Key = RandomNumberGenerator.GetBytes(32);

    private static AuthThrottle Replica(TestClock clock, IReplicaCoordination? shared, int maxFailures = 5, byte[]? key = null) =>
        new(clock, maxFailures, TimeSpan.FromMinutes(15), shared: shared, digestKey: shared is null ? null : key ?? Key);

    private static InMemoryReplicaCoordination Shared(TestClock clock) => new(clock);

    [Fact]
    public async Task The_budget_is_for_all_replicas_together()
    {
        var clock = new TestClock();
        var shared = Shared(clock);
        var a = Replica(clock, shared);
        var b = Replica(clock, shared);

        // An attacker alternates between the replicas: five failures in all lock the address out on both, not five on each.
        for (int i = 0; i < 5; i++)
        {
            var replica = i % 2 == 0 ? a : b;
            Assert.False((await replica.CheckAsync(default, "203.0.113.9", "user:alice")).IsLockedOut);
            await replica.RecordFailureAsync("203.0.113.9", "user:alice");
        }

        Assert.True((await a.CheckAsync(default, "203.0.113.9")).IsLockedOut);
        Assert.True((await b.CheckAsync(default, "203.0.113.9")).IsLockedOut);
        Assert.True((await b.CheckAsync(default, "198.51.100.1", "user:alice")).IsLockedOut);   // the user name is locked wherever it comes from
        Assert.False((await b.CheckAsync(default, "198.51.100.1", "user:bob")).IsLockedOut);
    }

    [Fact]
    public async Task Without_a_shared_store_each_process_counts_on_its_own()
    {
        var clock = new TestClock();
        var a = Replica(clock, null);
        var b = Replica(clock, null);
        for (int i = 0; i < 5; i++)
        {
            await a.RecordFailureAsync("203.0.113.9");
        }

        Assert.True((await a.CheckAsync(default, "203.0.113.9")).IsLockedOut);
        Assert.False((await b.CheckAsync(default, "203.0.113.9")).IsLockedOut);
        Assert.False(a.IsShared);
    }

    [Fact]
    public async Task A_success_on_one_replica_clears_the_user_everywhere_but_not_the_address()
    {
        var clock = new TestClock();
        var shared = Shared(clock);
        var a = Replica(clock, shared);
        var b = Replica(clock, shared);
        for (int i = 0; i < 5; i++)
        {
            await a.RecordFailureAsync("ip-1", "user:alice");
            await b.RecordFailureAsync("ip-2", "user:bob");
        }

        var check = await a.CheckAsync(default, "ip-3", "user:bob");   // the login attempt that succeeds, from another address, finds bob on record
        Assert.True(check.IsLockedOut);
        await a.RecordSuccessAsync(check, "user:bob");

        Assert.False((await b.CheckAsync(default, "user:bob")).IsLockedOut);
        Assert.True((await b.CheckAsync(default, "ip-2")).IsLockedOut);
        Assert.True((await b.CheckAsync(default, "user:alice")).IsLockedOut);
    }

    [Fact]
    public async Task A_successful_login_with_nothing_on_record_costs_no_write_and_one_that_follows_failures_one_delete()
    {
        var clock = new TestClock();
        var counting = new CountingCoordination(Shared(clock));
        var a = Replica(clock, counting);

        var clean = await a.CheckAsync(default, "ip-1", "user:alice");
        await a.RecordSuccessAsync(clean, "ip-1", "user:alice");
        Assert.Equal((1, 0, 0), (counting.Reads, counting.Adds, counting.Clears));   // the read, and nothing else

        await a.RecordFailureAsync("ip-1", "user:alice");
        var withFailures = await a.CheckAsync(default, "ip-1", "user:alice");
        Assert.False(withFailures.IsLockedOut);
        await a.RecordSuccessAsync(withFailures, "user:alice");
        Assert.Equal((2, 1, 1), (counting.Reads, counting.Adds, counting.Clears));
        Assert.False((await a.CheckAsync(default, "user:alice")).DigestsWithFailures.Any());
        Assert.True((await a.CheckAsync(default, "ip-1")).DigestsWithFailures.Any());   // only the user was cleared
    }

    [Fact]
    public async Task The_lockout_ends_as_the_oldest_failures_age_out_with_the_resolution_of_one_bucket()
    {
        var clock = new TestClock();
        var shared = Shared(clock);
        var a = Replica(clock, shared, maxFailures: 3);
        var b = Replica(clock, shared, maxFailures: 3);
        await a.RecordFailureAsync("ip-1");
        clock.Now = clock.Now.AddMinutes(5);
        await b.RecordFailureAsync("ip-1");
        await a.RecordFailureAsync("ip-1");

        // Three failures, the oldest five minutes ago: locked until the oldest leaves the window (15 minutes, plus the up to one minute its bucket is wide).
        TimeSpan wait = (await b.CheckAsync(default, "ip-1")).RetryAfter!.Value;
        Assert.InRange(wait.TotalMinutes, 10, 11.1);

        clock.Now = clock.Now.AddMinutes(11.5);
        Assert.False((await a.CheckAsync(default, "ip-1")).IsLockedOut);   // two left, below the budget of three
    }

    [Fact]
    public async Task A_database_that_cannot_be_reached_falls_back_to_the_counts_of_this_process()
    {
        var clock = new TestClock();
        var a = Replica(clock, new BrokenCoordination(), maxFailures: 3);
        Assert.False((await a.CheckAsync(default, "ip-1")).IsLockedOut);
        for (int i = 0; i < 3; i++)
        {
            await a.RecordFailureAsync("ip-1");   // does not throw
        }

        var check = await a.CheckAsync(default, "ip-1");
        Assert.True(check.IsLockedOut);
        await a.RecordSuccessAsync(check, "ip-1");
        Assert.False((await a.CheckAsync(default, "ip-1")).IsLockedOut);
    }

    [Fact]
    public async Task A_request_that_is_cancelled_does_not_cancel_the_recording_of_its_failure_but_does_stop_its_check()
    {
        var clock = new TestClock();
        var shared = new CountingCoordination(Shared(clock));
        var a = Replica(clock, shared);
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await a.CheckAsync(cancelled.Token, "ip-1"));
        await a.RecordFailureAsync("ip-1");   // takes no request token

        Assert.Single(await shared.GetAuthFailuresAsync(a.Digest(["ip-1"]), 0, default));
    }

    [Fact]
    public async Task Keys_are_stored_as_keyed_digests_so_the_same_key_in_any_case_is_one_budget_but_nothing_is_readable_without_the_key()
    {
        var clock = new TestClock();
        var recording = new CountingCoordination(Shared(clock));
        var a = Replica(clock, recording);
        var other = Replica(clock, recording, key: RandomNumberGenerator.GetBytes(32));
        await a.RecordFailureAsync("user:Alice@Example.COM", "2001:DB8::1");
        await a.RecordFailureAsync("user:alice@example.com");

        Assert.All(recording.Digests, k => Assert.Matches("^[0-9A-F]{64}$", k));
        Assert.DoesNotContain(recording.Digests, k => k.Contains("alice", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(2, recording.Digests.Count(k => k == recording.Digests[0]));   // both spellings of the user name hit one counter
        // A table copied without the key cannot be matched against guesses of addresses, and a different key gives different digests.
        Assert.NotEqual(a.Digest(["2001:db8::1"])[0], other.Digest(["2001:db8::1"])[0]);
        Assert.NotEqual(Convert.ToHexString(SHA256.HashData("2001:db8::1"u8)), a.Digest(["2001:db8::1"])[0]);
        Assert.Throws<ArgumentException>(() => new AuthThrottle(clock, shared: recording, digestKey: null));
    }

    [Fact]
    public async Task The_digest_key_is_created_once_protected_and_found_again_by_the_next_replica()
    {
        var clock = new TestClock();
        await using var storage = new InMemoryStorage(new StorageOptions(), clock);
        var protector = new TestProtector();

        byte[]? first = await AuthThrottleKeyStore.LoadOrCreateAsync(storage.Config, protector, clock, default);
        byte[]? second = await AuthThrottleKeyStore.LoadOrCreateAsync(storage.Config, protector, clock, default);

        Assert.NotNull(first);
        Assert.Equal(32, first.Length);
        Assert.Equal(first, second);
        var stored = (await storage.Config.GetSettingsAsync(null, default)).Single(s => s.Key == AuthThrottleKeyStore.SettingKey);
        Assert.DoesNotContain(Convert.ToBase64String(first), stored.ValueJson, StringComparison.Ordinal);   // protected, not stored in the clear

        // Replicas starting together agree on one key.
        await using var other = new InMemoryStorage(new StorageOptions(), clock);
        byte[]?[] keys = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => AuthThrottleKeyStore.LoadOrCreateAsync(other.Config, protector, clock, default)));
        Assert.All(keys, k => Assert.Equal(keys[0], k));
    }

    [Fact]
    public async Task A_stored_digest_key_that_can_no_longer_be_read_is_replaced()
    {
        var clock = new TestClock();
        await using var storage = new InMemoryStorage(new StorageOptions(), clock);
        await storage.Config.SetSettingAsync(new SettingRecord(AuthThrottleKeyStore.SettingKey, null, "{\"Protected\":\"AAAA\"}", clock.UtcNow), default);

        byte[]? key = await AuthThrottleKeyStore.LoadOrCreateAsync(storage.Config, new TestProtector(), clock, default);

        Assert.NotNull(key);
        Assert.Equal(key, await AuthThrottleKeyStore.LoadOrCreateAsync(storage.Config, new TestProtector(), clock, default));
    }

    private class PassThroughCoordination(IReplicaCoordination inner) : IReplicaCoordination
    {
        public virtual ValueTask<IReadOnlyList<string>> HeartbeatAsync(string replicaName, TimeSpan liveFor, CancellationToken ct) => inner.HeartbeatAsync(replicaName, liveFor, ct);

        public virtual ValueTask LeaveAsync(string replicaName, CancellationToken ct) => inner.LeaveAsync(replicaName, ct);

        public virtual ValueTask PublishSignalsAsync(string replicaName, IReadOnlyList<PeerSignal> signals, CancellationToken ct) => inner.PublishSignalsAsync(replicaName, signals, ct);

        public virtual ValueTask<IReadOnlyList<ReceivedPeerSignal>> GetSignalsAsync(string replicaName, CancellationToken ct) => inner.GetSignalsAsync(replicaName, ct);

        public virtual ValueTask<IReadOnlyList<AuthFailureCount>> GetAuthFailuresAsync(IReadOnlyList<string> keyDigests, long minBucket, CancellationToken ct) => inner.GetAuthFailuresAsync(keyDigests, minBucket, ct);

        public virtual ValueTask AddAuthFailuresAsync(IReadOnlyList<string> keyDigests, long bucket, long pruneBeforeBucket, CancellationToken ct) => inner.AddAuthFailuresAsync(keyDigests, bucket, pruneBeforeBucket, ct);

        public virtual ValueTask ClearAuthFailuresAsync(IReadOnlyList<string> keyDigests, CancellationToken ct) => inner.ClearAuthFailuresAsync(keyDigests, ct);
    }

    private sealed class CountingCoordination(IReplicaCoordination inner) : PassThroughCoordination(inner)
    {
        public int Reads;
        public int Adds;
        public int Clears;
        public List<string> Digests { get; } = [];

        public override ValueTask<IReadOnlyList<AuthFailureCount>> GetAuthFailuresAsync(IReadOnlyList<string> keyDigests, long minBucket, CancellationToken ct)
        {
            Reads++;
            ct.ThrowIfCancellationRequested();
            return base.GetAuthFailuresAsync(keyDigests, minBucket, ct);
        }

        public override ValueTask AddAuthFailuresAsync(IReadOnlyList<string> keyDigests, long bucket, long pruneBeforeBucket, CancellationToken ct)
        {
            Adds++;
            ct.ThrowIfCancellationRequested();
            Digests.AddRange(keyDigests);
            return base.AddAuthFailuresAsync(keyDigests, bucket, pruneBeforeBucket, ct);
        }

        public override ValueTask ClearAuthFailuresAsync(IReadOnlyList<string> keyDigests, CancellationToken ct)
        {
            Clears++;
            return base.ClearAuthFailuresAsync(keyDigests, ct);
        }
    }

    private sealed class BrokenCoordination : IReplicaCoordination
    {
        private static InvalidOperationException Down() => new("database unavailable");

        public ValueTask<IReadOnlyList<string>> HeartbeatAsync(string replicaName, TimeSpan liveFor, CancellationToken ct) => throw Down();

        public ValueTask LeaveAsync(string replicaName, CancellationToken ct) => throw Down();

        public ValueTask PublishSignalsAsync(string replicaName, IReadOnlyList<PeerSignal> signals, CancellationToken ct) => throw Down();

        public ValueTask<IReadOnlyList<ReceivedPeerSignal>> GetSignalsAsync(string replicaName, CancellationToken ct) => throw Down();

        public ValueTask<IReadOnlyList<AuthFailureCount>> GetAuthFailuresAsync(IReadOnlyList<string> keyDigests, long minBucket, CancellationToken ct) => throw Down();

        public ValueTask AddAuthFailuresAsync(IReadOnlyList<string> keyDigests, long bucket, long pruneBeforeBucket, CancellationToken ct) => throw Down();

        public ValueTask ClearAuthFailuresAsync(IReadOnlyList<string> keyDigests, CancellationToken ct) => throw Down();
    }
}
