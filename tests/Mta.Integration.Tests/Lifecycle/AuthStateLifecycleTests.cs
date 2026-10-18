using Mta.Host.Security;
using Mta.Storage;
using Mta.TestSupport;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>Session rows and shared failed-login counts in the database over virtual months, on both backends where the feature exists (shared counts need PostgreSQL's replica coordination).</summary>
public class AuthStateLifecycleTests
{
    private static readonly Guid UserId = Guid.Parse("c0000000-0000-7000-8000-000000000001");

    [Fact]
    public async Task Session_rows_are_removed_when_they_expire_over_a_virtual_month_on_sqlite()
    {
        var clock = new VirtualClock();
        await using HostBackend backend = await HostBackend.SqliteAsync(clock);
        await SessionTableAsync(backend, clock);
    }

    [PostgresFact]
    public async Task Session_rows_are_removed_when_they_expire_over_a_virtual_month_on_postgres()
    {
        var clock = new VirtualClock();
        await using HostBackend backend = await HostBackend.PostgresAsync(clock);
        await SessionTableAsync(backend, clock);
    }

    private static async Task SessionTableAsync(HostBackend backend, VirtualClock clock)
    {
        IConfigStore config = backend.Storage.Config;
        await config.UpsertDashboardUserAsync(new DashboardUser(UserId, "alice", "hash", DashboardRole.Tenant, null, true, clock.UtcNow), default);
        TimeSpan lifetime = TimeSpan.FromHours(12);
        var live = new List<DateTimeOffset>();   // expiry instants of the rows the model says are in the table
        int sessions = Accelerated.Scaled(360);
        for (int i = 0; i < sessions; i++)
        {
            clock.Advance(TimeSpan.FromHours(2));
            byte[] id = [.. Guid.NewGuid().ToByteArray(), .. Guid.NewGuid().ToByteArray()];
            var session = new DashboardSession(id, UserId, "csrf" + i, clock.UtcNow, clock.UtcNow, clock.UtcNow + lifetime);
            await config.AddDashboardSessionAsync(session, default);
            live.Add(session.ExpiresAt);

            // The purge a sign-in runs: it removes exactly the rows whose expiry is not after now.
            int expectedGone = live.Count(e => e <= clock.UtcNow);
            Assert.Equal(expectedGone, await config.DeleteExpiredDashboardSessionsAsync(clock.UtcNow, default));
            live.RemoveAll(e => e <= clock.UtcNow);
            Assert.InRange(live.Count, 1, 7);   // one row per two hours for twelve hours
        }

        // The rows that are left are the live ones and nothing else.
        Assert.Equal(live.Count, await config.DeleteExpiredDashboardSessionsAsync(clock.UtcNow + TimeSpan.FromDays(2), default));
    }

    [PostgresFact]
    public async Task Shared_failed_login_counts_lock_every_replica_and_unlock_at_the_end_of_the_window_for_two_years()
    {
        var clock = new VirtualClock();
        await using HostBackend backend = await HostBackend.PostgresAsync(clock);
        IReplicaCoordination shared = backend.Storage.Replicas ?? throw new InvalidOperationException("PostgreSQL provides replica coordination");
        byte[] digestKey = new byte[32];
        TimeSpan window = TimeSpan.FromMinutes(15);
        var replicaA = new AuthThrottle(clock, maxFailures: 5, window: window, shared: shared, digestKey: digestKey);
        var replicaB = new AuthThrottle(clock, maxFailures: 5, window: window, shared: shared, digestKey: digestKey);
        long bucketSeconds = (long)window.TotalSeconds / 15;   // 60 s
        string[] keys = ["198.51.100.7", "user:alice"];
        int cycles = Accelerated.Scaled(60);
        for (int cycle = 0; cycle < cycles; cycle++)
        {
            // Start of a counting bucket, so that the five failures share one and the lock ends at a computable instant.
            long unix = clock.UtcNow.ToUnixTimeSeconds();
            clock.Advance(TimeSpan.FromSeconds(bucketSeconds - unix % bucketSeconds));
            DateTimeOffset bucketStart = clock.UtcNow;

            for (int i = 0; i < 5; i++)
            {
                AuthThrottle replica = i % 2 == 0 ? replicaA : replicaB;
                Assert.False((await replica.CheckAsync(default, keys)).IsLockedOut);
                await replica.RecordFailureAsync(keys);   // failures land on both replicas, one count in the database
                clock.Advance(TimeSpan.FromSeconds(3));
            }

            Assert.True((await replicaB.CheckAsync(default, keys)).IsLockedOut);
            Assert.True((await replicaA.CheckAsync(default, keys)).IsLockedOut);

            // The counts of a bucket are valid until the end of the bucket plus the window.
            DateTimeOffset unlock = bucketStart + TimeSpan.FromSeconds(bucketSeconds) + window;
            clock.Advance(unlock - TimeSpan.FromSeconds(1) - clock.UtcNow);
            Assert.True((await replicaB.CheckAsync(default, keys)).IsLockedOut);
            clock.Advance(TimeSpan.FromSeconds(1));
            Assert.False((await replicaA.CheckAsync(default, keys)).IsLockedOut);
            Assert.False((await replicaB.CheckAsync(default, keys)).IsLockedOut);

            clock.Advance(TimeSpan.FromHours(10));
        }

        // Counts that aged out are pruned when new ones are written: what is left for the keys is within one window of buckets, not two years of them.
        string[] digests = replicaA.Digest(keys);
        await replicaA.RecordFailureAsync(keys);
        var stored = await shared.GetAuthFailuresAsync(digests, 0, default);
        Assert.InRange(stored.Count, 1, 2 * (int)(window.TotalSeconds / bucketSeconds + 2));
    }
}
