using Mta.Core;

namespace Mta.Storage.Postgres.Tests;

/// <summary>Process restarts: acknowledged mail survives, leases of a dead worker expire and the rows reappear, a new replica never steals live leases.</summary>
public class RecoveryTests : PgTestBase
{
    [Fact]
    public async Task Accepted_mail_and_history_survive_a_restart()
    {
        var m = await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"], subject: "Survives"));
        await Storage.DisposeAsync();

        PostgresStorage reopened = PostgresStorage.Create(PgHarness.WithDatabase(Options, Db.ConnectionString), Clock);
        await reopened.InitializeAsync(CancellationToken.None);
        try
        {
            Assert.NotNull(await reopened.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));
            Assert.Equal(2, (await reopened.Deliveries.ClaimAsync("w", 10, Clock.UtcNow, TimeSpan.FromMinutes(1), CancellationToken.None)).Count);
            Assert.Equal("Survives", (await reopened.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.Summary.Subject);
        }
        finally
        {
            await reopened.DisposeAsync();
        }
    }

    [Fact]
    public async Task Leases_of_a_dead_worker_expire_and_the_rows_are_claimable_again_without_counting_an_attempt()
    {
        await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"]));
        var firstClaim = await ClaimAsync(lease: TimeSpan.FromMinutes(2), owner: "dead-worker");
        Assert.Equal(2, firstClaim.Count);

        // The worker (and its whole process) is gone: only a new process with a new storage is left.
        await Storage.DisposeAsync();
        PostgresStorage restarted = PostgresStorage.Create(PgHarness.WithDatabase(Options, Db.ConnectionString), Clock);
        await restarted.InitializeAsync(CancellationToken.None);
        try
        {
            // Not before the lease ends (a replica must not steal live work, unlike the single-process SQLite backend).
            Assert.Empty(await restarted.Deliveries.ClaimAsync("w2", 10, Clock.UtcNow, TimeSpan.FromMinutes(1), CancellationToken.None));
            QueueStats during = await restarted.Deliveries.GetQueueStatsAsync(CancellationToken.None);
            Assert.Equal(2, during.Leased);

            Clock.Advance(TimeSpan.FromMinutes(3));
            var again = await restarted.Deliveries.ClaimAsync("w2", 10, Clock.UtcNow, TimeSpan.FromMinutes(1), CancellationToken.None);
            Assert.Equal(firstClaim.Select(d => d.DeliveryId).Order(), again.Select(d => d.DeliveryId).Order());
            Assert.All(again, d => Assert.Equal(0, d.Attempt));
        }
        finally
        {
            await restarted.DisposeAsync();
        }
    }

    [Fact]
    public async Task Maintenance_clears_the_owner_of_expired_leases()
    {
        await AcceptAsync();
        await ClaimAsync(lease: TimeSpan.FromMinutes(1), owner: "gone");
        Assert.Equal(1, await ScalarAsync<long>("SELECT count(*) FROM delivery_queue WHERE lease_owner IS NOT NULL"));

        Clock.Advance(TimeSpan.FromMinutes(2));
        var reports = await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        Assert.Equal(1, reports.Single(r => r.Job == "queue.leases").RowsAffected);
        Assert.Equal(0, await ScalarAsync<long>("SELECT count(*) FROM delivery_queue WHERE lease_owner IS NOT NULL"));
    }

    [Fact]
    public async Task A_second_replica_starting_leaves_the_first_ones_live_leases_alone()
    {
        await AcceptAsync();
        var claimed = await ClaimAsync(lease: TimeSpan.FromMinutes(10));
        PostgresStorage second = await OpenReplicaAsync();

        Assert.Empty(await second.Deliveries.ClaimAsync("other", 10, Clock.UtcNow, TimeSpan.FromMinutes(1), CancellationToken.None));
        Assert.True(await Storage.Deliveries.ExtendLeaseAsync(claimed.Single().DeliveryId, "worker-1", Clock.UtcNow.AddMinutes(20), CancellationToken.None));
    }

    [Fact]
    public async Task Unflushed_statistics_are_flushed_on_dispose()
    {
        Storage.Stats.Add(new StatKey(Start, TenantA, "s.example", "a.example"), StatCounter.Accepted, 7);
        await Storage.DisposeAsync();

        PostgresStorage reopened = PostgresStorage.Create(PgHarness.WithDatabase(Options, Db.ConnectionString), Clock);
        await reopened.InitializeAsync(CancellationToken.None);
        try
        {
            var rows = await reopened.Stats.QueryAsync(TenantA, Start.AddHours(-1), Start.AddHours(1), false, CancellationToken.None);
            Assert.Equal(7, rows.Single().Accepted);
        }
        finally
        {
            await reopened.DisposeAsync();
        }
    }

    [Fact]
    public async Task The_statistics_timer_flushes_without_being_asked()
    {
        await Storage.DisposeAsync();
        PostgresStorage timed = PostgresStorage.Create(PgHarness.WithDatabase(Options, Db.ConnectionString, o => new PostgresOptions
        {
            RuntimeConnectionString = o.RuntimeConnectionString,
            MaxPoolSize = o.MaxPoolSize,
            StatsFlushInterval = TimeSpan.FromMilliseconds(100),
        }), Clock);
        await timed.InitializeAsync(CancellationToken.None);
        try
        {
            timed.Stats.Add(new StatKey(Start, TenantA, "s.example", "a.example"), StatCounter.Delivered, 2);
            for (int i = 0; i < 50; i++)
            {
                var rows = await timed.Stats.QueryAsync(TenantA, Start.AddHours(-1), Start.AddHours(1), false, CancellationToken.None);
                if (rows.Count == 1)
                {
                    Assert.Equal(2, rows[0].Delivered);
                    return;
                }

                await Task.Delay(100);
            }

            Assert.Fail("the periodic flush never wrote the counters");
        }
        finally
        {
            await timed.DisposeAsync();
        }
    }
}
