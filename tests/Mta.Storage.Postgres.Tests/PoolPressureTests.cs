using Mta.Core;
using Npgsql;

namespace Mta.Storage.Postgres.Tests;

/// <summary>
/// Far more concurrent callers than pooled connections, with day partitions that are not known yet. No code path may hold a
/// connection (or a transaction with row locks) while it waits for a second one: that is a pool-exhaustion deadlock that only
/// ends when the connection timeout fires ("The operation has timed out").
/// </summary>
public class PoolPressureTests : PgTestBase
{
    private const int Callers = 64;

    private static Func<PostgresOptions, PostgresOptions> SmallPool(int size) => o => new PostgresOptions
    {
        RuntimeConnectionString = new NpgsqlConnectionStringBuilder(o.RuntimeConnectionString) { Timeout = 20 }.ConnectionString,
        MaxPoolSize = size,
        StatsFlushInterval = TimeSpan.Zero,
        RetentionDeletePause = o.RetentionDeletePause,
    };

    [Fact]
    public async Task Many_more_callers_than_pooled_connections_complete_without_timeouts_when_partitions_are_not_known_yet()
    {
        // Messages of 16 different days beyond the partitions created at start, so every first write needs a partition.
        var messages = Enumerable.Range(0, Callers)
            .Select(i => Msg(to: [$"u{i}@example.org"], received: Start.AddDays(15 + (i % 16)).AddSeconds(i), size: 256, lifetime: TimeSpan.FromDays(90)))
            .ToList();

        // A fresh instance with a pool of 4 and no knowledge of those days.
        PostgresStorage small = await OpenReplicaAsync(SmallPool(4));
        // No elapsed-time assertion (it measured the load of the machine): pool starvation shows as an exception from the
        // pool's own timeout, a deadlock as a hang, which the wait below turns into a failure.
        await Task.WhenAll(messages.Select(m => Task.Run(async () => (await small.Intake.AcceptAsync(m, CancellationToken.None)).Status))).WaitAsync(TimeSpan.FromMinutes(3));

        // Claim from 64 callers at once.
        Clock.Set(Start.AddDays(32));
        var claimed = new System.Collections.Concurrent.ConcurrentBag<ClaimedDelivery>();
        await Task.WhenAll(Enumerable.Range(0, Callers).Select(i => Task.Run(async () =>
        {
            foreach (ClaimedDelivery d in await small.Deliveries.ClaimAsync("w" + i, 2, Clock.UtcNow, TimeSpan.FromMinutes(5), CancellationToken.None))
            {
                claimed.Add(d);
            }
        })));
        Assert.Equal(Callers, claimed.Count);

        // Record from a second fresh instance (it has not seen those days either): 64 concurrent first attempts, pool of 4.
        PostgresStorage recorder = await OpenReplicaAsync(SmallPool(4));
        await Task.WhenAll(claimed.Select(d => Task.Run(async () =>
            await recorder.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = Clock.UtcNow, SmtpCode = 250 }, CancellationToken.None)))).WaitAsync(TimeSpan.FromMinutes(3));

        QueueStats stats = await recorder.Deliveries.GetQueueStatsAsync(CancellationToken.None);
        Assert.Equal(0, stats.Queued + stats.Leased + stats.Deferred);
        Assert.Equal("delivered", (await recorder.History.GetAsync(TenantA, messages[0].MessageId, CancellationToken.None))!.Summary.Status);
    }

    [Fact]
    public async Task Concurrent_records_that_all_need_missing_partitions_neither_deadlock_nor_time_out()
    {
        // 48 messages over 12 days, accepted normally; then every one of those days loses its partitions behind the app's back
        // (as if another replica's retention had dropped them), so each of the 48 concurrent first attempts has to bring a
        // partition back while others hold history rows in open transactions.
        var messages = new List<AcceptedMessage>();
        for (int i = 0; i < 48; i++)
        {
            messages.Add(await AcceptAsync(Msg(to: [$"u{i}@example.org"], received: Start.AddDays(10 + (i % 12)).AddSeconds(i), size: 128, lifetime: TimeSpan.FromDays(90))));
        }

        Clock.Set(Start.AddDays(25));
        var claimed = await ClaimAsync(max: 100);
        Assert.Equal(48, claimed.Count);
        for (int d = 10; d < 22; d++)
        {
            foreach (string table in PostgresPartitions.Tables)
            {
                await ExecuteAsync($"DROP TABLE {PostgresPartitions.NameOf(table, Logic.StorageTime.DayNumber(Start.AddDays(d)))}");
            }
        }

        PostgresStorage recorder = await OpenReplicaAsync(SmallPool(4));
        await Task.WhenAll(claimed.Select(c => Task.Run(async () =>
            await recorder.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = c.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = Clock.UtcNow, SmtpCode = 250 }, CancellationToken.None)))).WaitAsync(TimeSpan.FromMinutes(3));

        QueueStats stats = await recorder.Deliveries.GetQueueStatsAsync(CancellationToken.None);
        Assert.Equal(0, stats.Queued + stats.Leased + stats.Deferred);
        Assert.Equal(48, await ScalarAsync<long>("SELECT count(*) FROM message_event WHERE type = 1"));
    }

    [Fact]
    public async Task A_record_for_a_day_without_partitions_works_with_a_pool_of_one()
    {
        // The message is accepted by another instance; this one (pool of exactly one connection) has never seen its day.
        var m = await AcceptAsync(Msg(received: Start.AddDays(17)));
        Clock.Set(Start.AddDays(17));
        var d = (await ClaimAsync()).Single();
        await ExecuteAsync("DROP TABLE message_event_p" + Start.AddDays(17).UtcDateTime.ToString("yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture));

        PostgresStorage single = await OpenReplicaAsync(SmallPool(1));
        await single.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = Clock.UtcNow, SmtpCode = 250 }, CancellationToken.None);
        Assert.Equal("delivered", (await single.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.Summary.Status);
    }

    [Fact]
    public async Task Partition_creation_does_not_block_or_deadlock_with_writers_in_open_transactions()
    {
        // A writer holds history rows of the current day in an open transaction while another day's partition is created.
        await using var writer = new NpgsqlConnection(Db.ConnectionString);
        await writer.OpenAsync();
        await using NpgsqlTransaction tx = await writer.BeginTransactionAsync();
        await using (var insert = new NpgsqlCommand(
            "INSERT INTO message_event (day, message_id, event_id, tenant_id, type, at) VALUES ($1, $2, $3, $4, 0, $5)", writer, tx))
        {
            insert.Parameters.Add(new NpgsqlParameter { Value = Logic.StorageTime.DayNumber(Start) });
            insert.Parameters.Add(new NpgsqlParameter { Value = Ids.New(Start) });
            insert.Parameters.Add(new NpgsqlParameter { Value = Ids.New(Start) });
            insert.Parameters.Add(new NpgsqlParameter { Value = TenantA });
            insert.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.TimestampTz, Value = Start.UtcDateTime });
            await insert.ExecuteNonQueryAsync();
        }

        var creation = Pg.Runtime.Partitions.EnsureRangeAsync(Logic.StorageTime.DayNumber(Start) + 40, Logic.StorageTime.DayNumber(Start) + 40, CancellationToken.None);
        Assert.Same(creation, await Task.WhenAny(creation, Task.Delay(TimeSpan.FromSeconds(60))));
        Assert.Equal(PostgresPartitions.Tables.Length, await creation);
        await tx.RollbackAsync();
    }
}
