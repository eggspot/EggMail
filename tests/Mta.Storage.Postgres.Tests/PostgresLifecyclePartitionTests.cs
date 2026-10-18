using System.Globalization;
using Mta.Core;
using Mta.Storage.Logic;
using Mta.TestSupport;
using Npgsql;
using Xunit.Abstractions;

namespace Mta.Storage.Postgres.Tests;

/// <summary>
/// Accelerated lifecycle of the day partitions (part of the "Lifecycle" family, PostgreSQL only): creation ahead, rotation by DETACH + DROP at the metadata and content
/// retention over many virtual days, a rotation interrupted between DETACH and DROP, and several replicas maintaining at once.
/// </summary>
public class PostgresLifecyclePartitionTests(ITestOutputHelper output) : PgTestBase
{
    private const int MetadataDays = 12;
    private const int ContentDays = 6;

    protected override StorageOptions BuildOptions() => new()
    {
        Retention = new RetentionOptions { MetadataDays = MetadataDays },
        Content = new ContentOptions { RetentionDays = ContentDays },
    };

    private static string Name(string table, int day) => PostgresPartitions.NameOf(table, day);

    private async Task<HashSet<int>> DaysOfAsync(string table)
    {
        var days = new HashSet<int>();
        foreach (string name in await PartitionNamesAsync(table))
        {
            days.Add(StorageTime.DayNumber(DateTimeOffset.ParseExact(name[^8..], "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal)));
        }

        return days;
    }

    /// <summary>Tables named like a partition of a history table but attached to nothing: what an interrupted rotation leaves behind.</summary>
    private async Task<List<string>> DetachedLeftoversAsync()
    {
        await using var c = new NpgsqlConnection(Db.ConnectionString);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            @"SELECT c.relname FROM pg_class c WHERE c.relkind = 'r' AND c.relnamespace = 'public'::regnamespace AND NOT c.relispartition
              AND c.relname ~ '^message_(index|recipient|event|content|raw_retained)_p[0-9]{8}$' ORDER BY 1", c);
        var list = new List<string>();
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            list.Add(r.GetString(0));
        }

        return list;
    }

    [Fact]
    public async Task Lifecycle_partitions_are_created_ahead_and_rotated_out_at_the_retention_over_many_days_with_a_bounded_count()
    {
        int days = Accelerated.Scaled(30);   // EGGMAIL_ACCEL_SCALE=4 gives 120 virtual days
        int ahead = Options.Postgres.PartitionsAheadDays;
        int originDay = StorageTime.DayNumber(Start);
        int plateau = -1;
        var ids = new List<(Guid Id, DateTimeOffset At)>();

        for (int day = 0; day < days; day++)
        {
            Clock.Set(Start.AddDays(day));
            AcceptedMessage m = await AcceptAsync(Msg(received: Clock.UtcNow, retainRaw: day % 2 == 0, to: [$"u{day}@example.org"], size: 100));
            ids.Add((m.MessageId, m.ReceivedAt));
            foreach (ClaimedDelivery d in await ClaimAsync())
            {
                await RecordAsync(d, DeliveryOutcome.Delivered);
            }

            IReadOnlyList<MaintenanceReport> reports = await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
            Assert.DoesNotContain(reports, r => r.Detail?.StartsWith("skipped", StringComparison.Ordinal) == true);
            int today = originDay + day;

            foreach (string table in PostgresPartitions.Tables)
            {
                bool metadata = PostgresPartitions.MetadataTables.Contains(table);
                int cutoff = StorageTime.DayNumber(Clock.UtcNow.AddDays(-(metadata ? MetadataDays : ContentDays)));
                var expected = Enumerable.Range(Math.Max(cutoff, originDay - 1), today + ahead - Math.Max(cutoff, originDay - 1) + 1).ToHashSet();
                HashSet<int> actual = await DaysOfAsync(table);
                Assert.True(expected.SetEquals(actual), $"{table} on day {day}: partitions {string.Join(",", actual.Order().Select(d => d - originDay))} but expected {string.Join(",", expected.Order().Select(d => d - originDay))}");
            }

            Assert.Empty(await DetachedLeftoversAsync());

            // The count of partitions reaches a plateau and stays there: the metadata tables hold (retention + ahead + 1) days, the content tables (content retention + ahead + 1).
            int total = 0;
            foreach (string table in PostgresPartitions.Tables)
            {
                total += (await PartitionNamesAsync(table)).Count;
            }

            if (day == MetadataDays + 2)
            {
                plateau = total;
                Assert.Equal((3 * (MetadataDays + ahead + 1)) + (2 * (ContentDays + ahead + 1)), total);
            }
            else if (day > MetadataDays + 2)
            {
                Assert.Equal(plateau, total);
            }

            // The messages inside the window are readable, the ones outside are not, whatever the partitions say.
            foreach (var (id, at) in ids.TakeLast(MetadataDays + 3))
            {
                bool visible = Clock.UtcNow < at.AddDays(MetadataDays);
                Assert.Equal(visible, await Storage.History.GetAsync(TenantA, id, CancellationToken.None) is not null);
            }
        }

        Assert.True(plateau > 0);
        output.WriteLine($"{days} virtual days, {plateau} partitions at the plateau");
    }

    [Fact]
    public async Task Lifecycle_a_partition_detached_but_never_dropped_is_dropped_by_a_later_run_and_not_left_behind()
    {
        // A rotation that died between "ALTER TABLE … DETACH PARTITION" and "DROP TABLE": the table exists, holds the old rows and belongs to no parent.
        AcceptedMessage old = await AcceptAsync(Msg(received: Start, size: 100));
        int oldDay = StorageTime.DayNumber(Start);
        foreach (string table in PostgresPartitions.Tables)
        {
            await ExecuteAsync($"ALTER TABLE {table} DETACH PARTITION {Name(table, oldDay)}");
        }

        Assert.Equal(PostgresPartitions.Tables.Length, (await DetachedLeftoversAsync()).Count);

        // The day is long past every retention: the next runs must remove the leftovers (for the metadata tables after 12 days, the content tables after 6).
        Clock.Set(Start.AddDays(MetadataDays + 3));
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        Assert.Empty(await DetachedLeftoversAsync());
        Assert.Null(await Storage.History.GetAsync(TenantA, old.MessageId, CancellationToken.None));

        // New traffic and rotation carry on as usual.
        AcceptedMessage fresh = await AcceptAsync(Msg(received: Clock.UtcNow, size: 100));
        Clock.Advance(TimeSpan.FromDays(1));
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        Assert.NotNull(await Storage.History.GetAsync(TenantA, fresh.MessageId, CancellationToken.None));
    }

    [Fact]
    public async Task Lifecycle_replicas_maintaining_at_the_same_time_drop_every_expired_partition_once_without_errors()
    {
        PostgresStorage second = await OpenReplicaAsync();
        PostgresStorage third = await OpenReplicaAsync();
        int seed = Accelerated.Seed(20261018);
        output.WriteLine($"seed={seed}");
        var random = new Random(seed);
        int rounds = Accelerated.Scaled(3);
        DateTimeOffset cursor = Start;

        for (int round = 0; round < rounds; round++)
        {
            // Ten days of history that will all be expired together, then a day that stays.
            for (int d = 0; d < 10; d++)
            {
                await AcceptAsync(Msg(received: cursor.AddDays(d), to: [$"r{round}-{d}@example.org"], size: 100));
            }

            Clock.Set(cursor.AddDays(10 + MetadataDays + 1));
            Guid kept = (await AcceptAsync(Msg(received: Clock.UtcNow, to: [$"keep{round}@example.org"], size: 100))).MessageId;

            // Everything but the one fresh message (an index, a recipient and a queued event row) is past the retention.
            long expiredRows = await ScalarAsync<long>("SELECT (SELECT count(*) FROM message_index) + (SELECT count(*) FROM message_recipient) + (SELECT count(*) FROM message_event) - 3");

            IStorage[] runners = [Storage, second, third];
            IReadOnlyList<MaintenanceReport>[] all = await Task.WhenAll(runners.OrderBy(_ => random.Next()).Select(r => Task.Run(async () => await r.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None).AsTask())));

            // Whoever got the lock did the work, the others skipped or found nothing: the rows deleted add up to exactly what was expired.
            Assert.Equal(expiredRows, all.SelectMany(r => r).Where(r => r.Job == "retention.metadata").Sum(r => r.RowsAffected));
            foreach (string table in PostgresPartitions.MetadataTables)
            {
                Assert.All(await DaysOfAsync(table), day => Assert.True(day >= StorageTime.DayNumber(Clock.UtcNow.AddDays(-MetadataDays)), $"{table} still has an expired partition"));
            }

            Assert.Empty(await DetachedLeftoversAsync());
            Assert.NotNull(await Storage.History.GetAsync(TenantA, kept, CancellationToken.None));

            cursor = Clock.UtcNow;
        }
    }
}
