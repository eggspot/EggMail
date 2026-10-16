using Mta.Core;
using Mta.TestSupport;
using Xunit.Abstractions;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>
/// Accelerated lifecycle of the SQLite files (part of the "Lifecycle" family, SQLite only): batched deletes plus <c>incremental_vacuum</c> keep the files bounded over
/// many virtual days of steady traffic, and give the space back once the traffic stops.
/// </summary>
public class SqliteLifecycleFileTests(ITestOutputHelper output) : SqliteTestBase
{
    protected override StorageOptions BuildOptions() => new()
    {
        Retention = new RetentionOptions { MetadataDays = 12, WebhookOutboxDays = 3, WebhookAttemptLogDays = 3 },
        Content = new ContentOptions { RetentionDays = 6 },
    };

    private long FootprintOf(string file)
    {
        long total = 0;
        foreach (string suffix in new[] { "", "-wal" })
        {
            var info = new FileInfo(PathOf(file + suffix));
            total += info.Exists ? info.Length : 0;
        }

        return total;
    }

    [Fact]
    public async Task Lifecycle_the_database_files_stop_growing_once_retention_is_in_steady_state_and_shrink_when_traffic_stops()
    {
        // Small batches: every retention run needs many DELETE batches, interleaved with the traffic of the day.
        await ReopenAsync(tune: b => b.RetentionDeleteBatchSize = 11);
        int days = Accelerated.Scaled(32);
        var history = new List<long>();
        var queue = new List<long>();

        for (int day = 0; day < days; day++)
        {
            Clock.Set(Start.AddDays(day));
            for (int i = 0; i < 15; i++)
            {
                await AcceptAsync(Msg(to: [$"u{day}-{i}@example.org"], size: 20_000, retainRaw: true));
            }

            foreach (ClaimedDelivery d in await ClaimAsync(max: 100))
            {
                await RecordAsync(d, DeliveryOutcome.Delivered);
            }

            await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
            history.Add(FootprintOf("history.db"));
            queue.Add(FootprintOf("queue.db"));
        }

        // Steady state starts when the oldest retained raw (6 days) and metadata (12 days) have started to rotate: compare two equal windows after it.
        int from = 16;
        int mid = from + ((days - from) / 2);
        long early = history.Skip(from).Take(mid - from).Max();
        long late = history.Skip(mid).Max();
        output.WriteLine($"history.db: peak {early} bytes in days {from}..{mid - 1}, {late} bytes in days {mid}..{days - 1}; queue.db: {queue.Skip(from).Max()} bytes");
        Assert.True(late <= early + (early / 5) + 131_072, $"history.db kept growing in steady state: {early} -> {late} bytes");
        long queueEarly = queue.Skip(from).Take(mid - from).Max();
        Assert.True(queue.Skip(mid).Max() <= queueEarly + (queueEarly / 5) + 131_072, "queue.db kept growing in steady state");

        // The traffic stops; after the longest retention everything is deleted and the freed pages are returned to the file system.
        long peak = history.Max();
        Clock.Set(Start.AddDays(days + 20));
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        long after = FootprintOf("history.db");
        output.WriteLine($"history.db after the retention: {after} bytes (peak {peak})");
        Assert.True(after < peak / 3, $"history.db did not shrink: {peak} -> {after} bytes");
        Assert.Equal(0, ScalarLong(PathOf("history.db"), "SELECT count(*) FROM message_index"));
        Assert.Equal(0, ScalarLong(PathOf("history.db"), "SELECT count(*) FROM message_raw_retained"));
    }

    [Fact]
    public async Task Lifecycle_claims_and_intake_keep_working_between_the_delete_batches_of_a_big_cleanup()
    {
        await ReopenAsync(tune: b =>
        {
            b.RetentionDeleteBatchSize = 5;
            b.RetentionDeletePause = TimeSpan.FromMilliseconds(5);
        });
        for (int i = 0; i < 80; i++)
        {
            await AcceptAsync(Msg(to: [$"old{i}@example.org"], size: 300));
        }

        foreach (ClaimedDelivery d in await ClaimAsync(max: 1000))
        {
            await RecordAsync(d, DeliveryOutcome.Delivered, events: [Draft("message.delivered")]);
        }

        Clock.Set(Start.AddDays(40));
        long before = ScalarLong(PathOf("history.db"), "SELECT count(*) FROM message_event");
        Assert.True(before >= 160);

        // 80 messages × (index, recipient, events) are deleted five rows at a time (about 100 batches); meanwhile 20 messages go through the whole flow.
        Task<IReadOnlyList<MaintenanceReport>> cleanup = Task.Run(async () => await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None).AsTask());
        int through = 0;
        int accepted = 0;
        while (!cleanup.IsCompleted || through < 20)
        {
            await AcceptAsync(Msg(to: [$"live{accepted++}@example.org"], size: 300));
            foreach (ClaimedDelivery d in await ClaimAsync(max: 10))
            {
                await RecordAsync(d, DeliveryOutcome.Delivered);
                through++;
            }

            if (through >= 200)
            {
                break;   // the cleanup is slow to start on a loaded machine: enough proof that the writer was shared, the result below is what counts
            }
        }

        Task done = await Task.WhenAny(cleanup, Task.Delay(TimeSpan.FromMinutes(2)));
        Assert.Same(cleanup, done);
        var reports = await cleanup;
        Assert.True(reports.Single(r => r.Job == "retention.metadata").RowsAffected >= 160);
        foreach (ClaimedDelivery d in await ClaimAsync(max: 1000))
        {
            await RecordAsync(d, DeliveryOutcome.Delivered);
        }

        Assert.Equal(accepted, ScalarLong(PathOf("history.db"), "SELECT count(*) FROM message_index"));
        QueueStats stats = await Storage.Deliveries.GetQueueStatsAsync(CancellationToken.None);
        Assert.Equal((0, 0, 0), (stats.Queued, stats.Leased, stats.Deferred));
    }
}
