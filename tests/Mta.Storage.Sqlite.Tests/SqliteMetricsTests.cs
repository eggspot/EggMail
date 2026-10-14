using System.Collections.Concurrent;
using System.Diagnostics.Metrics;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>The SQLite meters: per-commit instruments recorded by the writer, and the state gauges (sync mode, quarantine, queue depth, WAL).</summary>
public class SqliteMetricsTests : SqliteTestBase
{
    private sealed class Capture : IDisposable
    {
        private readonly MeterListener _listener = new();
        public readonly ConcurrentQueue<(string Name, double Value, string? File)> Seen = new();

        public Capture()
        {
            _listener.InstrumentPublished = (i, l) =>
            {
                if (i.Meter.Name == "Mta.Storage.Sqlite")
                {
                    l.EnableMeasurementEvents(i);
                }
            };
            _listener.SetMeasurementEventCallback<double>((i, v, t, _) => Add(i, v, t));
            _listener.SetMeasurementEventCallback<long>((i, v, t, _) => Add(i, v, t));
            _listener.Start();
        }

        private void Add(Instrument i, double v, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            string? file = null;
            foreach (var t in tags)
            {
                if (t.Key == "file") { file = t.Value as string; }
            }

            Seen.Enqueue((i.Name, v, file));
        }

        public void Pull() => _listener.RecordObservableInstruments();

        public void Dispose() => _listener.Dispose();
    }

    private static Dictionary<string, long> ByFile(IEnumerable<Measurement<long>> measurements) =>
        measurements.ToDictionary(m => (string)m.Tags.ToArray().Single(t => t.Key == "file").Value!, m => m.Value);

    [Fact]
    public async Task Every_commit_records_its_duration_and_batch_size_per_file()
    {
        using var capture = new Capture();
        await ReopenAsync(b => b.SyncMode = SqliteSyncMode.Normal);

        await Task.WhenAll(Enumerable.Range(0, 50).Select(_ => Storage.Intake.AcceptAsync(Msg(size: 256), default).AsTask()));

        // Other tests commit concurrently into the same static meter: check what this class must have caused, not totals.
        var queue = capture.Seen.Where(s => s.File == "queue.db").ToList();
        Assert.Contains(queue, s => s.Name == "mta.storage.sqlite.commit.duration" && s.Value >= 0 && s.Value < 30);
        Assert.Contains(queue, s => s.Name == "mta.storage.sqlite.writer.batch.size" && s.Value >= 1);
    }

    [Theory]
    [InlineData(SqliteSyncMode.Off, 1)]
    [InlineData(SqliteSyncMode.Normal, 0)]
    [InlineData(SqliteSyncMode.Full, 0)]
    public async Task The_sync_off_gauge_is_one_exactly_for_files_running_with_synchronous_off(SqliteSyncMode mode, long expected)
    {
        await ReopenAsync(b => b.SyncMode = mode);   // queue, stats and history follow SyncMode; config.db has its own, Full by default

        var values = ByFile(SqliteMetrics.ObserveSyncOff([Sql]));

        Assert.Equal(expected, values["queue.db"]);
        Assert.Equal(expected, values["stats.db"]);
        Assert.Equal(expected, values["history.db"]);
        Assert.Equal(0, values["config.db"]);
    }

    [Fact]
    public async Task Config_sync_off_is_reported_too()
    {
        await ReopenAsync(b => { b.SyncMode = SqliteSyncMode.Full; b.ConfigSyncMode = SqliteSyncMode.Off; });

        var values = ByFile(SqliteMetrics.ObserveSyncOff([Sql]));

        Assert.Equal(1, values["config.db"]);
        Assert.Equal(0, values["queue.db"]);
    }

    [Fact]
    public async Task The_memory_queue_has_no_file_and_is_not_listed()
    {
        await ReopenAsync(b => b.QueuePersistence = QueuePersistence.Memory);

        Assert.DoesNotContain("queue.db", ByFile(SqliteMetrics.ObserveSyncOff([Sql])).Keys);
        Assert.DoesNotContain("queue.db", ByFile(SqliteMetrics.ObserveWalSize([Sql])).Keys);
        Assert.Contains("queue.db", ByFile(SqliteMetrics.ObserveQueueDepth([Sql])).Keys);   // the writer exists even though the file does not
    }

    [Fact]
    public async Task Writer_queue_depth_is_a_live_read_and_the_wal_has_a_size()
    {
        await ReopenAsync();
        await AcceptAsync();

        var depth = ByFile(SqliteMetrics.ObserveQueueDepth([Sql]));
        Assert.Equal(["config.db", "history.db", "queue.db", "stats.db"], depth.Keys.Order());
        Assert.All(depth.Values, v => Assert.True(v >= 0));
        Assert.True(ByFile(SqliteMetrics.ObserveWalSize([Sql]))["queue.db"] >= 0);

        // A blocked writer shows its backlog without any batch having run in between.
        var started = new ManualResetEventSlim();
        var release = new ManualResetEventSlim();
        Task blocked = Sql.Runtime.QueueWriter.SubmitAsync((started, release), static (_, s) => { s.started.Set(); s.release.Wait(); return 0; }).AsTask();
        Assert.True(started.Wait(TimeSpan.FromSeconds(10)));
        try
        {
            var pending = Enumerable.Range(0, 5).Select(_ => Storage.Intake.AcceptAsync(Msg(size: 128), default).AsTask()).ToList();
            Assert.Equal(5, ByFile(SqliteMetrics.ObserveQueueDepth([Sql]))["queue.db"]);
            release.Set();
            await Task.WhenAll(pending);
        }
        finally
        {
            release.Set();
        }

        await blocked;
        Assert.Equal(0, ByFile(SqliteMetrics.ObserveQueueDepth([Sql]))["queue.db"]);
    }

    [Fact]
    public async Task A_quarantined_file_shows_up_for_exactly_that_file()
    {
        await AcceptAsync();
        await Storage.DisposeAsync();
        using (var fs = new FileStream(PathOf("stats.db"), FileMode.Open, FileAccess.Write))
        {
            byte[] junk = new byte[128];
            new Random(7).NextBytes(junk);
            fs.Write(junk);
        }

        await ReopenAsync();

        var values = ByFile(SqliteMetrics.ObserveQuarantined([Sql]));
        Assert.Equal(1, values["stats.db"]);
        Assert.Equal(0, values["queue.db"]);
        Assert.Equal(0, values["config.db"]);
    }

    [Fact]
    public async Task A_running_storage_is_visible_to_a_scrape_and_gone_after_dispose()
    {
        await ReopenAsync();
        using var capture = new Capture();

        capture.Pull();
        Assert.Contains(capture.Seen, s => s.Name == "mta.storage.sqlite.writer.queue.depth" && s.File == "queue.db");
        Assert.Contains(capture.Seen, s => s.Name == "mta.storage.sqlite.sync_off" && s.File == "config.db");

        Assert.True(SqliteMetrics.IsAttached(Sql));
        await Storage.DisposeAsync();
        Assert.False(SqliteMetrics.IsAttached(Sql));   // a disposed storage is no longer observed
    }
}
