using System.Collections.Concurrent;
using System.Diagnostics.Metrics;

namespace Mta.Storage.Sqlite;

/// <summary>
/// Meters of the SQLite backend (<c>Mta.Storage.Sqlite</c>), one label value per database file (<c>queue.db</c>, <c>stats.db</c>, <c>config.db</c>,
/// <c>history.db</c>). The per-commit instruments are recorded by the writer thread once per transaction, not per command; the gauges read
/// counters the writer keeps anyway, so a scrape costs a few reads and one <c>stat</c> per file.
/// <para>These are the figures that feed the advisory storage-pressure indicator (decision C): commit latency, the batch size the group commit
/// reaches, the writer queue depth, the WAL size, and the warnings about <c>synchronous=OFF</c> and quarantined files (design §4.4, decision P).
/// The gauges are state (not events), so a quarantine that happened before the exporter started is still visible.</para>
/// </summary>
public static class SqliteMetrics
{
    public static readonly Meter Meter = new("Mta.Storage.Sqlite");

    /// <summary>Time of the COMMIT of one writer transaction (the part that waits for the disk with <c>synchronous=FULL</c>); benchmarks.md calls this sqlite_commit_latency.</summary>
    public static readonly Histogram<double> CommitDuration = Meter.CreateHistogram<double>("mta.storage.sqlite.commit.duration", "s", "Duration of the commit of one SQLite writer transaction");

    /// <summary>Commands per committed transaction: how well the group commit batches (sqlite_writer_batch_size).</summary>
    public static readonly Histogram<long> WriterBatchSize = Meter.CreateHistogram<long>("mta.storage.sqlite.writer.batch.size", "{command}", "Commands per committed SQLite writer transaction");

    /// <summary>Transactions that failed as a whole and were replayed one command at a time.</summary>
    public static readonly Counter<long> WriterBatchFailures = Meter.CreateCounter<long>("mta.storage.sqlite.writer.batch.failures", "{batch}", "SQLite writer transactions that failed and were replayed command by command");

    private static readonly ConcurrentDictionary<SqliteStorage, byte> Live = new();

    public static readonly ObservableGauge<long> WriterQueueDepth = Meter.CreateObservableGauge("mta.storage.sqlite.writer.queue.depth", () => ObserveQueueDepth(Live.Keys), "{command}", "Commands waiting for a SQLite writer (sqlite_writer_queue_depth)");

    public static readonly ObservableGauge<long> WalSize = Meter.CreateObservableGauge("mta.storage.sqlite.wal.size", () => ObserveWalSize(Live.Keys), "By", "Size of the write-ahead log of a SQLite file");

    public static readonly ObservableGauge<long> SyncOff = Meter.CreateObservableGauge("mta.storage.sqlite.sync_off", () => ObserveSyncOff(Live.Keys), "{file}", "1 for a SQLite file running with synchronous=OFF (process-kill safe, not power-loss safe), else 0 (sqlite_sync_off)");

    public static readonly ObservableGauge<long> QuarantinedFiles = Meter.CreateObservableGauge("mta.storage.sqlite.quarantined", () => ObserveQuarantined(Live.Keys), "{file}", "1 for a SQLite file that failed its start-up integrity check and was moved aside when this process started (a fresh empty file replaced it), else 0");

    /// <summary>Makes <paramref name="storage"/> visible to the gauges. Dispose to detach.</summary>
    internal static IDisposable Attach(SqliteStorage storage)
    {
        Live[storage] = 0;
        return new Detach(storage);
    }

    internal static bool IsAttached(SqliteStorage storage) => Live.ContainsKey(storage);

    /// <summary>Storages the gauges currently read (a leak check: closing a storage must detach it).</summary>
    internal static int AttachedCount => Live.Count;

    internal static IEnumerable<Measurement<long>> ObserveQueueDepth(IEnumerable<SqliteStorage> storages)
    {
        foreach (SqliteStorage storage in storages)
        {
            foreach (SqliteFileWriter writer in storage.Runtime.Writers)
            {
                yield return new Measurement<long>(writer.PendingCommands, FileTag(writer.File));
            }
        }
    }

    internal static IEnumerable<Measurement<long>> ObserveWalSize(IEnumerable<SqliteStorage> storages)
    {
        foreach (SqliteStorage storage in storages)
        {
            foreach (SqliteFile file in storage.Runtime.Files.Where(f => !f.IsMemory))
            {
                yield return new Measurement<long>(file.WalSize(), FileTag(file));
            }
        }
    }

    internal static IEnumerable<Measurement<long>> ObserveSyncOff(IEnumerable<SqliteStorage> storages)
    {
        foreach (SqliteStorage storage in storages)
        {
            foreach (SqliteFile file in storage.Runtime.Files.Where(f => !f.IsMemory))
            {
                yield return new Measurement<long>(file.Sync == SqliteSyncMode.Off ? 1 : 0, FileTag(file));
            }
        }
    }

    internal static IEnumerable<Measurement<long>> ObserveQuarantined(IEnumerable<SqliteStorage> storages)
    {
        foreach (SqliteStorage storage in storages)
        {
            foreach (SqliteFile file in storage.Runtime.Files.Where(f => !f.IsMemory))
            {
                yield return new Measurement<long>(storage.QuarantineEvents.Any(q => q.File == file.FileName) ? 1 : 0, FileTag(file));
            }
        }
    }

    private static KeyValuePair<string, object?> FileTag(SqliteFile file) => new("file", file.FileName);

    private sealed class Detach(SqliteStorage storage) : IDisposable
    {
        public void Dispose() => Live.TryRemove(storage, out _);
    }
}
