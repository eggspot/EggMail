using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Mta.Core;
using Mta.Storage.Logic;
using Mta.Storage.Model;
using Mta.Storage.Transfer;

namespace Mta.Storage.Sqlite;

/// <summary>
/// The SQLite backend (design §4.4): <c>queue.db</c>, <c>stats.db</c>, <c>config.db</c> and (only with
/// <see cref="HistoryMode.Full"/>) <c>history.db</c>, each with its own WAL and its own group-commit writer.
/// <para><b>Acknowledgement.</b> <see cref="IMessageIntake.AcceptAsync"/> returns after the queue transaction committed. With
/// <c>Sqlite:SyncMode=Off</c> that means handed to the operating system, not fsynced: a process kill is safe, an OS crash or
/// power loss can corrupt the file.</para>
/// <para><b>Cross-file crash windows.</b> SQLite is atomic per file, not across files, so every cross-file effect is ordered
/// and idempotent: a hard-bounce suppression is written to config.db before the queue row is completed (a crash in between
/// only makes the retry bounce again); retained raw is written to history.db before the spool row is deleted (a crash in
/// between leaves a spool row marked <c>awaiting_retention</c> that the reconcile job in maintenance finishes); history
/// entries are written after the queue commit (a crash in between loses the history entry of that message, never the
/// message); statistics are buffered and flushed about every 10 s (a crash loses at most that window).</para>
/// </summary>
public sealed class SqliteStorage : IStorage
{
    private readonly StorageOptions _options;
    private readonly SqliteRuntime _rt;
    private readonly SqliteStatsStore _stats;
    private readonly SqliteQueueStore _queue;
    private readonly SqliteHistoryStore _history;
    private readonly List<QuarantineEvent> _quarantine = [];
    private CancellationTokenSource? _flushCts;
    private Task? _flushLoop;
    private int _initialized;
    private int _disposed;
    private SqliteMaintenance? _maintenance;
    private EfStorageTransfer? _transfer;
    private IDisposable? _meters;

    private SqliteStorage(StorageOptions options, IClock clock, IMtaLog log)
    {
        StorageOptionsValidation.Validate(options);
        _options = options;
        _rt = new SqliteRuntime(options, clock, log);
        _stats = new SqliteStatsStore(_rt);
        _history = new SqliteHistoryStore(_rt);
        _queue = new SqliteQueueStore(_rt, _history);
    }

    /// <summary>Creates the storage. Call <see cref="InitializeAsync"/> before use.</summary>
    public static SqliteStorage Create(StorageOptions options, IClock? clock = null, IMtaLog? log = null) =>
        new(options, clock ?? SystemClock.Instance, log ?? NullMtaLog.Instance);

    public StorageBackend Backend => StorageBackend.Sqlite;

    public HistoryMode HistoryMode => _options.History.Mode;

    public IMessageIntake Intake => _queue;

    public IDeliveryStore Deliveries => _queue;

    public IConfigStore Config => _rt.ConfigStore ?? throw NotInitialized();

    public IStatsStore Stats => _stats;

    public IHistoryStore History => _history;

    public IWebhookOutbox Webhooks => _queue;

    public IStorageMaintenance Maintenance => _maintenance ?? throw NotInitialized();

    public IStorageTransfer Transfer => _transfer ?? throw NotInitialized();

    /// <summary>Quarantine events recorded at startup.</summary>
    public IReadOnlyList<QuarantineEvent> QuarantineEvents => _quarantine;

    /// <summary>Writer counters per file (commits, batch sizes, queue depth) for the storage-pressure indicator and tests.</summary>
    public IReadOnlyDictionary<string, WriterMetrics> WriterMetrics => _rt.Writers.ToDictionary(w => w.File.Name, w => w.Metrics);

    /// <summary>Internals for the SQLite-specific tests (pragmas, writer fault injection).</summary>
    internal SqliteRuntime Runtime => _rt;

    private static InvalidOperationException NotInitialized() => new("Call InitializeAsync before using the storage.");

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _initialized, 1) != 0)
        {
            return;
        }

        SqliteOptions so = _options.Sqlite;
        bool memoryQueue = so.QueuePersistence == QueuePersistence.Memory;
        bool full = _options.History.Mode == HistoryMode.Full;
        Directory.CreateDirectory(so.DataDirectory);

        IStorageModelHooks hooks = SqliteModelHooks.Instance;
        _rt.Queue = MakeFile<QueueDbContext>(SqliteFileKind.Queue, so.SyncMode, memoryQueue, o => new QueueDbContext(o, hooks));
        _rt.Stats = MakeFile<StatsDbContext>(SqliteFileKind.Stats, so.SyncMode, false, o => new StatsDbContext(o, hooks));
        _rt.Config = MakeFile<ConfigDbContext>(SqliteFileKind.Config, so.ConfigSyncMode, false, o => new ConfigDbContext(o, hooks));
        if (full)
        {
            _rt.History = MakeFile<HistoryDbContext>(SqliteFileKind.History, so.SyncMode, false, o => new HistoryDbContext(o, hooks));
        }

        // Startup integrity check; a failing file is quarantined (never deleted) and replaced by an empty one.
        string quarantineDir = Path.Combine(so.DataDirectory, "quarantine", _rt.Clock.UtcNow.ToString("yyyyMMddTHHmmssfff'Z'", CultureInfo.InvariantCulture));
        foreach (SqliteFile f in _rt.Files.Where(f => !f.IsMemory))
        {
            (bool ok, string detail) = f.CheckIntegrity(so.QuickCheck);
            if (ok)
            {
                continue;
            }

            string moved = f.Quarantine(quarantineDir);
            _quarantine.Add(new QuarantineEvent(f.FileName, moved, detail, _rt.Clock.UtcNow));
            _rt.Log.Write(MtaLogLevel.Error, "storage.sqlite", $"{f.FileName} failed its integrity check ({detail}); moved to {moved} and starting with an empty file.");
        }

        var access = new SqliteConfigAccess(_rt.Config, hooks);
        _rt.ConfigStore = new EfConfigStore<ConfigDbContext>(access);

        _rt.QueueWriter = new SqliteFileWriter(_rt.Queue, so);
        _rt.StatsWriter = new SqliteFileWriter(_rt.Stats, so, _stats.ResetBucketer);
        _rt.ConfigWriter = new SqliteFileWriter(_rt.Config, so);
        access.Writer = _rt.ConfigWriter;
        if (_rt.History is not null)
        {
            _rt.HistoryWriter = new SqliteFileWriter(_rt.History, so);
        }

        try
        {
            foreach (SqliteFileWriter w in _rt.Writers)
            {
                await w.StartAsync().ConfigureAwait(false);
            }

            // A backend switch may have closed this store (a fenced source, a target that is not activated yet). The gate comes
            // from the persisted state, so it holds after a restart; a closed store is left exactly as it is.
            _rt.Fence.Apply(await _rt.ConfigStore.GetSwitchStateAsync(cancellationToken).ConfigureAwait(false));
            _transfer = new EfStorageTransfer(new SqliteTransferAccess(_rt, hooks), _rt.ConfigStore, _rt.Fence, _rt.Clock);
            if (_rt.Fence.IsClosed)
            {
                _rt.Log.Write(MtaLogLevel.Warning, "storage.sqlite", _rt.Fence.Reason!);
            }
            else
            {
                await _queue.ClearAllLeasesAsync(cancellationToken).ConfigureAwait(false);
                await _queue.ReconcileSpoolAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch
        {
            await DisposeAsync().ConfigureAwait(false);
            throw;
        }

        _maintenance = new SqliteMaintenance(_rt, _queue, _stats, so.DataDirectory, _quarantine);
        _meters = SqliteMetrics.Attach(this);
        LogWarnings();

        if (so.StatsFlushInterval > TimeSpan.Zero)
        {
            _flushCts = new CancellationTokenSource();
            _flushLoop = FlushLoopAsync(so.StatsFlushInterval, _flushCts.Token);
        }
    }

    private SqliteFile MakeFile<TContext>(SqliteFileKind kind, SqliteSyncMode sync, bool inMemory, Func<DbContextOptions<TContext>, TContext> create) where TContext : DbContext
    {
        DbContextOptions<TContext> options = new DbContextOptionsBuilder<TContext>().UseSqlite("Data Source=:memory:").Options;
        IReadOnlyCollection<string> withoutRowId;
        using (TContext probe = create(options))
        {
            withoutRowId = SqliteFile.WithoutRowIdTablesOf(probe);
        }

        return new SqliteFile(kind, _options.Sqlite, sync, inMemory, () =>
        {
            using TContext ctx = create(options);
            return ctx.Database.GenerateCreateScript();
        }, withoutRowId);
    }

    private void LogWarnings()
    {
        var off = _rt.Files.Where(f => !f.IsMemory && f.Sync == SqliteSyncMode.Off).Select(f => f.FileName).ToList();
        if (off.Count > 0)
        {
            _rt.Log.Write(MtaLogLevel.Warning, "storage.sqlite",
                $"SQLite files run with synchronous=OFF ({string.Join(", ", off)}): a process kill is safe, but an operating system crash or power loss can CORRUPT them and lose queued mail already acknowledged with 250. Use Sqlite:SyncMode=Normal or Full, or the PostgreSQL backend, if you need power-loss safety.");
        }

        if (_rt.Queue.IsMemory)
        {
            _rt.Log.Write(MtaLogLevel.Warning, "storage.sqlite", "Sqlite:QueuePersistence=Memory: accepted mail is held in memory and lost on restart.");
        }
    }

    private async Task FlushLoopAsync(TimeSpan interval, CancellationToken ct)
    {
        using var timer = new PeriodicTimer(interval);
        try
        {
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            {
                try
                {
                    await _stats.FlushAsync(ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _rt.Log.Write(MtaLogLevel.Error, "storage.sqlite", "Statistics flush failed; the counters are kept and retried.", ex);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _meters?.Dispose();
        if (_flushCts is not null)
        {
            await _flushCts.CancelAsync().ConfigureAwait(false);
            if (_flushLoop is not null)
            {
                await _flushLoop.ConfigureAwait(false);
            }

            _flushCts.Dispose();
        }

        if (_rt.StatsWriter is not null)
        {
            try
            {
                await _stats.FlushAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _rt.Log.Write(MtaLogLevel.Error, "storage.sqlite", "Final statistics flush failed.", ex);
            }
        }

        foreach (SqliteFileWriter w in _rt.Writers.Where(w => w is not null).ToList())
        {
            await w.DisposeAsync().ConfigureAwait(false);
        }

        foreach (SqliteFile f in _rt.Files.Where(f => f is not null).ToList())
        {
            f.ReadSessions.Close();   // the storage is gone: later reads still work but keep no connection open
            f.ClearPool();
        }
    }
}
