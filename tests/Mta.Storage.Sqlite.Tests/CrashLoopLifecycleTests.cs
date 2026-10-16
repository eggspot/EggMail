using Mta.Storage.Tests;
using Xunit.Abstractions;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>
/// The crash/restart loop of the shared conformance suite on the SQLite backend, in every sync mode and under both history levels. The kill is the in-process model of a process kill:
/// the statistics buffer is discarded, writes in flight are abandoned, no graceful flush happens, and the files are reopened (the real SIGKILL of a child process is confirmed in
/// <see cref="CrashLoopLifecycleProcessKillTests"/>). SQLite releases every lease at start (single node), so a dead worker's deliveries are claimable at once and flagged.
/// </summary>
public abstract class SqliteCrashLoopLifecycleBase(ITestOutputHelper output) : CrashLoopLifecycleConformance(output)
{
    private string? _dir;

    protected abstract SqliteSyncMode Sync { get; }

    protected override bool MaintenanceReleasesExpiredLeases => false;

    protected override bool ClearsLeasesOnStart => true;

    protected override void DiscardUnflushedStatistics()
    {
        SqliteRuntime rt = ((SqliteStorage)Storage).Runtime;
        rt.Aggregator.Drain(Clock.UtcNow);
        rt.Aggregator.DrainRecent();
    }

    protected override Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_dir is null || !Reopening)
        {
            if (_dir is not null)
            {
                SqliteTestStorage.TryDelete(_dir);
            }

            _dir = SqliteTestStorage.NewDirectory();
        }

        return Task.FromResult<IStorage>(SqliteStorage.Create(SqliteTestStorage.WithDirectory(options, _dir, b => b.SyncMode = Sync), Clock));
    }

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        if (_dir is not null)
        {
            SqliteTestStorage.TryDelete(_dir);
        }
    }
}

public sealed class SqliteCrashLoopLifecycleOffFull(ITestOutputHelper output) : SqliteCrashLoopLifecycleBase(output)
{
    protected override SqliteSyncMode Sync => SqliteSyncMode.Off;
}

public sealed class SqliteCrashLoopLifecycleNormalFull(ITestOutputHelper output) : SqliteCrashLoopLifecycleBase(output)
{
    protected override SqliteSyncMode Sync => SqliteSyncMode.Normal;

    protected override int DefaultSeed => 7001;
}

public sealed class SqliteCrashLoopLifecycleFullSyncFull(ITestOutputHelper output) : SqliteCrashLoopLifecycleBase(output)
{
    protected override SqliteSyncMode Sync => SqliteSyncMode.Full;

    protected override int DefaultSeed => 7002;

    protected override int BaseSteps => 150;
}

public sealed class SqliteCrashLoopLifecycleOffStatsOnly(ITestOutputHelper output) : SqliteCrashLoopLifecycleBase(output)
{
    protected override SqliteSyncMode Sync => SqliteSyncMode.Off;

    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override int DefaultSeed => 7003;
}
