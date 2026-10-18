using Mta.Storage.Tests;
using Xunit.Abstractions;

namespace Mta.Storage.Postgres.Tests;

/// <summary>
/// The crash/restart loop of the shared conformance suite on PostgreSQL: the storage object is killed (the statistics buffer thrown away, writes in flight abandoned, no graceful flush) and
/// another one opens the same database. Unlike SQLite the leases of a dead worker are not released at start (several replicas share the database): they run out, and the delivery is then
/// claimed again and flagged <c>possible_duplicate</c>.
/// </summary>
public abstract class PgCrashLoopLifecycleBase(ITestOutputHelper output) : CrashLoopLifecycleConformance(output)
{
    private readonly PgHarness _pg = new();
    private TestDatabase? _database;

    protected override bool MaintenanceReleasesExpiredLeases => true;

    protected override bool ClearsLeasesOnStart => false;

    protected override void DiscardUnflushedStatistics()
    {
        PostgresRuntime rt = ((PostgresStorage)Storage).Runtime;
        rt.Aggregator.Drain(Clock.UtcNow);
        rt.Aggregator.DrainRecent();
    }

    protected override async Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_database is null || !Reopening)
        {
            await _pg.DisposeAsync();
            _database = await PostgresTestServer.Instance.CreateDatabaseAsync();
            _pg.Adopt(_database);
        }

        return PostgresStorage.Create(PgHarness.WithDatabase(options, _database.ConnectionString), Clock);
    }

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

public sealed class PgCrashLoopLifecycleFull(ITestOutputHelper output) : PgCrashLoopLifecycleBase(output)
{
    protected override int BaseSteps => 220;
}

public sealed class PgCrashLoopLifecycleStatsOnly(ITestOutputHelper output) : PgCrashLoopLifecycleBase(output)
{
    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    protected override int DefaultSeed => 7003;

    protected override int BaseSteps => 150;
}
