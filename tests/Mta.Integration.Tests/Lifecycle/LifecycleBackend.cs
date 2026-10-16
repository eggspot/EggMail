using Mta.Core;
using Mta.Storage;
using Mta.Storage.Sqlite;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>The storage backend a lifecycle scenario runs on: the scenarios are written once and run on each of these.</summary>
public abstract class LifecycleBackend
{
    /// <summary>No PostgreSQL on this machine (CI provides one): the scenarios return at once, like the chaos tests.</summary>
    public bool Unavailable { get; protected set; }

    /// <summary>A second process can use the same storage at the same time (a database server, not a local volume).</summary>
    public virtual bool SupportsSeveralProcesses => false;

    public virtual Task PrepareAsync() => Task.CompletedTask;

    public virtual Task CleanupAsync() => Task.CompletedTask;

    /// <summary>Options of a storage over the backend's files or database; the same files or database every time it is called.</summary>
    public abstract StorageOptions NewStorageOptions();

    public abstract IStorage CreateStorage(StorageOptions options, IClock clock);
}

public sealed class SqliteLifecycleBackend : LifecycleBackend
{
    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-lifecycle-").FullName;

    public override StorageOptions NewStorageOptions() => new() { Sqlite = new SqliteOptions { DataDirectory = _dir, StatsFlushInterval = TimeSpan.Zero } };

    public override IStorage CreateStorage(StorageOptions options, IClock clock) => SqliteStorage.Create(options, clock);

    public override Task CleanupAsync()
    {
        // A unique directory this backend created and owns.
        Directory.Delete(_dir, recursive: true);
        return Task.CompletedTask;
    }
}

public sealed class PostgresLifecycleBackend : LifecycleBackend
{
    public override bool SupportsSeveralProcesses => true;

    private Mta.Storage.Postgres.Tests.TestDatabase? _database;

    public override async Task PrepareAsync()
    {
        if (Mta.Storage.Postgres.Tests.PostgresTestServer.UnavailableReason is not null)
        {
            Unavailable = true;
            return;
        }

        _database = await Mta.Storage.Postgres.Tests.PostgresTestServer.Instance.CreateDatabaseAsync();
    }

    public override async Task CleanupAsync()
    {
        if (_database is not null)
        {
            await _database.DisposeAsync();
        }
    }

    public override StorageOptions NewStorageOptions() => new()
    {
        Backend = StorageBackend.Postgres,
        Postgres = new PostgresOptions { OwnerConnectionString = _database!.ConnectionString, RuntimeConnectionString = _database.ConnectionString, StatsFlushInterval = TimeSpan.Zero },
    };

    public override IStorage CreateStorage(StorageOptions options, IClock clock) => Mta.Storage.Postgres.PostgresStorage.Create(options, clock);
}
