using Mta.Core;
using Mta.Storage;
using Mta.Storage.Postgres;
using Mta.Storage.Postgres.Tests;
using Mta.Storage.Sqlite;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>
/// One storage backend for the lifecycle scenarios of the sending counters and the certificate store: opens a fresh storage object over the same data
/// every time it is asked (a restart or a replica), so a scenario runs unchanged on SQLite files and on PostgreSQL.
/// </summary>
internal abstract class RuntimeStateBackend : IAsyncDisposable
{
    public abstract string Name { get; }

    /// <summary>A new, initialized storage over the backend's data (state from earlier storages of this backend is still there).</summary>
    public abstract Task<IStorage> OpenAsync(IClock clock);

    public abstract StorageOptions Options { get; }

    public abstract ValueTask DisposeAsync();

    public static RuntimeStateBackend Sqlite() => new SqliteBackend();

    public static async Task<RuntimeStateBackend> PostgresAsync() => await PostgresBackend.CreateAsync();

    private sealed class SqliteBackend : RuntimeStateBackend
    {
        private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-lifecycle-").FullName;

        public override string Name => "sqlite";

        public override StorageOptions Options => new() { Sqlite = new SqliteOptions { DataDirectory = _dir, StatsFlushInterval = TimeSpan.Zero } };

        public override async Task<IStorage> OpenAsync(IClock clock)
        {
            var storage = SqliteStorage.Create(Options, clock);
            await storage.InitializeAsync(default);
            return storage;
        }

        public override ValueTask DisposeAsync()
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            // A unique directory created by this backend object; it holds only this scenario's files.
            Directory.Delete(_dir, recursive: true);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class PostgresBackend : RuntimeStateBackend
    {
        private readonly TestDatabase _database;

        private PostgresBackend(TestDatabase database) => _database = database;

        public static async Task<PostgresBackend> CreateAsync() => new(await PostgresTestServer.Instance.CreateDatabaseAsync());

        public override string Name => "postgres";

        public override StorageOptions Options => new()
        {
            Backend = StorageBackend.Postgres,
            Postgres = new PostgresOptions
            {
                OwnerConnectionString = _database.ConnectionString,
                RuntimeConnectionString = _database.ConnectionString,
                StatsFlushInterval = TimeSpan.Zero,
                MaxPoolSize = 8,
            },
        };

        public override async Task<IStorage> OpenAsync(IClock clock)
        {
            var storage = PostgresStorage.Create(Options, clock);
            await storage.InitializeAsync(default);
            return storage;
        }

        public override async ValueTask DisposeAsync() => await _database.DisposeAsync();
    }
}
