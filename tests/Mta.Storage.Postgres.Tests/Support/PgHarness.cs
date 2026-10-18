using Mta.Core;

namespace Mta.Storage.Postgres.Tests;

/// <summary>
/// Creates PostgreSQL storages over fresh databases (copies of the migrated template) and drops them afterwards. Each
/// conformance class owns one; <see cref="CreateAsync"/> is called again whenever a test re-opens the storage with other options.
/// </summary>
internal sealed class PgHarness
{
    private readonly List<TestDatabase> _databases = [];

    public TestDatabase? Current => _databases.Count == 0 ? null : _databases[^1];

    public async Task<IStorage> CreateAsync(StorageOptions options, IClock clock, Func<PostgresOptions, PostgresOptions>? tune = null)
    {
        // A re-open starts from an empty store (the SQLite tests also use a new directory each time).
        await DisposeAsync();
        TestDatabase db = await PostgresTestServer.Instance.CreateDatabaseAsync();
        _databases.Add(db);
        return PostgresStorage.Create(WithDatabase(options, db.ConnectionString, tune), clock);
    }

    /// <summary>Takes over a database the caller created, so <see cref="DisposeAsync"/> drops it.</summary>
    public void Adopt(TestDatabase db) => _databases.Add(db);

    public static StorageOptions WithDatabase(StorageOptions o, string connectionString, Func<PostgresOptions, PostgresOptions>? tune = null)
    {
        var pg = new PostgresOptions
        {
            RuntimeConnectionString = connectionString,
            MaxPoolSize = 8,
            StatsFlushInterval = TimeSpan.Zero,
            RetentionDeletePause = TimeSpan.FromMilliseconds(1),
        };
        return new StorageOptions
        {
            Backend = StorageBackend.Postgres,
            History = o.History,
            Retention = o.Retention,
            Sqlite = o.Sqlite,
            Postgres = tune?.Invoke(pg) ?? pg,
            Content = o.Content,
            Queue = o.Queue,
            Inbound = o.Inbound,
        };
    }

    public async Task DisposeAsync()
    {
        foreach (TestDatabase db in _databases)
        {
            await db.DisposeAsync();
        }

        _databases.Clear();
    }
}
