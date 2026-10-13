using Npgsql;
using Mta.Storage.Tests;

namespace Mta.Storage.Postgres.Tests;

/// <summary>
/// Base of the PostgreSQL-specific tests: a fresh database per test, the shared builders of <see cref="StorageTestBase"/>, and
/// helpers to open further "replicas" (more <see cref="PostgresStorage"/> instances over the same database).
/// </summary>
public abstract class PgTestBase : StorageTestBase
{
    private readonly PgHarness _pg = new();
    private readonly List<IStorage> _replicas = [];

    protected PostgresStorage Pg => (PostgresStorage)Storage;

    /// <summary>The database under test (valid after <c>InitializeAsync</c>).</summary>
    internal TestDatabase Db => _pg.Current!;

    protected override Task<IStorage> CreateAsync(StorageOptions options) => _pg.CreateAsync(options, Clock);

    /// <summary>Another application instance on the same database and clock (a second replica).</summary>
    internal async Task<PostgresStorage> OpenReplicaAsync(Func<PostgresOptions, PostgresOptions>? tune = null)
    {
        PostgresStorage replica = PostgresStorage.Create(PgHarness.WithDatabase(Options, Db.ConnectionString, tune), Clock);
        await replica.InitializeAsync(CancellationToken.None);
        _replicas.Add(replica);
        return replica;
    }

    public override async Task DisposeAsync()
    {
        foreach (IStorage replica in _replicas)
        {
            await replica.DisposeAsync();
        }

        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }

    /// <summary>Runs a scalar query as the administrator on the test database.</summary>
    internal async Task<T> ScalarAsync<T>(string sql, params object[] parameters)
    {
        await using var c = new NpgsqlConnection(Db.ConnectionString);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        foreach (object p in parameters)
        {
            cmd.Parameters.Add(new NpgsqlParameter { Value = p });
        }

        object? value = await cmd.ExecuteScalarAsync();
        return (T)Convert.ChangeType(value!, typeof(T), System.Globalization.CultureInfo.InvariantCulture);
    }

    internal async Task ExecuteAsync(string sql)
    {
        await using var c = new NpgsqlConnection(Db.ConnectionString);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        await cmd.ExecuteNonQueryAsync();
    }

    internal async Task<List<string>> PartitionNamesAsync(string table)
    {
        await using var c = new NpgsqlConnection(Db.ConnectionString);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = $1 ORDER BY 1", c);
        cmd.Parameters.Add(new NpgsqlParameter { Value = table });
        var list = new List<string>();
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            list.Add(r.GetString(0));
        }

        return list;
    }
}
