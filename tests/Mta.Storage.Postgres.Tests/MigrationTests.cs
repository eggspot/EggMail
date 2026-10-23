using Microsoft.EntityFrameworkCore;
using Mta.Storage.Model;
using Npgsql;

namespace Mta.Storage.Postgres.Tests;

/// <summary>The hand-written, versioned, idempotent migrator and its agreement with the shared EF model.</summary>
public class MigrationTests : PgTestBase
{
    [Fact]
    public async Task Every_table_and_column_of_the_model_exists_with_a_matching_type_and_nullability()
    {
        var options = new DbContextOptionsBuilder<PostgresDbContext>().UseNpgsql(Db.ConnectionString).Options;
        await using var ctx = new PostgresDbContext(options, PostgresModelHooks.Instance);

        var actual = new Dictionary<string, (string Type, bool Nullable)>();
        await using (var c = new NpgsqlConnection(Db.ConnectionString))
        {
            await c.OpenAsync();
            await using var cmd = new NpgsqlCommand(
                "SELECT table_name || '.' || column_name, data_type, is_nullable FROM information_schema.columns WHERE table_schema = 'public' AND table_name !~ '_p[0-9]{8}$'", c);
            await using var r = await cmd.ExecuteReaderAsync();
            while (await r.ReadAsync())
            {
                actual[r.GetString(0)] = (r.GetString(1), r.GetString(2) == "YES");
            }
        }

        var missing = new List<string>();
        var mismatched = new List<string>();
        var modelColumns = new HashSet<string>();
        foreach (var entity in ctx.Model.GetEntityTypes())
        {
            string table = entity.GetTableName()!;
            foreach (var property in entity.GetProperties())
            {
                string column = property.GetColumnName();
                string key = table + "." + column;
                modelColumns.Add(key);
                if (!actual.TryGetValue(key, out var found))
                {
                    missing.Add(key);
                    continue;
                }

                string? expectedType = property.GetColumnType() ?? property.GetRelationalTypeMapping().StoreType;
                bool typeOk = Normalize(expectedType) == found.Type;
                if (!typeOk || property.IsNullable != found.Nullable)
                {
                    mismatched.Add($"{key}: model {expectedType}{(property.IsNullable ? "?" : "")} vs database {found.Type}{(found.Nullable ? "?" : "")}");
                }
            }
        }

        Assert.Empty(missing);
        Assert.Empty(mismatched);
        // The replica coordination tables (V006) are PostgreSQL-only, ephemeral and written with raw SQL: not part of the model or of the backend switch bundle.
        string[] outsideTheModel = ["eggmail_schema_version.", "replica_heartbeat.", "replica_signal.", "auth_failure."];
        List<string> extra = [.. actual.Keys.Where(k => !modelColumns.Contains(k) && !outsideTheModel.Any(p => k.StartsWith(p, StringComparison.Ordinal)))];
        Assert.Empty(extra);
    }

    private static string Normalize(string storeType) => storeType switch
    {
        "uuid" => "uuid",
        "text" => "text",
        "boolean" => "boolean",
        "integer" => "integer",
        "bigint" => "bigint",
        "smallint" => "smallint",
        "bytea" => "bytea",
        "timestamp with time zone" => "timestamp with time zone",
        _ => storeType,
    };

    [Fact]
    public async Task Text_columns_use_the_C_collation_and_ids_are_native_uuids()
    {
        Assert.Equal(0, await ScalarAsync<long>(
            "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND data_type = 'text' AND collation_name IS DISTINCT FROM 'C' AND table_name <> 'eggmail_schema_version'"));
        Assert.Equal(0, await ScalarAsync<long>(
            "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND column_name LIKE '%\\_id' AND data_type <> 'uuid' AND column_name NOT IN ('outbox_id', 'chunk_id', 'key_id') AND table_name NOT IN ('eggmail_schema_version')"));
    }

    [Fact]
    public async Task History_tables_are_range_partitioned_by_day_and_the_queue_tables_are_not()
    {
        foreach (string table in PostgresPartitions.Tables)
        {
            Assert.Equal("r", await ScalarAsync<string>("SELECT partstrat FROM pg_partitioned_table WHERE partrelid = $1::regclass", table));
        }

        foreach (string table in new[] { "delivery_queue", "message_spool", "webhook_outbox", "stat_aggregate", "tenant" })
        {
            Assert.Equal(0, await ScalarAsync<long>("SELECT count(*) FROM pg_partitioned_table WHERE partrelid = $1::regclass", table));
        }
    }

    [Fact]
    public async Task Migrating_again_changes_nothing_and_the_version_is_recorded_once()
    {
        for (int i = 0; i < 3; i++)
        {
            await PostgresMigrator.MigrateAsync(Db.ConnectionString, null, CancellationToken.None);
        }

        Assert.Equal(PostgresMigrator.CurrentVersion, await ScalarAsync<long>("SELECT count(*) FROM eggmail_schema_version")); // every version exactly once
        Assert.Equal(PostgresMigrator.CurrentVersion, await ScalarAsync<int>("SELECT max(version) FROM eggmail_schema_version"));
        Assert.Equal(PostgresMigrator.CurrentVersion, await PostgresMigrator.GetDatabaseVersionAsync(Pg.Runtime.Data, CancellationToken.None));
    }

    [Fact]
    public async Task Concurrent_starts_of_several_replicas_on_an_empty_database_migrate_it_once()
    {
        await using var admin = new NpgsqlConnection(Db.Server.AdminConnectionString);
        await admin.OpenAsync();
        string name = "eggmail_test_mig_" + Guid.NewGuid().ToString("N")[..10];
        await using (var create = new NpgsqlCommand($"CREATE DATABASE {name} TEMPLATE template0", admin))
        {
            await create.ExecuteNonQueryAsync();
        }

        try
        {
            string connection = Db.Server.ConnectionStringFor(name, new NpgsqlConnectionStringBuilder(Db.Server.AdminConnectionString).Username!);
            var starts = Enumerable.Range(0, 6).Select(_ => Task.Run(async () =>
            {
                PostgresStorage s = PostgresStorage.Create(PgHarness.WithDatabase(Options, connection), Clock);
                await s.InitializeAsync(CancellationToken.None);
                await s.DisposeAsync();
            }));
            await Task.WhenAll(starts);

            await using var check = new NpgsqlConnection(connection);
            await check.OpenAsync();
            await using var count = new NpgsqlCommand("SELECT count(*) FROM eggmail_schema_version", check);
            Assert.Equal((long)PostgresMigrator.CurrentVersion, await count.ExecuteScalarAsync());
        }
        finally
        {
            await Db.Server.DropDatabaseAsync(name);
        }
    }
}
