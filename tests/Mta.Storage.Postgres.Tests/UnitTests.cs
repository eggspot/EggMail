using System.Net.Sockets;
using Npgsql;

namespace Mta.Storage.Postgres.Tests;

/// <summary>Pure logic that needs no server (these run even when no PostgreSQL is available).</summary>
[NoPostgres]
public class UnitTests
{
    [Fact]
    public void Network_failures_are_availability_failures()
    {
        Assert.True(PostgresErrors.IsUnavailable(new SocketException()));
        Assert.True(PostgresErrors.IsUnavailable(new IOException("broken pipe")));
        Assert.True(PostgresErrors.IsUnavailable(new TimeoutException()));
        Assert.True(PostgresErrors.IsUnavailable(new NpgsqlException("Exception while connecting", new SocketException())));
        Assert.True(PostgresErrors.IsUnavailable(new InvalidOperationException("outer", new NpgsqlException("x", new IOException()))));
    }

    [Fact]
    public void Programming_and_data_errors_are_not_availability_failures()
    {
        Assert.False(PostgresErrors.IsUnavailable(new ArgumentException("bad")));
        Assert.False(PostgresErrors.IsUnavailable(new InvalidOperationException("bad")));
        Assert.False(PostgresErrors.IsUnavailable(new NpgsqlException("syntax")));
        Assert.Null(PostgresErrors.Translate(new ArgumentException("bad")));
    }

    [Fact]
    public void Translate_wraps_availability_failures_once()
    {
        var wrapped = Assert.IsType<StorageUnavailableException>(PostgresErrors.Translate(new IOException("reset")));
        Assert.IsType<IOException>(wrapped.InnerException);
        Assert.Null(PostgresErrors.Translate(wrapped));
    }

    [Fact]
    public void Partition_names_carry_the_table_and_the_utc_day()
    {
        Assert.Equal("message_event_p20261012", PostgresPartitions.NameOf("message_event", 20738));
        Assert.Equal("message_index_p19700101", PostgresPartitions.NameOf("message_index", 0));
    }

    [Fact]
    public void Job_lock_keys_are_stable_and_distinct()
    {
        Assert.Equal(AdvisoryLockKeys.Job("retention.metadata"), AdvisoryLockKeys.Job("retention.metadata"));
        Assert.NotEqual(AdvisoryLockKeys.Job("retention.metadata"), AdvisoryLockKeys.Job("retention.content"));
        Assert.NotEqual(AdvisoryLockKeys.Migrate, AdvisoryLockKeys.PartitionDdl);
    }

    [Fact]
    public void The_migration_script_is_one_idempotent_block_that_quotes_the_runtime_role()
    {
        string script = PostgresMigrator.GenerateScript("app user");
        Assert.StartsWith("-- EggMail schema migration", script, StringComparison.Ordinal);
        Assert.Contains("pg_advisory_xact_lock", script, StringComparison.Ordinal);
        Assert.Contains("CREATE TABLE IF NOT EXISTS eggmail_schema_version", script, StringComparison.Ordinal);
        Assert.Contains("\"app user\"", script, StringComparison.Ordinal);
        Assert.Contains("ALTER DEFAULT PRIVILEGES", script, StringComparison.Ordinal);
        Assert.Single(script.Split("DO $eggmail_migrate$", StringSplitOptions.None).Skip(1));
        Assert.DoesNotContain("GRANT", PostgresMigrator.GenerateScript(null), StringComparison.Ordinal);
        Assert.Equal(3, PostgresMigrator.CurrentVersion);
    }

    [Fact]
    public void Invalid_options_are_refused_before_any_connection_is_made()
    {
        Assert.Throws<ArgumentException>(() => PostgresStorage.Create(new StorageOptions { Backend = StorageBackend.Postgres }));
        Assert.Throws<ArgumentException>(() => PostgresStorage.Create(new StorageOptions
        {
            Postgres = new PostgresOptions { RuntimeConnectionString = "Host=127.0.0.1", MaxPoolSize = 0 },
        }));
        Assert.Throws<ArgumentException>(() => PostgresStorage.Create(new StorageOptions
        {
            Postgres = new PostgresOptions { RuntimeConnectionString = "Host=127.0.0.1" },
            Content = new ContentOptions { RetentionDays = 3 },
        }));
    }

    [Fact]
    public async Task Using_the_storage_before_it_is_initialized_is_an_error()
    {
        await using PostgresStorage storage = PostgresStorage.Create(new StorageOptions { Postgres = new PostgresOptions { RuntimeConnectionString = "Host=127.0.0.1" } });
        Assert.Throws<InvalidOperationException>(() => storage.Config);
        Assert.Throws<InvalidOperationException>(() => storage.Maintenance);
        Assert.Equal(StorageBackend.Postgres, storage.Backend);
    }
}
