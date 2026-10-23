using System.Net.Sockets;
using Npgsql;

namespace Mta.Storage.Postgres.Tests;

/// <summary>Pure logic that needs no server (these run even when no PostgreSQL is available).</summary>
[NoPostgres]
public class UnitTests
{
    [Fact]
    public void Text_written_to_PostgreSQL_is_cleaned_and_text_in_a_filter_is_never_touched()
    {
        string lone = ((char)0xD800).ToString();
        var write = new NpgsqlCommand();
        write.Parameters.Text("a\0b" + lone).TextArray(["ok", "x\0y", null]).Text(null);
        Assert.Equal("a" + (char)0xFFFD + "b" + (char)0xFFFD, write.Parameters[0].Value);
        Assert.Equal(new string?[] { "ok", "x" + (char)0xFFFD + "y", null }, (string?[])write.Parameters[1].Value!);
        Assert.Equal(DBNull.Value, write.Parameters[2].Value);

        // A filter is passed as it is: cleaning it would let a search for "a<NUL>b" find the stored text "a<U+FFFD>b" (callers refuse unstorable filters first).
        var filter = new NpgsqlCommand();
        filter.Parameters.TextExact("a\0b");
        Assert.Equal("a\0b", filter.Parameters[0].Value);
    }

    [Fact]
    public void An_array_of_text_that_can_all_be_stored_is_passed_on_without_a_copy()
    {
        string?[] clean = ["a", "b", null, "\u00fc\u7528"];
        Assert.Same(clean, NpgsqlParameterExtensions.CleanedIfNeeded(clean));
        string?[] dirty = ["a", "b\0"];
        Assert.NotSame(dirty, NpgsqlParameterExtensions.CleanedIfNeeded(dirty));
        Assert.Equal("b" + (char)0xFFFD, NpgsqlParameterExtensions.CleanedIfNeeded(dirty)[1]);
        Assert.Equal("b\0", dirty[1]);   // the caller's array is not changed
    }

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
    public void Only_broken_connections_justify_discarding_the_pool_not_plain_timeouts()
    {
        Assert.True(PostgresErrors.IsBrokenConnection(new NpgsqlException("x", new IOException())));
        Assert.True(PostgresErrors.IsBrokenConnection(new NpgsqlException("x", new SocketException())));
        Assert.False(PostgresErrors.IsBrokenConnection(new NpgsqlException("Failed to connect", new TimeoutException("Timeout during connection attempt"))));
        Assert.False(PostgresErrors.IsBrokenConnection(new TimeoutException()));
        Assert.True(PostgresErrors.IsUnavailable(new NpgsqlException("Failed to connect", new TimeoutException())));
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
        Assert.Equal(12, PostgresMigrator.CurrentVersion);
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
