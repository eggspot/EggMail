using Mta.Core;
using Mta.Storage.Tests;
using Npgsql;

namespace Mta.Storage.Postgres.Tests;

/// <summary>
/// The third role of design section 4.3: a read-only login with a <c>statement_timeout</c> for the dashboard's queries. The schema migration grants it
/// <c>SELECT</c> on the history and statistics tables only; the history and statistics reads use it; it cannot write and cannot read secrets.
/// </summary>
public class ReadOnlyRoleTests : StorageTestBase
{
    private string _suffix = "";
    private string OwnerRole => "eggmail_t_owner_" + _suffix;
    private string RuntimeRole => "eggmail_t_rt_" + _suffix;
    private string ReadOnlyRole => "eggmail_t_ro_" + _suffix;
    private string DbName => "eggmail_test_ro_" + _suffix;

    private string OwnerConnection => PostgresTestServer.Instance.ConnectionStringFor(DbName, OwnerRole);

    private string RuntimeConnection => PostgresTestServer.Instance.ConnectionStringFor(DbName, RuntimeRole);

    private string ReadOnlyConnection => PostgresTestServer.Instance.ConnectionStringFor(DbName, ReadOnlyRole);

    private PostgresStorage Postgres => (PostgresStorage)Storage;

    protected override async Task<IStorage> CreateAsync(StorageOptions options)
    {
        await CleanupAsync();
        _suffix = Guid.NewGuid().ToString("N")[..10];
        PostgresTestServer server = PostgresTestServer.Instance;
        await server.CreateRoleAsync(OwnerRole);
        await server.CreateRoleAsync(RuntimeRole);
        await server.CreateRoleAsync(ReadOnlyRole);
        await using var admin = new NpgsqlConnection(server.AdminConnectionString);
        await admin.OpenAsync();
        await using var cmd = new NpgsqlCommand($"CREATE DATABASE {DbName} TEMPLATE template0 OWNER {OwnerRole}", admin);
        await cmd.ExecuteNonQueryAsync();
        return PostgresStorage.Create(ReadOnlyOptions(options, statementTimeoutSeconds: 5), Clock);
    }

    private StorageOptions ReadOnlyOptions(StorageOptions options, int statementTimeoutSeconds) => new()
    {
        Backend = StorageBackend.Postgres,
        History = options.History,
        Retention = options.Retention,
        Content = options.Content,
        Queue = options.Queue,
        Postgres = new PostgresOptions
        {
            OwnerConnectionString = OwnerConnection,
            RuntimeConnectionString = RuntimeConnection,
            ReadOnlyConnectionString = ReadOnlyConnection,
            ReadOnlyStatementTimeoutSeconds = statementTimeoutSeconds,
            ReadOnlyIdleInTransactionTimeoutSeconds = 7,
            ReadOnlyMaxPoolSize = 3,
            MaxPoolSize = 8,
            StatsFlushInterval = TimeSpan.Zero,
        },
    };

    private async Task CleanupAsync()
    {
        if (_suffix.Length == 0)
        {
            return;
        }

        PostgresTestServer server = PostgresTestServer.Instance;
        await server.DropDatabaseAsync(DbName);
        await server.DropRoleAsync(ReadOnlyRole);
        await server.DropRoleAsync(RuntimeRole);
        await server.DropRoleAsync(OwnerRole);
        _suffix = "";
    }

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await CleanupAsync();
    }

    private static async Task<string> ScalarTextAsync(NpgsqlDataSource source, string sql)
    {
        await using NpgsqlConnection c = await source.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        return Convert.ToString(await cmd.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture)!;
    }

    private static async Task<PostgresException> ExpectErrorAsync(NpgsqlDataSource source, string sql)
    {
        await using NpgsqlConnection c = await source.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        return await Assert.ThrowsAsync<PostgresException>(async () => await cmd.ExecuteNonQueryAsync());
    }

    [Fact]
    public async Task The_history_and_statistics_reads_run_as_the_read_only_role_and_see_what_the_runtime_role_wrote()
    {
        await AddEndpointAsync(TenantA, true, "*");
        var m = await AcceptAsync(Msg(to: ["a@example.org"], retainRaw: true));
        var claimed = await ClaimAsync();
        await RecordAsync(claimed.Single(), DeliveryOutcome.Delivered, events: [Draft("message.delivered")]);
        await FlushStatsAsync();
        PostgresRuntime rt = Postgres.Runtime;

        Assert.True(rt.SeparateReader);
        Assert.Equal(ReadOnlyRole, await ScalarTextAsync(rt.Reader, "SELECT current_user"));
        Assert.Equal(RuntimeRole, await ScalarTextAsync(rt.Data, "SELECT current_user"));

        // Every read of the dashboard works through the read-only connection (it would fail with 42501 if one of them still needed another table).
        Assert.Equal("delivered", (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.Summary.Status);
        Assert.Single((await Storage.History.SearchAsync(new MessageQuery { TenantId = TenantA, Limit = 10 }, CancellationToken.None)).Items);
        Assert.NotEmpty(await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None));
        Assert.NotNull(await Storage.History.GetRetainedRawAsync(TenantA, m.MessageId, CancellationToken.None));
        Assert.Single(await Storage.Stats.QueryAsync(TenantA, Start.AddHours(-1), Start.AddHours(1), false, CancellationToken.None));
        Assert.NotEmpty(await Storage.Stats.GetRecentEventsAsync(TenantA, 10, CancellationToken.None));
        Assert.Contains("a@example.org", (await ((IMessageRecipientLookup)Storage.History).GetRecipientsAsync(TenantA, [m.MessageId], 5, CancellationToken.None))[m.MessageId]);

        // The connections it used were the read-only ones.
        long readOnlySessions = long.Parse(await ScalarTextAsync(rt.Data, $"SELECT count(*) FROM pg_stat_activity WHERE usename = '{ReadOnlyRole}' AND application_name = 'eggmail-readonly'"), System.Globalization.CultureInfo.InvariantCulture);
        Assert.True(readOnlySessions > 0);

        StorageHealth health = await Storage.Maintenance.GetHealthAsync(CancellationToken.None);
        Assert.True(health.Ready);
        Assert.Equal(ReadOnlyRole, health.Details["read_only_role"]);
        Assert.DoesNotContain("postgres_read_only_role_can_write_or_read_secrets", health.Warnings);
    }

    [Fact]
    public async Task The_read_only_role_has_select_on_exactly_the_history_and_statistics_tables()
    {
        PostgresRuntime rt = Postgres.Runtime;

        foreach (string table in PostgresMigrator.ReadOnlyTables)
        {
            Assert.Equal("True", await ScalarTextAsync(rt.Reader, $"SELECT has_table_privilege(current_user, '{table}', 'SELECT')"));
        }

        // Secrets, the queue, configuration and webhook data are out of reach, and so is every kind of write.
        foreach (string table in new[] { "setting", "dkim_key", "certificate", "api_key", "data_protection_key", "smtp_credential", "dashboard_user", "dashboard_session", "delivery_queue", "message_spool", "webhook_endpoint", "tenant" })
        {
            Assert.Equal("False", await ScalarTextAsync(rt.Reader, $"SELECT has_table_privilege(current_user, '{table}', 'SELECT')"));
        }

        foreach (string table in PostgresMigrator.ReadOnlyTables)
        {
            Assert.Equal("False", await ScalarTextAsync(rt.Reader, $"SELECT has_table_privilege(current_user, '{table}', 'INSERT') OR has_table_privilege(current_user, '{table}', 'UPDATE') OR has_table_privilege(current_user, '{table}', 'DELETE') OR has_table_privilege(current_user, '{table}', 'TRUNCATE')"));
        }

        Assert.Equal(PostgresErrors.InsufficientPrivilege, (await ExpectErrorAsync(rt.Reader, "SELECT * FROM setting")).SqlState);
        Assert.Equal(PostgresErrors.InsufficientPrivilege, (await ExpectErrorAsync(rt.Reader, "DELETE FROM recent_event")).SqlState);
        Assert.Equal(PostgresErrors.InsufficientPrivilege, (await ExpectErrorAsync(rt.Reader, "CREATE TABLE sneaky (a int)")).SqlState);
    }

    [Fact]
    public async Task A_day_partition_created_later_is_readable_through_the_parent()
    {
        Clock.Advance(TimeSpan.FromDays(4));
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);   // creates partitions for the new days as the owner
        var late = await AcceptAsync(Msg());

        Assert.NotNull(await Storage.History.GetAsync(TenantA, late.MessageId, CancellationToken.None));
        Assert.NotEmpty((await Storage.History.SearchAsync(new MessageQuery { TenantId = TenantA, Limit = 10 }, CancellationToken.None)).Items);
    }

    [Fact]
    public async Task The_read_only_connections_carry_the_statement_and_idle_in_transaction_timeouts()
    {
        PostgresRuntime rt = Postgres.Runtime;

        // Several times over: a pooled connection is reset when it is returned (DISCARD ALL), and a plain SET would be gone from the second use on.
        for (int i = 0; i < 4; i++)
        {
            Assert.Equal("5s", await ScalarTextAsync(rt.Reader, "SHOW statement_timeout"));
            Assert.Equal("7s", await ScalarTextAsync(rt.Reader, "SHOW idle_in_transaction_session_timeout"));
        }

        Assert.NotEqual("5s", await ScalarTextAsync(rt.Data, "SHOW statement_timeout"));   // the runtime role is not limited this way
    }

    [Fact]
    public async Task A_statement_that_runs_past_the_timeout_is_stopped_by_the_server_and_counts_as_unavailable()
    {
        await Storage.DisposeAsync();
        await CleanupAsync();
        IStorage short1 = await StartWithTimeoutAsync(1);
        try
        {
            var error = await ExpectErrorAsync(((PostgresStorage)short1).Runtime.Reader, "SELECT pg_sleep(30)");
            Assert.Equal("57014", error.SqlState);
            Assert.True(PostgresErrors.IsUnavailable(error));   // answered as "try again later", not as a server error
        }
        finally
        {
            await short1.DisposeAsync();
        }
    }

    private async Task<IStorage> StartWithTimeoutAsync(int seconds)
    {
        _suffix = Guid.NewGuid().ToString("N")[..10];
        PostgresTestServer server = PostgresTestServer.Instance;
        await server.CreateRoleAsync(OwnerRole);
        await server.CreateRoleAsync(RuntimeRole);
        await server.CreateRoleAsync(ReadOnlyRole);
        await using (var admin = new NpgsqlConnection(server.AdminConnectionString))
        {
            await admin.OpenAsync();
            await using var cmd = new NpgsqlCommand($"CREATE DATABASE {DbName} TEMPLATE template0 OWNER {OwnerRole}", admin);
            await cmd.ExecuteNonQueryAsync();
        }

        PostgresStorage storage = PostgresStorage.Create(ReadOnlyOptions(new StorageOptions(), seconds), Clock);
        await storage.InitializeAsync(CancellationToken.None);
        return storage;
    }

    [Fact]
    public void The_error_classifier_treats_a_cancelled_statement_as_unavailable()
    {
        Assert.True(PostgresErrors.IsUnavailable(new PostgresException("canceling statement due to statement timeout", "ERROR", "ERROR", "57014")));
        Assert.False(PostgresErrors.IsUnavailable(new PostgresException("duplicate key", "ERROR", "ERROR", PostgresErrors.UniqueViolation)));
    }

    [Fact]
    public async Task Without_the_grants_the_start_is_refused_with_an_explanation()
    {
        await Storage.DisposeAsync();
        await CleanupAsync();
        _suffix = Guid.NewGuid().ToString("N")[..10];
        PostgresTestServer server = PostgresTestServer.Instance;
        await server.CreateRoleAsync(OwnerRole);
        await server.CreateRoleAsync(RuntimeRole);
        await server.CreateRoleAsync(ReadOnlyRole);
        await using (var admin = new NpgsqlConnection(server.AdminConnectionString))
        {
            await admin.OpenAsync();
            await using var cmd = new NpgsqlCommand($"CREATE DATABASE {DbName} TEMPLATE template0 OWNER {OwnerRole}", admin);
            await cmd.ExecuteNonQueryAsync();
        }

        // A DBA migrated with a script made without the read-only role, and the application does not migrate.
        await using (var owner = new NpgsqlConnection(OwnerConnection))
        {
            await owner.OpenAsync();
            await using var cmd = new NpgsqlCommand(PostgresMigrator.GenerateScript(RuntimeRole), owner);
            await cmd.ExecuteNonQueryAsync();
        }

        PostgresStorage storage = PostgresStorage.Create(new StorageOptions
        {
            Backend = StorageBackend.Postgres,
            Postgres = new PostgresOptions
            {
                OwnerConnectionString = OwnerConnection,
                RuntimeConnectionString = RuntimeConnection,
                ReadOnlyConnectionString = ReadOnlyConnection,
                AutoMigrate = false,
                MaxPoolSize = 4,
                StatsFlushInterval = TimeSpan.Zero,
            },
        }, Clock);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(async () => await storage.InitializeAsync(CancellationToken.None));
        Assert.Contains(ReadOnlyRole, error.Message, StringComparison.Ordinal);
        Assert.Contains("GenerateScript(runtimeRole, readOnlyRole)", error.Message, StringComparison.Ordinal);

        // With the script that names the read-only role the same configuration starts.
        await using (var owner = new NpgsqlConnection(OwnerConnection))
        {
            await owner.OpenAsync();
            await using var cmd = new NpgsqlCommand(PostgresMigrator.GenerateScript(RuntimeRole, ReadOnlyRole), owner);
            await cmd.ExecuteNonQueryAsync();
        }

        PostgresStorage fixedStorage = PostgresStorage.Create(new StorageOptions
        {
            Backend = StorageBackend.Postgres,
            Postgres = new PostgresOptions
            {
                OwnerConnectionString = OwnerConnection,
                RuntimeConnectionString = RuntimeConnection,
                ReadOnlyConnectionString = ReadOnlyConnection,
                AutoMigrate = false,
                MaxPoolSize = 4,
                StatsFlushInterval = TimeSpan.Zero,
            },
        }, Clock);
        await fixedStorage.InitializeAsync(CancellationToken.None);
        await fixedStorage.DisposeAsync();
    }

    [Fact]
    public void The_script_grants_the_read_only_role_only_the_history_tables_and_stays_one_idempotent_block()
    {
        string script = PostgresMigrator.GenerateScript("app", "dash board");

        Assert.Contains("GRANT USAGE ON SCHEMA public TO \"dash board\"", script, StringComparison.Ordinal);
        Assert.Contains("GRANT SELECT ON message_index, message_recipient, message_event, message_content, message_raw_retained, stat_aggregate, recent_event TO \"dash board\"", script, StringComparison.Ordinal);
        Assert.Equal(2, script.Split("\"dash board\"").Length - 1);   // the schema USAGE and the table SELECT, nothing else
        Assert.Single(script.Split("DO $eggmail_migrate$", StringSplitOptions.None).Skip(1));
        Assert.DoesNotContain("dash board", PostgresMigrator.GenerateScript("app"), StringComparison.Ordinal);
    }

    [Fact]
    public void Read_only_options_are_validated_before_any_connection_is_made()
    {
        Assert.Throws<ArgumentException>(() => PostgresStorage.Create(new StorageOptions
        {
            Postgres = new PostgresOptions { RuntimeConnectionString = "Host=127.0.0.1", ReadOnlyConnectionString = "Host=127.0.0.1;Username=ro", ReadOnlyStatementTimeoutSeconds = 0 },
        }));
    }
}
