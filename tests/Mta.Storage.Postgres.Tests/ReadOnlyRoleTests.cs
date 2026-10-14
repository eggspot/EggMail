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
        // Refused twice over: the session is read-only (25006) and the role has no privilege (42501, what a session that switched read-only off would meet).
        Assert.Equal("25006", (await ExpectErrorAsync(rt.Reader, "DELETE FROM recent_event")).SqlState);
        Assert.Equal("25006", (await ExpectErrorAsync(rt.Reader, "CREATE TABLE sneaky (a int)")).SqlState);
        Assert.Equal(PostgresErrors.InsufficientPrivilege, (await ExpectErrorAsync(rt.Reader, "BEGIN READ WRITE; DELETE FROM recent_event")).SqlState);
        Assert.Equal(PostgresErrors.InsufficientPrivilege, (await ExpectErrorAsync(rt.Reader, "BEGIN READ WRITE; CREATE TABLE sneaky (a int)")).SqlState);
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
    public async Task A_statement_that_runs_past_the_timeout_is_stopped_by_the_server_and_is_a_timeout_not_an_outage()
    {
        await Storage.DisposeAsync();
        await CleanupAsync();
        IStorage short1 = await StartWithTimeoutAsync(1);
        try
        {
            var error = await ExpectErrorAsync(((PostgresStorage)short1).Runtime.Reader, "SELECT pg_sleep(30)");
            Assert.Equal("57014", error.SqlState);
            Assert.True(PostgresErrors.IsStatementTimeout(error));
            Assert.False(PostgresErrors.IsUnavailable(error));   // the database is fine; the query is too heavy
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
    public void The_classifier_separates_a_statement_timeout_from_an_outage_and_from_a_cancellation_by_the_caller()
    {
        var timeout = new PostgresException("canceling statement due to statement timeout", "ERROR", "ERROR", "57014");
        Assert.True(PostgresErrors.IsStatementTimeout(timeout));
        Assert.False(PostgresErrors.IsUnavailable(timeout));
        Assert.False(PostgresErrors.IsStatementTimeout(new PostgresException("duplicate key", "ERROR", "ERROR", PostgresErrors.UniqueViolation)));

        // What Npgsql throws when the caller's token cancelled the statement: the server reports 57014 too, but it is the caller's decision.
        var cancelled = new OperationCanceledException("cancelled", new PostgresException("canceling statement due to user request", "ERROR", "ERROR", "57014"));
        Assert.False(PostgresErrors.IsStatementTimeout(cancelled));
        Assert.False(PostgresErrors.IsUnavailable(cancelled));
        using var source = new CancellationTokenSource();
        source.Cancel();
        Assert.False(PostgresErrors.IsStatementTimeout(timeout, source.Token));
    }

    [Fact]
    public async Task A_read_that_hits_the_timeout_is_a_StorageQueryTimeoutException_and_one_the_caller_cancels_stays_a_cancellation()
    {
        await Storage.DisposeAsync();
        await CleanupAsync();
        IStorage storage = await StartWithTimeoutAsync(1);
        try
        {
            var m = await AcceptOnAsync(storage);
            // Another session holds the table exclusively: the dashboard's read waits for it until the server's statement_timeout stops it.
            await using var blocker = new NpgsqlConnection(OwnerConnection);
            await blocker.OpenAsync();
            await using NpgsqlTransaction transaction = await blocker.BeginTransactionAsync();
            await using (var lockCmd = new NpgsqlCommand("LOCK TABLE message_index IN ACCESS EXCLUSIVE MODE", blocker, transaction))
            {
                await lockCmd.ExecuteNonQueryAsync();
            }

            var timedOut = await Assert.ThrowsAsync<StorageQueryTimeoutException>(async () => await storage.History.GetAsync(TenantA, m, CancellationToken.None));
            Assert.Contains("ReadOnlyStatementTimeoutSeconds", timedOut.Message, StringComparison.Ordinal);

            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await storage.History.GetAsync(TenantA, m, cts.Token));
            await transaction.RollbackAsync();
        }
        finally
        {
            await storage.DisposeAsync();
        }
    }

    private async Task<Guid> AcceptOnAsync(IStorage storage)
    {
        AcceptedMessage message = Msg();
        await storage.Intake.AcceptAsync(message, CancellationToken.None);
        return message.MessageId;
    }

    [Fact]
    public async Task Every_session_of_the_read_only_role_is_read_only_and_cannot_create_objects()
    {
        PostgresRuntime rt = Postgres.Runtime;
        Assert.Equal("on", await ScalarTextAsync(rt.Reader, "SHOW default_transaction_read_only"));
        Assert.Equal("False", await ScalarTextAsync(rt.Reader, "SELECT has_schema_privilege(current_user, 'public', 'CREATE')"));   // PostgreSQL before 15 grants it to PUBLIC
        Assert.Equal("False", await ScalarTextAsync(rt.Reader, "SELECT has_database_privilege(current_user, current_database(), 'CREATE')"));
    }

    [Fact]
    public async Task A_read_only_role_that_cannot_log_in_is_a_warning_and_the_instance_stays_ready()
    {
        PostgresRuntime rt = Postgres.Runtime;
        await using (var admin = new NpgsqlConnection(PostgresTestServer.Instance.AdminConnectionString))
        {
            await admin.OpenAsync();
            await using var cmd = new NpgsqlCommand($"ALTER ROLE {ReadOnlyRole} NOLOGIN", admin);
            await cmd.ExecuteNonQueryAsync();
        }

        rt.Reader.Clear();   // no pooled connection survives

        StorageHealth health = await Storage.Maintenance.GetHealthAsync(CancellationToken.None);   // must not throw
        Assert.True(health.Ready);
        Assert.Contains("postgres_read_only_unavailable", health.Warnings);
        Assert.DoesNotContain("postgres_unavailable", health.Warnings);
    }

    [Fact]
    public async Task A_read_only_role_with_too_many_privileges_is_reported()
    {
        await using (var admin = new NpgsqlConnection(OwnerConnection))
        {
            await admin.OpenAsync();
            await using var cmd = new NpgsqlCommand($"GRANT SELECT ON dkim_key TO {ReadOnlyRole}", admin);
            await cmd.ExecuteNonQueryAsync();
        }

        StorageHealth health = await Storage.Maintenance.GetHealthAsync(CancellationToken.None);
        Assert.True(health.Ready);
        Assert.Contains("postgres_read_only_role_too_privileged", health.Warnings);

        await using (var admin = new NpgsqlConnection(OwnerConnection))
        {
            await admin.OpenAsync();
            await using var cmd = new NpgsqlCommand($"REVOKE SELECT ON dkim_key FROM {ReadOnlyRole}; GRANT INSERT ON recent_event TO {ReadOnlyRole}", admin);
            await cmd.ExecuteNonQueryAsync();
        }

        Assert.Contains("postgres_read_only_role_too_privileged", (await Storage.Maintenance.GetHealthAsync(CancellationToken.None)).Warnings);   // a write grant on a history table too
    }

    [Fact]
    public async Task A_missing_read_only_role_stops_the_migration_with_the_key_to_fix()
    {
        await Storage.DisposeAsync();
        await CleanupAsync();
        _suffix = Guid.NewGuid().ToString("N")[..10];
        PostgresTestServer server = PostgresTestServer.Instance;
        await server.CreateRoleAsync(OwnerRole);
        await server.CreateRoleAsync(RuntimeRole);   // the read-only role is never created
        await using (var admin = new NpgsqlConnection(server.AdminConnectionString))
        {
            await admin.OpenAsync();
            await using var cmd = new NpgsqlCommand($"CREATE DATABASE {DbName} TEMPLATE template0 OWNER {OwnerRole}", admin);
            await cmd.ExecuteNonQueryAsync();
        }

        PostgresStorage storage = PostgresStorage.Create(ReadOnlyOptions(new StorageOptions(), 5), Clock);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(async () => await storage.InitializeAsync(CancellationToken.None));

        Assert.Contains("Postgres:ReadOnlyConnectionString", error.Message, StringComparison.Ordinal);
        Assert.Contains(ReadOnlyRole, error.Message, StringComparison.Ordinal);
        Assert.Contains("does not exist", error.Message, StringComparison.Ordinal);
        Assert.Contains("CREATE ROLE", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_read_only_connection_string_without_a_user_is_refused_before_any_connection_is_made()
    {
        var error = Assert.Throws<ArgumentException>(() => PostgresStorage.Create(new StorageOptions
        {
            Postgres = new PostgresOptions { RuntimeConnectionString = "Host=127.0.0.1;Username=rt", ReadOnlyConnectionString = "Host=127.0.0.1;Database=x" },
        }));
        Assert.Contains("Username", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_role_name_that_could_end_the_scripts_quoting_is_refused()
    {
        Assert.Throws<ArgumentException>(() => PostgresMigrator.GenerateScript("app", "x$eggmail_migrate$; DROP TABLE tenant; --"));
        Assert.Throws<ArgumentException>(() => PostgresMigrator.GenerateScript("x$eggmail_migrate$", null));
    }

    [Fact]
    public void Every_table_the_read_only_role_is_granted_is_read_by_the_stores_that_use_the_reader()
    {
        // The grants must be exactly what the reads need: a table in ReadOnlyTables that no reader queries any more is an over-grant, and a reader that queries
        // another table fails with 42501 in The_history_and_statistics_reads_run_as_the_read_only_role... (which runs every reader).
        string source = "";
        for (string? dir = AppContext.BaseDirectory; dir is not null && source.Length == 0; dir = Path.GetDirectoryName(dir))
        {
            string history = Path.Combine(dir, "src", "Mta.Storage.Postgres", "PostgresHistoryStore.cs");
            string stats = Path.Combine(dir, "src", "Mta.Storage.Postgres", "PostgresStatsStore.cs");
            if (File.Exists(history) && File.Exists(stats))
            {
                source = File.ReadAllText(history) + File.ReadAllText(stats);
            }
        }

        Assert.NotEmpty(source);
        foreach (string table in PostgresMigrator.ReadOnlyTables)
        {
            Assert.Contains(table, source, StringComparison.Ordinal);
        }
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
