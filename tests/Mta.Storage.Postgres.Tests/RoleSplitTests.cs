using Mta.Core;
using Mta.Storage.Tests;
using Npgsql;

namespace Mta.Storage.Postgres.Tests;

/// <summary>
/// The owner/runtime role split (design §4.3): the schema owner migrates and manages partitions, the runtime role only reads and
/// writes rows. Roles and the database are created for each test and dropped afterwards; role names are unique per test.
/// </summary>
public class RoleSplitTests : StorageTestBase
{
    private string _suffix = "";
    private string OwnerRole => "eggmail_t_owner_" + _suffix;
    private string RuntimeRole => "eggmail_t_rt_" + _suffix;
    private string DbName => "eggmail_test_split_" + _suffix;

    private string OwnerConnection => PostgresTestServer.Instance.ConnectionStringFor(DbName, OwnerRole);

    private string RuntimeConnection => PostgresTestServer.Instance.ConnectionStringFor(DbName, RuntimeRole);

    private async Task CreateRolesAndDatabaseAsync()
    {
        _suffix = Guid.NewGuid().ToString("N")[..10];
        PostgresTestServer server = PostgresTestServer.Instance;
        await server.CreateRoleAsync(OwnerRole);
        await server.CreateRoleAsync(RuntimeRole);
        await using var admin = new NpgsqlConnection(server.AdminConnectionString);
        await admin.OpenAsync();
        await using var cmd = new NpgsqlCommand($"CREATE DATABASE {DbName} TEMPLATE template0 OWNER {OwnerRole}", admin);
        await cmd.ExecuteNonQueryAsync();
    }

    protected override async Task<IStorage> CreateAsync(StorageOptions options)
    {
        await CleanupAsync();
        await CreateRolesAndDatabaseAsync();
        return PostgresStorage.Create(new StorageOptions
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
                MaxPoolSize = 8,
                StatsFlushInterval = TimeSpan.Zero,
            },
        }, Clock);
    }

    private async Task CleanupAsync()
    {
        if (_suffix.Length == 0)
        {
            return;
        }

        PostgresTestServer server = PostgresTestServer.Instance;
        await server.DropDatabaseAsync(DbName);
        await server.DropRoleAsync(RuntimeRole);
        await server.DropRoleAsync(OwnerRole);
        _suffix = "";
    }

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await CleanupAsync();
    }

    private static async Task<PostgresException> ExpectErrorAsync(string connection, string sql)
    {
        await using var c = new NpgsqlConnection(connection);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        return await Assert.ThrowsAsync<PostgresException>(async () => await cmd.ExecuteNonQueryAsync());
    }

    [Fact]
    public async Task The_whole_message_lifecycle_works_with_the_runtime_role_and_the_owner_only_does_ddl()
    {
        await AddEndpointAsync(TenantA, true, "*");
        var m = await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"], retainRaw: true));
        var claimed = await ClaimAsync();
        await RecordAsync(claimed.Single(c => c.Recipient.LocalPart == "a"), DeliveryOutcome.Delivered, events: [Draft("message.delivered")]);
        await RecordAsync(claimed.Single(c => c.Recipient.LocalPart == "b"), DeliveryOutcome.Failed, suppress: SuppressionReason.HardBounce, smtp: 550);
        await FlushStatsAsync();

        Assert.Equal("partial", (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.Summary.Status);
        Assert.NotNull(await Storage.History.GetRetainedRawAsync(TenantA, m.MessageId, CancellationToken.None));
        Assert.True(await Storage.Config.IsSuppressedAsync(TenantA, "b@example.org", CancellationToken.None));
        Assert.Single(await Storage.Webhooks.ClaimDueAsync("d", 10, Clock.UtcNow, TimeSpan.FromMinutes(1), CancellationToken.None));
        Assert.Single(await Storage.Stats.QueryAsync(TenantA, Start.AddHours(-1), Start.AddHours(1), false, CancellationToken.None));

        // Time moves on: maintenance (partition DDL on the owner connection) and then intake into the new day as the runtime role.
        Clock.Advance(TimeSpan.FromDays(4));
        var reports = await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        Assert.True(reports.Single(r => r.Job == "partitions.create").RowsAffected > 0);
        var late = await AcceptAsync(Msg());
        Assert.NotNull(await Storage.History.GetAsync(TenantA, late.MessageId, CancellationToken.None));

        StorageHealth health = await Storage.Maintenance.GetHealthAsync(CancellationToken.None);
        Assert.True(health.Ready);
        Assert.Equal("true", health.Details["role_split"]);
        Assert.DoesNotContain("postgres_single_role", health.Warnings);
    }

    [Fact]
    public async Task The_schema_belongs_to_the_owner_role()
    {
        Assert.Equal(OwnerRole, await ScalarTextAsync(OwnerConnection, "SELECT tableowner FROM pg_tables WHERE tablename = 'delivery_queue'"));
        Assert.Equal(OwnerRole, await ScalarTextAsync(OwnerConnection, "SELECT tableowner FROM pg_tables WHERE tablename = $$message_event_p" + Start.UtcDateTime.ToString("yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture) + "$$"));
    }

    [Theory]
    [InlineData("CREATE TABLE sneaky (a int)")]
    [InlineData("DROP TABLE delivery_queue")]
    [InlineData("TRUNCATE delivery_queue")]
    [InlineData("ALTER TABLE delivery_queue ADD COLUMN sneaky int")]
    [InlineData("CREATE INDEX sneaky ON delivery_queue (attempt)")]
    [InlineData("DROP TABLE eggmail_schema_version")]
    public async Task The_runtime_role_cannot_change_the_schema(string ddl)
    {
        PostgresException error = await ExpectErrorAsync(RuntimeConnection, ddl);
        Assert.Equal(PostgresErrors.InsufficientPrivilege, error.SqlState);
    }

    [Fact]
    public async Task The_runtime_role_cannot_create_or_detach_partitions()
    {
        var create = await ExpectErrorAsync(RuntimeConnection, "CREATE TABLE message_event_p20300101 PARTITION OF message_event FOR VALUES FROM (1) TO (2)");
        Assert.Equal(PostgresErrors.InsufficientPrivilege, create.SqlState);
        string partition = "message_event_p" + Start.UtcDateTime.ToString("yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture);
        var detach = await ExpectErrorAsync(RuntimeConnection, $"ALTER TABLE message_event DETACH PARTITION {partition}");
        Assert.Equal(PostgresErrors.InsufficientPrivilege, detach.SqlState);
    }

    [Fact]
    public async Task The_runtime_role_has_exactly_the_row_privileges()
    {
        await using var c = new NpgsqlConnection(RuntimeConnection);
        await c.OpenAsync();
        foreach (string table in new[] { "delivery_queue", "message_spool", "webhook_outbox", "tenant", "message_index", "recent_event" })
        {
            await using var cmd = new NpgsqlCommand(
                "SELECT has_table_privilege(current_user, $1, 'SELECT'), has_table_privilege(current_user, $1, 'INSERT'), has_table_privilege(current_user, $1, 'UPDATE'), " +
                "has_table_privilege(current_user, $1, 'DELETE'), has_table_privilege(current_user, $1, 'TRUNCATE'), has_table_privilege(current_user, $1, 'REFERENCES'), has_table_privilege(current_user, $1, 'TRIGGER')", c);
            cmd.Parameters.Add(new NpgsqlParameter { Value = table });
            await using var r = await cmd.ExecuteReaderAsync();
            await r.ReadAsync();
            Assert.Equal([true, true, true, true, false, false, false], Enumerable.Range(0, 7).Select(r.GetBoolean).ToArray());
        }

        Assert.False(await ScalarBoolAsync(RuntimeConnection, "SELECT has_database_privilege(current_user, current_database(), 'CREATE')"));
        Assert.False(await ScalarBoolAsync(RuntimeConnection, "SELECT has_schema_privilege(current_user, 'public', 'CREATE')"));
    }

    [Fact]
    public async Task Without_automigrate_an_unmigrated_database_is_refused_and_the_generated_script_fixes_it()
    {
        await Storage.DisposeAsync();
        await CleanupAsync();
        await CreateRolesAndDatabaseAsync();

        StorageOptions runtimeOnly = new()
        {
            Backend = StorageBackend.Postgres,
            Postgres = new PostgresOptions { RuntimeConnectionString = RuntimeConnection, AutoMigrate = false, MaxPoolSize = 4, StatsFlushInterval = TimeSpan.Zero },
        };
        PostgresStorage refused = PostgresStorage.Create(runtimeOnly, Clock);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(async () => await refused.InitializeAsync(CancellationToken.None));
        Assert.Contains("version", error.Message, StringComparison.Ordinal);

        // A DBA applies the script as the owner (here through the same connection the app would not have).
        await using (var owner = new NpgsqlConnection(OwnerConnection))
        {
            await owner.OpenAsync();
            await using var cmd = new NpgsqlCommand(PostgresMigrator.GenerateScript(RuntimeRole), owner);
            await cmd.ExecuteNonQueryAsync();
            await using var again = new NpgsqlCommand(PostgresMigrator.GenerateScript(RuntimeRole), owner); // idempotent
            await again.ExecuteNonQueryAsync();
        }

        // The migrator created no partitions; the runtime-only process runs without them until the owner connection does maintenance.
        PostgresStorage ready = PostgresStorage.Create(new StorageOptions
        {
            Backend = StorageBackend.Postgres,
            History = new HistoryOptions { Mode = HistoryMode.StatsOnly },
            Postgres = new PostgresOptions { RuntimeConnectionString = RuntimeConnection, AutoMigrate = false, MaxPoolSize = 4, StatsFlushInterval = TimeSpan.Zero },
        }, Clock);
        await ready.InitializeAsync(CancellationToken.None);
        try
        {
            await ready.Intake.AcceptAsync(Msg(), CancellationToken.None);
            Assert.Single(await ready.Deliveries.ClaimAsync("w", 10, Clock.UtcNow, TimeSpan.FromMinutes(1), CancellationToken.None));
            StorageHealth health = await ready.Maintenance.GetHealthAsync(CancellationToken.None);
            Assert.True(health.Ready);
            Assert.Equal("1", health.Details["schema_version"]);
        }
        finally
        {
            await ready.DisposeAsync();
        }
    }

    private static async Task<string> ScalarTextAsync(string connection, string sql)
    {
        await using var c = new NpgsqlConnection(connection);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql.Replace("$$", "'", StringComparison.Ordinal), c);
        return (string)(await cmd.ExecuteScalarAsync())!;
    }

    private static async Task<bool> ScalarBoolAsync(string connection, string sql)
    {
        await using var c = new NpgsqlConnection(connection);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        return (bool)(await cmd.ExecuteScalarAsync())!;
    }
}
