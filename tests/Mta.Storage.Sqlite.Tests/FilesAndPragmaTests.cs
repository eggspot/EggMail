using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Mta.Core;
using Mta.Storage.Model;

namespace Mta.Storage.Sqlite.Tests;

public class FilesAndPragmaTests : SqliteTestBase
{
    private static string[] DbFiles(string dir) => Directory.GetFiles(dir, "*.db").Select(Path.GetFileName).OfType<string>().Order(StringComparer.Ordinal).ToArray();

    [Fact]
    public void Full_history_creates_queue_stats_config_and_history_files()
    {
        Assert.Equal(["config.db", "history.db", "queue.db", "stats.db"], DbFiles(Dir));
    }

    [Fact]
    public async Task Stats_only_does_not_create_a_history_file()
    {
        string dir = SqliteTestStorage.NewDirectory();
        try
        {
            await using (var s = SqliteStorage.Create(SqliteTestStorage.WithDirectory(WithMode(Opts(), HistoryMode.StatsOnly), dir), Clock))
            {
                await s.InitializeAsync(default);
            }

            Assert.Equal(["config.db", "queue.db", "stats.db"], DbFiles(dir));
        }
        finally
        {
            SqliteTestStorage.TryDelete(dir);
        }
    }

    [Fact]
    public async Task Memory_queue_persistence_creates_no_queue_file_and_loses_mail_on_restart()
    {
        await ReopenAsync(b => b.QueuePersistence = QueuePersistence.Memory);
        await AcceptAsync();
        Assert.Single(await ClaimAsync());
        StorageHealth health = await Storage.Maintenance.GetHealthAsync(default);
        Assert.Contains("queue_persistence_memory", health.Warnings);

        await ReopenAsync(b => b.QueuePersistence = QueuePersistence.Memory);
        Assert.Empty(await ClaimAsync(now: Clock.UtcNow.AddDays(1)));
    }

    [Fact]
    public async Task Memory_queue_never_writes_a_queue_database()
    {
        string dir = SqliteTestStorage.NewDirectory();
        try
        {
            await using var s = SqliteStorage.Create(SqliteTestStorage.WithDirectory(Opts(), dir, b => b.QueuePersistence = QueuePersistence.Memory), Clock);
            await s.InitializeAsync(default);
            Assert.DoesNotContain("queue.db", DbFiles(dir));
        }
        finally
        {
            SqliteTestStorage.TryDelete(dir);
        }
    }

    [Theory]
    [InlineData(SqliteSyncMode.Off, 0)]
    [InlineData(SqliteSyncMode.Normal, 1)]
    [InlineData(SqliteSyncMode.Full, 2)]
    public async Task Synchronous_pragma_follows_the_sync_mode_and_config_stays_full(SqliteSyncMode mode, int expected)
    {
        await ReopenAsync(b => b.SyncMode = mode);
        Assert.Equal(expected, await WriterScalarAsync("queue", "PRAGMA synchronous"));
        Assert.Equal(expected, await WriterScalarAsync("stats", "PRAGMA synchronous"));
        Assert.Equal(expected, await WriterScalarAsync("history", "PRAGMA synchronous"));
        Assert.Equal(2, await WriterScalarAsync("config", "PRAGMA synchronous"));
    }

    [Fact]
    public async Task Config_sync_mode_is_independent()
    {
        await ReopenAsync(b => b.ConfigSyncMode = SqliteSyncMode.Normal);
        Assert.Equal(1, await WriterScalarAsync("config", "PRAGMA synchronous"));
        Assert.Equal(0, await WriterScalarAsync("queue", "PRAGMA synchronous"));
    }

    [Fact]
    public async Task Every_file_uses_wal_incremental_auto_vacuum_and_the_configured_limits()
    {
        SqliteRuntime rt = Sql.Runtime;
        foreach (SqliteFileWriter w in rt.Writers)
        {
            string mode = ScalarText(w.File.Path!, "PRAGMA journal_mode");
            Assert.Equal("wal", mode);
            Assert.Equal(2, ScalarLong(w.File.Path!, "PRAGMA auto_vacuum"));
            Assert.Equal(5000, await WriterScalarAsync(w.File.Name, "PRAGMA busy_timeout"));
            Assert.Equal(64L * 1024 * 1024, await WriterScalarAsync(w.File.Name, "PRAGMA journal_size_limit"));
            Assert.Equal(SqliteFile.SchemaVersion, ScalarLong(w.File.Path!, "PRAGMA user_version"));
        }
    }

    [Fact]
    public async Task Health_warns_about_sync_off_naming_the_files_and_clears_with_normal_or_full()
    {
        StorageHealth off = await Storage.Maintenance.GetHealthAsync(default);
        Assert.True(off.Ready);
        Assert.Contains("sqlite_sync_off", off.Warnings);
        Assert.Equal("history.db,queue.db,stats.db", string.Join(',', off.Details["sqlite_sync_off.files"].Split(',').Order(StringComparer.Ordinal)));
        Assert.Equal("Off", off.Details["sync_mode.queue"]);
        Assert.Equal("Full", off.Details["sync_mode.config"]);

        await ReopenAsync(b => b.SyncMode = SqliteSyncMode.Normal);
        Assert.DoesNotContain("sqlite_sync_off", (await Storage.Maintenance.GetHealthAsync(default)).Warnings);
        await ReopenAsync(b => b.SyncMode = SqliteSyncMode.Full);
        Assert.DoesNotContain("sqlite_sync_off", (await Storage.Maintenance.GetHealthAsync(default)).Warnings);
        await ReopenAsync(b => b.ConfigSyncMode = SqliteSyncMode.Off);
        var cfgOff = await Storage.Maintenance.GetHealthAsync(default);
        Assert.Contains("config.db", cfgOff.Details["sqlite_sync_off.files"]);
    }

    [Fact]
    public async Task Sync_off_is_logged_as_a_startup_warning()
    {
        var log = new CapturingLog();
        string dir = SqliteTestStorage.NewDirectory();
        try
        {
            await using var s = SqliteStorage.Create(SqliteTestStorage.WithDirectory(Opts(), dir), Clock, log);
            await s.InitializeAsync(default);
            Assert.Contains(log.Entries, e => e.Level == MtaLogLevel.Warning && e.Message.Contains("synchronous=OFF", StringComparison.Ordinal) && e.Message.Contains("queue.db", StringComparison.Ordinal));
        }
        finally
        {
            SqliteTestStorage.TryDelete(dir);
        }
    }

    [Fact]
    public async Task Ids_are_stored_as_upper_case_text_so_text_order_is_time_order()
    {
        var m = await AcceptAsync();
        await Storage.DisposeAsync();
        string stored = ScalarText(PathOf("queue.db"), "SELECT message_id FROM message_spool");
        Assert.Equal(m.MessageId.ToString("D").ToUpperInvariant(), stored);
        Assert.Equal("text", ScalarText(PathOf("queue.db"), "SELECT typeof(message_id) FROM message_spool"));
        Assert.Equal("integer", ScalarText(PathOf("queue.db"), "SELECT typeof(due_at) FROM delivery_queue"));
        Assert.Equal(Start.ToUnixTimeMilliseconds(), ScalarLong(PathOf("queue.db"), "SELECT due_at FROM delivery_queue"));
    }

    [Fact]
    public async Task History_tables_with_small_rows_are_without_rowid_and_big_ones_are_not()
    {
        await Storage.DisposeAsync();
        string sql(string t) => ScalarText(PathOf("history.db"), $"SELECT sql FROM sqlite_master WHERE name = '{t}'");
        foreach (string t in new[] { "message_index", "message_recipient", "message_event" })
        {
            Assert.EndsWith("WITHOUT ROWID", sql(t).TrimEnd(), StringComparison.Ordinal);
        }

        foreach (string t in new[] { "message_content", "message_raw_retained" })
        {
            Assert.DoesNotContain("WITHOUT ROWID", sql(t), StringComparison.Ordinal);
        }

        Assert.EndsWith("WITHOUT ROWID", ScalarText(PathOf("stats.db"), "SELECT sql FROM sqlite_master WHERE name = 'stat_aggregate'").TrimEnd(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_database_schema_matches_the_ef_model_of_every_part()
    {
        await Storage.DisposeAsync();
        Check<ConfigDbContext>("config.db", o => new ConfigDbContext(o, SqliteModelHooks.Instance));
        Check<QueueDbContext>("queue.db", o => new QueueDbContext(o, SqliteModelHooks.Instance));
        Check<StatsDbContext>("stats.db", o => new StatsDbContext(o, SqliteModelHooks.Instance));
        Check<HistoryDbContext>("history.db", o => new HistoryDbContext(o, SqliteModelHooks.Instance));

        void Check<T>(string file, Func<DbContextOptions<T>, T> create) where T : DbContext
        {
            var options = new DbContextOptionsBuilder<T>().UseSqlite($"Data Source={PathOf(file)};Pooling=False").Options;
            using T ctx = create(options);
            using var raw = new SqliteConnection($"Data Source={PathOf(file)};Pooling=False");
            raw.Open();
            foreach (var entity in ctx.Model.GetEntityTypes())
            {
                string table = entity.GetTableName()!;
                var modelColumns = entity.GetProperties().Select(p => p.GetColumnName()).Order(StringComparer.Ordinal).ToList();
                using SqliteCommand cmd = raw.CreateCommand();
                cmd.CommandText = $"SELECT name FROM pragma_table_info('{table}')";
                var actual = new List<string>();
                using (SqliteDataReader r = cmd.ExecuteReader())
                {
                    while (r.Read())
                    {
                        actual.Add(r.GetString(0));
                    }
                }

                Assert.Equal(modelColumns, actual.Order(StringComparer.Ordinal).ToList());
            }
        }
    }

    [Fact]
    public async Task A_version_1_database_is_upgraded_with_the_api_tables_and_the_idempotency_fingerprint()
    {
        await Storage.DisposeAsync();
        void Run(string file, params string[] sql)
        {
            using var c = new SqliteConnection($"Data Source={PathOf(file)};Pooling=False");
            c.Open();
            foreach (string statement in sql)
            {
                using SqliteCommand cmd = c.CreateCommand();
                cmd.CommandText = statement;
                cmd.ExecuteNonQuery();
            }
        }

        // Turn the files back into what version 1 created (no API tables, no fingerprint, and none of the version 3 switch tables).
        Run("config.db", "DROP TABLE dashboard_session", "DROP TABLE dashboard_user", "DROP TABLE transfer_chunk_config", "PRAGMA user_version = 1");
        Run("queue.db", "ALTER TABLE api_idempotency_key DROP COLUMN fingerprint", "ALTER TABLE delivery_queue DROP COLUMN smtp_utf8", "ALTER TABLE delivery_queue DROP COLUMN transfer_switch_id", "ALTER TABLE webhook_outbox DROP COLUMN transfer_switch_id", "DROP TABLE transfer_chunk_queue", "PRAGMA user_version = 1");
        Run("stats.db", "DROP TABLE transfer_chunk_stats", "PRAGMA user_version = 1");
        Run("history.db", "DROP TABLE transfer_chunk_history", "PRAGMA user_version = 1");

        await ReopenAsync();
        Assert.Equal(SqliteFile.SchemaVersion, ScalarLong(PathOf("config.db"), "PRAGMA user_version"));
        Assert.Equal(SqliteFile.SchemaVersion, ScalarLong(PathOf("queue.db"), "PRAGMA user_version"));
        Assert.Equal(5, SqliteFile.SchemaVersion);
        Assert.Equal(0, ScalarLong(PathOf("queue.db"), "SELECT count(*) FROM transfer_chunk_queue")); // the 1 to 2 to 3 path reached the switch tables too
        Assert.Equal(1, ScalarLong(PathOf("queue.db"), "SELECT count(*) FROM pragma_table_info('delivery_queue') WHERE name = 'smtp_utf8'")); // and the version 5 column

        var user = new DashboardUser(Guid.NewGuid(), "Upgraded", "hash", DashboardRole.Admin, null, true, Clock.UtcNow);
        await Storage.Config.UpsertDashboardUserAsync(user, default);
        Assert.Equal(user.Id, (await Storage.Config.FindDashboardUserAsync("upgraded", default))!.Id);
        await Assert.ThrowsAsync<StorageConflictException>(async () => await Storage.Config.UpsertDashboardUserAsync(user with { Id = Guid.NewGuid() }, default));

        AcceptedMessage first = Msg(idempotencyKey: "k");
        AcceptedMessage withPrint = new()
        {
            MessageId = first.MessageId, TenantId = first.TenantId, Source = first.Source, EnvelopeFrom = first.EnvelopeFrom, Recipients = first.Recipients, Raw = first.Raw,
            ReceivedAt = first.ReceivedAt, ExpiresAt = first.ExpiresAt, IdempotencyKey = "k", IdempotencyFingerprint = "sha256:x", Content = first.Content, SendingDomain = first.SendingDomain,
        };
        await Storage.Intake.AcceptAsync(withPrint, default);
        IntakeResult dup = await Storage.Intake.AcceptAsync(Msg(idempotencyKey: "k"), default);
        Assert.Equal("sha256:x", dup.IdempotencyFingerprint);
    }

    [Fact]
    public async Task A_database_with_a_newer_schema_version_is_refused()
    {
        await Storage.DisposeAsync();
        using (var c = new SqliteConnection($"Data Source={PathOf("config.db")};Pooling=False"))
        {
            c.Open();
            using SqliteCommand cmd = c.CreateCommand();
            cmd.CommandText = "PRAGMA user_version = 99";
            cmd.ExecuteNonQuery();
        }

        await Assert.ThrowsAnyAsync<InvalidOperationException>(async () => await ReopenAsync());
    }

    [Fact]
    public async Task A_version_2_database_is_upgraded_with_the_backend_switch_columns_and_tables()
    {
        await AcceptAsync(Msg(to: ["a@example.org"]));
        await Storage.DisposeAsync();

        // Rebuild what version 2 files looked like: no transfer hold column, no progress tables (the API tables stay).
        foreach (string file in new[] { "queue.db", "stats.db", "config.db", "history.db" })
        {
            string kind = file[..^3];
            using var c = new SqliteConnection($"Data Source={PathOf(file)};Pooling=False");
            c.Open();
            using SqliteCommand cmd = c.CreateCommand();
            cmd.CommandText = $"DROP TABLE transfer_chunk_{kind};" + (kind == "queue"
                ? "ALTER TABLE delivery_queue DROP COLUMN smtp_utf8; ALTER TABLE delivery_queue DROP COLUMN transfer_switch_id; ALTER TABLE webhook_outbox DROP COLUMN transfer_switch_id;"
                : "") + "PRAGMA user_version = 2";
            cmd.ExecuteNonQuery();
        }

        await ReopenAsync();
        foreach (string kind in new[] { "queue", "stats", "config", "history" })
        {
            Assert.Equal(SqliteFile.SchemaVersion, ScalarLong(PathOf(kind + ".db"), "PRAGMA user_version"));
            Assert.Equal(0, ScalarLong(PathOf(kind + ".db"), $"SELECT count(*) FROM transfer_chunk_{kind}"));
        }

        Assert.Equal(1, ScalarLong(PathOf("queue.db"), "SELECT count(*) FROM delivery_queue WHERE transfer_switch_id IS NULL"));
        Assert.Single(await ClaimAsync());
    }

    [Theory]
    [InlineData(3)]
    [InlineData(4)]
    public async Task An_older_database_is_upgraded_with_the_smtp_utf8_column_and_old_rows_read_false(int fromVersion)
    {
        await AcceptAsync(Msg(to: ["a@example.org"]));
        await Storage.DisposeAsync();

        foreach (string kind in new[] { "queue", "stats", "config", "history" })
        {
            using var c = new SqliteConnection($"Data Source={PathOf(kind + ".db")};Pooling=False");
            c.Open();
            using SqliteCommand cmd = c.CreateCommand();
            cmd.CommandText = (kind == "queue" ? "ALTER TABLE delivery_queue DROP COLUMN smtp_utf8;" : "") + "PRAGMA user_version = " + fromVersion;
            cmd.ExecuteNonQuery();
        }

        await ReopenAsync();
        Assert.Equal(5, SqliteFile.SchemaVersion);
        Assert.Equal(5, ScalarLong(PathOf("queue.db"), "PRAGMA user_version"));
        Assert.Equal(1, ScalarLong(PathOf("queue.db"), "SELECT count(*) FROM delivery_queue WHERE smtp_utf8 = 0"));
        var claimed = Assert.Single(await ClaimAsync());
        Assert.False(claimed.SmtpUtf8);
    }

    [Fact]
    public async Task Leases_are_cleared_when_the_storage_starts()
    {
        await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"]));
        Assert.Equal(2, (await ClaimAsync(lease: TimeSpan.FromHours(1))).Count);
        await Storage.Webhooks.ClaimDueAsync("x", 1, Clock.UtcNow, TimeSpan.FromHours(1), default);

        await ReopenAsync();
        Assert.Equal(2, (await ClaimAsync(owner: "after-restart")).Count);
    }

    [Fact]
    public async Task Statistics_are_flushed_on_dispose_and_survive_a_restart()
    {
        await AcceptAsync(Msg(to: ["a@one.example", "b@one.example"]));
        await Storage.DisposeAsync();
        await ReopenAsync();
        var rows = await Storage.Stats.QueryAsync(TenantA, Start.AddHours(-1), Start.AddHours(1), false, default);
        Assert.Equal(2, rows.Single().Accepted);
    }

    [Fact]
    public async Task Data_survives_a_clean_restart_in_every_file()
    {
        var m = await AcceptAsync(Msg(retainRaw: true));
        await Storage.Config.UpsertTenantAsync(new Tenant(Ids.New(), "Acme", "acme", true, Clock.UtcNow, false), default);
        var d = (await ClaimAsync()).Single();
        await Storage.Deliveries.ReleaseOwnedLeasesAsync("worker-1", default);
        await ReopenAsync();

        Assert.Single(await ClaimAsync(owner: "w2"));
        Assert.NotNull(await Storage.Deliveries.GetRawAsync(m.MessageId, default));
        Assert.Single(await Storage.Config.GetTenantsAsync(default));
        Assert.NotNull(await Storage.History.GetAsync(TenantA, m.MessageId, default));
        _ = d;
    }

    [Fact]
    public async Task Sqlite_reports_its_own_backend_and_exposes_writer_metrics()
    {
        Assert.Equal(StorageBackend.Sqlite, Storage.Backend);
        await AcceptAsync();
        Assert.True(Sql.WriterMetrics["queue"].Commands >= 1);
        Assert.Equal(4, Sql.WriterMetrics.Count);
    }
}

internal sealed class CapturingLog : IMtaLog
{
    public List<(MtaLogLevel Level, string Source, string Message)> Entries { get; } = [];

    public bool IsEnabled(MtaLogLevel level) => true;

    public void Write(MtaLogLevel level, string source, string message, Exception? exception = null)
    {
        lock (Entries)
        {
            Entries.Add((level, source, message));
        }
    }
}
