using Microsoft.Data.Sqlite;
using Mta.Core;

namespace Mta.Storage.Sqlite.Tests;

public class MaintenanceAndBackupTests : SqliteTestBase
{
    protected override StorageOptions BuildOptions() => new()
    {
        Content = new ContentOptions { RetentionDays = 6 },
        Retention = new RetentionOptions { MetadataDays = 20 },
    };

    private static MessageContent Big(int chars) => new("subject", new string('x', chars), "<p>" + new string('y', chars) + "</p>", [], false);

    [Fact]
    public async Task Retention_deletes_in_small_batches_and_incremental_vacuum_returns_the_space()
    {
        await ReopenAsync(b => b.RetentionDeleteBatchSize = 25, retention: new RetentionOptions { MetadataDays = 20 }, content: new ContentOptions { RetentionDays = 6, MaxStoredBodyBytes = 1 << 20 });
        for (int i = 0; i < 150; i++)
        {
            await AcceptAsync(Msg(to: [$"r{i}@example.org"], content: Big(20_000)));
        }

        await Storage.Maintenance.RunAsync(Clock.UtcNow, default); // checkpoint so the file size reflects the data
        long before = new FileInfo(PathOf("history.db")).Length;
        Assert.True(before > 4_000_000, $"history.db was only {before} bytes");
        long commandsBefore = Sql.WriterMetrics["history"].Commands;

        Clock.Advance(TimeSpan.FromDays(40));
        var reports = await Storage.Maintenance.RunAsync(Clock.UtcNow, default);

        Assert.True(reports.Single(r => r.Job == "retention.metadata").RowsAffected >= 150 * 3);
        Assert.True(reports.Single(r => r.Job == "retention.content").RowsAffected >= 150);
        Assert.True(Sql.WriterMetrics["history"].Commands - commandsBefore >= 6, "the deletes must run as several short transactions");
        Assert.True(reports.Single(r => r.Job == "vacuum.incremental").RowsAffected > 0);

        string path = PathOf("history.db");
        Assert.Equal(0, ScalarLong(path, "SELECT count(*) FROM message_index") + ScalarLong(path, "SELECT count(*) FROM message_event") + ScalarLong(path, "SELECT count(*) FROM message_content"));
        Assert.Equal(0, ScalarLong(path, "PRAGMA freelist_count"));
        long after = new FileInfo(path).Length;
        Assert.True(after < before / 4, $"history.db shrank from {before} to {after} bytes");
    }

    [Fact]
    public async Task The_wal_is_truncated_when_the_store_is_idle()
    {
        for (int i = 0; i < 50; i++)
        {
            await AcceptAsync(Msg(size: 8192));
        }

        Assert.True(new FileInfo(PathOf("queue.db-wal")).Length > 0);
        await Storage.Maintenance.RunAsync(Clock.UtcNow, default);
        Assert.Equal(0, new FileInfo(PathOf("queue.db-wal")).Length);
        Assert.Equal(0, Sql.WriterMetrics["queue"].QueueDepth);
        Assert.Equal(50, (await Storage.Deliveries.GetQueueStatsAsync(default)).Queued);
    }

    [Fact]
    public async Task Expired_idempotency_keys_are_purged()
    {
        await AcceptAsync(Msg(idempotencyKey: "a"));
        await AcceptAsync(Msg(idempotencyKey: "b"));
        Clock.Advance(TimeSpan.FromHours(23));
        await AcceptAsync(Msg(idempotencyKey: "c"));
        Assert.Equal(3, ScalarLong(PathOf("queue.db"), "SELECT count(*) FROM api_idempotency_key"));

        Clock.Advance(TimeSpan.FromHours(2));
        var reports = await Storage.Maintenance.RunAsync(Clock.UtcNow, default);
        Assert.Equal(2, reports.Single(r => r.Job == "idempotency.expired").RowsAffected);
        Assert.Equal(1, ScalarLong(PathOf("queue.db"), "SELECT count(*) FROM api_idempotency_key"));
    }

    [Fact]
    public async Task Reconcile_finishes_an_interrupted_retained_raw_hand_over()
    {
        var m = await AcceptAsync(Msg(retainRaw: true, size: 3000));
        var d = (await ClaimAsync()).Single();

        // Simulate the crash window: the queue transaction committed (delivery gone, spool marked awaiting retention) and the
        // process died before the raw message reached history.db.
        await Sql.Runtime.QueueWriter.SubmitAsync(d.DeliveryId, static (ctx, id) =>
        {
            ctx.Command(QueueSql.DeliveryDelete).Set(0, id).ExecuteNonQuery();
            return ctx.Command(new Stmt("UPDATE message_spool SET pending_recipients = 0, awaiting_retention = 1")).ExecuteNonQuery();
        });
        Assert.NotNull(await Storage.Deliveries.GetRawAsync(m.MessageId, default));
        Assert.Null(await Storage.History.GetRetainedRawAsync(TenantA, m.MessageId, default));

        // Restart: reconcile runs at startup and from maintenance.
        await ReopenAsync();
        var raw = await Storage.History.GetRetainedRawAsync(TenantA, m.MessageId, default);
        Assert.NotNull(raw);
        Assert.True(m.Raw.Span.SequenceEqual(raw));
        Assert.Null(await Storage.Deliveries.GetRawAsync(m.MessageId, default));
    }

    [Fact]
    public async Task Reconcile_removes_a_duplicate_left_when_the_crash_came_after_the_history_write()
    {
        var m = await AcceptAsync(Msg(retainRaw: true, size: 3000));
        var d = (await ClaimAsync()).Single();
        await Sql.Runtime.QueueWriter.SubmitAsync(d.DeliveryId, static (ctx, id) =>
        {
            ctx.Command(QueueSql.DeliveryDelete).Set(0, id).ExecuteNonQuery();
            return ctx.Command(new Stmt("UPDATE message_spool SET pending_recipients = 0, awaiting_retention = 1")).ExecuteNonQuery();
        });
        await Sql.Runtime.HistoryWriter!.SubmitAsync((m.MessageId, m.Raw.ToArray()), static (ctx, s) =>
            ctx.Command(HistorySql.RetainedInsert).Set(0, StorageTime(s.MessageId)).Set(1, s.MessageId).Set(2, TenantA).Set(3, s.Item2).Set(4, 0L).ExecuteNonQuery());

        var reports = await Storage.Maintenance.RunAsync(Clock.UtcNow, default);
        Assert.Equal(1, reports.Single(r => r.Job == "queue.reconcile").RowsAffected);
        Assert.Null(await Storage.Deliveries.GetRawAsync(m.MessageId, default));
        Assert.Equal(1, ScalarLong(PathOf("history.db"), "SELECT count(*) FROM message_raw_retained"));
    }

    private static int StorageTime(Guid id) => Mta.Storage.Logic.StorageTime.DayNumber(id);

    [Fact]
    public async Task Backup_with_vacuum_into_restores_every_file()
    {
        var m = await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"]));
        var tenant = new Tenant(Ids.New(), "Acme", "acme", true, Clock.UtcNow, false);
        await Storage.Config.UpsertTenantAsync(tenant, default);
        await AddEndpointAsync(TenantA, true, "*");
        await FlushStatsAsync();

        string backupRoot = Path.Combine(Dir, "backups");
        string? backup = await Storage.Maintenance.BackupAsync(backupRoot, default);
        Assert.NotNull(backup);
        Assert.Equal(["config.db", "history.db", "queue.db", "stats.db"], Directory.GetFiles(backup).Select(Path.GetFileName).OfType<string>().Order(StringComparer.Ordinal));

        string restoreDir = SqliteTestStorage.NewDirectory();
        try
        {
            foreach (string f in Directory.GetFiles(backup))
            {
                File.Copy(f, Path.Combine(restoreDir, Path.GetFileName(f)));
            }

            await using var restored = SqliteStorage.Create(SqliteTestStorage.WithDirectory(Options, restoreDir), Clock);
            await restored.InitializeAsync(default);
            Assert.Empty(restored.QuarantineEvents);
            Assert.Equal(2, (await restored.Deliveries.ClaimAsync("w", 10, Clock.UtcNow, TimeSpan.FromMinutes(1), default)).Count);
            Assert.NotNull(await restored.Deliveries.GetRawAsync(m.MessageId, default));
            Assert.Equal("acme", (await restored.Config.GetTenantBySlugAsync("acme", default))!.Slug);
            Assert.Single(await restored.Config.GetWebhookEndpointsAsync(TenantA, default));
            Assert.NotNull(await restored.History.GetAsync(TenantA, m.MessageId, default));
            Assert.Equal(2, (await restored.Stats.QueryAsync(TenantA, Start.AddHours(-1), Start.AddHours(1), false, default)).Sum(r => r.Accepted));
        }
        finally
        {
            SqliteTestStorage.TryDelete(restoreDir);
        }
    }

    [Fact]
    public async Task A_backup_taken_while_writing_is_a_consistent_snapshot()
    {
        for (int i = 0; i < 30; i++)
        {
            await AcceptAsync(Msg(size: 2048));
        }

        using var cts = new CancellationTokenSource();
        Task writers = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                await Storage.Intake.AcceptAsync(Msg(size: 2048), default);
            }
        });
        string? backup;
        try
        {
            backup = await Storage.Maintenance.BackupAsync(Path.Combine(Dir, "backups"), default);
        }
        finally
        {
            cts.Cancel();
            await writers;
        }

        foreach (string f in Directory.GetFiles(backup!))
        {
            using var c = new SqliteConnection($"Data Source={f};Mode=ReadOnly;Pooling=False");
            c.Open();
            using SqliteCommand cmd = c.CreateCommand();
            cmd.CommandText = "PRAGMA integrity_check";
            Assert.Equal("ok", (string)cmd.ExecuteScalar()!);
        }

        Assert.True(ScalarLong(Path.Combine(backup!, "queue.db"), "SELECT count(*) FROM delivery_queue") >= 30);
    }

    [Fact]
    public async Task Memory_queue_is_not_part_of_a_backup()
    {
        await ReopenAsync(b => b.QueuePersistence = QueuePersistence.Memory);
        string? backup = await Storage.Maintenance.BackupAsync(Path.Combine(Dir, "backups"), default);
        Assert.False(File.Exists(Path.Combine(backup!, "queue.db")));
        Assert.True(File.Exists(Path.Combine(backup!, "config.db")));
    }
}
