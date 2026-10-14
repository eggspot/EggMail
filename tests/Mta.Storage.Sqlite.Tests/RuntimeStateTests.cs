using Microsoft.Data.Sqlite;
using Mta.Core;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>The persisted runtime state on SQLite: it survives a restart (the files are reopened), and a version 3 database is upgraded in place.</summary>
public class RuntimeStateTests : SqliteTestBase
{
    [Fact]
    public async Task Check_results_tls_rpt_buckets_counters_tags_and_message_ids_survive_a_restart()
    {
        long hour = Clock.UtcNow.ToUnixTimeSeconds() / 3600;
        long day = Clock.UtcNow.ToUnixTimeSeconds() / 86400;
        Guid domain = Ids.New();
        var bucket = new TlsRptBucketRecord(Ids.New(), (int)day - 1, "mail.example", "{\"policies\":[]}", 2, Clock.UtcNow);
        var m = await AcceptAsync(Msg(messageIdHeader: "<restart@x>", tags: ["welcome"]));
        await Storage.Config.ReplaceDomainRecordChecksAsync(domain, [new DomainRecordCheckRecord(domain, "TXT|example.com", "ok", "v=spf1 -all", Clock.UtcNow)], default);
        await Storage.Config.AddTlsRptBucketsAsync([bucket], default);
        await Storage.Config.AddSendingCountersAsync([new SendingCounterRecord(1, TenantA, "", 0, hour, 41)], hour - 1, day - 1, default);

        await ReopenAsync();

        Assert.Equal("ok", Assert.Single(await Storage.Config.GetDomainRecordChecksAsync(domain, default)).Status);
        Assert.Equal(bucket, Assert.Single(await Storage.Config.GetTlsRptBucketsAsync((int)day, 10, default)));
        Assert.Equal(41, Assert.Single(await Storage.Config.GetSendingCountersAsync(hour, day, default)).Count);
        Assert.Equal(["welcome"], (await Storage.History.GetAsync(TenantA, m.MessageId, default))!.Summary.Tags);
        Assert.Equal(m.MessageId, await Storage.History.AttachReportAsync(TenantA, "<restart@x>", new AsyncReport(MessageEventType.Bounced, Clock.UtcNow, "alice@example.org", 550, "5.1.1", "no"), default));
    }

    [Fact]
    public async Task The_runtime_state_is_written_with_the_config_files_full_synchronous_mode()
    {
        // config.db is the durable file (Sqlite:ConfigSyncMode, default Full): the state is small and written in batches, so it can afford the fsync.
        await ReopenAsync(b => b.SyncMode = SqliteSyncMode.Off);
        await Storage.Config.AddSendingCountersAsync([new SendingCounterRecord(0, Guid.Empty, "", 0, 5, 1)], 0, 0, default);
        Assert.Equal(2, await WriterScalarAsync("config", "PRAGMA synchronous")); // 2 = FULL
    }

    [Fact]
    public async Task A_version_3_database_is_upgraded_in_place_and_keeps_its_messages()
    {
        var old = await AcceptAsync(Msg(to: ["a@example.org"]));
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

        // Turn the files back into what version 3 created.
        Run("config.db", "DROP TABLE domain_record_check", "DROP TABLE tls_rpt_bucket", "DROP TABLE sending_counter", "PRAGMA user_version = 3");
        Run("history.db", "DROP INDEX IX_message_index_tenant_id_message_id_header", "ALTER TABLE message_index DROP COLUMN message_id_header", "ALTER TABLE message_index DROP COLUMN tags", "PRAGMA user_version = 3");
        Run("queue.db", "ALTER TABLE delivery_queue DROP COLUMN headers_utf8", "PRAGMA user_version = 3");
        Run("stats.db", "PRAGMA user_version = 3");

        await ReopenAsync();

        foreach (string file in new[] { "config.db", "history.db", "queue.db", "stats.db" })
        {
            Assert.Equal(SqliteFile.SchemaVersion, ScalarLong(PathOf(file), "PRAGMA user_version"));
        }

        Assert.Equal(0, ScalarLong(PathOf("config.db"), "SELECT count(*) FROM sending_counter"));
        Assert.Equal(1, ScalarLong(PathOf("history.db"), "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'IX_message_index_tenant_id_message_id_header'"));
        Assert.NotNull(await Storage.History.GetAsync(TenantA, old.MessageId, default));
        Assert.Null((await Storage.History.GetAsync(TenantA, old.MessageId, default))!.Summary.Tags);

        var fresh = Msg(messageIdHeader: "<after@x>", tags: ["t"]);
        await Storage.Intake.AcceptAsync(fresh, default);
        Assert.Equal(["t"], (await Storage.History.GetAsync(TenantA, fresh.MessageId, default))!.Summary.Tags);
        Assert.Equal(fresh.MessageId, await Storage.History.AttachReportAsync(TenantA, "<after@x>", new AsyncReport(MessageEventType.Complained, Clock.UtcNow, null, null, null, "abuse"), default));
        await Storage.Config.AddSendingCountersAsync([new SendingCounterRecord(0, Guid.Empty, "", 0, 1, 1)], 0, 0, default);
    }
}
