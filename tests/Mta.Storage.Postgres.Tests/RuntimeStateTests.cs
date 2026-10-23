using Mta.Core;
using Npgsql;

namespace Mta.Storage.Postgres.Tests;

/// <summary>The persisted runtime state on PostgreSQL: it survives a restart, replicas add to the same counters, and a version 3 database is upgraded in place.</summary>
public class RuntimeStateTests : PgTestBase
{
    private async Task<PostgresStorage> RestartAsync()
    {
        await Storage.DisposeAsync();
        PostgresStorage restarted = PostgresStorage.Create(PgHarness.WithDatabase(Options, Db.ConnectionString), Clock);
        await restarted.InitializeAsync(CancellationToken.None);
        return restarted;
    }

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

        PostgresStorage restarted = await RestartAsync();
        try
        {
            Assert.Equal("ok", Assert.Single(await restarted.Config.GetDomainRecordChecksAsync(domain, default)).Status);
            Assert.Equal(bucket, Assert.Single(await restarted.Config.GetTlsRptBucketsAsync((int)day, 10, default)));
            Assert.Equal(41, Assert.Single(await restarted.Config.GetSendingCountersAsync(hour, day, default)).Count);
            Assert.Equal(["welcome"], (await restarted.History.GetAsync(TenantA, m.MessageId, default))!.Summary.Tags);
            Assert.Equal(m.MessageId, await restarted.History.AttachReportAsync(TenantA, "<restart@x>", new AsyncReport(MessageEventType.Bounced, Clock.UtcNow, "alice@example.org", 550, "5.1.1", "no"), default));
        }
        finally
        {
            await restarted.DisposeAsync();
        }
    }

    [Fact]
    public async Task Replicas_add_their_counter_deltas_to_the_same_rows_without_losing_any()
    {
        PostgresStorage second = await OpenReplicaAsync();
        long hour = Clock.UtcNow.ToUnixTimeSeconds() / 3600;
        long day = Clock.UtcNow.ToUnixTimeSeconds() / 86400;
        const int rounds = 25;
        async Task Writer(IStorage replica, long perRound)
        {
            for (int i = 0; i < rounds; i++)
            {
                await replica.Config.AddSendingCountersAsync([new SendingCounterRecord(0, Guid.Empty, "", 0, hour, perRound), new SendingCounterRecord(2, Guid.Empty, "example.com", 1, day, 1)], hour - 1, day - 1, default);
            }
        }

        await Task.WhenAll(Writer(Storage, 2), Writer(second, 3), Writer(Storage, 5), Writer(second, 7));

        var counters = await Storage.Config.GetSendingCountersAsync(hour, day, default);
        Assert.Equal(rounds * (2 + 3 + 5 + 7), counters.Single(c => c.Scope == 0).Count);
        Assert.Equal(rounds * 4, counters.Single(c => c.Scope == 2).Count);
    }

    [Fact]
    public async Task A_version_3_database_is_upgraded_in_place_and_keeps_its_messages()
    {
        var old = await AcceptAsync(Msg(to: ["a@example.org"]));
        await Storage.DisposeAsync();

        // Turn the database back into what version 3 created: no runtime state tables, no header or tags column, no headers_utf8 column, no replica coordination tables, no message_id index on the queue, no inbound mail tables, no verp_key table, no sending domain column, no version 4 to 12 row.
        await using (var c = new NpgsqlConnection(Db.ConnectionString))
        {
            await c.OpenAsync();
            await using var cmd = new NpgsqlCommand(
                "DROP TABLE verp_key; DROP TABLE inbound_message_raw; DROP TABLE inbound_message; DROP TABLE inbound_route; DROP TABLE inbound_domain_settings; DROP TABLE domain_record_check; DROP TABLE tls_rpt_bucket; DROP TABLE sending_counter; DROP TABLE replica_heartbeat; DROP TABLE replica_signal; DROP TABLE auth_failure; " +
                "DROP INDEX \"IX_message_index_tenant_id_message_id_header\"; ALTER TABLE message_index DROP COLUMN message_id_header; ALTER TABLE message_index DROP COLUMN tags; ALTER TABLE message_index DROP COLUMN sending_domain_id; " +
                "ALTER TABLE delivery_queue DROP COLUMN headers_utf8; DROP INDEX \"IX_delivery_queue_message_id\"; DROP INDEX \"IX_delivery_queue_tenant_id_sending_domain\"; DELETE FROM eggmail_schema_version WHERE version IN (4, 5, 6, 7, 8, 9, 10, 11, 12)", c);
            await cmd.ExecuteNonQueryAsync();
        }

        Assert.Equal(3, await PostgresMigrator.GetDatabaseVersionAsync(NpgsqlDataSource.Create(Db.ConnectionString), default));
        PostgresStorage upgraded = PostgresStorage.Create(PgHarness.WithDatabase(Options, Db.ConnectionString), Clock);
        await upgraded.InitializeAsync(CancellationToken.None);
        try
        {
            Assert.Equal(12, PostgresMigrator.CurrentVersion);
            Assert.Empty(await upgraded.Config.GetVerpKeysAsync(default));   // the version 11 table exists
            Assert.Empty(await upgraded.Inbound.LoadEnabledDomainsAsync(default));   // the version 8 tables exist
            Assert.Equal(["a"], await upgraded.Replicas!.HeartbeatAsync("a", TimeSpan.FromSeconds(20), default));   // the version 6 tables exist
            Assert.NotNull(await upgraded.History.GetAsync(TenantA, old.MessageId, default));
            Assert.Null((await upgraded.History.GetAsync(TenantA, old.MessageId, default))!.Summary.Tags);
            var fresh = Msg(messageIdHeader: "<after@x>", tags: ["t"]);
            await upgraded.Intake.AcceptAsync(fresh, default);
            Assert.Equal(fresh.MessageId, await upgraded.History.AttachReportAsync(TenantA, "<after@x>", new AsyncReport(MessageEventType.Complained, Clock.UtcNow, null, null, null, "abuse"), default));
            await upgraded.Config.AddSendingCountersAsync([new SendingCounterRecord(0, Guid.Empty, "", 0, 1, 1)], 0, 0, default);
            await using var check = new NpgsqlConnection(Db.ConnectionString);
            await check.OpenAsync();
            await using var count = new NpgsqlCommand("SELECT count(*) FROM pg_indexes WHERE indexname = 'IX_delivery_queue_message_id'", check);
            Assert.Equal(1L, await count.ExecuteScalarAsync());   // version 7
            await using var claimIndex = new NpgsqlCommand("SELECT count(*) FROM pg_indexes WHERE indexname = 'IX_inbound_message_tenant_id_action_next_attempt_at_id'", check);
            Assert.Equal(1L, await claimIndex.ExecuteScalarAsync());   // version 9
            await using var forwardIndex = new NpgsqlCommand("SELECT count(*) FROM pg_indexes WHERE indexname = 'IX_delivery_queue_tenant_id_sending_domain'", check);
            Assert.Equal(1L, await forwardIndex.ExecuteScalarAsync());   // version 10
            await using var sendingDomainColumn = new NpgsqlCommand("SELECT count(*) FROM information_schema.columns WHERE table_name = 'message_index' AND column_name = 'sending_domain_id'", check);
            Assert.Equal(1L, await sendingDomainColumn.ExecuteScalarAsync());
        }
        finally
        {
            await upgraded.DisposeAsync();
        }
    }
}
