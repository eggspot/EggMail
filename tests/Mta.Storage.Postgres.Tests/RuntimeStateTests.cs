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

        // Turn the database back into what version 3 created: no runtime state tables, no header or tags column, no version 4 row.
        await using (var c = new NpgsqlConnection(Db.ConnectionString))
        {
            await c.OpenAsync();
            await using var cmd = new NpgsqlCommand(
                "DROP TABLE domain_record_check; DROP TABLE tls_rpt_bucket; DROP TABLE sending_counter; " +
                "DROP INDEX \"IX_message_index_tenant_id_message_id_header\"; ALTER TABLE message_index DROP COLUMN message_id_header; ALTER TABLE message_index DROP COLUMN tags; " +
                "DELETE FROM eggmail_schema_version WHERE version = 4", c);
            await cmd.ExecuteNonQueryAsync();
        }

        Assert.Equal(3, await PostgresMigrator.GetDatabaseVersionAsync(NpgsqlDataSource.Create(Db.ConnectionString), default));
        PostgresStorage upgraded = PostgresStorage.Create(PgHarness.WithDatabase(Options, Db.ConnectionString), Clock);
        await upgraded.InitializeAsync(CancellationToken.None);
        try
        {
            Assert.Equal(4, PostgresMigrator.CurrentVersion);
            Assert.NotNull(await upgraded.History.GetAsync(TenantA, old.MessageId, default));
            Assert.Null((await upgraded.History.GetAsync(TenantA, old.MessageId, default))!.Summary.Tags);
            var fresh = Msg(messageIdHeader: "<after@x>", tags: ["t"]);
            await upgraded.Intake.AcceptAsync(fresh, default);
            Assert.Equal(fresh.MessageId, await upgraded.History.AttachReportAsync(TenantA, "<after@x>", new AsyncReport(MessageEventType.Complained, Clock.UtcNow, null, null, null, "abuse"), default));
            await upgraded.Config.AddSendingCountersAsync([new SendingCounterRecord(0, Guid.Empty, "", 0, 1, 1)], 0, 0, default);
        }
        finally
        {
            await upgraded.DisposeAsync();
        }
    }
}
