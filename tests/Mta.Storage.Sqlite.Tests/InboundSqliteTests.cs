using Mta.Storage.Tests;
using Microsoft.Data.Sqlite;
using Mta.Core;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>Inbound mail on SQLite: the stored mail and its leases across restarts, the in-place upgrade from schema version 7, batched retention and concurrent claims.</summary>
public class InboundSqliteTests : SqliteTestBase
{
    private async Task<(DomainRecord Domain, Guid Route)> DomainAsync(string name = "example.com")
    {
        await Storage.Config.UpsertTenantAsync(new Tenant(TenantA, "A", "a", true, Clock.UtcNow, false), default);
        var domain = new DomainRecord(Ids.New(), TenantA, name, DomainStatus.Verified, null, false, Clock.UtcNow, null, null, 0, null, false, null);
        await Storage.Config.UpsertDomainAsync(domain, default);
        return (domain, Ids.New());
    }

    private static InboundMessageDraft Draft(DomainRecord domain, Guid route, InboundActionKind kind, DateTimeOffset at, int size) => new()
    {
        Id = Ids.New(at), TenantId = domain.TenantId, DomainId = domain.Id, Domain = domain.Name, ReceivedAt = at, RemoteAddress = "203.0.113.9", EnvelopeFrom = "a@sender.test",
        EnvelopeTo = "x@" + domain.Name, Auth = InboundAuthResults.NotChecked, RouteId = route, ActionKind = kind, Raw = new byte[size],
    };

    [Fact]
    public async Task Inbound_data_survives_a_restart_and_the_leases_of_the_old_process_are_cleared()
    {
        (DomainRecord domain, Guid route) = await DomainAsync();
        await Storage.Inbound.UpsertSettingsAsync(new InboundDomainSettings(domain.Id, TenantA, true, InboundDmarcAction.Reject, 1_000_000, 5, 2, null, 3, Clock.UtcNow), default);
        await Storage.Inbound.UpsertRouteAsync(new InboundRouteRecord(route, TenantA, domain.Id, "all", 100, true, InboundMatchKind.CatchAll, null, false, InboundActionKind.Forward, null, InboundWebhookFormat.Json, ["f@example.org"], Clock.UtcNow, Clock.UtcNow), default);
        InboundMessageDraft pending = Draft(domain, route, InboundActionKind.Forward, Clock.UtcNow, 321);
        InboundMessageDraft kept = Draft(domain, route, InboundActionKind.Store, Clock.UtcNow, 123);
        await Storage.Inbound.AcceptAsync([pending, kept], default);
        Assert.Single(await Storage.Inbound.ClaimActionsAsync("old-process", 5, Clock.UtcNow, TimeSpan.FromHours(1), default));

        await ReopenAsync();

        Assert.Equal(InboundDmarcAction.Reject, (await Storage.Inbound.GetSettingsAsync(domain.Id, default))!.DmarcAction);
        Assert.Equal(["f@example.org"], Assert.Single(await Storage.Inbound.GetRoutesAsync(domain.Id, default)).ForwardTo);
        Assert.Equal(123, (await Storage.Inbound.GetRawAsync(TenantA, kept.Id, default))!.Length);
        // Nothing can still be in flight in a single-process backend: the claim of the dead process is cleared, as for deliveries.
        var again = Assert.Single(await Storage.Inbound.ClaimActionsAsync("new-process", 5, Clock.UtcNow, TimeSpan.FromMinutes(1), default));
        Assert.Equal(pending.Id, again.Message.Id);
    }

    [Fact]
    public async Task A_version_7_database_is_upgraded_with_the_inbound_tables_and_keeps_its_messages()
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

        // Turn the files back into what version 7 created: none of the four inbound tables.
        Run("config.db", "DROP TABLE inbound_route", "DROP TABLE inbound_domain_settings", "PRAGMA user_version = 7");
        Run("queue.db", "DROP TABLE inbound_message_raw", "DROP TABLE inbound_message", "PRAGMA user_version = 7");
        Run("stats.db", "PRAGMA user_version = 7");
        Run("history.db", "PRAGMA user_version = 7");

        await ReopenAsync();

        foreach (string file in new[] { "config.db", "history.db", "queue.db", "stats.db" })
        {
            Assert.Equal(SqliteFile.SchemaVersion, ScalarLong(PathOf(file), "PRAGMA user_version"));
        }

        Assert.Equal(1, ScalarLong(PathOf("queue.db"), "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'IX_inbound_message_action_next_attempt_at'"));
        Assert.Equal(1, ScalarLong(PathOf("config.db"), "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'IX_inbound_route_domain_id_sort_order_id'"));
        Assert.NotNull(await Storage.History.GetAsync(TenantA, old.MessageId, default));
        Assert.Single(await ClaimAsync());

        (DomainRecord domain, Guid route) = await DomainAsync();
        InboundMessageDraft draft = Draft(domain, route, InboundActionKind.Store, Clock.UtcNow, 50);
        await Storage.Inbound.AcceptAsync([draft], default);
        Assert.NotNull(await Storage.Inbound.GetAsync(TenantA, draft.Id, default));
    }

    [Fact]
    public async Task Retention_deletes_in_batches_until_nothing_old_is_left()
    {
        await ReopenAsync(b => b.RetentionDeleteBatchSize = 10);
        (DomainRecord domain, Guid route) = await DomainAsync();
        for (int i = 0; i < 25; i++)
        {
            await Storage.Inbound.AcceptAsync([Draft(domain, route, InboundActionKind.Store, Clock.UtcNow.AddDays(-9).AddSeconds(i), 100 + i)], default);
        }

        InboundMessageDraft fresh = Draft(domain, route, InboundActionKind.Store, Clock.UtcNow, 99);
        await Storage.Inbound.AcceptAsync([fresh], default);

        MaintenanceReport job = Assert.Single(await Storage.Maintenance.RunAsync(Clock.UtcNow, default), r => r.Job == "inbound_retention");
        Assert.Equal(25, job.RowsAffected);
        Assert.Equal([fresh.Id], (await Storage.Inbound.SearchAsync(new InboundMessageQuery(TenantId: TenantA), default)).Items.Select(m => m.Id));
        Assert.Equal(1, ScalarLong(PathOf("queue.db"), "SELECT count(*) FROM inbound_message_raw"));
    }

    [Fact]
    public async Task Concurrent_workers_never_claim_the_same_action()
    {
        (DomainRecord domain, Guid route) = await DomainAsync();
        const int total = 60;
        for (int i = 0; i < total; i++)
        {
            await Storage.Inbound.AcceptAsync([Draft(domain, route, InboundActionKind.Webhook, Clock.UtcNow.AddSeconds(-total + i), 100 + i)], default);
        }

        async Task<List<Guid>> Worker(string owner)
        {
            var mine = new List<Guid>();
            while (true)
            {
                var batch = await Storage.Inbound.ClaimActionsAsync(owner, 7, Clock.UtcNow, TimeSpan.FromMinutes(5), default);
                if (batch.Count == 0)
                {
                    return mine;
                }

                mine.AddRange(batch.Select(b => b.Message.Id));
            }
        }

        List<Guid>[] results = await Task.WhenAll(Worker("w1"), Worker("w2"), Worker("w3"), Worker("w4"));
        List<Guid> all = [.. results.SelectMany(r => r)];
        Assert.Equal(total, all.Count);
        Assert.Equal(total, all.Distinct().Count());
    }

    [Fact]
    public async Task Mail_received_in_one_transaction_joins_the_group_commit_with_the_queue()
    {
        (DomainRecord domain, Guid route) = await DomainAsync();
        long before = Sql.WriterMetrics["queue"].Commands;
        await Storage.Inbound.AcceptAsync([Draft(domain, route, InboundActionKind.Store, Clock.UtcNow, 50), Draft(domain, route, InboundActionKind.Store, Clock.UtcNow, 51)], default);

        // Both recipients are one writer command, so one atomic step.
        Assert.Equal(before + 1, Sql.WriterMetrics["queue"].Commands);
        Assert.Equal(2, ScalarLong(PathOf("queue.db"), "SELECT count(*) FROM inbound_message"));
    }

    [Fact]
    public async Task A_full_disk_fails_an_inbound_write_as_storage_full_and_keeps_what_was_stored()
    {
        (DomainRecord domain, Guid route) = await DomainAsync();
        await Storage.Inbound.AcceptAsync([Draft(domain, route, InboundActionKind.Store, Clock.UtcNow, 1024)], default);
        await ReopenAsync();   // closes the files so that the page count below includes everything
        string queue = PathOf("queue.db");
        SqliteFile.PageLimitsForTests[queue] = (int)ScalarLong(queue, "PRAGMA page_count") + 8;
        try
        {
            await ReopenAsync();   // the writer connection of the reopened file carries the limit

            int accepted = 0;
            StorageFullException? full = null;
            for (int i = 0; i < 100 && full is null; i++)
            {
                try
                {
                    await Storage.Inbound.AcceptAsync([Draft(domain, route, InboundActionKind.Store, Clock.UtcNow.AddMilliseconds(i + 1), 65536)], default);
                    accepted++;
                }
                catch (StorageFullException ex)
                {
                    full = ex;   // not a StorageConflictException: a full disk is the operator's problem and the sender retries (452 4.3.1)
                }
            }

            Assert.NotNull(full);
            Assert.True(accepted < 100, "the cap must bite");
            Assert.Equal(1 + accepted, (await Storage.Inbound.GetUsageAsync(TenantA, null, default)).Messages);
        }
        finally
        {
            SqliteFile.PageLimitsForTests.TryRemove(queue, out _);
        }
    }

    [Fact]
    public async Task The_retention_pass_for_the_server_default_has_an_index_on_settled_messages()
    {
        Assert.Equal(1, ScalarLong(PathOf("queue.db"), "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'IX_inbound_message_received_at' AND sql LIKE '%action_state%<>%'"));
    }

    [Fact]
    public Task Retention_keeps_a_message_that_a_retry_made_pending_between_the_read_and_the_write() =>
        InboundBatchScenarios.Retention_keeps_a_message_that_a_retry_made_pending_between_the_read_and_the_write(Storage, Sql.Runtime.InboundMessages, Clock);

    [Fact]
    public Task An_erasure_deletes_in_batches_bounded_by_rows_and_bytes_with_a_pause() =>
        InboundBatchScenarios.An_erasure_deletes_in_batches_bounded_by_rows_and_bytes_with_a_pause(Storage, Sql.Runtime.InboundMessages, Clock);

    [Fact]
    public void Only_a_constraint_is_a_conflict_and_a_full_or_busy_database_is_unavailable()
    {
        static SqliteException Failure(int code) => new("failure", code);
        static Exception Wrapped(int code) => new Microsoft.EntityFrameworkCore.DbUpdateException("update failed", Failure(code));

        Assert.True(SqliteInboundAccess.IsConstraint(Wrapped(19)));
        Assert.True(SqliteInboundAccess.IsConstraint(Wrapped(19 | (5 << 8))));   // SQLITE_CONSTRAINT_UNIQUE
        Assert.False(SqliteInboundAccess.IsConstraint(Wrapped(13)));
        Assert.False(SqliteInboundAccess.IsConstraint(new InvalidOperationException("bug")));

        Assert.IsType<StorageFullException>(SqliteInboundAccess.Translate(Wrapped(13)));
        Assert.IsType<StorageFullException>(SqliteInboundAccess.Translate(Wrapped(13 | (3 << 8))));
        foreach (int code in new[] { 5, 6, 8, 10, 11, 14 })   // busy, locked, readonly, I/O error, corrupt, cannot open
        {
            Exception? translated = SqliteInboundAccess.Translate(Wrapped(code));
            Assert.NotNull(translated);
            Assert.IsNotType<StorageFullException>(translated);
            Assert.IsAssignableFrom<StorageUnavailableException>(translated);
        }

        Assert.Null(SqliteInboundAccess.Translate(Wrapped(19)));
        Assert.Null(SqliteInboundAccess.Translate(new InvalidOperationException("bug")));
    }

    [Fact]
    public Task An_erasure_walks_the_ids_not_the_receive_times() =>
        InboundBatchScenarios.An_erasure_walks_the_ids_not_the_receive_times(Storage, Sql.Runtime.InboundMessages, Clock);
}
