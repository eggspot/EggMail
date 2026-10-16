using Mta.Storage.Tests;
using Mta.Core;

namespace Mta.Storage.Postgres.Tests;

/// <summary>Inbound mail on PostgreSQL: replicas split the pending actions without overlap, the retention delete runs in batches, and everything survives a restart.</summary>
public class InboundPostgresTests : PgTestBase
{
    private async Task<(DomainRecord Domain, Guid Route)> DomainAsync(IStorage storage, string name = "example.com")
    {
        await storage.Config.UpsertTenantAsync(new Tenant(TenantA, "A", "a", true, Clock.UtcNow, false), default);
        var domain = new DomainRecord(Ids.New(), TenantA, name, DomainStatus.Verified, null, false, Clock.UtcNow, null, null, 0, null, false, null);
        await storage.Config.UpsertDomainAsync(domain, default);
        return (domain, Ids.New());
    }

    private InboundMessageDraft Draft(DomainRecord domain, Guid route, InboundActionKind kind, DateTimeOffset at, int size) => new()
    {
        Id = Ids.New(at), TenantId = domain.TenantId, DomainId = domain.Id, Domain = domain.Name, ReceivedAt = at, RemoteAddress = "203.0.113.9", EnvelopeFrom = "a@sender.test",
        EnvelopeTo = "x@" + domain.Name, Auth = InboundAuthResults.NotChecked, RouteId = route, ActionKind = kind, Raw = new byte[size],
    };

    [Fact]
    public async Task Replicas_claim_disjoint_actions_while_both_are_claiming_at_once()
    {
        PostgresStorage second = await OpenReplicaAsync();
        (DomainRecord domain, Guid route) = await DomainAsync(Storage);
        const int total = 60;
        for (int i = 0; i < total; i++)
        {
            await Storage.Inbound.AcceptAsync([Draft(domain, route, InboundActionKind.Webhook, Clock.UtcNow.AddSeconds(-total + i), 100 + i)], default);
        }

        async Task<List<Guid>> Worker(IStorage replica, string owner)
        {
            var mine = new List<Guid>();
            while (true)
            {
                var batch = await replica.Inbound.ClaimActionsAsync(owner, 7, Clock.UtcNow, TimeSpan.FromMinutes(5), default);
                if (batch.Count == 0)
                {
                    return mine;
                }

                mine.AddRange(batch.Select(b => b.Message.Id));
            }
        }

        List<Guid>[] results = await Task.WhenAll(Worker(Storage, "a-1"), Worker(second, "b-1"), Worker(Storage, "a-2"), Worker(second, "b-2"));
        List<Guid> all = [.. results.SelectMany(r => r)];
        Assert.Equal(total, all.Count);
        Assert.Equal(total, all.Distinct().Count());
    }

    [Fact]
    public async Task Retention_deletes_in_batches_until_nothing_old_is_left_and_leaves_other_rows_alone()
    {
        await OpenAsync(WithInbound(Opts(), 1));
        // The harness builds the PostgreSQL options itself; a second storage with a small batch size is the one that runs the job.
        PostgresStorage batched = await OpenReplicaAsync(pg => new PostgresOptions
        {
            RuntimeConnectionString = pg.RuntimeConnectionString,
            MaxPoolSize = pg.MaxPoolSize,
            StatsFlushInterval = pg.StatsFlushInterval,
            RetentionDeletePause = TimeSpan.Zero,
            RetentionDeleteBatchSize = 10,
        });
        (DomainRecord domain, Guid route) = await DomainAsync(batched);
        for (int i = 0; i < 25; i++)
        {
            await batched.Inbound.AcceptAsync([Draft(domain, route, InboundActionKind.Store, Clock.UtcNow.AddDays(-2).AddSeconds(i), 100 + i)], default);
        }

        InboundMessageDraft fresh = Draft(domain, route, InboundActionKind.Store, Clock.UtcNow, 99);
        await batched.Inbound.AcceptAsync([fresh], default);

        MaintenanceReport job = Assert.Single(await batched.Maintenance.RunAsync(Clock.UtcNow, default), r => r.Job == "inbound_retention");
        Assert.Equal(25, job.RowsAffected);
        Assert.Equal([fresh.Id], (await batched.Inbound.SearchAsync(new InboundMessageQuery(TenantId: TenantA), default)).Items.Select(m => m.Id));
        Assert.Equal(1L, await ScalarAsync<long>("SELECT count(*) FROM inbound_message_raw"));
    }

    [Fact]
    public async Task Inbound_data_survives_a_restart_and_a_claimed_action_can_be_claimed_by_another_replica_after_its_lease()
    {
        (DomainRecord domain, Guid route) = await DomainAsync(Storage);
        await Storage.Inbound.UpsertSettingsAsync(new InboundDomainSettings(domain.Id, TenantA, true, InboundDmarcAction.Flag, null, null, null, null, 3, Clock.UtcNow), default);
        await Storage.Inbound.UpsertRouteAsync(new InboundRouteRecord(route, TenantA, domain.Id, "all", 100, true, InboundMatchKind.CatchAll, null, false, InboundActionKind.Webhook, await AddEndpointAsync(TenantA, true, "*"), InboundWebhookFormat.RawMime, [], Clock.UtcNow, Clock.UtcNow), default);
        InboundMessageDraft draft = Draft(domain, route, InboundActionKind.Webhook, Clock.UtcNow, 321);
        await Storage.Inbound.AcceptAsync([draft], default);
        Assert.Single(await Storage.Inbound.ClaimActionsAsync("a", 5, Clock.UtcNow, TimeSpan.FromMinutes(1), default));

        await Storage.DisposeAsync();
        PostgresStorage restarted = PostgresStorage.Create(PgHarness.WithDatabase(Options, Db.ConnectionString), Clock);
        await restarted.InitializeAsync(CancellationToken.None);
        try
        {
            Assert.Equal(3, (await restarted.Inbound.GetSettingsAsync(domain.Id, default))!.RetentionDays);
            Assert.Equal(InboundWebhookFormat.RawMime, Assert.Single(await restarted.Inbound.GetRoutesAsync(domain.Id, default)).WebhookFormat);
            Assert.Equal(321, (await restarted.Inbound.GetRawAsync(TenantA, draft.Id, default))!.Length);

            // Another replica takes the action over once the lease ran out, not before.
            Assert.Empty(await restarted.Inbound.ClaimActionsAsync("b", 5, Clock.UtcNow.AddSeconds(30), TimeSpan.FromMinutes(1), default));
            Assert.Single(await restarted.Inbound.ClaimActionsAsync("b", 5, Clock.UtcNow.AddMinutes(2), TimeSpan.FromMinutes(1), default));
        }
        finally
        {
            await restarted.DisposeAsync();
        }
    }

    [Fact]
    public async Task The_inbound_tables_are_not_partitioned_and_the_claim_index_covers_only_pending_rows()
    {
        foreach (string table in new[] { "inbound_message", "inbound_message_raw", "inbound_route", "inbound_domain_settings" })
        {
            Assert.Equal(0L, await ScalarAsync<long>("SELECT count(*) FROM pg_partitioned_table WHERE partrelid = $1::regclass", table));
        }

        string definition = await ScalarAsync<string>("SELECT indexdef FROM pg_indexes WHERE indexname = 'IX_inbound_message_action_next_attempt_at'");
        Assert.Contains("WHERE (action_state = 0)", definition, StringComparison.Ordinal);
    }

    [Fact]
    public Task Retention_keeps_a_message_that_a_retry_made_pending_between_the_read_and_the_write() =>
        InboundBatchScenarios.Retention_keeps_a_message_that_a_retry_made_pending_between_the_read_and_the_write(Storage, ((PostgresStorage)Storage).Runtime.InboundMessages, Clock);

    [Fact]
    public Task An_erasure_deletes_in_batches_bounded_by_rows_and_bytes_with_a_pause() =>
        InboundBatchScenarios.An_erasure_deletes_in_batches_bounded_by_rows_and_bytes_with_a_pause(Storage, ((PostgresStorage)Storage).Runtime.InboundMessages, Clock);

    [Fact]
    public void Errors_are_classified_a_constraint_a_full_disk_a_retryable_failure()
    {
        static Exception Wrapped(string state) => new Microsoft.EntityFrameworkCore.DbUpdateException("update failed", new Npgsql.PostgresException("failure", "ERROR", "ERROR", state));

        Assert.True(PostgresErrors.IsConstraint(Wrapped("23505")));
        Assert.True(PostgresErrors.IsConstraint(Wrapped("23503")));
        Assert.False(PostgresErrors.IsConstraint(Wrapped("53100")));
        Assert.False(PostgresErrors.IsConstraint(new InvalidOperationException("bug")));

        Assert.True(PostgresErrors.IsDiskFull(Wrapped("53100")));
        Assert.False(PostgresErrors.IsDiskFull(Wrapped("23505")));

        foreach (string state in new[] { "40001", "40P01", "57014" })
        {
            Assert.True(PostgresErrors.IsRetryable(Wrapped(state)));
        }

        Assert.False(PostgresErrors.IsRetryable(Wrapped("23505")));
        Assert.False(PostgresErrors.IsRetryable(Wrapped("42601")));   // bad SQL is a bug, not a moment to wait out
    }
}
