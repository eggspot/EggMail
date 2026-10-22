using System.Security.Cryptography;
using System.Text;
using Mta.Core;
using Mta.Storage.Transfer;

namespace Mta.Storage.Tests;

/// <summary>
/// The backend switch contract of a store (design §4.6): streaming export of every table, idempotent chunked import, the
/// fence and transfer marks, and the target's activation hold. Every backend plugs in here.
/// </summary>
public abstract class TransferConformance : StorageTestBase
{
    private static readonly Guid SwitchId = Guid.Parse("01900000-0000-7000-8000-0000000000aa");

    private IStorageTransfer Transfer => Storage.Transfer ?? throw new InvalidOperationException("The backend does not implement IStorageTransfer.");

    private async Task<List<object>> ReadAllAsync(TransferTable table, TransferRange? range = null)
    {
        var rows = new List<object>();
        await foreach (object row in Transfer.ReadAsync(table, range ?? TransferRange.All, CancellationToken.None))
        {
            rows.Add(row);
        }

        return rows;
    }

    private async Task<Dictionary<string, List<string>>> SnapshotAsync()
    {
        var result = new Dictionary<string, List<string>>();
        foreach (TransferTable table in TransferTables.All.Where(t => Transfer.HasPart(t.Part)))
        {
            result[table.Name] = (await ReadAllAsync(table)).Select(table.Canonical).ToList();
        }

        return result;
    }

    /// <summary>Fills every part with rows through the public APIs, so the export has something in every table.</summary>
    private async Task PopulateAsync()
    {
        DateTimeOffset now = Clock.UtcNow;
        IConfigStore c = Storage.Config;
        var domainId = Ids.New();
        await c.UpsertTenantAsync(new Tenant(TenantA, "Acme", "acme", true, now, true), default);
        await c.UpsertTenantAsync(new Tenant(TenantB, "Beta", "beta", false, now, false), default);
        await c.UpsertDomainAsync(new DomainRecord(domainId, TenantA, "example.com", DomainStatus.Verified, "bounces.example.com", true, now, now, now.AddHours(1), 0, null, false, null), default);
        await c.AddDkimKeyAsync(new DkimKeyRecord(Ids.New(), domainId, "s1", [9, 8, 7, 6], "PUBLICKEY", now, true, null), default);
        await c.AddVerpKeysAsync([new VerpKeyRecord(1, [3, 1, 4, 1], now, now, null)], default);
        Guid dashboardUser = Ids.New();
        await c.UpsertDashboardUserAsync(new DashboardUser(dashboardUser, "admin", "pbkdf2$hash", DashboardRole.Admin, null, true, now), default);
        await c.AddDashboardSessionAsync(new DashboardSession(SHA256.HashData("session"u8), dashboardUser, "csrf-token", now, now, now.AddHours(8)), default);
        await c.AddApiKeyAsync(new ApiKeyRecord(Ids.New(), TenantA, "ci", "egg_ab", SHA256.HashData("key"u8), "send,read", now, null, null), default);
        await c.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), TenantA, "acme-user", "pbkdf2$hash", true, now), default);
        await c.AddSuppressionAsync(new SuppressionRecord(TenantA, "gone@example.org", SuppressionReason.HardBounce, "550 5.1.1", now, null), default);
        await c.AddSuppressionAsync(new SuppressionRecord(TenantA, "ü@example.org", SuppressionReason.Manual, null, now, null), default);
        await c.SetSettingAsync(new SettingRecord("limits.perMinute", null, "120", now), default);
        await c.SetSettingAsync(new SettingRecord("brand.name", TenantA, "\"Acme\"", now), default);
        await c.UpsertTlsPolicyAsync(new TlsPolicyRecord(Ids.New(), "*.partner.example", TlsLevel.Verify), default);
        await c.UpsertRelayRouteAsync(new RelayRouteRecord(Ids.New(), "relay1", "relay.example.net", 587, "StartTls", "u", [4, 5, 6], 10, true, ["partner.example"]), default);
        await c.UpsertCertificateAsync(new CertificateRecord(Ids.New(), "default", ["mail.example.com"], now.AddDays(-1), now.AddDays(89), "-----BEGIN CERTIFICATE-----", [1, 2, 3], "acme", "AB:CD", true, 0, now), default);
        await c.UpsertAcmeAccountAsync(new AcmeAccountRecord(Ids.New(), "https://acme.example/dir", "ops@example.com", [7, 7, 7], "https://acme.example/acct/1", now), default);
        await c.UpsertAcmeRenewalAsync(new AcmeRenewalRecord("default", "ok", now, now.AddDays(60), 0, null, "{\"pending\":true}", "{\"ari\":1}"), default);
        await c.SetSettingAsync(new SettingRecord(TransferTables.DataProtectionSettingPrefix + "key-1", null, "\"<key/>\"", now), default);
        Guid endpoint = await AddEndpointAsync(TenantA, true, "*");

        // Inbound mail: settings, a webhook and a forward route, a pending webhook action, a stored message and a discarded one.
        await Storage.Inbound.UpsertSettingsAsync(new InboundDomainSettings(domainId, TenantA, true, InboundDmarcAction.Flag, 5_000_000, 100, 10, 1L << 30, 30, now), default);
        Guid hookRoute = Ids.New();
        await Storage.Inbound.UpsertRouteAsync(new InboundRouteRecord(hookRoute, TenantA, domainId, "hook", 10, true, InboundMatchKind.Wildcard, "billing-*", true, InboundActionKind.Webhook, endpoint, InboundWebhookFormat.RawMime, [], now, now), default);
        await Storage.Inbound.UpsertRouteAsync(new InboundRouteRecord(Ids.New(), TenantA, domainId, "fwd", 20, true, InboundMatchKind.CatchAll, null, false, InboundActionKind.Forward, null, InboundWebhookFormat.Json, ["f@example.org"], now, now), default);
        InboundMessageDraft Inbound(InboundActionKind kind, int size) => new()
        {
            Id = Ids.New(now), TenantId = TenantA, DomainId = domainId, Domain = "example.com", ReceivedAt = now, RemoteAddress = "203.0.113.9", Helo = "mail.sender.test", TlsUsed = true, EnvelopeFrom = "a@sender.test",
            EnvelopeTo = "billing-eu@example.com", Subject = "Invoice", Auth = new InboundAuthResults(InboundVerdict.Pass, "sender.test", InboundVerdict.None, InboundVerdict.Fail, "sender.test", InboundVerdict.Fail, "reject", InboundVerdict.None),
            Disposition = InboundDmarcDisposition.Flagged, RouteId = hookRoute, ActionKind = kind, Raw = new byte[size],
        };
        await Storage.Inbound.AcceptAsync([Inbound(InboundActionKind.Webhook, 300), Inbound(InboundActionKind.Store, 400), Inbound(InboundActionKind.Discard, 500)], default);

        AcceptedMessage withFingerprint = Msg(to: ["a@example.org", "b@example.net"], idempotencyKey: "idem-1", retainRaw: true);
        await AcceptAsync(new AcceptedMessage
        {
            MessageId = withFingerprint.MessageId, TenantId = withFingerprint.TenantId, Source = withFingerprint.Source, EnvelopeFrom = withFingerprint.EnvelopeFrom, Recipients = withFingerprint.Recipients,
            Raw = withFingerprint.Raw, ReceivedAt = withFingerprint.ReceivedAt, ExpiresAt = withFingerprint.ExpiresAt, IdempotencyKey = "idem-1", IdempotencyFingerprint = "fp-123", Content = withFingerprint.Content,
            RetainRaw = true, SendingDomain = withFingerprint.SendingDomain, HeadersUtf8 = true,
        });
        await AcceptAsync(Msg(to: ["c@example.org"], idempotencyKey: "idem-2", size: 40_000));
        await AcceptAsync(Msg(to: ["d@example.org"], tenant: TenantB));
        var claimed = await ClaimAsync(max: 10, now: now);
        Assert.Equal(4, claimed.Count);
        var tenantA = claimed.Where(d => d.TenantId == TenantA).ToList();
        await RecordAsync(tenantA[0], DeliveryOutcome.Delivered, events: [Draft("message.delivered")]);
        await RecordAsync(tenantA[1], DeliveryOutcome.Deferred, next: now.AddMinutes(10), smtp: 451, message: "try later", possibleDuplicate: true);
        await Storage.Deliveries.ReleaseOwnedLeasesAsync("worker-1", default);
        Clock.Advance(TimeSpan.FromSeconds(1));
        var items = await Storage.Webhooks.ClaimDueAsync("w", 5, Clock.UtcNow, TimeSpan.FromMinutes(1), default);
        Assert.NotEmpty(items);
        await Storage.Webhooks.CompleteAsync(items[0].Id, new WebhookAttemptRecord(items[0].Id, Clock.UtcNow, 200, TimeSpan.FromMilliseconds(20), null, "ok"), WebhookOutboxState.Delivered, null, default);
        Assert.NotEqual(Guid.Empty, endpoint);
        await FlushStatsAsync();
    }

    [Fact]
    public async Task Every_table_that_moves_is_read_in_a_populated_store()
    {
        await PopulateAsync();
        foreach (TransferTable table in TransferTables.All.Where(t => Transfer.HasPart(t.Part)))
        {
            long count = await Transfer.CountAsync(table, TransferRange.All, default);
            var rows = await ReadAllAsync(table);
            Assert.Equal(count, rows.Count);
            if (table.Name is "tenant" or "dashboard_user" or "dashboard_session" or "domain" or "dkim_key" or "api_key" or "smtp_credential" or "suppression" or "setting" or "tls_policy" or "relay_route" or "certificate"
                or "acme_account" or "acme_renewal" or "webhook_endpoint" or "delivery_queue" or "message_spool" or "webhook_outbox" or "api_idempotency_key" or "stat_aggregate" or "webhook_attempt"
                or "inbound_domain_settings" or "inbound_route" or "inbound_message" or "inbound_message_raw")
            {
                Assert.True(count > 0, $"{table.Name} should have rows");
            }

            if (IsFull && table.Name is "message_index" or "message_recipient" or "message_event" or "message_content")
            {
                Assert.True(count > 0, $"{table.Name} should have rows");
            }
        }
    }

    [Fact]
    public async Task The_data_protection_key_ring_never_moves()
    {
        await PopulateAsync();
        var settings = await ReadAllAsync(TransferTables.Settings);
        Assert.DoesNotContain(settings.Cast<Model.SettingEntity>(), s => s.Key.StartsWith(TransferTables.DataProtectionSettingPrefix, StringComparison.Ordinal));
        Assert.Equal(2, settings.Count);
    }

    [Fact]
    public async Task Rows_survive_the_bundle_json_form_unchanged()
    {
        await PopulateAsync();
        foreach (TransferTable table in TransferTables.All.Where(t => Transfer.HasPart(t.Part)))
        {
            foreach (object row in await ReadAllAsync(table))
            {
                object back = table.Deserialize(table.Serialize(row));
                if (table.Body is { } body)
                {
                    table.Body.Set(back, body.Get(row));
                }

                Assert.Equal(table.Canonical(row), table.Canonical(back));
            }
        }
    }

    [Fact]
    public async Task Wiping_and_re_importing_every_table_restores_the_store()
    {
        await PopulateAsync();
        Dictionary<string, List<string>> before = await SnapshotAsync();

        // Export the way the engine does: each row through the bundle form (and a body separately).
        var exported = new List<(TransferTable Table, List<object> Rows)>();
        foreach (TransferTable table in TransferTables.All.Where(t => Transfer.HasPart(t.Part)))
        {
            var rows = new List<object>();
            foreach (object row in await ReadAllAsync(table))
            {
                object copy = table.Deserialize(table.Serialize(row));
                table.Body?.Set(copy, table.Body.Get(row));
                rows.Add(copy);
            }

            exported.Add((table, rows));
        }

        await Transfer.DiscardImportedAsync(SwitchId, default);
        Assert.Empty(await Transfer.GetNonEmptyTablesAsync(default));

        foreach ((TransferTable table, List<object> rows) in exported.Where(e => e.Rows.Count > 0))
        {
            Assert.Equal(ChunkApplyOutcome.Applied, await Transfer.ApplyChunkAsync(new TransferChunk(SwitchId, table, table.Directory + "/" + table.Name + ".00001.ndjson", "c0ffee", false), rows, default));
        }

        Dictionary<string, List<string>> after = await SnapshotAsync();
        foreach (string table in before.Keys)
        {
            if (table is "recent_event" or "webhook_attempt")
            {
                Assert.Equal(before[table], after[table]); // sequence order is preserved
            }
            else
            {
                Assert.Equal(before[table].Order(StringComparer.Ordinal), after[table].Order(StringComparer.Ordinal));
            }
        }
    }

    [Fact]
    public async Task Applying_a_chunk_twice_writes_it_once_and_a_changed_checksum_is_refused()
    {
        await PopulateAsync();
        var tenants = await ReadAllAsync(TransferTables.Tenants);
        await Transfer.DiscardImportedAsync(SwitchId, default);

        var chunk = new TransferChunk(SwitchId, TransferTables.Tenants, "config/tenant.00001.ndjson", "AA", false);
        Assert.Equal(ChunkApplyOutcome.Applied, await Transfer.ApplyChunkAsync(chunk, tenants, default));
        Assert.Equal(ChunkApplyOutcome.AlreadyApplied, await Transfer.ApplyChunkAsync(chunk, tenants, default));
        Assert.Equal(2, await Transfer.CountAsync(TransferTables.Tenants, TransferRange.All, default));

        await Assert.ThrowsAsync<StorageTransferException>(async () => await Transfer.ApplyChunkAsync(chunk with { Checksum = "BB" }, tenants, default));
        var applied = await Transfer.GetAppliedChunksAsync(SwitchId, TransferPart.Config, default);
        var record = Assert.Single(applied);
        Assert.Equal("config/tenant.00001.ndjson", record.ChunkId);
        Assert.Equal(2, record.Rows);
        Assert.Empty(await Transfer.GetAppliedChunksAsync(Guid.NewGuid(), TransferPart.Config, default));
    }

    [Fact]
    public async Task Transfer_marks_make_queued_rows_unclaimable_until_released()
    {
        await PopulateAsync();
        Clock.Advance(TimeSpan.FromMinutes(11));
        Assert.NotEmpty(await ClaimAsync(owner: "probe", lease: TimeSpan.FromSeconds(1)));
        Clock.Advance(TimeSpan.FromMinutes(1));

        // A pending outbox row exists too.
        await Storage.Webhooks.EnqueueAsync(TenantA, Draft("message.bounced"), Clock.UtcNow, default);
        Assert.NotEmpty(await Storage.Webhooks.ClaimDueAsync("probe", 10, Clock.UtcNow, TimeSpan.FromSeconds(1), default));
        Clock.Advance(TimeSpan.FromMinutes(1));

        long marked = await Transfer.MarkQueueTransferredAsync(SwitchId, default);
        Assert.True(marked >= 2);
        Assert.Equal(marked, await Transfer.CountHeldQueueRowsAsync(SwitchId, default));
        Assert.Empty(await ClaimAsync(owner: "after-mark"));
        Assert.Empty(await Storage.Deliveries.ClaimExpiredAsync("after-mark", 10, Clock.UtcNow.AddDays(30), default));
        Assert.Empty(await Storage.Webhooks.ClaimDueAsync("after-mark", 10, Clock.UtcNow, TimeSpan.FromMinutes(1), default));

        // Marked rows are still exported, without the mark.
        var rows = await ReadAllAsync(TransferTables.Deliveries);
        Assert.NotEmpty(rows);
        Assert.DoesNotContain("transfer", TransferTables.Deliveries.Serialize(rows[0]), StringComparison.OrdinalIgnoreCase);

        Assert.Equal(marked, await Transfer.ReleaseQueueAsync(SwitchId, default));
        Assert.Equal(0, await Transfer.CountHeldQueueRowsAsync(SwitchId, default));
        Assert.NotEmpty(await ClaimAsync(owner: "after-release"));
    }

    [Fact]
    public async Task Imported_queue_rows_are_held_until_released()
    {
        await PopulateAsync();
        var deliveries = (await ReadAllAsync(TransferTables.Deliveries)).Select(r => TransferTables.Deliveries.Deserialize(TransferTables.Deliveries.Serialize(r))).ToList();
        var spool = (await ReadAllAsync(TransferTables.Spool)).Select(r =>
        {
            object copy = TransferTables.Spool.Deserialize(TransferTables.Spool.Serialize(r));
            TransferTables.Spool.Body!.Set(copy, TransferTables.Spool.Body.Get(r));
            return copy;
        }).ToList();
        await Transfer.DiscardImportedAsync(SwitchId, default);

        await Transfer.ApplyChunkAsync(new TransferChunk(SwitchId, TransferTables.Spool, "queue/message_spool.00001.ndjson", "S", true), spool, default);
        await Transfer.ApplyChunkAsync(new TransferChunk(SwitchId, TransferTables.Deliveries, "queue/delivery_queue.00001.ndjson", "D", true), deliveries, default);
        Clock.Advance(TimeSpan.FromDays(1));
        Assert.Empty(await ClaimAsync());
        Assert.Equal(deliveries.Count, await Transfer.CountHeldQueueRowsAsync(SwitchId, default));

        await Transfer.ReleaseQueueAsync(SwitchId, default);
        Assert.Equal(deliveries.Count, (await ClaimAsync()).Count);
    }

    [Fact]
    public async Task Pending_inbound_actions_are_held_by_a_transfer_mark_and_by_an_import_until_released()
    {
        await PopulateAsync();

        // Source side: marked rows are not dispatched, are still exported, and run again when released.
        var messages = await ReadAllAsync(TransferTables.InboundMessages);
        var bodies = await ReadAllAsync(TransferTables.InboundRaw);
        Assert.Equal(3, messages.Count);
        Assert.Equal(2, bodies.Count);   // the discarded message has no body
        long marked = await Transfer.MarkQueueTransferredAsync(SwitchId, default);
        Assert.True(marked >= 3);
        Assert.Empty(await Storage.Inbound.ClaimActionsAsync("after-mark", 10, Clock.UtcNow, TimeSpan.FromMinutes(1), default));
        Assert.DoesNotContain("transfer", TransferTables.InboundMessages.Serialize(messages[0]), StringComparison.OrdinalIgnoreCase);
        await Transfer.ReleaseQueueAsync(SwitchId, default);
        var claimed = await Storage.Inbound.ClaimActionsAsync("after-release", 10, Clock.UtcNow, TimeSpan.FromMinutes(1), default);
        Assert.Single(claimed);

        // Target side: rows applied with the hold are not dispatched until it is released.
        var copies = messages.Select(r => TransferTables.InboundMessages.Deserialize(TransferTables.InboundMessages.Serialize(r))).ToList();
        var bodyCopies = bodies.Select(r =>
        {
            object copy = TransferTables.InboundRaw.Deserialize(TransferTables.InboundRaw.Serialize(r));
            TransferTables.InboundRaw.Body!.Set(copy, TransferTables.InboundRaw.Body.Get(r));
            return copy;
        }).ToList();
        await Transfer.DiscardImportedAsync(SwitchId, default);
        Assert.Empty((await Storage.Inbound.SearchAsync(new InboundMessageQuery(TenantId: TenantA), default)).Items);

        await Transfer.ApplyChunkAsync(new TransferChunk(SwitchId, TransferTables.InboundMessages, "queue/inbound_message.00001.ndjson", "M", true), copies, default);
        await Transfer.ApplyChunkAsync(new TransferChunk(SwitchId, TransferTables.InboundRaw, "queue/inbound_message_raw.00001.ndjson", "R", false), bodyCopies, default);
        Clock.Advance(TimeSpan.FromDays(1));
        Assert.Empty(await Storage.Inbound.ClaimActionsAsync("held", 10, Clock.UtcNow, TimeSpan.FromMinutes(1), default));
        Assert.Equal(3, (await Storage.Inbound.SearchAsync(new InboundMessageQuery(TenantId: TenantA), default)).Items.Count);   // visible, not dispatched
        await Transfer.ReleaseQueueAsync(SwitchId, default);
        var again = Assert.Single(await Storage.Inbound.ClaimActionsAsync("released", 10, Clock.UtcNow, TimeSpan.FromMinutes(1), default));
        Assert.Equal(300, again.Raw!.Length);
    }

    [Fact]
    public async Task A_fenced_source_neither_accepts_nor_dispatches()
    {
        await AcceptAsync();
        Assert.False(Transfer.Gate.IsClosed);
        await Transfer.SetStateAsync(new SwitchStateRecord(SwitchId, SwitchRoles.Source, SwitchStates.Fenced, Clock.UtcNow, "test"), default);

        Assert.True(Transfer.Gate.IsClosed);
        Assert.Contains(SwitchId.ToString(), Transfer.Gate.Reason);
        await Assert.ThrowsAsync<StorageFencedException>(async () => await Storage.Intake.AcceptAsync(Msg(), default));
        Assert.Empty(await ClaimAsync());
        Assert.Empty(await Storage.Deliveries.ClaimExpiredAsync("w", 10, Clock.UtcNow.AddDays(30), default));
        Assert.Empty(await Storage.Webhooks.ClaimDueAsync("w", 10, Clock.UtcNow, TimeSpan.FromMinutes(1), default));
        Assert.Empty(await Storage.Maintenance.RunAsync(Clock.UtcNow, default));
        Assert.Empty(await Storage.Inbound.ClaimActionsAsync("w", 10, Clock.UtcNow, TimeSpan.FromMinutes(1), default));
        await Assert.ThrowsAsync<StorageFencedException>(async () => await Storage.Inbound.AcceptAsync([new InboundMessageDraft
        {
            Id = Ids.New(), TenantId = TenantA, DomainId = Ids.New(), Domain = "example.com", ReceivedAt = Clock.UtcNow, RemoteAddress = "203.0.113.9", EnvelopeFrom = "a@b.test", EnvelopeTo = "x@example.com",
            Auth = InboundAuthResults.NotChecked, RouteId = Ids.New(), ActionKind = InboundActionKind.Store, Raw = new byte[10],
        }], default));

        // Reads still work (the fenced source is the read-only copy of the data).
        Assert.Equal(1, await Transfer.CountAsync(TransferTables.Deliveries, TransferRange.All, default));

        await Transfer.SetStateAsync(new SwitchStateRecord(SwitchId, SwitchRoles.Source, SwitchStates.Active, Clock.UtcNow, "rolled back"), default);
        Assert.False(Transfer.Gate.IsClosed);
        await AcceptAsync();
        Assert.Single(await ClaimAsync(max: 1));
    }

    [Theory]
    [InlineData(SwitchStates.Importing)]
    [InlineData(SwitchStates.Verified)]
    [InlineData(SwitchStates.Confirmed)]
    public async Task A_target_that_is_not_active_neither_accepts_nor_dispatches(string state)
    {
        await Transfer.SetStateAsync(new SwitchStateRecord(SwitchId, SwitchRoles.Target, state, Clock.UtcNow, null), default);
        Assert.True(Transfer.Gate.IsClosed);
        await Assert.ThrowsAsync<StorageFencedException>(async () => await Storage.Intake.AcceptAsync(Msg(), default));

        await Transfer.SetStateAsync(new SwitchStateRecord(SwitchId, SwitchRoles.Target, SwitchStates.Active, Clock.UtcNow, null), default);
        Assert.False(Transfer.Gate.IsClosed);
        await AcceptAsync();
    }

    [Theory]
    [InlineData(SwitchStates.Draining)]
    [InlineData(SwitchStates.Quiescing)]
    public async Task A_draining_or_quiescing_source_is_controlled_by_the_host_not_the_store(string state)
    {
        await Transfer.SetStateAsync(new SwitchStateRecord(SwitchId, SwitchRoles.Source, state, Clock.UtcNow, null), default);
        Assert.False(Transfer.Gate.IsClosed);
        await AcceptAsync();
        Assert.NotEmpty(await ClaimAsync());
    }

    [Fact]
    public async Task The_switch_state_round_trips_and_can_be_cleared()
    {
        Assert.Null(await Transfer.GetStateAsync(default));
        var state = new SwitchStateRecord(SwitchId, SwitchRoles.Target, SwitchStates.Importing, StorageTime(Clock.UtcNow), "detail");
        await Transfer.SetStateAsync(state, default);
        Assert.Equal(state, await Transfer.GetStateAsync(default));
        Assert.Equal(state, await Storage.Config.GetSwitchStateAsync(default));
        await Transfer.ClearStateAsync(default);
        Assert.Null(await Transfer.GetStateAsync(default));
        Assert.False(Transfer.Gate.IsClosed);
    }

    private static DateTimeOffset StorageTime(DateTimeOffset value) => DateTimeOffset.FromUnixTimeMilliseconds(value.ToUnixTimeMilliseconds());

    [Fact]
    public async Task An_empty_store_has_nothing_that_would_move_and_a_populated_one_lists_its_tables()
    {
        Assert.Empty(await Transfer.GetNonEmptyTablesAsync(default));
        await Storage.Config.SetSettingAsync(new SettingRecord(TransferTables.DataProtectionSettingPrefix + "k", null, "\"x\"", Clock.UtcNow), default);
        Assert.Empty(await Transfer.GetNonEmptyTablesAsync(default)); // the key ring does not count
        await PopulateAsync();
        var tables = await Transfer.GetNonEmptyTablesAsync(default);
        Assert.Contains("tenant", tables);
        Assert.Contains("delivery_queue", tables);
        Assert.Contains("stat_aggregate", tables);
    }

    [Fact]
    public async Task History_is_read_day_by_day_and_only_when_the_store_records_it()
    {
        if (!IsFull)
        {
            Assert.False(Transfer.HasPart(TransferPart.History));
            Assert.Empty(await Transfer.GetHistoryDaysAsync(default));
            await Assert.ThrowsAsync<StorageTransferException>(async () => await ReadAllAsync(TransferTables.MessageIndex));
            return;
        }

        DateTimeOffset d1 = Clock.UtcNow.AddDays(-2);
        DateTimeOffset d2 = Clock.UtcNow;
        var m1 = await AcceptAsync(Msg(received: d1, to: ["x@example.org"]));
        var m2 = await AcceptAsync(Msg(received: d2, to: ["y@example.org", "z@example.org"]));
        int day1 = Logic.StorageTime.DayNumber(m1.MessageId);
        int day2 = Logic.StorageTime.DayNumber(m2.MessageId);

        Assert.Equal([day1, day2], await Transfer.GetHistoryDaysAsync(default));
        var first = await ReadAllAsync(TransferTables.MessageIndex, TransferRange.Day(day1));
        Assert.Equal(m1.MessageId, Assert.Single(first.Cast<Model.MessageIndexEntity>()).MessageId);
        Assert.Equal(2, (await ReadAllAsync(TransferTables.MessageRecipients, TransferRange.Day(day2))).Count);
        Assert.Equal(2, (await ReadAllAsync(TransferTables.MessageIndex, new TransferRange(day1, day2))).Count);
        Assert.Equal(2, (await ReadAllAsync(TransferTables.MessageIndex, new TransferRange(null, day2))).Count);
        Assert.Single(await ReadAllAsync(TransferTables.MessageIndex, new TransferRange(day2, null)));
    }

    [Fact]
    public async Task Discarding_a_switch_removes_its_rows_and_progress_but_keeps_other_stores_state()
    {
        await PopulateAsync();
        await Transfer.ApplyChunkAsync(new TransferChunk(SwitchId, TransferTables.IdempotencyKeys, "queue/api_idempotency_key.00001.ndjson", "X", false), [], default);
        await Transfer.DiscardImportedAsync(SwitchId, default);
        Assert.Empty(await Transfer.GetNonEmptyTablesAsync(default));
        Assert.Empty(await Transfer.GetAppliedChunksAsync(SwitchId, TransferPart.Queue, default));
        Assert.Equal(0, (await Storage.Deliveries.GetQueueStatsAsync(default)).Queued);
    }

    [Fact]
    public async Task Secret_columns_are_read_exactly_as_stored()
    {
        await PopulateAsync();
        var dkim = (Model.DkimKeyEntity)Assert.Single(await ReadAllAsync(TransferTables.DkimKeys));
        Assert.Equal(new byte[] { 9, 8, 7, 6 }, dkim.PrivateKeyProtected);
        var relay = (Model.RelayRouteEntity)Assert.Single(await ReadAllAsync(TransferTables.RelayRoutes));
        Assert.Equal(new byte[] { 4, 5, 6 }, relay.PasswordProtected);
        Assert.Equal(new[] { TransferTables.DkimKeys.Secrets[0].Purpose }, TransferTables.DkimKeys.Secrets.Select(s => s.Purpose));
    }
}
