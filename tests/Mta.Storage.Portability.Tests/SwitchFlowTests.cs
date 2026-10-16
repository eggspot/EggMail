using Mta.Core;
using Mta.Storage.Model;
using Mta.Storage.Transfer;

namespace Mta.Storage.Portability.Tests;

/// <summary>The complete switch between two stores, in every direction and in both history modes (design §4.6).</summary>
public class SwitchFlowTests : SwitchTestBase
{
    [Theory]
    [InlineData(StoreKind.InMemory, StoreKind.Sqlite, false)]
    [InlineData(StoreKind.Sqlite, StoreKind.InMemory, false)]
    [InlineData(StoreKind.Sqlite, StoreKind.Sqlite, false)]
    [InlineData(StoreKind.InMemory, StoreKind.InMemory, false)]
    [InlineData(StoreKind.InMemory, StoreKind.Sqlite, true)]
    [InlineData(StoreKind.Sqlite, StoreKind.Sqlite, true)]
    public async Task Full_drain_flow_moves_everything_and_the_old_data_stays_in_the_source(StoreKind from, StoreKind to, bool skipHistory)
    {
        TestStore source = await NewStoreAsync(from, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(to, HistoryMode.Full, "target");
        Seed.Seeded seeded = await Seed.PopulateAsync(source.Storage, source.Protector);
        var activator = new RecordingActivator();
        StorageSwitchEngine engine = NewEngine(source, target, activator: activator);

        PreflightReport pre = await engine.PreflightAsync(new SwitchRequest { Mode = SwitchMode.Drain, BundlePath = BundleDir(), Passphrase = Pass, SkipHistory = skipHistory }, default);
        Assert.True(pre.CanProceed, string.Join("; ", pre.Errors.Select(e => e.Message)));
        Assert.True(pre.SourceRows["delivery_queue"] > 0);

        // Drain: stop accepting, deliver what is queued, then the source is fenced by the export.
        SwitchStatus started = await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Drain, BundlePath = BundleDir(), Passphrase = Pass, SkipHistory = skipHistory }, null, default);
        Assert.Equal(SwitchStates.Draining, started.SourceState);
        var early = await Assert.ThrowsAsync<SwitchException>(() => engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default));
        Assert.Contains("not drained", early.Message);

        await DeliverEverythingAsync(source.Storage);
        ExportResult export = await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass, SkipHistory = skipHistory }, null, default);
        Assert.True(export.HistoryComplete);
        Assert.Equal(SwitchStates.Fenced, (await source.Transfer.GetStateAsync(default))!.State);

        ImportResult import = await engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.True(import.RowsApplied > 0);
        Assert.Equal(SwitchStates.Importing, (await target.Transfer.GetStateAsync(default))!.State);

        VerifyReport verify = await engine.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.True(verify.Ok, string.Join("; ", verify.Problems));
        Assert.True(verify.SecretsChecked);
        Assert.All(verify.Tables.Where(t => t.SecretsMatch.HasValue), t => Assert.True(t.SecretsMatch));
        Assert.Equal(SwitchStates.Verified, (await target.Transfer.GetStateAsync(default))!.State);

        await engine.ConfirmAsync(default);
        SwitchActivation activation = await engine.ActivateAsync(default);
        Assert.Equal(ActivationKind.CutoverPatch, activation.Kind);
        Assert.Equal("Full", activator.Request!.EffectiveSettings["History:Mode"]);

        // The target starts: the gate activates it.
        Assert.True(await TargetActivation.ActivateAsync(target.Transfer, SystemClock.Instance, default));
        Assert.Equal(SwitchStates.Active, (await target.Transfer.GetStateAsync(default))!.State);

        await AssertSameAsync(source, target, includeHistory: !skipHistory);
        await AssertSecretsAsync(source, target);
        await AssertRuntimeStateMovedAsync(source, target, seeded);
        if (skipHistory)
        {
            Assert.Empty(await ReadAsync<MessageIndexEntity>(target, TransferTables.MessageIndex));
        }

        // The queue moved: nothing was in it (drain), idempotency keys did.
        Assert.Equal(0, (await target.Storage.Deliveries.GetQueueStatsAsync(default)).Queued);
        IntakeResult again = await target.Storage.Intake.AcceptAsync(Seed.Message(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(5), ["x@example.org"], idempotencyKey: seeded.IdempotencyKey), default);
        Assert.Equal(IntakeStatus.DuplicateIdempotencyKey, again.Status);
        Assert.Equal(seeded.IdempotencyMessageId, again.MessageId);

        // The old data is untouched and fenced until the owner finalizes.
        await Assert.ThrowsAsync<StorageFencedException>(async () => await source.Storage.Intake.AcceptAsync(Seed.Message(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(5), ["y@example.org"]), default));
        SwitchStatus final = await engine.FinalizeAsync(deleteBundle: false, null, default);
        Assert.Equal(SwitchStates.Finalized, final.SourceState);
        Assert.True(Directory.Exists(BundleDir()));
    }

    /// <summary>The persisted runtime state carries over: the target shows the same check results, the same unsent TLS-RPT counters and the same sending counters.</summary>
    private static async Task AssertRuntimeStateMovedAsync(TestStore source, TestStore target, Seed.Seeded seeded)
    {
        var checks = await target.Storage.Config.GetDomainRecordChecksAsync(seeded.DomainId, default);
        Assert.Equal(["invalid", "missing", "ok"], checks.OrderBy(c => c.RecordKey, StringComparer.Ordinal).Select(c => c.Status).Order(StringComparer.Ordinal));
        Assert.Equal(await source.Storage.Config.GetDomainRecordChecksAsync(seeded.DomainId, default), checks);

        int tomorrow = (int)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 86400) + 1;
        var buckets = await target.Storage.Config.GetTlsRptBucketsAsync(tomorrow, 100, default);
        Assert.Equal("partner.example", Assert.Single(buckets).PolicyDomain);
        Assert.Equal(2, buckets[0].Attempts);
        Assert.Equal(await source.Storage.Config.GetTlsRptBucketsAsync(tomorrow, 100, default), buckets);

        long hour = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 3600;
        var counters = await target.Storage.Config.GetSendingCountersAsync(hour - 1, hour / 24 - 1, default);
        Assert.Equal([17L, 29L, 31L], counters.OrderBy(c => c.Scope).Select(c => c.Count));
        Assert.Equal(await source.Storage.Config.GetSendingCountersAsync(hour - 1, hour / 24 - 1, default), counters);
    }

    [Theory]
    [InlineData(StoreKind.InMemory, StoreKind.Sqlite)]
    [InlineData(StoreKind.Sqlite, StoreKind.Sqlite)]
    [InlineData(StoreKind.Sqlite, StoreKind.InMemory)]
    public async Task Quiesce_moves_the_queued_mail_with_ids_and_retry_state_and_nothing_is_lost_or_doubled(StoreKind from, StoreKind to)
    {
        TestStore source = await NewStoreAsync(from, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(to, HistoryMode.Full, "target");
        Seed.Seeded seeded = await Seed.PopulateAsync(source.Storage, source.Protector, queued: 5);
        var before = await ReadAsync<QueuedDeliveryEntity>(source, TransferTables.Deliveries);
        Assert.Equal(10, before.Count);
        Assert.Contains(before, d => d.Attempt == 1 && d.LastError!.Contains("try again later"));

        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());
        ExportResult export = await SwitchToConfirmedAsync(engine, BundleDir());
        // Of the 3 inbound messages only the pending action is held: a message that is done or failed is just data.
        Assert.Equal(3, (await source.Storage.Inbound.SearchAsync(new InboundMessageQuery(TenantId: Seed.TenantA), default)).Items.Count);
        long pendingInbound = (await source.Storage.Inbound.SearchAsync(new InboundMessageQuery(TenantId: Seed.TenantA, ActionState: InboundActionState.Pending), default)).Items.Count;
        Assert.Equal(1, pendingInbound);
        Assert.Equal(10 + (await ReadAsync<WebhookOutboxEntity>(source, TransferTables.WebhookOutbox)).Count + pendingInbound, export.QueueRowsMarked);

        // The source rows are marked and fenced: it can neither claim them nor accept.
        Assert.Empty(await source.Storage.Deliveries.ClaimAsync("late", 100, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default));

        // The target holds the same rows (ids preserved, retry state preserved) but dispatches nothing until it is activated.
        var imported = await ReadAsync<QueuedDeliveryEntity>(target, TransferTables.Deliveries);
        Assert.Equal(before.Select(d => d.Id).Order(), imported.Select(d => d.Id).Order());
        Assert.Contains(imported, d => d.Attempt == 1 && d.LastError!.Contains("try again later"));
        Assert.Equal(seeded.QueuedDeliveryIds.Order(), imported.Select(d => d.Id).Order());
        Assert.Empty(await target.Storage.Deliveries.ClaimAsync("early", 100, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default));
        await Assert.ThrowsAsync<StorageFencedException>(async () => await target.Storage.Intake.AcceptAsync(Seed.Message(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(5), ["z@example.org"]), default));

        Assert.True(await TargetActivation.ActivateAsync(target.Transfer, SystemClock.Instance, default));
        var claimed = await target.Storage.Deliveries.ClaimAsync("after", 100, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default);
        Assert.Equal(10, claimed.Count);

        // The inbound mail came along: settings, routes, the stored messages, and the pending webhook action runs on the target (and only there).
        Assert.Equal(3, (await target.Storage.Inbound.SearchAsync(new InboundMessageQuery(TenantId: Seed.TenantA), default)).Items.Count);
        Assert.Equal(2, (await target.Storage.Inbound.GetRoutesAsync(seeded.DomainId, default)).Count);
        Assert.True((await target.Storage.Inbound.GetSettingsAsync(seeded.DomainId, default))!.Enabled);
        InboundMessage movedAction = Assert.Single((await target.Storage.Inbound.ClaimActionsAsync("inbound-after", 10, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default)).Select(c => c.Message));
        Assert.Equal(InboundActionKind.Webhook, movedAction.ActionKind);
        Assert.Empty(await source.Storage.Inbound.ClaimActionsAsync("inbound-before", 10, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default));
        Assert.Equal(seeded.QueuedDeliveryIds.Order(), claimed.Select(c => c.DeliveryId).Order());
        byte[]? raw = await target.Storage.Deliveries.GetRawAsync(seeded.QueuedMessageIds[1], default);
        Assert.True(raw is { Length: > 100_000 });
        Assert.Equal(await source.Storage.Deliveries.GetRawAsync(seeded.QueuedMessageIds[1], default), raw);
    }

    [Fact]
    public async Task Quiesce_with_a_delivery_in_flight_requeues_it_flagged_and_every_other_message_goes_out_once()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 0);
        await using var remote = new RemoteMta();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        remote.HoldReply = release;
        remote.HoldWhen = r => r == "held@example.org";

        await using var sourceRig = new DeliveryRig(source.Storage, remote, "source-rig");
        var host = new RigHostControl(sourceRig);
        StorageSwitchEngine engine = NewEngine(source, target, host, new RecordingActivator());

        // One message is mid-conversation (the remote has the message but has not answered yet); more are queued behind it.
        Guid heldMessage = await EnqueueAsync(source.Storage, "held@example.org");
        await DeliveryRig.WaitAsync(() => remote.CountFor("held@example.org") == 1);
        sourceRig.Engine.Pause();
        var pending = new List<string>();
        for (int i = 0; i < 4; i++)
        {
            string to = $"pending{i}@example.org";
            pending.Add(to);
            await EnqueueAsync(source.Storage, to);
        }

        await SwitchToConfirmedAsync(engine, BundleDir(), SwitchMode.Quiesce, quiesceTimeout: TimeSpan.FromMilliseconds(300));
        Assert.False(host.Accepting);

        // The in-flight delivery was aborted after the end of data was sent: requeued unchanged, flagged possibly sent twice.
        var rows = await ReadAsync<QueuedDeliveryEntity>(target, TransferTables.Deliveries);
        Assert.Equal(5, rows.Count);
        QueuedDeliveryEntity held = rows.Single(r => r.Recipient == "held@example.org");
        Assert.True(held.PossibleDuplicate);
        Assert.Equal(0, held.Attempt);
        Assert.All(rows.Where(r => r.Recipient != "held@example.org"), r => Assert.False(r.PossibleDuplicate));
        var events = await source.Storage.History.GetEventsAsync(Seed.TenantA, heldMessage, default);
        Assert.Contains(events, e => e.Type == MessageEventType.AbortedBySwitch);
        Assert.Contains(events, e => e.Type == MessageEventType.PossibleDuplicate);

        // The source does not send anything any more, even though its rows are still there.
        Assert.Equal(5, (await ReadAsync<QueuedDeliveryEntity>(source, TransferTables.Deliveries)).Count);
        sourceRig.Engine.Resume();
        await Task.Delay(300);
        Assert.Single(remote.Received);

        // Activate the target and let it deliver.
        remote.HoldReply = null;
        Assert.True(await TargetActivation.ActivateAsync(target.Transfer, SystemClock.Instance, default));
        await using var targetRig = new DeliveryRig(target.Storage, remote, "target-rig");
        await DeliveryRig.WaitAsync(() => pending.All(p => remote.CountFor(p) >= 1) && remote.CountFor("held@example.org") >= 2);
        await Task.Delay(300);

        Assert.All(pending, p => Assert.Equal(1, remote.CountFor(p)));
        Assert.Equal(2, remote.CountFor("held@example.org")); // at-least-once, and visible as possible_duplicate
        await DeliveryRig.WaitAsync(() => target.Storage.Deliveries.GetQueueStatsAsync(default).AsTask().Result is { Queued: 0, Leased: 0, Deferred: 0 });
        release.TrySetResult();
    }

    [Fact]
    public async Task Pending_webhook_events_move_with_their_event_ids_and_stay_unsent_until_activation()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector);
        var before = await ReadAsync<WebhookOutboxEntity>(source, TransferTables.WebhookOutbox);
        Assert.Contains(before, o => o.State == WebhookOutboxState.Pending);

        await SwitchToConfirmedAsync(NewEngine(source, target, activator: new RecordingActivator()), BundleDir());
        var after = await ReadAsync<WebhookOutboxEntity>(target, TransferTables.WebhookOutbox);
        Assert.Equal(before.Select(o => (o.Id, o.EventId)).Order(), after.Select(o => (o.Id, o.EventId)).Order());
        Assert.Empty(await target.Storage.Webhooks.ClaimDueAsync("w", 10, DateTimeOffset.UtcNow.AddDays(1), TimeSpan.FromMinutes(1), default));
        Assert.Empty(await source.Storage.Webhooks.ClaimDueAsync("w", 10, DateTimeOffset.UtcNow.AddDays(1), TimeSpan.FromMinutes(1), default));

        await TargetActivation.ActivateAsync(target.Transfer, SystemClock.Instance, default);
        var claimed = await target.Storage.Webhooks.ClaimDueAsync("w", 10, DateTimeOffset.UtcNow.AddDays(1), TimeSpan.FromMinutes(1), default);
        Assert.Equal(before.Count(o => o.State == WebhookOutboxState.Pending), claimed.Count);
    }

    [Fact]
    public async Task A_target_with_StatsOnly_history_gets_everything_but_history_and_says_so()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.StatsOnly, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());

        PreflightReport pre = await engine.PreflightAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass }, default);
        Assert.True(pre.CanProceed);
        Assert.Contains(pre.WillNotCarryOver, w => w.Contains("StatsOnly"));
        Assert.Contains(pre.Checks, c => c.Name == "history" && c.Status == CheckStatus.Warning);

        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass, QuiesceTimeout = TimeSpan.FromMilliseconds(100) }, null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        ImportResult import = await engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.Contains(import.Notes, n => n.Contains("StatsOnly"));
        VerifyReport verify = await engine.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.True(verify.Ok, string.Join("; ", verify.Problems));
        Assert.False(target.Transfer.HasPart(TransferPart.History));
        await AssertSameAsync(source, target, includeHistory: false);
        // The history stays in the read-only source.
        Assert.NotEmpty(await ReadAsync<MessageIndexEntity>(source, TransferTables.MessageIndex));
    }

    [Fact]
    public async Task A_StatsOnly_source_has_no_history_to_move()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.StatsOnly, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector);
        ExportResult export = await SwitchToConfirmedAsync(NewEngine(source, target, activator: new RecordingActivator()), BundleDir());
        Assert.True(export.HistoryComplete);
        await AssertSameAsync(source, target, includeHistory: false);
        Assert.Empty(await ReadAsync<MessageIndexEntity>(target, TransferTables.MessageIndex));
    }

    [Fact]
    public async Task Ids_idempotency_keys_and_message_bodies_are_preserved_across_the_switch()
    {
        TestStore source = await NewStoreAsync(StoreKind.InMemory, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        Seed.Seeded seeded = await Seed.PopulateAsync(source.Storage, source.Protector);
        await SwitchToConfirmedAsync(NewEngine(source, target, activator: new RecordingActivator()), BundleDir());
        await TargetActivation.ActivateAsync(target.Transfer, SystemClock.Instance, default);

        var keys = await ReadAsync<IdempotencyKeyEntity>(target, TransferTables.IdempotencyKeys);
        IdempotencyKeyEntity key = Assert.Single(keys);
        Assert.Equal(seeded.IdempotencyKey, key.IdempotencyKey);
        Assert.Equal(seeded.IdempotencyMessageId, key.MessageId);

        foreach (Guid id in seeded.QueuedMessageIds)
        {
            Assert.Equal(await source.Storage.Deliveries.GetRawAsync(id, default), await target.Storage.Deliveries.GetRawAsync(id, default));
        }

        // A client retrying an API send after the cutover is de-duplicated by the preserved key.
        IntakeResult retry = await target.Storage.Intake.AcceptAsync(Seed.Message(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(5), ["retry@example.org"], idempotencyKey: seeded.IdempotencyKey), default);
        Assert.Equal(IntakeStatus.DuplicateIdempotencyKey, retry.Status);
    }

    [Fact]
    public async Task The_switch_is_symmetric_and_can_be_run_again_in_reverse_after_activation()
    {
        TestStore a = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "a");
        TestStore b = await NewStoreAsync(StoreKind.InMemory, HistoryMode.Full, "b");
        TestStore c = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "c");
        await Seed.PopulateAsync(a.Storage, a.Protector);

        StorageSwitchEngine forward = NewEngine(a, b, activator: new RecordingActivator());
        await SwitchToConfirmedAsync(forward, BundleDir("b1"));
        await TargetActivation.ActivateAsync(b.Transfer, SystemClock.Instance, default);
        await forward.FinalizeAsync(false, null, default);

        // Running on b now: switch b -> c (what going back would be: the same flow in the other direction).
        await b.Storage.Intake.AcceptAsync(Seed.Message(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(5), ["new@example.org"]), default);
        StorageSwitchEngine back = NewEngine(b, c, activator: new RecordingActivator());
        await SwitchToConfirmedAsync(back, BundleDir("c1"));
        await TargetActivation.ActivateAsync(c.Transfer, SystemClock.Instance, default);

        await AssertSameAsync(b, c);
        await AssertSecretsAsync(b, c);
        Assert.Equal(SwitchStates.Fenced, (await b.Transfer.GetStateAsync(default))!.State);
        Assert.Equal(SwitchStates.Finalized, (await a.Transfer.GetStateAsync(default))!.State);
    }

    internal static async Task<Guid> EnqueueAsync(IStorage storage, string to)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        AcceptedMessage m = Seed.Message(now, now.AddDays(5), [to]);
        await storage.Intake.AcceptAsync(m, default);
        return m.MessageId;
    }
}
