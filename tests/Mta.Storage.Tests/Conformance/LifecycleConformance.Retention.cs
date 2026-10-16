using Mta.Core;
using Mta.Storage.Logic;
using Mta.TestSupport;

namespace Mta.Storage.Tests;

// Area 1: history, content, raw retention, webhook outbox and attempt log, idempotency keys and the live queue over many virtual days.

public abstract partial class LifecycleConformance
{
    private const int ContentDays = 6;
    private TimeSpan _longLifetime = TimeSpan.FromDays(400);
    private TimeSpan _deferralFarAway = TimeSpan.FromDays(300);
    private static readonly TimeSpan SecondStep = TimeSpan.FromSeconds(90);

    private sealed record Sent(Guid Id, Guid Tenant, DateTimeOffset At, bool HasContent, bool RawRetained, int Recipients, int Events);

    private sealed class Ledger
    {
        public List<Sent> Messages { get; } = [];

        public List<DateTimeOffset> OutboxFinished { get; } = [];

        public List<DateTimeOffset> AttemptsAt { get; } = [];

        public List<DateTimeOffset> IdempotencyExpires { get; } = [];

        public List<Guid> Deferred { get; } = [];

        public Guid? Stuck { get; set; }
    }

    /// <summary>
    /// Runs <paramref name="days"/> virtual days. Each day at T0: the read side is checked with no maintenance having run yet; tenant A's traffic is accepted; 90 seconds later tenant B's
    /// traffic, the webhook dispatcher and one maintenance run follow, and then read side and physical rows are checked. The 90 seconds put the two tenants' messages on either side of a
    /// retention boundary that is crossed at T0 exactly.
    /// </summary>
    private async Task RunHistoryScenarioAsync(int metadataDays, int outboxDays, int attemptDays, int days)
    {
        _deferralFarAway = TimeSpan.FromDays(days + 300);
        _longLifetime = TimeSpan.FromDays((2 * days) + 400);
        await OpenAsync(Opts(
            retention: new RetentionOptions { MetadataDays = metadataDays, WebhookOutboxDays = outboxDays, WebhookAttemptLogDays = attemptDays, StatsHourlyDays = 0, StatsDailyDays = 0 },
            content: new ContentOptions { RetentionDays = ContentDays },
            recentEvents: 25));
        Guid endpoint = await AddEndpointAsync(TenantA, true, "*");
        var ledger = new Ledger();
        DateTimeOffset origin = Clock.UtcNow;

        for (int day = 0; day < days; day++)
        {
            Clock.Set(origin.AddDays(day));
            if (day > 0)
            {
                await CheckReadSideAsync(ledger, metadataDays, "start of day " + day);
            }

            await TrafficAsync(ledger, TenantA, day);
            Clock.Advance(SecondStep);
            await TrafficAsync(ledger, TenantB, day);
            await DispatchWebhooksAsync(ledger, endpoint);
            await MaintainAsync();
            await CheckReadSideAsync(ledger, metadataDays, "after maintenance on day " + day);
            await CheckPhysicalAsync(ledger, metadataDays, outboxDays, attemptDays, "after maintenance on day " + day);
        }

        await CheckLiveQueueAsync(ledger);
        if (days > Math.Max(metadataDays, ContentDays) + 2)
        {
            AssertJobsDeleted(metadataDays, outboxDays, attemptDays);
        }
    }

    private void AssertJobsDeleted(int metadataDays, int outboxDays, int attemptDays)
    {
        // A retention job that never deleted a row in a scenario built to make it delete proves nothing.
        if (IsFull)
        {
            Assert.True(metadataDays <= 0 || _jobRows["retention.metadata"] > 0, "retention.metadata deleted nothing");
            Assert.True(_jobRows["retention.content"] > 0, "retention.content deleted nothing");
        }

        Assert.True(outboxDays <= 0 || _jobRows["retention.webhook_outbox"] > 0, "retention.webhook_outbox deleted nothing");
        Assert.True(attemptDays <= 0 || _jobRows["retention.webhook_attempts"] > 0, "retention.webhook_attempts deleted nothing");
        Assert.True(_jobRows["idempotency.expired"] > 0, "idempotency.expired deleted nothing");
        if (outboxDays <= 0)
        {
            Assert.Equal(0, _jobRows["retention.webhook_outbox"]);
        }

        if (attemptDays <= 0)
        {
            Assert.Equal(0, _jobRows["retention.webhook_attempts"]);
        }

        if (metadataDays <= 0)
        {
            Assert.Equal(0, _jobRows["retention.metadata"]);
        }
    }

    private async Task TrafficAsync(Ledger ledger, Guid tenant, int day)
    {
        DateTimeOffset at = Clock.UtcNow;
        bool isA = tenant == TenantA;
        var batch = new List<(AcceptedMessage Message, bool Fail, bool Webhook)>();
        int count = isA ? 3 : 2;
        for (int j = 0; j < count; j++)
        {
            string[] to = !isA && j == 0 ? [$"x{day}@example.org", $"y{day}@example.org"] : [$"r{day}-{j}-{(isA ? 'a' : 'b')}@example.org"];
            AcceptedMessage m = Msg(
                tenant: tenant,
                to: to,
                received: at,
                subject: $"d{day}-{j}",
                retainRaw: isA && j == 0,
                noContent: !isA && j == 1,
                idempotencyKey: isA && j == 1 ? $"key-{day}" : null,
                size: 300);
            await AcceptAsync(m);
            if (m.IdempotencyKey is not null)
            {
                ledger.IdempotencyExpires.Add(at + Options.Queue.IdempotencyKeyLifetime);
            }

            batch.Add((m, Fail: isA && j == 2, Webhook: isA && j < 2));
        }

        // The long-lived queue entries that maintenance must never touch: one deferred far into the future every tenth day, and one delivery whose lease never runs out.
        AcceptedMessage? deferred = null;
        AcceptedMessage? stuck = null;
        if (isA && day % 10 == 0)
        {
            deferred = await AcceptAsync(Msg(tenant: tenant, to: [$"later{day}@example.org"], received: at, lifetime: _longLifetime, size: 300));
            if (day == 0)
            {
                stuck = await AcceptAsync(Msg(tenant: tenant, to: ["stuck@example.org"], received: at, lifetime: _longLifetime, size: 300));
            }
        }

        foreach (ClaimedDelivery d in await ClaimAsync(max: 1000))
        {
            if (deferred is not null && d.MessageId == deferred.MessageId)
            {
                await RecordAsync(d, DeliveryOutcome.Deferred, next: Clock.UtcNow + _deferralFarAway, smtp: 451, enhanced: "4.2.0", message: "later");
                ledger.Deferred.Add(d.MessageId);
                continue;
            }

            if (stuck is not null && d.MessageId == stuck.MessageId)
            {
                Assert.True(await Storage.Deliveries.ExtendLeaseAsync(d.DeliveryId, "worker-1", Clock.UtcNow + _longLifetime, CancellationToken.None));
                ledger.Stuck = d.MessageId;
                continue;
            }

            var (message, fail, webhook) = batch.Single(b => b.Message.MessageId == d.MessageId);
            _ = message;
            if (fail)
            {
                await RecordAsync(d, DeliveryOutcome.Failed, smtp: 550, enhanced: "5.1.1", message: "no such user");
            }
            else
            {
                await RecordAsync(d, DeliveryOutcome.Delivered, events: webhook ? [Draft("message.delivered", "{\"id\":\"" + d.MessageId + "\"}")] : null);
            }
        }

        foreach (AcceptedMessage? extra in new[] { deferred, stuck })
        {
            if (extra is not null)
            {
                batch.Add((extra, false, false));
            }
        }

        foreach ((AcceptedMessage m, _, _) in batch)
        {
            int events = IsFull ? (await Storage.History.GetEventsAsync(tenant, m.MessageId, CancellationToken.None)).Count : 0;
            ledger.Messages.Add(new Sent(m.MessageId, tenant, at, m.Content is not null, m.RetainRaw, m.Recipients.Count, events));
        }
    }

    private async Task DispatchWebhooksAsync(Ledger ledger, Guid endpoint)
    {
        _ = endpoint;
        while (true)
        {
            IReadOnlyList<WebhookOutboxItem> items = await Storage.Webhooks.ClaimDueAsync("dispatcher", 50, Clock.UtcNow, TimeSpan.FromMinutes(1), CancellationToken.None);
            if (items.Count == 0)
            {
                return;
            }

            foreach (WebhookOutboxItem item in items)
            {
                await Storage.Webhooks.CompleteAsync(item.Id, new WebhookAttemptRecord(item.Id, Clock.UtcNow, 200, TimeSpan.FromMilliseconds(20), null, "ok"), WebhookOutboxState.Delivered, null, CancellationToken.None);
                ledger.OutboxFinished.Add(Clock.UtcNow);
                ledger.AttemptsAt.Add(Clock.UtcNow);
            }
        }
    }

    private async Task CheckReadSideAsync(Ledger ledger, int metadataDays, string when)
    {
        DateTimeOffset now = Clock.UtcNow;
        if (!IsFull)
        {
            Assert.Empty((await Storage.History.SearchAsync(new MessageQuery(Limit: 500), CancellationToken.None)).Items);
            return;
        }

        // Exactly the messages inside the metadata retention are visible, per tenant, to the second.
        foreach (Guid tenant in new[] { TenantA, TenantB })
        {
            var seen = new HashSet<Guid>();
            string? cursor = null;
            do
            {
                Page<MessageSummary> page = await Storage.History.SearchAsync(new MessageQuery(TenantId: tenant, Limit: 500, Cursor: cursor), CancellationToken.None);
                foreach (MessageSummary s in page.Items)
                {
                    Assert.True(seen.Add(s.MessageId), "search returned a message twice");
                }

                cursor = page.NextCursor;
            }
            while (cursor is not null);

            var expected = ledger.Messages.Where(m => m.Tenant == tenant && Within(now, m.At, metadataDays)).Select(m => m.Id).ToHashSet();
            Assert.True(expected.SetEquals(seen), $"visible messages of tenant {tenant} differ from the model {when}: expected {expected.Count}, saw {seen.Count}");
        }

        // The messages on either side of the two boundaries, in detail.
        int day = StorageTime.DayNumber(now);
        foreach (Sent m in ledger.Messages.Where(m => IsNearBoundary(day, StorageTime.DayNumber(m.At), metadataDays) || IsNearBoundary(day, StorageTime.DayNumber(m.At), ContentDays)))
        {
            MessageDetail? detail = await Storage.History.GetAsync(m.Tenant, m.Id, CancellationToken.None);
            if (!Within(now, m.At, metadataDays))
            {
                Assert.Null(detail);
                Assert.Empty(await Storage.History.GetEventsAsync(m.Tenant, m.Id, CancellationToken.None));
                continue;
            }

            Assert.NotNull(detail);
            bool contentLive = Within(now, m.At, ContentDays);
            ContentState expectedState = !m.HasContent ? ContentState.NotRecorded : contentLive ? ContentState.Available : ContentState.Expired;
            Assert.True(expectedState == detail.ContentState, $"content state of a message received {m.At:O} {when} (now {now:O}): expected {expectedState}, got {detail.ContentState}");
            Assert.Equal(expectedState == ContentState.Available, detail.Content is not null);
            Assert.Equal(m.Events, (await Storage.History.GetEventsAsync(m.Tenant, m.Id, CancellationToken.None)).Count);
            if (m.RawRetained)
            {
                byte[]? raw = await Storage.History.GetRetainedRawAsync(m.Tenant, m.Id, CancellationToken.None);
                Assert.True(contentLive == (raw is not null), $"retained raw of a message received {m.At:O} {when}: live={contentLive}, found={raw is not null}");
            }
        }
    }

    private static bool IsNearBoundary(int today, int messageDay, int retentionDays) =>
        retentionDays > 0 && today - messageDay >= retentionDays - 1 && today - messageDay <= retentionDays;

    private async Task CheckPhysicalAsync(Ledger ledger, int metadataDays, int outboxDays, int attemptDays, string when)
    {
        DateTimeOffset now = Clock.UtcNow;
        if (IsFull)
        {
            var kept = ledger.Messages.Where(m => DayKeyRetained(now, m.At, metadataDays)).ToList();
            await AssertCountAsync(LifecycleTable.MessageIndex, kept.Count, "history rows are deleted by day key: " + when);
            await AssertCountAsync(LifecycleTable.MessageRecipient, kept.Sum(m => m.Recipients), when);
            await AssertCountAsync(LifecycleTable.MessageEvent, kept.Sum(m => m.Events), when);
            await AssertCountAsync(LifecycleTable.MessageContent, ledger.Messages.Count(m => m.HasContent && DayKeyRetained(now, m.At, ContentDays)), "content follows Content:RetentionDays: " + when);
            await AssertCountAsync(LifecycleTable.RawRetained, ledger.Messages.Count(m => m.RawRetained && DayKeyRetained(now, m.At, ContentDays)), when);
        }
        else
        {
            foreach (LifecycleTable t in new[] { LifecycleTable.MessageIndex, LifecycleTable.MessageRecipient, LifecycleTable.MessageEvent, LifecycleTable.MessageContent, LifecycleTable.RawRetained })
            {
                await AssertCountAsync(t, 0, "StatsOnly records no per-message rows: " + when);
            }
        }

        DateTimeOffset outboxCutoff = StorageTime.Normalize(now.AddDays(-outboxDays));
        await AssertCountAsync(LifecycleTable.WebhookOutbox, ledger.OutboxFinished.Count(f => outboxDays <= 0 || f >= outboxCutoff), "finished outbox items go after WebhookOutboxDays: " + when);
        DateTimeOffset attemptCutoff = StorageTime.Normalize(now.AddDays(-attemptDays));
        await AssertCountAsync(LifecycleTable.WebhookAttempt, ledger.AttemptsAt.Count(a => attemptDays <= 0 || a >= attemptCutoff), "attempt log goes after WebhookAttemptLogDays: " + when);
        await AssertCountAsync(LifecycleTable.Idempotency, ledger.IdempotencyExpires.Count(e => e > now), "idempotency keys live for their lifetime: " + when);

        // The live queue is untouched whatever the age: only the long-lived deferred deliveries and the one stuck lease are left.
        await AssertCountAsync(LifecycleTable.DeliveryQueue, ledger.Deferred.Count + (ledger.Stuck is null ? 0 : 1), "final deliveries leave the queue, live ones never do: " + when);
        await AssertCountAsync(LifecycleTable.MessageSpool, ledger.Deferred.Count + (ledger.Stuck is null ? 0 : 1), when);

        IReadOnlyList<RecentEvent> ring = await Storage.Stats.GetRecentEventsAsync(null, 1000, CancellationToken.None);
        Assert.True(ring.Count <= 25, $"the recent-events ring holds {ring.Count} events but is limited to 25 ({when})");
        long? ringRows = await CountRowsAsync(LifecycleTable.RecentEvent);
        Assert.True(ringRows is null or <= 25);
    }

    private async Task CheckLiveQueueAsync(Ledger ledger)
    {
        QueueStats stats = await Storage.Deliveries.GetQueueStatsAsync(CancellationToken.None);
        Assert.Equal(ledger.Deferred.Count, stats.Deferred);
        Assert.Equal(1, stats.Leased);
        Assert.Equal(0, stats.Queued);
        Assert.True(stats.SpoolBytes > 0);
        foreach (Guid id in ledger.Deferred.Append(ledger.Stuck!.Value))
        {
            Assert.NotNull(await Storage.Deliveries.GetRawAsync(id, CancellationToken.None));
        }

        // Far in the future (but before they would expire) every deferred delivery is due and claimable; the stuck lease is still held.
        DateTimeOffset probe = Clock.UtcNow + _deferralFarAway + TimeSpan.FromDays(1);
        IReadOnlyList<ClaimedDelivery> due = await Storage.Deliveries.ClaimAsync("probe", 1000, probe, TimeSpan.FromMinutes(1), CancellationToken.None);
        Assert.Equal(ledger.Deferred.Order(), due.Select(d => d.MessageId).Order());
        Assert.DoesNotContain(due, d => d.MessageId == ledger.Stuck);
        Assert.Equal(ledger.Deferred.Count, await Storage.Deliveries.ReleaseOwnedLeasesAsync("probe", CancellationToken.None));
    }

    [Fact]
    public async Task Lifecycle_retention_windows_are_honored_to_the_second_over_many_days()
    {
        if (!Heavy)
        {
            return;
        }

        await RunHistoryScenarioAsync(metadataDays: 12, outboxDays: 3, attemptDays: 2, days: Accelerated.Scaled(30));
    }

    [Fact]
    public async Task Lifecycle_zero_means_unlimited_for_metadata_outbox_and_attempts_but_content_still_expires()
    {
        if (!Heavy)
        {
            return;
        }

        await RunHistoryScenarioAsync(metadataDays: 0, outboxDays: 0, attemptDays: 0, days: Accelerated.Scaled(20));
        if (IsFull)
        {
            // Nothing but content was ever deleted: every message of the 20 days is still listed.
            Assert.Equal(Math.Min(500, (Accelerated.Scaled(20) * 5) + ((Accelerated.Scaled(20) + 9) / 10) + 1), (await Storage.History.SearchAsync(new MessageQuery(Limit: 500), CancellationToken.None)).Items.Count);
        }
    }
}
