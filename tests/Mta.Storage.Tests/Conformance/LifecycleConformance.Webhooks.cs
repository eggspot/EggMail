using Mta.Core;
using Mta.TestSupport;

namespace Mta.Storage.Tests;

// Area 7 (storage half): the webhook outbox through its whole life: the retry ladder up to the last attempt, replay, the retention of finished items and of the attempt log,
// pending and leased items that cleanup must never touch, and dispatchers that claim concurrently.

public abstract partial class LifecycleConformance
{
    /// <summary>The webhook retry schedule (decision 16): immediately, then 5 s, 5 m, 30 m, 2 h, 5 h, 10 h, 10 h. Eight attempts in all.</summary>
    private static readonly TimeSpan[] WebhookLadder =
    [
        TimeSpan.Zero,
        TimeSpan.FromSeconds(5),
        TimeSpan.FromMinutes(5),
        TimeSpan.FromMinutes(30),
        TimeSpan.FromHours(2),
        TimeSpan.FromHours(5),
        TimeSpan.FromHours(10),
        TimeSpan.FromHours(10),
    ];

    private async Task<int> EnqueueDeliveredEventsAsync(Guid tenant, int count, string tag)
    {
        for (int i = 0; i < count; i++)
        {
            await AcceptAsync(Msg(tenant: tenant, to: [$"{tag}{i}@example.org"]));
        }

        int events = 0;
        foreach (ClaimedDelivery d in await ClaimAsync(max: 1000))
        {
            await RecordAsync(d, DeliveryOutcome.Delivered, events: [Draft("message.delivered", $"{{\"to\":\"{d.Recipient.LocalPart}\"}}")]);
            events++;
        }

        return events;
    }

    private async Task<IReadOnlyList<WebhookOutboxItem>> DueAsync(string owner, DateTimeOffset at, int max = 100, TimeSpan? lease = null) =>
        await Storage.Webhooks.ClaimDueAsync(owner, max, at, lease ?? TimeSpan.FromSeconds(30), CancellationToken.None);

    private static WebhookAttemptRecord Failure(WebhookOutboxItem item, DateTimeOffset at) =>
        new(item.Id, at, 503, TimeSpan.FromMilliseconds(40), "http_5xx", "service unavailable");

    [Fact]
    public async Task Lifecycle_a_failing_endpoint_is_retried_on_the_ladder_then_failed_replayed_and_cleaned_up_on_schedule()
    {
        await OpenAsync(Opts(retention: new RetentionOptions { WebhookOutboxDays = 7, WebhookAttemptLogDays = 3, StatsHourlyDays = 0, StatsDailyDays = 0, MetadataDays = 0 }));
        Guid endpoint = await AddEndpointAsync(TenantA, true, "*");
        Assert.Equal(1, await EnqueueDeliveredEventsAsync(TenantA, 1, "w"));
        DateTimeOffset t0 = Clock.UtcNow;
        var attemptAt = new List<DateTimeOffset>();
        DateTimeOffset due = t0;
        Guid itemId = default;

        for (int k = 0; k < WebhookLadder.Length; k++)
        {
            if (k > 0)
            {
                Clock.Set(due - TimeSpan.FromSeconds(1));
                Assert.Empty(await DueAsync("early", Clock.UtcNow));
            }

            Clock.Set(due);
            var racers = await Task.WhenAll(new[] { "dispatcher-1", "dispatcher-2", "dispatcher-3" }.Select(o => Task.Run(async () => (await DueAsync(o, due)).ToList())));
            WebhookOutboxItem item = racers.SelectMany(r => r).Single();
            itemId = item.Id;
            Assert.Equal(k, item.Attempt);
            attemptAt.Add(Clock.UtcNow);

            // While it is leased nobody else gets it; when the lease (30 s) has run out without a result, it is claimable again, and the attempt count is unchanged.
            Assert.Empty(await DueAsync("other", due + TimeSpan.FromSeconds(29)));
            if (k == 3)
            {
                WebhookOutboxItem crashed = (await DueAsync("dispatcher-after-crash", due + TimeSpan.FromSeconds(30))).Single();
                Assert.Equal(k, crashed.Attempt);
            }

            if (k < WebhookLadder.Length - 1)
            {
                due = Clock.UtcNow + WebhookLadder[k + 1];
                await Storage.Webhooks.CompleteAsync(item.Id, Failure(item, Clock.UtcNow), WebhookOutboxState.Pending, due, CancellationToken.None);
            }
            else
            {
                await Storage.Webhooks.CompleteAsync(item.Id, Failure(item, Clock.UtcNow), WebhookOutboxState.Failed, null, CancellationToken.None);
            }
        }

        // 0, 5 s, 5 m 5 s, 35 m 5 s, 2 h 35 m 5 s, 7 h 35 m 5 s, 17 h 35 m 5 s, 27 h 35 m 5 s after the first.
        Assert.Equal([0, 5, 305, 2105, 9305, 27305, 63305, 99305], attemptAt.Select(a => (long)(a - t0).TotalSeconds));
        var log = await Storage.Webhooks.GetAttemptsAsync(TenantA, endpoint, 100, CancellationToken.None);
        Assert.Equal(attemptAt.AsEnumerable().Reverse(), log.Select(a => a.At));
        DateTimeOffset failedAt = Clock.UtcNow;

        // Failed is final: nothing claims it, however long we wait, until cleanup removes it.
        Assert.Empty(await DueAsync("late", failedAt + TimeSpan.FromDays(2)));

        // The attempt log keeps 3 days: with the clock between the 4th and 5th attempt (3 days later) the first four attempts are gone and the other four remain.
        Clock.Set(t0 + TimeSpan.FromDays(3) + TimeSpan.FromSeconds(2105 + 4600));
        await MaintainAsync();
        Assert.Equal(4, (await Storage.Webhooks.GetAttemptsAsync(TenantA, endpoint, 100, CancellationToken.None)).Count);
        await AssertCountAsync(LifecycleTable.WebhookAttempt, 4, "the attempt log is cut at the second");

        // A replay starts again from attempt 0, immediately, with the lifetime of the outbox row restarting from the next finish.
        Assert.True(await Storage.Webhooks.ReplayAsync(TenantA, itemId, Clock.UtcNow, CancellationToken.None));
        WebhookOutboxItem replayed = (await DueAsync("replayer", Clock.UtcNow)).Single();
        Assert.Equal(0, replayed.Attempt);
        await Storage.Webhooks.CompleteAsync(replayed.Id, new WebhookAttemptRecord(replayed.Id, Clock.UtcNow, 200, TimeSpan.FromMilliseconds(30), null, "ok"), WebhookOutboxState.Delivered, null, CancellationToken.None);
        DateTimeOffset deliveredAt = Clock.UtcNow;

        // The finished row is kept for exactly 7 days after it finished: still replayable at the 7th day, gone one second later.
        Clock.Set(deliveredAt + TimeSpan.FromDays(7));
        await MaintainAsync();
        await AssertCountAsync(LifecycleTable.WebhookOutbox, 1, "kept for the whole retention");
        Clock.Advance(TimeSpan.FromSeconds(1));
        await MaintainAsync();
        await AssertCountAsync(LifecycleTable.WebhookOutbox, 0, "gone one second after the retention");
        Assert.False(await Storage.Webhooks.ReplayAsync(TenantA, itemId, Clock.UtcNow, CancellationToken.None));
        Assert.Empty(await Storage.Webhooks.GetAttemptsAsync(TenantA, endpoint, 100, CancellationToken.None));
    }

    [Fact]
    public async Task Lifecycle_pending_and_leased_webhook_items_survive_cleanup_for_as_long_as_they_wait()
    {
        await OpenAsync(Opts(retention: new RetentionOptions { WebhookOutboxDays = 3, WebhookAttemptLogDays = 2, StatsHourlyDays = 0, StatsDailyDays = 0, MetadataDays = 0 }));
        Guid endpoint = await AddEndpointAsync(TenantA, true, "*");
        Assert.Equal(3, await EnqueueDeliveredEventsAsync(TenantA, 3, "p"));
        DateTimeOffset t0 = Clock.UtcNow;
        var items = (await DueAsync("dispatcher", t0, lease: TimeSpan.FromDays(30))).OrderBy(i => i.Id).ToList();
        Assert.Equal(3, items.Count);

        // One is retried only in 20 days, one was claimed by a dispatcher that died (30 day lease), one is finished and will be cleaned.
        DateTimeOffset retryAt = t0 + TimeSpan.FromDays(20);
        await Storage.Webhooks.CompleteAsync(items[0].Id, Failure(items[0], t0), WebhookOutboxState.Pending, retryAt, CancellationToken.None);
        await Storage.Webhooks.CompleteAsync(items[2].Id, new WebhookAttemptRecord(items[2].Id, t0, 200, TimeSpan.FromMilliseconds(5), null, null), WebhookOutboxState.Delivered, null, CancellationToken.None);

        for (int day = 1; day <= 15; day++)
        {
            Clock.Set(t0 + TimeSpan.FromDays(day));
            await MaintainAsync();
            Assert.Empty(await DueAsync("scanner", Clock.UtcNow));   // neither is due; the pending one is not "stale", the leased one is not free
        }

        await AssertCountAsync(LifecycleTable.WebhookOutbox, 2, "the delivered item went after 3 days, the waiting and the leased ones are kept");
        await AssertCountAsync(LifecycleTable.WebhookAttempt, 0, "only attempts older than 2 days go, and all of them are");

        // The pending one is claimable exactly at its time; the leased one once its lease ran out.
        Assert.Empty(await DueAsync("scanner", retryAt - TimeSpan.FromSeconds(1)));
        WebhookOutboxItem retried = (await DueAsync("scanner", retryAt)).Single();
        Assert.Equal(items[0].Id, retried.Id);
        Assert.Equal(1, retried.Attempt);
        await Storage.Webhooks.CompleteAsync(retried.Id, new WebhookAttemptRecord(retried.Id, retryAt, 200, TimeSpan.FromMilliseconds(5), null, null), WebhookOutboxState.Delivered, null, CancellationToken.None);
        Assert.Equal(items[1].Id, (await DueAsync("scanner", t0 + TimeSpan.FromDays(30))).Single().Id);
        _ = endpoint;
    }

    [Fact]
    public async Task Lifecycle_concurrent_dispatchers_never_work_on_the_same_item_and_every_item_is_finished_once()
    {
        int items = Accelerated.Scaled(60);
        int seed = LogSeed(20261017);
        await AddEndpointAsync(TenantA, true, "*");
        Assert.Equal(items, await EnqueueDeliveredEventsAsync(TenantA, items, "c"));
        var claimedBy = new System.Collections.Concurrent.ConcurrentDictionary<Guid, string>();
        var finished = new System.Collections.Concurrent.ConcurrentBag<Guid>();
        DateTimeOffset now = Clock.UtcNow;

        async Task Worker(string name, int salt)
        {
            var random = new Random(seed + salt);
            while (true)
            {
                var batch = await Storage.Webhooks.ClaimDueAsync(name, random.Next(1, 9), now, TimeSpan.FromMinutes(5), CancellationToken.None);
                if (batch.Count == 0)
                {
                    return;
                }

                foreach (WebhookOutboxItem item in batch)
                {
                    Assert.True(claimedBy.TryAdd(item.Id, name), $"{item.Id} was claimed by {claimedBy.GetValueOrDefault(item.Id)} and by {name}");
                    await Storage.Webhooks.CompleteAsync(item.Id, new WebhookAttemptRecord(item.Id, now, 200, TimeSpan.FromMilliseconds(3), null, null), WebhookOutboxState.Delivered, null, CancellationToken.None);
                    finished.Add(item.Id);
                }
            }
        }

        await Task.WhenAll(Worker("w1", 1), Worker("w2", 2), Worker("w3", 3), Worker("w4", 4));
        Assert.Equal(items, claimedBy.Count);
        Assert.Equal(items, finished.Distinct().Count());
        Assert.Empty(await DueAsync("after", now + TimeSpan.FromDays(1)));
    }
}
