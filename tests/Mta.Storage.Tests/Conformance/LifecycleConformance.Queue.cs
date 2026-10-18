using Mta.Core;
using Mta.TestSupport;

namespace Mta.Storage.Tests;

// Area 2 (storage half): the 5 day queue lifetime with the full retry schedule, expiry claimed exactly once whoever sweeps, lease expiry and release cycles,
// possible_duplicate bookkeeping, and the 24 hour idempotency key lifetime.

public abstract partial class LifecycleConformance
{
    /// <summary>The delays between attempts of the retry schedule: 2m, 5m, 15m, 30m, 1h, 2h, 4h, then every 4h until the message expires.</summary>
    private static TimeSpan RetryDelay(int attemptsMade) => attemptsMade switch
    {
        1 => TimeSpan.FromMinutes(2),
        2 => TimeSpan.FromMinutes(5),
        3 => TimeSpan.FromMinutes(15),
        4 => TimeSpan.FromMinutes(30),
        5 => TimeSpan.FromHours(1),
        6 => TimeSpan.FromHours(2),
        _ => TimeSpan.FromHours(4),
    };

    [Fact]
    public async Task Lifecycle_a_message_deferred_on_every_attempt_is_tried_on_the_schedule_and_expires_exactly_once_at_five_days()
    {
        AcceptedMessage m = await AcceptAsync(Msg(lifetime: TimeSpan.FromDays(5), to: ["slow@example.org"]));
        DateTimeOffset expires = m.ExpiresAt;
        var attemptTimes = new List<DateTimeOffset>();
        DateTimeOffset due = Clock.UtcNow;

        while (due < expires)
        {
            // Not before it is due (one second early: nothing), and never expired early.
            if (attemptTimes.Count > 0)
            {
                Clock.Set(due - TimeSpan.FromSeconds(1));
                Assert.Empty(await ClaimAsync());
                Assert.Empty(await Storage.Deliveries.ClaimExpiredAsync("reaper", 10, Clock.UtcNow, CancellationToken.None));
            }

            Clock.Set(due);
            ClaimedDelivery d = (await ClaimAsync()).Single();
            Assert.Equal(attemptTimes.Count, d.Attempt);
            Assert.False(d.PossibleDuplicate, "a clean schedule never flags a possible duplicate");
            attemptTimes.Add(Clock.UtcNow);
            due = Clock.UtcNow + RetryDelay(attemptTimes.Count);
            await RecordAsync(d, DeliveryOutcome.Deferred, next: due, smtp: 451, enhanced: "4.2.2", message: "mailbox full");
        }

        // The ladder: 2m, 5m, 15m, 30m, 1h, 2h, 4h, then every 4h. 8 attempts take 472 minutes; the rest of the 5 days (7,200 minutes) holds 28 more.
        Assert.Equal(TimeSpan.Zero, attemptTimes[0] - m.ReceivedAt);
        Assert.Equal([2, 5, 15, 30, 60, 120, 240, 240, 240], attemptTimes.Skip(1).Take(9).Select((t, i) => (int)(t - attemptTimes[i]).TotalMinutes));
        Assert.All(attemptTimes.Skip(8).Zip(attemptTimes.Skip(7)), p => Assert.Equal(TimeSpan.FromHours(4), p.First - p.Second));
        Assert.Equal(1 + 7 + 28, attemptTimes.Count);

        // Between the last deferral and the expiry nothing is claimable; at the expiry instant the delivery is no longer a claim but an expired one, exactly once.
        Clock.Set(expires - TimeSpan.FromSeconds(1));
        Assert.Empty(await Storage.Deliveries.ClaimExpiredAsync("reaper-1", 10, Clock.UtcNow, CancellationToken.None));
        Clock.Set(expires);
        Assert.Empty(await ClaimAsync());
        var sweepers = Enumerable.Range(0, 4).Select(i => Task.Run(async () =>
            (await Storage.Deliveries.ClaimExpiredAsync($"reaper-{i}", 10, expires, CancellationToken.None)).ToList())).ToArray();
        List<ClaimedDelivery>[] swept = await Task.WhenAll(sweepers);
        ClaimedDelivery expired = swept.SelectMany(s => s).Single();
        Assert.Equal(m.MessageId, expired.MessageId);
        Assert.Equal(attemptTimes.Count, expired.Attempt);

        // Further sweeps while it is held, and after the owner finished it, find nothing.
        Assert.Empty(await Storage.Deliveries.ClaimExpiredAsync("reaper-late", 10, expires, CancellationToken.None));
        await RecordAsync(expired, DeliveryOutcome.Expired, smtp: null, message: "expired after 5 days", events: [Draft("message.bounced")], countAttempt: false);
        Clock.Advance(TimeSpan.FromDays(1));
        Assert.Empty(await Storage.Deliveries.ClaimExpiredAsync("reaper-late", 10, Clock.UtcNow, CancellationToken.None));
        Assert.Empty(await ClaimAsync());
        await MaintainAsync();
        QueueStats stats = await Storage.Deliveries.GetQueueStatsAsync(CancellationToken.None);
        Assert.Equal((0, 0, 0), (stats.Queued, stats.Leased, stats.Deferred));
        await AssertCountAsync(LifecycleTable.DeliveryQueue, 0, "an expired delivery leaves the queue");
        await AssertCountAsync(LifecycleTable.MessageSpool, 0, "and its spool row");
        if (IsFull)
        {
            MessageDetail detail = (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!;
            Assert.Equal("expired", detail.Summary.Status);
            var events = await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None);
            Assert.Single(events, e => e.Type == MessageEventType.Expired);
        }
    }

    [Fact]
    public async Task Lifecycle_many_deferred_messages_are_each_expired_exactly_once_by_whichever_replica_sweeps_first()
    {
        int count = Accelerated.Scaled(24);
        int seed = LogSeed(20261016);
        var random = new Random(seed);
        var expiry = new Dictionary<Guid, DateTimeOffset>();
        DateTimeOffset origin = Clock.UtcNow;

        // Messages arrive every 37 minutes for the first day; each is deferred on its first attempt and then never delivered.
        for (int i = 0; i < count; i++)
        {
            Clock.Set(origin + TimeSpan.FromMinutes(37 * i));
            AcceptedMessage m = await AcceptAsync(Msg(to: [$"slow{i}@example.org"], lifetime: TimeSpan.FromDays(5) + TimeSpan.FromMinutes(random.Next(0, 600))));
            expiry[m.MessageId] = m.ExpiresAt;
            foreach (ClaimedDelivery d in await ClaimAsync(max: 1000))
            {
                await RecordAsync(d, DeliveryOutcome.Deferred, next: Clock.UtcNow + TimeSpan.FromHours(4), smtp: 451);
            }
        }

        // Sweep every virtual hour for 7 days with three replicas in random order; a message must be expired at the first sweep at or after its expiry and by one replica only.
        var expiredAt = new Dictionary<Guid, DateTimeOffset>();
        DateTimeOffset end = origin + TimeSpan.FromDays(7);
        for (DateTimeOffset t = Clock.UtcNow; t <= end; t += TimeSpan.FromHours(1))
        {
            Clock.Set(t);
            var owners = new[] { "r0", "r1", "r2" }.OrderBy(_ => random.Next()).ToArray();
            var results = await Task.WhenAll(owners.Select(o => Task.Run(async () => (await Storage.Deliveries.ClaimExpiredAsync(o, 100, t, CancellationToken.None)).ToList())));
            foreach (ClaimedDelivery d in results.SelectMany(r => r))
            {
                Assert.True(expiredAt.TryAdd(d.MessageId, t), $"message {d.MessageId} was handed to two sweepers");
                Assert.True(expiry[d.MessageId] <= t, "expired before its time");
                Assert.True(expiry[d.MessageId] > t - TimeSpan.FromHours(1), "expired later than the first sweep after its expiry");
                await RecordAsync(d, DeliveryOutcome.Expired, message: "expired", countAttempt: false);
            }

            // Whatever is due and not expired is claimed and deferred again, as the engine would.
            foreach (ClaimedDelivery d in await ClaimAsync(max: 1000))
            {
                await RecordAsync(d, DeliveryOutcome.Deferred, next: t + TimeSpan.FromHours(4), smtp: 451);
            }

            if ((t - origin).TotalHours % 12 == 0)
            {
                await MaintainAsync();   // maintenance is interleaved with the sweeps and must not touch live or leased deliveries
            }
        }

        Assert.Equal(count, expiredAt.Count);
        QueueStats stats = await Storage.Deliveries.GetQueueStatsAsync(CancellationToken.None);
        Assert.Equal((0, 0, 0), (stats.Queued, stats.Leased, stats.Deferred));
    }

    [Fact]
    public async Task Lifecycle_lease_cycles_of_a_worker_that_keeps_dying_flag_a_possible_duplicate_without_inflating_attempts_or_events()
    {
        AcceptedMessage m = await AcceptAsync(Msg(to: ["flaky@example.org"]));
        int cycles = Accelerated.Scaled(120);
        TimeSpan lease = TimeSpan.FromMinutes(1);
        bool takeoverWithoutRelease = false;

        for (int i = 0; i < cycles; i++)
        {
            ClaimedDelivery d = (await Storage.Deliveries.ClaimAsync($"worker-{i}", 10, Clock.UtcNow, lease, CancellationToken.None)).Single();
            Assert.Equal(i > 0, d.PossibleDuplicate);
            Assert.Equal(0, d.Attempt);   // nobody reported: no attempt is counted

            // A heartbeat keeps the lease: just before the end it is extended, so the new holder still cannot claim.
            Clock.Advance(lease - TimeSpan.FromSeconds(1));
            Assert.Empty(await Storage.Deliveries.ClaimAsync("thief", 10, Clock.UtcNow, lease, CancellationToken.None));
            Assert.True(await Storage.Deliveries.ExtendLeaseAsync(d.DeliveryId, $"worker-{i}", Clock.UtcNow + lease, CancellationToken.None));
            Assert.False(await Storage.Deliveries.ExtendLeaseAsync(d.DeliveryId, "somebody-else", Clock.UtcNow + lease, CancellationToken.None));
            Clock.Advance(lease - TimeSpan.FromSeconds(1));
            Assert.Empty(await Storage.Deliveries.ClaimAsync("thief", 10, Clock.UtcNow, lease, CancellationToken.None));
            Assert.Equal(0, await Storage.Deliveries.ReleaseExpiredLeasesAsync(Clock.UtcNow, CancellationToken.None));

            // The worker dies. At the exact end of the lease the delivery is free again; the next cycle either releases it first (maintenance) or just takes it over.
            Clock.Advance(TimeSpan.FromSeconds(1));
            takeoverWithoutRelease = i % 2 == 1;
            if (!takeoverWithoutRelease)
            {
                Assert.Equal(1, await Storage.Deliveries.ReleaseExpiredLeasesAsync(Clock.UtcNow, CancellationToken.None));
                Assert.Equal(0, await Storage.Deliveries.ReleaseExpiredLeasesAsync(Clock.UtcNow, CancellationToken.None));
            }

            // Over many hours of such cycles the maintenance job runs too, and must not disturb a lease that is still held.
            if (i % 10 == 0)
            {
                await MaintainAsync();
            }
        }

        ClaimedDelivery last = (await ClaimAsync()).Single();
        Assert.True(last.PossibleDuplicate);
        await Storage.Deliveries.RecordAttemptAsync(Attempt(last, DeliveryOutcome.Delivered, possibleDuplicate: true), CancellationToken.None);
        if (IsFull)
        {
            var events = await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None);
            Assert.True(events.Count <= 4, $"{cycles} lease cycles wrote {events.Count} events");
            Assert.Equal("delivered", (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.Summary.Status);
        }

        Assert.Empty(await ClaimAsync());
    }

    [Fact]
    public async Task Lifecycle_an_idempotency_key_blocks_a_repeat_for_24_hours_and_not_a_second_longer()
    {
        const string key = "order-4711";
        TimeSpan lifetime = Options.Queue.IdempotencyKeyLifetime;
        AcceptedMessage first = await AcceptAsync(Msg(idempotencyKey: key));
        DateTimeOffset t0 = Clock.UtcNow;

        // The same key for another tenant is independent; a repeat inside the lifetime returns the first message.
        await AcceptAsync(Msg(tenant: TenantB, idempotencyKey: key));
        Clock.Set(t0 + lifetime - TimeSpan.FromSeconds(1));
        await MaintainAsync();   // maintenance must not free a key that is still live
        IntakeResult repeat = await Storage.Intake.AcceptAsync(Msg(idempotencyKey: key), CancellationToken.None);
        Assert.Equal(IntakeStatus.DuplicateIdempotencyKey, repeat.Status);
        Assert.Equal(first.MessageId, repeat.MessageId);
        await AssertCountAsync(LifecycleTable.Idempotency, 2, "two live keys");

        // At the end of the lifetime the key is free, before any maintenance ran.
        Clock.Set(t0 + lifetime);
        AcceptedMessage second = Msg(idempotencyKey: key);
        IntakeResult reused = await Storage.Intake.AcceptAsync(second, CancellationToken.None);
        Assert.Equal(IntakeStatus.Accepted, reused.Status);
        Assert.Equal(second.MessageId, reused.MessageId);

        // Its lifetime starts again from the new acceptance; tenant B's key expired too and maintenance removes the expired rows only.
        Clock.Set(t0 + lifetime + lifetime - TimeSpan.FromSeconds(1));
        Assert.Equal(IntakeStatus.DuplicateIdempotencyKey, (await Storage.Intake.AcceptAsync(Msg(idempotencyKey: key), CancellationToken.None)).Status);
        await MaintainAsync();
        await AssertCountAsync(LifecycleTable.Idempotency, 1, "tenant B's key and the first of A's are gone, the renewed key stays");
        Clock.Advance(TimeSpan.FromSeconds(1));
        await MaintainAsync();
        await AssertCountAsync(LifecycleTable.Idempotency, 0, "all expired");
    }

    [Fact]
    public async Task Lifecycle_a_key_used_every_day_for_many_days_never_accumulates_rows()
    {
        int days = Accelerated.Scaled(40);
        for (int day = 0; day < days; day++)
        {
            for (int j = 0; j < 3; j++)
            {
                IntakeResult r = await Storage.Intake.AcceptAsync(Msg(idempotencyKey: $"daily-{j}"), CancellationToken.None);
                Assert.Equal(IntakeStatus.Accepted, r.Status);
                Assert.Equal(IntakeStatus.DuplicateIdempotencyKey, (await Storage.Intake.AcceptAsync(Msg(idempotencyKey: $"daily-{j}"), CancellationToken.None)).Status);
            }

            foreach (ClaimedDelivery d in await ClaimAsync(max: 100))
            {
                await RecordAsync(d, DeliveryOutcome.Delivered);
            }

            await MaintainAsync();
            await AssertCountAsync(LifecycleTable.Idempotency, 3, "only today's keys are live after maintenance");
            Clock.Advance(Day);
        }
    }

    [Fact]
    public async Task Lifecycle_a_large_backlog_of_expired_rows_is_cleaned_in_batches_while_intake_and_claims_carry_on()
    {
        if (!Heavy)
        {
            return;
        }

        await OpenAsync(Opts(retention: new RetentionOptions { MetadataDays = 12, WebhookOutboxDays = 3, WebhookAttemptLogDays = 3, StatsHourlyDays = 5, StatsDailyDays = 0 }, content: new ContentOptions { RetentionDays = 6 }));
        Guid endpoint = await AddEndpointAsync(TenantA, true, "*");
        _ = endpoint;

        // A backlog nobody cleaned for 60 days: 3 days of traffic, every message with a webhook event, all finished.
        int perDay = Accelerated.Scaled(40);
        for (int day = 0; day < 3; day++)
        {
            Clock.Set(Start.AddDays(day));
            for (int i = 0; i < perDay; i++)
            {
                await AcceptAsync(Msg(to: [$"old{day}-{i}@example.org"], size: 200));
                Storage.Stats.Add(new StatKey(Clock.UtcNow, TenantA, "s.example", $"dom{i % 12}.example"), StatCounter.Accepted, 1);
            }

            foreach (ClaimedDelivery d in await ClaimAsync(max: 1000))
            {
                await RecordAsync(d, DeliveryOutcome.Delivered, events: [Draft("message.delivered")]);
            }

            foreach (WebhookOutboxItem item in await DueAsync("dispatcher", Clock.UtcNow, max: 1000))
            {
                await Storage.Webhooks.CompleteAsync(item.Id, new WebhookAttemptRecord(item.Id, Clock.UtcNow, 200, TimeSpan.FromMilliseconds(2), null, null), WebhookOutboxState.Delivered, null, CancellationToken.None);
            }
        }

        await FlushStatsAsync();

        // Sixty days later the first maintenance run has everything to do, while the application keeps working.
        Clock.Set(Start.AddDays(63));
        var fresh = new List<Guid>();
        Task<IReadOnlyList<MaintenanceReport>> maintenance = Task.Run(async () => await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None).AsTask());
        for (int i = 0; i < 25; i++)
        {
            AcceptedMessage m = await AcceptAsync(Msg(to: [$"new{i}@example.org"], size: 200));
            fresh.Add(m.MessageId);
            foreach (ClaimedDelivery d in await ClaimAsync(max: 100))
            {
                await RecordAsync(d, DeliveryOutcome.Delivered);
            }
        }

        Task finished = await Task.WhenAny(maintenance, Task.Delay(TimeSpan.FromMinutes(2)));   // a hang becomes a failure; the bound is not an assertion about speed
        Assert.Same(maintenance, finished);
        IReadOnlyList<MaintenanceReport> reports = await maintenance;
        Assert.All(reports, r => Assert.True(RetentionJobs.Contains(r.Job) || HousekeepingJobs.Contains(r.Job)));
        Assert.True(reports.Single(r => r.Job == "retention.webhook_outbox").RowsAffected >= 3 * perDay);
        Assert.True(reports.Single(r => r.Job == "retention.webhook_attempts").RowsAffected >= 3 * perDay);

        // The old rows are gone, the new ones are intact, the queue is empty.
        await MaintainAsync();
        await AssertCountAsync(LifecycleTable.WebhookOutbox, 0, "the finished backlog is gone");
        await AssertCountAsync(LifecycleTable.WebhookAttempt, 0, "and its attempts");
        if (IsFull)
        {
            await AssertCountAsync(LifecycleTable.MessageIndex, fresh.Count, "only the fresh messages remain in the history");
            var seen = (await Storage.History.SearchAsync(new MessageQuery(Limit: 500), CancellationToken.None)).Items.Select(i => i.MessageId).Order();
            Assert.Equal(fresh.Order(), seen);
        }

        QueueStats stats = await Storage.Deliveries.GetQueueStatsAsync(CancellationToken.None);
        Assert.Equal((0, 0, 0), (stats.Queued, stats.Leased, stats.Deferred));
        Assert.Empty(await ClaimAsync());
    }
}
