using Mta.Core;

namespace Mta.Storage.Tests;

/// <summary>Claiming, leases, expiry and recording attempts for every outcome.</summary>
public abstract class DeliveryConformance : StorageTestBase
{
    // Claiming

    [Fact]
    public async Task Claim_returns_only_due_deliveries_oldest_first()
    {
        var early = await AcceptAsync(Msg(received: Start, to: ["early@example.org"]));
        var late = await AcceptAsync(Msg(received: Start.AddMinutes(10), to: ["late@example.org"]));
        var mid = await AcceptAsync(Msg(received: Start.AddMinutes(5), to: ["mid@example.org"]));

        var first = await ClaimAsync(now: Start.AddMinutes(6), lease: TimeSpan.FromDays(1));
        Assert.Equal([early.MessageId, mid.MessageId], first.Select(c => c.MessageId));

        var second = await ClaimAsync(now: Start.AddMinutes(11));
        Assert.Equal([late.MessageId], second.Select(c => c.MessageId));
    }

    [Fact]
    public async Task Claim_honours_max_and_returns_nothing_when_empty()
    {
        Assert.Empty(await ClaimAsync());
        for (int i = 0; i < 5; i++)
        {
            await AcceptAsync(Msg(received: Start.AddSeconds(i)));
        }

        Clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(2, (await ClaimAsync(max: 2)).Count);
        Assert.Equal(3, (await ClaimAsync(max: 10)).Count);
        Assert.Empty(await ClaimAsync(max: 10));
        Assert.Empty(await ClaimAsync(max: 0));
    }

    [Fact]
    public async Task Claimed_delivery_carries_a_lease_and_is_not_claimed_again_until_it_expires()
    {
        await AcceptAsync();
        var claimed = (await ClaimAsync(lease: TimeSpan.FromMinutes(1))).Single();
        Assert.Equal(Start.AddMinutes(1), claimed.LeaseUntil);

        Assert.Empty(await ClaimAsync(owner: "worker-2"));
        Clock.Advance(TimeSpan.FromSeconds(59));
        Assert.Empty(await ClaimAsync(owner: "worker-2"));

        Clock.Advance(TimeSpan.FromSeconds(2));
        var again = (await ClaimAsync(owner: "worker-2")).Single();
        Assert.Equal(claimed.DeliveryId, again.DeliveryId);
        Assert.Equal(0, again.Attempt);
    }

    [Fact]
    public async Task Parallel_workers_never_claim_the_same_delivery()
    {
        const int messages = 60;
        for (int i = 0; i < messages; i++)
        {
            await AcceptAsync(Msg(to: [$"a{i}@example.org", $"b{i}@example.org", $"c{i}@example.org", $"d{i}@example.org"], size: 256));
        }

        var claimedIds = new System.Collections.Concurrent.ConcurrentBag<Guid>();
        var workers = Enumerable.Range(0, 8).Select(w => Task.Run(async () =>
        {
            while (true)
            {
                var batch = await ClaimAsync(max: 7, owner: "w" + w);
                if (batch.Count == 0)
                {
                    return;
                }

                foreach (var d in batch)
                {
                    claimedIds.Add(d.DeliveryId);
                }
            }
        }));
        await Task.WhenAll(workers);

        Assert.Equal(messages * 4, claimedIds.Count);
        Assert.Equal(messages * 4, claimedIds.Distinct().Count());
    }

    [Fact]
    public async Task ExtendLease_requires_the_owner()
    {
        await AcceptAsync();
        var d = (await ClaimAsync(lease: TimeSpan.FromMinutes(1))).Single();

        Assert.False(await Storage.Deliveries.ExtendLeaseAsync(d.DeliveryId, "someone-else", Start.AddHours(1), CancellationToken.None));
        Assert.False(await Storage.Deliveries.ExtendLeaseAsync(Ids.New(), "worker-1", Start.AddHours(1), CancellationToken.None));
        Assert.True(await Storage.Deliveries.ExtendLeaseAsync(d.DeliveryId, "worker-1", Start.AddMinutes(30), CancellationToken.None));

        Clock.Advance(TimeSpan.FromMinutes(5));
        Assert.Empty(await ClaimAsync(owner: "worker-2"));
        Clock.Advance(TimeSpan.FromMinutes(26));
        Assert.Single(await ClaimAsync(owner: "worker-2"));
    }

    [Fact]
    public async Task ReleaseOwnedLeases_makes_the_deliveries_claimable_without_counting_an_attempt()
    {
        await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"]));
        var claimed = await ClaimAsync(owner: "worker-1", max: 1);
        Assert.Single(claimed);
        await ClaimAsync(owner: "worker-2", max: 1);

        Assert.Equal(1, await Storage.Deliveries.ReleaseOwnedLeasesAsync("worker-1", CancellationToken.None));
        Assert.Equal(0, await Storage.Deliveries.ReleaseOwnedLeasesAsync("nobody", CancellationToken.None));

        var again = await ClaimAsync(owner: "worker-3");
        Assert.Equal(claimed.Single().DeliveryId, again.Single().DeliveryId);
        Assert.Equal(0, again.Single().Attempt);
    }

    [Fact]
    public async Task A_delivery_whose_holder_never_reported_is_flagged_possible_duplicate_when_it_is_claimed_again()
    {
        await AcceptAsync(Msg(to: ["a@example.org"]));
        var first = Assert.Single(await ClaimAsync(owner: "worker-1", lease: TimeSpan.FromMinutes(1)));
        Assert.False(first.PossibleDuplicate);

        Clock.Advance(TimeSpan.FromMinutes(2));                         // the holder died: its lease simply expires
        var second = Assert.Single(await ClaimAsync(owner: "worker-2"));

        Assert.Equal(first.DeliveryId, second.DeliveryId);
        Assert.True(second.PossibleDuplicate, "the first holder may have sent the message before it died");
    }

    [Fact]
    public async Task Releasing_expired_leases_flags_possible_duplicate_but_a_graceful_release_does_not()
    {
        await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"]));
        var claimed = await ClaimAsync(owner: "worker-1", max: 2, lease: TimeSpan.FromMinutes(1));
        Assert.Equal(2, claimed.Count);
        Assert.Equal(2, await Storage.Deliveries.ReleaseOwnedLeasesAsync("worker-1", CancellationToken.None));
        var graceful = await ClaimAsync(owner: "worker-2", max: 2, lease: TimeSpan.FromMinutes(1));
        Assert.All(graceful, d => Assert.False(d.PossibleDuplicate));

        Clock.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(2, await Storage.Deliveries.ReleaseExpiredLeasesAsync(Clock.UtcNow, CancellationToken.None));
        var afterCrash = await ClaimAsync(owner: "worker-3", max: 2);
        Assert.All(afterCrash, d => Assert.True(d.PossibleDuplicate));
    }

    [Fact]
    public async Task ReleaseExpiredLeases_only_touches_expired_leases()
    {
        await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"]));
        await ClaimAsync(max: 1, lease: TimeSpan.FromMinutes(1));
        await ClaimAsync(max: 1, lease: TimeSpan.FromMinutes(10), owner: "worker-2");
        Clock.Advance(TimeSpan.FromMinutes(2));

        Assert.Equal(1, await Storage.Deliveries.ReleaseExpiredLeasesAsync(Clock.UtcNow, CancellationToken.None));
        QueueStats stats = await Storage.Deliveries.GetQueueStatsAsync(CancellationToken.None);
        Assert.Equal(1, stats.Leased);
        Assert.Equal(1, stats.Queued);
    }

    [Fact]
    public async Task Expired_deliveries_are_claimed_by_ClaimExpired_not_ClaimAsync()
    {
        var m = await AcceptAsync(Msg(lifetime: TimeSpan.FromHours(1)));
        Assert.Empty(await Storage.Deliveries.ClaimExpiredAsync("reaper", 10, Clock.UtcNow, CancellationToken.None));

        Clock.Advance(TimeSpan.FromHours(2));
        Assert.Empty(await ClaimAsync());

        var expired = await Storage.Deliveries.ClaimExpiredAsync("reaper", 10, Clock.UtcNow, CancellationToken.None);
        Assert.Equal(m.MessageId, expired.Single().MessageId);
        Assert.Empty(await Storage.Deliveries.ClaimExpiredAsync("reaper-2", 10, Clock.UtcNow, CancellationToken.None));

        await RecordAsync(expired.Single(), DeliveryOutcome.Expired, message: "queue lifetime exceeded");
        Assert.Equal(0, (await Storage.Deliveries.GetQueueStatsAsync(CancellationToken.None)).Queued);
        Assert.Null(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));
    }

    [Fact]
    public async Task ClaimExpired_skips_deliveries_that_are_currently_leased()
    {
        await AcceptAsync(Msg(lifetime: TimeSpan.FromHours(1)));
        var claimed = await ClaimAsync(lease: TimeSpan.FromHours(3));
        Assert.Single(claimed);
        Clock.Advance(TimeSpan.FromHours(2));
        Assert.Empty(await Storage.Deliveries.ClaimExpiredAsync("reaper", 10, Clock.UtcNow, CancellationToken.None));
    }

    [Fact]
    public async Task QueueStats_reports_queued_leased_deferred_and_oldest_due()
    {
        await AcceptAsync(Msg(received: Start, to: ["a@example.org"], size: 1000));
        await AcceptAsync(Msg(received: Start.AddMinutes(1), to: ["b@example.org"], size: 500));
        await AcceptAsync(Msg(received: Start.AddMinutes(2), to: ["c@example.org"], size: 250));
        Clock.Advance(TimeSpan.FromMinutes(3));

        var first = (await ClaimAsync(max: 1)).Single();
        var second = (await ClaimAsync(max: 1)).Single();
        await RecordAsync(second, DeliveryOutcome.Deferred, next: Clock.UtcNow.AddHours(1), smtp: 451, enhanced: "4.7.1");

        QueueStats s = await Storage.Deliveries.GetQueueStatsAsync(CancellationToken.None);
        Assert.Equal(1, s.Queued);
        Assert.Equal(1, s.Leased);
        Assert.Equal(1, s.Deferred);
        Assert.Equal(1750, s.SpoolBytes);
        Assert.Equal(Start.AddMinutes(2), s.OldestDueAt);
        _ = first;
    }

    // Recording attempts

    [Fact]
    public async Task Delivered_removes_the_delivery_and_frees_the_spool_with_the_last_recipient()
    {
        var m = await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"]));
        var claimed = await ClaimAsync();

        await RecordAsync(claimed[0], DeliveryOutcome.Delivered, smtp: 250);
        Assert.NotNull(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));
        Assert.Equal(1, (await Storage.Deliveries.GetQueueStatsAsync(CancellationToken.None)).Leased);

        await RecordAsync(claimed[1], DeliveryOutcome.Delivered, smtp: 250);
        Assert.Null(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));
        QueueStats s = await Storage.Deliveries.GetQueueStatsAsync(CancellationToken.None);
        Assert.Equal(0, s.Leased + s.Queued + s.Deferred);
        Assert.Equal(0, s.SpoolBytes);
    }

    [Fact]
    public async Task Recording_the_same_attempt_twice_is_harmless()
    {
        var m = await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"]));
        var claimed = await ClaimAsync();
        await RecordAsync(claimed[0], DeliveryOutcome.Delivered);
        await RecordAsync(claimed[0], DeliveryOutcome.Delivered);
        Assert.NotNull(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));
        await RecordAsync(claimed[1], DeliveryOutcome.Delivered);
        Assert.Null(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));
    }

    [Fact]
    public async Task Recording_an_unknown_delivery_does_nothing()
    {
        await Storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = Ids.New(), Outcome = DeliveryOutcome.Delivered, At = Clock.UtcNow }, CancellationToken.None);
    }

    [Fact]
    public async Task Deferred_reschedules_with_an_incremented_attempt_and_the_error()
    {
        await AcceptAsync();
        var d = (await ClaimAsync()).Single();
        DateTimeOffset retryAt = Start.AddMinutes(5);
        await RecordAsync(d, DeliveryOutcome.Deferred, next: retryAt, smtp: 451, enhanced: "4.2.1", message: "mailbox busy");

        Assert.Empty(await ClaimAsync(owner: "worker-2"));
        Clock.Set(retryAt.AddSeconds(-1));
        Assert.Empty(await ClaimAsync(owner: "worker-2"));
        Clock.Set(retryAt);
        var again = (await ClaimAsync(owner: "worker-2")).Single();
        Assert.Equal(d.DeliveryId, again.DeliveryId);
        Assert.Equal(1, again.Attempt);
        Assert.Contains("451", again.LastError);
        Assert.Contains("mailbox busy", again.LastError);

        await RecordAsync(again, DeliveryOutcome.Deferred, next: retryAt.AddMinutes(30));
        Clock.Set(retryAt.AddMinutes(30));
        Assert.Equal(2, (await ClaimAsync()).Single().Attempt);
    }

    [Fact]
    public async Task An_uncounted_hold_only_reschedules_the_row()
    {
        await AddEndpointAsync(TenantA, true, "*");
        var m = await AcceptAsync();
        var d = (await ClaimAsync()).Single();
        DateTimeOffset retryAt = Start.AddMinutes(5);
        await RecordAsync(d, DeliveryOutcome.Deferred, next: retryAt, countAttempt: false, message: "rate limited", events: [Draft("message.deferred")]);

        Assert.Empty(await ClaimAsync(owner: "worker-2"));
        Clock.Set(retryAt);
        var again = (await ClaimAsync(owner: "worker-2")).Single();
        Assert.Equal(d.DeliveryId, again.DeliveryId);
        Assert.Equal(d.Attempt, again.Attempt);
        Assert.Equal(0, again.Attempt);
        Assert.Null(again.LastError);

        Assert.Empty(await Storage.Webhooks.ClaimDueAsync("d", 10, Clock.UtcNow.AddDays(1), TimeSpan.FromMinutes(1), CancellationToken.None));
        await FlushStatsAsync();
        Assert.All(await Storage.Stats.QueryAsync(null, Start.AddHours(-1), Start.AddDays(1), false, CancellationToken.None), r => Assert.Equal(0, r.Deferred));
        Assert.Empty(await Storage.Stats.GetRecentEventsAsync(null, 10, CancellationToken.None));
        if (IsFull)
        {
            var events = await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None);
            Assert.Equal([MessageEventType.Queued], events.Select(e => e.Type));
            Assert.Equal("queued", (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.Summary.Status);
        }

        // A counted deferral afterwards still starts from attempt 0.
        await RecordAsync(again, DeliveryOutcome.Deferred, next: retryAt.AddMinutes(1));
        Clock.Set(retryAt.AddMinutes(1));
        Assert.Equal(1, (await ClaimAsync()).Single().Attempt);
    }

    [Fact]
    public async Task An_uncounted_hold_requires_a_next_attempt_time()
    {
        await AcceptAsync();
        var d = (await ClaimAsync()).Single();
        await Assert.ThrowsAnyAsync<ArgumentException>(async () => await RecordAsync(d, DeliveryOutcome.Deferred, countAttempt: false));
    }

    [Fact]
    public async Task Deferred_requires_a_next_attempt_time()
    {
        await AcceptAsync();
        var d = (await ClaimAsync()).Single();
        await Assert.ThrowsAnyAsync<ArgumentException>(async () => await RecordAsync(d, DeliveryOutcome.Deferred));
    }

    [Fact]
    public async Task Hard_bounce_suppresses_the_recipient_and_removes_the_delivery()
    {
        await AcceptAsync(Msg(to: ["Bad.User@Example.org"]));
        var d = (await ClaimAsync()).Single();
        Assert.False(await Storage.Config.IsSuppressedAsync(TenantA, "bad.user@example.org", CancellationToken.None));

        await RecordAsync(d, DeliveryOutcome.Failed, suppress: SuppressionReason.HardBounce, smtp: 550, enhanced: "5.1.1", message: "no such user");

        Assert.True(await Storage.Config.IsSuppressedAsync(TenantA, "bad.user@example.org", CancellationToken.None));
        Assert.False(await Storage.Config.IsSuppressedAsync(TenantB, "bad.user@example.org", CancellationToken.None));
        var page = await Storage.Config.GetSuppressionsAsync(TenantA, null, 10, CancellationToken.None);
        var s = Assert.Single(page.Items);
        Assert.Equal(SuppressionReason.HardBounce, s.Reason);
        Assert.Equal(d.MessageId, s.MessageId);
        Assert.Empty(await ClaimAsync(owner: "worker-2", now: Start.AddDays(1)));
    }

    [Fact]
    public async Task Suppression_write_is_idempotent_when_a_bounce_is_recorded_again_after_a_crash()
    {
        await AcceptAsync();
        var d = (await ClaimAsync()).Single();
        // A crash between writing the suppression and completing the row is simulated by writing the suppression first.
        await Storage.Config.AddSuppressionAsync(new SuppressionRecord(TenantA, "alice@example.org", SuppressionReason.HardBounce, "pre-crash", Start, d.MessageId), CancellationToken.None);
        await RecordAsync(d, DeliveryOutcome.Failed, suppress: SuppressionReason.HardBounce, smtp: 550);
        Assert.Single((await Storage.Config.GetSuppressionsAsync(TenantA, null, 10, CancellationToken.None)).Items);
    }

    [Theory]
    [InlineData(DeliveryOutcome.Expired)]
    [InlineData(DeliveryOutcome.Suppressed)]
    [InlineData(DeliveryOutcome.Cancelled)]
    [InlineData(DeliveryOutcome.Failed)]
    public async Task Final_outcomes_remove_the_delivery_and_free_the_spool(DeliveryOutcome outcome)
    {
        var m = await AcceptAsync();
        var d = (await ClaimAsync()).Single();
        await RecordAsync(d, outcome);
        Assert.Null(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));
        Assert.Empty(await ClaimAsync(now: Start.AddDays(30)));
    }

    [Fact]
    public async Task AbortedBySwitch_requeues_the_delivery_unchanged()
    {
        await AcceptAsync();
        var d = (await ClaimAsync()).Single();
        await RecordAsync(d, DeliveryOutcome.AbortedBySwitch);

        var again = (await ClaimAsync(owner: "worker-2")).Single();
        Assert.Equal(d.DeliveryId, again.DeliveryId);
        Assert.Equal(0, again.Attempt);
        Assert.False(again.PossibleDuplicate);
        Assert.Equal(d.CreatedAt, again.CreatedAt);
    }

    [Fact]
    public async Task PossibleDuplicate_is_flagged_on_the_requeued_delivery_and_in_history()
    {
        var m = await AcceptAsync();
        var d = (await ClaimAsync()).Single();
        await RecordAsync(d, DeliveryOutcome.AbortedBySwitch, possibleDuplicate: true);

        var again = (await ClaimAsync(owner: "worker-2")).Single();
        Assert.True(again.PossibleDuplicate);

        var events = await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None);
        if (IsFull)
        {
            Assert.Contains(events, e => e.Type == MessageEventType.AbortedBySwitch);
            Assert.Contains(events, e => e.Type == MessageEventType.PossibleDuplicate);
        }
        else
        {
            Assert.Empty(events);
        }

        await RecordAsync(again, DeliveryOutcome.Delivered);
    }

    [Fact]
    public async Task Events_follow_the_attempts_in_order_and_carry_the_attempt_details()
    {
        if (!IsFull)
        {
            return;
        }

        var m = await AcceptAsync();
        var d = (await ClaimAsync()).Single();
        await RecordAsync(d, DeliveryOutcome.Deferred, next: Start.AddMinutes(1), smtp: 451, enhanced: "4.7.1", message: "try later");
        Clock.Advance(TimeSpan.FromMinutes(2));
        var again = (await ClaimAsync()).Single();
        await RecordAsync(again, DeliveryOutcome.Delivered, smtp: 250, enhanced: "2.0.0", message: "queued as 123");

        var events = await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None);
        Assert.Equal([MessageEventType.Queued, MessageEventType.Deferred, MessageEventType.Delivered], events.Select(e => e.Type));
        var deferred = events[1];
        Assert.Equal(451, deferred.SmtpCode);
        Assert.Equal("4.7.1", deferred.EnhancedCode);
        Assert.Equal("try later", deferred.Message);
        Assert.Equal(d.DeliveryId, deferred.DeliveryId);
        Assert.Equal("alice@example.org", deferred.Recipient);
        var delivered = events[2];
        Assert.Equal("mx.example.org", delivered.MxHost);
        Assert.Equal("direct", delivered.Route);
        Assert.NotNull(delivered.Tls);
        Assert.Equal("TLS1.3", delivered.Tls.Version);
        Assert.True(delivered.Tls.Verified);

        MessageDetail? detail = await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None);
        Assert.Equal("delivered", detail!.Summary.Status);
    }

    [Fact]
    public async Task Message_status_reflects_partial_delivery_and_bounces()
    {
        if (!IsFull)
        {
            return;
        }

        var m = await AcceptAsync(Msg(to: ["a@example.org", "b@example.org", "c@example.org"]));
        var claimed = await ClaimAsync();
        await RecordAsync(claimed[0], DeliveryOutcome.Delivered);
        Assert.Equal("queued", (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.Summary.Status);
        await RecordAsync(claimed[1], DeliveryOutcome.Deferred, next: Start.AddHours(1));
        Assert.Equal("deferred", (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.Summary.Status);
        await RecordAsync(claimed[2], DeliveryOutcome.Failed, smtp: 550);
        Assert.Equal("deferred", (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.Summary.Status);

        Clock.Advance(TimeSpan.FromHours(2));
        var rest = (await ClaimAsync()).Single();
        await RecordAsync(rest, DeliveryOutcome.Expired);
        // delivered 1, bounced 1, expired 1
        Assert.Equal("partial", (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.Summary.Status);
    }

    [Fact]
    public async Task Statistics_count_each_outcome()
    {
        await AcceptAsync(Msg(to: ["a@one.example", "b@one.example", "c@one.example", "d@one.example", "e@one.example", "f@one.example"], sendingDomain: "s.example"));
        var c = await ClaimAsync();
        await RecordAsync(c[0], DeliveryOutcome.Delivered);
        await RecordAsync(c[1], DeliveryOutcome.Delivered);
        await RecordAsync(c[2], DeliveryOutcome.Deferred, next: Start.AddHours(1));
        await RecordAsync(c[3], DeliveryOutcome.Failed, suppress: SuppressionReason.Complaint);
        await RecordAsync(c[4], DeliveryOutcome.Suppressed);
        await RecordAsync(c[5], DeliveryOutcome.Expired);
        await FlushStatsAsync();

        var rows = await Storage.Stats.QueryAsync(TenantA, Start.AddHours(-1), Start.AddHours(1), daily: false, CancellationToken.None);
        var row = Assert.Single(rows);
        Assert.Equal(6, row.Accepted);
        Assert.Equal(2, row.Delivered);
        Assert.Equal(1, row.Deferred);
        Assert.Equal(1, row.HardBounce);
        Assert.Equal(1, row.Complained);
        Assert.Equal(1, row.Suppressed);
        Assert.Equal(1, row.Expired);
    }

    // Webhook fan-out

    [Fact]
    public async Task Webhook_events_fan_out_to_enabled_subscribed_endpoints_of_the_tenant_only()
    {
        await AddEndpointAsync(TenantA, true, "message.delivered");
        await AddEndpointAsync(TenantA, true, "*");
        await AddEndpointAsync(TenantA, false, "message.delivered");
        await AddEndpointAsync(TenantA, true, "message.bounced");
        await AddEndpointAsync(TenantA, true);
        await AddEndpointAsync(TenantB, true, "message.delivered");

        await AcceptAsync();
        var d = (await ClaimAsync()).Single();
        var draft = new WebhookEventDraft(Ids.New(), "message.delivered", "{\"id\":1}");
        await RecordAsync(d, DeliveryOutcome.Delivered, events: [draft]);

        var items = await Storage.Webhooks.ClaimDueAsync("dispatcher", 100, Clock.UtcNow, TimeSpan.FromMinutes(1), CancellationToken.None);
        Assert.Equal(2, items.Count);
        Assert.All(items, i =>
        {
            Assert.Equal(TenantA, i.TenantId);
            Assert.Equal("message.delivered", i.EventType);
            Assert.Equal(draft.EventId, i.EventId);
            Assert.Equal("{\"id\":1}", i.PayloadJson);
            Assert.Equal(0, i.Attempt);
        });
        Assert.Equal(2, items.Select(i => i.EndpointId).Distinct().Count());
    }

    [Fact]
    public async Task Several_drafts_produce_independent_outbox_rows_and_fan_out_changes_with_endpoint_edits()
    {
        Guid ep = await AddEndpointAsync(TenantA, true, "a.event", "b.event");
        await AcceptAsync(Msg(to: ["x@example.org", "y@example.org"]));
        var claimed = await ClaimAsync();
        await RecordAsync(claimed[0], DeliveryOutcome.Delivered, events: [Draft("a.event"), Draft("b.event"), Draft("c.event")]);
        Assert.Equal(2, (await Storage.Webhooks.ClaimDueAsync("d", 100, Clock.UtcNow, TimeSpan.FromDays(1), CancellationToken.None)).Count);

        await Storage.Config.DisableWebhookEndpointAsync(ep, "gone", Clock.UtcNow, CancellationToken.None);
        await RecordAsync(claimed[1], DeliveryOutcome.Delivered, events: [Draft("a.event")]);
        Assert.Empty(await Storage.Webhooks.ClaimDueAsync("d", 100, Clock.UtcNow.AddHours(1), TimeSpan.FromMinutes(1), CancellationToken.None));
    }

    // Retained raw

    [Fact]
    public async Task Retained_raw_is_kept_after_the_last_recipient_when_requested()
    {
        var m = await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"], retainRaw: true, size: 5000));
        var claimed = await ClaimAsync();
        await RecordAsync(claimed[0], DeliveryOutcome.Delivered);
        Assert.Null(await Storage.History.GetRetainedRawAsync(TenantA, m.MessageId, CancellationToken.None));
        Assert.NotNull(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));

        await RecordAsync(claimed[1], DeliveryOutcome.Delivered);
        Assert.Null(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));

        byte[]? retained = await Storage.History.GetRetainedRawAsync(TenantA, m.MessageId, CancellationToken.None);
        if (IsFull)
        {
            Assert.NotNull(retained);
            Assert.True(m.Raw.Span.SequenceEqual(retained));
            Assert.Null(await Storage.History.GetRetainedRawAsync(TenantB, m.MessageId, CancellationToken.None));
            Assert.True((await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.RawRetained);
        }
        else
        {
            Assert.Null(retained);
        }
    }

    [Fact]
    public async Task Raw_is_not_retained_unless_requested()
    {
        var m = await AcceptAsync(Msg(retainRaw: false));
        var d = (await ClaimAsync()).Single();
        await RecordAsync(d, DeliveryOutcome.Delivered);
        Assert.Null(await Storage.History.GetRetainedRawAsync(TenantA, m.MessageId, CancellationToken.None));
        if (IsFull)
        {
            Assert.False((await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.RawRetained);
        }
    }

    // Recent events

    [Fact]
    public async Task Recent_events_ring_records_outcomes_without_content_in_both_modes()
    {
        await AcceptAsync(Msg(to: ["a@one.example", "b@two.example"]));
        var c = await ClaimAsync();
        await RecordAsync(c.Single(x => x.RecipientDomain == "one.example"), DeliveryOutcome.Delivered, smtp: 250, enhanced: "2.0.0");
        Clock.Advance(TimeSpan.FromSeconds(1));
        await RecordAsync(c.Single(x => x.RecipientDomain == "two.example"), DeliveryOutcome.Deferred, next: Start.AddHours(1), smtp: 451, enhanced: "4.7.1", message: "secret text");
        await FlushStatsAsync();

        var all = await Storage.Stats.GetRecentEventsAsync(null, 10, CancellationToken.None);
        Assert.Equal(2, all.Count);
        Assert.Equal("deferred", all[0].EventType);
        Assert.Equal("delivered", all[1].EventType);
        Assert.Equal("two.example", all[0].RecipientDomain);
        Assert.Equal("451 4.7.1", all[0].Detail);
        Assert.DoesNotContain("secret", all[0].Detail ?? "");
        Assert.Empty(await Storage.Stats.GetRecentEventsAsync(TenantB, 10, CancellationToken.None));
        Assert.Single(await Storage.Stats.GetRecentEventsAsync(TenantA, 1, CancellationToken.None));
    }

    [Fact]
    public async Task History_Mode_is_reported()
    {
        Assert.Equal(Mode, Storage.HistoryMode);
        await Task.CompletedTask;
    }
}
