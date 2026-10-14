using Mta.Core;

namespace Mta.Storage.Tests;

/// <summary>
/// Cancelling pending deliveries (decision 80): what is finished, what is left alone because a worker holds it, and that a cancelled
/// delivery can never come back. Runs on every backend and in both history modes.
/// </summary>
public abstract partial class DeliveryConformance
{
    private Task<CancelResult> CancelAsync(Guid messageId, string[]? recipients = null, Guid? tenant = null) =>
        Storage.Deliveries.CancelAsync(tenant ?? TenantA, messageId, recipients, Clock.UtcNow, CancellationToken.None).AsTask();

    private async Task<string?> StatusAsync(Guid messageId) => (await Storage.History.GetAsync(TenantA, messageId, CancellationToken.None))?.Summary.Status;

    [Fact]
    public async Task Cancel_finishes_every_pending_recipient_and_the_message_is_never_claimed_again()
    {
        var m = await AcceptAsync(Msg(to: ["b@example.org", "a@example.org", "c@example.org"]));

        CancelResult result = await CancelAsync(m.MessageId);

        Assert.Equal(["a@example.org", "b@example.org", "c@example.org"], result.Cancelled);
        Assert.Empty(result.InFlight);
        Assert.Empty(result.NotPending);
        Assert.Null(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));
        QueueStats stats = await Storage.Deliveries.GetQueueStatsAsync(CancellationToken.None);
        Assert.Equal(0, stats.Queued + stats.Leased + stats.Deferred);
        Assert.Equal(0, stats.SpoolBytes);
        Assert.Empty(await ClaimAsync(now: Start.AddDays(30)));

        if (IsFull)
        {
            Assert.Equal("cancelled", await StatusAsync(m.MessageId));
            var events = await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None);
            var cancelled = events.Where(e => e.Type == MessageEventType.Cancelled).ToList();
            Assert.Equal(["a@example.org", "b@example.org", "c@example.org"], cancelled.Select(e => e.Recipient).OrderBy(x => x, StringComparer.Ordinal));
            Assert.All(cancelled, e => Assert.NotNull(e.DeliveryId));
        }
    }

    [Fact]
    public async Task Cancelling_one_recipient_leaves_the_others_deliverable_and_the_spool_in_place()
    {
        var m = await AcceptAsync(Msg(to: ["a@example.org", "b@example.org", "c@example.org"]));

        CancelResult result = await CancelAsync(m.MessageId, ["b@example.org"]);

        Assert.Equal(["b@example.org"], result.Cancelled);
        Assert.NotNull(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));
        var claimed = await ClaimAsync();
        Assert.Equal(["a@example.org", "c@example.org"], claimed.Select(c => c.Recipient.ToString()).OrderBy(x => x, StringComparer.Ordinal));
        if (IsFull)
        {
            Assert.Equal("queued", await StatusAsync(m.MessageId));
        }

        foreach (ClaimedDelivery c in claimed)
        {
            await RecordAsync(c, DeliveryOutcome.Delivered, smtp: 250);
        }

        Assert.Null(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));
        if (IsFull)
        {
            Assert.Equal("partial", await StatusAsync(m.MessageId));
        }
    }

    [Fact]
    public async Task A_leased_recipient_is_in_flight_and_is_left_alone()
    {
        var m = await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"]));
        var claimed = await ClaimAsync(max: 1, lease: TimeSpan.FromMinutes(5));
        string leased = claimed.Single().Recipient.ToString();
        string other = leased == "a@example.org" ? "b@example.org" : "a@example.org";

        CancelResult result = await CancelAsync(m.MessageId);

        Assert.Equal([other], result.Cancelled);
        Assert.Equal([leased], result.InFlight);
        Assert.NotNull(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));

        // The worker's outcome is recorded as usual and frees the spool with the last pending recipient.
        await RecordAsync(claimed.Single(), DeliveryOutcome.Delivered, smtp: 250);
        Assert.Null(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));
        Assert.Empty(await ClaimAsync(now: Start.AddDays(30)));
        if (IsFull)
        {
            Assert.Equal("partial", await StatusAsync(m.MessageId));
        }
    }

    [Fact]
    public async Task A_cancel_that_finds_only_leased_recipients_changes_nothing()
    {
        var m = await AcceptAsync(Msg(to: ["a@example.org"]));
        var d = (await ClaimAsync(lease: TimeSpan.FromMinutes(5))).Single();

        CancelResult result = await CancelAsync(m.MessageId);

        Assert.Empty(result.Cancelled);
        Assert.Equal(["a@example.org"], result.InFlight);
        await RecordAsync(d, DeliveryOutcome.Delivered, smtp: 250);
        if (IsFull)
        {
            Assert.Equal("delivered", await StatusAsync(m.MessageId));
            Assert.DoesNotContain(await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None), e => e.Type == MessageEventType.Cancelled);
        }
    }

    [Fact]
    public async Task An_expired_lease_is_no_longer_in_flight_and_a_late_result_cannot_bring_the_delivery_back()
    {
        var m = await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"]));
        var stale = (await ClaimAsync(max: 1, lease: TimeSpan.FromMinutes(1))).Single();
        Clock.Advance(TimeSpan.FromMinutes(2));   // the lease is past: any worker could claim it now, so cancelling may take it

        CancelResult result = await CancelAsync(m.MessageId);
        Assert.Equal(["a@example.org", "b@example.org"], result.Cancelled);
        Assert.Null(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));

        // The holder that outlived its lease reports a deferral (or a delivery): nothing is resurrected, nothing is double counted.
        await RecordAsync(stale, DeliveryOutcome.Deferred, next: Clock.UtcNow.AddHours(1), smtp: 451);
        await RecordAsync(stale, DeliveryOutcome.Delivered, smtp: 250);
        Assert.Empty(await ClaimAsync(now: Start.AddDays(30)));
        if (IsFull)
        {
            Assert.Equal("cancelled", await StatusAsync(m.MessageId));
            var events = await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None);
            Assert.DoesNotContain(events, e => e.Type is MessageEventType.Delivered or MessageEventType.Deferred);
        }
    }

    [Fact]
    public async Task A_deferred_recipient_waiting_for_its_retry_can_be_cancelled_and_is_not_retried()
    {
        var m = await AcceptAsync(Msg(to: ["a@example.org"]));
        var d = (await ClaimAsync()).Single();
        await RecordAsync(d, DeliveryOutcome.Deferred, next: Start.AddHours(1), smtp: 451, enhanced: "4.7.1");

        CancelResult result = await CancelAsync(m.MessageId);

        Assert.Equal(["a@example.org"], result.Cancelled);
        Assert.Empty(await ClaimAsync(now: Start.AddDays(30)));
        if (IsFull)
        {
            Assert.Equal("cancelled", await StatusAsync(m.MessageId));
        }
    }

    [Fact]
    public async Task Cancel_matches_recipients_case_insensitively_and_reports_those_that_are_not_pending()
    {
        var m = await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"]));
        var claimed = await ClaimAsync();
        await RecordAsync(claimed.Single(c => c.Recipient.ToString() == "a@example.org"), DeliveryOutcome.Delivered, smtp: 250);
        Clock.Advance(TimeSpan.FromMinutes(5));   // the lease of b is past, so b is cancellable

        CancelResult result = await CancelAsync(m.MessageId, ["B@Example.ORG", "a@example.org", "stranger@example.org"]);

        Assert.Equal(["b@example.org"], result.Cancelled);
        Assert.Empty(result.InFlight);
        Assert.Equal(["a@example.org", "stranger@example.org"], result.NotPending);
        if (IsFull)
        {
            Assert.Equal("partial", await StatusAsync(m.MessageId));
        }
    }

    [Fact]
    public async Task Cancelling_twice_or_an_unknown_message_finds_nothing()
    {
        var m = await AcceptAsync(Msg(to: ["a@example.org"]));
        Assert.Single((await CancelAsync(m.MessageId)).Cancelled);

        CancelResult again = await CancelAsync(m.MessageId);
        Assert.Empty(again.Cancelled);
        Assert.Empty(again.InFlight);
        again = await CancelAsync(m.MessageId, ["a@example.org"]);
        Assert.Equal(["a@example.org"], again.NotPending);

        CancelResult unknown = await CancelAsync(Ids.New(Clock.UtcNow));
        Assert.Empty(unknown.Cancelled);
        if (IsFull)
        {
            Assert.Single(await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None), e => e.Type == MessageEventType.Cancelled);
        }
    }

    [Fact]
    public async Task A_message_of_another_tenant_cannot_be_cancelled_and_stays_deliverable()
    {
        var m = await AcceptAsync(Msg(to: ["a@example.org"]));

        CancelResult result = await CancelAsync(m.MessageId, tenant: TenantB);
        Assert.Empty(result.Cancelled);
        Assert.Empty(result.InFlight);

        result = await CancelAsync(m.MessageId, ["a@example.org"], tenant: TenantB);
        Assert.Empty(result.Cancelled);
        Assert.Equal(["a@example.org"], result.NotPending);   // only echoes the caller's own input; nothing about the real message leaks

        Assert.Single(await ClaimAsync());
    }

    [Fact]
    public async Task Cancel_writes_no_statistic_no_webhook_event_and_a_ring_entry_without_content()
    {
        await AddEndpointAsync(TenantA, true, "*");
        var m = await AcceptAsync(Msg(to: ["a@one.example", "b@two.example"], sendingDomain: "s.example"));

        await CancelAsync(m.MessageId);
        await FlushStatsAsync();

        Assert.Empty(await Storage.Webhooks.ClaimDueAsync("d", 100, Clock.UtcNow.AddHours(1), TimeSpan.FromMinutes(1), CancellationToken.None));
        var rows = await Storage.Stats.QueryAsync(TenantA, Start.AddHours(-1), Start.AddHours(1), daily: false, CancellationToken.None);
        Assert.Equal(2, rows.Sum(r => r.Accepted));
        Assert.Equal(0, rows.Sum(r => r.Delivered + r.Deferred + r.HardBounce + r.SoftBounce + r.Expired + r.Complained + r.Rejected + r.Suppressed));
        var ring = await Storage.Stats.GetRecentEventsAsync(TenantA, 10, CancellationToken.None);
        Assert.Equal(2, ring.Count(e => e.EventType == "cancelled"));
        Assert.All(ring, e => Assert.Null(e.Detail));
    }

    [Fact]
    public async Task Cancelling_the_last_recipient_moves_a_retained_raw_to_history_like_any_final_outcome()
    {
        var m = await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"], retainRaw: true, size: 3000));
        await CancelAsync(m.MessageId, ["a@example.org"]);
        Assert.Null(await Storage.History.GetRetainedRawAsync(TenantA, m.MessageId, CancellationToken.None));

        await CancelAsync(m.MessageId);

        Assert.Null(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));
        byte[]? retained = await Storage.History.GetRetainedRawAsync(TenantA, m.MessageId, CancellationToken.None);
        if (IsFull)
        {
            Assert.NotNull(retained);
            Assert.True(m.Raw.Span.SequenceEqual(retained));
        }
        else
        {
            Assert.Null(retained);
        }
    }

    [Fact]
    public async Task A_mix_of_final_outcomes_gives_the_usual_aggregate_status()
    {
        if (!IsFull)
        {
            return;
        }

        var m = await AcceptAsync(Msg(to: ["a@example.org", "b@example.org", "c@example.org"]));
        var claimed = await ClaimAsync(lease: TimeSpan.FromSeconds(30));
        await RecordAsync(claimed.Single(c => c.Recipient.ToString() == "a@example.org"), DeliveryOutcome.Failed, smtp: 550);
        Clock.Advance(TimeSpan.FromMinutes(1));

        await CancelAsync(m.MessageId);

        Assert.Equal("bounced", await StatusAsync(m.MessageId));   // a bounce wins over a cancellation, as with expiry
    }

    [Fact]
    public async Task Racing_claims_and_cancels_never_cancel_a_claimed_delivery_nor_claim_a_cancelled_one()
    {
        const int messages = 40;
        var ids = new List<AcceptedMessage>();
        for (int i = 0; i < messages; i++)
        {
            ids.Add(await AcceptAsync(Msg(to: [$"r{i}@example.org"], size: 128)));
        }

        // The clock does not move, so a lease taken by a claim stays active for the whole run: every delivery is either claimed first
        // (and then cancel must report it in flight) or cancelled first (and then it is gone for every claim).
        var claimedIds = new System.Collections.Concurrent.ConcurrentBag<Guid>();
        var cancelledRecipients = new System.Collections.Concurrent.ConcurrentBag<string>();
        var inFlightRecipients = new System.Collections.Concurrent.ConcurrentBag<string>();
        using var start = new ManualResetEventSlim();
        var claimers = Enumerable.Range(0, 3).Select(w => Task.Run(async () =>
        {
            start.Wait();
            while (true)
            {
                var batch = await ClaimAsync(max: 3, lease: TimeSpan.FromHours(1), owner: "w" + w);
                if (batch.Count == 0 && ids.Count == cancelledRecipients.Count + inFlightRecipients.Count)
                {
                    return;
                }

                foreach (var d in batch)
                {
                    claimedIds.Add(d.DeliveryId);
                }

                await Task.Yield();
            }
        })).ToList();
        var canceller = Task.Run(async () =>
        {
            start.Wait();
            foreach (AcceptedMessage m in ids)
            {
                CancelResult r = await CancelAsync(m.MessageId);
                foreach (string c in r.Cancelled) { cancelledRecipients.Add(c); }
                foreach (string c in r.InFlight) { inFlightRecipients.Add(c); }
                await Task.Yield();
            }
        });
        start.Set();
        await Task.WhenAll(claimers.Append(canceller));

        Assert.Equal(messages, cancelledRecipients.Count + inFlightRecipients.Count);
        var cancelledDeliveries = ids.Where(m => cancelledRecipients.Contains(m.Recipients[0].Address.ToString())).Select(m => m.Recipients[0].DeliveryId).ToHashSet();
        Assert.Empty(cancelledDeliveries.Intersect(claimedIds));
        var inFlightDeliveries = ids.Where(m => inFlightRecipients.Contains(m.Recipients[0].Address.ToString())).Select(m => m.Recipients[0].DeliveryId).ToHashSet();
        Assert.All(inFlightDeliveries, d => Assert.Contains(d, claimedIds));
        Assert.Equal(messages, claimedIds.Distinct().Count() + cancelledDeliveries.Count);
        Assert.Equal(claimedIds.Count, claimedIds.Distinct().Count());
    }
}
