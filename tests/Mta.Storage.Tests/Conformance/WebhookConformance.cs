using Mta.Core;

namespace Mta.Storage.Tests;

/// <summary>The webhook outbox: claim, complete, replay, attempt log and retention.</summary>
public abstract class WebhookConformance : StorageTestBase
{
    private Guid _endpoint;

    /// <summary>False for a backend whose endpoint list is also refreshed by age (PostgreSQL: another replica may change it), where "no subscriber" is only guaranteed while the list is young.</summary>
    protected virtual bool SubscriberAnswerIsPrecise => true;

    public override async Task InitializeAsync()
    {
        await base.InitializeAsync();
        _endpoint = await AddEndpointAsync(TenantA, true, "*");
    }

    /// <summary>Creates <paramref name="count"/> outbox rows through a real delivery completion.</summary>
    private async Task SeedAsync(int count, Guid? tenant = null)
    {
        for (int i = 0; i < count; i++)
        {
            await AcceptAsync(Msg(tenant: tenant, to: [$"r{i}@example.org"]));
        }

        foreach (var d in await ClaimAsync(max: 1000, now: Clock.UtcNow.AddSeconds(1)))
        {
            await RecordAsync(d, DeliveryOutcome.Delivered, events: [Draft("message.delivered", $"{{\"to\":\"{d.Recipient.LocalPart}\"}}")]);
        }
    }

    private async Task<IReadOnlyList<WebhookOutboxItem>> ClaimDueAsync(int max = 100, string owner = "dispatcher", TimeSpan? lease = null, DateTimeOffset? now = null) =>
        await Storage.Webhooks.ClaimDueAsync(owner, max, now ?? Clock.UtcNow, lease ?? TimeSpan.FromMinutes(1), CancellationToken.None);

    private static WebhookAttemptRecord AttemptOf(WebhookOutboxItem item, DateTimeOffset at, int? status = 200, string? error = null, string? snippet = null) =>
        new(item.Id, at, status, TimeSpan.FromMilliseconds(35), error, snippet);

    [Fact]
    public async Task Targeted_enqueue_reaches_only_the_named_enabled_endpoint_of_the_tenant_whatever_it_subscribes_to()
    {
        Guid narrow = await AddEndpointAsync(TenantA, true, "message.bounced");
        Guid disabled = await AddEndpointAsync(TenantA, false, "*");
        Guid foreign = await AddEndpointAsync(TenantB, true, "*");
        var draft = Draft("webhook.test", "{\"hello\":true}");

        Guid? id = await Storage.Webhooks.EnqueueForEndpointAsync(TenantA, narrow, draft, Clock.UtcNow, CancellationToken.None);
        Assert.NotNull(id);
        Assert.Null(await Storage.Webhooks.EnqueueForEndpointAsync(TenantA, disabled, draft, Clock.UtcNow, CancellationToken.None));
        Assert.Null(await Storage.Webhooks.EnqueueForEndpointAsync(TenantA, foreign, draft, Clock.UtcNow, CancellationToken.None));
        Assert.Null(await Storage.Webhooks.EnqueueForEndpointAsync(TenantA, Ids.New(), draft, Clock.UtcNow, CancellationToken.None));

        var items = await ClaimDueAsync();
        var item = Assert.Single(items);
        Assert.Equal(id, item.Id);
        Assert.Equal(narrow, item.EndpointId);
        Assert.Equal("webhook.test", item.EventType);
        Assert.Equal(draft.EventId, item.EventId);
        Assert.Equal("{\"hello\":true}", item.PayloadJson);
    }

    [Fact]
    public async Task MayHaveSubscribers_never_says_no_while_an_enabled_endpoint_would_receive_the_event()
    {
        // The delivery path builds an event payload only when this is true, so a false here for a subscribed event would lose the event.
        Guid narrow = await AddEndpointAsync(TenantB, true, "message.bounced");
        Assert.True(Storage.Webhooks.MayHaveSubscribers(TenantA, "message.delivered"));    // "*"
        Assert.True(Storage.Webhooks.MayHaveSubscribers(TenantA, "message.bounced"));
        Assert.True(Storage.Webhooks.MayHaveSubscribers(TenantB, "message.bounced"));
        Assert.NotEqual(Guid.Empty, narrow);
    }

    [Fact]
    public async Task MayHaveSubscribers_notices_an_endpoint_that_is_added_after_the_list_was_loaded()
    {
        // Load the endpoint list through a fan-out that has nobody to deliver to for tenant B...
        await AcceptAsync(Msg(tenant: TenantB, to: ["x@example.org"]));
        foreach (var d in await ClaimAsync(max: 10, now: Clock.UtcNow.AddSeconds(1)))
        {
            await RecordAsync(d, DeliveryOutcome.Delivered, events: [Draft("message.delivered", "{}")]);
        }

        // With the list loaded and current, a tenant nobody subscribed for is skipped, an event the other tenant's "*" endpoint wants is not.
        if (SubscriberAnswerIsPrecise)
        {
            Assert.False(Storage.Webhooks.MayHaveSubscribers(TenantB, "message.delivered"));
            Assert.False(Storage.Webhooks.MayHaveSubscribers(Guid.NewGuid(), "message.delivered"));
        }

        Assert.True(Storage.Webhooks.MayHaveSubscribers(TenantA, "message.delivered"));

        // ...then subscribe tenant B: the very next question must say yes, however the answer was cached before,
        Guid added = await AddEndpointAsync(TenantB, true, "message.delivered");
        Assert.True(Storage.Webhooks.MayHaveSubscribers(TenantB, "message.delivered"));

        // and the next delivery of tenant B reaches the new endpoint.
        await AcceptAsync(Msg(tenant: TenantB, to: ["y@example.org"]));
        foreach (var d in await ClaimAsync(max: 10, now: Clock.UtcNow.AddSeconds(1)))
        {
            await RecordAsync(d, DeliveryOutcome.Delivered, events: [Draft("message.delivered", "{}")]);
        }

        Assert.Equal(added, Assert.Single(await ClaimDueAsync(), i => i.TenantId == TenantB).EndpointId);
    }

    [Fact]
    public async Task Claim_respects_max_due_time_and_leases()
    {
        await SeedAsync(3);
        Clock.Advance(TimeSpan.FromSeconds(5));
        var first = await ClaimDueAsync(max: 2);
        Assert.Equal(2, first.Count);
        var second = await ClaimDueAsync(max: 10, owner: "dispatcher-2");
        Assert.Single(second);
        Assert.Empty(await ClaimDueAsync(owner: "dispatcher-3"));

        Clock.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(3, (await ClaimDueAsync(owner: "dispatcher-3")).Count);
    }

    [Fact]
    public async Task Claim_returns_item_details_and_oldest_first()
    {
        await SeedAsync(2);
        Clock.Advance(TimeSpan.FromSeconds(1));
        var items = await ClaimDueAsync();
        Assert.Equal(2, items.Count);
        Assert.All(items, i =>
        {
            Assert.Equal(_endpoint, i.EndpointId);
            Assert.Equal(TenantA, i.TenantId);
            Assert.Equal("message.delivered", i.EventType);
            Assert.Equal(0, i.Attempt);
            Assert.Contains("\"to\":", i.PayloadJson);
            Assert.True(i.CreatedAt <= Clock.UtcNow);
        });
        Assert.True(items[0].NextAttemptAt <= items[1].NextAttemptAt);
    }

    [Fact]
    public async Task Pending_completion_schedules_the_next_attempt_and_counts_the_attempt()
    {
        await SeedAsync(1);
        Clock.Advance(TimeSpan.FromSeconds(1));
        var item = (await ClaimDueAsync()).Single();

        DateTimeOffset retryAt = Clock.UtcNow.AddMinutes(5);
        await Storage.Webhooks.CompleteAsync(item.Id, AttemptOf(item, Clock.UtcNow, 503, "http_5xx", "unavailable"), WebhookOutboxState.Pending, retryAt, CancellationToken.None);

        Assert.Empty(await ClaimDueAsync(owner: "d2"));
        Assert.Empty(await ClaimDueAsync(owner: "d2", now: retryAt.AddSeconds(-1)));
        var again = (await ClaimDueAsync(owner: "d2", now: retryAt)).Single();
        Assert.Equal(item.Id, again.Id);
        Assert.Equal(1, again.Attempt);
        Assert.Equal(retryAt, again.NextAttemptAt);
    }

    [Fact]
    public async Task Pending_completion_requires_a_next_attempt_time()
    {
        await SeedAsync(1);
        var item = (await ClaimDueAsync()).Single();
        await Assert.ThrowsAnyAsync<ArgumentException>(async () =>
            await Storage.Webhooks.CompleteAsync(item.Id, AttemptOf(item, Clock.UtcNow), WebhookOutboxState.Pending, null, CancellationToken.None));
    }

    [Theory]
    [InlineData(WebhookOutboxState.Delivered)]
    [InlineData(WebhookOutboxState.Failed)]
    public async Task Finished_items_are_not_claimed_again(WebhookOutboxState finalState)
    {
        await SeedAsync(1);
        var item = (await ClaimDueAsync()).Single();
        await Storage.Webhooks.CompleteAsync(item.Id, AttemptOf(item, Clock.UtcNow), finalState, null, CancellationToken.None);
        Clock.Advance(TimeSpan.FromDays(1));
        Assert.Empty(await ClaimDueAsync(owner: "d2"));
    }

    [Fact]
    public async Task Completing_an_unknown_item_does_nothing()
    {
        await Storage.Webhooks.CompleteAsync(Ids.New(), new WebhookAttemptRecord(Ids.New(), Clock.UtcNow, 200, TimeSpan.Zero, null, null), WebhookOutboxState.Delivered, null, CancellationToken.None);
        Assert.Empty(await Storage.Webhooks.GetAttemptsAsync(TenantA, _endpoint, 10, CancellationToken.None));
    }

    [Fact]
    public async Task Attempt_log_lists_newest_first_per_tenant_and_endpoint()
    {
        await SeedAsync(1);
        var item = (await ClaimDueAsync()).Single();
        for (int i = 1; i <= 3; i++)
        {
            Clock.Advance(TimeSpan.FromSeconds(10));
            await Storage.Webhooks.CompleteAsync(item.Id, AttemptOf(item, Clock.UtcNow, i == 3 ? 200 : 500, i == 3 ? null : "http_5xx", $"attempt {i}"),
                i == 3 ? WebhookOutboxState.Delivered : WebhookOutboxState.Pending, i == 3 ? null : Clock.UtcNow, CancellationToken.None);
            if (i < 3)
            {
                item = (await ClaimDueAsync(owner: "d" + i)).Single();
            }
        }

        var log = await Storage.Webhooks.GetAttemptsAsync(TenantA, _endpoint, 10, CancellationToken.None);
        Assert.Equal(3, log.Count);
        Assert.Equal(["attempt 3", "attempt 2", "attempt 1"], log.Select(a => a.ResponseSnippet));
        Assert.Equal(200, log[0].StatusCode);
        Assert.Equal("http_5xx", log[1].ErrorClass);
        Assert.Equal(TimeSpan.FromMilliseconds(35), log[0].Duration);
        Assert.Single(await Storage.Webhooks.GetAttemptsAsync(TenantA, _endpoint, 1, CancellationToken.None));
        Assert.Empty(await Storage.Webhooks.GetAttemptsAsync(TenantB, _endpoint, 10, CancellationToken.None));
        Assert.Empty(await Storage.Webhooks.GetAttemptsAsync(TenantA, Ids.New(), 10, CancellationToken.None));
    }

    [Fact]
    public async Task Enqueue_fans_an_event_out_to_the_tenants_subscribed_enabled_endpoints_only()
    {
        Guid onlyBounced = await AddEndpointAsync(TenantA, true, "message.bounced");
        await AddEndpointAsync(TenantA, false, "*");              // disabled
        await AddEndpointAsync(TenantB, true, "*");               // other tenant
        var draft = Draft("message.bounced", "{\"async\":true}");

        Assert.Equal(2, await Storage.Webhooks.EnqueueAsync(TenantA, draft, Clock.UtcNow, CancellationToken.None));
        Assert.Equal(1, await Storage.Webhooks.EnqueueAsync(TenantA, Draft("message.delivered", "{}"), Clock.UtcNow, CancellationToken.None));
        Assert.Equal(0, await Storage.Webhooks.EnqueueAsync(Guid.NewGuid(), draft, Clock.UtcNow, CancellationToken.None));

        var due = await ClaimDueAsync();
        Assert.Equal(3, due.Count);
        Assert.All(due, i => Assert.Equal(TenantA, i.TenantId));
        Assert.Equal(2, due.Count(i => i.EventType == "message.bounced"));
        Assert.Contains(due, i => i.EndpointId == onlyBounced && i.EventId == draft.EventId && i.PayloadJson == draft.PayloadJson);
    }

    [Fact]
    public async Task Replay_requeues_a_finished_item_for_its_tenant_only()
    {
        await SeedAsync(1);
        var item = (await ClaimDueAsync()).Single();
        Assert.False(await Storage.Webhooks.ReplayAsync(TenantA, item.Id, Clock.UtcNow, CancellationToken.None), "pending items cannot be replayed");

        await Storage.Webhooks.CompleteAsync(item.Id, AttemptOf(item, Clock.UtcNow, 410), WebhookOutboxState.Failed, null, CancellationToken.None);
        Assert.False(await Storage.Webhooks.ReplayAsync(TenantB, item.Id, Clock.UtcNow, CancellationToken.None));
        Assert.False(await Storage.Webhooks.ReplayAsync(TenantA, Ids.New(), Clock.UtcNow, CancellationToken.None));

        Clock.Advance(TimeSpan.FromHours(1));
        Assert.True(await Storage.Webhooks.ReplayAsync(TenantA, item.Id, Clock.UtcNow, CancellationToken.None));
        var again = (await ClaimDueAsync(owner: "d2")).Single();
        Assert.Equal(item.Id, again.Id);
        Assert.Equal(0, again.Attempt);
        Assert.Equal(Clock.UtcNow, again.NextAttemptAt);
    }

    // Retention

    [Fact]
    public async Task Finished_items_and_attempts_are_deleted_after_the_retention_days()
    {
        await OpenAsync(Opts(retention: new RetentionOptions { WebhookOutboxDays = 7, WebhookAttemptLogDays = 3 }));
        _endpoint = await AddEndpointAsync(TenantA, true, "*");
        await SeedAsync(2);
        var items = await ClaimDueAsync();
        await Storage.Webhooks.CompleteAsync(items[0].Id, AttemptOf(items[0], Clock.UtcNow), WebhookOutboxState.Delivered, null, CancellationToken.None);
        // items[1] stays pending (leased) and must survive retention.

        Clock.Advance(TimeSpan.FromDays(4));
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        Assert.Empty(await Storage.Webhooks.GetAttemptsAsync(TenantA, _endpoint, 10, CancellationToken.None));
        Assert.True(await Storage.Webhooks.ReplayAsync(TenantA, items[0].Id, Clock.UtcNow, CancellationToken.None), "finished item still inside the 7 day outbox retention");
        await Storage.Webhooks.CompleteAsync(items[0].Id, AttemptOf(items[0], Clock.UtcNow), WebhookOutboxState.Delivered, null, CancellationToken.None);

        Clock.Advance(TimeSpan.FromDays(8));
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        Assert.False(await Storage.Webhooks.ReplayAsync(TenantA, items[0].Id, Clock.UtcNow, CancellationToken.None), "finished item deleted");
        var pending = await ClaimDueAsync(owner: "d9");
        Assert.Equal(items[1].Id, pending.Single().Id);
    }

    [Fact]
    public async Task Zero_retention_keeps_finished_items_and_attempts_forever()
    {
        await OpenAsync(Opts(retention: new RetentionOptions { WebhookOutboxDays = 0, WebhookAttemptLogDays = 0 }));
        _endpoint = await AddEndpointAsync(TenantA, true, "*");
        await SeedAsync(1);
        var item = (await ClaimDueAsync()).Single();
        await Storage.Webhooks.CompleteAsync(item.Id, AttemptOf(item, Clock.UtcNow), WebhookOutboxState.Delivered, null, CancellationToken.None);

        Clock.Advance(TimeSpan.FromDays(3650));
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        Assert.Single(await Storage.Webhooks.GetAttemptsAsync(TenantA, _endpoint, 10, CancellationToken.None));
        Assert.True(await Storage.Webhooks.ReplayAsync(TenantA, item.Id, Clock.UtcNow, CancellationToken.None));
    }
}
