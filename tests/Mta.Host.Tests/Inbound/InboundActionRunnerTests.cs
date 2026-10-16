using System.Diagnostics.Metrics;
using System.Net;
using Mta.Core;
using Mta.Host.Inbound;
using Mta.Storage;
using Mta.Storage.Logic;
using Mta.Webhooks;

namespace Mta.Host.Tests.Inbound;

/// <summary>The runner around the actions (design section 11.7): leases and attempts, the route as it is when the action runs, deferrals, the poison pill, the pool and the metrics.</summary>
[Collection("inbound-actions")]   // the meter test counts the process-wide static instruments, so these classes do not run beside each other
public class InboundActionRunnerTests
{
    private static async Task WaitUntilAsync(Func<Task<bool>> condition)
    {
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        while (!await condition().ConfigureAwait(false))
        {
            await Task.Delay(5, limit.Token);
        }
    }

    [Fact]
    public async Task The_claim_counts_the_attempt_and_a_crashed_attempt_has_used_it_up()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();   // four attempts
        InboundMessageDraft draft = await h.ReceiveAsync();

        // A runner that dies in the middle of every attempt: claim, never complete, wait for the lease to run out.
        for (int i = 1; i <= 4; i++)
        {
            var claimed = await h.Storage.Inbound.ClaimActionsAsync("crashing-runner", 1, h.Clock.UtcNow, TimeSpan.FromSeconds(30), default);
            Assert.Equal(i, Assert.Single(claimed).Message.ActionAttempts);
            h.Clock.Advance(TimeSpan.FromSeconds(31));
        }

        // The fifth claim is past the last rung: the runner ends the message without trying it a fifth time.
        Assert.Equal(1, await h.RunAsync());
        InboundMessage stored = await h.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Failed, stored.ActionState);
        Assert.Equal("attempts_exhausted", stored.ActionLastError);
        Assert.Empty(h.Receiver.Requests);
    }

    [Fact]
    public async Task A_completion_from_a_lease_that_was_taken_over_is_not_recorded_and_does_not_notify()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        var gate = new TaskCompletionSource();
        var released = new TaskCompletionSource();
        h.Receiver.Respond(HttpStatusCode.InternalServerError);
        h.Receiver.Gate = async () => { released.TrySetResult(); await gate.Task; };
        var options = new InboundActionOptions { RetrySchedule = [], Lease = TimeSpan.FromSeconds(30) };   // one attempt only: a failure would be final
        InboundActionRunner runner = h.CreateRunner(options: options);
        InboundMessageDraft draft = await h.ReceiveAsync();

        Task<int> run = runner.RunOnceAsync(default);
        await released.Task;   // the runner is inside its HTTP call
        h.Clock.Advance(TimeSpan.FromMinutes(1));   // its lease ran out
        // Another replica takes the row over and does the work.
        var taken = await h.Storage.Inbound.ClaimActionsAsync("other-replica", 1, h.Clock.UtcNow, TimeSpan.FromMinutes(1), default);
        Assert.Equal(2, Assert.Single(taken).Message.ActionAttempts);
        gate.SetResult();
        await run;

        InboundMessage stored = await h.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Pending, stored.ActionState);   // the first runner's failure was not recorded over the other claim
        Assert.Empty(h.Publisher.Published);
    }

    [Fact]
    public async Task Inbound_switched_off_defers_each_action_against_the_ladder_and_a_retry_brings_it_back()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        h.InboundEnabled = false;
        InboundMessageDraft draft = await h.ReceiveAsync();

        for (int i = 1; i <= 4; i++)
        {
            await h.RunAsync();
            InboundMessage current = await h.GetAsync(draft.Id);
            Assert.Equal("inbound_disabled", current.ActionLastError);
            Assert.Equal(i, current.ActionAttempts);
            h.Clock.Advance(TimeSpan.FromMinutes(11));
        }

        Assert.Equal(InboundActionState.Failed, (await h.GetAsync(draft.Id)).ActionState);
        Assert.Empty(h.Receiver.Requests);

        h.InboundEnabled = true;
        Assert.Equal(InboundRetryResult.Queued, await h.Storage.Inbound.RetryActionAsync(h.TenantId, draft.Id, h.Clock.UtcNow, default));
        await h.RunAsync();
        Assert.Equal(InboundActionState.Done, (await h.GetAsync(draft.Id)).ActionState);
    }

    [Fact]
    public async Task A_suspended_tenant_defers_and_resuming_inside_the_ladder_delivers()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        InboundMessageDraft draft = await h.ReceiveAsync();
        await h.Storage.Config.UpsertTenantAsync(new Tenant(h.TenantId, "Tenant", "tenant", false, h.Clock.UtcNow, false), default);

        await h.RunAsync();
        Assert.Equal("tenant_suspended", (await h.GetAsync(draft.Id)).ActionLastError);
        Assert.Empty(h.Receiver.Requests);

        await h.Storage.Config.UpsertTenantAsync(new Tenant(h.TenantId, "Tenant", "tenant", true, h.Clock.UtcNow, false), default);
        h.Clock.Advance(TimeSpan.FromSeconds(10));
        await h.RunAsync();
        Assert.Equal(InboundActionState.Done, (await h.GetAsync(draft.Id)).ActionState);
    }

    [Fact]
    public async Task The_route_is_read_when_the_action_runs_not_when_the_mail_arrived()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        InboundMessageDraft toStore = await h.ReceiveAsync();
        InboundMessageDraft toDiscard = await h.ReceiveAsync();
        InboundMessageDraft toDelete = await h.ReceiveAsync();

        // The route became a store route while the messages waited: nothing is delivered, nothing is deleted.
        await h.Storage.Inbound.UpsertRouteAsync(h.Route with { ActionKind = InboundActionKind.Store, WebhookEndpointId = null, UpdatedAt = h.Clock.UtcNow }, default);
        Assert.Equal(3, await h.RunAsync());
        InboundMessage stored = await h.GetAsync(toStore.Id);
        Assert.Equal(InboundActionState.Done, stored.ActionState);
        Assert.Equal("route_is_now_store", stored.ActionNote);
        Assert.True(stored.HasRaw);
        Assert.Empty(h.Receiver.Requests);

        await h.Storage.Inbound.UpsertRouteAsync(h.Route with { ActionKind = InboundActionKind.Discard, WebhookEndpointId = null, UpdatedAt = h.Clock.UtcNow }, default);
        InboundMessageDraft later = await h.ReceiveAsync(kind: InboundActionKind.Webhook);
        await h.RunAsync();
        Assert.Equal("route_is_now_discard", (await h.GetAsync(later.Id)).ActionNote);
        Assert.True((await h.GetAsync(later.Id)).HasRaw);

        // A deleted route fails what was waiting for it.
        await h.Storage.Inbound.UpsertRouteAsync(h.Route, default);
        InboundMessageDraft orphan = await h.ReceiveAsync();
        Assert.True(await h.Storage.Inbound.DeleteRouteAsync(h.TenantId, h.Route.Id, default));
        await h.RunAsync();
        InboundMessage failed = await h.GetAsync(orphan.Id);
        Assert.Equal(InboundActionState.Failed, failed.ActionState);
        Assert.Equal("route_deleted", failed.ActionLastError);
        _ = toDiscard;
        _ = toDelete;
    }

    [Fact]
    public async Task A_disabled_route_still_carries_out_the_actions_it_was_given_and_a_new_endpoint_applies()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        InboundMessageDraft draft = await h.ReceiveAsync();
        WebhookEndpointRecord fixedEndpoint = await h.AddEndpointAsync(h.TenantId, "https://fixed.example.test/hook");
        // The tenant noticed the endpoint was wrong, pointed the route at another one and disabled the route for new mail.
        await h.Storage.Inbound.UpsertRouteAsync(h.Route with { Enabled = false, WebhookEndpointId = fixedEndpoint.Id, UpdatedAt = h.Clock.UtcNow }, default);

        await h.RunAsync();

        Assert.Equal("https://fixed.example.test/hook", Assert.Single(h.Receiver.Requests).Url.ToString());
        Assert.Equal(InboundActionState.Done, (await h.GetAsync(draft.Id)).ActionState);
    }

    [Fact]
    public async Task A_forward_action_without_a_forwarder_is_a_deferral()
    {
        await using var h = await new InboundActionHarness().InitializeAsync(InboundActionKind.Forward);
        InboundMessageDraft draft = await h.ReceiveAsync();

        await h.RunAsync();

        InboundMessage stored = await h.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Pending, stored.ActionState);
        Assert.Equal("forward_unavailable", stored.ActionLastError);
    }

    [Fact]
    public async Task The_forwarder_result_is_recorded_with_the_note_and_the_freed_body()
    {
        await using var h = await new InboundActionHarness().InitializeAsync(InboundActionKind.Forward, withForwarder: true);
        Guid outbound = Ids.New();
        h.Forwarder.Handler = (_, _, _) => InboundActionResult.Done(forwardMessageId: outbound, freeBody: true);
        InboundMessageDraft draft = await h.ReceiveAsync();

        await h.RunAsync();

        InboundMessage stored = await h.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Done, stored.ActionState);
        Assert.Equal(outbound, stored.ForwardMessageId);
        Assert.False(stored.HasRaw);
        Assert.Equal(h.Route.Id, Assert.Single(h.Forwarder.Calls).Route.Id);

        // A completion note travels to the API.
        h.Forwarder.Handler = (_, _, _) => InboundActionResult.Done(note: "all_targets_suppressed");
        InboundMessageDraft second = await h.ReceiveAsync();
        await h.RunAsync();
        Assert.Equal("all_targets_suppressed", (await h.GetAsync(second.Id)).ActionNote);
    }

    [Fact]
    public async Task A_permanent_forwarder_failure_is_final_and_published()
    {
        await using var h = await new InboundActionHarness().InitializeAsync(InboundActionKind.Forward, withForwarder: true);
        h.Forwarder.Handler = (_, _, _) => InboundActionResult.Failed("loop_detected");
        InboundMessageDraft draft = await h.ReceiveAsync();

        await h.RunAsync();

        Assert.Equal("loop_detected", (await h.GetAsync(draft.Id)).ActionLastError);
        Assert.Single(h.Publisher.Published);
    }

    [Fact]
    public async Task One_tenant_cannot_take_more_than_its_share_of_the_pool()
    {
        var options = new InboundActionOptions { Concurrency = 4, MaxConcurrencyPerTenant = 2 };
        await using var h = await new InboundActionHarness(options).InitializeAsync();
        var release = new TaskCompletionSource();
        h.Receiver.Gate = () => release.Task;
        for (int i = 0; i < 4; i++)
        {
            await h.ReceiveAsync();
        }

        Task<int> run = h.Runner.RunOnceAsync(default);
        await WaitUntilAsync(() => Task.FromResult(h.Receiver.Requests.Count >= 2));

        // Two are in flight and the other two wait for the tenant's slots: a slow receiver of one tenant never takes the whole pool.
        // (The maximum below can only be too low when the runner is slow, never too high, so a loaded machine cannot make this fail.)
        for (int i = 0; i < 200; i++)
        {
            await Task.Yield();
        }

        release.SetResult();
        Assert.Equal(4, await run);
        Assert.Equal(2, h.Receiver.MaxConcurrent);
        Assert.Equal(4, h.Receiver.Requests.Count);
    }

    [Fact]
    public async Task The_pool_delivers_new_mail_and_stops_cleanly_releasing_what_it_still_holds()
    {
        await using var h = await new InboundActionHarness(new InboundActionOptions { PollInterval = TimeSpan.FromMilliseconds(20) }).InitializeAsync();
        using var cts = new CancellationTokenSource();
        Task loop = h.Runner.RunAsync(cts.Token);

        var delivered = new TaskCompletionSource();
        h.Receiver.Gate = () =>
        {
            delivered.TrySetResult();
            return Task.CompletedTask;
        };
        InboundMessageDraft draft = await h.ReceiveAsync();
        h.Runner.Wake();
        await delivered.Task.WaitAsync(TimeSpan.FromSeconds(30));
        await WaitUntilAsync(async () => (await h.GetAsync(draft.Id)).ActionState == InboundActionState.Done);

        await cts.CancelAsync();
        await loop.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(InboundActionState.Done, (await h.GetAsync(draft.Id)).ActionState);
    }

    [Fact]
    public async Task A_paused_runner_claims_nothing_and_a_quiesce_gives_back_what_it_holds()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        InboundMessageDraft draft = await h.ReceiveAsync();

        h.Runner.Pause();
        using var cts = new CancellationTokenSource();
        Task loop = h.Runner.RunAsync(cts.Token);
        for (int i = 0; i < 200; i++)
        {
            await Task.Yield();   // a paused runner does nothing; the quiesce below is the deterministic part
        }

        Assert.Empty(h.Receiver.Requests);

        // A claim by this runner that has not been completed (a crash in the middle) is given back, with its attempt.
        var claimed = await h.Storage.Inbound.ClaimActionsAsync(h.Runner.Owner, 1, h.Clock.UtcNow, TimeSpan.FromMinutes(5), default);
        Assert.Equal(1, Assert.Single(claimed).Message.ActionAttempts);
        await h.Runner.QuiesceAsync(TimeSpan.FromSeconds(1), default);
        var again = await h.Storage.Inbound.ClaimActionsAsync("someone-else", 1, h.Clock.UtcNow, TimeSpan.FromMinutes(5), default);
        Assert.Equal(1, Assert.Single(again).Message.ActionAttempts);   // the attempt was given back

        await cts.CancelAsync();
        await loop.WaitAsync(TimeSpan.FromSeconds(30));
        _ = draft;
    }

    [Fact]
    public async Task Attempts_are_counted_by_kind_and_outcome_and_the_failure_is_one_tagged_series()
    {
        var counts = new Dictionary<string, long>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == "Mta.Inbound.Actions")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
        {
            string key = instrument.Name + ":" + string.Join(",", tags.ToArray().Select(t => $"{t.Key}={t.Value}").Order());
            lock (counts) { counts[key] = counts.GetValueOrDefault(key) + value; }
        });
        listener.Start();

        await using var h = await new InboundActionHarness().InitializeAsync();
        h.Receiver.Respond(HttpStatusCode.InternalServerError, HttpStatusCode.OK);
        await h.ReceiveAsync();
        await h.RunAsync();
        h.Clock.Advance(TimeSpan.FromSeconds(10));
        await h.RunAsync();

        lock (counts)
        {
            Assert.Equal(1, counts["mta.inbound.actions:kind=webhook,outcome=retry"]);
            Assert.Equal(1, counts["mta.inbound.actions:kind=webhook,outcome=done"]);
        }
    }

    [Fact]
    public void Webhook_ids_repeat_for_automatic_retries_and_change_for_a_manual_one()
    {
        Guid id = Guid.Parse("018f0000-0000-7000-8000-000000000001");
        Assert.Equal("evt_018f0000000070008000000000000001", InboundWebhookPayload.WebhookId(id, 0));
        Assert.Equal("evt_018f0000000070008000000000000001-3", InboundWebhookPayload.WebhookId(id, 3));
    }

    [Theory]
    [InlineData("alice@sender.test", "alice@sender.test")]
    [InlineData("a b", "a%20b")]
    [InlineData("x\r\nEvil: 1", "x%0D%0AEvil:%201")]
    [InlineData("bü@x.test", "b%C3%BC@x.test")]
    [InlineData("100%", "100%25")]
    [InlineData("<a>\"q\"", "%3Ca%3E%22q%22")]
    public void Header_values_are_percent_encoded_ascii(string value, string expected) => Assert.Equal(expected, InboundWebhookPayload.EncodeHeaderValue(value));

    [Fact]
    public void An_unpaired_surrogate_cannot_reach_the_json_writer()
    {
        Assert.Equal("a�b", InboundWebhookPayload.Safe("a\uD800b"));
        Assert.Equal("a😀b", InboundWebhookPayload.Safe("a😀b"));
        Assert.Equal("�", InboundWebhookPayload.Safe("\uDC00"));
    }

    [Fact]
    public void The_default_ladder_is_the_webhook_ladder_about_27_hours_in_eight_attempts()
    {
        Assert.Equal(8, new InboundActionOptions().MaxAttempts);
        Assert.InRange(InboundActionOptions.DefaultRetrySchedule.Aggregate(TimeSpan.Zero, (a, b) => a + b).TotalHours, 27, 28);
        Assert.Equal(new WebhookOptions().RetrySchedule, InboundActionOptions.DefaultRetrySchedule);
    }
}
