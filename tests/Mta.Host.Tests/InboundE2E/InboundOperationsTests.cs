using Mta.Host.Configuration;
using Mta.Host.Switching;
using Mta.Host.Tests.Inbound;
using Mta.Storage;

namespace Mta.Host.Tests.InboundE2E;

/// <summary>
/// What an operator does to a server that receives mail, seen from the mail: the master switch, and a backend switch that starts while a webhook action is in flight.
/// </summary>
public abstract class InboundOperationsTests(LabBackend backend)
{
    private static InboundSection Enabled(bool on = true) => new()
    {
        Enabled = on,
        CheckSpfForInternalClients = true,
        MaxMessagesPerMinute = 1_000_000,
        MaxMessagesPerMinutePerRemote = 1_000_000,
        Action = new InboundActionSection { PollInterval = TimeSpan.FromMilliseconds(40) },
    };

    [Fact]
    public async Task With_the_master_switch_off_the_port_is_the_bounce_listener_it_always_was_and_mail_stored_before_waits_with_its_reason()
    {
        var on = new LabOptions { Inbound = Enabled(), WithApi = true };
        await using InboundLab? lab = await InboundLab.StartAsync(backend, on);
        if (lab is null)
        {
            return;
        }

        await using WebhookReceiver receiver = await WebhookReceiver.StartAsync();
        WebhookEndpointRecord endpoint = await lab.AddWebhookEndpointAsync(InboundLab.Acme, receiver.Url);
        await lab.AddRouteAsync(lab.ExampleOrg, InboundLab.Acme, 5, InboundMatchKind.Address, "hook", InboundActionKind.Webhook, webhookEndpoint: endpoint.Id);
        await lab.RefreshAsync();
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "while on"))).Code);
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "hook@example.org", InboundLab.Message(subject: "waiting for its webhook"))).Code);   // no runner yet: pending
        InboundMessage waiting = (await lab.MessagesAsync(InboundLab.Acme)).Single(m => m.Subject == "waiting for its webhook");
        Assert.Equal(InboundActionState.Pending, waiting.ActionState);

        await lab.RestartAsync(reconfigure: o => o with { Inbound = Enabled(on: false) });

        // Off: exactly the server of before inbound mail. The domain is still enabled in the database, and nothing is received for it.
        Assert.Null(lab.Runtime.Inbound);
        await using (Host.Tests.Inbound.FakeMta mta = await lab.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
            var denied = await mta.RcptAsync("support@example.org");
            Assert.Equal((550, "5.1.1"), (denied.Code, denied.Enhanced));   // what the bounce listener always said to anything that is not a bounce address
        }

        // The bounce path is untouched.
        string token = lab.BounceLocalPart();
        Assert.Equal(250, (await lab.SendAsync("", $"{token}@{InboundLab.BounceDomain}", InboundLab.Dsn($"{token}@{InboundLab.BounceDomain}", "gone@dest.example"))).Code);
        Assert.True(await lab.Storage.Config.IsSuppressedAsync(InboundLab.Acme, "gone@dest.example", default));

        // What was stored while it was on is still there, and the action that waited is deferred with its reason (it counts against the ladder: this is the bound on how long it can wait).
        Assert.Equal(2, (await lab.MessagesAsync(InboundLab.Acme)).Count);
        Assert.Equal(1, await lab.Runtime.InboundActions.RunOnceAsync(default));
        InboundMessage deferred = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, waiting.Id, default))!;
        Assert.Equal((InboundActionState.Pending, 1, "inbound_disabled"), (deferred.ActionState, deferred.ActionAttempts, deferred.ActionLastError));
        Assert.Empty(receiver.Requests);

        // Switched on again: the mail is received again and the waiting action is carried out on its next rung.
        await lab.RestartAsync(reconfigure: o => o with { Inbound = Enabled(), RunActions = true });
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "on again"))).Code);
        await lab.AdvanceAsync(TimeSpan.FromSeconds(6));
        await receiver.WaitForRequestsAsync(1);
        Assert.Equal("evt_" + Mta.Host.Api.ApiJson.Id(waiting.Id), receiver.Requests.Single().Id);
    }

    [Fact]
    public async Task A_switch_that_starts_while_a_webhook_is_in_flight_gives_the_attempt_back_and_the_action_runs_again_after_the_switch_is_called_off()
    {
        var options = new LabOptions { Inbound = Enabled(), RunActions = true };
        await using InboundLab? lab = await InboundLab.StartAsync(backend, options);
        if (lab is null)
        {
            return;
        }

        await using WebhookReceiver receiver = await WebhookReceiver.StartAsync();
        var hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        receiver.Gate = () => hold.Task;
        WebhookEndpointRecord endpoint = await lab.AddWebhookEndpointAsync(InboundLab.Acme, receiver.Url);
        await lab.AddRouteAsync(lab.ExampleOrg, InboundLab.Acme, 5, InboundMatchKind.Address, "hook", InboundActionKind.Webhook, webhookEndpoint: endpoint.Id);
        await lab.RefreshAsync();
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "hook@example.org", InboundLab.Message(subject: "in flight"))).Code);
        Guid id = Assert.Single(await lab.MessagesAsync(InboundLab.Acme)).Id;
        await receiver.WaitForRequestsAsync(1);   // the runner has claimed it and is waiting for the receiver

        // The switch quiesces the instance: the attempt in flight is waited for (the receiver does not answer), then given back.
        var control = new HostSwitchControl(lab.Runtime, new SwitchRuntimeState(StartupDecision.Normal));
        await control.PauseDispatchAsync(default);
        await control.QuiesceDeliveriesAsync(TimeSpan.FromMilliseconds(200), default);

        InboundMessage given = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, id, default))!;
        Assert.Equal((InboundActionState.Pending, 0), (given.ActionState, given.ActionAttempts));   // the attempt the claim counted was not made as far as the record goes
        var probe = await lab.Storage.Inbound.ClaimActionsAsync("another-replica", 5, lab.Clock.UtcNow, TimeSpan.FromMinutes(1), default);
        Assert.Equal(id, Assert.Single(probe).Message.Id);   // it is free for whoever holds the rows next (the switch's hold, or the target after activation)
        await lab.Storage.Inbound.ReleaseOwnedActionLeasesAsync("another-replica", default);

        // The late answer of the receiver changes nothing: the lease is gone, so the result is not recorded. Asserted once the receiver has answered and the runner is done with the answer (the
        // runner is paused, so waiting for its attempts in flight waits for exactly this one and claims nothing new).
        hold.SetResult();
        await receiver.WaitForAnswersAsync(1);
        await lab.Runtime.InboundActions.QuiesceAsync(TimeSpan.FromSeconds(30), default);
        InboundMessage afterLateAnswer = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, id, default))!;
        Assert.Equal((InboundActionState.Pending, 0), (afterLateAnswer.ActionState, afterLateAnswer.ActionAttempts));

        // The switch is called off: dispatch resumes and the action runs again. The receiver sees the same webhook-id twice, as it must be ready for (at-least-once).
        receiver.Gate = null;
        await control.ResumeDispatchAsync(default);
        DateTime deadline = DateTime.UtcNow.AddSeconds(30);
        InboundMessage done;
        do
        {
            await Task.Delay(30);
            done = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, id, default))!;
        }
        while (done.ActionState != InboundActionState.Done && DateTime.UtcNow < deadline);

        Assert.Equal((InboundActionState.Done, 1), (done.ActionState, done.ActionAttempts));
        Assert.Equal(2, receiver.Requests.Count);
        Assert.Single(receiver.Requests.Select(r => r.Id).Distinct());
    }
}

public sealed class SqliteInboundOperationsTests() : InboundOperationsTests(LabBackend.Sqlite);

public sealed class PostgresInboundOperationsTests() : InboundOperationsTests(LabBackend.Postgres);
