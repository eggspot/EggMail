using Mta.Host.Configuration;
using Mta.Host.Switching;
using Mta.Host.Tests.Inbound;
using Mta.Storage;

namespace Mta.Host.Tests.InboundE2E;

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
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "hook@example.org", InboundLab.Message(subject: "waiting for its webhook"))).Code);
        InboundMessage waiting = (await lab.MessagesAsync(InboundLab.Acme)).Single(m => m.Subject == "waiting for its webhook");
        Assert.Equal(InboundActionState.Pending, waiting.ActionState);

        await lab.RestartAsync(reconfigure: o => o with { Inbound = Enabled(on: false) });

        Assert.Null(lab.Runtime.Inbound);
        await using (Host.Tests.Inbound.FakeMta mta = await lab.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
            var denied = await mta.RcptAsync("support@example.org");
            Assert.Equal((550, "5.1.1"), (denied.Code, denied.Enhanced));
        }

        string token = lab.BounceLocalPart();
        string sent = await lab.MessageIdOfAMessageDeliveredToAsync("gone@dest.example");
        Assert.Equal(250, (await lab.SendAsync("", $"{token}@{InboundLab.BounceDomain}", InboundLab.Dsn($"{token}@{InboundLab.BounceDomain}", "gone@dest.example", sent))).Code);
        Assert.True(await lab.Storage.Config.IsSuppressedAsync(InboundLab.Acme, "gone@dest.example", default));

        Assert.Equal(2, (await lab.MessagesAsync(InboundLab.Acme)).Count);
        Assert.Equal(1, await lab.Runtime.InboundActions.RunOnceAsync(default));
        InboundMessage deferred = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, waiting.Id, default))!;
        Assert.Equal((InboundActionState.Pending, 1, "inbound_disabled"), (deferred.ActionState, deferred.ActionAttempts, deferred.ActionLastError));
        Assert.Empty(receiver.Requests);

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
        await receiver.WaitForRequestsAsync(1);

        var control = new HostSwitchControl(lab.Runtime, new SwitchRuntimeState(StartupDecision.Normal));
        await control.PauseDispatchAsync(default);
        await control.QuiesceDeliveriesAsync(TimeSpan.FromMilliseconds(200), default);

        InboundMessage given = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, id, default))!;
        Assert.Equal((InboundActionState.Pending, 0), (given.ActionState, given.ActionAttempts));
        var probe = await lab.Storage.Inbound.ClaimActionsAsync("another-replica", 5, lab.Clock.UtcNow, TimeSpan.FromMinutes(1), default);
        Assert.Equal(id, Assert.Single(probe).Message.Id);
        await lab.Storage.Inbound.ReleaseOwnedActionLeasesAsync("another-replica", default);

        hold.SetResult();
        await receiver.WaitForAnswersAsync(1);
        await lab.Runtime.InboundActions.QuiesceAsync(TimeSpan.FromSeconds(30), default);
        InboundMessage afterLateAnswer = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, id, default))!;
        Assert.Equal((InboundActionState.Pending, 0), (afterLateAnswer.ActionState, afterLateAnswer.ActionAttempts));

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
