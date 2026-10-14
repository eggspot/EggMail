using Mta.Smtp.Protocol;
using Mta.Storage;

namespace Mta.Delivery.Tests;

/// <summary>Cancelling (decision 80) through the real engine, processor, SMTP client and a loopback remote server.</summary>
[Collection("delivery-pipeline")]
public class CancelThroughEngineTests
{
    private static Task<CancelResult> CancelAsync(DeliveryFixture f, Guid messageId, params string[] recipients) =>
        f.Storage.Deliveries.CancelAsync(DeliveryFixture.Tenant, messageId, recipients.Length == 0 ? null : recipients, DateTimeOffset.UtcNow, default).AsTask();

    [Fact]
    public async Task A_message_cancelled_before_its_first_attempt_is_never_sent()
    {
        await using var f = new DeliveryFixture(startEngine: false);
        var cancelled = await f.EnqueueAsync(["gone@dest.example", "also@dest.example"]);

        CancelResult result = await CancelAsync(f, cancelled);
        Assert.Equal(["also@dest.example", "gone@dest.example"], result.Cancelled);

        // A message queued afterwards is delivered by the same engine, which proves the engine ran over the queue without finding the cancelled one.
        f.StartEngine();
        var sentinel = await f.EnqueueAsync(["after@dest.example"]);
        await f.WaitForEventAsync(sentinel, MessageEventType.Delivered);

        Assert.Equal(["after@dest.example"], Assert.Single(f.Remote.Messages).Recipients);
        var events = await f.EventsAsync(cancelled);
        Assert.Equal(2, events.Count(e => e.Type == MessageEventType.Cancelled));
        Assert.DoesNotContain(events, e => e.Type is MessageEventType.Delivered or MessageEventType.Deferred or MessageEventType.Bounced);
        // No bounce message goes to the sender for a cancellation: only the sentinel was ever sent to the remote.
        Assert.Single(f.Remote.Messages);
    }

    [Fact]
    public async Task A_deferred_message_that_is_cancelled_is_not_retried()
    {
        await using var f = new DeliveryFixture();
        f.Remote.OnMessage = _ => SmtpReply.Create(451, "4.7.1", "Greylisted, try again later");
        var id = await f.EnqueueAsync(["rcpt@dest.example"]);
        await f.WaitForEventAsync(id, MessageEventType.Deferred);
        f.Remote.OnMessage = null;   // the next attempt would be accepted

        CancelResult result = await CancelAsync(f, id);

        Assert.Equal(["rcpt@dest.example"], result.Cancelled);
        QueueStats stats = await f.Storage.Deliveries.GetQueueStatsAsync(default);
        Assert.Equal(0, stats.Queued + stats.Leased + stats.Deferred);
        // Even far in the future there is nothing to claim, so no retry can ever start.
        Assert.Empty(await f.Storage.Deliveries.ClaimAsync("later", 10, DateTimeOffset.UtcNow.AddDays(30), TimeSpan.FromMinutes(1), default));
        Assert.Empty(f.Remote.Messages);
        Assert.Equal("cancelled", (await f.Storage.History.GetAsync(DeliveryFixture.Tenant, id, default))!.Summary.Status);
    }

    [Fact]
    public async Task A_delivery_in_the_middle_of_its_transaction_is_not_cancelled_and_completes_normally()
    {
        await using var f = new DeliveryFixture();
        var gate = new TaskCompletionSource();
        var entered = new TaskCompletionSource();
        f.Remote.OnMessage = _ =>
        {
            entered.TrySetResult();
            gate.Task.Wait(TimeSpan.FromSeconds(20));
            return null;
        };
        var id = await f.EnqueueAsync(["rcpt@dest.example"]);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));

        CancelResult result = await CancelAsync(f, id);

        Assert.Empty(result.Cancelled);
        Assert.Equal(["rcpt@dest.example"], result.InFlight);
        gate.SetResult();
        var events = await f.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.DoesNotContain(events, e => e.Type == MessageEventType.Cancelled);
        Assert.Equal("delivered", (await f.Storage.History.GetAsync(DeliveryFixture.Tenant, id, default))!.Summary.Status);
        Assert.Single(f.Remote.Messages);

        // And once it is final there is nothing left to cancel.
        result = await CancelAsync(f, id, "rcpt@dest.example");
        Assert.Empty(result.Cancelled);
        Assert.Equal(["rcpt@dest.example"], result.NotPending);
    }

    [Fact]
    public async Task Cancelling_one_recipient_of_a_waiting_message_still_delivers_the_others()
    {
        await using var f = new DeliveryFixture(startEngine: false);
        var id = await f.EnqueueAsync(["keep@dest.example", "drop@dest.example"]);

        await CancelAsync(f, id, "drop@dest.example");
        f.StartEngine();

        await f.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.Equal(["keep@dest.example"], Assert.Single(f.Remote.Messages).Recipients);
        Assert.Equal("partial", (await f.Storage.History.GetAsync(DeliveryFixture.Tenant, id, default))!.Summary.Status);
    }
}
