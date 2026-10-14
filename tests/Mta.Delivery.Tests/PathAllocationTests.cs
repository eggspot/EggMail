using System.Collections.Concurrent;
using Mta.Core;
using Mta.Storage;

namespace Mta.Delivery.Tests;

/// <summary>Work the delivery path used to do for nothing (event payloads nobody receives, trace lines nobody reads) now only happens when it can matter.</summary>
public class PathAllocationTests
{
    private static WebhookEndpointRecord Endpoint(params string[] types) =>
        new(Ids.New(), DeliveryFixture.Tenant, "https://hooks.example.com/x", [1, 2, 3], types, true, null, null, DateTimeOffset.UtcNow, null);

    private static async Task<IReadOnlyList<WebhookOutboxItem>> OutboxAsync(DeliveryFixture f) =>
        await f.Storage.Webhooks.ClaimDueAsync("test", 100, DateTimeOffset.UtcNow.AddMinutes(1), TimeSpan.FromMinutes(1), default);

    [Fact]
    public async Task No_event_payload_is_queued_when_no_endpoint_exists()
    {
        await using var f = new DeliveryFixture();
        var id = await f.EnqueueAsync(["rcpt@dest.example"]);
        await f.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.Empty(await OutboxAsync(f));
    }

    [Fact]
    public async Task A_subscribed_endpoint_gets_the_delivered_event_with_its_payload()
    {
        await using var f = new DeliveryFixture();
        await f.Storage.Config.UpsertWebhookEndpointAsync(Endpoint("message.delivered"), default);
        var id = await f.EnqueueAsync(["rcpt@dest.example"]);
        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        var item = Assert.Single(await OutboxAsync(f));
        Assert.Equal("message.delivered", item.EventType);
        Assert.Contains("\"type\":\"message.delivered\"", item.PayloadJson);
        Assert.Contains("\"recipient\":\"rcpt@dest.example\"", item.PayloadJson);
    }

    [Fact]
    public async Task An_endpoint_that_subscribes_to_other_events_gets_nothing_for_a_delivery()
    {
        await using var f = new DeliveryFixture();
        await f.Storage.Config.UpsertWebhookEndpointAsync(Endpoint("message.bounced"), default);
        var id = await f.EnqueueAsync(["rcpt@dest.example"]);
        await f.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.Empty(await OutboxAsync(f));
    }

    [Fact]
    public async Task An_endpoint_added_while_the_engine_runs_receives_the_next_delivery()
    {
        await using var f = new DeliveryFixture();
        var first = await f.EnqueueAsync(["a@dest.example"]);
        await f.WaitForEventAsync(first, MessageEventType.Delivered);
        Assert.Empty(await OutboxAsync(f));

        await f.Storage.Config.UpsertWebhookEndpointAsync(Endpoint("*"), default);
        var second = await f.EnqueueAsync(["b@dest.example"]);
        await f.WaitForEventAsync(second, MessageEventType.Delivered);
        Assert.Contains("b@dest.example", Assert.Single(await OutboxAsync(f)).PayloadJson);
    }

    private sealed class CapturingLog(MtaLogLevel level) : IMtaLog
    {
        public ConcurrentQueue<string> Lines { get; } = [];

        public bool IsEnabled(MtaLogLevel l) => l >= level;

        public void Write(MtaLogLevel l, string source, string message, Exception? exception = null)
        {
            if (IsEnabled(l))
            {
                Lines.Enqueue(source + ": " + message);
            }
        }
    }

    [Fact]
    public async Task Trace_lines_are_written_with_debug_logging_and_not_at_all_without_it()
    {
        var debug = new CapturingLog(MtaLogLevel.Debug);
        await using (var f = new DeliveryFixture(log: debug))
        {
            var id = await f.EnqueueAsync(["rcpt@dest.example"]);
            await f.WaitForEventAsync(id, MessageEventType.Delivered);
        }

        Assert.Contains(debug.Lines, l => l.Contains("connect mx.dest.example [127.0.0.1]", StringComparison.Ordinal));
        Assert.Contains(debug.Lines, l => l.Contains("sent via mx.dest.example: delivered=True", StringComparison.Ordinal));
        Assert.Contains(debug.Lines, l => l.Contains(": recorded", StringComparison.Ordinal));

        var quiet = new CapturingLog(MtaLogLevel.Warning);
        await using (var f = new DeliveryFixture(log: quiet))
        {
            var id = await f.EnqueueAsync(["rcpt@dest.example"]);
            await f.WaitForEventAsync(id, MessageEventType.Delivered);
        }

        Assert.Empty(quiet.Lines);
    }
}
