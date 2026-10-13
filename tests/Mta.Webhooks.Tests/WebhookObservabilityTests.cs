using System.Diagnostics;
using System.Net;
using System.Text;
using Mta.Core;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Webhooks.Tests;

/// <summary>Metrics and the trace span of the webhook dispatcher, with a stub receiver. All dispatching in this assembly happens in this class, so counts are exact.</summary>
[Collection("webhook-dispatch")]
public class WebhookObservabilityTests
{
    private sealed class PlainProtector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => plaintext.ToArray();

        public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose) => protectedData.ToArray();
    }

    private sealed class StubReceiver(HttpStatusCode status) : HttpMessageHandler
    {
        public int Calls;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Calls);
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent("answer") });
        }
    }

    private sealed class Rig : IAsyncDisposable
    {
        public readonly InMemoryStorage Storage = new(new StorageOptions { History = new HistoryOptions { Mode = HistoryMode.Full } }, SystemClock.Instance);
        public readonly Guid Tenant = Ids.New();
        public readonly Guid Endpoint = Ids.New();
        public WebhookDispatcher Dispatcher = null!;
        public StubReceiver Receiver = null!;

        public static async Task<Rig> StartAsync(HttpStatusCode status, WebhookOptions? options = null)
        {
            var rig = new Rig();
            await rig.Storage.InitializeAsync(default);
            rig.Receiver = new StubReceiver(status);
            var protector = new PlainProtector();
            await rig.Storage.Config.UpsertWebhookEndpointAsync(new WebhookEndpointRecord(
                rig.Endpoint, rig.Tenant, "https://hooks.example/in", protector.Protect(Encoding.UTF8.GetBytes(StandardWebhooksSigner.GenerateSecret()), SecretPurposes.WebhookSecret),
                ["message.delivered"], true, null, null, DateTimeOffset.UtcNow, null), default);
            rig.Dispatcher = new WebhookDispatcher(rig.Storage.Webhooks, rig.Storage.Config, protector, options, handlerOverride: rig.Receiver);
            return rig;
        }

        public async Task QueueEventAsync(Guid? messageId)
        {
            string data = messageId is { } id ? $"\"data\":{{\"message_id\":\"{Ids.ToCompact(id)}\"}}" : "\"data\":{}";
            var draft = new WebhookEventDraft(Ids.New(), "message.delivered", "{\"type\":\"message.delivered\"," + data + "}");
            Assert.Equal(1, await Storage.Webhooks.EnqueueAsync(Tenant, draft, DateTimeOffset.UtcNow, default));
        }

        public async ValueTask DisposeAsync()
        {
            await Dispatcher.DisposeAsync();
            await Storage.DisposeAsync();
        }
    }

    private static MeterCapture Capture() => new(m => m.Name == "Mta.Webhooks");

    [Fact]
    public async Task A_delivered_event_counts_one_delivery_and_its_duration()
    {
        await using var rig = await Rig.StartAsync(HttpStatusCode.OK);
        using var capture = Capture();
        await rig.QueueEventAsync(Ids.New());

        Assert.Equal(1, await rig.Dispatcher.RunOnceAsync(default));

        Assert.Equal(1, capture.Sum("mta.webhooks.claimed"));
        Assert.Equal(1, capture.Sum("mta.webhooks.deliveries", ("outcome", "delivered")));
        Assert.Equal(0, capture.Sum("mta.webhooks.failures"));
        Assert.Single(capture.Of("mta.webhooks.delivery.duration"));
        Assert.Equal(1, rig.Receiver.Calls);
    }

    [Fact]
    public async Task A_server_error_is_a_retry_with_a_bounded_reason()
    {
        await using var rig = await Rig.StartAsync(HttpStatusCode.ServiceUnavailable);
        using var capture = Capture();
        await rig.QueueEventAsync(Ids.New());

        await rig.Dispatcher.RunOnceAsync(default);

        Assert.Equal(1, capture.Sum("mta.webhooks.deliveries", ("outcome", "retry")));
        Assert.Equal(1, capture.Sum("mta.webhooks.failures", ("reason", "http_5xx")));
    }

    [Fact]
    public async Task Giving_up_after_the_last_retry_is_a_failure()
    {
        await using var rig = await Rig.StartAsync(HttpStatusCode.BadRequest, new WebhookOptions { RetrySchedule = [] });
        using var capture = Capture();
        await rig.QueueEventAsync(Ids.New());

        await rig.Dispatcher.RunOnceAsync(default);

        Assert.Equal(1, capture.Sum("mta.webhooks.deliveries", ("outcome", "failed")));
        Assert.Equal(1, capture.Sum("mta.webhooks.failures", ("reason", "http_4xx")));
    }

    [Fact]
    public async Task Gone_disables_the_endpoint_and_counts_it()
    {
        await using var rig = await Rig.StartAsync(HttpStatusCode.Gone);
        using var capture = Capture();
        await rig.QueueEventAsync(Ids.New());

        await rig.Dispatcher.RunOnceAsync(default);

        Assert.Equal(1, capture.Sum("mta.webhooks.deliveries", ("outcome", "failed")));
        Assert.Equal(1, capture.Sum("mta.webhooks.failures", ("reason", "gone")));
        Assert.Equal(1, capture.Sum("mta.webhooks.endpoints.disabled"));
    }

    [Theory]
    [InlineData("timeout", "timeout")]
    [InlineData("connect_failed", "connect_failed")]
    [InlineData("ssrf_blocked", "ssrf_blocked")]
    [InlineData("throttled", "throttled")]
    [InlineData("gone", "gone")]
    [InlineData("redirect_not_followed", "redirect")]
    [InlineData("http_404", "http_4xx")]
    [InlineData("http_503", "http_5xx")]
    [InlineData("http_error", "other")]
    [InlineData("http_999", "other")]
    [InlineData("something_new", "other")]
    [InlineData("endpoint_unavailable", "endpoint_unavailable")]
    [InlineData("secret_unreadable", "secret_unreadable")]
    public void Error_classes_fold_into_a_fixed_set_of_reasons(string errorClass, string reason) =>
        Assert.Equal(reason, WebhookMetrics.ReasonOf(errorClass));

    private static ActivityListener Listen(List<Activity> stopped, Func<Activity, bool> keep)
    {
        var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == MessageTrace.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = a => { if (keep(a)) { lock (stopped) { stopped.Add(a); } } },
        };
        ActivitySource.AddActivityListener(listener);
        return listener;
    }

    [Fact]
    public async Task The_webhook_span_joins_the_trace_of_the_message_named_in_the_payload()
    {
        await using var rig = await Rig.StartAsync(HttpStatusCode.OK);
        var message = Ids.New();
        var stopped = new List<Activity>();
        using ActivityListener listener = Listen(stopped, _ => true);
        await rig.QueueEventAsync(message);

        await rig.Dispatcher.RunOnceAsync(default);

        Activity span;
        lock (stopped)
        {
            span = Assert.Single(stopped);
        }

        Assert.Equal(MessageTrace.WebhookDeliverSpan, span.OperationName);
        Assert.Equal(ActivityKind.Client, span.Kind);
        Assert.Equal(Ids.ToCompact(message), span.TraceId.ToHexString());
        Assert.Equal(MessageTrace.RootContextOf(message).SpanId, span.ParentSpanId);
        Assert.Equal("message.delivered", span.GetTagItem("mta.webhook.event_type"));
        Assert.Equal(200, span.GetTagItem("http.response.status_code"));
        Assert.NotEqual(ActivityStatusCode.Error, span.Status);
    }

    [Fact]
    public async Task A_failed_call_marks_the_span_and_an_event_without_a_message_starts_its_own_trace()
    {
        await using var rig = await Rig.StartAsync(HttpStatusCode.InternalServerError);
        var stopped = new List<Activity>();
        using ActivityListener listener = Listen(stopped, _ => true);
        await rig.QueueEventAsync(messageId: null);

        await rig.Dispatcher.RunOnceAsync(default);

        Activity span;
        lock (stopped)
        {
            span = Assert.Single(stopped);
        }

        Assert.Equal(ActivityStatusCode.Error, span.Status);
        Assert.Equal("http_500", span.GetTagItem("mta.webhook.error"));
        Assert.Equal(default, span.ParentSpanId);
        Assert.Null(span.GetTagItem(MessageTrace.MessageIdTag));
    }
}
