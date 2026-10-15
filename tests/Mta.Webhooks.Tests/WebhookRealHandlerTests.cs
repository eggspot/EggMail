using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Mta.Core;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Webhooks.Tests;

/// <summary>The dispatcher's own HTTP handler (not the test stub): what actually goes on the wire to a customer's receiver.</summary>
[Collection("webhook-dispatch")]
public sealed class WebhookRealHandlerTests : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly string _url;
    private readonly List<System.Collections.Specialized.NameValueCollection> _headers = [];
    private readonly Task _serve;

    public WebhookRealHandlerTests()
    {
        int port;
        using (var probe = new TcpListener(IPAddress.Loopback, 0))
        {
            probe.Start();
            port = ((IPEndPoint)probe.LocalEndpoint).Port;
        }

        _url = $"http://127.0.0.1:{port}/hook";
        _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        _listener.Start();
        _serve = Task.Run(async () =>
        {
            while (true)
            {
                HttpListenerContext context;
                try { context = await _listener.GetContextAsync(); }
                catch (Exception ex) when (ex is HttpListenerException or ObjectDisposedException or InvalidOperationException) { return; }
                lock (_headers) { _headers.Add(context.Request.Headers); }
                context.Response.StatusCode = 200;
                context.Response.Close();
            }
        });
    }

    public void Dispose()
    {
        _listener.Close();
        _serve.Wait(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task The_production_handler_never_uses_a_proxy_follows_no_redirect_and_connects_through_the_ssrf_guard()
    {
        var storage = new InMemoryStorage(new StorageOptions(), SystemClock.Instance);
        await storage.InitializeAsync(default);
        await using var dispatcher = new WebhookDispatcher(storage.Webhooks, storage.Config, new PlainProtector());

        using SocketsHttpHandler handler = dispatcher.CreateHandler();

        // The guard validates the address of the connection it makes; through a proxy that would be the proxy's, whatever HTTPS_PROXY says.
        Assert.False(handler.UseProxy);
        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.NotNull(handler.ConnectCallback);
    }

    [Fact]
    public async Task A_sampled_webhook_call_does_not_hand_trace_headers_to_the_receiver()
    {
        var storage = new InMemoryStorage(new StorageOptions { History = new HistoryOptions { Mode = HistoryMode.Full } }, SystemClock.Instance);
        await storage.InitializeAsync(default);
        var tenant = Ids.New();
        var endpoint = Ids.New();
        var protector = new PlainProtector();
        await storage.Config.UpsertWebhookEndpointAsync(new WebhookEndpointRecord(
            endpoint, tenant, _url, protector.Protect(Encoding.UTF8.GetBytes(StandardWebhooksSigner.GenerateSecret()), SecretPurposes.WebhookSecret),
            ["message.delivered"], true, null, null, DateTimeOffset.UtcNow, null), default);
        await using var dispatcher = new WebhookDispatcher(storage.Webhooks, storage.Config, protector)
        {
            AllowlistProvider = _ => [IpNetwork.Parse("127.0.0.0/8")],   // the receiver is on loopback
        };

        // A listener makes the span real (and current while the request is sent): the case where the handler would add traceparent.
        var spans = new List<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == MessageTrace.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = a => { lock (spans) { spans.Add(a); } },
        };
        ActivitySource.AddActivityListener(listener);
        var message = Ids.New();
        Assert.Equal(1, await storage.Webhooks.EnqueueAsync(tenant, new WebhookEventDraft(Ids.New(), "message.delivered",
            "{\"type\":\"message.delivered\",\"data\":{\"message_id\":\"" + Ids.ToCompact(message) + "\"}}"), DateTimeOffset.UtcNow, default));

        Assert.Equal(1, await dispatcher.RunOnceAsync(default));

        lock (spans) { Assert.Contains(spans, s => s.OperationName == MessageTrace.WebhookDeliverSpan && s.TraceId.ToHexString() == Ids.ToCompact(message)); }
        System.Collections.Specialized.NameValueCollection received;
        lock (_headers) { received = Assert.Single(_headers); }
        Assert.Null(received["traceparent"]);
        Assert.Null(received["tracestate"]);
        Assert.Null(received["Request-Id"]);
        Assert.Null(received["baggage"]);
        Assert.NotNull(received["webhook-signature"]);   // the call itself went through the real handler
    }

    private sealed class PlainProtector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => plaintext.ToArray();

        public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose) => protectedData.ToArray();
    }
}

public class WebhookTracingTests
{
    [Fact]
    public void The_message_id_is_found_in_our_payloads_without_parsing_them()
    {
        var id = Ids.New();
        string payload = "{\"id\":\"evt_1\",\"type\":\"message.delivered\",\"data\":{\"message_id\":\"" + Ids.ToCompact(id) + "\",\"recipient\":\"a@b.test\"}}";

        Assert.Equal(id, WebhookTracing.MessageIdOf(payload));
    }

    [Theory]
    [InlineData("{\"type\":\"webhook.endpoint.disabled\",\"data\":{\"endpoint_id\":\"abc\"}}")]
    [InlineData("{\"data\":{\"original_message_id\":\"<1@example.org>\"}}")]       // an RFC Message-ID of a remote bounce, not ours
    [InlineData("{\"data\":{\"message_id\":\"not-a-guid-not-a-guid-not-a-guid-xx\"}}")]
    [InlineData("{\"data\":{\"message_id\":\"abc\"}}")]
    [InlineData("")]
    public void Payloads_without_a_message_of_ours_have_no_message_id(string payload) =>
        Assert.Null(WebhookTracing.MessageIdOf(payload));
}
