using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Ingest;
using Mta.Host.Tests.Api;
using Mta.Host.Inbound;
using Mta.Storage;
using Mta.Storage.InMemory;
using Mta.Webhooks;

namespace Mta.Host.Tests.Inbound;

/// <summary>A receiver that records what it was sent and answers from a script (one status per request, the last repeats).</summary>
internal sealed class FakeReceiver : HttpMessageHandler
{
    public sealed record Request(Uri Url, IReadOnlyDictionary<string, string> Headers, byte[] Body, string ContentType);

    private readonly ConcurrentQueue<Request> _requests = new();
    private readonly Queue<HttpStatusCode> _script = new();
    private HttpStatusCode _last = HttpStatusCode.OK;
    private int _active;
    private int _maxActive;

    /// <summary>When set, a request waits for it before answering (to hold requests in flight).</summary>
    public Func<Task>? Gate { get; set; }

    public IReadOnlyCollection<Request> Requests => _requests;

    public int MaxConcurrent => Volatile.Read(ref _maxActive);

    public void Respond(params HttpStatusCode[] statuses)
    {
        lock (_script)
        {
            foreach (HttpStatusCode status in statuses)
            {
                _script.Enqueue(status);
            }
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        int active = Interlocked.Increment(ref _active);
        int seen;
        while ((seen = Volatile.Read(ref _maxActive)) < active && Interlocked.CompareExchange(ref _maxActive, active, seen) != seen)
        {
        }

        try
        {
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in request.Headers)
            {
                headers[h.Key] = string.Join(",", h.Value);
            }

            byte[] body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            _requests.Enqueue(new Request(request.RequestUri!, headers, body, request.Content?.Headers.ContentType?.ToString() ?? ""));
            if (Gate is { } gate)
            {
                await gate().WaitAsync(cancellationToken).ConfigureAwait(false);   // a real handler stops when the caller cancels
            }

            HttpStatusCode status;
            lock (_script)
            {
                status = _script.Count > 0 ? _last = _script.Dequeue() : _last;
            }

            return new HttpResponseMessage(status) { Content = new StringContent("ok") };
        }
        finally
        {
            Interlocked.Decrement(ref _active);
        }
    }
}

internal sealed class PlainProtector : ISecretProtector
{
    /// <summary>A key provider that is down: opening a secret throws, like a key ring that cannot be read.</summary>
    public bool Down { get; set; }

    public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => plaintext.ToArray();

    public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose) =>
        Down ? throw new System.Security.Cryptography.CryptographicException("the key ring is not available") : protectedData.ToArray();
}

internal sealed class RecordingPublisher : IWebhookPublisher
{
    public ConcurrentQueue<(Guid Tenant, WebhookEventDraft Draft)> Published { get; } = new();

    public ValueTask PublishAsync(Guid tenantId, WebhookEventDraft draft, DateTimeOffset now, CancellationToken cancellationToken)
    {
        Published.Enqueue((tenantId, draft));
        return ValueTask.CompletedTask;
    }
}

internal sealed class FakeForwarder : IInboundForwarder
{
    public Func<InboundMessage, InboundRouteRecord, byte[], InboundActionResult> Handler { get; set; } = (_, _, _) => InboundActionResult.Done(forwardMessageId: Guid.NewGuid(), freeBody: true);

    public ConcurrentQueue<(InboundMessage Message, InboundRouteRecord Route)> Calls { get; } = new();

    public ValueTask<InboundActionResult> ForwardAsync(InboundMessage message, InboundRouteRecord route, byte[] raw, CancellationToken cancellationToken)
    {
        Calls.Enqueue((message, route));
        return ValueTask.FromResult(Handler(message, route, raw));
    }
}

/// <summary>A tenant, a verified inbound domain with a webhook endpoint and route on the in-memory store, and a runner wired to a fake receiver and a manual clock.</summary>
internal sealed class InboundActionHarness : IAsyncDisposable
{
    public const string Secret = "whsec_c2VjcmV0LWZvci10ZXN0cy0xMjM0NTY3ODkwMTI=";

    public TestClock Clock { get; } = new(new DateTimeOffset(2026, 10, 16, 8, 0, 0, TimeSpan.Zero));
    public InMemoryStorage Storage { get; }
    public FakeReceiver Receiver { get; } = new();
    public RecordingPublisher Publisher { get; } = new();
    public FakeForwarder Forwarder { get; } = new();
    public bool InboundEnabled { get; set; } = true;

    /// <summary>What tells the tenant that an endpoint was switched off (none by default).</summary>
    public IWebhookNotifier? Notifier { get; set; }
    public bool KeysDown { get => _protector.Down; set => _protector.Down = value; }
    public Guid TenantId { get; } = Ids.New();
    public DomainRecord Domain { get; private set; } = null!;
    public WebhookEndpointRecord Endpoint { get; private set; } = null!;
    public InboundRouteRecord Route { get; private set; } = null!;
    public WebhookTransport Transport { get; }
    public InboundActionRunner Runner { get; private set; } = null!;
    private readonly PlainProtector _protector = new();
    private InboundActionOptions _options;

    public InboundActionHarness(InboundActionOptions? options = null, bool useReceiver = true, Func<string, CancellationToken, ValueTask<IPAddress[]>>? resolver = null)
    {
        _options = options ?? new InboundActionOptions { RetrySchedule = [TimeSpan.FromSeconds(10), TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(10)] };
        Storage = new InMemoryStorage(new StorageOptions(), Clock);
        Transport = new WebhookTransport(new WebhookOptions { AllowHttp = true }, Clock, resolver, useReceiver ? Receiver : null);
    }

    public async Task<InboundActionHarness> InitializeAsync(InboundActionKind action = InboundActionKind.Webhook, InboundWebhookFormat format = InboundWebhookFormat.Json, bool withForwarder = false)
    {
        await Storage.InitializeAsync(default);
        await Storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Tenant", "tenant", true, Clock.UtcNow, false), default);
        Domain = new DomainRecord(Ids.New(), TenantId, "example.com", DomainStatus.Verified, null, false, Clock.UtcNow, null, null, 0, null, false, null);
        await Storage.Config.UpsertDomainAsync(Domain, default);
        await Storage.Inbound.UpsertSettingsAsync(new InboundDomainSettings(Domain.Id, TenantId, true, InboundDmarcAction.RecordOnly, null, null, null, null, null, Clock.UtcNow), default);
        Endpoint = await AddEndpointAsync(TenantId, "https://hooks.example.test/inbound");
        Route = new InboundRouteRecord(
            Ids.New(), TenantId, Domain.Id, "route", 10, true, InboundMatchKind.CatchAll, null, false, action,
            action == InboundActionKind.Webhook ? Endpoint.Id : null, format, action == InboundActionKind.Forward ? ["target@example.org"] : [], Clock.UtcNow, Clock.UtcNow);
        await Storage.Inbound.UpsertRouteAsync(Route, default);
        Runner = CreateRunner(withForwarder);
        return this;
    }

    public InboundActionRunner CreateRunner(bool withForwarder = false, InboundActionOptions? options = null)
    {
        if (options is not null)
        {
            _options = options;
        }

        var health = new WebhookEndpointHealth(Storage.Config, new WebhookOptions(), null, Notifier);
        return new InboundActionRunner(Storage, Transport, health, _protector, _options, Clock, NullMtaLog.Instance, () => InboundEnabled, Publisher, withForwarder ? Forwarder : null);
    }

    public async Task<WebhookEndpointRecord> AddEndpointAsync(Guid tenantId, string url, bool enabled = true)
    {
        var endpoint = new WebhookEndpointRecord(
            Ids.New(), tenantId, url, _protector.Protect(Encoding.UTF8.GetBytes(Secret), SecretPurposes.WebhookSecret), ["*"], enabled, enabled ? null : "off", enabled ? null : Clock.UtcNow, Clock.UtcNow, null);
        await Storage.Config.UpsertWebhookEndpointAsync(endpoint, default);
        return endpoint;
    }

    public static byte[] SimpleMessage(string subject = "Hello", string body = "Hi there\r\n") =>
        Encoding.UTF8.GetBytes($"From: Alice <alice@sender.test>\r\nTo: support@example.com\r\nSubject: {subject}\r\nMessage-ID: <m1@sender.test>\r\nDate: Thu, 16 Oct 2026 07:59:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}");

    public static byte[] MessageWithAttachment() => Encoding.ASCII.GetBytes(
        "From: Alice <alice@sender.test>\r\nTo: Support <support@example.com>, other@example.com\r\nCc: cc@example.com\r\nSubject: With file\r\nMessage-ID: <m2@sender.test>\r\n"
        + "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n"
        + "--b1\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSee attached.\r\n"
        + "--b1\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>See <b>attached</b>.</p>\r\n"
        + "--b1\r\nContent-Type: application/pdf; name=\"report.pdf\"\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8gd29ybGQ=\r\n"
        + "--b1--\r\n");

    /// <summary>Stores one message for the route of the harness and returns its id.</summary>
    public async Task<InboundMessageDraft> ReceiveAsync(byte[]? raw = null, InboundActionKind? kind = null, string from = "alice@sender.test", string to = "support@example.com", Guid? routeId = null)
    {
        DateTimeOffset at = Clock.UtcNow;
        var draft = new InboundMessageDraft
        {
            Id = Ids.New(at),
            TenantId = TenantId,
            DomainId = Domain.Id,
            Domain = Domain.Name,
            ReceivedAt = at,
            RemoteAddress = "203.0.113.9",
            Helo = "mail.sender.test",
            TlsUsed = true,
            EnvelopeFrom = from,
            EnvelopeTo = to,
            Subject = "Hello",
            Auth = new InboundAuthResults(InboundVerdict.Pass, "sender.test", InboundVerdict.Pass, InboundVerdict.Pass, "sender.test", InboundVerdict.Pass, "reject", InboundVerdict.None),
            RouteId = routeId ?? Route.Id,
            ActionKind = kind ?? Route.ActionKind,
            Raw = raw ?? SimpleMessage(),
        };
        await Storage.Inbound.AcceptAsync([draft], default);
        return draft;
    }

    /// <summary>Another tenant with an enabled inbound domain, a webhook endpoint and a catch-all webhook route.</summary>
    public sealed record OtherTenant(Guid TenantId, DomainRecord Domain, InboundRouteRecord Route);

    public async Task<OtherTenant> AddTenantAsync(string domainName, string url)
    {
        Guid tenantId = Ids.New();
        await Storage.Config.UpsertTenantAsync(new Tenant(tenantId, "Other " + domainName, "o" + tenantId.ToString("N")[..8], true, Clock.UtcNow, false), default);
        var domain = new DomainRecord(Ids.New(), tenantId, domainName, DomainStatus.Verified, null, false, Clock.UtcNow, null, null, 0, null, false, null);
        await Storage.Config.UpsertDomainAsync(domain, default);
        await Storage.Inbound.UpsertSettingsAsync(new InboundDomainSettings(domain.Id, tenantId, true, InboundDmarcAction.RecordOnly, null, null, null, null, null, Clock.UtcNow), default);
        WebhookEndpointRecord endpoint = await AddEndpointAsync(tenantId, url);
        var route = new InboundRouteRecord(Ids.New(), tenantId, domain.Id, "route", 10, true, InboundMatchKind.CatchAll, null, false, InboundActionKind.Webhook, endpoint.Id, InboundWebhookFormat.Json, [], Clock.UtcNow, Clock.UtcNow);
        await Storage.Inbound.UpsertRouteAsync(route, default);
        return new OtherTenant(tenantId, domain, route);
    }

    public async Task<InboundMessageDraft> ReceiveForAsync(OtherTenant tenant, byte[]? raw = null)
    {
        DateTimeOffset at = Clock.UtcNow;
        var draft = new InboundMessageDraft
        {
            Id = Ids.New(at), TenantId = tenant.TenantId, DomainId = tenant.Domain.Id, Domain = tenant.Domain.Name, ReceivedAt = at, RemoteAddress = "203.0.113.9", Helo = "mail.sender.test", TlsUsed = true,
            EnvelopeFrom = "alice@sender.test", EnvelopeTo = "support@" + tenant.Domain.Name, Subject = "Hello",
            Auth = InboundAuthResults.NotChecked, RouteId = tenant.Route.Id, ActionKind = InboundActionKind.Webhook, Raw = raw ?? SimpleMessage(),
        };
        await Storage.Inbound.AcceptAsync([draft], default);
        return draft;
    }

    public async Task<InboundMessage> GetAsync(Guid id) => (await Storage.Inbound.GetAsync(TenantId, id, default))!;

    /// <summary>Runs one pass at the current time.</summary>
    public Task<int> RunAsync() => Runner.RunOnceAsync(default);

    public async ValueTask DisposeAsync()
    {
        Transport.Dispose();
        await Storage.DisposeAsync();
    }
}
