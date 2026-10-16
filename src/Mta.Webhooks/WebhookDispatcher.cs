using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using Mta.Core;
using Mta.Storage;

namespace Mta.Webhooks;

/// <summary>Called when an endpoint is auto-disabled so the tenant can be told (dashboard banner, email).</summary>
public interface IWebhookNotifier
{
    ValueTask EndpointDisabledAsync(WebhookEndpointRecord endpoint, string reason, CancellationToken cancellationToken);
}

/// <summary>
/// Delivers outbox items to endpoints (Standard Webhooks signing, at-least-once, retry schedule of decision 16, SSRF guard,
/// no redirects, 15 s timeout, per-endpoint concurrency cap). Shared by both backends (decision E).
/// </summary>
public sealed class WebhookDispatcher : IAsyncDisposable
{
    private static readonly HttpRequestOptionsKey<IReadOnlyList<IpNetwork>> AllowlistKey = new("eggmail.allowlist");

    private readonly IWebhookOutbox _outbox;
    private readonly IConfigStore _config;
    private readonly ISecretProtector _protector;
    private readonly WebhookOptions _options;
    private readonly IClock _clock;
    private readonly IMtaLog _log;
    private readonly IWebhookNotifier? _notifier;
    private readonly Func<string, CancellationToken, ValueTask<IPAddress[]>> _resolve;
    private readonly HttpMessageHandler? _handlerOverride;
    private readonly ConcurrentDictionary<string, HttpClient> _clients = new();
    private readonly ConcurrentDictionary<Guid, SemaphoreSlim> _endpointGates = new();
    private readonly SemaphoreSlim _global;
    private readonly string _owner = $"webhooks-{Ids.ToCompact(Ids.New())[..12]}";

    public WebhookDispatcher(
        IWebhookOutbox outbox,
        IConfigStore config,
        ISecretProtector protector,
        WebhookOptions? options = null,
        IClock? clock = null,
        IMtaLog? log = null,
        IWebhookNotifier? notifier = null,
        Func<string, CancellationToken, ValueTask<IPAddress[]>>? resolver = null,
        HttpMessageHandler? handlerOverride = null)
    {
        _outbox = outbox;
        _config = config;
        _protector = protector;
        _options = options ?? new WebhookOptions();
        _clock = clock ?? SystemClock.Instance;
        _log = log ?? NullMtaLog.Instance;
        _notifier = notifier;
        _resolve = resolver ?? (async (h, ct) => await Dns.GetHostAddressesAsync(h, ct).ConfigureAwait(false));
        _handlerOverride = handlerOverride;
        _global = new SemaphoreSlim(_options.MaxConcurrency);
    }

    /// <summary>Runs until cancelled, polling the outbox.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            int processed;
            try
            {
                processed = await RunOnceAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                _log.Write(MtaLogLevel.Error, "webhooks", "dispatcher loop failed", ex);
                processed = 0;
            }

            if (processed == 0)
            {
                try
                {
                    await Task.Delay(_options.PollInterval, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
    }

    /// <summary>Claims and processes one batch. Returns the number of items handled.</summary>
    public async Task<int> RunOnceAsync(CancellationToken cancellationToken)
    {
        var batch = await _outbox.ClaimDueAsync(_owner, Math.Min(_options.BatchSize, _options.MaxConcurrency), _clock.UtcNow, _options.Lease, cancellationToken).ConfigureAwait(false);
        if (batch.Count == 0)
        {
            return 0;
        }

        WebhookMetrics.Claimed.Add(batch.Count);
        await Task.WhenAll(batch.Select(item => ProcessAsync(item, cancellationToken))).ConfigureAwait(false);
        return batch.Count;
    }

    private async Task ProcessAsync(WebhookOutboxItem item, CancellationToken ct)
    {
        var gate = _endpointGates.GetOrAdd(item.EndpointId, _ => new SemaphoreSlim(_options.MaxConcurrencyPerEndpoint));
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await _global.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await DeliverAsync(item, ct).ConfigureAwait(false);
            }
            finally
            {
                _global.Release();
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.Write(MtaLogLevel.Error, "webhooks", $"unexpected failure delivering outbox item {item.Id}", ex);
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task DeliverAsync(WebhookOutboxItem item, CancellationToken ct)
    {
        var endpoint = await _config.GetWebhookEndpointAsync(item.EndpointId, ct).ConfigureAwait(false);
        var now = _clock.UtcNow;
        if (endpoint is null || !endpoint.Enabled)
        {
            await _outbox.CompleteAsync(item.Id, new WebhookAttemptRecord(item.Id, now, null, TimeSpan.Zero, "endpoint_unavailable", null),
                WebhookOutboxState.Failed, null, ct).ConfigureAwait(false);
            CountFailed("endpoint_unavailable");
            return;
        }

        string[] secrets;
        try
        {
            secrets = Encoding.UTF8.GetString(_protector.Unprotect(endpoint.SecretProtected, SecretPurposes.WebhookSecret))
                .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or FormatException)
        {
            _log.Write(MtaLogLevel.Error, "webhooks", $"endpoint {endpoint.Id}: secret cannot be unprotected", ex);
            await _outbox.CompleteAsync(item.Id, new WebhookAttemptRecord(item.Id, now, null, TimeSpan.Zero, "secret_unreadable", null),
                WebhookOutboxState.Failed, null, ct).ConfigureAwait(false);
            CountFailed("secret_unreadable");
            return;
        }

        using Activity? span = WebhookTracing.Start(item);
        var started = _clock.Timestamp;
        int? status = null;
        string? errorClass = null;
        string? snippet = null;
        try
        {
            using var request = BuildRequest(item, endpoint, secrets, now);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(_options.Timeout);
            using var response = await GetClient(Allowlist(endpoint)).SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            status = (int)response.StatusCode;
            snippet = await ReadSnippetAsync(response, cts.Token).ConfigureAwait(false);
            if (status is >= 300 and < 400)
            {
                errorClass = "redirect_not_followed";
            }
            else if (status is < 200 or >= 300)
            {
                errorClass = status switch { 410 => "gone", 429 => "throttled", 502 or 504 => "throttled", _ => $"http_{status}" };
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            errorClass = "timeout";
        }
        catch (HttpRequestException ex)
        {
            errorClass = ex.InnerException is SsrfBlockedException ? "ssrf_blocked" : ex.InnerException is SocketException ? "connect_failed" : "http_error";
        }

        var duration = _clock.GetElapsedTime(started);
        WebhookMetrics.DeliveryDuration.Record(duration.TotalSeconds);
        WebhookTracing.Finish(span, status, errorClass);
        var attempt = new WebhookAttemptRecord(item.Id, now, status, duration, errorClass, snippet);
        if (errorClass is null)
        {
            WebhookMetrics.Deliveries.Add(1, new KeyValuePair<string, object?>("outcome", "delivered"));
            await _outbox.CompleteAsync(item.Id, attempt, WebhookOutboxState.Delivered, null, ct).ConfigureAwait(false);
            if (endpoint.FailingSince is not null)
            {
                await _config.UpsertWebhookEndpointAsync(endpoint with { FailingSince = null }, ct).ConfigureAwait(false);
            }

            return;
        }

        if (errorClass == "gone")
        {
            CountFailed(errorClass);
            await _outbox.CompleteAsync(item.Id, attempt, WebhookOutboxState.Failed, null, ct).ConfigureAwait(false);
            await DisableAsync(endpoint, "The receiver answered 410 Gone", now, ct).ConfigureAwait(false);
            return;
        }

        // Retry or give up.
        int failedAttempts = item.Attempt + 1;
        if (failedAttempts > _options.RetrySchedule.Count)
        {
            CountFailed(errorClass);
            await _outbox.CompleteAsync(item.Id, attempt, WebhookOutboxState.Failed, null, ct).ConfigureAwait(false);
        }
        else
        {
            WebhookMetrics.Deliveries.Add(1, new KeyValuePair<string, object?>("outcome", "retry"));
            WebhookMetrics.Failures.Add(1, new KeyValuePair<string, object?>("reason", WebhookMetrics.ReasonOf(errorClass)));
            var delay = _options.RetrySchedule[failedAttempts - 1];
            if (errorClass == "throttled")
            {
                delay += _options.ThrottleExtraDelay;
            }

            await _outbox.CompleteAsync(item.Id, attempt, WebhookOutboxState.Pending, now + delay, ct).ConfigureAwait(false);
        }

        // Endpoint-level health: disable after a continuous failure period.
        var failingSince = endpoint.FailingSince ?? now;
        if (now - failingSince >= _options.DisableAfter)
        {
            await DisableAsync(endpoint, $"Failing continuously since {failingSince:u}", now, ct).ConfigureAwait(false);
        }
        else if (endpoint.FailingSince is null)
        {
            await _config.UpsertWebhookEndpointAsync(endpoint with { FailingSince = now }, ct).ConfigureAwait(false);
        }
    }

    /// <summary>Counts an attempt that ended the item without delivery (it will not be tried again).</summary>
    private static void CountFailed(string errorClass)
    {
        WebhookMetrics.Deliveries.Add(1, new KeyValuePair<string, object?>("outcome", "failed"));
        WebhookMetrics.Failures.Add(1, new KeyValuePair<string, object?>("reason", WebhookMetrics.ReasonOf(errorClass)));
    }

    private async ValueTask DisableAsync(WebhookEndpointRecord endpoint, string reason, DateTimeOffset now, CancellationToken ct)
    {
        // Items of one endpoint fail side by side (and so do replicas): only the attempt that really switched the endpoint off counts it and tells the tenant.
        if (!await _config.DisableWebhookEndpointAsync(endpoint.Id, reason, now, ct).ConfigureAwait(false))
        {
            return;
        }

        WebhookMetrics.EndpointsDisabled.Add(1);
        _log.Write(MtaLogLevel.Warning, "webhooks", $"endpoint {endpoint.Id} of tenant {endpoint.TenantId} disabled: {reason}");
        if (_notifier is not null)
        {
            await _notifier.EndpointDisabledAsync(endpoint, reason, ct).ConfigureAwait(false);
        }
    }

    private HttpRequestMessage BuildRequest(WebhookOutboxItem item, WebhookEndpointRecord endpoint, string[] secrets, DateTimeOffset now)
    {
        byte[] payload = Encoding.UTF8.GetBytes(item.PayloadJson);
        string id = $"evt_{Ids.ToCompact(item.EventId)}";
        long ts = now.ToUnixTimeSeconds();
        var request = new HttpRequestMessage(HttpMethod.Post, endpoint.Url) { Content = new ByteArrayContent(payload) };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        request.Headers.TryAddWithoutValidation(StandardWebhooksSigner.IdHeader, id);
        request.Headers.TryAddWithoutValidation(StandardWebhooksSigner.TimestampHeader, ts.ToString(System.Globalization.CultureInfo.InvariantCulture));
        request.Headers.TryAddWithoutValidation(StandardWebhooksSigner.SignatureHeader, StandardWebhooksSigner.Sign(id, ts, payload, secrets));
        request.Headers.UserAgent.ParseAdd(_options.UserAgent);
        request.Options.Set(AllowlistKey, Allowlist(endpoint));
        return request;
    }

    /// <summary>Per-tenant allowlist for internal endpoints (settings key <c>webhooks.allowlist</c>, CIDR list).</summary>
    private IReadOnlyList<IpNetwork> Allowlist(WebhookEndpointRecord endpoint) => AllowlistProvider?.Invoke(endpoint.TenantId) ?? [];

    /// <summary>Supplies the tenant's allowlisted networks; wired by the host from tenant settings.</summary>
    public Func<Guid, IReadOnlyList<IpNetwork>>? AllowlistProvider { get; set; }

    private async Task<string?> ReadSnippetAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            await using var s = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            byte[] buf = new byte[_options.MaxResponseSnippetBytes];
            int total = 0;
            while (total < buf.Length)
            {
                int n = await s.ReadAsync(buf.AsMemory(total), ct).ConfigureAwait(false);
                if (n == 0) { break; }
                total += n;
            }

            return total == 0 ? null : Encoding.UTF8.GetString(buf, 0, total).Replace('\0', ' ');
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or OperationCanceledException)
        {
            return null;
        }
    }

    private HttpClient GetClient(IReadOnlyList<IpNetwork> allowlist)
    {
        // Connections are pooled per client; clients with different allowlists must not share pooled connections.
        string key = allowlist.Count == 0 ? "" : string.Join(',', allowlist.Select(n => n.ToString()));
        return _clients.GetOrAdd(key, _ => CreateClient());
    }

    private HttpClient CreateClient() =>
        new(_handlerOverride ?? CreateHandler(), disposeHandler: _handlerOverride is null) { Timeout = Timeout.InfiniteTimeSpan };

    /// <summary>The handler of production deliveries (a test can inspect it).</summary>
    internal SocketsHttpHandler CreateHandler() => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        // The connect callback below validates the address it connects to. Through a proxy that address would be the proxy's, and the
        // proxy would reach whatever the URL says: the SSRF guard would check the wrong hop. Never use one, whatever HTTP(S)_PROXY says.
        UseProxy = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        ConnectTimeout = _options.Timeout,
        ConnectCallback = ConnectGuardedAsync,
        // While our webhook span is the current activity the handler would add traceparent/tracestate to the request, handing customers'
        // receivers our trace ids. Nothing of ours belongs on a request to a third party.
        ActivityHeadersPropagator = DistributedContextPropagator.CreateNoOutputPropagator(),
    };

    private async ValueTask<Stream> ConnectGuardedAsync(SocketsHttpConnectionContext context, CancellationToken ct)
    {
        var allowlist = context.InitialRequestMessage.Options.TryGetValue(AllowlistKey, out var a) ? a : [];
        var addresses = await SsrfGuard.ResolveAllowedAsync(context.DnsEndPoint.Host, _resolve, allowlist, ct).ConfigureAwait(false);
        if (addresses.Count == 0)
        {
            throw new SsrfBlockedException(context.DnsEndPoint.Host);
        }

        Exception? last = null;
        foreach (var address in addresses)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), ct).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception ex) when (ex is SocketException)
            {
                socket.Dispose();
                last = ex;
            }
        }

        throw last ?? new SocketException((int)SocketError.HostNotFound);
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var c in _clients.Values) { c.Dispose(); }
        _global.Dispose();
        await ValueTask.CompletedTask.ConfigureAwait(false);
    }
}

/// <summary>Raised inside the connect callback when every resolved address is in a blocked range.</summary>
public sealed class SsrfBlockedException : Exception
{
    public SsrfBlockedException(string host) : base($"No permitted address for {host}") { }
}
