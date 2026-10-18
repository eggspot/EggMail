using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using Mta.Core;
using Mta.Storage;

namespace Mta.Webhooks;

/// <summary>The outcome of one signed HTTP call to a webhook receiver. <see cref="ErrorClass"/> is null for a 2xx answer.</summary>
/// <param name="Status">HTTP status, or null when no answer arrived.</param>
/// <param name="ErrorClass">null on success, else <c>timeout</c>, <c>ssrf_blocked</c>, <c>connect_failed</c>, <c>http_error</c>, <c>redirect_not_followed</c>, <c>gone</c> (410), <c>throttled</c> (429/502/504) or <c>http_NNN</c>.</param>
/// <param name="Snippet">The first bytes of the answer (null when empty).</param>
/// <param name="Duration">Time of the call including reading the snippet.</param>
public sealed record WebhookSendResult(int? Status, string? ErrorClass, string? Snippet, TimeSpan Duration);

/// <summary>
/// The one place that makes HTTP calls to customers' webhook receivers: Standard Webhooks signing, the SSRF guard on the address actually connected to (and the per-tenant
/// allowlist), no redirects, no proxy, no cookies, no trace headers, a bounded timeout. Used by the outbox dispatcher and by the inbound route actions, so both have exactly the
/// same network posture (decision 95: inbound webhooks are signed and guarded like every other event).
/// </summary>
public sealed class WebhookTransport : IDisposable
{
    private static readonly HttpRequestOptionsKey<IReadOnlyList<IpNetwork>> AllowlistKey = new("eggmail.allowlist");

    private readonly WebhookOptions _options;
    private readonly IClock _clock;
    private readonly Func<string, CancellationToken, ValueTask<IPAddress[]>> _resolve;
    private readonly HttpMessageHandler? _handlerOverride;
    private readonly ConcurrentDictionary<string, HttpClient> _clients = new();

    public WebhookTransport(WebhookOptions? options = null, IClock? clock = null, Func<string, CancellationToken, ValueTask<IPAddress[]>>? resolver = null, HttpMessageHandler? handlerOverride = null)
    {
        _options = options ?? new WebhookOptions();
        _clock = clock ?? SystemClock.Instance;
        _resolve = resolver ?? (async (h, ct) => await Dns.GetHostAddressesAsync(h, ct).ConfigureAwait(false));
        _handlerOverride = handlerOverride;
    }

    /// <summary>Supplies the tenant's allowlisted networks (internal endpoints a tenant may call); wired by the host from tenant settings.</summary>
    public Func<Guid, IReadOnlyList<IpNetwork>>? AllowlistProvider { get; set; }

    /// <summary>
    /// Signs <paramref name="payload"/> (Standard Webhooks: <c>webhook-id</c>, <c>webhook-timestamp</c>, <c>webhook-signature</c> over those bytes) with every secret in <paramref name="secrets"/>
    /// and posts it to the endpoint's URL. Never throws for a network or HTTP failure (that is the result's <see cref="WebhookSendResult.ErrorClass"/>); cancellation of
    /// <paramref name="ct"/> propagates.
    /// </summary>
    /// <param name="extraHeaders">Further request headers (the caller percent-encodes values, so they are plain ASCII).</param>
    public async Task<WebhookSendResult> SendAsync(
        WebhookEndpointRecord endpoint, string webhookId, ReadOnlyMemory<byte> payload, string contentType, IReadOnlyList<string> secrets, DateTimeOffset now,
        IReadOnlyList<KeyValuePair<string, string>>? extraHeaders, CancellationToken ct)
    {
        var started = _clock.Timestamp;
        int? status = null;
        string? errorClass = null;
        string? snippet = null;
        try
        {
            using HttpRequestMessage request = BuildRequest(endpoint, webhookId, payload, contentType, secrets, now, extraHeaders);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(_options.Timeout);
            using HttpResponseMessage response = await GetClient(Allowlist(endpoint)).SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
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

        return new WebhookSendResult(status, errorClass, snippet, _clock.GetElapsedTime(started));
    }

    private HttpRequestMessage BuildRequest(
        WebhookEndpointRecord endpoint, string webhookId, ReadOnlyMemory<byte> payload, string contentType, IReadOnlyList<string> secrets, DateTimeOffset now,
        IReadOnlyList<KeyValuePair<string, string>>? extraHeaders)
    {
        long ts = now.ToUnixTimeSeconds();
        var request = new HttpRequestMessage(HttpMethod.Post, endpoint.Url) { Content = new ReadOnlyMemoryContent(payload) };
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
        request.Headers.TryAddWithoutValidation(StandardWebhooksSigner.IdHeader, webhookId);
        request.Headers.TryAddWithoutValidation(StandardWebhooksSigner.TimestampHeader, ts.ToString(System.Globalization.CultureInfo.InvariantCulture));
        request.Headers.TryAddWithoutValidation(StandardWebhooksSigner.SignatureHeader, StandardWebhooksSigner.Sign(webhookId, ts, payload.Span, secrets));
        request.Headers.UserAgent.ParseAdd(_options.UserAgent);
        if (extraHeaders is not null)
        {
            foreach (KeyValuePair<string, string> header in extraHeaders)
            {
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        request.Options.Set(AllowlistKey, Allowlist(endpoint));
        return request;
    }

    private IReadOnlyList<IpNetwork> Allowlist(WebhookEndpointRecord endpoint) => AllowlistProvider?.Invoke(endpoint.TenantId) ?? [];

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
        ActivityHeadersPropagator = System.Diagnostics.DistributedContextPropagator.CreateNoOutputPropagator(),
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

    public void Dispose()
    {
        foreach (HttpClient c in _clients.Values)
        {
            c.Dispose();
        }
    }
}

/// <summary>Raised inside the connect callback when every resolved address is in a blocked range.</summary>
public sealed class SsrfBlockedException : Exception
{
    public SsrfBlockedException(string host) : base($"No permitted address for {host}") { }
}

/// <summary>
/// What an endpoint's delivery results do to the endpoint itself, for the outbox dispatcher and the inbound route actions alike: a success clears the failing streak, a failure
/// starts it, and a streak longer than <see cref="WebhookOptions.DisableAfter"/> (or a <c>410 Gone</c>) disables the endpoint and tells the tenant. The endpoint is read again just
/// before it is written, so a secret rotation or an edit made while the call was in flight is not overwritten with the copy the call started from.
/// </summary>
public sealed class WebhookEndpointHealth
{
    private readonly IConfigStore _config;
    private readonly WebhookOptions _options;
    private readonly IMtaLog _log;
    private readonly IWebhookNotifier? _notifier;

    public WebhookEndpointHealth(IConfigStore config, WebhookOptions options, IMtaLog? log = null, IWebhookNotifier? notifier = null)
    {
        _config = config;
        _options = options;
        _log = log ?? NullMtaLog.Instance;
        _notifier = notifier;
    }

    /// <summary>A delivery succeeded: the endpoint is healthy again.</summary>
    public async ValueTask RecordSuccessAsync(WebhookEndpointRecord endpoint, CancellationToken ct)
    {
        if (endpoint.FailingSince is null)
        {
            return;
        }

        WebhookEndpointRecord? current = await _config.GetWebhookEndpointAsync(endpoint.Id, ct).ConfigureAwait(false);
        if (current is { FailingSince: not null })
        {
            await _config.UpsertWebhookEndpointAsync(current with { FailingSince = null }, ct).ConfigureAwait(false);
        }
    }

    /// <summary>A delivery failed (a <c>410</c> goes to <see cref="DisableAsync"/> instead): start the failing streak, or disable the endpoint when it has lasted too long.</summary>
    public async ValueTask RecordFailureAsync(WebhookEndpointRecord endpoint, DateTimeOffset now, CancellationToken ct)
    {
        WebhookEndpointRecord current = await _config.GetWebhookEndpointAsync(endpoint.Id, ct).ConfigureAwait(false) ?? endpoint;
        DateTimeOffset failingSince = current.FailingSince ?? now;
        if (now - failingSince >= _options.DisableAfter)
        {
            await DisableAsync(current, $"Failing continuously since {failingSince:u}", now, ct).ConfigureAwait(false);
        }
        else if (current.FailingSince is null && current.Enabled)
        {
            await _config.UpsertWebhookEndpointAsync(current with { FailingSince = now }, ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Switches the endpoint off and tells the tenant, once: only the call that really changed the endpoint from enabled to disabled counts, logs and notifies. Several attempts to the same dead
    /// endpoint run at the same time and each of them ends in a <c>410</c> or in the failure window, so without this the tenant would get a notice, a log line and a count for each.
    /// </summary>
    public async ValueTask DisableAsync(WebhookEndpointRecord endpoint, string reason, DateTimeOffset now, CancellationToken ct)
    {
        // The storage decides, atomically: true only for the call that changed the endpoint from enabled to disabled (false: already disabled, or gone).
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
}
