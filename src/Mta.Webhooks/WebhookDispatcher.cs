using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
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
    private readonly IWebhookOutbox _outbox;
    private readonly IConfigStore _config;
    private readonly ISecretProtector _protector;
    private readonly WebhookOptions _options;
    private readonly IClock _clock;
    private readonly IMtaLog _log;
    private readonly WebhookTransport _transport;
    private readonly bool _ownsTransport;
    private readonly WebhookEndpointHealth _health;
    private readonly ConcurrentDictionary<Guid, SemaphoreSlim> _endpointGates = new();
    private readonly SemaphoreSlim _global;
    // Random: the first 12 hex digits of a version 7 id are its millisecond timestamp, so two dispatchers created in the same millisecond would share an owner name.
    private readonly string _owner = $"webhooks-{Guid.NewGuid().ToString("N")[..16]}";

    public WebhookDispatcher(
        IWebhookOutbox outbox,
        IConfigStore config,
        ISecretProtector protector,
        WebhookOptions? options = null,
        IClock? clock = null,
        IMtaLog? log = null,
        IWebhookNotifier? notifier = null,
        Func<string, CancellationToken, ValueTask<IPAddress[]>>? resolver = null,
        HttpMessageHandler? handlerOverride = null,
        WebhookTransport? transport = null)
    {
        _outbox = outbox;
        _config = config;
        _protector = protector;
        _options = options ?? new WebhookOptions();
        _clock = clock ?? SystemClock.Instance;
        _log = log ?? NullMtaLog.Instance;
        // The transport (HTTP, signing, SSRF guard) is shared with the inbound route actions when the host passes one in.
        _transport = transport ?? new WebhookTransport(_options, _clock, resolver, handlerOverride);
        _ownsTransport = transport is null;
        _health = new WebhookEndpointHealth(config, _options, _log, notifier);
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
        string id = $"evt_{Ids.ToCompact(item.EventId)}";
        WebhookSendResult sent = await _transport.SendAsync(endpoint, id, Encoding.UTF8.GetBytes(item.PayloadJson), "application/json; charset=utf-8", secrets, now, null, ct).ConfigureAwait(false);
        int? status = sent.Status;
        string? errorClass = sent.ErrorClass;
        WebhookMetrics.DeliveryDuration.Record(sent.Duration.TotalSeconds);
        WebhookTracing.Finish(span, status, errorClass);
        var attempt = new WebhookAttemptRecord(item.Id, now, status, sent.Duration, errorClass, sent.Snippet);
        if (errorClass is null)
        {
            WebhookMetrics.Deliveries.Add(1, new KeyValuePair<string, object?>("outcome", "delivered"));
            await _outbox.CompleteAsync(item.Id, attempt, WebhookOutboxState.Delivered, null, ct).ConfigureAwait(false);
            await _health.RecordSuccessAsync(endpoint, ct).ConfigureAwait(false);
            return;
        }

        if (errorClass == "gone")
        {
            CountFailed(errorClass);
            await _outbox.CompleteAsync(item.Id, attempt, WebhookOutboxState.Failed, null, ct).ConfigureAwait(false);
            await _health.DisableAsync(endpoint, "The receiver answered 410 Gone", now, ct).ConfigureAwait(false);
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
        await _health.RecordFailureAsync(endpoint, now, ct).ConfigureAwait(false);
    }

    /// <summary>Counts an attempt that ended the item without delivery (it will not be tried again).</summary>
    private static void CountFailed(string errorClass)
    {
        WebhookMetrics.Deliveries.Add(1, new KeyValuePair<string, object?>("outcome", "failed"));
        WebhookMetrics.Failures.Add(1, new KeyValuePair<string, object?>("reason", WebhookMetrics.ReasonOf(errorClass)));
    }

    /// <summary>Supplies the tenant's allowlisted networks for internal endpoints; wired by the host from tenant settings (the transport is shared with the inbound route actions).</summary>
    public Func<Guid, IReadOnlyList<IpNetwork>>? AllowlistProvider
    {
        get => _transport.AllowlistProvider;
        set => _transport.AllowlistProvider = value;
    }

    /// <summary>The handler of production deliveries (a test can inspect it).</summary>
    internal SocketsHttpHandler CreateHandler() => _transport.CreateHandler();

    public async ValueTask DisposeAsync()
    {
        if (_ownsTransport)
        {
            _transport.Dispose();
        }

        _global.Dispose();
        await ValueTask.CompletedTask.ConfigureAwait(false);
    }
}
