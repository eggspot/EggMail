using System.Collections.Concurrent;
using System.Text;
using Mta.Core;
using Mta.Host.Ingest;
using Mta.Storage;
using Mta.Storage.Logic;
using Mta.Webhooks;

namespace Mta.Host.Inbound;

/// <summary>What one attempt at a route action came to. Created with the factory methods; the runner turns it into the stored outcome (the retry ladder is the runner's, not the action's).</summary>
public sealed class InboundActionResult
{
    private InboundActionResult(Kind kind, string? error, string? note, Guid? forwardMessageId, bool freeBody, TimeSpan extraDelay)
    {
        Outcome = kind;
        Error = error;
        Note = note;
        ForwardMessageId = forwardMessageId;
        FreeBody = freeBody;
        ExtraDelay = extraDelay;
    }

    internal enum Kind { Done, Retry, Failed }

    internal Kind Outcome { get; }

    /// <summary>A short code for <c>actionLastError</c>: never a URL, an address or the receiver's answer.</summary>
    public string? Error { get; }

    public string? Note { get; }

    public Guid? ForwardMessageId { get; }

    public bool FreeBody { get; }

    /// <summary>Added to the next rung of the ladder (a receiver that asked to slow down).</summary>
    public TimeSpan ExtraDelay { get; }

    /// <summary>The action is complete. <paramref name="note"/> is a code the tenant should see (<c>all_targets_suppressed</c>), <paramref name="freeBody"/> deletes the stored body (a forward now lives in the outbound queue).</summary>
    public static InboundActionResult Done(string? note = null, Guid? forwardMessageId = null, bool freeBody = false) => new(Kind.Done, null, note, forwardMessageId, freeBody, TimeSpan.Zero);

    /// <summary>The attempt failed or could not be made for a reason that is not the message's: the next rung of the ladder, or <c>failed</c> when none is left. A deferral is exactly this.</summary>
    public static InboundActionResult Retry(string error, TimeSpan extraDelay = default) => new(Kind.Retry, error, null, null, false, extraDelay);

    /// <summary>The action can never succeed (no body, a deleted route, a message too large for the format): <c>failed</c> at once.</summary>
    public static InboundActionResult Failed(string error) => new(Kind.Failed, error, null, null, false, TimeSpan.Zero);
}

/// <summary>The forward action (design section 11.7), supplied by the host; the runner calls it for a route whose current action is <c>forward</c>.</summary>
public interface IInboundForwarder
{
    ValueTask<InboundActionResult> ForwardAsync(InboundMessage message, InboundRouteRecord route, byte[] raw, CancellationToken cancellationToken);
}

/// <summary>Settings of the runner (<c>Inbound:Action:*</c>, <c>Inbound:Webhook:*</c>, <c>Inbound:ApiBaseUrl</c>).</summary>
public sealed record InboundActionOptions
{
    /// <summary>The webhook ladder (decision 16): eight attempts over about 27 hours.</summary>
    public static IReadOnlyList<TimeSpan> DefaultRetrySchedule { get; } =
    [
        TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(30), TimeSpan.FromHours(2), TimeSpan.FromHours(5), TimeSpan.FromHours(10), TimeSpan.FromHours(10),
    ];

    public int Concurrency { get; init; } = 4;

    public int MaxConcurrencyPerTenant { get; init; } = 2;

    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(1);

    public TimeSpan Lease { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>Delay before attempt 2, 3, ...; the action has <c>Count + 1</c> attempts in all.</summary>
    public IReadOnlyList<TimeSpan> RetrySchedule { get; init; } = DefaultRetrySchedule;

    public int WebhookMaxTextBytes { get; init; } = 256 * 1024;

    public long WebhookMaxRawMessageBytes { get; init; } = 10L * 1024 * 1024;

    public string? ApiBaseUrl { get; init; }

    /// <summary>Extra delay after a receiver that answered 429/502/504.</summary>
    public TimeSpan ThrottleExtraDelay { get; init; } = TimeSpan.FromMinutes(1);

    public int MaxAttempts => RetrySchedule.Count + 1;
}

/// <summary>
/// Carries out the route actions of received mail (design section 11.7): claims pending <c>webhook</c> and <c>forward</c> actions through the storage contract (one pool per replica, the
/// attempt counted at the claim), runs them under a lease, records the result with the retry ladder, and publishes <c>inbound.action.failed</c> when one gives up.
/// The action that runs is the route's <b>current</b> one, read when it runs. Store and discard are complete at receipt; they reach the runner only after a route change
/// (<c>route_is_now_store</c> / <c>route_is_now_discard</c>).
/// </summary>
public sealed class InboundActionRunner
{
    private readonly IStorage _storage;
    private readonly WebhookTransport _transport;
    private readonly WebhookEndpointHealth _health;
    private readonly ISecretProtector _secrets;
    private readonly InboundActionOptions _options;
    private readonly IClock _clock;
    private readonly IMtaLog _log;
    private readonly Func<bool> _inboundEnabled;
    private readonly IInboundForwarder? _forwarder;
    private readonly IWebhookPublisher _publisher;
    private readonly string _owner = $"inbound-{Ids.ToCompact(Ids.New())[..12]}";
    private readonly ConcurrentDictionary<Guid, SemaphoreSlim> _tenantGates = new();
    private readonly SemaphoreSlim _wake = new(0);
    private readonly ConcurrentDictionary<Task, byte> _running = new();
    private volatile bool _paused;
    private long _lastSampleTimestamp;
    private InboundUsage? _latestUsage;

    public InboundActionRunner(
        IStorage storage, WebhookTransport transport, WebhookEndpointHealth health, ISecretProtector secrets, InboundActionOptions options, IClock clock, IMtaLog log,
        Func<bool> inboundEnabled, IWebhookPublisher publisher, IInboundForwarder? forwarder = null)
    {
        _storage = storage;
        _transport = transport;
        _health = health;
        _secrets = secrets;
        _options = options;
        _clock = clock;
        _log = log;
        _inboundEnabled = inboundEnabled;
        _publisher = publisher;
        _forwarder = forwarder;
    }

    /// <summary>The last sample of the pending and failed counts (null before the first), for the gauge.</summary>
    internal InboundUsage? LatestUsage => Volatile.Read(ref _latestUsage);

    /// <summary>The lease owner name of this runner (a test claims with it to simulate a crash).</summary>
    public string Owner => _owner;

    /// <summary>Asks the loop to look for work now (a message was accepted).</summary>
    public void Wake()
    {
        if (_wake.CurrentCount == 0)
        {
            try { _wake.Release(); } catch (SemaphoreFullException) { }
        }
    }

    /// <summary>Runs until cancelled: keeps up to <see cref="InboundActionOptions.Concurrency"/> attempts in flight, claiming more as they finish.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        InboundActionMetrics.Attach(this);
        ConcurrentDictionary<Task, byte> running = _running;
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                int claimedNow = 0;
                try
                {
                    await SampleUsageAsync(cancellationToken).ConfigureAwait(false);
                    int free = _options.Concurrency - running.Count;
                    if (free > 0 && !_paused)
                    {
                        IReadOnlyList<ClaimedInboundAction> claimed = await _storage.Inbound.ClaimActionsAsync(_owner, free, _clock.UtcNow, _options.Lease, cancellationToken).ConfigureAwait(false);
                        claimedNow = claimed.Count;
                        foreach (ClaimedInboundAction claim in claimed)
                        {
                            Task task = Task.Run(() => ProcessGuardedAsync(claim, cancellationToken), CancellationToken.None);
                            running[task] = 0;
                            _ = task.ContinueWith(t => { running.TryRemove(t, out _); Wake(); }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                        }
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _log.Write(MtaLogLevel.Error, "inbound", "the route action runner could not claim work; trying again", ex);
                }

                // Busy: look again when an attempt finishes (a slot frees) or after the poll interval; idle: after the poll interval or when woken.
                if (claimedNow == 0 || running.Count >= _options.Concurrency)
                {
                    try
                    {
                        // Inbound off: whatever is pending is deferred (and ends failed after the ladder), but nobody needs that second by second; an installation that never receives mail does not poll the queue file every second.
                        TimeSpan idle = _inboundEnabled() ? _options.PollInterval : TimeSpan.FromTicks(Math.Max(_options.PollInterval.Ticks, TimeSpan.FromSeconds(30).Ticks));
                        await _wake.WaitAsync(idle, cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            }
        }
        finally
        {
            try
            {
                await Task.WhenAll(running.Keys).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _log.Write(MtaLogLevel.Warning, "inbound", "an action attempt ended with an error while stopping", ex);
            }

            // What this replica still holds was claimed but not completed: give the attempts back so the next owner starts the rung over (a graceful stop is not a failure).
            try
            {
                using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await _storage.Inbound.ReleaseOwnedActionLeasesAsync(_owner, limit.Token).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _log.Write(MtaLogLevel.Warning, "inbound", "could not release the claimed route actions at stop; they are taken over when their lease runs out", ex);
            }

            InboundActionMetrics.Detach(this);
        }
    }

    /// <summary>Stops claiming (a backend switch quiesces this replica); attempts in flight finish. <see cref="Resume"/> undoes it.</summary>
    public void Pause() => _paused = true;

    public void Resume()
    {
        _paused = false;
        Wake();
    }

    /// <summary>
    /// Pauses, waits up to <paramref name="timeout"/> for the attempts in flight to be recorded, and gives back the claims that are still held (their attempts were not made or not
    /// recorded), so the rows are free to be held by a backend switch.
    /// </summary>
    public async Task QuiesceAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        Pause();
        Task all = Task.WhenAll(_running.Keys);
        await Task.WhenAny(all, Task.Delay(timeout, cancellationToken)).ConfigureAwait(false);
        await _storage.Inbound.ReleaseOwnedActionLeasesAsync(_owner, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Claims up to <see cref="InboundActionOptions.Concurrency"/> due actions and carries them out; returns how many were claimed. The loop of <see cref="RunAsync"/> is the same work, continuously.</summary>
    public async Task<int> RunOnceAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<ClaimedInboundAction> claimed = await _storage.Inbound.ClaimActionsAsync(_owner, _options.Concurrency, _clock.UtcNow, _options.Lease, cancellationToken).ConfigureAwait(false);
        await Task.WhenAll(claimed.Select(c => ProcessGuardedAsync(c, cancellationToken))).ConfigureAwait(false);
        return claimed.Count;
    }

    private async Task SampleUsageAsync(CancellationToken ct)
    {
        long now = _clock.Timestamp;
        if (_lastSampleTimestamp != 0 && _clock.GetElapsedTime(_lastSampleTimestamp) < TimeSpan.FromSeconds(15))
        {
            return;
        }

        _lastSampleTimestamp = now;
        try
        {
            Volatile.Write(ref _latestUsage, await _storage.Inbound.GetUsageAsync(null, null, ct).ConfigureAwait(false));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Write(MtaLogLevel.Warning, "inbound", "could not sample the pending and failed route actions for the metrics", ex);
        }
    }

    private async Task ProcessGuardedAsync(ClaimedInboundAction claim, CancellationToken ct)
    {
        try
        {
            await ProcessAsync(claim, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Stopping: the lease is released with the others at the end of RunAsync.
        }
        catch (Exception ex)
        {
            // Not recorded: the lease runs out and the next claim counts the attempt again, so a message that makes the runner fail every time reaches the end of the ladder.
            _log.Write(MtaLogLevel.Error, "inbound", $"route action of inbound message {claim.Message.Id:N} failed unexpectedly; it is retried when its lease runs out", ex);
        }
    }

    private async Task ProcessAsync(ClaimedInboundAction claim, CancellationToken ct)
    {
        InboundMessage message = claim.Message;
        long started = _clock.Timestamp;
        int attempt = message.ActionAttempts;
        InboundRouteRecord? route = null;
        string kind = InboundNames.Of(message.ActionKind);
        InboundActionResult result;

        if (attempt > _options.MaxAttempts)
        {
            // The claims of a message that kills its runner count too: past the last rung it is over.
            result = InboundActionResult.Failed("attempts_exhausted");
        }
        else if (!_inboundEnabled())
        {
            result = InboundActionResult.Retry("inbound_disabled");
        }
        else if ((await _storage.Config.GetTenantAsync(message.TenantId, ct).ConfigureAwait(false)) is not { } tenant)
        {
            result = InboundActionResult.Failed("tenant_missing");
        }
        else if (!tenant.Enabled)
        {
            result = InboundActionResult.Retry("tenant_suspended");
        }
        else if (message.RouteId is not { } routeId || (route = await _storage.Inbound.GetRouteAsync(message.TenantId, routeId, ct).ConfigureAwait(false)) is null)
        {
            result = InboundActionResult.Failed("route_deleted");
        }
        else
        {
            kind = InboundNames.Of(route.ActionKind);
            result = await RunRouteActionAsync(claim, route, ct).ConfigureAwait(false);
        }

        await RecordAsync(claim, route, kind, result, started, ct).ConfigureAwait(false);
    }

    private async ValueTask<InboundActionResult> RunRouteActionAsync(ClaimedInboundAction claim, InboundRouteRecord route, CancellationToken ct)
    {
        switch (route.ActionKind)
        {
            case InboundActionKind.Store:
                return InboundActionResult.Done("route_is_now_store");
            case InboundActionKind.Discard:
                return InboundActionResult.Done("route_is_now_discard");
        }

        if (claim.Raw is not { } raw)
        {
            return InboundActionResult.Failed("body_missing");
        }

        SemaphoreSlim gate = _tenantGates.GetOrAdd(claim.Message.TenantId, _ => new SemaphoreSlim(_options.MaxConcurrencyPerTenant));
        await AcquireKeepingLeaseAsync(gate, claim.Message.Id, ct).ConfigureAwait(false);
        try
        {
            return route.ActionKind == InboundActionKind.Forward
                ? _forwarder is null
                    ? InboundActionResult.Retry("forward_unavailable")
                    : await _forwarder.ForwardAsync(claim.Message, route, raw, ct).ConfigureAwait(false)
                : await RunWebhookAsync(claim.Message, route, raw, ct).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>Waits for a tenant slot without letting the claimed action's lease run out (another replica would take it over and the attempt would be made twice).</summary>
    private async Task AcquireKeepingLeaseAsync(SemaphoreSlim gate, Guid messageId, CancellationToken ct)
    {
        TimeSpan step = TimeSpan.FromTicks(Math.Max(TimeSpan.FromSeconds(1).Ticks, _options.Lease.Ticks / 3));
        while (!await gate.WaitAsync(step, ct).ConfigureAwait(false))
        {
            await _storage.Inbound.ExtendActionLeaseAsync(messageId, _owner, _clock.UtcNow + _options.Lease, ct).ConfigureAwait(false);
        }
    }

    private async ValueTask<InboundActionResult> RunWebhookAsync(InboundMessage message, InboundRouteRecord route, byte[] raw, CancellationToken ct)
    {
        if (route.WebhookEndpointId is not { } endpointId || await _storage.Config.GetWebhookEndpointAsync(endpointId, ct).ConfigureAwait(false) is not { } endpoint)
        {
            return InboundActionResult.Retry("endpoint_missing");
        }

        // The route was written with a check that the endpoint is the tenant's; the runner does not rely on it (a mail must never be posted to another tenant's receiver).
        if (endpoint.TenantId != message.TenantId)
        {
            return InboundActionResult.Failed("endpoint_not_of_tenant");
        }

        if (!endpoint.Enabled)
        {
            return InboundActionResult.Retry("endpoint_disabled");
        }

        bool rawFormat = route.WebhookFormat == InboundWebhookFormat.RawMime;
        if (rawFormat && raw.Length > _options.WebhookMaxRawMessageBytes)
        {
            return InboundActionResult.Failed("too_large_for_raw_webhook");
        }

        string[] secrets;
        try
        {
            secrets = Encoding.UTF8.GetString(_secrets.Unprotect(endpoint.SecretProtected, SecretPurposes.WebhookSecret)).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or FormatException)
        {
            _log.Write(MtaLogLevel.Error, "inbound", $"webhook endpoint {endpoint.Id:N}: the secret cannot be unprotected", ex);
            return InboundActionResult.Failed("secret_unreadable");
        }

        string webhookId = InboundWebhookPayload.WebhookId(message.Id, message.RetryGeneration);
        DateTimeOffset now = _clock.UtcNow;
        WebhookSendResult sent = rawFormat
            ? await _transport.SendAsync(endpoint, webhookId, raw, "message/rfc822", secrets, now, InboundWebhookPayload.RawHeaders(message), ct).ConfigureAwait(false)
            : await _transport.SendAsync(
                endpoint, webhookId,
                InboundWebhookPayload.BuildJson(message, raw, webhookId, new InboundWebhookLimits(_options.WebhookMaxTextBytes, _options.WebhookMaxRawMessageBytes, _options.ApiBaseUrl)),
                "application/json; charset=utf-8", secrets, now, null, ct).ConfigureAwait(false);

        WebhookMetrics.DeliveryDuration.Record(sent.Duration.TotalSeconds);
        if (sent.ErrorClass is not { } errorClass)
        {
            await _health.RecordSuccessAsync(endpoint, ct).ConfigureAwait(false);
            return InboundActionResult.Done();
        }

        if (errorClass == "gone")
        {
            // The receiver says the address is gone for good: the endpoint is switched off (the tenant is told). The message keeps its ladder, so re-enabling or repointing the route in time delivers it.
            await _health.DisableAsync(endpoint, "The receiver answered 410 Gone", now, ct).ConfigureAwait(false);
        }
        else
        {
            await _health.RecordFailureAsync(endpoint, now, ct).ConfigureAwait(false);
        }

        return InboundActionResult.Retry("webhook_" + errorClass, errorClass == "throttled" ? _options.ThrottleExtraDelay : TimeSpan.Zero);
    }

    private async Task RecordAsync(ClaimedInboundAction claim, InboundRouteRecord? route, string kind, InboundActionResult result, long started, CancellationToken ct)
    {
        InboundMessage message = claim.Message;
        DateTimeOffset now = _clock.UtcNow;
        int attempt = message.ActionAttempts;
        InboundActionOutcome outcome;
        string label;
        bool gaveUp = false;
        if (result.Outcome == InboundActionResult.Kind.Done)
        {
            outcome = new InboundActionOutcome(InboundActionState.Done, now, null, null, result.ForwardMessageId, result.FreeBody, result.Note, attempt);
            label = "done";
        }
        else if (result.Outcome == InboundActionResult.Kind.Retry && attempt < _options.MaxAttempts)
        {
            outcome = new InboundActionOutcome(InboundActionState.Pending, now, now + _options.RetrySchedule[attempt - 1] + result.ExtraDelay, result.Error, ClaimedAttempt: attempt);
            label = "retry";
        }
        else
        {
            outcome = new InboundActionOutcome(InboundActionState.Failed, now, null, result.Error, ClaimedAttempt: attempt);
            label = "failed";
            gaveUp = true;
        }

        bool recorded = await _storage.Inbound.CompleteActionAsync(message.Id, _owner, outcome, ct).ConfigureAwait(false);
        InboundActionMetrics.ActionDuration.Record(_clock.GetElapsedTime(started).TotalSeconds, new KeyValuePair<string, object?>("kind", kind));
        if (!recorded)
        {
            // The lease was lost (the message was deleted, or another replica took it over after the lease ran out): that replica's attempt decides.
            _log.Write(MtaLogLevel.Debug, "inbound", $"route action result of inbound message {message.Id:N} not recorded: the lease is gone");
            return;
        }

        InboundActionMetrics.Actions.Add(1, new KeyValuePair<string, object?>("kind", kind), new KeyValuePair<string, object?>("outcome", label));
        if (gaveUp)
        {
            _log.Write(MtaLogLevel.Warning, "inbound", $"route action of inbound message {message.Id:N} ({kind}) failed for good after {attempt} attempt(s): {result.Error}");
            await PublishFailureAsync(message, route, kind, result.Error ?? "failed", attempt, now, ct).ConfigureAwait(false);
        }
    }

    private async Task PublishFailureAsync(InboundMessage message, InboundRouteRecord? route, string kind, string error, int attempts, DateTimeOffset now, CancellationToken ct)
    {
        try
        {
            await _publisher.PublishAsync(message.TenantId, WebhookEventFactory.InboundActionFailedEvent(message.Id, route?.Id ?? message.RouteId, kind, error, attempts, now), now, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The state is recorded and visible; the notice is the courtesy.
            _log.Write(MtaLogLevel.Warning, "inbound", $"could not publish inbound.action.failed for inbound message {message.Id:N}", ex);
        }
    }
}
