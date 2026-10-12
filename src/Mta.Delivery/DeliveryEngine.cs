using Mta.Core;
using Mta.Policy;
using Mta.Storage;

namespace Mta.Delivery;

/// <summary>
/// The outbound scheduler: leases due deliveries from the queue, groups them by message and recipient domain, runs the groups
/// concurrently through a <see cref="DeliveryProcessor"/> and keeps the expiry sweep and configuration refresh going.
/// Call <see cref="Wake"/> after accepting mail so new deliveries are picked up at once.
/// </summary>
public sealed class DeliveryEngine
{
    private const string Source = "delivery";

    private readonly DeliveryProcessor _processor;
    private readonly DeliveryServices _s;
    private readonly DeliveryOptions _options;
    private readonly SemaphoreSlim _wake = new(0, int.MaxValue);
    private readonly SemaphoreSlim _slots;
    private volatile CancellationTokenSource _abort = new();
    private int _pendingGroups;
    private volatile bool _paused;
    private readonly TaskCompletionSource _stopped = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public DeliveryEngine(DeliveryProcessor processor, DeliveryServices services, DeliveryOptions options)
    {
        _processor = processor;
        _s = services;
        _options = options;
        options.Validate();
        _slots = new SemaphoreSlim(options.MaxConcurrentGroups, options.MaxConcurrentGroups);
    }

    /// <summary>Groups currently waiting for or holding a worker slot.</summary>
    public int PendingGroups => Volatile.Read(ref _pendingGroups);

    /// <summary>True while no new work is claimed (quiesce).</summary>
    public bool Paused => _paused;

    /// <summary>Asks the loop to look for due work now.</summary>
    public void Wake()
    {
        if (_wake.CurrentCount == 0)
        {
            _wake.Release();
        }
    }

    /// <summary>Stops claiming new deliveries; running groups continue.</summary>
    public void Pause() => _paused = true;

    /// <summary>Resumes claiming.</summary>
    public void Resume()
    {
        _paused = false;
        Wake();
    }

    /// <summary>
    /// Stops claiming, waits up to <paramref name="timeout"/> for running groups, aborts what is left and releases this process's leases
    /// so the remaining deliveries are requeued with their retry state unchanged (decision R). Aborted deliveries that may already have
    /// been sent carry the possible-duplicate flag.
    /// </summary>
    public async Task QuiesceAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        Pause();
        var deadline = DateTime.UtcNow + timeout;
        while (PendingGroups > 0 && DateTime.UtcNow < deadline && !cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(20, CancellationToken.None).ConfigureAwait(false);
        }

        if (PendingGroups > 0)
        {
            var aborted = _abort;
            await aborted.CancelAsync().ConfigureAwait(false);
            while (PendingGroups > 0)
            {
                await Task.Delay(20, CancellationToken.None).ConfigureAwait(false);
            }

            // A later Resume() (for example after a rolled-back backend switch) must work with a fresh token.
            _abort = new CancellationTokenSource();
            aborted.Dispose();
        }

        await _s.Storage.Deliveries.ReleaseOwnedLeasesAsync(_options.Owner, CancellationToken.None).ConfigureAwait(false);
    }

    /// <summary>Runs until <paramref name="stopping"/> is cancelled, then drains gracefully (running groups finish; leases are released).</summary>
    public async Task RunAsync(CancellationToken stopping)
    {
        var lastSweep = DateTimeOffset.MinValue;
        var lastRefresh = DateTimeOffset.MinValue;
        try
        {
            await _s.Storage.Deliveries.ReleaseExpiredLeasesAsync(_s.Clock.UtcNow, stopping).ConfigureAwait(false);
            while (!stopping.IsCancellationRequested)
            {
                var now = _s.Clock.UtcNow;
                try
                {
                    if (now - lastRefresh >= _options.ConfigRefreshInterval)
                    {
                        lastRefresh = now;
                        await RefreshConfigAsync(stopping).ConfigureAwait(false);
                    }

                    if (!_paused)
                    {
                        if (now - lastSweep >= _options.ExpirySweepInterval)
                        {
                            lastSweep = now;
                            await SweepExpiredAsync(now, stopping).ConfigureAwait(false);
                        }

                        int free = _options.MaxConcurrentGroups - PendingGroups;
                        if (free > 0)
                        {
                            var claimed = await _s.Storage.Deliveries.ClaimAsync(_options.Owner, Math.Min(_options.ClaimBatchSize, free), now, _options.Lease, stopping).ConfigureAwait(false);
                            if (claimed.Count > 0)
                            {
                                DeliveryMetrics.Claimed.Add(claimed.Count);
                                Dispatch(claimed);
                                continue;
                            }
                        }
                    }

                    await _wake.WaitAsync(_options.IdlePoll, stopping).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stopping.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    // A storage hiccup must not kill the scheduler; back off briefly and look again.
                    _s.Log.Write(MtaLogLevel.Error, Source, "scheduler iteration failed", ex);
                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(1), stopping).ConfigureAwait(false);
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
            await QuiesceAsync(TimeSpan.FromSeconds(30), CancellationToken.None).ConfigureAwait(false);
            _stopped.TrySetResult();
        }
    }

    private void Dispatch(IReadOnlyList<ClaimedDelivery> claimed)
    {
        foreach (var group in claimed.GroupBy(d => (d.MessageId, Domain: d.RecipientDomain.ToLowerInvariant())))
        {
            var items = group.ToList();
            Interlocked.Increment(ref _pendingGroups);
            var abort = _abort.Token;
            _ = Task.Run(() => RunGroupAsync(items, abort));
        }
    }

    private async Task RunGroupAsync(List<ClaimedDelivery> items, CancellationToken abort)
    {
        try
        {
            await _slots.WaitAsync(abort).ConfigureAwait(false);
            try
            {
                await _processor.ProcessAsync(items, abort).ConfigureAwait(false);
            }
            finally
            {
                _slots.Release();
            }
        }
        catch (OperationCanceledException)
        {
            // Aborted before the group started: the leases are released by QuiesceAsync.
        }
        catch (Exception ex)
        {
            // The leases expire and the deliveries come back; nothing is lost.
            _s.Log.Write(MtaLogLevel.Error, Source, $"group for message {items[0].MessageId} failed", ex);
        }
        finally
        {
            Interlocked.Decrement(ref _pendingGroups);
            Wake();
        }
    }

    private async Task SweepExpiredAsync(DateTimeOffset now, CancellationToken ct)
    {
        while (true)
        {
            var expired = await _s.Storage.Deliveries.ClaimExpiredAsync(_options.Owner, _options.ClaimBatchSize, now, ct).ConfigureAwait(false);
            if (expired.Count == 0)
            {
                return;
            }

            await _processor.ExpireAsync(expired, ct).ConfigureAwait(false);
        }
    }

    private async Task RefreshConfigAsync(CancellationToken ct)
    {
        try
        {
            var routes = await _s.Storage.Config.GetRelayRoutesAsync(ct).ConfigureAwait(false);
            _s.Routes.UpdateRoutes(routes);
            var policies = await _s.Storage.Config.GetTlsPoliciesAsync(ct).ConfigureAwait(false);
            _s.TlsPolicies.Update(policies);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _s.Log.Write(MtaLogLevel.Warning, Source, "could not reload routes and TLS policies; keeping the previous ones", ex);
        }
    }
}
