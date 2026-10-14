using Mta.Core;
using Mta.Storage;

namespace Mta.Policy;

/// <summary>Timing of the periodic replica coordination.</summary>
public sealed class ReplicaCoordinatorOptions
{
    /// <summary>How often a replica beats, publishes what it learned and reads what the others learned. Default 5 seconds.</summary>
    public TimeSpan Interval { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>A replica that has not beaten for this long no longer counts and its share goes to the others. Default 20 seconds (four missed beats).</summary>
    public TimeSpan LiveFor { get; init; } = TimeSpan.FromSeconds(20);

    /// <summary>How long a slowdown told by a destination stays worth passing on to the others. Default 2 minutes (twice the throttle's cooldown).</summary>
    public TimeSpan SlowdownValidFor { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>The longest one round of coordination may take; a database that does not answer in time is treated like one that is down. Default 4 seconds (less than the interval).</summary>
    public TimeSpan CallTimeout { get; init; } = TimeSpan.FromSeconds(4);

    internal void Validate()
    {
        if (Interval <= TimeSpan.Zero || LiveFor <= Interval || SlowdownValidFor <= TimeSpan.Zero || CallTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentException("Invalid replica coordination option (the liveness window must be longer than the interval).");
        }
    }
}

/// <summary>
/// What replicas on one database share about the remote destinations they all send to (DESIGN-DECIDED, decision 82), coordinated every few seconds so the delivery hot path
/// never waits for the database:
/// <list type="bullet">
/// <item><b>Shares.</b> Every beat returns the live replicas; this replica's rank among them and their number set the <see cref="DestinationThrottle"/> share, so the
/// per-destination connection and message-rate ceilings hold for all replicas together instead of each.</item>
/// <item><b>Signals.</b> A destination that told this replica to slow down (the throttle's multiplicative decrease) and an MX host this replica could not reach (an opened
/// circuit) are published; the others apply them (<see cref="DestinationThrottle.ApplyPeerSlowdown"/>, <see cref="RouteHealth.ApplyPeerOpen"/>, which bounds what one sick
/// replica can make the others skip) without publishing them again. Signals are durations stamped by the database, so replica clocks are never compared.</item>
/// </list>
/// A round that fails or takes longer than <see cref="ReplicaCoordinatorOptions.CallTimeout"/> keeps the last share and the unpublished signals (the newest per key, and only
/// while they are still worth passing on) for the next one. A replica cut off from the database for longer than the liveness window is dropped by the others while it keeps
/// its old share, so for that time the shares add up to more than a ceiling; it rejoins at its next successful beat.
/// </summary>
public sealed class ReplicaCoordinator : IAsyncDisposable
{
    private const char KeySeparator = '\t';

    private readonly IReplicaCoordination _coordination;
    private readonly string _replicaName;
    private readonly IClock _clock;
    private readonly DestinationThrottle _throttle;
    private readonly RouteHealth _health;
    private readonly ReplicaCoordinatorOptions _options;
    private readonly IMtaLog _log;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<(string Replica, string Key), DateTimeOffset> _slowdownsApplied = [];
    private readonly Dictionary<ThrottleKey, DateTimeOffset> _unsentSlowdowns = [];
    private readonly Dictionary<RouteHealthKey, (DateTimeOffset RetryAt, TimeSpan Cooldown)> _unsentOpened = [];
    private readonly List<(ThrottleKey Key, DateTimeOffset At)> _drainedSlowdowns = [];
    private readonly List<(RouteHealthKey Key, DateTimeOffset RetryAt, TimeSpan Cooldown)> _drainedOpened = [];
    private int _index;
    private int _count = 1;

    /// <summary>Creates the coordinator for the replica <paramref name="replicaName"/> (unique among the replicas of the deployment, stable for the life of the process) and makes the throttle and the circuit breakers start keeping what it will pass on.</summary>
    public ReplicaCoordinator(IReplicaCoordination coordination, string replicaName, IClock clock, DestinationThrottle throttle, RouteHealth health, ReplicaCoordinatorOptions? options = null, IMtaLog? log = null)
    {
        _coordination = coordination ?? throw new ArgumentNullException(nameof(coordination));
        _replicaName = string.IsNullOrWhiteSpace(replicaName) ? throw new ArgumentException("A replica name is required.", nameof(replicaName)) : replicaName;
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _throttle = throttle ?? throw new ArgumentNullException(nameof(throttle));
        _health = health ?? throw new ArgumentNullException(nameof(health));
        _options = options ?? new ReplicaCoordinatorOptions();
        _options.Validate();
        _log = log ?? NullMtaLog.Instance;
        _throttle.ShareSlowdowns();
        _health.ShareOpenCircuits();
    }

    /// <summary>The name this replica beats under.</summary>
    public string ReplicaName => _replicaName;

    /// <summary>The number of live replicas as of the last round (1 before the first).</summary>
    public int ReplicaCount => Volatile.Read(ref _count);

    /// <summary>This replica's 0-based rank among the live replicas as of the last round.</summary>
    public int ReplicaIndex => Volatile.Read(ref _index);

    /// <summary>One round: beat, apply the share, publish what this replica learned, apply what the others learned. Throws <see cref="TimeoutException"/> when the database does not answer within <see cref="ReplicaCoordinatorOptions.CallTimeout"/>.</summary>
    public async Task RunOnceAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_options.CallTimeout);
            try
            {
                await CoordinateAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException($"the replica coordination did not finish within {_options.CallTimeout.TotalSeconds:0.#} s");
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task CoordinateAsync(CancellationToken ct)
    {
        DateTimeOffset now = _clock.UtcNow;
        IReadOnlyList<string> live = await _coordination.HeartbeatAsync(_replicaName, _options.LiveFor, ct).ConfigureAwait(false);
        ApplyShare(live);

        _drainedSlowdowns.Clear();
        _drainedOpened.Clear();
        _throttle.DrainSlowdowns(_drainedSlowdowns);
        _health.DrainOpened(_drainedOpened);
        foreach ((ThrottleKey key, DateTimeOffset at) in _drainedSlowdowns)
        {
            _unsentSlowdowns[key] = at;
        }

        foreach ((RouteHealthKey key, DateTimeOffset retryAt, TimeSpan cooldown) in _drainedOpened)
        {
            _unsentOpened[key] = (retryAt, cooldown);
        }

        // Only the newest signal per key, and only while it is still worth passing on.
        foreach (var stale in _unsentSlowdowns.Where(s => s.Value + _options.SlowdownValidFor <= now).Select(s => s.Key).ToList())
        {
            _unsentSlowdowns.Remove(stale);
        }

        foreach (var stale in _unsentOpened.Where(o => o.Value.RetryAt <= now).Select(o => o.Key).ToList())
        {
            _unsentOpened.Remove(stale);
        }

        if (_unsentSlowdowns.Count > 0 || _unsentOpened.Count > 0)
        {
            var signals = new List<PeerSignal>(_unsentSlowdowns.Count + _unsentOpened.Count);
            foreach (var (key, at) in _unsentSlowdowns)
            {
                signals.Add(new PeerSignal(PeerSignalKind.DestinationSlowedDown, EncodeKey(key), at + _options.SlowdownValidFor - now, TimeSpan.Zero));
            }

            foreach (var (key, (retryAt, cooldown)) in _unsentOpened)
            {
                signals.Add(new PeerSignal(PeerSignalKind.CircuitOpened, key.ToString(), retryAt - now, cooldown));
            }

            await _coordination.PublishSignalsAsync(_replicaName, signals, ct).ConfigureAwait(false);
            _unsentSlowdowns.Clear();
            _unsentOpened.Clear();
        }

        foreach (ReceivedPeerSignal received in await _coordination.GetSignalsAsync(_replicaName, ct).ConfigureAwait(false))
        {
            Apply(received, now);
        }
    }

    /// <summary>Takes part until cancelled, then stops. A failed round is logged and tried again at the next interval.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(_options.Interval);
        try
        {
            do
            {
                try
                {
                    await RunOnceAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _log.Write(MtaLogLevel.Warning, "replicas", "could not coordinate with the other replicas; keeping the last share and trying again", ex);
                }
            }
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
        }
    }

    /// <summary>Removes this replica from the live set (graceful shutdown). A failure is logged: the others notice within the liveness window anyway.</summary>
    public async Task LeaveAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _coordination.LeaveAsync(_replicaName, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Write(MtaLogLevel.Warning, "replicas", "could not leave the replica set cleanly; the others will notice within the liveness window", ex);
        }
    }

    /// <summary>Releases the coordinator's lock.</summary>
    public ValueTask DisposeAsync()
    {
        _gate.Dispose();
        return ValueTask.CompletedTask;
    }

    private void ApplyShare(IReadOnlyList<string> live)
    {
        int index = -1;
        for (int i = 0; i < live.Count; i++)
        {
            if (string.Equals(live[i], _replicaName, StringComparison.Ordinal))
            {
                index = i;
                break;
            }
        }

        int count = live.Count;
        if (index < 0)
        {
            // Our own beat is not in the list (it was just removed, or the database's clock jumped): count ourselves anyway, last in order.
            index = count++;
        }

        _throttle.SetReplicaShare(index, count);
        Volatile.Write(ref _index, index);
        Volatile.Write(ref _count, count);
    }

    private void Apply(ReceivedPeerSignal received, DateTimeOffset now)
    {
        PeerSignal signal = received.Signal;
        switch (signal.Kind)
        {
            case PeerSignalKind.CircuitOpened when RouteHealthKey.TryParse(signal.Key, out RouteHealthKey health):
                _health.ApplyPeerOpen(health, now + signal.ValidFor, signal.Cooldown);
                break;
            case PeerSignalKind.DestinationSlowedDown:
                // Applied once per publication: the same one is read at every round until it ends.
                var id = (received.ReplicaName, signal.Key);
                if (_slowdownsApplied.TryGetValue(id, out DateTimeOffset seen) && seen >= received.RaisedAt)
                {
                    break;
                }

                _slowdownsApplied[id] = received.RaisedAt;
                _throttle.ApplyPeerSlowdown(DecodeKey(signal.Key));
                if (_slowdownsApplied.Count > 10_000)
                {
                    // Publications are stamped by the database; remember only the ones of the latest few minutes' worth of rounds.
                    DateTimeOffset newest = _slowdownsApplied.Values.Max();
                    foreach (var old in _slowdownsApplied.Where(a => newest - a.Value > _options.SlowdownValidFor).Select(a => a.Key).ToList())
                    {
                        _slowdownsApplied.Remove(old);
                    }
                }

                break;
        }
    }

    private static string EncodeKey(in ThrottleKey key) => key.Route is null ? key.Destination : key.Destination + KeySeparator + key.Route;

    private static ThrottleKey DecodeKey(string text)
    {
        int at = text.IndexOf(KeySeparator, StringComparison.Ordinal);
        return at < 0 ? new ThrottleKey(text) : new ThrottleKey(text[..at], text[(at + 1)..]);
    }
}
