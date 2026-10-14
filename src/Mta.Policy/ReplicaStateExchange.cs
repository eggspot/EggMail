using Mta.Core;
using Mta.Storage;

namespace Mta.Policy;

/// <summary>Timing of the periodic exchange between replicas.</summary>
public sealed class ReplicaStateExchangeOptions
{
    /// <summary>How often a replica beats, publishes what it learned and reads what the others learned. Default 5 seconds.</summary>
    public TimeSpan Interval { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>A replica that has not beaten for this long no longer counts and its share goes to the others. Default 20 seconds (four missed beats).</summary>
    public TimeSpan LiveFor { get; init; } = TimeSpan.FromSeconds(20);

    /// <summary>How long a slowdown told by a destination stays worth passing on to the others. Default 2 minutes (twice the throttle's cooldown).</summary>
    public TimeSpan SlowdownValidFor { get; init; } = TimeSpan.FromMinutes(2);

    internal void Validate()
    {
        if (Interval <= TimeSpan.Zero || LiveFor <= Interval || SlowdownValidFor <= TimeSpan.Zero)
        {
            throw new ArgumentException("Invalid replica exchange option (the liveness window must be longer than the interval).");
        }
    }
}

/// <summary>
/// What replicas on one database share about the remote destinations they all send to (DESIGN-DECIDED, decision 81), exchanged every few seconds so the delivery hot path
/// never waits for the database:
/// <list type="bullet">
/// <item><b>Shares.</b> Every beat returns the live replicas; this replica's rank among them and their number set the <see cref="DestinationThrottle"/> share, so the
/// per-destination connection and message-rate ceilings hold for all replicas together instead of each.</item>
/// <item><b>Signals.</b> A destination that told this replica to slow down (the throttle's multiplicative decrease) and a circuit this replica opened are published; the
/// others apply them (<see cref="DestinationThrottle.ApplyPeerSlowdown"/>, <see cref="RouteHealth.ApplyPeerOpen"/>) without publishing them again.</item>
/// </list>
/// A failed exchange (database unavailable) keeps the last share and the unsent signals for the next one. A replica that has just started takes part in the first
/// exchange before it delivers (<see cref="ExchangeAsync"/>); the others learn of it within one interval, during which the sum of the shares can exceed the ceiling.
/// </summary>
public sealed class ReplicaStateExchange
{
    private const char KeySeparator = '\t';

    private readonly IReplicaCoordination _coordination;
    private readonly string _replicaId;
    private readonly IClock _clock;
    private readonly DestinationThrottle _throttle;
    private readonly RouteHealth _health;
    private readonly ReplicaStateExchangeOptions _options;
    private readonly IMtaLog _log;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<(string Replica, string Key), long> _slowdownsApplied = [];
    private readonly List<(ThrottleKey Key, DateTimeOffset At)> _unsentSlowdowns = [];
    private readonly List<(RouteHealthKey Key, DateTimeOffset RetryAt, TimeSpan Cooldown)> _unsentOpened = [];
    private int _index;
    private int _count = 1;

    /// <summary>Creates the exchange for the replica <paramref name="replicaId"/> (unique among the replicas of the deployment, stable for the life of the process).</summary>
    public ReplicaStateExchange(IReplicaCoordination coordination, string replicaId, IClock clock, DestinationThrottle throttle, RouteHealth health, ReplicaStateExchangeOptions? options = null, IMtaLog? log = null)
    {
        _coordination = coordination ?? throw new ArgumentNullException(nameof(coordination));
        _replicaId = string.IsNullOrWhiteSpace(replicaId) ? throw new ArgumentException("A replica id is required.", nameof(replicaId)) : replicaId;
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _throttle = throttle ?? throw new ArgumentNullException(nameof(throttle));
        _health = health ?? throw new ArgumentNullException(nameof(health));
        _options = options ?? new ReplicaStateExchangeOptions();
        _options.Validate();
        _log = log ?? NullMtaLog.Instance;
    }

    /// <summary>The id this replica beats under.</summary>
    public string ReplicaId => _replicaId;

    /// <summary>The number of live replicas as of the last exchange (1 before the first).</summary>
    public int ReplicaCount => Volatile.Read(ref _count);

    /// <summary>This replica's 0-based rank among the live replicas as of the last exchange.</summary>
    public int ReplicaIndex => Volatile.Read(ref _index);

    /// <summary>One exchange: beat, apply the share, publish what this replica learned, apply what the others learned.</summary>
    public async Task ExchangeAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            DateTimeOffset now = _clock.UtcNow;
            IReadOnlyList<string> live = await _coordination.HeartbeatAsync(_replicaId, now, _options.LiveFor, cancellationToken).ConfigureAwait(false);
            ApplyShare(live);

            _throttle.DrainSlowdowns(_unsentSlowdowns);
            _health.DrainOpened(_unsentOpened);
            if (_unsentSlowdowns.Count > 0 || _unsentOpened.Count > 0)
            {
                var signals = new List<PeerSignal>(_unsentSlowdowns.Count + _unsentOpened.Count);
                foreach ((ThrottleKey key, DateTimeOffset at) in _unsentSlowdowns)
                {
                    signals.Add(new PeerSignal(PeerSignalKind.DestinationSlowedDown, EncodeKey(key), _replicaId, at, at + _options.SlowdownValidFor, 0));
                }

                foreach ((RouteHealthKey key, DateTimeOffset retryAt, TimeSpan cooldown) in _unsentOpened)
                {
                    signals.Add(new PeerSignal(PeerSignalKind.CircuitOpened, key.ToString(), _replicaId, now, retryAt, cooldown.Ticks));
                }

                await _coordination.PublishSignalsAsync(signals, now, cancellationToken).ConfigureAwait(false);
                _unsentSlowdowns.Clear();
                _unsentOpened.Clear();
            }

            foreach (PeerSignal signal in await _coordination.GetSignalsAsync(_replicaId, now, cancellationToken).ConfigureAwait(false))
            {
                Apply(signal);
            }
        }
        finally
        {
            // A failure loses nothing: what was drained but not published stays in the unsent lists for the next exchange, and the share stays as it was.
            _gate.Release();
        }
    }

    /// <summary>Beats until cancelled, then leaves (so the others take over this replica's share at once). A failed exchange is logged and tried again at the next interval.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(_options.Interval);
        try
        {
            do
            {
                try
                {
                    await ExchangeAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _log.Write(MtaLogLevel.Warning, "replicas", "could not exchange state with the other replicas; keeping the last share and trying again", ex);
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
            await _coordination.LeaveAsync(_replicaId, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Write(MtaLogLevel.Warning, "replicas", "could not leave the replica set cleanly; the others will notice within the liveness window", ex);
        }
    }

    private void ApplyShare(IReadOnlyList<string> live)
    {
        int index = -1;
        for (int i = 0; i < live.Count; i++)
        {
            if (string.Equals(live[i], _replicaId, StringComparison.Ordinal))
            {
                index = i;
                break;
            }
        }

        int count = live.Count;
        if (index < 0)
        {
            // Our own beat is not in the list (a clock far from the others'): count ourselves anyway, last in order.
            index = count++;
        }

        _throttle.SetReplicaShare(index, count);
        Volatile.Write(ref _index, index);
        Volatile.Write(ref _count, count);
    }

    private void Apply(PeerSignal signal)
    {
        switch (signal.Kind)
        {
            case PeerSignalKind.CircuitOpened when RouteHealthKey.TryParse(signal.Key, out RouteHealthKey health):
                _health.ApplyPeerOpen(health, signal.Until, TimeSpan.FromTicks(signal.Value));
                break;
            case PeerSignalKind.DestinationSlowedDown:
                // Applied once per signal: the same one is read at every exchange until it ends.
                var id = (signal.ReplicaId, signal.Key);
                if (_slowdownsApplied.TryGetValue(id, out long seen) && seen >= signal.At.UtcTicks)
                {
                    break;
                }

                _slowdownsApplied[id] = signal.At.UtcTicks;
                _throttle.ApplyPeerSlowdown(DecodeKey(signal.Key));
                if (_slowdownsApplied.Count > 10_000)
                {
                    long cutoff = (_clock.UtcNow - _options.SlowdownValidFor).UtcTicks;
                    foreach (var stale in _slowdownsApplied.Where(a => a.Value < cutoff).Select(a => a.Key).ToList())
                    {
                        _slowdownsApplied.Remove(stale);
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
