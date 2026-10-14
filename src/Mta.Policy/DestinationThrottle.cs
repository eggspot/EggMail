using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using Mta.Core;

namespace Mta.Policy;

/// <summary>Identifies what is throttled: a destination (recipient domain or MX host), optionally narrowed to a sending route or IP.</summary>
public readonly struct ThrottleKey : IEquatable<ThrottleKey>
{
    /// <summary>Creates a key.</summary>
    /// <param name="destination">Destination domain or MX host name (compared case-insensitively).</param>
    /// <param name="route">Optional route name or sending IP (compared case-insensitively); null means "any".</param>
    public ThrottleKey(string destination, string? route = null)
    {
        Destination = destination ?? throw new ArgumentNullException(nameof(destination));
        Route = route;
    }

    /// <summary>The destination domain or MX host.</summary>
    public string Destination { get; }

    /// <summary>The route or sending IP, or null.</summary>
    public string? Route { get; }

    /// <inheritdoc />
    public bool Equals(ThrottleKey other) =>
        string.Equals(Destination, other.Destination, StringComparison.OrdinalIgnoreCase)
        && string.Equals(Route, other.Route, StringComparison.OrdinalIgnoreCase);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is ThrottleKey other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() =>
        HashCode.Combine(
            Destination is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(Destination),
            Route is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(Route));

    /// <inheritdoc />
    public override string ToString() => Route is null ? Destination : Destination + " via " + Route;

    /// <summary>Equality operator.</summary>
    public static bool operator ==(ThrottleKey left, ThrottleKey right) => left.Equals(right);

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(ThrottleKey left, ThrottleKey right) => !left.Equals(right);
}

/// <summary>Ceilings for one throttle key.</summary>
/// <param name="MaxConcurrentConnections">Maximum simultaneous connections.</param>
/// <param name="MaxMessagesPerMinute">Maximum sustained messages per minute (token bucket refill rate).</param>
/// <param name="MaxMessagesPerConnection">Messages that may be sent over one connection before it must be closed (connection re-use cap).</param>
public readonly record struct ThrottleLimits(int MaxConcurrentConnections, double MaxMessagesPerMinute, int MaxMessagesPerConnection);

/// <summary>Configuration for <see cref="DestinationThrottle"/>. Defaults are proposed values.</summary>
public sealed class DestinationThrottleOptions
{
    /// <summary>Ceilings used for destinations without an override. Default: 20 connections, 600 messages/min, 100 messages per connection.</summary>
    public ThrottleLimits Defaults { get; init; } = new(20, 600, 100);

    /// <summary>Per-destination overrides keyed by destination (domain or MX host, case-insensitive), e.g. stricter limits for a fussy provider.</summary>
    public IReadOnlyDictionary<string, ThrottleLimits> Overrides { get; init; } =
        new Dictionary<string, ThrottleLimits>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Concurrency a destination starts at (capped by its ceiling); additive increase grows it. Default 5.</summary>
    public int InitialConcurrentConnections { get; init; } = 5;

    /// <summary>Concurrency floor for multiplicative decrease. Default 1.</summary>
    public int MinConcurrentConnections { get; init; } = 1;

    /// <summary>Rate a destination starts at (capped by its ceiling), messages per minute. Default 120.</summary>
    public double InitialMessagesPerMinute { get; init; } = 120;

    /// <summary>Rate floor, messages per minute. Default 6 (one message every ten seconds).</summary>
    public double MinMessagesPerMinute { get; init; } = 6;

    /// <summary>Token bucket depth expressed as seconds of sustained rate (burst allowance). Default 10 seconds.</summary>
    public double BurstSeconds { get; init; } = 10;

    /// <summary>Consecutive successes needed for one additive increase step. Default 20.</summary>
    public int SuccessesPerIncrease { get; init; } = 20;

    /// <summary>Multiplier applied on a decrease (0.5 halves). Default 0.5.</summary>
    public double DecreaseFactor { get; init; } = 0.5;

    /// <summary>Additive rate increase per step as a fraction of the rate ceiling. Default 0.1.</summary>
    public double RateIncreaseFraction { get; init; } = 0.1;

    /// <summary>After a decrease, no further decrease or increase happens for this long (one throttle burst halves once). Default 60 seconds.</summary>
    public TimeSpan Cooldown { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Connection failures within <see cref="ConnectionFailureWindow"/> that count as a "refusal burst" and cause a decrease. Default 3.</summary>
    public int ConnectionFailureBurstThreshold { get; init; } = 3;

    /// <summary>Window for counting connection failures. Default 30 seconds.</summary>
    public TimeSpan ConnectionFailureWindow { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Retry hint returned when the concurrency limit is reached. Default 1 second.</summary>
    public TimeSpan ConcurrencyRetryHint { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>Keys idle (no leases, no activity) for this long are forgotten, including their learned limits. Default 15 minutes.</summary>
    public TimeSpan IdleEviction { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>How often acquire calls trigger an opportunistic sweep. Default 1 minute.</summary>
    public TimeSpan SweepInterval { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>Soft cap on tracked keys: above it, every idle key is evicted immediately. Default 100,000.</summary>
    public int MaxTrackedKeys { get; init; } = 100_000;

    internal void Validate()
    {
        ValidateLimits(Defaults, nameof(Defaults));
        foreach (var kv in Overrides)
        {
            ValidateLimits(kv.Value, "Overrides[" + kv.Key + "]");
        }

        if (MinConcurrentConnections < 1 || InitialConcurrentConnections < MinConcurrentConnections)
        {
            throw new ArgumentException("Concurrency bounds are inconsistent.");
        }

        if (MinMessagesPerMinute <= 0 || InitialMessagesPerMinute < MinMessagesPerMinute)
        {
            throw new ArgumentException("Rate bounds are inconsistent.");
        }

        if (BurstSeconds <= 0 || SuccessesPerIncrease < 1 || DecreaseFactor is <= 0 or >= 1 || RateIncreaseFraction <= 0
            || ConnectionFailureBurstThreshold < 1 || MaxTrackedKeys < 1)
        {
            throw new ArgumentException("Invalid throttle option.");
        }
    }

    private static void ValidateLimits(ThrottleLimits l, string name)
    {
        if (l.MaxConcurrentConnections < 1 || l.MaxMessagesPerMinute <= 0 || l.MaxMessagesPerConnection < 1 || double.IsNaN(l.MaxMessagesPerMinute))
        {
            throw new ArgumentException("Throttle limits must be positive.", name);
        }
    }
}

/// <summary>Feedback from a delivery attempt that adapts a destination's limits (AIMD).</summary>
public enum ThrottleSignal : byte
{
    /// <summary>The destination accepted a message: counts toward an additive increase.</summary>
    Success = 0,

    /// <summary>The destination asked us to slow down (<see cref="DeliveryClass.TransientThrottle"/> or a 421): multiplicative decrease.</summary>
    Throttled,

    /// <summary>A connection was refused or timed out. A burst of these causes a multiplicative decrease.</summary>
    ConnectionFailure,
}

/// <summary>Why <see cref="DestinationThrottle.TryAcquire"/> refused.</summary>
public enum ThrottleDenial : byte
{
    /// <summary>Not denied.</summary>
    None = 0,

    /// <summary>All connection slots for the key are in use.</summary>
    ConcurrencyLimit,

    /// <summary>The message rate bucket is empty.</summary>
    RateLimit,
}

/// <summary>The outcome of <see cref="DestinationThrottle.TryAcquire"/>: a lease, or how long to wait.</summary>
public readonly struct ThrottleResult
{
    internal ThrottleResult(ThrottleLease? lease, ThrottleDenial denial, TimeSpan retryAfter)
    {
        Lease = lease;
        Denial = denial;
        RetryAfter = retryAfter;
    }

    /// <summary>The lease (dispose it when the connection is closed), or null when denied.</summary>
    public ThrottleLease? Lease { get; }

    /// <summary>Why the request was denied (None when a lease was granted).</summary>
    public ThrottleDenial Denial { get; }

    /// <summary>When denied, how long until a retry is worthwhile.</summary>
    public TimeSpan RetryAfter { get; }

    /// <summary>True when a lease was granted.</summary>
    [MemberNotNullWhen(true, nameof(Lease))]
    public bool Acquired => Lease is not null;
}

/// <summary>Current adaptive state of one throttle key, for the dashboard and tests.</summary>
public sealed record ThrottleSnapshot(
    ThrottleKey Key,
    int InUse,
    int ConcurrencyLimit,
    int ConcurrencyCeiling,
    double MessagesPerMinute,
    double MessagesPerMinuteCeiling,
    double AvailableTokens,
    bool Penalized,
    DateTimeOffset? LastDecreaseAt);

internal sealed class ThrottleState
{
    public readonly ThrottleKey Key;

    /// <summary>The ceilings of the options (this destination's override or the defaults), before this replica's share of them is taken.</summary>
    public readonly ThrottleLimits FullCeiling;

    /// <summary>The ceilings this replica may use: <see cref="FullCeiling"/> divided among the live replicas. Changed only under <see cref="Gate"/>.</summary>
    public ThrottleLimits Ceiling;
    public readonly object Gate = new();

    public int InUse;
    public int ConcurrencyLimit;
    public double Rate;
    public double Tokens;
    public long RefillTicks;
    public int SuccessStreak;
    public bool HasDecreased;
    public long LastDecreaseTicks;
    public int FailureCount;
    public long FailureWindowStartTicks;
    public long LastTouchTicks;
    public bool Evicted;

    public ThrottleState(ThrottleKey key, ThrottleLimits fullCeiling, ThrottleLimits ceiling, int concurrency, double rate, long nowTicks, double burstSeconds)
    {
        Key = key;
        FullCeiling = fullCeiling;
        Ceiling = ceiling;
        ConcurrencyLimit = concurrency;
        Rate = rate;
        RefillTicks = nowTicks;
        LastTouchTicks = nowTicks;
        Tokens = Capacity(burstSeconds);
    }

    public double Capacity(double burstSeconds) => Math.Max(1.0, Rate * burstSeconds / 60.0);
}

/// <summary>
/// A granted connection slot for a throttle key. Holds one of the key's concurrent-connection slots until disposed and has consumed
/// the rate token for its first message. Further messages sent over the same connection call <see cref="TryTakeMessage"/>.
/// This is a class (not a struct) so that copies cannot be disposed twice or lose the per-connection message count; dispose is idempotent.
/// </summary>
public sealed class ThrottleLease : IDisposable
{
    private readonly DestinationThrottle _owner;
    private readonly ThrottleState _state;
    private int _messages = 1;
    private int _disposed;

    internal ThrottleLease(DestinationThrottle owner, ThrottleState state)
    {
        _owner = owner;
        _state = state;
    }

    /// <summary>The key this lease is for.</summary>
    public ThrottleKey Key => _state.Key;

    /// <summary>Messages taken on this connection so far (including the first).</summary>
    public int MessagesTaken => Volatile.Read(ref _messages);

    /// <summary>True when the per-connection message cap is reached: close the connection and acquire a new lease for further messages.</summary>
    public bool IsExhausted => MessagesTaken >= _state.Ceiling.MaxMessagesPerConnection;

    /// <summary>
    /// Reserves one more message on this connection. Returns false when the connection is exhausted (<see cref="IsExhausted"/>)
    /// or the rate bucket is empty; <paramref name="retryAfter"/> is then the time until a token is available (zero if exhausted).
    /// </summary>
    public bool TryTakeMessage(out TimeSpan retryAfter) => _owner.TryTakeMessage(_state, ref _messages, out retryAfter);

    /// <summary>Feeds the outcome of an attempt on this connection back into the key's adaptive limits.</summary>
    public void Report(ThrottleSignal signal) => _owner.Report(_state, signal);

    /// <summary>Releases the connection slot.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _owner.Release(_state);
        }
    }
}

/// <summary>
/// Per-destination connection and rate control with adaptive (AIMD) limits. Keyed by (destination domain or MX host, optional route/IP).
/// A key's concurrency and message rate start modestly, grow additively after a run of successes and are halved when the destination
/// throttles us or refuses connections in a burst, with a cooldown between changes. Thread-safe: each key has its own short lock.
/// Idle keys are evicted so memory stays bounded.
/// </summary>
public sealed class DestinationThrottle
{
    private readonly ConcurrentDictionary<ThrottleKey, ThrottleState> _states = new();
    private readonly DestinationThrottleOptions _options;
    private readonly IClock _clock;
    private readonly long _idleTicks;
    private readonly long _sweepTicks;
    private readonly long _cooldownTicks;
    private readonly long _failureWindowTicks;
    private readonly ConcurrentDictionary<ThrottleKey, long> _slowdowns = new();
    private volatile ReplicaShare _share = ReplicaShare.Alone;
    private int _count;
    private long _lastSweepTicks;
    private int _sweeping;

    /// <summary>Slowdowns kept for the other replicas at most (a burst against more keys than this tells them nothing more).</summary>
    private const int MaxPendingSlowdowns = 4096;

    private sealed record ReplicaShare(int Index, int Count)
    {
        public static readonly ReplicaShare Alone = new(0, 1);
    }

    /// <summary>Creates a throttle.</summary>
    public DestinationThrottle(IClock clock, DestinationThrottleOptions? options = null)
    {
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _options = options ?? new DestinationThrottleOptions();
        _options.Validate();
        _idleTicks = _options.IdleEviction.Ticks;
        _sweepTicks = _options.SweepInterval.Ticks;
        _cooldownTicks = _options.Cooldown.Ticks;
        _failureWindowTicks = _options.ConnectionFailureWindow.Ticks;
        _lastSweepTicks = clock.UtcNow.UtcTicks;
    }

    /// <summary>The number of keys currently tracked.</summary>
    public int TrackedKeyCount => Volatile.Read(ref _count);

    /// <summary>
    /// Tells the throttle it is replica <paramref name="index"/> (0-based rank among the live replicas, the same ordering on every replica) of <paramref name="count"/>
    /// sharing one set of remote destinations. Every ceiling is divided so the replicas together stay within it: the connection ceiling is split into whole connections
    /// (the first <c>ceiling mod count</c> ranks get one more; at least one each, so with a ceiling below the replica count the sum can exceed it), the message rate, the initial
    /// values and the floor are divided evenly, the per-connection message cap is unchanged. Limits the destination has already learned are scaled by the same ratio, so a
    /// penalized destination stays penalized by the same fraction. A replica that learns of its peers a few seconds late sends at the old share for those seconds.
    /// </summary>
    public void SetReplicaShare(int index, int count)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(count, 1);
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, count);
        ReplicaShare current = _share;
        if (current.Index == index && current.Count == count)
        {
            return;
        }

        var next = new ReplicaShare(index, count);
        _share = next;
        foreach (var kv in _states)
        {
            lock (kv.Value.Gate)
            {
                Rescale(kv.Value, next);
            }
        }
    }

    /// <summary>Moves a state to <paramref name="share"/>: the ceilings are recomputed and what the destination has learned is scaled by the same ratio. Call under the state's lock; a state already at the share is unchanged.</summary>
    private void Rescale(ThrottleState state, ReplicaShare share)
    {
        ThrottleLimits old = state.Ceiling;
        ThrottleLimits scaled = Scale(state.FullCeiling, share);
        if (scaled == old)
        {
            return;
        }

        state.Ceiling = scaled;
        state.ConcurrencyLimit = Math.Clamp((int)Math.Ceiling(state.ConcurrencyLimit * (double)scaled.MaxConcurrentConnections / old.MaxConcurrentConnections), Math.Min(_options.MinConcurrentConnections, scaled.MaxConcurrentConnections), scaled.MaxConcurrentConnections);
        state.Rate = Math.Clamp(state.Rate * scaled.MaxMessagesPerMinute / old.MaxMessagesPerMinute, Math.Min(MinRate(share), scaled.MaxMessagesPerMinute), scaled.MaxMessagesPerMinute);
        state.Tokens = Math.Min(state.Tokens, state.Capacity(_options.BurstSeconds));
    }

    /// <summary>
    /// Takes the destinations this replica slowed down since the last call (a throttling reply or a burst of refused connections, not a slowdown it adopted from another
    /// replica), with the time of the latest one, so the host can tell the other replicas. Each key appears once.
    /// </summary>
    public void DrainSlowdowns(List<(ThrottleKey Key, DateTimeOffset At)> into)
    {
        foreach (var kv in _slowdowns)
        {
            if (_slowdowns.TryRemove(kv))
            {
                into.Add((kv.Key, new DateTimeOffset(kv.Value, TimeSpan.Zero)));
            }
        }
    }

    /// <summary>
    /// Slows <paramref name="key"/> down because another replica was told to by the destination (the same multiplicative decrease, including its cooldown, which makes
    /// a burst of replicas halve once). Not passed on again.
    /// </summary>
    public void ApplyPeerSlowdown(in ThrottleKey key)
    {
        long now = _clock.UtcNow.UtcTicks;
        while (true)
        {
            ThrottleState state = GetOrCreate(key, now);
            lock (state.Gate)
            {
                if (state.Evicted)
                {
                    continue;
                }

                state.LastTouchTicks = now;
                state.SuccessStreak = 0;
                Decrease(state, now, passOn: false);
                return;
            }
        }
    }

    /// <summary>
    /// Tries to take a connection slot (and the first message token) for <paramref name="key"/>.
    /// On success dispose the returned lease when the connection closes.
    /// </summary>
    public ThrottleResult TryAcquire(in ThrottleKey key)
    {
        long now = _clock.UtcNow.UtcTicks;
        MaybeSweep(now);
        while (true)
        {
            ThrottleState state = GetOrCreate(key, now);
            lock (state.Gate)
            {
                if (state.Evicted)
                {
                    continue; // lost a race with the sweeper; fetch a fresh state
                }

                state.LastTouchTicks = now;
                Refill(state, now);
                if (state.InUse >= state.ConcurrencyLimit)
                {
                    return new ThrottleResult(null, ThrottleDenial.ConcurrencyLimit, _options.ConcurrencyRetryHint);
                }

                if (state.Tokens < 1.0)
                {
                    return new ThrottleResult(null, ThrottleDenial.RateLimit, TimeUntilToken(state));
                }

                state.Tokens -= 1.0;
                state.InUse++;
                return new ThrottleResult(new ThrottleLease(this, state), ThrottleDenial.None, TimeSpan.Zero);
            }
        }
    }

    /// <summary>Feeds an attempt outcome back for <paramref name="key"/> without needing a lease (for example a connect failure before any lease was held).</summary>
    public void Report(in ThrottleKey key, ThrottleSignal signal)
    {
        long now = _clock.UtcNow.UtcTicks;
        while (true)
        {
            ThrottleState state = GetOrCreate(key, now);
            if (!ReportCore(state, signal, now))
            {
                continue;
            }

            return;
        }
    }

    /// <summary>Maps a classified reply to the throttle signal it implies: throttling replies and 421 slow us down, deliveries speed us up, everything else is neutral (null).</summary>
    public static ThrottleSignal? SignalFor(DeliveryClass deliveryClass, int replyCode = 0) =>
        deliveryClass switch
        {
            DeliveryClass.TransientThrottle => ThrottleSignal.Throttled,
            DeliveryClass.Delivered => ThrottleSignal.Success,
            _ when replyCode == 421 => ThrottleSignal.Throttled,
            _ => null,
        };

    /// <summary>Current state of a key, or null if it is not tracked.</summary>
    public ThrottleSnapshot? GetSnapshot(in ThrottleKey key) =>
        _states.TryGetValue(key, out ThrottleState? state) ? Snapshot(state) : null;

    /// <summary>Snapshots of every tracked key (for the dashboard).</summary>
    public IReadOnlyList<ThrottleSnapshot> GetSnapshots()
    {
        var list = new List<ThrottleSnapshot>(_states.Count);
        foreach (var kv in _states)
        {
            list.Add(Snapshot(kv.Value));
        }

        return list;
    }

    /// <summary>Evicts idle keys now. Returns the number evicted.</summary>
    public int Sweep() => SweepCore(_clock.UtcNow.UtcTicks, force: false, keep: null);

    // -------------------------------------------------------------------------------------------------------------

    internal bool TryTakeMessage(ThrottleState state, ref int messages, out TimeSpan retryAfter)
    {
        retryAfter = TimeSpan.Zero;
        long now = _clock.UtcNow.UtcTicks;
        lock (state.Gate)
        {
            state.LastTouchTicks = now;
            if (messages >= state.Ceiling.MaxMessagesPerConnection)
            {
                return false;
            }

            Refill(state, now);
            if (state.Tokens < 1.0)
            {
                retryAfter = TimeUntilToken(state);
                return false;
            }

            state.Tokens -= 1.0;
            messages++;
            return true;
        }
    }

    internal void Release(ThrottleState state)
    {
        long now = _clock.UtcNow.UtcTicks;
        lock (state.Gate)
        {
            state.InUse--;
            state.LastTouchTicks = now;
        }
    }

    internal void Report(ThrottleState state, ThrottleSignal signal)
    {
        // A lease pins its state (InUse > 0), so it cannot have been evicted.
        ReportCore(state, signal, _clock.UtcNow.UtcTicks);
    }

    private bool ReportCore(ThrottleState state, ThrottleSignal signal, long now)
    {
        lock (state.Gate)
        {
            if (state.Evicted)
            {
                return false;
            }

            state.LastTouchTicks = now;
            switch (signal)
            {
                case ThrottleSignal.Success:
                    state.FailureCount = 0;
                    if (++state.SuccessStreak >= _options.SuccessesPerIncrease && !InCooldown(state, now))
                    {
                        Increase(state);
                        state.SuccessStreak = 0;
                    }

                    break;
                case ThrottleSignal.Throttled:
                    state.SuccessStreak = 0;
                    Decrease(state, now, passOn: true);
                    break;
                case ThrottleSignal.ConnectionFailure:
                    state.SuccessStreak = 0;
                    if (state.FailureCount == 0 || now - state.FailureWindowStartTicks > _failureWindowTicks)
                    {
                        state.FailureCount = 0;
                        state.FailureWindowStartTicks = now;
                    }

                    if (++state.FailureCount >= _options.ConnectionFailureBurstThreshold)
                    {
                        state.FailureCount = 0;
                        Decrease(state, now, passOn: true);
                    }

                    break;
            }

            return true;
        }
    }

    private bool InCooldown(ThrottleState state, long now) => state.HasDecreased && now - state.LastDecreaseTicks < _cooldownTicks;

    private void Decrease(ThrottleState state, long now, bool passOn)
    {
        if (InCooldown(state, now))
        {
            return;
        }

        Refill(state, now);
        state.ConcurrencyLimit = Math.Max(_options.MinConcurrentConnections, (int)(state.ConcurrencyLimit * _options.DecreaseFactor));
        state.Rate = Math.Max(MinRate(_share), state.Rate * _options.DecreaseFactor);
        state.Tokens = Math.Min(state.Tokens, state.Capacity(_options.BurstSeconds));
        state.HasDecreased = true;
        state.LastDecreaseTicks = now;
        if (passOn && _slowdowns.Count < MaxPendingSlowdowns)
        {
            _slowdowns[state.Key] = now;
        }
    }

    private void Increase(ThrottleState state)
    {
        state.ConcurrencyLimit = Math.Min(state.Ceiling.MaxConcurrentConnections, state.ConcurrencyLimit + 1);
        double step = Math.Max(1.0, state.Ceiling.MaxMessagesPerMinute * _options.RateIncreaseFraction);
        state.Rate = Math.Min(state.Ceiling.MaxMessagesPerMinute, state.Rate + step);
    }

    private void Refill(ThrottleState state, long now)
    {
        long elapsed = now - state.RefillTicks;
        if (elapsed <= 0)
        {
            return; // clock did not advance (or went backwards): never refill from a negative interval
        }

        state.RefillTicks = now;
        double capacity = state.Capacity(_options.BurstSeconds);
        double added = state.Rate / 60.0 * ((double)elapsed / TimeSpan.TicksPerSecond);
        state.Tokens = Math.Min(capacity, state.Tokens + added);
    }

    private static TimeSpan TimeUntilToken(ThrottleState state)
    {
        double secondsPerToken = 60.0 / state.Rate;
        double wait = (1.0 - state.Tokens) * secondsPerToken;
        return TimeSpan.FromSeconds(Math.Max(wait, 0.001));
    }

    private ThrottleState GetOrCreate(in ThrottleKey key, long now)
    {
        if (_states.TryGetValue(key, out ThrottleState? existing))
        {
            return existing;
        }

        ReplicaShare share = _share;
        ThrottleLimits full = _options.Overrides.TryGetValue(key.Destination, out ThrottleLimits o) ? o : _options.Defaults;
        ThrottleLimits ceiling = Scale(full, share);
        int concurrency = Math.Clamp((int)Math.Ceiling((double)_options.InitialConcurrentConnections / share.Count), Math.Min(_options.MinConcurrentConnections, ceiling.MaxConcurrentConnections), ceiling.MaxConcurrentConnections);
        double rate = Math.Clamp(_options.InitialMessagesPerMinute / share.Count, Math.Min(MinRate(share), ceiling.MaxMessagesPerMinute), ceiling.MaxMessagesPerMinute);
        var created = new ThrottleState(key, full, ceiling, concurrency, rate, now, _options.BurstSeconds);
        ThrottleState winner = _states.GetOrAdd(key, created);
        if (ReferenceEquals(winner, created))
        {
            // The share may have changed between reading it and adding the state, in which case SetReplicaShare did not see this state.
            ReplicaShare current = _share;
            if (!ReferenceEquals(current, share))
            {
                lock (created.Gate)
                {
                    Rescale(created, current);
                }
            }

            if (Interlocked.Increment(ref _count) > _options.MaxTrackedKeys)
            {
                SweepCore(now, force: true, keep: created);
            }
        }

        return winner;
    }

    private static ThrottleLimits Scale(ThrottleLimits full, ReplicaShare share)
    {
        if (share.Count <= 1)
        {
            return full;
        }

        int connections = full.MaxConcurrentConnections / share.Count + (share.Index < full.MaxConcurrentConnections % share.Count ? 1 : 0);
        return new ThrottleLimits(Math.Max(1, connections), full.MaxMessagesPerMinute / share.Count, full.MaxMessagesPerConnection);
    }

    private double MinRate(ReplicaShare share) => _options.MinMessagesPerMinute / share.Count;

    private void MaybeSweep(long now)
    {
        long last = Volatile.Read(ref _lastSweepTicks);
        if (now - last >= _sweepTicks && Interlocked.CompareExchange(ref _lastSweepTicks, now, last) == last)
        {
            SweepCore(now, force: false, keep: null);
        }
    }

    private int SweepCore(long now, bool force, ThrottleState? keep)
    {
        if (Interlocked.CompareExchange(ref _sweeping, 1, 0) != 0)
        {
            return 0;
        }

        int removed = 0;
        try
        {
            foreach (var kv in _states)
            {
                ThrottleState state = kv.Value;
                if (ReferenceEquals(state, keep))
                {
                    continue;
                }

                lock (state.Gate)
                {
                    if (state.InUse > 0 || (!force && now - state.LastTouchTicks < _idleTicks))
                    {
                        continue;
                    }

                    state.Evicted = true;
                }

                if (_states.TryRemove(new KeyValuePair<ThrottleKey, ThrottleState>(kv.Key, state)))
                {
                    Interlocked.Decrement(ref _count);
                    removed++;
                }
            }
        }
        finally
        {
            Volatile.Write(ref _sweeping, 0);
        }

        return removed;
    }

    private ThrottleSnapshot Snapshot(ThrottleState state)
    {
        lock (state.Gate)
        {
            Refill(state, _clock.UtcNow.UtcTicks);
            return new ThrottleSnapshot(
                state.Key,
                state.InUse,
                state.ConcurrencyLimit,
                state.Ceiling.MaxConcurrentConnections,
                state.Rate,
                state.Ceiling.MaxMessagesPerMinute,
                state.Tokens,
                state.ConcurrencyLimit < state.Ceiling.MaxConcurrentConnections || state.Rate < state.Ceiling.MaxMessagesPerMinute,
                state.HasDecreased ? new DateTimeOffset(state.LastDecreaseTicks, TimeSpan.Zero) : null);
        }
    }
}
