using System.Collections.Concurrent;
using Mta.Core;

namespace Mta.Policy;

/// <summary>What a <see cref="RouteHealthKey"/> names.</summary>
public enum RouteHealthKind : byte
{
    /// <summary>A delivery route: the direct-MX route (<see cref="RoutePlanner.DirectRouteName"/>) or a configured relay.</summary>
    Route = 0,

    /// <summary>A single MX host (or relay host) on the direct route.</summary>
    MxHost,
}

/// <summary>Identifies a circuit breaker.</summary>
public readonly struct RouteHealthKey : IEquatable<RouteHealthKey>
{
    /// <summary>Creates a key.</summary>
    public RouteHealthKey(RouteHealthKind kind, string name)
    {
        Kind = kind;
        Name = name ?? throw new ArgumentNullException(nameof(name));
    }

    /// <summary>A route key.</summary>
    public static RouteHealthKey ForRoute(string routeName) => new(RouteHealthKind.Route, routeName);

    /// <summary>An MX host key.</summary>
    public static RouteHealthKey ForMxHost(string host) => new(RouteHealthKind.MxHost, host);

    /// <summary>Route or MX host.</summary>
    public RouteHealthKind Kind { get; }

    /// <summary>Route name or host name (case-insensitive).</summary>
    public string Name { get; }

    /// <inheritdoc />
    public bool Equals(RouteHealthKey other) => Kind == other.Kind && string.Equals(Name, other.Name, StringComparison.OrdinalIgnoreCase);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is RouteHealthKey other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(Kind, Name is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(Name));

    /// <inheritdoc />
    public override string ToString() => Kind == RouteHealthKind.Route ? "route:" + Name : "mx:" + Name;
}

/// <summary>Circuit breaker states.</summary>
public enum CircuitState : byte
{
    /// <summary>Healthy: traffic flows.</summary>
    Closed = 0,

    /// <summary>Tripped: traffic is refused until the cooldown ends.</summary>
    Open,

    /// <summary>Cooldown over: one probe attempt is allowed to find out whether the target recovered.</summary>
    HalfOpen,
}

/// <summary>Admission decision for an attempt.</summary>
public enum RouteAdmission : byte
{
    /// <summary>The breaker is closed: go ahead.</summary>
    Allowed = 0,

    /// <summary>The breaker is half-open and this caller holds the single probe: report the result with <see cref="RouteHealth.ReportSuccess"/> or <see cref="RouteHealth.ReportFailure"/>.</summary>
    Probe,

    /// <summary>The breaker is open (or a probe is already in flight): skip this target.</summary>
    Rejected,
}

/// <summary>Configuration for <see cref="RouteHealth"/>. Defaults are proposed.</summary>
public sealed class RouteHealthOptions
{
    /// <summary>Consecutive connect failures or timeouts that open the circuit. Default 5.</summary>
    public int FailureThreshold { get; init; } = 5;

    /// <summary>Initial cooldown while open. Default 5 minutes.</summary>
    public TimeSpan Cooldown { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Each failed probe multiplies the cooldown by this factor. Default 2.</summary>
    public double CooldownMultiplier { get; init; } = 2.0;

    /// <summary>Upper bound for the cooldown. Default 1 hour.</summary>
    public TimeSpan MaxCooldown { get; init; } = TimeSpan.FromHours(1);

    /// <summary>A probe that never reports back frees the slot after this long. Default 2 minutes.</summary>
    public TimeSpan ProbeTimeout { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>Closed entries with no recent activity are dropped after this long. Default 1 hour.</summary>
    public TimeSpan IdleEviction { get; init; } = TimeSpan.FromHours(1);

    /// <summary>Failures older than this no longer count toward consecutive failures. Default 10 minutes.</summary>
    public TimeSpan FailureStaleAfter { get; init; } = TimeSpan.FromMinutes(10);

    internal void Validate()
    {
        if (FailureThreshold < 1 || Cooldown <= TimeSpan.Zero || CooldownMultiplier < 1 || MaxCooldown < Cooldown
            || ProbeTimeout <= TimeSpan.Zero || IdleEviction <= TimeSpan.Zero || FailureStaleAfter <= TimeSpan.Zero)
        {
            throw new ArgumentException("Invalid route health option.");
        }
    }
}

/// <summary>A point-in-time view of one breaker, for the dashboard.</summary>
public sealed record RouteHealthSnapshot(
    RouteHealthKey Key,
    CircuitState State,
    int ConsecutiveFailures,
    DateTimeOffset? OpenedAt,
    DateTimeOffset? RetryAt,
    DateTimeOffset? LastFailureAt,
    DateTimeOffset? LastSuccessAt,
    string? LastError,
    long TotalFailures,
    long TotalSuccesses);

/// <summary>
/// Circuit breakers per route and per MX host. A target opens after <see cref="RouteHealthOptions.FailureThreshold"/> consecutive
/// connect failures or timeouts, stays open for a cooldown (growing after each failed probe), then lets exactly one probe through
/// (half-open). A success closes it. Thread-safe with one short lock per target; entries for healthy idle targets are evicted.
/// </summary>
public sealed class RouteHealth
{
    private sealed class Entry
    {
        public readonly object Gate = new();
        public CircuitState State;
        public int ConsecutiveFailures;
        public long OpenedAtTicks;
        public long RetryAtTicks;
        public long CooldownTicks;
        public long LastFailureTicks;
        public long LastSuccessTicks;
        public long LastTouchTicks;
        public bool ProbeInFlight;
        public long ProbeStartedTicks;
        public string? LastError;
        public long TotalFailures;
        public long TotalSuccesses;
        public bool Evicted;
    }

    private readonly ConcurrentDictionary<RouteHealthKey, Entry> _entries = new();
    private readonly RouteHealthOptions _options;
    private readonly IClock _clock;
    private int _reports;

    /// <summary>Creates the tracker.</summary>
    public RouteHealth(IClock clock, RouteHealthOptions? options = null)
    {
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _options = options ?? new RouteHealthOptions();
        _options.Validate();
    }

    /// <summary>
    /// Asks whether an attempt may use <paramref name="key"/>. When rejected, <paramref name="retryAt"/> is when the target may be probed again.
    /// When the result is <see cref="RouteAdmission.Probe"/> the caller must report the outcome.
    /// </summary>
    public RouteAdmission TryAdmit(in RouteHealthKey key, out DateTimeOffset retryAt)
    {
        retryAt = default;
        if (!_entries.TryGetValue(key, out Entry? entry))
        {
            return RouteAdmission.Allowed; // never seen: closed
        }

        long now = _clock.UtcNow.UtcTicks;
        lock (entry.Gate)
        {
            switch (entry.State)
            {
                case CircuitState.Closed:
                    return RouteAdmission.Allowed;

                case CircuitState.Open:
                    if (now < entry.RetryAtTicks)
                    {
                        retryAt = new DateTimeOffset(entry.RetryAtTicks, TimeSpan.Zero);
                        return RouteAdmission.Rejected;
                    }

                    entry.State = CircuitState.HalfOpen;
                    entry.ProbeInFlight = true;
                    entry.ProbeStartedTicks = now;
                    return RouteAdmission.Probe;

                default: // HalfOpen
                    if (!entry.ProbeInFlight || now - entry.ProbeStartedTicks >= _options.ProbeTimeout.Ticks)
                    {
                        entry.ProbeInFlight = true;
                        entry.ProbeStartedTicks = now;
                        return RouteAdmission.Probe;
                    }

                    retryAt = new DateTimeOffset(entry.ProbeStartedTicks + _options.ProbeTimeout.Ticks, TimeSpan.Zero);
                    return RouteAdmission.Rejected;
            }
        }
    }

    /// <summary>
    /// Non-mutating check used when planning: would <see cref="TryAdmit(in RouteHealthKey, out DateTimeOffset)"/> let an attempt through right now?
    /// Never claims the half-open probe. When false, <paramref name="retryAt"/> is when the target can be tried again.
    /// </summary>
    public bool IsAvailable(in RouteHealthKey key, out DateTimeOffset retryAt)
    {
        retryAt = default;
        if (!_entries.TryGetValue(key, out Entry? entry))
        {
            return true;
        }

        long now = _clock.UtcNow.UtcTicks;
        lock (entry.Gate)
        {
            switch (entry.State)
            {
                case CircuitState.Closed:
                    return true;
                case CircuitState.Open:
                    if (now >= entry.RetryAtTicks)
                    {
                        return true;
                    }

                    retryAt = At(entry.RetryAtTicks);
                    return false;
                default:
                    if (!entry.ProbeInFlight || now - entry.ProbeStartedTicks >= _options.ProbeTimeout.Ticks)
                    {
                        return true;
                    }

                    retryAt = At(entry.ProbeStartedTicks + _options.ProbeTimeout.Ticks);
                    return false;
            }
        }
    }

    /// <summary>Convenience overload that discards the retry time.</summary>
    public RouteAdmission TryAdmit(in RouteHealthKey key) => TryAdmit(key, out _);

    /// <summary>Records that a connection to the target was established (any SMTP reply, including 4xx and 5xx, proves connectivity). Closes the circuit.</summary>
    public void ReportSuccess(in RouteHealthKey key)
    {
        long now = _clock.UtcNow.UtcTicks;
        if (!_entries.TryGetValue(key, out Entry? entry))
        {
            return; // healthy and untracked: nothing to remember
        }

        lock (entry.Gate)
        {
            entry.State = CircuitState.Closed;
            entry.ConsecutiveFailures = 0;
            entry.ProbeInFlight = false;
            entry.CooldownTicks = 0;
            entry.LastSuccessTicks = now;
            entry.LastTouchTicks = now;
            entry.TotalSuccesses++;
        }

        MaybeSweep(now);
    }

    /// <summary>Records a connect failure, refusal or timeout. May open the circuit; a failed probe re-opens it with a longer cooldown.</summary>
    /// <param name="key">The target.</param>
    /// <param name="error">Short description for the dashboard (optional).</param>
    public void ReportFailure(in RouteHealthKey key, string? error = null)
    {
        long now = _clock.UtcNow.UtcTicks;
        while (true)
        {
            Entry entry = _entries.GetOrAdd(key, static _ => new Entry());
            lock (entry.Gate)
            {
                if (entry.Evicted)
                {
                    continue;
                }

                entry.LastTouchTicks = now;
                entry.TotalFailures++;
                entry.LastError = error;
                if (entry.State == CircuitState.HalfOpen)
                {
                    // Probe failed: re-open with a longer cooldown.
                    long next = (long)Math.Min(
                        (entry.CooldownTicks == 0 ? _options.Cooldown.Ticks : entry.CooldownTicks) * _options.CooldownMultiplier,
                        _options.MaxCooldown.Ticks);
                    Open(entry, now, next);
                    entry.ProbeInFlight = false;
                }
                else if (entry.State == CircuitState.Closed)
                {
                    if (entry.ConsecutiveFailures > 0 && now - entry.LastFailureTicks > _options.FailureStaleAfter.Ticks)
                    {
                        entry.ConsecutiveFailures = 0; // old failures do not accumulate across long quiet periods
                    }

                    if (++entry.ConsecutiveFailures >= _options.FailureThreshold)
                    {
                        Open(entry, now, _options.Cooldown.Ticks);
                    }
                }

                // Failures reported while Open (stragglers from in-flight attempts) only update counters.
                entry.LastFailureTicks = now;
            }

            break;
        }

        MaybeSweep(now);
    }

    /// <summary>The state of one target without changing it (Open is reported as HalfOpen once its cooldown has elapsed).</summary>
    public RouteHealthSnapshot GetSnapshot(in RouteHealthKey key)
    {
        if (_entries.TryGetValue(key, out Entry? entry))
        {
            return Snapshot(key, entry);
        }

        return new RouteHealthSnapshot(key, CircuitState.Closed, 0, null, null, null, null, null, 0, 0);
    }

    /// <summary>Snapshots of every tracked target (for the dashboard).</summary>
    public IReadOnlyList<RouteHealthSnapshot> GetSnapshots()
    {
        var list = new List<RouteHealthSnapshot>(_entries.Count);
        foreach (var kv in _entries)
        {
            list.Add(Snapshot(kv.Key, kv.Value));
        }

        return list;
    }

    /// <summary>The number of tracked targets.</summary>
    public int TrackedCount => _entries.Count;

    /// <summary>Drops closed, idle entries. Returns the number removed.</summary>
    public int Sweep() => SweepCore(_clock.UtcNow.UtcTicks);

    private static void Open(Entry entry, long now, long cooldownTicks)
    {
        entry.State = CircuitState.Open;
        entry.OpenedAtTicks = now;
        entry.CooldownTicks = cooldownTicks;
        entry.RetryAtTicks = now + cooldownTicks;
    }

    private RouteHealthSnapshot Snapshot(RouteHealthKey key, Entry e)
    {
        long now = _clock.UtcNow.UtcTicks;
        lock (e.Gate)
        {
            CircuitState state = e.State == CircuitState.Open && now >= e.RetryAtTicks ? CircuitState.HalfOpen : e.State;
            return new RouteHealthSnapshot(
                key,
                state,
                e.ConsecutiveFailures,
                e.State == CircuitState.Closed ? null : At(e.OpenedAtTicks),
                e.State == CircuitState.Open ? At(e.RetryAtTicks) : null,
                e.TotalFailures > 0 ? At(e.LastFailureTicks) : null,
                e.TotalSuccesses > 0 ? At(e.LastSuccessTicks) : null,
                e.LastError,
                e.TotalFailures,
                e.TotalSuccesses);
        }
    }

    private static DateTimeOffset At(long ticks) => new(ticks, TimeSpan.Zero);

    private void MaybeSweep(long now)
    {
        if ((Interlocked.Increment(ref _reports) & 0xFF) == 0)
        {
            SweepCore(now);
        }
    }

    private int SweepCore(long now)
    {
        int removed = 0;
        foreach (var kv in _entries)
        {
            Entry e = kv.Value;
            lock (e.Gate)
            {
                if (e.State != CircuitState.Closed || now - e.LastTouchTicks < _options.IdleEviction.Ticks)
                {
                    continue;
                }

                e.Evicted = true;
            }

            if (_entries.TryRemove(new KeyValuePair<RouteHealthKey, Entry>(kv.Key, e)))
            {
                removed++;
            }
        }

        return removed;
    }
}
