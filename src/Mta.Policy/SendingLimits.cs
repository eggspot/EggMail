using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using Mta.Core;

namespace Mta.Policy;

/// <summary>Hourly and daily caps for one scope. A null value means unlimited.</summary>
/// <param name="PerHour">Messages per UTC clock hour.</param>
/// <param name="PerDay">Messages per UTC calendar day.</param>
public readonly record struct LimitSet(long? PerHour, long? PerDay)
{
    /// <summary>No limits.</summary>
    public static LimitSet Unlimited => default;
}

/// <summary>Configuration for <see cref="SendingLimits"/>. All defaults are unlimited; the operator sets caps.</summary>
public sealed class SendingLimitsOptions
{
    /// <summary>Caps for the whole installation.</summary>
    public LimitSet Global { get; init; }

    /// <summary>Caps for every tenant without an explicit override.</summary>
    public LimitSet DefaultTenant { get; init; }

    /// <summary>Caps for every sending domain without an explicit override.</summary>
    public LimitSet DefaultSendingDomain { get; init; }

    /// <summary>Warm-up schedule used by <see cref="SendingLimits.StartWarmup(string, DateOnly, WarmupSchedule?)"/> when none is given. Default <see cref="WarmupSchedule.Default"/> (proposed).</summary>
    public WarmupSchedule DefaultWarmup { get; init; } = WarmupSchedule.Default;
}

/// <summary>Result of a sending-limit check.</summary>
public enum SendingDecisionKind : byte
{
    /// <summary>Within all limits; the counters were incremented.</summary>
    Allowed = 0,

    /// <summary>A limit is reached for now: hold the delivery until <see cref="SendingDecision.DeferredUntil"/> instead of dropping it.</summary>
    Deferred,

    /// <summary>The request can never be satisfied (a limit of zero, or a batch larger than a hard cap).</summary>
    Rejected,
}

/// <summary>The outcome of <see cref="SendingLimits.TryReserve"/>.</summary>
/// <param name="Kind">Allowed, deferred or rejected.</param>
/// <param name="At">The time the decision was made; pass it to <see cref="SendingLimits.Release"/> to give the reservation back.</param>
/// <param name="DeferredUntil">For <see cref="SendingDecisionKind.Deferred"/>, when the blocking window ends.</param>
/// <param name="Reason">For deferred or rejected, a short constant naming the limit that stopped it.</param>
/// <param name="LimitedBy">The scope whose limit stopped it.</param>
/// <param name="LimitedWindow">The window of the limit that stopped it.</param>
public readonly record struct SendingDecision(
    SendingDecisionKind Kind,
    DateTimeOffset At,
    DateTimeOffset? DeferredUntil,
    string? Reason,
    CounterScope? LimitedBy,
    CounterWindow? LimitedWindow)
{
    /// <summary>True when sending may proceed.</summary>
    public bool IsAllowed => Kind == SendingDecisionKind.Allowed;
}

/// <summary>One counter and its limit, for the dashboard.</summary>
public sealed record SendingUsage(CounterScope Scope, CounterWindow Window, long Used, long? Limit, bool LimitFromWarmup);

[InlineArray(6)]
internal struct ReservationBuffer
{
    private CounterReservation _element0;
}

/// <summary>
/// Global, per-tenant and per-sending-domain hourly and daily caps with optional warm-up for new sending domains. Every check atomically
/// reserves capacity in all affected counters (all or nothing), so concurrent senders never exceed a cap. The scheduler uses
/// <see cref="SendingDecisionKind.Deferred"/> to hold deliveries until the window rolls over instead of dropping them.
/// Windows are UTC. Counters live behind <see cref="ISendingCounterStore"/> (in memory by default).
/// </summary>
public sealed class SendingLimits
{
    private const long Unbounded = long.MaxValue;

    private readonly IClock _clock;
    private readonly ISendingCounterStore _store;
    private readonly SendingLimitsOptions _options;
    private readonly ConcurrentDictionary<Guid, LimitSet> _tenantLimits = new();
    private readonly ConcurrentDictionary<string, LimitSet> _domainLimits = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, (DateOnly Start, WarmupSchedule Schedule)> _warmups = new(StringComparer.Ordinal);
    private long _lastPrunedHour = long.MinValue;

    /// <summary>Creates the limiter.</summary>
    public SendingLimits(IClock clock, ISendingCounterStore? store = null, SendingLimitsOptions? options = null)
    {
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _store = store ?? new InMemorySendingCounterStore();
        _options = options ?? new SendingLimitsOptions();
    }

    /// <summary>Overrides the caps of one tenant; null removes the override.</summary>
    public void SetTenantLimits(Guid tenantId, LimitSet? limits)
    {
        if (limits is { } l)
        {
            _tenantLimits[tenantId] = l;
        }
        else
        {
            _tenantLimits.TryRemove(tenantId, out _);
        }
    }

    /// <summary>Overrides the caps of one sending domain; null removes the override.</summary>
    public void SetSendingDomainLimits(string sendingDomain, LimitSet? limits)
    {
        string key = NormalizeDomain(sendingDomain);
        if (limits is { } l)
        {
            _domainLimits[key] = l;
        }
        else
        {
            _domainLimits.TryRemove(key, out _);
        }
    }

    /// <summary>Puts a sending domain on a warm-up ramp starting on UTC day <paramref name="startDay"/>.</summary>
    public void StartWarmup(string sendingDomain, DateOnly startDay, WarmupSchedule? schedule = null) =>
        _warmups[NormalizeDomain(sendingDomain)] = (startDay, schedule ?? _options.DefaultWarmup);

    /// <summary>Removes a domain's warm-up ramp.</summary>
    public void StopWarmup(string sendingDomain) => _warmups.TryRemove(NormalizeDomain(sendingDomain), out _);

    /// <summary>The daily warm-up cap applying to a domain right now, or null if it is not warming up (or has graduated).</summary>
    public long? GetWarmupCap(string sendingDomain)
    {
        DateTimeOffset now = _clock.UtcNow;
        return _warmups.TryGetValue(NormalizeDomain(sendingDomain), out var w)
            ? w.Schedule.GetDailyCap(w.Start, DateOnly.FromDateTime(now.UtcDateTime))
            : null;
    }

    /// <summary>
    /// Checks the global, tenant and (if given) sending-domain caps for <paramref name="count"/> messages and, if all fit, reserves them.
    /// </summary>
    /// <param name="tenantId">The sending tenant.</param>
    /// <param name="sendingDomain">The sending domain (registered domain name), or null/empty to skip domain caps.</param>
    /// <param name="count">Messages to reserve (usually 1 per recipient delivery).</param>
    public SendingDecision TryReserve(Guid tenantId, string? sendingDomain, int count = 1)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(count, 1);
        DateTimeOffset now = _clock.UtcNow;
        string? domain = string.IsNullOrEmpty(sendingDomain) ? null : NormalizeDomain(sendingDomain);
        var buffer = new ReservationBuffer();
        Span<CounterReservation> reservations = buffer;
        int n = Build(reservations, tenantId, domain, count, now, out bool warmupDaily);
        MaybePrune(now);

        if (_store.TryReserve(reservations[..n], out _))
        {
            return new SendingDecision(SendingDecisionKind.Allowed, now, null, null, null, null);
        }

        // Find the first scope that cannot take the request; report that one (deterministic order: global, tenant, domain; hour before day).
        for (int i = 0; i < n; i++)
        {
            CounterReservation r = reservations[i];
            long used = _store.GetCount(r.Key);
            if (r.Limit == Unbounded || used + r.Amount <= r.Limit)
            {
                continue;
            }

            CounterScope scope = r.Key.Scope;
            CounterWindow window = r.Key.Window;
            bool warmupCapped = warmupDaily && scope == CounterScope.SendingDomain && window == CounterWindow.Day;
            if (r.Amount > r.Limit && !warmupCapped)
            {
                return new SendingDecision(SendingDecisionKind.Rejected, now, null, Describe(scope, window, hard: true), scope, window);
            }

            return new SendingDecision(SendingDecisionKind.Deferred, now, WindowEnd(now, window), Describe(scope, window, hard: false), scope, window);
        }

        // Capacity was released between the failed reservation and the diagnosis: ask the caller to try again shortly.
        return new SendingDecision(SendingDecisionKind.Deferred, now, now.AddSeconds(1), "contention on sending counters", null, null);
    }

    /// <summary>Gives back a reservation made at <paramref name="reservedAt"/> (the <see cref="SendingDecision.At"/> value), for example when the delivery was cancelled before sending.</summary>
    public void Release(Guid tenantId, string? sendingDomain, int count, DateTimeOffset reservedAt)
    {
        string? domain = string.IsNullOrEmpty(sendingDomain) ? null : NormalizeDomain(sendingDomain);
        var buffer = new ReservationBuffer();
        Span<CounterReservation> reservations = buffer;
        int n = Build(reservations, tenantId, domain, count, reservedAt, out _);
        _store.Release(reservations[..n]);
    }

    /// <summary>Current usage and limits for the dashboard.</summary>
    public IReadOnlyList<SendingUsage> GetUsage(Guid tenantId, string? sendingDomain)
    {
        DateTimeOffset now = _clock.UtcNow;
        string? domain = string.IsNullOrEmpty(sendingDomain) ? null : NormalizeDomain(sendingDomain);
        var buffer = new ReservationBuffer();
        Span<CounterReservation> reservations = buffer;
        int n = Build(reservations, tenantId, domain, 1, now, out bool warmupDaily);
        var list = new List<SendingUsage>(n);
        for (int i = 0; i < n; i++)
        {
            CounterReservation r = reservations[i];
            list.Add(new SendingUsage(
                r.Key.Scope,
                r.Key.Window,
                _store.GetCount(r.Key),
                r.Limit == Unbounded ? null : r.Limit,
                warmupDaily && r.Key.Scope == CounterScope.SendingDomain && r.Key.Window == CounterWindow.Day));
        }

        return list;
    }

    private int Build(Span<CounterReservation> into, Guid tenantId, string? domain, int count, DateTimeOffset now, out bool warmupDaily)
    {
        warmupDaily = false;
        long hour = now.ToUnixTimeSeconds() / 3600;
        long day = now.ToUnixTimeSeconds() / 86400;

        LimitSet global = _options.Global;
        LimitSet tenant = _tenantLimits.TryGetValue(tenantId, out LimitSet t) ? t : _options.DefaultTenant;
        int n = 0;
        into[n++] = new CounterReservation(new CounterKey(CounterScope.Global, Guid.Empty, null, CounterWindow.Hour, hour), count, global.PerHour ?? Unbounded);
        into[n++] = new CounterReservation(new CounterKey(CounterScope.Global, Guid.Empty, null, CounterWindow.Day, day), count, global.PerDay ?? Unbounded);
        into[n++] = new CounterReservation(new CounterKey(CounterScope.Tenant, tenantId, null, CounterWindow.Hour, hour), count, tenant.PerHour ?? Unbounded);
        into[n++] = new CounterReservation(new CounterKey(CounterScope.Tenant, tenantId, null, CounterWindow.Day, day), count, tenant.PerDay ?? Unbounded);
        if (domain is not null)
        {
            LimitSet d = _domainLimits.TryGetValue(domain, out LimitSet dl) ? dl : _options.DefaultSendingDomain;
            long? dayLimit = d.PerDay;
            if (_warmups.TryGetValue(domain, out var warmup) && warmup.Schedule.GetDailyCap(warmup.Start, DateOnly.FromDateTime(now.UtcDateTime)) is { } cap
                && (dayLimit is null || cap < dayLimit))
            {
                dayLimit = cap;
                warmupDaily = true;
            }

            into[n++] = new CounterReservation(new CounterKey(CounterScope.SendingDomain, Guid.Empty, domain, CounterWindow.Hour, hour), count, d.PerHour ?? Unbounded);
            into[n++] = new CounterReservation(new CounterKey(CounterScope.SendingDomain, Guid.Empty, domain, CounterWindow.Day, day), count, dayLimit ?? Unbounded);
        }

        return n;
    }

    private void MaybePrune(DateTimeOffset now)
    {
        long hour = now.ToUnixTimeSeconds() / 3600;
        long last = Interlocked.Read(ref _lastPrunedHour);
        if (hour > last && Interlocked.CompareExchange(ref _lastPrunedHour, hour, last) == last)
        {
            _store.Prune(hour, now.ToUnixTimeSeconds() / 86400);
        }
    }

    private static DateTimeOffset WindowEnd(DateTimeOffset now, CounterWindow window)
    {
        long seconds = now.ToUnixTimeSeconds();
        long length = window == CounterWindow.Hour ? 3600 : 86400;
        return DateTimeOffset.FromUnixTimeSeconds((seconds / length + 1) * length);
    }

    private static string Describe(CounterScope scope, CounterWindow window, bool hard) => (scope, window, hard) switch
    {
        (CounterScope.Global, CounterWindow.Hour, false) => "global hourly limit reached",
        (CounterScope.Global, CounterWindow.Day, false) => "global daily limit reached",
        (CounterScope.Tenant, CounterWindow.Hour, false) => "tenant hourly limit reached",
        (CounterScope.Tenant, CounterWindow.Day, false) => "tenant daily limit reached",
        (CounterScope.SendingDomain, CounterWindow.Hour, false) => "sending domain hourly limit reached",
        (CounterScope.SendingDomain, CounterWindow.Day, false) => "sending domain daily limit or warm-up cap reached",
        (CounterScope.Global, _, true) => "global limit is zero or smaller than the request",
        (CounterScope.Tenant, _, true) => "tenant limit is zero or smaller than the request",
        _ => "sending domain limit is zero or smaller than the request",
    };

    private static string NormalizeDomain(string domain) => domain.Trim().TrimEnd('.').ToLowerInvariant();
}
