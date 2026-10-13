using System.Collections.Concurrent;

namespace Mta.Policy;

/// <summary>What a sending counter is scoped to.</summary>
public enum CounterScope : byte
{
    /// <summary>The whole installation.</summary>
    Global = 0,

    /// <summary>One tenant.</summary>
    Tenant,

    /// <summary>One sending domain.</summary>
    SendingDomain,
}

/// <summary>Length of a counter window. Windows are aligned to UTC (hour boundaries and UTC midnight).</summary>
public enum CounterWindow : byte
{
    /// <summary>A UTC clock hour.</summary>
    Hour = 0,

    /// <summary>A UTC calendar day.</summary>
    Day,
}

/// <summary>Identifies one counter in one window. A new window has a new <see cref="WindowIndex"/>, so rollover needs no reset.</summary>
/// <param name="Scope">Scope of the counter.</param>
/// <param name="TenantId">Tenant id for <see cref="CounterScope.Tenant"/>, otherwise <see cref="Guid.Empty"/>.</param>
/// <param name="Domain">Lower-case sending domain for <see cref="CounterScope.SendingDomain"/>, otherwise null.</param>
/// <param name="Window">Window length.</param>
/// <param name="WindowIndex">Hours (or days) since the Unix epoch.</param>
public readonly record struct CounterKey(CounterScope Scope, Guid TenantId, string? Domain, CounterWindow Window, long WindowIndex);

/// <summary>A request to add <paramref name="Amount"/> to a counter provided the result stays at or below <paramref name="Limit"/>.</summary>
public readonly record struct CounterReservation(CounterKey Key, long Amount, long Limit);

/// <summary>
/// Storage for sending counters. The in-memory implementation is <see cref="InMemorySendingCounterStore"/>; a persistent one
/// (for restarts or multiple nodes) implements the same contract later. Implementations must be thread-safe.
/// </summary>
public interface ISendingCounterStore
{
    /// <summary>
    /// Adds every reservation's amount to its counter if and only if every counter stays within its limit (all or nothing).
    /// Concurrent callers must never push a counter past its limit. On failure <paramref name="failedIndex"/> is the index of a reservation that did not fit.
    /// </summary>
    bool TryReserve(ReadOnlySpan<CounterReservation> reservations, out int failedIndex);

    /// <summary>Gives amounts back (for example when a delivery was not made after all). Counters never drop below zero.</summary>
    void Release(ReadOnlySpan<CounterReservation> reservations);

    /// <summary>The current value of a counter (zero if unknown).</summary>
    long GetCount(in CounterKey key);

    /// <summary>Forgets windows older than the previous hour/day. Returns the number of counters removed.</summary>
    int Prune(long currentHourIndex, long currentDayIndex);
}

/// <summary>
/// Lock-free in-memory <see cref="ISendingCounterStore"/>. A reservation adds to every counter with <see cref="Interlocked"/> and rolls back
/// if any counter overshoots; counters therefore never stay above their limit. A concurrent caller can briefly observe an inflated value
/// and be refused although it would have fitted; that errs on the side of deferring, never of exceeding a limit.
/// </summary>
public sealed class InMemorySendingCounterStore : ISendingCounterStore
{
    private sealed class Counter
    {
        public long Value;

        /// <summary>The part of <see cref="Value"/> that the persistent copy already holds (only the flushing thread touches it).</summary>
        public long Flushed;
    }

    private readonly ConcurrentDictionary<CounterKey, Counter> _counters = new();

    /// <summary>The number of counters currently held.</summary>
    public int CounterCount => _counters.Count;

    /// <inheritdoc />
    public bool TryReserve(ReadOnlySpan<CounterReservation> reservations, out int failedIndex)
    {
        for (int i = 0; i < reservations.Length; i++)
        {
            ref readonly CounterReservation r = ref reservations[i];
            Counter counter = _counters.GetOrAdd(r.Key, static _ => new Counter());
            long updated = Interlocked.Add(ref counter.Value, r.Amount);
            if (updated > r.Limit)
            {
                Interlocked.Add(ref counter.Value, -r.Amount);
                for (int j = 0; j < i; j++)
                {
                    ref readonly CounterReservation done = ref reservations[j];
                    if (_counters.TryGetValue(done.Key, out Counter? c))
                    {
                        Interlocked.Add(ref c.Value, -done.Amount);
                    }
                }

                failedIndex = i;
                return false;
            }
        }

        failedIndex = -1;
        return true;
    }

    /// <inheritdoc />
    public void Release(ReadOnlySpan<CounterReservation> reservations)
    {
        foreach (ref readonly CounterReservation r in reservations)
        {
            if (!_counters.TryGetValue(r.Key, out Counter? counter))
            {
                continue;
            }

            long current;
            long next;
            do
            {
                current = Volatile.Read(ref counter.Value);
                next = Math.Max(0, current - r.Amount);
            }
            while (Interlocked.CompareExchange(ref counter.Value, next, current) != current);
        }
    }

    /// <inheritdoc />
    public long GetCount(in CounterKey key) => _counters.TryGetValue(key, out Counter? c) ? Volatile.Read(ref c.Value) : 0;

    /// <summary>
    /// Takes every counter's change since the last call (the amount to add to the persistent copy) and marks it as flushed. Call <see cref="Unflush"/> with the same list when the
    /// write failed. Only one thread may use this and <see cref="Absorb"/> at a time (the flush loop).
    /// </summary>
    internal int TakeUnflushed(List<(CounterKey Key, long Delta)> into)
    {
        int n = 0;
        foreach (var kv in _counters)
        {
            long value = Volatile.Read(ref kv.Value.Value);
            long delta = value - kv.Value.Flushed;
            if (delta != 0)
            {
                into.Add((kv.Key, delta));
                kv.Value.Flushed = value;
                n++;
            }
        }

        return n;
    }

    /// <summary>Gives back what <see cref="TakeUnflushed"/> took (the write failed), so the next flush sends it again.</summary>
    internal void Unflush(IEnumerable<(CounterKey Key, long Delta)> taken)
    {
        foreach ((CounterKey key, long delta) in taken)
        {
            if (_counters.TryGetValue(key, out Counter? counter))
            {
                counter.Flushed -= delta;
            }
        }
    }

    /// <summary>
    /// Moves a counter to include what the persistent copy holds beyond what this process already knows of it: at start (the current window as it was before the restart) and after each
    /// flush (what other replicas added). The part this process has not flushed yet stays on top. A persistent value below what is known lowers the counter (another replica posted a
    /// reservation it later gave back, for example a rolled-back multi-counter reservation that was flushed in between), but never below zero.
    /// </summary>
    internal void Absorb(in CounterKey key, long persistedTotal)
    {
        Counter counter = _counters.GetOrAdd(key, static _ => new Counter());
        long extra = persistedTotal - counter.Flushed;
        if (extra == 0)
        {
            return;
        }

        long current;
        long next;
        do
        {
            current = Volatile.Read(ref counter.Value);
            next = Math.Max(0, current + extra);
        }
        while (Interlocked.CompareExchange(ref counter.Value, next, current) != current);
        counter.Flushed += next - current;   // what was really applied (a downward correction is clamped at zero)
    }

    /// <inheritdoc />
    public int Prune(long currentHourIndex, long currentDayIndex)
    {
        int removed = 0;
        foreach (var kv in _counters)
        {
            CounterKey k = kv.Key;
            bool stale = k.Window == CounterWindow.Hour ? k.WindowIndex < currentHourIndex - 1 : k.WindowIndex < currentDayIndex - 1;
            if (stale && _counters.TryRemove(kv))
            {
                removed++;
            }
        }

        return removed;
    }
}
