using Mta.Core;
using Mta.Storage;

namespace Mta.Policy;

/// <summary>
/// Keeps the sending counters behind the hourly and daily caps (and the warm-up) across restarts and replicas. The hot path is unchanged: reservations only touch the
/// in-memory <see cref="InMemorySendingCounterStore"/>. This class
/// <list type="bullet">
/// <item><see cref="LoadAsync"/> (at start, before any delivery): reads the stored totals of the current hour and day windows, so a restart does not reset the window and allow an overshoot of a cap;</item>
/// <item><see cref="FlushAsync"/> (write-behind, every few seconds, like the statistics, and at shutdown): adds what this process counted since the last flush to the stored totals
/// (a delta, so replicas add to each other and nothing is overwritten), deletes windows older than the previous hour and day, then reads the totals back and raises its own counters to
/// them, which is how a replica learns what the others sent. Between flushes each replica sees its own counts plus what the others had flushed, so with several replicas a cap
/// can be overshot by at most what the others send in one flush interval.</item>
/// </list>
/// A flush that fails (storage unavailable) keeps its delta for the next one.
/// </summary>
public sealed class SendingCounterPersistence
{
    private readonly InMemorySendingCounterStore _counters;
    private readonly IRuntimeStateStore _state;
    private readonly IClock _clock;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private long _prunedHour = long.MinValue;

    /// <summary>Creates the persistence for <paramref name="counters"/>, which must be the store of the <see cref="SendingLimits"/> it serves.</summary>
    public SendingCounterPersistence(InMemorySendingCounterStore counters, IRuntimeStateStore state, IClock clock)
    {
        _counters = counters ?? throw new ArgumentNullException(nameof(counters));
        _state = state ?? throw new ArgumentNullException(nameof(state));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
    }

    /// <summary>Loads the stored totals of the current windows into the in-memory counters.</summary>
    public async Task LoadAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await AbsorbStoredAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Writes what changed since the last flush, prunes old windows and picks up what other replicas added. Returns the number of counters written.</summary>
    public async Task<int> FlushAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            DateTimeOffset now = _clock.UtcNow;
            long hour = now.ToUnixTimeSeconds() / 3600;
            long day = now.ToUnixTimeSeconds() / 86400;
            var taken = new List<(CounterKey Key, long Delta)>();
            _counters.TakeUnflushed(taken);
            bool prune = hour != _prunedHour;
            if (taken.Count > 0 || prune)
            {
                try
                {
                    await _state.AddSendingCountersAsync(taken.Select(t => ToRecord(t.Key, t.Delta)).ToList(), hour - 1, day - 1, cancellationToken).ConfigureAwait(false);
                    _prunedHour = hour;
                }
                catch
                {
                    _counters.Unflush(taken);
                    throw;
                }
            }

            await AbsorbStoredAsync(cancellationToken).ConfigureAwait(false);
            return taken.Count;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task AbsorbStoredAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset now = _clock.UtcNow;
        long hour = now.ToUnixTimeSeconds() / 3600;
        long day = now.ToUnixTimeSeconds() / 86400;
        foreach (SendingCounterRecord stored in await _state.GetSendingCountersAsync(hour, day, cancellationToken).ConfigureAwait(false))
        {
            var key = new CounterKey((CounterScope)stored.Scope, stored.TenantId, stored.Domain.Length == 0 ? null : stored.Domain, (CounterWindow)stored.Window, stored.WindowIndex);
            _counters.Absorb(key, stored.Count);
        }
    }

    private static SendingCounterRecord ToRecord(CounterKey key, long delta) =>
        new((byte)key.Scope, key.TenantId, key.Domain ?? "", (byte)key.Window, key.WindowIndex, delta);
}
