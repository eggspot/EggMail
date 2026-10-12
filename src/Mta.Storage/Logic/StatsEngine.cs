using System.Collections.Concurrent;

namespace Mta.Storage.Logic;

/// <summary>Counter values for one statistic series, indexed by <see cref="StatCounter"/>.</summary>
public readonly record struct StatDelta(StatKey Key, long[] Counts)
{
    public const int CounterCount = 9;

    public long Total()
    {
        long sum = 0;
        foreach (long c in Counts)
        {
            sum += c;
        }

        return sum;
    }
}

/// <summary>
/// Concurrent in-memory statistics buffer shared by every backend (design §4.5). <see cref="Add"/> takes no lock on the
/// common path (one dictionary lookup and an <see cref="Interlocked"/> add); <see cref="Drain"/> takes the values with
/// an atomic exchange so no increment is lost while a flush runs.
/// </summary>
public sealed class StatsAggregator
{
    public const string OtherDomain = "other";

    private readonly ConcurrentDictionary<StatKey, long[]> _series = new();
    private readonly ConcurrentQueue<RecentEvent> _recent = new();
    private readonly int _seriesSoftCap;
    private readonly int _recentMax;
    private int _recentCount;

    public StatsAggregator(RetentionOptions retention, HistoryOptions history)
    {
        // Memory guard against a cardinality flood between two flushes; the exact cap is applied by StatsBucketer.
        _seriesSoftCap = Math.Max(1024, retention.MaxSeriesPerHour * 4);
        _recentMax = Math.Max(0, history.RecentEvents);
    }

    public void Add(in StatKey key, StatCounter counter, long count = 1)
    {
        int index = (int)counter;
        if ((uint)index >= StatDelta.CounterCount)
        {
            throw new ArgumentOutOfRangeException(nameof(counter));
        }

        StatKey k = key;
        if (StorageTime.HourStart(k.HourStart) != k.HourStart || k.SendingDomain is null)
        {
            k = k with { HourStart = StorageTime.HourStart(k.HourStart), SendingDomain = k.SendingDomain ?? "" };
        }

        if (!_series.TryGetValue(k, out long[]? counts))
        {
            if (_series.Count >= _seriesSoftCap && k.RecipientDomain != OtherDomain)
            {
                k = k with { RecipientDomain = OtherDomain };
            }

            counts = _series.GetOrAdd(k, static _ => new long[StatDelta.CounterCount]);
        }

        Interlocked.Add(ref counts[index], count);
    }

    public void AddRecent(RecentEvent recentEvent)
    {
        if (_recentMax == 0)
        {
            return;
        }

        _recent.Enqueue(recentEvent);
        if (Interlocked.Increment(ref _recentCount) > _recentMax * 2 && _recent.TryDequeue(out _))
        {
            Interlocked.Decrement(ref _recentCount);
        }
    }

    /// <summary>Takes the pending deltas. Series idle for more than a few hours are forgotten.</summary>
    public List<StatDelta> Drain(DateTimeOffset now)
    {
        var result = new List<StatDelta>();
        DateTimeOffset forgetBefore = StorageTime.HourStart(now).AddHours(-3);
        foreach (var pair in _series)
        {
            long[] taken = new long[StatDelta.CounterCount];
            bool any = false;
            for (int i = 0; i < taken.Length; i++)
            {
                long v = Interlocked.Exchange(ref pair.Value[i], 0);
                taken[i] = v;
                any |= v != 0;
            }

            if (any)
            {
                result.Add(new StatDelta(pair.Key, taken));
            }
            else if (pair.Key.HourStart < forgetBefore)
            {
                _series.TryRemove(pair);
            }
        }

        return result;
    }

    /// <summary>Puts deltas back after a failed flush so they are retried by the next one.</summary>
    public void Restore(IEnumerable<StatDelta> deltas)
    {
        foreach (var d in deltas)
        {
            for (int i = 0; i < d.Counts.Length; i++)
            {
                if (d.Counts[i] != 0)
                {
                    Add(d.Key, (StatCounter)i, d.Counts[i]);
                }
            }
        }
    }

    public List<RecentEvent> DrainRecent()
    {
        var list = new List<RecentEvent>();
        while (_recent.TryDequeue(out var e))
        {
            Interlocked.Decrement(ref _recentCount);
            list.Add(e);
        }

        return list;
    }

    public void RestoreRecent(IEnumerable<RecentEvent> events)
    {
        foreach (var e in events)
        {
            AddRecent(e);
        }
    }
}

/// <summary>
/// Applies the recipient-domain top-N and the per-hour series cap when deltas are written (design §4.5): within one
/// (hour, tenant, sending domain) group the first <c>TopN</c> recipient domains seen get their own series, ranked by
/// volume inside a flush; the rest are bucketed as "other". Once an hour holds <c>MaxSeriesPerHour</c> series, new
/// domains also go to "other". The ranking is approximate across flushes of the same hour and exact for days, where the
/// rollup re-ranks by real volume.
/// </summary>
public sealed class StatsBucketer
{
    private readonly int _topN;
    private readonly int _maxSeries;
    private readonly Func<DateTimeOffset, IEnumerable<(Guid Tenant, string Sending, string Recipient)>> _loadHour;
    private readonly Dictionary<DateTimeOffset, HourState> _hours = [];

    public StatsBucketer(RetentionOptions retention, Func<DateTimeOffset, IEnumerable<(Guid Tenant, string Sending, string Recipient)>> loadExistingSeries)
    {
        _topN = retention.RecipientDomainTopNHourly;
        _maxSeries = retention.MaxSeriesPerHour;
        _loadHour = loadExistingSeries;
    }

    private sealed class HourState
    {
        public readonly Dictionary<(Guid, string), HashSet<string>> Groups = [];
        public int Series;
    }

    /// <summary>Forget cached series (after a failed write the cache may be ahead of the store).</summary>
    public void Reset() => _hours.Clear();

    public List<StatDelta> Apply(List<StatDelta> deltas)
    {
        var merged = new Dictionary<StatKey, long[]>();
        foreach (var hourGroup in deltas.GroupBy(d => d.Key.HourStart).OrderBy(g => g.Key))
        {
            HourState hour = GetHour(hourGroup.Key);

            // Bigger series first so they win the limited slots.
            foreach (StatDelta d in hourGroup.OrderByDescending(x => x.Total()).ThenBy(x => x.Key.RecipientDomain, StringComparer.Ordinal))
            {
                var groupKey = (d.Key.TenantId, d.Key.SendingDomain);
                if (!hour.Groups.TryGetValue(groupKey, out var domains))
                {
                    hour.Groups[groupKey] = domains = [];
                }

                string domain = d.Key.RecipientDomain;
                if (domain != StatsAggregator.OtherDomain && !domains.Contains(domain))
                {
                    int named = domains.Count - (domains.Contains(StatsAggregator.OtherDomain) ? 1 : 0);
                    if (named < _topN && hour.Series < _maxSeries)
                    {
                        domains.Add(domain);
                        hour.Series++;
                    }
                    else
                    {
                        domain = StatsAggregator.OtherDomain;
                    }
                }

                if (domain == StatsAggregator.OtherDomain && domains.Add(domain))
                {
                    hour.Series++;
                }

                StatKey finalKey = domain == d.Key.RecipientDomain ? d.Key : d.Key with { RecipientDomain = domain };
                if (merged.TryGetValue(finalKey, out long[]? sum))
                {
                    for (int i = 0; i < sum.Length; i++)
                    {
                        sum[i] += d.Counts[i];
                    }
                }
                else
                {
                    merged[finalKey] = (long[])d.Counts.Clone();
                }
            }
        }

        if (_hours.Count > 0)
        {
            DateTimeOffset newest = _hours.Keys.Max();
            foreach (var old in _hours.Keys.Where(h => h < newest.AddHours(-2)).ToList())
            {
                _hours.Remove(old);
            }
        }

        return merged.Select(kv => new StatDelta(kv.Key, kv.Value)).ToList();
    }

    private HourState GetHour(DateTimeOffset hour)
    {
        if (_hours.TryGetValue(hour, out var state))
        {
            return state;
        }

        state = new HourState();
        foreach (var (tenant, sending, recipient) in _loadHour(hour))
        {
            if (!state.Groups.TryGetValue((tenant, sending), out var set))
            {
                state.Groups[(tenant, sending)] = set = [];
            }

            if (set.Add(recipient))
            {
                state.Series++;
            }
        }

        _hours[hour] = state;
        return state;
    }
}

/// <summary>Rollup and retention arithmetic shared by every backend.</summary>
public static class StatsRollup
{
    /// <summary>
    /// Completed days to roll up: a day is complete one hour after it ends (late flushes still land in its last hour).
    /// Returns an empty range when nothing is due.
    /// </summary>
    public static (int First, int Last) DaysToRoll(DateTimeOffset now, int? watermarkDay, int? firstHourlyDay)
    {
        int last = StorageTime.DayNumber(now.AddHours(-1)) - 1;
        int first = watermarkDay is { } w ? w + 1 : firstHourlyDay ?? (last + 1);
        return (first, last);
    }

    /// <summary>
    /// Rolls one day of hourly rows into daily rows: sums the series, ranks the recipient domains of each
    /// (tenant, sending domain) group by total volume (ties by name) and folds everything past <paramref name="topN"/>
    /// (and any pre-existing "other") into "other".
    /// </summary>
    public static List<StatRow> RollUpDay(IEnumerable<StatRow> hourlyRows, DateTimeOffset dayStart, int topN)
    {
        var sums = new Dictionary<(Guid, string, string), long[]>();
        foreach (var r in hourlyRows)
        {
            var key = (r.TenantId, r.SendingDomain, r.RecipientDomain);
            if (!sums.TryGetValue(key, out long[]? counts))
            {
                sums[key] = counts = new long[StatDelta.CounterCount];
            }

            Accumulate(counts, r);
        }

        var result = new Dictionary<(Guid, string, string), long[]>();
        foreach (var group in sums.GroupBy(kv => (kv.Key.Item1, kv.Key.Item2)))
        {
            var ranked = group.Where(kv => kv.Key.Item3 != StatsAggregator.OtherDomain)
                .OrderByDescending(kv => kv.Value.Sum())
                .ThenBy(kv => kv.Key.Item3, StringComparer.Ordinal)
                .ToList();
            var keep = ranked.Take(topN).Select(kv => kv.Key.Item3).ToHashSet(StringComparer.Ordinal);
            foreach (var kv in group)
            {
                string domain = keep.Contains(kv.Key.Item3) ? kv.Key.Item3 : StatsAggregator.OtherDomain;
                var outKey = (kv.Key.Item1, kv.Key.Item2, domain);
                if (!result.TryGetValue(outKey, out long[]? acc))
                {
                    result[outKey] = acc = new long[StatDelta.CounterCount];
                }

                for (int i = 0; i < acc.Length; i++)
                {
                    acc[i] += kv.Value[i];
                }
            }
        }

        return result.Select(kv => ToRow(dayStart, true, kv.Key.Item1, kv.Key.Item2, kv.Key.Item3, kv.Value)).ToList();
    }

    public static void Accumulate(long[] counts, StatRow r)
    {
        counts[(int)StatCounter.Accepted] += r.Accepted;
        counts[(int)StatCounter.Delivered] += r.Delivered;
        counts[(int)StatCounter.Deferred] += r.Deferred;
        counts[(int)StatCounter.HardBounce] += r.HardBounce;
        counts[(int)StatCounter.SoftBounce] += r.SoftBounce;
        counts[(int)StatCounter.Expired] += r.Expired;
        counts[(int)StatCounter.Complained] += r.Complained;
        counts[(int)StatCounter.Rejected] += r.Rejected;
        counts[(int)StatCounter.Suppressed] += r.Suppressed;
    }

    public static StatRow ToRow(DateTimeOffset period, bool daily, Guid tenant, string sending, string recipient, long[] c) => new()
    {
        PeriodStart = period,
        Daily = daily,
        TenantId = tenant,
        SendingDomain = sending,
        RecipientDomain = recipient,
        Accepted = c[(int)StatCounter.Accepted],
        Delivered = c[(int)StatCounter.Delivered],
        Deferred = c[(int)StatCounter.Deferred],
        HardBounce = c[(int)StatCounter.HardBounce],
        SoftBounce = c[(int)StatCounter.SoftBounce],
        Expired = c[(int)StatCounter.Expired],
        Complained = c[(int)StatCounter.Complained],
        Rejected = c[(int)StatCounter.Rejected],
        Suppressed = c[(int)StatCounter.Suppressed],
    };
}

/// <summary>Cutoff arithmetic for retention (0 = keep forever, decision 28).</summary>
public static class RetentionCutoffs
{
    /// <summary>History rows with a day key below the result are deleted; null when retention is unlimited.</summary>
    public static int? DayKeyCutoff(DateTimeOffset now, int days) => days <= 0 ? null : StorageTime.DayNumber(now.AddDays(-days));

    /// <summary>Instants before the result are expired; null when retention is unlimited.</summary>
    public static DateTimeOffset? InstantCutoff(DateTimeOffset now, int days) => days <= 0 ? null : StorageTime.Normalize(now.AddDays(-days));

    /// <summary>Statistic rows with a period start before the result are deleted (aligned to a UTC day).</summary>
    public static DateTimeOffset? StatsCutoff(DateTimeOffset now, int days) => days <= 0 ? null : StorageTime.DayStart(now.AddDays(-days));
}
