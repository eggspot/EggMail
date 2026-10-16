using Mta.Core;
using Mta.Storage.Logic;
using Mta.TestSupport;

namespace Mta.Storage.Tests;

// Area 6: hourly and daily statistics over many virtual days: hourly to daily rollup, the daily top-N, hourly and daily retention (including 0 = unlimited and
// the 400-day default), idempotent re-runs and a maintenance gap longer than the hourly retention.

public abstract partial class LifecycleConformance
{
    private const string Sending = "s.example";
    private static readonly int[] HoursOfA = [9, 14, 22];

    private readonly record struct RowKey(DateTimeOffset Period, bool Daily, Guid Tenant, string Domain);

    private static long Weight(int domainIndex, int domains) => domains - domainIndex;

    private static long Multiplier(int day) => 1 + (day % 3);

    private static string DomainA(int index) => "d" + index;

    /// <summary>What was added on virtual day <paramref name="day"/> (0 = the first day): the hourly rows the store must hold for it.</summary>
    private static Dictionary<RowKey, (long Accepted, long Delivered)> HourlyOf(DateTimeOffset origin, int day, int domainsA)
    {
        var rows = new Dictionary<RowKey, (long, long)>();
        DateTimeOffset dayStart = StorageTime.DayStart(origin.AddDays(day));
        foreach (int hour in HoursOfA)
        {
            for (int i = 0; i < domainsA; i++)
            {
                rows[new RowKey(dayStart.AddHours(hour), false, TenantA, DomainA(i))] = (Weight(i, domainsA) * Multiplier(day), Weight(i, domainsA));
            }
        }

        rows[new RowKey(dayStart.AddHours(12), false, TenantB, "b0")] = (5, 4);
        rows[new RowKey(dayStart.AddHours(12), false, TenantB, "b1")] = (3, 2);
        return rows;
    }

    /// <summary>The daily rows of a complete day: the hourly sums, the busiest <paramref name="topN"/> recipient domains per tenant by name, everything else folded into "other".</summary>
    private static Dictionary<RowKey, (long Accepted, long Delivered)> DailyOf(DateTimeOffset origin, int day, int domainsA, int topN)
    {
        var hourly = HourlyOf(origin, day, domainsA);
        DateTimeOffset dayStart = StorageTime.DayStart(origin.AddDays(day));
        var daily = new Dictionary<RowKey, (long, long)>();
        foreach (var byTenant in hourly.GroupBy(kv => kv.Key.Tenant))
        {
            var totals = byTenant.GroupBy(kv => kv.Key.Domain).Select(g => (Domain: g.Key, Accepted: g.Sum(x => x.Value.Accepted), Delivered: g.Sum(x => x.Value.Delivered)))
                .OrderByDescending(t => t.Accepted + t.Delivered).ThenBy(t => t.Domain, StringComparer.Ordinal).ToList();
            long otherAccepted = 0;
            long otherDelivered = 0;
            for (int rank = 0; rank < totals.Count; rank++)
            {
                if (rank < topN)
                {
                    daily[new RowKey(dayStart, true, byTenant.Key, totals[rank].Domain)] = (totals[rank].Accepted, totals[rank].Delivered);
                }
                else
                {
                    otherAccepted += totals[rank].Accepted;
                    otherDelivered += totals[rank].Delivered;
                }
            }

            if (totals.Count > topN)
            {
                daily[new RowKey(dayStart, true, byTenant.Key, "other")] = (otherAccepted, otherDelivered);
            }
        }

        return daily;
    }

    private void AddDay(DateTimeOffset origin, int day, int domainsA)
    {
        foreach (var (key, value) in HourlyOf(origin, day, domainsA))
        {
            Storage.Stats.Add(new StatKey(key.Period, key.Tenant, Sending, key.Domain), StatCounter.Accepted, value.Accepted);
            Storage.Stats.Add(new StatKey(key.Period, key.Tenant, Sending, key.Domain), StatCounter.Delivered, value.Delivered);
        }
    }

    private async Task<Dictionary<RowKey, (long Accepted, long Delivered)>> ReadStatsAsync(DateTimeOffset origin, bool daily)
    {
        IReadOnlyList<StatRow> rows = await Storage.Stats.QueryAsync(null, StorageTime.DayStart(origin.AddDays(-2)), Clock.UtcNow.AddDays(2), daily, CancellationToken.None);
        var result = new Dictionary<RowKey, (long, long)>();
        foreach (StatRow r in rows)
        {
            Assert.Equal(daily, r.Daily);
            Assert.Equal(0, r.Deferred + r.HardBounce + r.SoftBounce + r.Expired + r.Complained + r.Rejected + r.Suppressed);
            Assert.Equal(Sending, r.SendingDomain);
            Assert.True(result.TryAdd(new RowKey(r.PeriodStart, r.Daily, r.TenantId, r.RecipientDomain), (r.Accepted, r.Delivered)), "a statistics row was returned twice");
        }

        return result;
    }

    private async Task CheckStatsAsync(DateTimeOffset origin, int domainsA, int hourlyDays, int dailyDays, int topN, string when)
    {
        DateTimeOffset now = Clock.UtcNow;
        int today = StorageTime.DayNumber(now);
        int originDay = StorageTime.DayNumber(origin);
        DateTimeOffset hourlyCutoff = StorageTime.DayStart(now.AddDays(-hourlyDays));
        DateTimeOffset dailyCutoff = StorageTime.DayStart(now.AddDays(-dailyDays));

        // A day is rolled up once it has been over for an hour; the hourly rows of "today" stay hourly.
        int lastComplete = StorageTime.DayNumber(now.AddHours(-1)) - 1;
        var expectedHourly = new Dictionary<RowKey, (long, long)>();
        var expectedDaily = new Dictionary<RowKey, (long, long)>();
        for (int day = 0; day <= today - originDay; day++)
        {
            DateTimeOffset dayStart = StorageTime.DayStart(origin.AddDays(day));
            if (hourlyDays <= 0 || dayStart >= hourlyCutoff)
            {
                foreach (var kv in HourlyOf(origin, day, domainsA))
                {
                    expectedHourly[kv.Key] = kv.Value;
                }
            }

            if (originDay + day <= lastComplete && (dailyDays <= 0 || dayStart >= dailyCutoff))
            {
                foreach (var kv in DailyOf(origin, day, domainsA, topN))
                {
                    expectedDaily[kv.Key] = kv.Value;
                }
            }
        }

        var hourly = await ReadStatsAsync(origin, daily: false);
        var dailyRows = await ReadStatsAsync(origin, daily: true);
        AssertSameRows(expectedHourly, hourly, "hourly " + when);
        AssertSameRows(expectedDaily, dailyRows, "daily " + when);
        await AssertCountAsync(LifecycleTable.StatsHourly, expectedHourly.Count, "hourly rows on disk " + when);
        await AssertCountAsync(LifecycleTable.StatsDaily, expectedDaily.Count, "daily rows on disk " + when);
    }

    private static void AssertSameRows(Dictionary<RowKey, (long Accepted, long Delivered)> expected, Dictionary<RowKey, (long Accepted, long Delivered)> actual, string what)
    {
        var missing = expected.Keys.Except(actual.Keys).OrderBy(k => k.Period).Take(3).ToList();
        var extra = actual.Keys.Except(expected.Keys).OrderBy(k => k.Period).Take(3).ToList();
        Assert.True(missing.Count == 0 && extra.Count == 0,
            $"{what}: expected {expected.Count} rows, found {actual.Count}; first missing {string.Join(", ", missing.Select(Describe))}; first unexpected {string.Join(", ", extra.Select(Describe))}");
        foreach (var kv in expected)
        {
            Assert.True(kv.Value == actual[kv.Key], $"{what}: {Describe(kv.Key)} expected {kv.Value} but is {actual[kv.Key]}");
        }

        static string Describe(RowKey k) => $"{k.Period:yyyy-MM-ddTHH}/{(k.Tenant == TenantA ? 'A' : 'B')}/{k.Domain}";
    }

    /// <summary>
    /// <paramref name="days"/> virtual days of statistics for two tenants. Maintenance runs every <paramref name="maintainEvery"/> days (at 12:30, so the day before is complete) and
    /// after each run every row of both granularities is compared with the model; every fifth run is repeated at once to prove the rollup is idempotent.
    /// </summary>
    private async Task RunStatsScenarioAsync(int hourlyDays, int dailyDays, int days, int maintainEvery, int domainsA, int topN)
    {
        await OpenAsync(Opts(retention: new RetentionOptions { StatsHourlyDays = hourlyDays, StatsDailyDays = dailyDays, RecipientDomainTopNDaily = topN, MetadataDays = 0, WebhookOutboxDays = 0, WebhookAttemptLogDays = 0 }));
        DateTimeOffset origin = Clock.UtcNow;
        int runs = 0;
        for (int day = 0; day < days; day++)
        {
            Clock.Set(origin.AddDays(day));
            AddDay(origin, day, domainsA);
            if ((day + 1) % maintainEvery != 0 && day != days - 1)
            {
                continue;
            }

            await MaintainAsync();
            runs++;
            await CheckStatsAsync(origin, domainsA, hourlyDays, dailyDays, topN, "after maintenance on day " + day);
            if (runs % 5 == 0)
            {
                // Idempotent: the same run again changes nothing.
                await MaintainAsync();
                await CheckStatsAsync(origin, domainsA, hourlyDays, dailyDays, topN, "after a repeated maintenance on day " + day);
            }
        }

        Assert.True(_jobRows["stats.rollup"] > 0, "stats.rollup never wrote a daily row");
        Assert.True(hourlyDays <= 0 && dailyDays <= 0 ? _jobRows["stats.retention"] == 0 : _jobRows["stats.retention"] > 0, "stats.retention: unlimited deletes nothing, a limit deletes something");
    }

    [Fact]
    public async Task Lifecycle_statistics_roll_up_daily_with_the_top_n_and_expire_hourly_then_daily()
    {
        if (!Heavy)
        {
            return;
        }

        await RunStatsScenarioAsync(hourlyDays: 10, dailyDays: 40, days: Accelerated.Scaled(55), maintainEvery: 1, domainsA: 8, topN: 3);
    }

    [Fact]
    public async Task Lifecycle_zero_statistics_retention_keeps_hourly_and_daily_rows_forever()
    {
        if (!Heavy || !IsFull)   // statistics do not depend on History:Mode: the StatsOnly variant runs only the bounded scenario
        {
            return;
        }

        await RunStatsScenarioAsync(hourlyDays: 0, dailyDays: 0, days: Accelerated.Scaled(45), maintainEvery: 3, domainsA: 6, topN: 2);
    }

    [Fact]
    public async Task Lifecycle_a_maintenance_gap_longer_than_the_hourly_retention_loses_no_daily_row()
    {
        if (!Heavy || !IsFull)   // statistics do not depend on History:Mode: the StatsOnly variant runs only the bounded scenario
        {
            return;
        }

        // Nothing ran for 60 days: one run must roll every completed day up before the hourly retention (10 days) deletes its hourly rows.
        await RunStatsScenarioAsync(hourlyDays: 10, dailyDays: 40, days: 60, maintainEvery: 60, domainsA: 5, topN: 3);
    }

    [Fact]
    public async Task Lifecycle_the_default_400_day_daily_and_30_day_hourly_retention_over_450_days()
    {
        if (!Heavy || !IsFull)   // statistics do not depend on History:Mode: the StatsOnly variant runs only the bounded scenario
        {
            return;
        }

        // The shipped defaults, maintenance every 20 days: the daily rows of the last 400 days are there, with the right totals on both sides of the cutoff, and nothing older.
        await RunStatsScenarioAsync(hourlyDays: 30, dailyDays: 400, days: 450, maintainEvery: 20, domainsA: 3, topN: 10);
        DateTimeOffset now = Clock.UtcNow;
        IReadOnlyList<StatRow> oldest = await Storage.Stats.QueryAsync(TenantB, StorageTime.DayStart(now.AddDays(-401)), StorageTime.DayStart(now.AddDays(-398)), daily: true, CancellationToken.None);
        Assert.Equal([StorageTime.DayStart(now.AddDays(-400)), StorageTime.DayStart(now.AddDays(-400)), StorageTime.DayStart(now.AddDays(-399)), StorageTime.DayStart(now.AddDays(-399))], oldest.Select(r => r.PeriodStart).Order());

        // One more day: the day that was the oldest falls off, and only that day.
        Clock.Advance(Day);
        AddDay(Start, 450, 3);
        await MaintainAsync();
        IReadOnlyList<StatRow> after = await Storage.Stats.QueryAsync(TenantB, StorageTime.DayStart(now.AddDays(-401)), StorageTime.DayStart(now.AddDays(-398)), daily: true, CancellationToken.None);
        Assert.Equal([StorageTime.DayStart(now.AddDays(-399)), StorageTime.DayStart(now.AddDays(-399))], after.Select(r => r.PeriodStart).Order());
    }

    [Fact]
    public async Task Lifecycle_the_recent_events_ring_stays_at_its_limit_while_deliveries_continue()
    {
        await OpenAsync(Opts(recentEvents: 12));
        for (int day = 0; day < 6; day++)
        {
            for (int i = 0; i < 5; i++)
            {
                await AcceptAsync(Msg(to: [$"u{day}-{i}@example.org"]));
            }

            foreach (ClaimedDelivery d in await ClaimAsync())
            {
                await RecordAsync(d, DeliveryOutcome.Delivered);
            }

            await MaintainAsync();
            IReadOnlyList<RecentEvent> ring = await Storage.Stats.GetRecentEventsAsync(null, 1000, CancellationToken.None);
            Assert.True(ring.Count <= 12, $"the ring holds {ring.Count} events");
            Assert.Equal(ring.OrderByDescending(e => e.At).Select(e => e.At), ring.Select(e => e.At));
            long? rows = await CountRowsAsync(LifecycleTable.RecentEvent);
            Assert.True(rows is null or <= 12);
            Clock.Advance(Day);
        }

        Assert.Equal(12, (await Storage.Stats.GetRecentEventsAsync(null, 1000, CancellationToken.None)).Count);
    }
}
