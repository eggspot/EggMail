using Mta.Core;

namespace Mta.Storage.Tests;

/// <summary>Counters, flushing, top-N and series cap, rollup, retention and the recent-events ring.</summary>
public abstract class StatsConformance : StorageTestBase
{
    private static DateTimeOffset Hour(int day, int hour) => new(2026, 10, day, hour, 0, 0, TimeSpan.Zero);

    private void Add(DateTimeOffset hour, string recipientDomain, StatCounter counter, long count, Guid? tenant = null, string sending = "s.example") =>
        Storage.Stats.Add(new StatKey(hour, tenant ?? TenantA, sending, recipientDomain), counter, count);

    private async Task<IReadOnlyList<StatRow>> Hourly(DateTimeOffset from, DateTimeOffset to, Guid? tenant = null) =>
        await Storage.Stats.QueryAsync(tenant, from, to, daily: false, CancellationToken.None);

    private async Task<IReadOnlyList<StatRow>> Daily(DateTimeOffset from, DateTimeOffset to, Guid? tenant = null) =>
        await Storage.Stats.QueryAsync(tenant, from, to, daily: true, CancellationToken.None);

    [Fact]
    public async Task Counters_are_added_flushed_and_queried_by_hour_range_and_tenant()
    {
        Add(Hour(12, 9), "a.example", StatCounter.Accepted, 5);
        Add(Hour(12, 9), "a.example", StatCounter.Delivered, 3);
        Add(Hour(12, 9), "a.example", StatCounter.Deferred, 2);
        Add(Hour(12, 9), "a.example", StatCounter.HardBounce, 1);
        Add(Hour(12, 9), "a.example", StatCounter.SoftBounce, 1);
        Add(Hour(12, 9), "a.example", StatCounter.Expired, 1);
        Add(Hour(12, 9), "a.example", StatCounter.Complained, 1);
        Add(Hour(12, 9), "a.example", StatCounter.Rejected, 4);
        Add(Hour(12, 9), "a.example", StatCounter.Suppressed, 6);
        Add(Hour(12, 10), "a.example", StatCounter.Accepted, 7);
        Add(Hour(12, 10), "a.example", StatCounter.Accepted, 8, tenant: TenantB);
        await FlushStatsAsync();

        var all = await Hourly(Hour(12, 0), Hour(13, 0));
        Assert.Equal(3, all.Count);

        var nine = (await Hourly(Hour(12, 9), Hour(12, 10), TenantA)).Single();
        Assert.Equal(Hour(12, 9), nine.PeriodStart);
        Assert.False(nine.Daily);
        Assert.Equal(TenantA, nine.TenantId);
        Assert.Equal("s.example", nine.SendingDomain);
        Assert.Equal("a.example", nine.RecipientDomain);
        Assert.Equal((5, 3, 2, 1, 1, 1, 1, 4, 6), (nine.Accepted, nine.Delivered, nine.Deferred, nine.HardBounce, nine.SoftBounce, nine.Expired, nine.Complained, nine.Rejected, nine.Suppressed));

        Assert.Equal(7, (await Hourly(Hour(12, 10), Hour(12, 11), TenantA)).Single().Accepted);
        Assert.Equal(8, (await Hourly(Hour(12, 10), Hour(12, 11), TenantB)).Single().Accepted);
        Assert.Empty(await Hourly(Hour(12, 11), Hour(12, 12)));
        Assert.Empty(await Daily(Hour(12, 0), Hour(13, 0)));
    }

    [Fact]
    public async Task Counters_accumulate_across_flushes()
    {
        Add(Hour(12, 9), "a.example", StatCounter.Delivered, 2);
        await FlushStatsAsync();
        Add(Hour(12, 9), "a.example", StatCounter.Delivered, 3);
        Add(Hour(12, 9), "a.example", StatCounter.Accepted, 1);
        await FlushStatsAsync();
        await FlushStatsAsync();

        var row = (await Hourly(Hour(12, 0), Hour(13, 0))).Single();
        Assert.Equal(5, row.Delivered);
        Assert.Equal(1, row.Accepted);
    }

    [Fact]
    public async Task A_key_inside_an_hour_is_counted_in_that_hour()
    {
        Storage.Stats.Add(new StatKey(new DateTimeOffset(2026, 10, 12, 9, 37, 12, TimeSpan.Zero), TenantA, "s.example", "a.example"), StatCounter.Accepted, 1);
        Storage.Stats.Add(new StatKey(Hour(12, 9), TenantA, "s.example", "a.example"), StatCounter.Accepted, 1);
        await FlushStatsAsync();
        var row = (await Hourly(Hour(12, 0), Hour(13, 0))).Single();
        Assert.Equal(Hour(12, 9), row.PeriodStart);
        Assert.Equal(2, row.Accepted);
    }

    [Fact]
    public async Task Concurrent_adds_lose_nothing()
    {
        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
        {
            for (int i = 0; i < 5000; i++)
            {
                Add(Hour(12, 9), "a.example", StatCounter.Accepted, 1);
                Add(Hour(12, 9), "b.example", StatCounter.Delivered, 2);
            }
        })));
        await FlushStatsAsync();

        var rows = await Hourly(Hour(12, 0), Hour(13, 0));
        Assert.Equal(40_000, rows.Single(r => r.RecipientDomain == "a.example").Accepted);
        Assert.Equal(80_000, rows.Single(r => r.RecipientDomain == "b.example").Delivered);
    }

    [Fact]
    public async Task Concurrent_adds_and_flushes_lose_nothing()
    {
        using var cts = new CancellationTokenSource();
        var flusher = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                await FlushStatsAsync();
                await Task.Delay(1);
            }
        });
        await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
        {
            for (int i = 0; i < 5000; i++)
            {
                Add(Hour(12, 9), "a.example", StatCounter.Accepted, 1);
            }
        })));
        cts.Cancel();
        await flusher;
        await FlushStatsAsync();

        Assert.Equal(20_000, (await Hourly(Hour(12, 0), Hour(13, 0))).Single().Accepted);
    }

    [Fact]
    public async Task Recipient_domains_beyond_the_top_n_are_bucketed_as_other()
    {
        await OpenAsync(Opts(retention: new RetentionOptions { RecipientDomainTopNHourly = 3 }));
        (string Domain, long Count)[] volumes = [("d1.example", 100), ("d2.example", 90), ("d3.example", 80), ("d4.example", 10), ("d5.example", 5), ("d6.example", 1)];
        foreach (var (domain, count) in volumes)
        {
            Add(Hour(12, 9), domain, StatCounter.Accepted, count);
        }

        await FlushStatsAsync();
        var rows = await Hourly(Hour(12, 0), Hour(13, 0));

        Assert.Equal(4, rows.Count);
        Assert.Equal(["d1.example", "d2.example", "d3.example", "other"], rows.Select(r => r.RecipientDomain).Order(StringComparer.Ordinal));
        Assert.Equal(16, rows.Single(r => r.RecipientDomain == "other").Accepted);
        Assert.Equal(286, rows.Sum(r => r.Accepted));
    }

    [Fact]
    public async Task Top_n_is_applied_per_sending_domain_and_tenant()
    {
        await OpenAsync(Opts(retention: new RetentionOptions { RecipientDomainTopNHourly = 1 }));
        Add(Hour(12, 9), "x.example", StatCounter.Accepted, 5, TenantA, "s1.example");
        Add(Hour(12, 9), "y.example", StatCounter.Accepted, 2, TenantA, "s1.example");
        Add(Hour(12, 9), "x.example", StatCounter.Accepted, 5, TenantA, "s2.example");
        Add(Hour(12, 9), "y.example", StatCounter.Accepted, 2, TenantB, "s1.example");
        await FlushStatsAsync();

        var rows = await Hourly(Hour(12, 0), Hour(13, 0));
        Assert.Equal(4, rows.Count);
        Assert.Contains(rows, r => r.TenantId == TenantA && r.SendingDomain == "s1.example" && r.RecipientDomain == "x.example" && r.Accepted == 5);
        Assert.Contains(rows, r => r.TenantId == TenantA && r.SendingDomain == "s1.example" && r.RecipientDomain == "other" && r.Accepted == 2);
        Assert.Contains(rows, r => r.TenantId == TenantA && r.SendingDomain == "s2.example" && r.RecipientDomain == "x.example");
        Assert.Contains(rows, r => r.TenantId == TenantB && r.RecipientDomain == "y.example" && r.Accepted == 2);
    }

    [Fact]
    public async Task A_domain_that_already_has_a_series_keeps_it_across_flushes()
    {
        await OpenAsync(Opts(retention: new RetentionOptions { RecipientDomainTopNHourly = 1 }));
        Add(Hour(12, 9), "first.example", StatCounter.Accepted, 1);
        await FlushStatsAsync();
        Add(Hour(12, 9), "second.example", StatCounter.Accepted, 50);
        Add(Hour(12, 9), "first.example", StatCounter.Accepted, 1);
        await FlushStatsAsync();

        var rows = await Hourly(Hour(12, 0), Hour(13, 0));
        Assert.Equal(2, rows.Single(r => r.RecipientDomain == "first.example").Accepted);
        Assert.Equal(50, rows.Single(r => r.RecipientDomain == "other").Accepted);
        Assert.DoesNotContain(rows, r => r.RecipientDomain == "second.example");
    }

    [Fact]
    public async Task The_series_cap_per_hour_overflows_into_other()
    {
        await OpenAsync(Opts(retention: new RetentionOptions { MaxSeriesPerHour = 5, RecipientDomainTopNHourly = 100 }));
        for (int i = 0; i < 12; i++)
        {
            Add(Hour(12, 9), $"d{i:00}.example", StatCounter.Accepted, 100 - i);
        }

        await FlushStatsAsync();
        var rows = await Hourly(Hour(12, 0), Hour(13, 0));
        Assert.Equal(5, rows.Count(r => r.RecipientDomain != "other"));
        Assert.Equal(1, rows.Count(r => r.RecipientDomain == "other"));
        Assert.Equal(Enumerable.Range(0, 12).Sum(i => 100L - i), rows.Sum(r => r.Accepted));
        Assert.All(Enumerable.Range(0, 5), i => Assert.Contains(rows, r => r.RecipientDomain == $"d{i:00}.example"));
    }

    // Rollup and retention

    private void SeedTwoDays()
    {
        // Oct 9 and Oct 10 are complete days relative to the test clock (Oct 12 12:30).
        foreach (int day in new[] { 9, 10 })
        {
            Add(Hour(day, 8), "a.example", StatCounter.Accepted, 10);
            Add(Hour(day, 9), "a.example", StatCounter.Accepted, 5);
            Add(Hour(day, 9), "a.example", StatCounter.Delivered, 4);
            Add(Hour(day, 8), "b.example", StatCounter.Accepted, 7);
            Add(Hour(day, 8), "c.example", StatCounter.Accepted, 3);
            Add(Hour(day, 9), "d.example", StatCounter.Accepted, 1);
        }

        // Today is not complete and must not be rolled up.
        Add(Hour(12, 8), "a.example", StatCounter.Accepted, 99);
    }

    [Fact]
    public async Task Completed_days_are_rolled_up_with_the_daily_top_n()
    {
        await OpenAsync(Opts(retention: new RetentionOptions { RecipientDomainTopNDaily = 2 }));
        SeedTwoDays();
        await FlushStatsAsync();

        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);

        var oct9 = await Daily(Hour(9, 0), Hour(10, 0));
        Assert.All(oct9, r => Assert.True(r.Daily));
        Assert.All(oct9, r => Assert.Equal(Hour(9, 0), r.PeriodStart));
        Assert.Equal(["a.example", "b.example", "other"], oct9.Select(r => r.RecipientDomain).Order(StringComparer.Ordinal));
        var a = oct9.Single(r => r.RecipientDomain == "a.example");
        Assert.Equal(15, a.Accepted);
        Assert.Equal(4, a.Delivered);
        Assert.Equal(7, oct9.Single(r => r.RecipientDomain == "b.example").Accepted);
        Assert.Equal(4, oct9.Single(r => r.RecipientDomain == "other").Accepted);

        Assert.Equal(3, (await Daily(Hour(10, 0), Hour(11, 0))).Count);
        Assert.Empty(await Daily(Hour(12, 0), Hour(13, 0)));
        Assert.Empty(await Daily(Hour(11, 0), Hour(12, 0)));

        // Hourly rows are untouched (default hourly retention is 30 days).
        Assert.Equal(5, (await Hourly(Hour(9, 0), Hour(10, 0))).Count);
    }

    [Fact]
    public async Task Rollup_is_idempotent_and_picks_up_new_days_later()
    {
        SeedTwoDays();
        await FlushStatsAsync();
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        var first = await Daily(Hour(9, 0), Hour(11, 0));
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        var second = await Daily(Hour(9, 0), Hour(11, 0));
        Assert.Equal(first.Select(Describe), second.Select(Describe));

        Clock.Advance(TimeSpan.FromDays(1));
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        var oct12 = await Daily(Hour(12, 0), Hour(13, 0));
        Assert.Equal(99, oct12.Single().Accepted);

        static string Describe(StatRow r) => $"{r.PeriodStart:O}|{r.TenantId}|{r.SendingDomain}|{r.RecipientDomain}|{r.Accepted}|{r.Delivered}";
    }

    [Fact]
    public async Task Expired_hourly_rows_are_deleted_after_their_day_was_rolled_up()
    {
        await OpenAsync(Opts(retention: new RetentionOptions { StatsHourlyDays = 2, StatsDailyDays = 400 }));
        SeedTwoDays();
        Add(Hour(11, 8), "a.example", StatCounter.Accepted, 1);
        await FlushStatsAsync();

        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);

        // cutoff = start of the day two days before "now" = Oct 10 00:00
        Assert.Empty(await Hourly(Hour(9, 0), Hour(10, 0)));
        Assert.NotEmpty(await Hourly(Hour(10, 0), Hour(11, 0)));
        Assert.NotEmpty(await Hourly(Hour(11, 0), Hour(12, 0)));
        Assert.NotEmpty(await Daily(Hour(9, 0), Hour(10, 0)));
    }

    [Fact]
    public async Task Expired_daily_rows_are_deleted()
    {
        await OpenAsync(Opts(retention: new RetentionOptions { StatsDailyDays = 2 }));
        SeedTwoDays();
        await FlushStatsAsync();
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        Assert.Empty(await Daily(Hour(9, 0), Hour(10, 0)));
        Assert.NotEmpty(await Daily(Hour(10, 0), Hour(11, 0)));
    }

    [Fact]
    public async Task Zero_retention_keeps_hourly_and_daily_rows_forever()
    {
        await OpenAsync(Opts(retention: new RetentionOptions { StatsHourlyDays = 0, StatsDailyDays = 0 }));
        SeedTwoDays();
        await FlushStatsAsync();
        Clock.Advance(TimeSpan.FromDays(3000));
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);

        Assert.Equal(5, (await Hourly(Hour(9, 0), Hour(10, 0))).Count);
        Assert.NotEmpty(await Daily(Hour(9, 0), Hour(10, 0)));
        Assert.NotEmpty(await Daily(Hour(10, 0), Hour(11, 0)));
    }

    [Fact]
    public async Task Negative_retention_is_rejected()
    {
        await Assert.ThrowsAnyAsync<ArgumentException>(async () => await OpenAsync(Opts(retention: new RetentionOptions { StatsHourlyDays = -1 })));
    }

    [Fact]
    public async Task Content_retention_outside_6_to_30_is_rejected()
    {
        await Assert.ThrowsAnyAsync<ArgumentException>(async () => await OpenAsync(Opts(content: new ContentOptions { RetentionDays = 5 })));
        await Assert.ThrowsAnyAsync<ArgumentException>(async () => await OpenAsync(Opts(content: new ContentOptions { RetentionDays = 31 })));
    }

    // Recent events

    [Fact]
    public async Task The_recent_events_ring_keeps_only_the_newest_events()
    {
        await OpenAsync(Opts(recentEvents: 5));
        for (int i = 0; i < 12; i++)
        {
            await AcceptAsync(Msg(to: [$"u{i}@d{i}.example"], tenant: i % 2 == 0 ? TenantA : TenantB));
        }

        foreach (var c in await ClaimAsync(max: 100))
        {
            Clock.Advance(TimeSpan.FromSeconds(1));
            await RecordAsync(c, DeliveryOutcome.Delivered);
            await FlushStatsAsync();
        }

        var all = await Storage.Stats.GetRecentEventsAsync(null, 100, CancellationToken.None);
        Assert.Equal(5, all.Count);
        Assert.Equal(all.OrderByDescending(e => e.At).Select(e => e.At), all.Select(e => e.At));
        Assert.True(all.Select(e => e.At).Distinct().Count() == 5);
        Assert.Equal(2, (await Storage.Stats.GetRecentEventsAsync(null, 2, CancellationToken.None)).Count);
        Assert.All(await Storage.Stats.GetRecentEventsAsync(TenantA, 100, CancellationToken.None), e => Assert.Equal(TenantA, e.TenantId));
    }

    [Fact]
    public async Task The_recent_events_ring_can_be_disabled()
    {
        await OpenAsync(Opts(recentEvents: 0));
        await AcceptAsync();
        await RecordAsync((await ClaimAsync()).Single(), DeliveryOutcome.Delivered);
        await FlushStatsAsync();
        Assert.Empty(await Storage.Stats.GetRecentEventsAsync(null, 100, CancellationToken.None));
    }
}
