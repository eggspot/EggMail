namespace Mta.Policy.Tests;

public class SendingLimitsTests
{
    private static readonly Guid TenantA = Guid.Parse("00000000-0000-0000-0000-00000000000a");
    private static readonly Guid TenantB = Guid.Parse("00000000-0000-0000-0000-00000000000b");

    private static (SendingLimits Limits, FakeClock Clock, InMemorySendingCounterStore Store) Create(SendingLimitsOptions? options = null, DateTimeOffset? start = null)
    {
        var clock = new FakeClock(start ?? new DateTimeOffset(2026, 10, 12, 8, 30, 0, TimeSpan.Zero));
        var store = new InMemorySendingCounterStore();
        return (new SendingLimits(clock, store, options), clock, store);
    }

    [Fact]
    public void Unlimited_by_default_but_still_counted()
    {
        var (l, _, _) = Create();
        for (int i = 0; i < 1000; i++)
        {
            Assert.True(l.TryReserve(TenantA, "example.com").IsAllowed);
        }

        var usage = l.GetUsage(TenantA, "example.com");
        Assert.Equal(6, usage.Count);
        Assert.All(usage, u => Assert.Equal(1000, u.Used));
        Assert.All(usage, u => Assert.Null(u.Limit));
    }

    [Fact]
    public void Hourly_cap_defers_until_the_next_hour_and_then_allows_again()
    {
        var (l, clock, _) = Create(new SendingLimitsOptions { DefaultTenant = new LimitSet(3, null) });
        for (int i = 0; i < 3; i++)
        {
            Assert.True(l.TryReserve(TenantA, null).IsAllowed);
        }

        var d = l.TryReserve(TenantA, null);
        Assert.Equal(SendingDecisionKind.Deferred, d.Kind);
        Assert.Equal(new DateTimeOffset(2026, 10, 12, 9, 0, 0, TimeSpan.Zero), d.DeferredUntil);
        Assert.Equal(CounterScope.Tenant, d.LimitedBy);
        Assert.Equal(CounterWindow.Hour, d.LimitedWindow);
        Assert.Equal("tenant hourly limit reached", d.Reason);

        clock.Set(d.DeferredUntil!.Value);
        Assert.True(l.TryReserve(TenantA, null).IsAllowed);
    }

    [Fact]
    public void Daily_cap_defers_until_utc_midnight()
    {
        var (l, clock, _) = Create(new SendingLimitsOptions { Global = new LimitSet(null, 2) });
        Assert.True(l.TryReserve(TenantA, null).IsAllowed);
        Assert.True(l.TryReserve(TenantB, null).IsAllowed);
        var d = l.TryReserve(TenantA, null);
        Assert.Equal(SendingDecisionKind.Deferred, d.Kind);
        Assert.Equal(CounterScope.Global, d.LimitedBy);
        Assert.Equal(new DateTimeOffset(2026, 10, 13, 0, 0, 0, TimeSpan.Zero), d.DeferredUntil);

        clock.Set(new DateTimeOffset(2026, 10, 12, 23, 59, 59, TimeSpan.Zero));
        Assert.Equal(SendingDecisionKind.Deferred, l.TryReserve(TenantA, null).Kind);
        clock.Advance(TimeSpan.FromSeconds(1)); // UTC midnight: the day rolled over
        Assert.True(l.TryReserve(TenantA, null).IsAllowed);
    }

    [Fact]
    public void Tenants_have_independent_caps()
    {
        var (l, _, _) = Create(new SendingLimitsOptions { DefaultTenant = new LimitSet(null, 2) });
        l.SetTenantLimits(TenantB, new LimitSet(null, 5));
        for (int i = 0; i < 2; i++)
        {
            Assert.True(l.TryReserve(TenantA, null).IsAllowed);
        }

        Assert.False(l.TryReserve(TenantA, null).IsAllowed);
        for (int i = 0; i < 5; i++)
        {
            Assert.True(l.TryReserve(TenantB, null).IsAllowed);
        }

        Assert.False(l.TryReserve(TenantB, null).IsAllowed);
        l.SetTenantLimits(TenantB, null); // back to the default of 2: already past it
        Assert.False(l.TryReserve(TenantB, null).IsAllowed);
    }

    [Fact]
    public void A_refused_reservation_leaves_no_trace_in_other_counters()
    {
        var (l, _, _) = Create(new SendingLimitsOptions { Global = new LimitSet(null, 1) });
        Assert.True(l.TryReserve(TenantA, "a.example").IsAllowed);
        Assert.False(l.TryReserve(TenantB, "b.example").IsAllowed);

        var usage = l.GetUsage(TenantB, "b.example");
        Assert.All(usage.Where(u => u.Scope != CounterScope.Global), u => Assert.Equal(0, u.Used));
        Assert.Equal(1, usage.Single(u => u.Scope == CounterScope.Global && u.Window == CounterWindow.Day).Used);
    }

    [Fact]
    public void Sending_domain_caps_are_separate_per_domain()
    {
        var (l, _, _) = Create(new SendingLimitsOptions { DefaultSendingDomain = new LimitSet(2, null) });
        Assert.True(l.TryReserve(TenantA, "a.example").IsAllowed);
        Assert.True(l.TryReserve(TenantA, "A.example.").IsAllowed); // normalized
        var d = l.TryReserve(TenantA, "a.example");
        Assert.Equal(CounterScope.SendingDomain, d.LimitedBy);
        Assert.True(l.TryReserve(TenantA, "b.example").IsAllowed);
        l.SetSendingDomainLimits("b.example", new LimitSet(100, null));
        for (int i = 0; i < 50; i++)
        {
            Assert.True(l.TryReserve(TenantA, "b.example").IsAllowed);
        }
    }

    [Fact]
    public void Default_warmup_ramp_matches_the_proposal()
    {
        long?[] expected = [50, 100, 200, 400, 800, 1500, 3000, 5000, 10000, 20000, 40000, null, null];
        for (int day = 0; day < expected.Length; day++)
        {
            Assert.Equal(expected[day], WarmupSchedule.Default.GetDailyCap(day));
        }

        Assert.Equal(50, WarmupSchedule.Default.GetDailyCap(-3));
        Assert.True(WarmupSchedule.Default.IsGraduated(11));
        Assert.False(WarmupSchedule.Default.IsGraduated(10));
    }

    [Fact]
    public void Warmup_caps_a_new_sending_domain_per_day_and_grows_each_day()
    {
        var (l, clock, _) = Create(start: new DateTimeOffset(2026, 10, 12, 8, 0, 0, TimeSpan.Zero));
        l.StartWarmup("new.example", new DateOnly(2026, 10, 12));
        Assert.Equal(50, l.GetWarmupCap("new.example"));

        for (int i = 0; i < 50; i++)
        {
            Assert.True(l.TryReserve(TenantA, "new.example").IsAllowed, $"message {i}");
        }

        var d = l.TryReserve(TenantA, "new.example");
        Assert.Equal(SendingDecisionKind.Deferred, d.Kind);
        Assert.Equal(CounterScope.SendingDomain, d.LimitedBy);
        Assert.Equal(CounterWindow.Day, d.LimitedWindow);
        Assert.Equal(new DateTimeOffset(2026, 10, 13, 0, 0, 0, TimeSpan.Zero), d.DeferredUntil);

        clock.Set(d.DeferredUntil!.Value);
        Assert.Equal(100, l.GetWarmupCap("new.example"));
        for (int i = 0; i < 100; i++)
        {
            Assert.True(l.TryReserve(TenantA, "new.example").IsAllowed);
        }

        Assert.False(l.TryReserve(TenantA, "new.example").IsAllowed);

        // Graduated after the table: no warm-up cap any more.
        clock.Set(new DateTimeOffset(2026, 10, 12, 8, 0, 0, TimeSpan.Zero).AddDays(11));
        Assert.Null(l.GetWarmupCap("new.example"));
        for (int i = 0; i < 100_000 / 1000; i++)
        {
            Assert.True(l.TryReserve(TenantA, "new.example", 1000).IsAllowed);
        }
    }

    [Fact]
    public void Warmup_other_domains_are_unaffected_and_the_stricter_limit_wins()
    {
        var (l, _, _) = Create();
        l.StartWarmup("new.example", new DateOnly(2026, 10, 12), new WarmupSchedule([10, 20]));
        l.SetSendingDomainLimits("new.example", new LimitSet(null, 5));
        for (int i = 0; i < 5; i++)
        {
            Assert.True(l.TryReserve(TenantA, "new.example").IsAllowed);
        }

        var d = l.TryReserve(TenantA, "new.example");
        Assert.False(d.IsAllowed);
        Assert.False(l.GetUsage(TenantA, "new.example").Single(u => u.Scope == CounterScope.SendingDomain && u.Window == CounterWindow.Day).LimitFromWarmup);

        for (int i = 0; i < 500; i++)
        {
            Assert.True(l.TryReserve(TenantA, "old.example").IsAllowed);
        }

        l.StopWarmup("new.example");
        l.SetSendingDomainLimits("new.example", null);
        Assert.True(l.TryReserve(TenantA, "new.example").IsAllowed);
    }

    [Fact]
    public void Warmup_starting_in_the_future_uses_the_first_day_cap()
    {
        var (l, _, _) = Create();
        l.StartWarmup("future.example", new DateOnly(2026, 11, 1));
        Assert.Equal(50, l.GetWarmupCap("future.example"));
    }

    [Fact]
    public void Zero_limit_and_oversized_batches_are_rejected_not_deferred()
    {
        var (l, _, _) = Create(new SendingLimitsOptions { DefaultTenant = new LimitSet(10, 0) });
        var zero = l.TryReserve(TenantA, null);
        Assert.Equal(SendingDecisionKind.Rejected, zero.Kind);
        Assert.Null(zero.DeferredUntil);
        Assert.Equal(CounterScope.Tenant, zero.LimitedBy);

        var (l2, _, _) = Create(new SendingLimitsOptions { Global = new LimitSet(10, null) });
        var big = l2.TryReserve(TenantA, null, 11);
        Assert.Equal(SendingDecisionKind.Rejected, big.Kind);
        Assert.Equal(CounterScope.Global, big.LimitedBy);
        Assert.True(l2.TryReserve(TenantA, null, 10).IsAllowed);
    }

    [Fact]
    public void A_batch_larger_than_todays_warmup_cap_is_deferred_not_rejected()
    {
        var (l, _, _) = Create();
        l.StartWarmup("new.example", new DateOnly(2026, 10, 12));
        var d = l.TryReserve(TenantA, "new.example", 60); // today's cap is 50, tomorrow's 100
        Assert.Equal(SendingDecisionKind.Deferred, d.Kind);
    }

    [Fact]
    public void Release_returns_capacity()
    {
        var (l, _, _) = Create(new SendingLimitsOptions { DefaultTenant = new LimitSet(2, null) });
        var first = l.TryReserve(TenantA, "a.example");
        l.TryReserve(TenantA, "a.example");
        Assert.False(l.TryReserve(TenantA, "a.example").IsAllowed);
        l.Release(TenantA, "a.example", 1, first.At);
        Assert.True(l.TryReserve(TenantA, "a.example").IsAllowed);
        l.Release(TenantA, "a.example", 10, first.At); // over-release never goes negative
        Assert.All(l.GetUsage(TenantA, "a.example"), u => Assert.True(u.Used >= 0));
    }

    [Fact]
    public void Release_targets_the_window_of_the_original_reservation()
    {
        var (l, clock, _) = Create(new SendingLimitsOptions { DefaultTenant = new LimitSet(2, null) });
        var first = l.TryReserve(TenantA, null);
        clock.Advance(TimeSpan.FromHours(1));
        l.TryReserve(TenantA, null);
        l.Release(TenantA, null, 1, first.At); // old hour: must not touch the current hour
        Assert.Equal(1, l.GetUsage(TenantA, null).Single(u => u.Scope == CounterScope.Tenant && u.Window == CounterWindow.Hour).Used);
    }

    [Fact]
    public void Counters_of_old_windows_are_pruned()
    {
        var (l, clock, store) = Create();
        l.TryReserve(TenantA, "a.example");
        int initial = store.CounterCount;
        Assert.Equal(6, initial);
        clock.Advance(TimeSpan.FromDays(3));
        l.TryReserve(TenantA, "a.example");
        Assert.Equal(6, store.CounterCount);
    }

    [Fact]
    public void Parallel_reservations_never_exceed_a_cap()
    {
        var (l, _, _) = Create(new SendingLimitsOptions { DefaultTenant = new LimitSet(null, 1000) });
        long allowed = 0;
        long deferred = 0;
        Parallel.For(0, 32, new ParallelOptions { MaxDegreeOfParallelism = 32 }, _ =>
        {
            for (int i = 0; i < 100; i++)
            {
                if (l.TryReserve(TenantA, "a.example").IsAllowed)
                {
                    Interlocked.Increment(ref allowed);
                }
                else
                {
                    Interlocked.Increment(ref deferred);
                }
            }
        });

        Assert.True(allowed <= 1000, $"allowed {allowed}");
        Assert.Equal(3200, allowed + deferred);
        // Contention can only cause extra refusals, but with all attempts racing at least most of the cap is used.
        Assert.True(allowed >= 900, $"allowed {allowed}");
        Assert.True(l.GetUsage(TenantA, "a.example").Single(u => u.Scope == CounterScope.Tenant && u.Window == CounterWindow.Day).Used <= 1000);
    }

    [Fact]
    public void Parallel_reservations_respect_global_and_per_tenant_caps_together()
    {
        var (l, _, _) = Create(new SendingLimitsOptions { Global = new LimitSet(null, 500), DefaultTenant = new LimitSet(null, 200) });
        var perTenant = new long[3];
        Guid[] tenants = [Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid()];
        Parallel.For(0, 24, new ParallelOptions { MaxDegreeOfParallelism = 24 }, worker =>
        {
            int t = worker % 3;
            for (int i = 0; i < 100; i++)
            {
                if (l.TryReserve(tenants[t], null).IsAllowed)
                {
                    Interlocked.Increment(ref perTenant[t]);
                }
            }
        });

        Assert.True(perTenant.Sum() <= 500, $"total {perTenant.Sum()}");
        Assert.All(perTenant, c => Assert.True(c <= 200));
        // Counters reflect only allowed reservations (refused ones were rolled back).
        for (int t = 0; t < 3; t++)
        {
            Assert.Equal(perTenant[t], l.GetUsage(tenants[t], null).Single(u => u.Scope == CounterScope.Tenant && u.Window == CounterWindow.Day).Used);
        }
    }

    [Fact]
    public void Store_reservation_is_all_or_nothing()
    {
        var store = new InMemorySendingCounterStore();
        var k1 = new CounterKey(CounterScope.Global, Guid.Empty, null, CounterWindow.Day, 1);
        var k2 = new CounterKey(CounterScope.Tenant, TenantA, null, CounterWindow.Day, 1);
        Assert.True(store.TryReserve([new CounterReservation(k2, 5, 5)], out _));
        Assert.False(store.TryReserve([new CounterReservation(k1, 1, 10), new CounterReservation(k2, 1, 5)], out int failed));
        Assert.Equal(1, failed);
        Assert.Equal(0, store.GetCount(k1));
        Assert.Equal(5, store.GetCount(k2));
    }

    [Fact]
    public void Warmup_schedule_validates_its_table()
    {
        Assert.Throws<ArgumentException>(() => new WarmupSchedule([]));
        Assert.Throws<ArgumentException>(() => new WarmupSchedule([10, 5]));
        Assert.Throws<ArgumentException>(() => new WarmupSchedule([0, 5]));
        Assert.Throws<ArgumentOutOfRangeException>(() => new WarmupSchedule([10, 20], 15));
        var withFinal = new WarmupSchedule([10, 20], 50);
        Assert.Equal(50, withFinal.GetDailyCap(2));
        Assert.Equal(50, withFinal.GetDailyCap(100));
        Assert.Equal(20, withFinal.GetDailyCap(new DateOnly(2026, 1, 2), new DateOnly(2026, 1, 3)));
        Assert.Equal(10, withFinal.GetDailyCap(new DateOnly(2026, 1, 2), new DateOnly(2026, 1, 2)));
    }

    [Fact]
    public void Invalid_count_is_rejected()
    {
        var (l, _, _) = Create();
        Assert.Throws<ArgumentOutOfRangeException>(() => l.TryReserve(TenantA, null, 0));
    }
}
