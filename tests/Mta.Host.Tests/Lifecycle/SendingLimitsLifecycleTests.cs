using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Policy;
using Mta.TestSupport;

namespace Mta.Host.Tests.Lifecycle;

/// <summary>
/// Days and weeks of sending policy in milliseconds, on a virtual clock: the warm-up ramp, the hourly and daily counter windows at the exact instants
/// they roll over, and the recovery of the per-destination throttle and the route circuit breaker. Pure policy code (no storage): the same rules with
/// restarts and both storage backends are in <c>Mta.Integration.Tests/Lifecycle/SendingStateLifecycleTests</c>.
/// This does not replace a wall-clock soak: nothing here runs on the real clock.
/// </summary>
public class SendingLimitsLifecycleTests
{
    private static readonly Guid Tenant = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    private static DateTimeOffset At(int y, int mo, int d, int h = 0, int mi = 0, int s = 0) => new(y, mo, d, h, mi, s, TimeSpan.Zero);

    // ---- warm-up ----

    [Fact]
    public void Lifecycle_warm_up_ramp_allows_exactly_the_days_cap_and_steps_up_at_midnight_UTC_only()
    {
        var clock = new VirtualClock(At(2026, 10, 12, 12, 30));
        var limits = new SendingLimits(clock, new InMemorySendingCounterStore(), SendingConfigurator.OptionsFrom(new SendingSection { WarmupEnabled = true }));
        DateOnly dayZero = DateOnly.FromDateTime(clock.UtcNow.UtcDateTime);
        limits.StartWarmup("new.example", dayZero);
        // A second domain that was added three days later: its own ramp, not the first one's.
        limits.StartWarmup("Later.Example.", dayZero.AddDays(3));

        long[] schedule = [.. WarmupSchedule.Default.DailyCaps];
        for (int day = 0; day < schedule.Length + 2; day++)
        {
            clock.Set(At(2026, 10, 12).AddDays(day));   // exactly midnight: the first instant of the day
            Assert.Equal(day < schedule.Length ? schedule[day] : (long?)null, limits.GetWarmupCap("new.example"));

            long allowed = 0;
            if (day < schedule.Length)
            {
                while (limits.TryReserve(Tenant, "new.example").IsAllowed)
                {
                    allowed++;
                }
            }

            if (day < schedule.Length)
            {
                // The cap, never above it, and the refusal says when the next window opens: the next midnight.
                Assert.Equal(schedule[day], allowed);
                clock.Set(At(2026, 10, 12).AddDays(day).AddHours(23).AddMinutes(59).AddSeconds(59).AddTicks(TimeSpan.TicksPerSecond - 1));
                SendingDecision refused = limits.TryReserve(Tenant, "new.example");
                Assert.Equal(SendingDecisionKind.Deferred, refused.Kind);
                Assert.Equal(CounterScope.SendingDomain, refused.LimitedBy);
                Assert.Equal(CounterWindow.Day, refused.LimitedWindow);
                Assert.Equal(At(2026, 10, 12).AddDays(day + 1), refused.DeferredUntil);
                Assert.Contains("warm-up", refused.Reason);
            }
            else
            {
                // Graduated: the schedule no longer caps the domain.
                Assert.True(limits.TryReserve(Tenant, "new.example", 1_000_000).IsAllowed);
            }

            // The second domain follows its own day index (before its start day it is on the first rung).
            int laterDay = Math.Max(day - 3, 0);
            clock.Set(At(2026, 10, 12).AddDays(day).AddHours(12));
            Assert.Equal(laterDay < schedule.Length ? schedule[laterDay] : (long?)null, limits.GetWarmupCap("later.example"));
            if (laterDay < schedule.Length)
            {
                long got = 0;
                while (limits.TryReserve(Tenant, "later.example").IsAllowed)
                {
                    got++;
                }

                Assert.Equal(schedule[laterDay], got);
            }
        }

        // Each day a fresh window: the usage reports the cap as coming from the warm-up while it applies.
        clock.Set(At(2026, 10, 12));
        SendingUsage usage = limits.GetUsage(Tenant, "new.example").Single(u => u is { Scope: CounterScope.SendingDomain, Window: CounterWindow.Day });
        Assert.True(usage.LimitFromWarmup);
        Assert.Equal(50, usage.Limit);
        Assert.Equal(0, usage.Used);

        // Taking the domain off the ramp lifts the cap at once.
        limits.StopWarmup("new.example");
        Assert.Null(limits.GetWarmupCap("new.example"));
        Assert.True(limits.TryReserve(Tenant, "new.example", 10_000).IsAllowed);
    }

    [Fact]
    public void Lifecycle_a_domain_limit_below_the_ramp_wins_and_a_configured_ramp_applies_through_the_configurator_options()
    {
        var clock = new VirtualClock(At(2026, 10, 12, 8));
        var options = SendingConfigurator.OptionsFrom(new SendingSection { DomainPerDay = 30, WarmupEnabled = true });
        var limits = new SendingLimits(clock, new InMemorySendingCounterStore(), options);
        limits.StartWarmup("a.example", DateOnly.FromDateTime(clock.UtcNow.UtcDateTime));

        long allowed = 0;
        while (limits.TryReserve(Tenant, "a.example").IsAllowed)
        {
            allowed++;
        }

        Assert.Equal(30, allowed);   // 30 per day is below the first ramp day (50): the lower limit decides and it is not reported as a warm-up cap
        Assert.False(limits.GetUsage(Tenant, "a.example").Single(u => u is { Scope: CounterScope.SendingDomain, Window: CounterWindow.Day }).LimitFromWarmup);

        clock.Set(At(2026, 10, 13, 8));   // day 1: cap 100 > 30, so the domain limit still decides
        allowed = 0;
        while (limits.TryReserve(Tenant, "a.example").IsAllowed)
        {
            allowed++;
        }

        Assert.Equal(30, allowed);

        // A custom ramp that graduates to a fixed cap.
        var ramp = new WarmupSchedule([10, 20, 40], capAfterSchedule: 100);
        var limits2 = new SendingLimits(clock, new InMemorySendingCounterStore(), new SendingLimitsOptions());
        limits2.StartWarmup("b.example", DateOnly.FromDateTime(clock.UtcNow.UtcDateTime), ramp);
        long[] expected = [10, 20, 40, 100, 100, 100];
        foreach (long cap in expected)
        {
            long got = 0;
            while (limits2.TryReserve(Tenant, "b.example").IsAllowed)
            {
                got++;
            }

            Assert.Equal(cap, got);
            clock.Advance(TimeSpan.FromDays(1));
        }
    }

    // ---- counter windows ----

    public static TheoryData<string, int, int, int, int, int, int, int> Boundaries => new()
    {
        // Name, then the boundary instant (year, month, day, hour) and whether it is a day boundary (1) or only an hour boundary (0).
        { "an hour inside a day", 2026, 10, 14, 10, 0, 0, 0 },
        { "midnight", 2026, 10, 14, 0, 0, 0, 1 },
        { "the end of a 31-day month", 2026, 11, 1, 0, 0, 0, 1 },
        { "the end of a 30-day month", 2026, 10, 1, 0, 0, 0, 1 },
        { "new year", 2027, 1, 1, 0, 0, 0, 1 },
        { "the end of February in a common year", 2027, 3, 1, 0, 0, 0, 1 },
        { "the leap day begins", 2028, 2, 29, 0, 0, 0, 1 },
        { "the leap day ends", 2028, 3, 1, 0, 0, 0, 1 },
    };

    [Theory]
    [MemberData(nameof(Boundaries))]
    public void Lifecycle_hour_and_day_counters_roll_over_at_the_exact_instant(string name, int y, int mo, int d, int h, int mi, int s, int dayBoundary)
    {
        _ = name;
        DateTimeOffset boundary = At(y, mo, d, h, mi, s);
        var clock = new VirtualClock(boundary.AddTicks(-1));   // the last 100 ns before the boundary
        var limits = new SendingLimits(clock, new InMemorySendingCounterStore(), new SendingLimitsOptions { DefaultTenant = new LimitSet(PerHour: 2, PerDay: 3) });

        Assert.True(limits.TryReserve(Tenant, null).IsAllowed);
        Assert.True(limits.TryReserve(Tenant, null).IsAllowed);
        SendingDecision before = limits.TryReserve(Tenant, null);
        Assert.Equal(SendingDecisionKind.Deferred, before.Kind);
        Assert.Equal("tenant hourly limit reached", before.Reason);
        Assert.Equal(boundary, before.DeferredUntil);   // the retry time is the boundary, to the tick

        clock.Set(boundary);
        long hourUsed = limits.GetUsage(Tenant, null).Single(u => u is { Scope: CounterScope.Tenant, Window: CounterWindow.Hour }).Used;
        long dayUsed = limits.GetUsage(Tenant, null).Single(u => u is { Scope: CounterScope.Tenant, Window: CounterWindow.Day }).Used;
        Assert.Equal(0, hourUsed);
        Assert.Equal(dayBoundary == 1 ? 0 : 2, dayUsed);

        if (dayBoundary == 1)
        {
            Assert.True(limits.TryReserve(Tenant, null).IsAllowed);
            Assert.True(limits.TryReserve(Tenant, null).IsAllowed);
            SendingDecision again = limits.TryReserve(Tenant, null);
            Assert.Equal("tenant hourly limit reached", again.Reason);
            Assert.Equal(boundary.AddHours(1), again.DeferredUntil);
        }
        else
        {
            Assert.True(limits.TryReserve(Tenant, null).IsAllowed);   // the third of the day
            SendingDecision dayFull = limits.TryReserve(Tenant, null);
            Assert.Equal("tenant daily limit reached", dayFull.Reason);
            Assert.Equal(At(y, mo, d).AddDays(1), dayFull.DeferredUntil);
        }
    }

    [Fact]
    public void Lifecycle_a_month_of_hours_never_lets_a_window_exceed_its_limit_and_prunes_old_windows()
    {
        int seed = Accelerated.Seed(20261012);
        var random = new Random(seed);
        var clock = new VirtualClock(At(2026, 12, 15, 0, 0, 1));
        var store = new InMemorySendingCounterStore();
        var limits = new SendingLimits(clock, store, new SendingLimitsOptions { Global = new LimitSet(40, 400), DefaultTenant = new LimitSet(25, 250) });
        var perHour = new Dictionary<long, long>();
        var perDay = new Dictionary<long, long>();
        long maxCounters = 0;
        int days = 45 * Accelerated.Scale;   // crosses the month and the year boundary
        for (int step = 0; step < days * 24 * 6; step++)   // every ten minutes
        {
            clock.Advance(TimeSpan.FromMinutes(10));
            int attempts = random.Next(0, 12);
            for (int i = 0; i < attempts; i++)
            {
                if (limits.TryReserve(Tenant, null).IsAllowed)
                {
                    long s = clock.UtcNow.ToUnixTimeSeconds();
                    perHour[s / 3600] = perHour.GetValueOrDefault(s / 3600) + 1;
                    perDay[s / 86400] = perDay.GetValueOrDefault(s / 86400) + 1;
                }
            }

            maxCounters = Math.Max(maxCounters, store.CounterCount);
        }

        Assert.True(perHour.Values.Max() <= 25, $"seed {seed}");
        Assert.True(perDay.Values.Max() <= 250, $"seed {seed}");
        Assert.Contains(perHour.Values, v => v == 25);   // the loop did hit the limit, so the assertion above means something
        // Windows older than the previous hour/day are dropped as time passes: a few counters, not one per hour of the 45 days.
        Assert.True(maxCounters <= 16, $"{maxCounters} counters were alive at once (seed {seed})");
    }

    // ---- per-destination throttle ----

    [Fact]
    public void Lifecycle_destination_throttle_slows_down_once_per_cooldown_and_climbs_back_to_the_ceiling_in_exact_steps()
    {
        var clock = new VirtualClock(At(2026, 10, 12, 9));
        var throttle = new DestinationThrottle(clock);   // defaults: ceiling 20 connections and 600 a minute, start at 5 and 120
        var key = new ThrottleKey("big.example");

        throttle.Report(key, ThrottleSignal.Success);   // creates the state
        ThrottleSnapshot start = throttle.GetSnapshot(key)!;
        Assert.Equal((5, 120.0, 20, 600.0), (start.ConcurrencyLimit, start.MessagesPerMinute, start.ConcurrencyCeiling, start.MessagesPerMinuteCeiling));

        throttle.Report(key, ThrottleSignal.Throttled);
        Assert.Equal((2, 60.0), Limits(throttle, key));

        clock.Advance(TimeSpan.FromSeconds(10));
        throttle.Report(key, ThrottleSignal.Throttled);   // within the 60 s cooldown: one bad reply is one slowdown
        Assert.Equal((2, 60.0), Limits(throttle, key));

        clock.Advance(TimeSpan.FromSeconds(50));   // exactly the cooldown
        throttle.Report(key, ThrottleSignal.Throttled);
        Assert.Equal((1, 30.0), Limits(throttle, key));
        throttle.Report(key, ThrottleSignal.Throttled);
        Assert.Equal((1, 30.0), Limits(throttle, key));   // and never below the floor in the same cooldown

        // 25 successes inside the cooldown do not raise the limits ...
        clock.Advance(TimeSpan.FromSeconds(30));
        for (int i = 0; i < 25; i++)
        {
            throttle.Report(key, ThrottleSignal.Success);
        }

        Assert.Equal((1, 30.0), Limits(throttle, key));

        // ... the first success after it does (the streak is already long enough).
        clock.Advance(TimeSpan.FromSeconds(30));
        throttle.Report(key, ThrottleSignal.Success);
        Assert.Equal((2, 90.0), Limits(throttle, key));

        // From there every 20 successes add one connection and a tenth of the ceiling in rate, up to the ceiling and not above it.
        int batches = 0;
        while (Limits(throttle, key) != (20, 600.0))
        {
            for (int i = 0; i < 20; i++)
            {
                throttle.Report(key, ThrottleSignal.Success);
            }

            batches++;
            Assert.InRange(batches, 1, 18);
        }

        Assert.Equal(18, batches);   // connections 2 -> 20 is the longer climb; the rate (90 -> 600 in steps of 60) was at the ceiling after 9
        for (int i = 0; i < 200; i++)
        {
            throttle.Report(key, ThrottleSignal.Success);
        }

        Assert.Equal((20, 600.0), Limits(throttle, key));

        // A failure streak of connections (3 within 30 s) is a slowdown as well.
        clock.Advance(TimeSpan.FromMinutes(2));
        for (int i = 0; i < 3; i++)
        {
            throttle.Report(key, ThrottleSignal.ConnectionFailure);
            clock.Advance(TimeSpan.FromSeconds(5));
        }

        Assert.Equal((10, 300.0), Limits(throttle, key));
    }

    [Fact]
    public void Lifecycle_destination_throttle_token_bucket_refills_on_the_exact_schedule_and_idle_destinations_are_forgotten()
    {
        var clock = new VirtualClock(At(2026, 10, 12, 9));
        var throttle = new DestinationThrottle(clock, new DestinationThrottleOptions { InitialConcurrentConnections = 5, InitialMessagesPerMinute = 120 });
        var key = new ThrottleKey("steady.example");

        // The burst is ten seconds of the rate: 20 tokens at 120 a minute.
        for (int i = 0; i < 20; i++)
        {
            ThrottleResult r = throttle.TryAcquire(key);
            Assert.True(r.Acquired, $"token {i}");
            r.Lease!.Dispose();
        }

        ThrottleResult denied = throttle.TryAcquire(key);
        Assert.Equal(ThrottleDenial.RateLimit, denied.Denial);
        Assert.Equal(TimeSpan.FromSeconds(0.5), denied.RetryAfter);   // one token at two a second

        clock.Advance(TimeSpan.FromSeconds(0.25));
        ThrottleResult stillDenied = throttle.TryAcquire(key);
        Assert.Equal(ThrottleDenial.RateLimit, stillDenied.Denial);
        Assert.Equal(TimeSpan.FromSeconds(0.25), stillDenied.RetryAfter);
        clock.Advance(stillDenied.RetryAfter);
        ThrottleResult ok = throttle.TryAcquire(key);
        Assert.True(ok.Acquired);
        ok.Lease!.Dispose();

        // A pause of any length refills the bucket to its capacity and not beyond.
        clock.Advance(TimeSpan.FromHours(6));
        Assert.Equal(20.0, throttle.GetSnapshot(key)!.AvailableTokens, precision: 6);

        // Idle destinations are dropped (memory is bounded by the destinations in use), and a returning one starts from the defaults again.
        throttle.Report(key, ThrottleSignal.Throttled);
        Assert.Equal((2, 60.0), Limits(throttle, key));
        clock.Advance(TimeSpan.FromMinutes(16));
        Assert.Equal(1, throttle.Sweep());
        Assert.Equal(0, throttle.TrackedKeyCount);
        Assert.True(throttle.TryAcquire(key).Acquired);
        Assert.Equal((5, 120.0), Limits(throttle, key));
    }

    private static (int Connections, double PerMinute) Limits(DestinationThrottle throttle, ThrottleKey key)
    {
        ThrottleSnapshot s = throttle.GetSnapshot(key)!;
        return (s.ConcurrencyLimit, s.MessagesPerMinute);
    }

    // ---- route circuit breaker ----

    [Fact]
    public void Lifecycle_circuit_breaker_opens_probes_backs_off_5_10_20_40_60_minutes_and_closes_on_a_good_probe()
    {
        var clock = new VirtualClock(At(2026, 10, 12, 9));
        var health = new RouteHealth(clock);
        var key = RouteHealthKey.ForMxHost("mx.flaky.example");

        // Failures that are more than ten minutes apart are not a streak, however many there are.
        for (int i = 0; i < 20; i++)
        {
            health.ReportFailure(key, "timeout");
            clock.Advance(TimeSpan.FromMinutes(11));
            Assert.Equal(CircuitState.Closed, health.GetSnapshot(key).State);
        }

        // Five in a row open it for five minutes.
        for (int i = 0; i < 5; i++)
        {
            health.ReportFailure(key, "refused");
        }

        DateTimeOffset openedAt = clock.UtcNow;
        Assert.Equal(CircuitState.Open, health.GetSnapshot(key).State);
        TimeSpan[] cooldowns = [TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(20), TimeSpan.FromMinutes(40), TimeSpan.FromMinutes(60), TimeSpan.FromMinutes(60)];
        DateTimeOffset retryAt = openedAt + cooldowns[0];
        for (int round = 0; round < cooldowns.Length; round++)
        {
            clock.Set(retryAt - TimeSpan.FromTicks(1));
            Assert.Equal(RouteAdmission.Rejected, health.TryAdmit(key, out DateTimeOffset reported));
            Assert.Equal(retryAt, reported);

            clock.Set(retryAt);
            Assert.Equal(RouteAdmission.Probe, health.TryAdmit(key, out _));
            // While the probe is out nobody else gets in, for at most the probe timeout (two minutes).
            clock.Advance(TimeSpan.FromMinutes(1));
            Assert.Equal(RouteAdmission.Rejected, health.TryAdmit(key, out DateTimeOffset probeEnds));
            Assert.Equal(retryAt + TimeSpan.FromMinutes(2), probeEnds);

            health.ReportFailure(key, "still down");   // the probe failed: re-open with twice the cooldown, capped at an hour
            Assert.Equal(CircuitState.Open, health.GetSnapshot(key).State);
            TimeSpan next = round + 1 < cooldowns.Length ? cooldowns[round + 1] : TimeSpan.FromMinutes(60);
            retryAt = clock.UtcNow + next;
            Assert.Equal(retryAt, health.GetSnapshot(key).RetryAt);
        }

        // A probe that never reports back does not lock the route: after the probe timeout another one is admitted.
        clock.Set(retryAt);
        Assert.Equal(RouteAdmission.Probe, health.TryAdmit(key, out _));
        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(RouteAdmission.Probe, health.TryAdmit(key, out _));

        health.ReportSuccess(key);
        RouteHealthSnapshot closed = health.GetSnapshot(key);
        Assert.Equal((CircuitState.Closed, 0), (closed.State, closed.ConsecutiveFailures));
        Assert.Equal(RouteAdmission.Allowed, health.TryAdmit(key));

        // After a success the next outage starts from the short cooldown again.
        for (int i = 0; i < 5; i++)
        {
            health.ReportFailure(key, "down again");
        }

        Assert.Equal(clock.UtcNow + TimeSpan.FromMinutes(5), health.GetSnapshot(key).RetryAt);

        // Healthy, idle routes are forgotten after an hour.
        var other = RouteHealthKey.ForMxHost("mx.once-bad.example");
        health.ReportFailure(other, "x");
        clock.Advance(TimeSpan.FromHours(2));
        health.ReportSuccess(key);   // keeps this one touched
        int tracked = health.TrackedCount;
        Assert.True(health.Sweep() >= 1);
        Assert.True(health.TrackedCount < tracked);
    }
}
