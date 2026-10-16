using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Policy;
using Mta.Storage;
using Mta.TestSupport;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>
/// The sending counters (hour and day windows) and the warm-up ramp of the real <see cref="EggMailRuntime"/> over weeks of virtual time, with graceful stops
/// and crashes in between, on the SQLite files and on PostgreSQL. The runtime is the one the host builds; only the clock is virtual and the flush that the
/// runtime state service does every ten seconds is called by the test. A crash is a runtime and a storage that are disposed without the flush.
/// This does not replace a wall-clock soak: no real timer, no real power loss, and the flush interval is not exercised.
/// </summary>
internal static class SendingStateScenarios
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    private static MtaConfig Config(IStorage storage, SendingSection sending, StorageOptions options) => new()
    {
        Hostname = "egg.test",
        Storage = options,
        Smtp = new SmtpSection { Listeners = new Dictionary<string, ListenerSection>() },
        Sending = sending,
        Delivery = new DeliverySection { AllowPrivateMxAddresses = true },
    };

    private static async Task<EggMailRuntime> StartAsync(RuntimeStateBackend backend, IClock clock, SendingSection sending)
    {
        IStorage storage = await backend.OpenAsync(clock);
        return await EggMailRuntime.CreateAsync(Config(storage, sending, backend.Options), storage, clock, NullMtaLog.Instance, default);
    }

    private static async Task CloseAsync(EggMailRuntime runtime)
    {
        await runtime.DisposeAsync();
        await runtime.Storage.DisposeAsync();
    }

    private static long Used(EggMailRuntime runtime, CounterScope scope, CounterWindow window, string? domain = null) =>
        runtime.Limits.GetUsage(TenantId, domain).Single(u => u.Scope == scope && u.Window == window).Used;

    /// <summary>
    /// A seeded random walk of a week (more with EGGMAIL_ACCEL_SCALE) across New Year: reservations, flushes, graceful restarts and crashes. A model of what the store has been told
    /// predicts every decision: after a crash exactly the flushed counts of the current windows are there, after a graceful stop all of them.
    /// </summary>
    public static async Task CountersFollowTheModelAcrossRestartsAsync(RuntimeStateBackend backend)
    {
        int seed = Accelerated.Seed(20261228);
        var random = new Random(seed);
        string context = $" (backend {backend.Name}, seed {seed})";
        const int PerHour = 6;
        const int PerDay = 40;
        var clock = new VirtualClock(new DateTimeOffset(2026, 12, 28, 12, 30, 0, TimeSpan.Zero));
        var sending = new SendingSection { TenantPerHour = PerHour, TenantPerDay = PerDay };

        // Model: counts per window index, as the live process sees them and as the store holds them.
        var live = new Dictionary<(CounterWindow, long), long>();
        var stored = new Dictionary<(CounterWindow, long), long>();
        static (CounterWindow, long) HourKey(IClock c) => (CounterWindow.Hour, c.UtcNow.ToUnixTimeSeconds() / 3600);
        static (CounterWindow, long) DayKey(IClock c) => (CounterWindow.Day, c.UtcNow.ToUnixTimeSeconds() / 86400);

        EggMailRuntime runtime = await StartAsync(backend, clock, sending);
        int restarts = 0;
        int crashes = 0;
        int refusedByHour = 0;
        int refusedByDay = 0;
        try
        {
            int steps = Accelerated.Scaled(7 * 24 * 2);   // 30-minute steps; the default is a week across New Year, EGGMAIL_ACCEL_SCALE=3 is three
            for (int step = 0; step < steps; step++)
            {
                clock.Advance(TimeSpan.FromMinutes(30));
                int attempts = random.Next(0, 5);
                for (int i = 0; i < attempts; i++)
                {
                    bool modelAllows = live.GetValueOrDefault(HourKey(clock)) < PerHour && live.GetValueOrDefault(DayKey(clock)) < PerDay;
                    SendingDecision decision = runtime.Limits.TryReserve(TenantId, null);
                    Assert.True(modelAllows == decision.IsAllowed, $"step {step}: model says {modelAllows}, runtime says {decision.Kind} ({decision.Reason}){context}");
                    if (decision.IsAllowed)
                    {
                        live[HourKey(clock)] = live.GetValueOrDefault(HourKey(clock)) + 1;
                        live[DayKey(clock)] = live.GetValueOrDefault(DayKey(clock)) + 1;
                    }
                    else if (decision.LimitedWindow == CounterWindow.Hour)
                    {
                        refusedByHour++;
                    }
                    else
                    {
                        refusedByDay++;
                        // A refusal by the day limit says when the next window opens: the coming midnight, UTC.
                        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds((clock.UtcNow.ToUnixTimeSeconds() / 86400 + 1) * 86400), decision.DeferredUntil);
                    }
                }

                if (random.NextDouble() < 0.3)
                {
                    await runtime.FlushRuntimeStateAsync(default);
                    stored = new Dictionary<(CounterWindow, long), long>(live);
                }

                if (random.NextDouble() < 0.07)
                {
                    restarts++;
                    bool crash = random.NextDouble() < 0.5;
                    if (crash)
                    {
                        crashes++;
                        await CloseAsync(runtime);
                        live = new Dictionary<(CounterWindow, long), long>(stored);   // what was not flushed is gone
                    }
                    else
                    {
                        await runtime.FlushRuntimeStateAsync(default);
                        await CloseAsync(runtime);
                        stored = new Dictionary<(CounterWindow, long), long>(live);
                    }

                    // A little downtime: sometimes the restart is in a later hour or day than the stop.
                    if (random.NextDouble() < 0.5)
                    {
                        clock.Advance(TimeSpan.FromMinutes(random.Next(1, 90)));
                    }

                    runtime = await StartAsync(backend, clock, sending);
                    Assert.Equal(live.GetValueOrDefault(HourKey(clock)), Used(runtime, CounterScope.Tenant, CounterWindow.Hour));
                    Assert.Equal(live.GetValueOrDefault(DayKey(clock)), Used(runtime, CounterScope.Tenant, CounterWindow.Day));
                }
            }

            // The loop must have been long enough to matter: both limits refused something and both kinds of stop happened.
            Assert.True(refusedByHour > 0 && refusedByDay > 0 && crashes > 0 && restarts > crashes, $"the walk was too tame: hour {refusedByHour}, day {refusedByDay}, restarts {restarts}, crashes {crashes}{context}");

            // Whatever the runtime wrote, the store holds a handful of windows, not one per hour of the walk.
            await runtime.FlushRuntimeStateAsync(default);
            var rows = await runtime.Storage.Config.GetSendingCountersAsync(0, 0, default);
            Assert.True(rows.Count <= 12, $"{rows.Count} counter rows are stored after the walk{context}");
        }
        finally
        {
            await CloseAsync(runtime);
        }
    }

    /// <summary>
    /// The warm-up ramp through the configurator and the config store: day after day the allowed volume is the day's cap in total, whichever restarts
    /// happen in the middle of it. A graceful stop loses nothing; a crash can lose only what was counted after the last flush (so at most that much extra is sent).
    /// </summary>
    public static async Task WarmupRampHoldsAcrossRestartsAsync(RuntimeStateBackend backend)
    {
        var clock = new VirtualClock(new DateTimeOffset(2026, 10, 12, 12, 30, 0, TimeSpan.Zero));
        var sending = new SendingSection { WarmupEnabled = true };
        long[] ramp = [.. WarmupSchedule.Default.DailyCaps.Take(5)];   // 50, 100, 200, 400, 800

        // The tenant and the domain, as the API creates them; the ramp counts from the domain's creation day.
        await using (IStorage seed = await backend.OpenAsync(clock))
        {
            await seed.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, clock.UtcNow, false), default);
            await seed.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), TenantId, "ramp.example", DomainStatus.Verified, null, false, clock.UtcNow, null, null, 0, null, false, null), default);
        }

        for (int day = 0; day < ramp.Length; day++)
        {
            clock.Set(new DateTimeOffset(2026, 10, 12, 0, 0, 0, TimeSpan.Zero).AddDays(day).AddHours(3));
            bool crashDay = day % 2 == 1;
            long allowed = 0;
            long lostToCrash = 0;
            // Three runtimes per day: send a third of the cap, stop (gracefully, or by crash on odd days), repeat, then send until refused.
            for (int part = 0; part < 3; part++)
            {
                EggMailRuntime runtime = await StartAsync(backend, clock, sending);
                try
                {
                    await SendingConfigurator.RefreshAsync(runtime.Limits, sending, runtime.Storage.Config, default);
                    Assert.Equal(ramp[day], runtime.Limits.GetWarmupCap("ramp.example"));
                    long target = part < 2 ? ramp[day] / 3 : long.MaxValue;
                    long sentNow = 0;
                    while (sentNow < target && runtime.Limits.TryReserve(TenantId, "ramp.example").IsAllowed)
                    {
                        sentNow++;
                        allowed++;
                        if (crashDay && part < 2 && sentNow == target - 2)
                        {
                            await runtime.FlushRuntimeStateAsync(default);   // the last two of this part are counted after the flush
                        }
                    }

                    if (part < 2)
                    {
                        if (crashDay)
                        {
                            lostToCrash += Math.Min(2, sentNow);
                            await CloseAsync(runtime);
                            runtime = null!;
                        }
                        else
                        {
                            await runtime.FlushRuntimeStateAsync(default);
                        }
                    }
                }
                finally
                {
                    if (runtime is not null)
                    {
                        await CloseAsync(runtime);
                    }
                }

                clock.Advance(TimeSpan.FromHours(2));
            }

            if (crashDay)
            {
                // At most the unflushed counts (2 per crash) went out in addition to the cap, and never fewer than the cap.
                Assert.InRange(allowed, ramp[day], ramp[day] + lostToCrash);
            }
            else
            {
                Assert.Equal(ramp[day], allowed);   // restarts in the middle of the day did not give the domain a second allowance
            }
        }
    }
}

[Collection("Runtime")]
public class SendingStateLifecycleOnSqlite
{
    [Fact]
    public async Task Lifecycle_counters_follow_the_model_across_restarts_and_crashes()
    {
        await using RuntimeStateBackend backend = RuntimeStateBackend.Sqlite();
        await SendingStateScenarios.CountersFollowTheModelAcrossRestartsAsync(backend);
    }

    [Fact]
    public async Task Lifecycle_warm_up_ramp_holds_across_restarts_and_crashes()
    {
        await using RuntimeStateBackend backend = RuntimeStateBackend.Sqlite();
        await SendingStateScenarios.WarmupRampHoldsAcrossRestartsAsync(backend);
    }
}

[Collection("Runtime")]
public class SendingStateLifecycleOnPostgres
{
    [PostgresFact]
    public async Task Lifecycle_counters_follow_the_model_across_restarts_and_crashes()
    {
        await using RuntimeStateBackend backend = await RuntimeStateBackend.PostgresAsync();
        await SendingStateScenarios.CountersFollowTheModelAcrossRestartsAsync(backend);
    }

    [PostgresFact]
    public async Task Lifecycle_warm_up_ramp_holds_across_restarts_and_crashes()
    {
        await using RuntimeStateBackend backend = await RuntimeStateBackend.PostgresAsync();
        await SendingStateScenarios.WarmupRampHoldsAcrossRestartsAsync(backend);
    }
}
