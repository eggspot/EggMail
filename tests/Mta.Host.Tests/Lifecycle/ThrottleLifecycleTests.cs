using System.Collections;
using System.Reflection;
using Mta.Host.Security;
using Mta.TestSupport;

namespace Mta.Host.Tests.Lifecycle;

/// <summary>The process-local failed-login throttle over two virtual years: the lockout starts with the limit-th failure and ends when the oldest counted failure is older than the window, every time, and the table of keys stays small.</summary>
public class ThrottleLifecycleTests
{
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(15);

    [Fact]
    public void The_lockout_ends_exactly_when_the_oldest_failure_leaves_the_window_in_every_cycle_of_two_years()
    {
        int seed = Accelerated.Seed(5);
        var random = new Random(seed);
        var clock = new VirtualClock();
        var throttle = new AuthThrottle(clock, maxFailures: 10, window: Window);
        int cycles = Accelerated.Scaled(700);   // about two years at one cycle a day
        for (int cycle = 0; cycle < cycles; cycle++)
        {
            string ip = "203.0.113." + random.Next(1, 250);
            string user = "user:u" + random.Next(0, 5);
            DateTimeOffset first = clock.UtcNow;
            for (int i = 0; i < 10; i++)
            {
                Assert.False(throttle.IsLockedOut(out _, ip, user), $"locked after {i} failures (seed {seed}, cycle {cycle})");
                throttle.RecordFailure(ip, user);
                clock.Advance(TimeSpan.FromSeconds(random.Next(1, 30)));
            }

            Assert.True(throttle.IsLockedOut(out TimeSpan retryAfter, ip, user));
            Assert.Equal(first + Window - clock.UtcNow, retryAfter);   // the advice is exact

            clock.Advance(first + Window - clock.UtcNow);
            Assert.True(throttle.IsLockedOut(out _, ip, user), "at exactly the window the first failure still counts");
            clock.Advance(TimeSpan.FromSeconds(1));
            Assert.False(throttle.IsLockedOut(out _, ip, user), $"still locked one second after the window (seed {seed}, cycle {cycle})");

            // A success clears the user's count for good.
            throttle.RecordFailure(user);
            throttle.RecordSuccess(user);
            Assert.False(throttle.IsLockedOut(out _, user));
            clock.Advance(TimeSpan.FromDays(1) - Window);
        }
    }

    [Fact]
    public void Keys_of_old_failures_are_swept_so_the_table_stays_near_the_key_limit_over_months()
    {
        var clock = new VirtualClock();
        int maxKeys = 500;
        var throttle = new AuthThrottle(clock, maxFailures: 10, window: Window, maxKeys: maxKeys);
        FieldInfo? field = typeof(AuthThrottle).GetField("_failures", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);   // renamed? then this test needs the new name: it reads the size of the key table, which the type does not expose
        var table = (ICollection)field.GetValue(throttle)!;

        int worst = 0;
        int attempts = Accelerated.Scaled(20_000);
        for (int i = 0; i < attempts; i++)
        {
            // One failure from a new address every 30 seconds for weeks: every key is old before the next 15 minutes are over.
            throttle.RecordFailure("198.51." + (i / 250 % 250) + "." + (i % 250) + "-" + i);
            clock.Advance(TimeSpan.FromSeconds(30));
            worst = Math.Max(worst, table.Count);
        }

        // Sweeps run when the table passes its limit and remove every key whose failures have aged out: with one failure per 30 seconds and a 15 minute window, about 30 keys are live.
        Assert.InRange(worst, 1, maxKeys + 1);
    }
}
