namespace Mta.Policy.Tests;

public class RetryScheduleTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 12, 8, 30, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Far = Now.AddDays(5);

    private static RetrySchedule NoJitter(RetryScheduleOptions? options = null) => new(options, new FixedRandom(0.5));

    private static RemoteReply Reply(int code, string? enhanced, string text) => new(code, enhanced, text);

    [Fact]
    public void Default_base_delays_follow_the_proposed_ladder_then_repeat()
    {
        var s = NoJitter();
        int[] minutes = [2, 5, 15, 30, 60, 120, 240, 240, 240, 240];
        for (int i = 0; i < minutes.Length; i++)
        {
            Assert.Equal(TimeSpan.FromMinutes(minutes[i]), s.GetBaseDelay(i + 1));
        }

        Assert.Equal(TimeSpan.FromHours(4), s.GetBaseDelay(1000));
        Assert.Equal(TimeSpan.FromMinutes(2), s.GetBaseDelay(0)); // defensive: treated as the first attempt
    }

    [Fact]
    public void Without_jitter_the_next_attempt_is_now_plus_base_delay()
    {
        var s = NoJitter();
        var d = s.NextAttemptAt(2, Now, Far, Reply(451, "4.3.0", "local error"));
        Assert.False(d.Expire);
        Assert.Equal(Now.AddMinutes(5), d.NextAttemptAt);
        Assert.Equal(TimeSpan.FromMinutes(5), d.Delay);
    }

    [Theory]
    [InlineData(0.0, 0.9)]
    [InlineData(0.5, 1.0)]
    [InlineData(0.999999, 1.1)]
    public void Jitter_spreads_plus_minus_ten_percent(double random, double factor)
    {
        var s = new RetrySchedule(random: new FixedRandom(random));
        var d = s.NextAttemptAt(3, Now, Far, Reply(451, "4.3.0", "x"));
        Assert.Equal(TimeSpan.FromMinutes(15).TotalSeconds * factor, d.Delay.TotalSeconds, 0.5);
    }

    [Fact]
    public void Property_jitter_stays_within_bounds_for_every_attempt()
    {
        var s = new RetrySchedule(random: new SeededRandomSource(42));
        for (int attempt = 1; attempt <= 60; attempt++)
        {
            TimeSpan b = s.GetBaseDelay(attempt);
            for (int i = 0; i < 50; i++)
            {
                var d = s.NextAttemptAt(attempt, Now, Now.AddDays(365), Reply(451, "4.3.0", "x"));
                Assert.InRange(d.Delay.TotalSeconds, b.TotalSeconds * 0.9 - 0.001, b.TotalSeconds * 1.1 + 0.001);
            }
        }
    }

    [Fact]
    public void Property_base_delay_is_monotonic_and_bounded()
    {
        var s = NoJitter();
        TimeSpan previous = TimeSpan.Zero;
        for (int attempt = 1; attempt <= 500; attempt++)
        {
            TimeSpan b = s.GetBaseDelay(attempt);
            Assert.True(b >= previous, $"attempt {attempt}");
            Assert.True(b <= TimeSpan.FromHours(4));
            previous = b;
        }
    }

    [Fact]
    public void Property_next_attempt_times_are_monotonic_over_a_simulated_delivery()
    {
        var s = NoJitter();
        DateTimeOffset now = Now;
        DateTimeOffset expires = Now.AddDays(5);
        DateTimeOffset previousNext = now;
        int attempts = 0;
        while (true)
        {
            attempts++;
            var d = s.NextAttemptAt(attempts, now, expires, Reply(451, "4.3.0", "x"));
            if (d.Expire)
            {
                break;
            }

            Assert.True(d.NextAttemptAt > previousNext);
            Assert.True(d.NextAttemptAt < expires, "never at or past expiry");
            previousNext = d.NextAttemptAt;
            now = d.NextAttemptAt;
            Assert.True(attempts < 200);
        }

        // 2m+5m+15m+30m+1h+2h = ~3.87h, then 4h steps: a 5 day lifetime holds roughly 30 attempts.
        Assert.InRange(attempts, 25, 40);
    }

    [Fact]
    public void Property_never_schedules_at_or_past_expiry()
    {
        var s = new RetrySchedule(random: new SeededRandomSource(7));
        var rnd = new Random(1234);
        string[] texts = ["x", "greylisted", "rate limit exceeded", "try again in 3 hours"];
        for (int i = 0; i < 5000; i++)
        {
            DateTimeOffset now = Now.AddMinutes(rnd.Next(0, 10_000));
            DateTimeOffset expires = now.AddSeconds(rnd.Next(-3600, 3 * 86400));
            int attempt = rnd.Next(1, 40);
            var reply = Reply(rnd.Next(0, 3) == 0 ? 421 : 450, rnd.Next(0, 2) == 0 ? "4.7.0" : "4.2.0", texts[rnd.Next(texts.Length)]);
            var d = s.NextAttemptAt(attempt, now, expires, reply);
            if (d.Expire)
            {
                Assert.Equal(TimeSpan.Zero, d.Delay);
                continue;
            }

            Assert.True(expires > now);
            Assert.True(d.NextAttemptAt > now);
            Assert.True(d.NextAttemptAt < expires, $"next {d.NextAttemptAt:o} expires {expires:o}");
            Assert.Equal(d.NextAttemptAt - now, d.Delay);
        }
    }

    [Fact]
    public void Expires_immediately_at_or_after_the_expiry()
    {
        var s = NoJitter();
        Assert.True(s.NextAttemptAt(1, Far, Far).Expire);
        Assert.True(s.NextAttemptAt(1, Far.AddSeconds(1), Far).Expire);
        Assert.False(s.NextAttemptAt(1, Far.AddMinutes(-10), Far).Expire);
    }

    [Fact]
    public void Schedules_one_final_attempt_before_expiry_when_the_ladder_overshoots()
    {
        var s = NoJitter();
        DateTimeOffset expires = Now.AddMinutes(10);
        var d = s.NextAttemptAt(5, Now, expires, Reply(451, "4.3.0", "x")); // base delay 1h
        Assert.False(d.Expire);
        Assert.Equal(expires.AddMinutes(-1), d.NextAttemptAt);
        Assert.Equal("final attempt before expiry", d.Reason);
    }

    [Fact]
    public void Expires_instead_of_a_pointless_final_attempt_when_almost_out_of_time()
    {
        var s = NoJitter();
        Assert.True(s.NextAttemptAt(5, Now, Now.AddSeconds(100), Reply(451, "4.3.0", "x")).Expire);
        Assert.False(s.NextAttemptAt(5, Now, Now.AddSeconds(121), Reply(451, "4.3.0", "x")).Expire);
    }

    [Fact]
    public void Final_attempt_can_be_disabled()
    {
        var s = NoJitter(new RetryScheduleOptions { FinalAttemptMargin = TimeSpan.Zero });
        Assert.True(s.NextAttemptAt(5, Now, Now.AddMinutes(10), Reply(451, "4.3.0", "x")).Expire);
    }

    [Fact]
    public void Connection_problems_retry_sooner_the_first_time_only()
    {
        var s = NoJitter();
        Assert.Equal(TimeSpan.FromMinutes(1), s.NextAttemptAt(1, Now, Far, Reply(421, null, "closing channel")).Delay);
        Assert.Equal(TimeSpan.FromMinutes(1), s.NextAttemptAt(1, Now, Far, Reply(451, "4.4.2", "bad connection")).Delay);
        Assert.Equal(TimeSpan.FromMinutes(1), s.NextAttemptAt(1, Now, Far, lastReply: null).Delay); // no reply: timeout or refusal
        Assert.Equal(TimeSpan.FromMinutes(5), s.NextAttemptAt(2, Now, Far, Reply(421, null, "closing channel")).Delay);
        Assert.Equal(TimeSpan.FromMinutes(2), s.NextAttemptAt(1, Now, Far, Reply(451, "4.3.0", "local error")).Delay);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(7)]
    [InlineData(20)]
    public void Greylisting_retries_in_five_to_fifteen_minutes(int attempt)
    {
        var reply = Reply(450, "4.2.0", "Recipient address rejected: Greylisted, please try again later");
        foreach (double r in new[] { 0.0, 0.25, 0.5, 0.75, 0.9999 })
        {
            var s = new RetrySchedule(random: new FixedRandom(r));
            var d = s.NextAttemptAt(attempt, Now, Far, reply);
            Assert.InRange(d.Delay, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(15));
            Assert.Equal("greylisting", d.Reason);
        }
    }

    [Fact]
    public void Throttling_backs_off_longer_than_the_normal_ladder()
    {
        var s = NoJitter();
        var throttled = Reply(421, "4.7.0", "Try again later, rate limited");
        Assert.Equal(TimeSpan.FromMinutes(10), s.NextAttemptAt(1, Now, Far, throttled).Delay); // 2 x 2m is below the 10m floor
        Assert.Equal(TimeSpan.FromMinutes(30), s.NextAttemptAt(3, Now, Far, throttled).Delay); // 2 x 15m
        Assert.Equal(TimeSpan.FromHours(8), s.NextAttemptAt(7, Now, Far, throttled).Delay); // capped at MaxDelay
        Assert.Equal(TimeSpan.FromHours(8), s.NextAttemptAt(30, Now, Far, throttled).Delay);
    }

    [Fact]
    public void Throttle_class_overload_is_honoured_without_a_reply()
    {
        var s = NoJitter();
        Assert.Equal(TimeSpan.FromMinutes(30), s.NextAttemptAt(3, Now, Far, DeliveryClass.TransientThrottle).Delay);
    }

    [Theory]
    [InlineData("Please try again in 20 minutes", 20 * 60)]
    [InlineData("rate limited, Retry-After: 1800", 1800)]
    [InlineData("Greylisted, try again in 600 seconds", 600)]
    public void Server_hint_raises_the_delay(string text, int expectedSeconds)
    {
        var s = NoJitter();
        var d = s.NextAttemptAt(2, Now, Far, Reply(451, "4.3.0", text));
        Assert.Equal(expectedSeconds, d.Delay.TotalSeconds, 0.5);
        Assert.Equal("server retry hint", d.Reason);
    }

    [Fact]
    public void Server_hint_never_shortens_the_scheduled_delay()
    {
        var s = NoJitter();
        var d = s.NextAttemptAt(5, Now, Far, Reply(451, "4.3.0", "try again in 90 seconds"));
        Assert.Equal(TimeSpan.FromHours(1), d.Delay);
    }

    [Fact]
    public void Server_hint_is_bounded()
    {
        var s = NoJitter();
        var huge = s.NextAttemptAt(1, Now, Far, Reply(451, "4.3.0", "try again in 48 hours"));
        Assert.Equal(TimeSpan.FromHours(4), huge.Delay);
        var tiny = s.NextAttemptAt(1, Now, Far, Reply(451, "4.3.0", "try again in 1 seconds"));
        Assert.Equal(TimeSpan.FromMinutes(2), tiny.Delay); // the 30 s minimum does not beat the 2 m ladder
    }

    [Fact]
    public void Hint_is_applied_after_jitter_so_it_is_never_undercut()
    {
        var s = new RetrySchedule(random: new FixedRandom(0.0)); // maximum negative jitter
        var d = s.NextAttemptAt(1, Now, Far, Reply(451, "4.3.0", "try again in 2 minutes"));
        Assert.Equal(TimeSpan.FromMinutes(2), d.Delay);
    }

    [Fact]
    public void Raw_reply_overload_classifies_with_the_stage()
    {
        var s = NoJitter();
        var d = s.NextAttemptAt(1, Now, Far, Reply(450, null, "Greylisted"), SmtpStage.RcptTo);
        Assert.Equal(TimeSpan.FromMinutes(5), d.Delay);
    }

    [Fact]
    public void Custom_ladder_is_used()
    {
        var s = NoJitter(new RetryScheduleOptions
        {
            Delays = [TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(20)],
            RepeatInterval = TimeSpan.FromSeconds(30),
            FirstConnectionRetryDelay = TimeSpan.FromSeconds(5),
        });
        Assert.Equal(TimeSpan.FromSeconds(10), s.GetBaseDelay(1));
        Assert.Equal(TimeSpan.FromSeconds(20), s.GetBaseDelay(2));
        Assert.Equal(TimeSpan.FromSeconds(30), s.GetBaseDelay(3));
        Assert.Equal(TimeSpan.FromSeconds(5), s.NextAttemptAt(1, Now, Far, lastReply: null).Delay);
    }

    [Fact]
    public void Invalid_options_are_rejected()
    {
        Assert.Throws<ArgumentException>(() => new RetrySchedule(new RetryScheduleOptions { Delays = [] }));
        Assert.Throws<ArgumentException>(() => new RetrySchedule(new RetryScheduleOptions { Delays = [TimeSpan.Zero] }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new RetrySchedule(new RetryScheduleOptions { JitterFraction = 1.5 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new RetrySchedule(new RetryScheduleOptions { ThrottleMultiplier = 0.5 }));
        Assert.Throws<ArgumentException>(() => new RetrySchedule(new RetryScheduleOptions { GreylistMaxDelay = TimeSpan.FromMinutes(1) }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new RetrySchedule(new RetryScheduleOptions { RepeatInterval = TimeSpan.Zero }));
    }

    [Theory]
    [InlineData("Retry-After: 120", 120)]
    [InlineData("retry-after:120", 120)]
    [InlineData("Please retry after 5 minutes.", 300)]
    [InlineData("try again in 60 seconds", 60)]
    [InlineData("Try again in about 10 min", 600)]
    [InlineData("try again after 2 hours", 7200)]
    [InlineData("come back in 15 mins", 900)]
    [InlineData("please wait 30 secs before retrying", 30)]
    [InlineData("Greylisted for 5 minutes: try again in 5m", 300)]
    [InlineData("try again in 1 day", 86400)]
    public void Retry_after_hint_parses(string text, int seconds)
    {
        Assert.True(RetryAfterHint.TryParse(text, out var hint));
        Assert.Equal(seconds, hint.TotalSeconds);
    }

    [Theory]
    [InlineData("")]
    [InlineData("try again later")]
    [InlineData("service unavailable")]
    [InlineData("try again in a while")]
    [InlineData("retry after the weekend. 5 minutes")]
    [InlineData("please wait 30 parsecs")]
    [InlineData("wait")]
    public void Retry_after_hint_ignores_text_without_a_hint(string text) => Assert.False(RetryAfterHint.TryParse(text, out _));
}
