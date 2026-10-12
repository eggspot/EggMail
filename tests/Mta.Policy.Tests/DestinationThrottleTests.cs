namespace Mta.Policy.Tests;

public class DestinationThrottleTests
{
    private static DestinationThrottleOptions Opts(
        int maxConcurrent = 8,
        double maxPerMinute = 120,
        int perConnection = 3,
        int initialConcurrent = 8,
        double initialRate = 120,
        int successesPerIncrease = 5) => new()
    {
        Defaults = new ThrottleLimits(maxConcurrent, maxPerMinute, perConnection),
        InitialConcurrentConnections = initialConcurrent,
        InitialMessagesPerMinute = initialRate,
        SuccessesPerIncrease = successesPerIncrease,
        BurstSeconds = 10,
        Cooldown = TimeSpan.FromSeconds(60),
    };

    private static readonly ThrottleKey Gmail = new("gmail.com");

    [Fact]
    public void Concurrency_limit_is_enforced_and_released_on_dispose()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, Opts(maxConcurrent: 3, initialConcurrent: 3));
        var leases = new List<ThrottleLease>();
        for (int i = 0; i < 3; i++)
        {
            var r = t.TryAcquire(Gmail);
            Assert.True(r.Acquired);
            leases.Add(r.Lease);
        }

        var denied = t.TryAcquire(Gmail);
        Assert.False(denied.Acquired);
        Assert.Equal(ThrottleDenial.ConcurrencyLimit, denied.Denial);
        Assert.True(denied.RetryAfter > TimeSpan.Zero);

        leases[0].Dispose();
        Assert.True(t.TryAcquire(Gmail).Acquired);
    }

    [Fact]
    public void Dispose_is_idempotent()
    {
        var t = new DestinationThrottle(new FakeClock(), Opts(maxConcurrent: 1, initialConcurrent: 1));
        var lease = t.TryAcquire(Gmail).Lease!;
        lease.Dispose();
        lease.Dispose();
        var a = t.TryAcquire(Gmail);
        Assert.True(a.Acquired);
        Assert.False(t.TryAcquire(Gmail).Acquired); // still exactly one slot
    }

    [Fact]
    public void Rate_bucket_limits_bursts_and_refills_over_time()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, Opts(maxConcurrent: 1000, initialConcurrent: 1000, maxPerMinute: 60, initialRate: 60));

        // 60 per minute with a 10 second burst: capacity 10 tokens.
        for (int i = 0; i < 10; i++)
        {
            Assert.True(t.TryAcquire(Gmail).Acquired, $"token {i}");
        }

        var denied = t.TryAcquire(Gmail);
        Assert.Equal(ThrottleDenial.RateLimit, denied.Denial);
        Assert.InRange(denied.RetryAfter.TotalMilliseconds, 990, 1010);

        clock.Advance(TimeSpan.FromMilliseconds(500));
        Assert.InRange(t.TryAcquire(Gmail).RetryAfter.TotalMilliseconds, 490, 510);

        clock.Advance(TimeSpan.FromMilliseconds(500));
        Assert.True(t.TryAcquire(Gmail).Acquired);
        Assert.False(t.TryAcquire(Gmail).Acquired);
    }

    [Fact]
    public void Bucket_never_holds_more_than_its_capacity()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, Opts(maxConcurrent: 1000, initialConcurrent: 1000, maxPerMinute: 60, initialRate: 60));
        t.TryAcquire(Gmail);
        clock.Advance(TimeSpan.FromHours(5));
        int granted = 0;
        while (t.TryAcquire(Gmail).Acquired)
        {
            granted++;
            Assert.True(granted <= 10);
        }

        Assert.Equal(10, granted);
    }

    [Fact]
    public void Clock_moving_backwards_does_not_mint_tokens()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, Opts(maxConcurrent: 1000, initialConcurrent: 1000, maxPerMinute: 60, initialRate: 60));
        for (int i = 0; i < 10; i++)
        {
            t.TryAcquire(Gmail);
        }

        clock.Advance(TimeSpan.FromHours(-1));
        Assert.False(t.TryAcquire(Gmail).Acquired);
    }

    [Fact]
    public void Messages_per_connection_cap_applies_to_a_lease()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, Opts(perConnection: 3));
        using var lease = t.TryAcquire(Gmail).Lease!;
        Assert.Equal(1, lease.MessagesTaken);
        Assert.False(lease.IsExhausted);
        Assert.True(lease.TryTakeMessage(out _));
        Assert.True(lease.TryTakeMessage(out _));
        Assert.True(lease.IsExhausted);
        Assert.False(lease.TryTakeMessage(out var wait));
        Assert.Equal(TimeSpan.Zero, wait); // exhausted: close the connection rather than wait
        Assert.Equal(3, lease.MessagesTaken);
    }

    [Fact]
    public void Additional_messages_consume_rate_tokens()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, Opts(maxConcurrent: 10, initialConcurrent: 10, perConnection: 1000, maxPerMinute: 60, initialRate: 60));
        using var lease = t.TryAcquire(Gmail).Lease!;
        int taken = 0;
        while (lease.TryTakeMessage(out _))
        {
            taken++;
        }

        Assert.Equal(9, taken); // 10 token bucket, one spent by TryAcquire
        Assert.False(lease.TryTakeMessage(out var wait));
        Assert.True(wait > TimeSpan.Zero);
        Assert.False(lease.IsExhausted);
    }

    [Fact]
    public void Throttle_signal_halves_concurrency_and_rate_down_to_the_floor()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, Opts(maxConcurrent: 8, initialConcurrent: 8, maxPerMinute: 120, initialRate: 120));
        t.TryAcquire(Gmail).Lease!.Dispose();

        t.Report(Gmail, ThrottleSignal.Throttled);
        var s = t.GetSnapshot(Gmail)!;
        Assert.Equal(4, s.ConcurrencyLimit);
        Assert.Equal(60, s.MessagesPerMinute, 3);
        Assert.True(s.Penalized);

        // Floors: concurrency 1, 6 messages per minute.
        for (int i = 0; i < 12; i++)
        {
            clock.Advance(TimeSpan.FromMinutes(2));
            t.Report(Gmail, ThrottleSignal.Throttled);
        }

        s = t.GetSnapshot(Gmail)!;
        Assert.Equal(1, s.ConcurrencyLimit);
        Assert.Equal(6, s.MessagesPerMinute, 3);
    }

    [Fact]
    public void Decrease_happens_once_per_cooldown_even_for_a_burst_of_signals()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, Opts(maxConcurrent: 16, initialConcurrent: 16, maxPerMinute: 120, initialRate: 120));
        t.TryAcquire(Gmail).Lease!.Dispose();
        for (int i = 0; i < 20; i++)
        {
            t.Report(Gmail, ThrottleSignal.Throttled);
        }

        Assert.Equal(8, t.GetSnapshot(Gmail)!.ConcurrencyLimit);
        clock.Advance(TimeSpan.FromSeconds(61));
        t.Report(Gmail, ThrottleSignal.Throttled);
        Assert.Equal(4, t.GetSnapshot(Gmail)!.ConcurrencyLimit);
    }

    [Fact]
    public void Successes_increase_limits_additively_after_the_cooldown_up_to_the_ceiling()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, Opts(maxConcurrent: 8, initialConcurrent: 8, maxPerMinute: 120, initialRate: 120, successesPerIncrease: 5));
        t.TryAcquire(Gmail).Lease!.Dispose();
        t.Report(Gmail, ThrottleSignal.Throttled); // 4 conns, 60/min

        // During cooldown successes do not increase.
        for (int i = 0; i < 10; i++)
        {
            t.Report(Gmail, ThrottleSignal.Success);
        }

        Assert.Equal(4, t.GetSnapshot(Gmail)!.ConcurrencyLimit);

        clock.Advance(TimeSpan.FromSeconds(61));
        for (int i = 0; i < 5; i++)
        {
            t.Report(Gmail, ThrottleSignal.Success);
        }

        var s = t.GetSnapshot(Gmail)!;
        Assert.Equal(5, s.ConcurrencyLimit);
        Assert.Equal(72, s.MessagesPerMinute, 3); // +10% of the 120/min ceiling

        for (int i = 0; i < 5 * 20; i++)
        {
            t.Report(Gmail, ThrottleSignal.Success);
        }

        s = t.GetSnapshot(Gmail)!;
        Assert.Equal(8, s.ConcurrencyLimit);
        Assert.Equal(120, s.MessagesPerMinute, 3);
        Assert.False(s.Penalized);
    }

    [Fact]
    public void A_throttle_signal_resets_the_success_streak()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, Opts(maxConcurrent: 8, initialConcurrent: 4, successesPerIncrease: 5));
        t.TryAcquire(Gmail).Lease!.Dispose();
        for (int i = 0; i < 4; i++)
        {
            t.Report(Gmail, ThrottleSignal.Success);
        }

        t.Report(Gmail, ThrottleSignal.Throttled);
        clock.Advance(TimeSpan.FromMinutes(5));
        t.Report(Gmail, ThrottleSignal.Success); // would have been the 5th without the reset
        Assert.Equal(2, t.GetSnapshot(Gmail)!.ConcurrencyLimit);
    }

    [Fact]
    public void Connection_failure_bursts_decrease_but_isolated_failures_do_not()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, Opts(maxConcurrent: 8, initialConcurrent: 8));
        t.TryAcquire(Gmail).Lease!.Dispose();

        t.Report(Gmail, ThrottleSignal.ConnectionFailure);
        t.Report(Gmail, ThrottleSignal.ConnectionFailure);
        Assert.Equal(8, t.GetSnapshot(Gmail)!.ConcurrencyLimit);

        clock.Advance(TimeSpan.FromMinutes(5)); // window expired: the count restarts
        t.Report(Gmail, ThrottleSignal.ConnectionFailure);
        t.Report(Gmail, ThrottleSignal.ConnectionFailure);
        Assert.Equal(8, t.GetSnapshot(Gmail)!.ConcurrencyLimit);

        t.Report(Gmail, ThrottleSignal.ConnectionFailure); // third within 30 s
        Assert.Equal(4, t.GetSnapshot(Gmail)!.ConcurrencyLimit);
    }

    [Fact]
    public void A_success_clears_the_connection_failure_count()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, Opts(maxConcurrent: 8, initialConcurrent: 8));
        t.TryAcquire(Gmail).Lease!.Dispose();
        t.Report(Gmail, ThrottleSignal.ConnectionFailure);
        t.Report(Gmail, ThrottleSignal.ConnectionFailure);
        t.Report(Gmail, ThrottleSignal.Success);
        t.Report(Gmail, ThrottleSignal.ConnectionFailure);
        Assert.Equal(8, t.GetSnapshot(Gmail)!.ConcurrencyLimit);
    }

    [Fact]
    public void Lease_report_feeds_the_same_state()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, Opts(maxConcurrent: 8, initialConcurrent: 8));
        using var lease = t.TryAcquire(Gmail).Lease!;
        lease.Report(ThrottleSignal.Throttled);
        Assert.Equal(4, t.GetSnapshot(Gmail)!.ConcurrencyLimit);
    }

    [Fact]
    public void Keys_are_independent_and_case_insensitive_and_route_specific()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, Opts(maxConcurrent: 1, initialConcurrent: 1));
        using var a = t.TryAcquire(new ThrottleKey("Gmail.com")).Lease!;
        Assert.False(t.TryAcquire(new ThrottleKey("gmail.COM")).Acquired);
        Assert.True(t.TryAcquire(new ThrottleKey("outlook.com")).Acquired);
        Assert.True(t.TryAcquire(new ThrottleKey("gmail.com", "relay-a")).Acquired);
        Assert.False(t.TryAcquire(new ThrottleKey("gmail.com", "RELAY-A")).Acquired);
        Assert.Equal(new ThrottleKey("A.com", "b"), new ThrottleKey("a.COM", "B"));
        Assert.NotEqual(new ThrottleKey("a.com"), new ThrottleKey("a.com", "x"));
    }

    [Fact]
    public void Per_destination_overrides_set_stricter_ceilings()
    {
        var clock = new FakeClock();
        var options = new DestinationThrottleOptions
        {
            Defaults = new ThrottleLimits(8, 120, 100),
            Overrides = new Dictionary<string, ThrottleLimits>(StringComparer.OrdinalIgnoreCase) { ["yahoo.com"] = new ThrottleLimits(2, 30, 5) },
        };
        var t = new DestinationThrottle(clock, options);
        var y = new List<ThrottleLease>();
        while (true)
        {
            var r = t.TryAcquire(new ThrottleKey("Yahoo.com"));
            if (!r.Acquired)
            {
                break;
            }

            y.Add(r.Lease);
        }

        Assert.Equal(2, y.Count);
        Assert.Equal(2, t.GetSnapshot(new ThrottleKey("yahoo.com"))!.ConcurrencyCeiling);
        Assert.Equal(30, t.GetSnapshot(new ThrottleKey("yahoo.com"))!.MessagesPerMinuteCeiling);
    }

    [Fact]
    public void Idle_keys_are_evicted_and_active_ones_are_kept()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, Opts());
        var held = t.TryAcquire(new ThrottleKey("held.example")).Lease!;
        for (int i = 0; i < 1000; i++)
        {
            t.TryAcquire(new ThrottleKey($"d{i}.example")).Lease!.Dispose();
        }

        Assert.Equal(1001, t.TrackedKeyCount);
        clock.Advance(TimeSpan.FromMinutes(14));
        Assert.Equal(0, t.Sweep());
        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(1000, t.Sweep());
        Assert.Equal(1, t.TrackedKeyCount);
        Assert.NotNull(t.GetSnapshot(new ThrottleKey("held.example")));
        held.Dispose();
    }

    [Fact]
    public void Acquire_sweeps_opportunistically()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, Opts());
        for (int i = 0; i < 100; i++)
        {
            t.TryAcquire(new ThrottleKey($"d{i}.example")).Lease!.Dispose();
        }

        clock.Advance(TimeSpan.FromMinutes(20));
        t.TryAcquire(new ThrottleKey("fresh.example")).Lease!.Dispose();
        Assert.Equal(1, t.TrackedKeyCount);
    }

    [Fact]
    public void Tracked_keys_are_bounded_even_without_time_passing()
    {
        var clock = new FakeClock();
        var options = new DestinationThrottleOptions { MaxTrackedKeys = 50 };
        var t = new DestinationThrottle(clock, options);
        for (int i = 0; i < 2000; i++)
        {
            t.TryAcquire(new ThrottleKey($"d{i}.example")).Lease!.Dispose();
            Assert.True(t.TrackedKeyCount <= 51, $"count {t.TrackedKeyCount} at {i}");
        }
    }

    [Fact]
    public void Held_leases_pin_their_keys_when_the_cap_is_exceeded()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, new DestinationThrottleOptions { MaxTrackedKeys = 5 });
        var leases = new List<ThrottleLease>();
        for (int i = 0; i < 20; i++)
        {
            leases.Add(t.TryAcquire(new ThrottleKey($"d{i}.example")).Lease!);
        }

        Assert.Equal(20, t.TrackedKeyCount); // bounded by the number of in-use keys
        foreach (var l in leases)
        {
            l.Dispose();
        }

        t.TryAcquire(new ThrottleKey("x.example")).Lease!.Dispose();
        Assert.True(t.TrackedKeyCount <= 6);
    }

    [Fact]
    public void Parallel_acquire_never_exceeds_the_concurrency_limit()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, new DestinationThrottleOptions
        {
            Defaults = new ThrottleLimits(5, 1_000_000, 1000),
            InitialConcurrentConnections = 5,
            InitialMessagesPerMinute = 1_000_000,
            BurstSeconds = 1000,
        });
        int inFlight = 0;
        int maxSeen = 0;
        long acquired = 0;
        Parallel.For(0, 32, new ParallelOptions { MaxDegreeOfParallelism = 32 }, _ =>
        {
            for (int i = 0; i < 3000; i++)
            {
                var r = t.TryAcquire(Gmail);
                if (!r.Acquired)
                {
                    continue;
                }

                int now = Interlocked.Increment(ref inFlight);
                int seen;
                while (now > (seen = Volatile.Read(ref maxSeen)) && Interlocked.CompareExchange(ref maxSeen, now, seen) != seen)
                {
                }

                Interlocked.Increment(ref acquired);
                Thread.SpinWait(20);
                Interlocked.Decrement(ref inFlight);
                r.Lease.Dispose();
            }
        });

        Assert.True(maxSeen <= 5, $"saw {maxSeen} concurrent leases");
        Assert.True(acquired > 0);
        Assert.Equal(0, t.GetSnapshot(Gmail)!.InUse);
    }

    [Fact]
    public void Parallel_acquire_never_exceeds_the_token_bucket()
    {
        var clock = new FakeClock(); // time never advances: exactly the burst capacity may be granted
        var t = new DestinationThrottle(clock, Opts(maxConcurrent: 10_000, initialConcurrent: 10_000, maxPerMinute: 600, initialRate: 600));
        long granted = 0;
        Parallel.For(0, 16, new ParallelOptions { MaxDegreeOfParallelism = 16 }, _ =>
        {
            for (int i = 0; i < 500; i++)
            {
                if (t.TryAcquire(Gmail).Acquired)
                {
                    Interlocked.Increment(ref granted);
                }
            }
        });

        Assert.Equal(100, granted); // 600/min x 10 s burst
    }

    [Fact]
    public void Parallel_eviction_and_acquire_keep_accounting_consistent()
    {
        var clock = new FakeClock();
        var t = new DestinationThrottle(clock, new DestinationThrottleOptions
        {
            MaxTrackedKeys = 8,
            Defaults = new ThrottleLimits(2, 1_000_000, 100),
            InitialConcurrentConnections = 2,
            InitialMessagesPerMinute = 1_000_000,
            BurstSeconds = 1000,
        });
        var inFlight = new int[16];
        int violations = 0;
        Parallel.For(0, 16, new ParallelOptions { MaxDegreeOfParallelism = 16 }, worker =>
        {
            var rnd = new Random(worker);
            for (int i = 0; i < 3000; i++)
            {
                int k = rnd.Next(16);
                var r = t.TryAcquire(new ThrottleKey("k" + k));
                if (!r.Acquired)
                {
                    continue;
                }

                if (Interlocked.Increment(ref inFlight[k]) > 2)
                {
                    Interlocked.Increment(ref violations);
                }

                Thread.SpinWait(10);
                Interlocked.Decrement(ref inFlight[k]);
                r.Lease.Dispose();
                if (i % 50 == 0)
                {
                    t.Sweep();
                }
            }
        });

        Assert.Equal(0, violations);
    }

    [Fact]
    public void Signal_mapping_from_classification()
    {
        Assert.Equal(ThrottleSignal.Throttled, DestinationThrottle.SignalFor(DeliveryClass.TransientThrottle));
        Assert.Equal(ThrottleSignal.Throttled, DestinationThrottle.SignalFor(DeliveryClass.Transient, 421));
        Assert.Equal(ThrottleSignal.Success, DestinationThrottle.SignalFor(DeliveryClass.Delivered, 250));
        Assert.Null(DestinationThrottle.SignalFor(DeliveryClass.PermanentRecipient, 550));
        Assert.Null(DestinationThrottle.SignalFor(DeliveryClass.TransientGreylist, 450));
    }

    [Fact]
    public void Snapshots_list_all_keys()
    {
        var t = new DestinationThrottle(new FakeClock(), Opts());
        t.TryAcquire(new ThrottleKey("a.example")).Lease!.Dispose();
        t.TryAcquire(new ThrottleKey("b.example")).Lease!.Dispose();
        Assert.Equal(2, t.GetSnapshots().Count);
        Assert.Null(t.GetSnapshot(new ThrottleKey("nope.example")));
    }

    [Fact]
    public void Invalid_options_are_rejected()
    {
        var clock = new FakeClock();
        Assert.Throws<ArgumentException>(() => new DestinationThrottle(clock, new DestinationThrottleOptions { Defaults = new ThrottleLimits(0, 10, 10) }));
        Assert.Throws<ArgumentException>(() => new DestinationThrottle(clock, new DestinationThrottleOptions { DecreaseFactor = 1.5 }));
        Assert.Throws<ArgumentException>(() => new DestinationThrottle(clock, new DestinationThrottleOptions { MinConcurrentConnections = 0 }));
        Assert.Throws<ArgumentNullException>(() => new DestinationThrottle(null!));
    }
}
