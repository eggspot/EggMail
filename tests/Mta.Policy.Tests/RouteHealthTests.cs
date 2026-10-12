namespace Mta.Policy.Tests;

public class RouteHealthTests
{
    private static readonly RouteHealthKey Direct = RouteHealthKey.ForRoute("direct");

    private static (RouteHealth Health, FakeClock Clock) Create(int threshold = 3, double multiplier = 2.0)
    {
        var clock = new FakeClock();
        var health = new RouteHealth(clock, new RouteHealthOptions
        {
            FailureThreshold = threshold,
            Cooldown = TimeSpan.FromMinutes(5),
            CooldownMultiplier = multiplier,
            MaxCooldown = TimeSpan.FromMinutes(30),
            ProbeTimeout = TimeSpan.FromMinutes(1),
            FailureStaleAfter = TimeSpan.FromMinutes(10),
            IdleEviction = TimeSpan.FromHours(1),
        });
        return (health, clock);
    }

    [Fact]
    public void Unknown_targets_are_allowed()
    {
        var (h, _) = Create();
        Assert.Equal(RouteAdmission.Allowed, h.TryAdmit(Direct, out _));
        Assert.Equal(CircuitState.Closed, h.GetSnapshot(Direct).State);
    }

    [Fact]
    public void Opens_after_threshold_consecutive_failures()
    {
        var (h, clock) = Create(threshold: 3);
        h.ReportFailure(Direct, "timeout");
        h.ReportFailure(Direct);
        Assert.Equal(RouteAdmission.Allowed, h.TryAdmit(Direct));
        h.ReportFailure(Direct, "connect timeout");

        Assert.Equal(RouteAdmission.Rejected, h.TryAdmit(Direct, out var retryAt));
        Assert.Equal(clock.UtcNow.AddMinutes(5), retryAt);
        var snap = h.GetSnapshot(Direct);
        Assert.Equal(CircuitState.Open, snap.State);
        Assert.Equal(3, snap.ConsecutiveFailures);
        Assert.Equal("connect timeout", snap.LastError);
        Assert.Equal(clock.UtcNow.AddMinutes(5), snap.RetryAt);
    }

    [Fact]
    public void A_success_resets_the_failure_streak()
    {
        var (h, _) = Create(threshold: 3);
        h.ReportFailure(Direct);
        h.ReportFailure(Direct);
        h.ReportSuccess(Direct);
        h.ReportFailure(Direct);
        h.ReportFailure(Direct);
        Assert.Equal(RouteAdmission.Allowed, h.TryAdmit(Direct));
        Assert.Equal(2, h.GetSnapshot(Direct).ConsecutiveFailures);
    }

    [Fact]
    public void Stale_failures_do_not_accumulate()
    {
        var (h, clock) = Create(threshold: 3);
        h.ReportFailure(Direct);
        h.ReportFailure(Direct);
        clock.Advance(TimeSpan.FromMinutes(11));
        h.ReportFailure(Direct);
        Assert.Equal(RouteAdmission.Allowed, h.TryAdmit(Direct));
        Assert.Equal(1, h.GetSnapshot(Direct).ConsecutiveFailures);
    }

    [Fact]
    public void After_the_cooldown_exactly_one_probe_is_admitted()
    {
        var (h, clock) = Create(threshold: 1);
        h.ReportFailure(Direct);
        clock.Advance(TimeSpan.FromMinutes(4));
        Assert.Equal(RouteAdmission.Rejected, h.TryAdmit(Direct));
        clock.Advance(TimeSpan.FromMinutes(1));

        Assert.Equal(CircuitState.HalfOpen, h.GetSnapshot(Direct).State);
        Assert.Equal(RouteAdmission.Probe, h.TryAdmit(Direct));
        Assert.Equal(RouteAdmission.Rejected, h.TryAdmit(Direct, out var retryAt));
        Assert.Equal(clock.UtcNow.AddMinutes(1), retryAt);
    }

    [Fact]
    public void Successful_probe_closes_the_circuit()
    {
        var (h, clock) = Create(threshold: 1);
        h.ReportFailure(Direct);
        clock.Advance(TimeSpan.FromMinutes(5));
        Assert.Equal(RouteAdmission.Probe, h.TryAdmit(Direct));
        h.ReportSuccess(Direct);
        Assert.Equal(RouteAdmission.Allowed, h.TryAdmit(Direct));
        Assert.Equal(CircuitState.Closed, h.GetSnapshot(Direct).State);
        Assert.Equal(0, h.GetSnapshot(Direct).ConsecutiveFailures);
    }

    [Fact]
    public void Failed_probe_reopens_with_a_longer_cooldown_up_to_the_maximum()
    {
        var (h, clock) = Create(threshold: 1);
        h.ReportFailure(Direct);
        TimeSpan[] expected = [TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(20), TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(30)];
        TimeSpan cooldown = TimeSpan.FromMinutes(5);
        foreach (TimeSpan next in expected)
        {
            clock.Advance(cooldown);
            Assert.Equal(RouteAdmission.Probe, h.TryAdmit(Direct));
            h.ReportFailure(Direct, "still down");
            Assert.Equal(RouteAdmission.Rejected, h.TryAdmit(Direct, out var retryAt));
            Assert.Equal(clock.UtcNow + next, retryAt);
            cooldown = next;
        }
    }

    [Fact]
    public void A_probe_that_never_reports_back_frees_the_slot()
    {
        var (h, clock) = Create(threshold: 1);
        h.ReportFailure(Direct);
        clock.Advance(TimeSpan.FromMinutes(5));
        Assert.Equal(RouteAdmission.Probe, h.TryAdmit(Direct));
        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal(RouteAdmission.Probe, h.TryAdmit(Direct));
    }

    [Fact]
    public void IsAvailable_never_claims_the_probe()
    {
        var (h, clock) = Create(threshold: 1);
        h.ReportFailure(Direct);
        Assert.False(h.IsAvailable(Direct, out var retryAt));
        Assert.Equal(clock.UtcNow.AddMinutes(5), retryAt);
        clock.Advance(TimeSpan.FromMinutes(5));
        Assert.True(h.IsAvailable(Direct, out _));
        Assert.True(h.IsAvailable(Direct, out _));
        Assert.Equal(RouteAdmission.Probe, h.TryAdmit(Direct));
        Assert.False(h.IsAvailable(Direct, out _));
    }

    [Fact]
    public void Routes_and_mx_hosts_are_separate_breakers()
    {
        var (h, _) = Create(threshold: 1);
        h.ReportFailure(RouteHealthKey.ForMxHost("mx1.example.com"));
        Assert.Equal(RouteAdmission.Rejected, h.TryAdmit(RouteHealthKey.ForMxHost("MX1.example.com")));
        Assert.Equal(RouteAdmission.Allowed, h.TryAdmit(RouteHealthKey.ForMxHost("mx2.example.com")));
        Assert.Equal(RouteAdmission.Allowed, h.TryAdmit(RouteHealthKey.ForRoute("mx1.example.com")));
    }

    [Fact]
    public void Snapshots_expose_state_for_the_dashboard()
    {
        var (h, clock) = Create(threshold: 2);
        h.ReportFailure(Direct, "x");
        h.ReportFailure(Direct, "y");
        h.ReportSuccess(Direct);
        var snap = h.GetSnapshot(Direct);
        Assert.Equal(2, snap.TotalFailures);
        Assert.Equal(1, snap.TotalSuccesses);
        Assert.Equal(clock.UtcNow, snap.LastSuccessAt);
        Assert.Equal("y", snap.LastError);
        Assert.Single(h.GetSnapshots());
    }

    [Fact]
    public void Healthy_idle_entries_are_evicted_but_open_ones_are_kept()
    {
        var (h, clock) = Create(threshold: 2);
        h.ReportFailure(RouteHealthKey.ForMxHost("flaky.example"));
        h.ReportFailure(RouteHealthKey.ForMxHost("dead.example"));
        h.ReportFailure(RouteHealthKey.ForMxHost("dead.example"));
        clock.Advance(TimeSpan.FromHours(2));
        Assert.Equal(1, h.Sweep());
        Assert.Equal(1, h.TrackedCount);
        Assert.Equal(RouteAdmission.Probe, h.TryAdmit(RouteHealthKey.ForMxHost("dead.example")));
    }

    [Fact]
    public void Parallel_admission_of_a_half_open_circuit_grants_exactly_one_probe()
    {
        var (h, clock) = Create(threshold: 1);
        h.ReportFailure(Direct);
        clock.Advance(TimeSpan.FromMinutes(5));
        int probes = 0;
        int allowed = 0;
        Parallel.For(0, 64, new ParallelOptions { MaxDegreeOfParallelism = 32 }, _ =>
        {
            var a = h.TryAdmit(Direct);
            if (a == RouteAdmission.Probe)
            {
                Interlocked.Increment(ref probes);
            }
            else if (a == RouteAdmission.Allowed)
            {
                Interlocked.Increment(ref allowed);
            }
        });

        Assert.Equal(1, probes);
        Assert.Equal(0, allowed);
    }

    [Fact]
    public void Parallel_failures_open_the_circuit_exactly_once()
    {
        var (h, _) = Create(threshold: 5);
        Parallel.For(0, 200, new ParallelOptions { MaxDegreeOfParallelism = 16 }, _ => h.ReportFailure(Direct));
        Assert.Equal(CircuitState.Open, h.GetSnapshot(Direct).State);
        Assert.Equal(200, h.GetSnapshot(Direct).TotalFailures);
    }

    [Fact]
    public void Invalid_options_are_rejected()
    {
        var clock = new FakeClock();
        Assert.Throws<ArgumentException>(() => new RouteHealth(clock, new RouteHealthOptions { FailureThreshold = 0 }));
        Assert.Throws<ArgumentException>(() => new RouteHealth(clock, new RouteHealthOptions { CooldownMultiplier = 0.5 }));
        Assert.Throws<ArgumentException>(() => new RouteHealth(clock, new RouteHealthOptions { Cooldown = TimeSpan.FromHours(2) }));
    }
}
