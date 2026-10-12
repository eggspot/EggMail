using Mta.Storage;

namespace Mta.Policy.Tests;

public class VerificationScheduleTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 12, 8, 30, 0, TimeSpan.Zero);
    private readonly VerificationSchedule _schedule = new();

    private const VerificationCheckResult Ok = VerificationCheckResult.AllRecordsOk;
    private const VerificationCheckResult Bad = VerificationCheckResult.RecordsNotOk;
    private const VerificationCheckResult Dns = VerificationCheckResult.DnsTemporaryFailure;

    private static TimeSpan M(double minutes) => TimeSpan.FromMinutes(minutes);

    private static TimeSpan H(double hours) => TimeSpan.FromHours(hours);

    private static object?[] Row(
        DomainStatus status, int failures, TimeSpan age, TimeSpan? tfAge, bool paused, VerificationCheckResult result,
        DomainStatus expectedStatus, int expectedFailures, bool expectedTfSince, bool expectedPaused, TimeSpan expectedNext, bool expectedChanged) =>
        [status, failures, age, tfAge, paused, result, expectedStatus, expectedFailures, expectedTfSince, expectedPaused, expectedNext, expectedChanged];

    public static IEnumerable<object?[]> Transitions()
    {
        const DomainStatus P = DomainStatus.Pending;
        const DomainStatus V = DomainStatus.Verifying;
        const DomainStatus Ver = DomainStatus.Verified;
        const DomainStatus T = DomainStatus.TemporaryFailure;
        const DomainStatus F = DomainStatus.Failed;
        TimeSpan s90 = TimeSpan.FromSeconds(90);

        // Unverified domains: cadence by age since creation (1.5 min for 15 min, 15 min for 24 h, then hourly).
        yield return Row(P, 0, M(1), null, false, Bad, V, 1, false, false, s90, true);
        yield return Row(P, 0, M(1), null, false, Ok, Ver, 0, false, false, H(24), true);
        yield return Row(V, 3, M(10), null, false, Bad, V, 4, false, false, s90, false);
        yield return Row(V, 3, M(14.9), null, false, Bad, V, 4, false, false, s90, false);
        yield return Row(V, 3, M(15), null, false, Bad, V, 4, false, false, M(15), false);
        yield return Row(V, 20, H(16), null, false, Bad, V, 21, false, false, M(15), false);
        yield return Row(V, 20, H(24) + M(14.9), null, false, Bad, V, 21, false, false, M(15), false);
        yield return Row(V, 20, H(24) + M(15), null, false, Bad, V, 21, false, false, H(1), false);
        yield return Row(V, 20, TimeSpan.FromDays(5), null, false, Bad, V, 21, false, false, H(1), false);
        yield return Row(V, 5, M(30), null, false, Ok, Ver, 0, false, false, H(24), true);
        yield return Row(V, 5, TimeSpan.FromDays(9), null, false, Ok, Ver, 0, false, false, H(24), true);

        // DNS temporary failures never worsen anything.
        yield return Row(P, 0, M(1), null, false, Dns, V, 0, false, false, M(5), true);
        yield return Row(V, 2, M(30), null, false, Dns, V, 2, false, false, M(5), false);
        yield return Row(Ver, 1, H(500), null, false, Dns, Ver, 1, false, false, M(5), false);
        yield return Row(T, 4, H(500), H(100), false, Dns, T, 4, true, false, M(5), false);
        yield return Row(F, 9, H(500), H(100), true, Dns, F, 9, true, true, M(5), false);

        // Verified: two consecutive failed checks lead to temporary failure.
        yield return Row(Ver, 0, H(500), null, false, Ok, Ver, 0, false, false, H(24), false);
        yield return Row(Ver, 0, H(500), null, false, Bad, Ver, 1, false, false, M(15), false);
        yield return Row(Ver, 1, H(500), null, false, Bad, T, 2, true, false, H(1), true);
        yield return Row(Ver, 1, H(500), null, false, Ok, Ver, 0, false, false, H(24), false);

        // Temporary failure: back to verified on success, Failed (and paused) once the 72 h grace is over.
        yield return Row(T, 2, H(500), H(10), false, Ok, Ver, 0, false, false, H(24), true);
        yield return Row(T, 2, H(500), H(10), false, Bad, T, 3, true, false, H(1), false);
        yield return Row(T, 2, H(500), H(71) + M(59), false, Bad, T, 3, true, false, H(1), false);
        yield return Row(T, 2, H(500), H(72), false, Bad, F, 3, true, true, H(24), true);
        yield return Row(T, 2, H(500), H(100), false, Bad, F, 3, true, true, H(24), true);
        yield return Row(T, 2, H(500), null, false, Bad, T, 3, true, false, H(1), false); // missing timestamp: start counting now

        // Failed recovers automatically when the records return; the pause set by Failed is lifted.
        yield return Row(F, 9, H(500), H(100), true, Ok, Ver, 0, false, false, H(24), true);
        yield return Row(F, 9, H(500), H(100), true, Bad, F, 10, true, true, H(24), false);

        // A manual pause on a healthy domain is not silently lifted.
        yield return Row(Ver, 0, H(500), null, true, Ok, Ver, 0, false, true, H(24), false);
        yield return Row(T, 2, H(500), H(5), true, Ok, Ver, 0, false, true, H(24), true);
    }

    [Theory]
    [MemberData(nameof(Transitions))]
    public void Check_result_moves_the_domain_through_the_state_machine(
        DomainStatus status, int failures, TimeSpan age, TimeSpan? tfAge, bool paused, VerificationCheckResult result,
        DomainStatus expectedStatus, int expectedFailures, bool expectedTfSince, bool expectedPaused, TimeSpan expectedNext, bool expectedChanged)
    {
        var state = new VerificationState(status, failures, Now - age, tfAge is { } t ? Now - t : null, paused);
        var o = _schedule.Evaluate(state, result, Now);

        Assert.Equal(expectedStatus, o.Status);
        Assert.Equal(expectedFailures, o.ConsecutiveFailures);
        Assert.Equal(expectedTfSince, o.TemporaryFailureSince is not null);
        Assert.Equal(expectedPaused, o.SendingPaused);
        Assert.Equal(Now + expectedNext, o.NextCheckAt);
        Assert.Equal(expectedChanged, o.StatusChanged);
    }

    [Fact]
    public void Temporary_failure_timestamp_is_the_moment_of_the_second_failed_check_and_is_preserved()
    {
        var s = new VerificationState(DomainStatus.Verified, 1, Now.AddDays(-30), null, false);
        var entered = _schedule.Evaluate(s, Bad, Now);
        Assert.Equal(Now, entered.TemporaryFailureSince);

        var later = _schedule.Evaluate(new VerificationState(entered.Status, entered.ConsecutiveFailures, s.CreatedAt, entered.TemporaryFailureSince, false), Bad, Now.AddHours(1));
        Assert.Equal(Now, later.TemporaryFailureSince);
        var failed = _schedule.Evaluate(new VerificationState(later.Status, later.ConsecutiveFailures, s.CreatedAt, later.TemporaryFailureSince, false), Bad, Now.AddHours(72));
        Assert.Equal(DomainStatus.Failed, failed.Status);
        Assert.Equal(Now, failed.TemporaryFailureSince);
    }

    [Fact]
    public void Simulated_outage_runs_the_whole_ladder_verified_temporary_failed_verified()
    {
        var domain = new DomainRecord(Guid.NewGuid(), Guid.NewGuid(), "example.com", DomainStatus.Verified, null, false, Now.AddDays(-40), Now, Now, 0, null, false, null);
        DateTimeOffset t = Now;
        var statuses = new List<DomainStatus> { domain.Status };

        // Records break and stay broken; checks happen exactly when they are due.
        while (domain.Status != DomainStatus.Failed)
        {
            t = domain.NextCheckAt!.Value;
            domain = _schedule.Apply(domain, Bad, t, "DKIM TXT missing");
            if (domain.Status != statuses[^1])
            {
                statuses.Add(domain.Status);
            }

            Assert.True(t - Now < TimeSpan.FromDays(10), "runaway simulation");
        }

        Assert.Equal([DomainStatus.Verified, DomainStatus.TemporaryFailure, DomainStatus.Failed], statuses);
        Assert.True(domain.SendingPaused);
        Assert.Equal("DKIM TXT missing", domain.LastError);
        Assert.Equal(t, domain.LastCheckedAt);
        TimeSpan inTemporaryFailure = t - domain.TemporaryFailureSince!.Value;
        Assert.InRange(inTemporaryFailure, H(72), H(73)); // first hourly check at or after the grace period

        // Records come back.
        t = domain.NextCheckAt!.Value;
        domain = _schedule.Apply(domain, Ok, t);
        Assert.Equal(DomainStatus.Verified, domain.Status);
        Assert.False(domain.SendingPaused);
        Assert.Null(domain.TemporaryFailureSince);
        Assert.Equal(0, domain.ConsecutiveFailures);
        Assert.Null(domain.LastError);
        Assert.Equal(t + H(24), domain.NextCheckAt);
    }

    [Fact]
    public void Brief_outage_recovers_without_pausing()
    {
        var domain = new DomainRecord(Guid.NewGuid(), Guid.NewGuid(), "example.com", DomainStatus.Verified, null, false, Now.AddDays(-40), Now, Now, 0, null, false, null);
        domain = _schedule.Apply(domain, Bad, Now, "x");
        domain = _schedule.Apply(domain, Bad, domain.NextCheckAt!.Value, "x");
        Assert.Equal(DomainStatus.TemporaryFailure, domain.Status);
        Assert.False(domain.SendingPaused);
        domain = _schedule.Apply(domain, Ok, domain.NextCheckAt!.Value);
        Assert.Equal(DomainStatus.Verified, domain.Status);
        Assert.False(domain.SendingPaused);
    }

    [Fact]
    public void Property_unverified_check_intervals_never_shrink_as_a_domain_ages()
    {
        TimeSpan previous = TimeSpan.Zero;
        for (int minutes = 0; minutes < 60 * 24 * 7; minutes += 7)
        {
            var created = Now.AddMinutes(-minutes);
            TimeSpan interval = _schedule.UnverifiedInterval(created, Now);
            Assert.True(interval >= previous, $"age {minutes} min");
            previous = interval;
        }

        Assert.Equal(H(1), previous);
    }

    [Fact]
    public void Unverified_domain_gets_the_documented_number_of_checks()
    {
        // From creation: ~10 checks in 15 minutes, 96 in the next 24 hours, then hourly.
        var created = Now;
        DateTimeOffset t = created;
        int fast = 0;
        int medium = 0;
        int slow = 0;
        while (t - created < H(24) + M(15) + H(3))
        {
            TimeSpan interval = _schedule.UnverifiedInterval(created, t);
            if (interval == TimeSpan.FromSeconds(90))
            {
                fast++;
            }
            else if (interval == M(15))
            {
                medium++;
            }
            else
            {
                slow++;
            }

            t += interval;
        }

        Assert.Equal(10, fast);
        Assert.InRange(medium, 95, 97);
        Assert.InRange(slow, 3, 4);
        Assert.Equal(created + TimeSpan.FromSeconds(90), _schedule.FirstCheckAt(created));
    }

    [Theory]
    [InlineData(null, true, 0)]
    [InlineData(-100, true, 0)]
    [InlineData(-29, false, 1)]
    [InlineData(-30, true, 0)]
    [InlineData(-31, true, 0)]
    [InlineData(5, true, 0)] // clock went backwards: do not lock the user out
    public void Verify_now_is_limited_to_once_per_30_seconds(int? secondsAgo, bool allowed, int retryAfterSeconds)
    {
        DateTimeOffset? last = secondsAgo is { } s ? Now.AddSeconds(s) : null;
        Assert.Equal(allowed, _schedule.CanVerifyNow(last, Now, out var retryAfter));
        Assert.Equal(retryAfterSeconds, retryAfter.TotalSeconds);
    }

    [Theory]
    [InlineData(DomainStatus.Verified, false, true)]
    [InlineData(DomainStatus.TemporaryFailure, false, true)]
    [InlineData(DomainStatus.Pending, false, false)]
    [InlineData(DomainStatus.Verifying, false, false)]
    [InlineData(DomainStatus.Failed, false, false)]
    [InlineData(DomainStatus.Verified, true, false)]
    [InlineData(DomainStatus.TemporaryFailure, true, false)]
    public void Only_verified_and_temporary_failure_allow_sending(DomainStatus status, bool paused, bool expected) =>
        Assert.Equal(expected, VerificationSchedule.AllowsSending(status, paused));

    [Fact]
    public void Grace_period_and_cadence_are_configurable()
    {
        var custom = new VerificationSchedule(new VerificationScheduleOptions
        {
            TemporaryFailureGrace = H(1),
            VerifiedInterval = H(6),
            FailuresBeforeTemporaryFailure = 3,
            TemporaryFailureInterval = M(10),
        });
        var s = new VerificationState(DomainStatus.Verified, 1, Now.AddDays(-30), null, false);
        var second = custom.Evaluate(s, Bad, Now);
        Assert.Equal(DomainStatus.Verified, second.Status); // needs three failures now
        var third = custom.Evaluate(new VerificationState(DomainStatus.Verified, 2, s.CreatedAt, null, false), Bad, Now);
        Assert.Equal(DomainStatus.TemporaryFailure, third.Status);
        Assert.Equal(Now.AddMinutes(10), third.NextCheckAt);
        var failed = custom.Evaluate(new VerificationState(DomainStatus.TemporaryFailure, 3, s.CreatedAt, Now.AddMinutes(-61), false), Bad, Now);
        Assert.Equal(DomainStatus.Failed, failed.Status);
        Assert.Equal(Now.AddHours(6), custom.Evaluate(s, Ok, Now).NextCheckAt);
    }

    [Fact]
    public void Apply_keeps_the_previous_error_on_a_dns_failure_and_clears_it_on_success()
    {
        var domain = new DomainRecord(Guid.NewGuid(), Guid.NewGuid(), "example.com", DomainStatus.Verified, null, false, Now.AddDays(-40), null, null, 0, null, false, "old error");
        Assert.Equal("old error", _schedule.Apply(domain, Dns, Now).LastError);
        Assert.Equal("new", _schedule.Apply(domain, Bad, Now, "new").LastError);
        Assert.Null(_schedule.Apply(domain, Ok, Now, "ignored").LastError);
        Assert.Equal(Now, _schedule.Apply(domain, Dns, Now).LastCheckedAt);
    }

    [Fact]
    public void Invalid_options_are_rejected()
    {
        Assert.Throws<ArgumentException>(() => new VerificationSchedule(new VerificationScheduleOptions { VerifiedInterval = TimeSpan.Zero }));
        Assert.Throws<ArgumentException>(() => new VerificationSchedule(new VerificationScheduleOptions { FailuresBeforeTemporaryFailure = 0 }));
    }
}
