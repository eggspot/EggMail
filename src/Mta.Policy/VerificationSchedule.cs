using Mta.Storage;

namespace Mta.Policy;

/// <summary>The result of one DNS verification check of a domain.</summary>
public enum VerificationCheckResult : byte
{
    /// <summary>Every required record is present and correct.</summary>
    AllRecordsOk = 0,

    /// <summary>The DNS answered and at least one required record is missing or wrong.</summary>
    RecordsNotOk,

    /// <summary>DNS could not answer (SERVFAIL, timeout). Says nothing about the records, so it never worsens a domain's state.</summary>
    DnsTemporaryFailure,
}

/// <summary>Cadence and thresholds for domain verification (design section 8). Every value is a proposed default.</summary>
public sealed class VerificationScheduleOptions
{
    /// <summary>Check interval during the first <see cref="InitialPhase"/>. Default 90 seconds (the design says 1 to 2 minutes).</summary>
    public TimeSpan InitialInterval { get; init; } = TimeSpan.FromSeconds(90);

    /// <summary>Length of the fast-check phase measured from domain creation. Default 15 minutes.</summary>
    public TimeSpan InitialPhase { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>Check interval in the second phase. Default 15 minutes.</summary>
    public TimeSpan MediumInterval { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>Length of the second phase, starting when the first ends. Default 24 hours.</summary>
    public TimeSpan MediumPhase { get; init; } = TimeSpan.FromHours(24);

    /// <summary>Check interval for a domain still unverified after both phases. Default 1 hour.</summary>
    public TimeSpan SlowInterval { get; init; } = TimeSpan.FromHours(1);

    /// <summary>Check interval for a verified domain. Default 24 hours.</summary>
    public TimeSpan VerifiedInterval { get; init; } = TimeSpan.FromHours(24);

    /// <summary>Re-check delay after a first failed check of a verified domain (to confirm before alerting). Default 15 minutes.</summary>
    public TimeSpan ConfirmFailureInterval { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>Check interval while in <see cref="DomainStatus.TemporaryFailure"/>. Default 1 hour.</summary>
    public TimeSpan TemporaryFailureInterval { get; init; } = TimeSpan.FromHours(1);

    /// <summary>Check interval for a <see cref="DomainStatus.Failed"/> domain (it recovers automatically if the records return). Default 24 hours.</summary>
    public TimeSpan FailedInterval { get; init; } = TimeSpan.FromHours(24);

    /// <summary>Retry delay after a DNS temporary failure. Default 5 minutes.</summary>
    public TimeSpan DnsRetryInterval { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Consecutive failed checks that move a verified domain to temporary failure. Default 2.</summary>
    public int FailuresBeforeTemporaryFailure { get; init; } = 2;

    /// <summary>How long a domain may stay in temporary failure before it becomes Failed and sending is paused. Default 72 hours (SES and Resend practice).</summary>
    public TimeSpan TemporaryFailureGrace { get; init; } = TimeSpan.FromHours(72);

    /// <summary>Minimum time between two checks of a domain, which rate-limits "Verify now". Default 30 seconds.</summary>
    public TimeSpan VerifyNowMinimumInterval { get; init; } = TimeSpan.FromSeconds(30);

    internal void Validate()
    {
        TimeSpan[] positives =
        [
            InitialInterval, InitialPhase, MediumInterval, MediumPhase, SlowInterval, VerifiedInterval, ConfirmFailureInterval,
            TemporaryFailureInterval, FailedInterval, DnsRetryInterval, TemporaryFailureGrace,
        ];
        foreach (TimeSpan t in positives)
        {
            if (t <= TimeSpan.Zero)
            {
                throw new ArgumentException("Verification intervals must be positive.");
            }
        }

        if (FailuresBeforeTemporaryFailure < 1 || VerifyNowMinimumInterval < TimeSpan.Zero)
        {
            throw new ArgumentException("Invalid verification threshold.");
        }
    }
}

/// <summary>The inputs of a verification transition, copied from a <see cref="DomainRecord"/>.</summary>
/// <param name="Status">Current status.</param>
/// <param name="ConsecutiveFailures">Failed checks in a row so far.</param>
/// <param name="CreatedAt">When the domain was added (start of the verification cadence).</param>
/// <param name="TemporaryFailureSince">When the domain entered temporary failure, if it did.</param>
/// <param name="SendingPaused">Whether sending is currently paused.</param>
public readonly record struct VerificationState(
    DomainStatus Status,
    int ConsecutiveFailures,
    DateTimeOffset CreatedAt,
    DateTimeOffset? TemporaryFailureSince,
    bool SendingPaused)
{
    /// <summary>Copies the relevant fields of a domain record.</summary>
    public static VerificationState From(DomainRecord domain)
    {
        ArgumentNullException.ThrowIfNull(domain);
        return new VerificationState(domain.Status, domain.ConsecutiveFailures, domain.CreatedAt, domain.TemporaryFailureSince, domain.SendingPaused);
    }
}

/// <summary>The result of applying a check result to a <see cref="VerificationState"/>.</summary>
/// <param name="Status">The new status.</param>
/// <param name="ConsecutiveFailures">The new failure count.</param>
/// <param name="TemporaryFailureSince">When temporary failure began, or null.</param>
/// <param name="SendingPaused">Whether sending is paused afterwards.</param>
/// <param name="NextCheckAt">When to check next.</param>
/// <param name="StatusChanged">True when <see cref="Status"/> differs from the input status (raise an event, alert or banner).</param>
public readonly record struct VerificationOutcome(
    DomainStatus Status,
    int ConsecutiveFailures,
    DateTimeOffset? TemporaryFailureSince,
    bool SendingPaused,
    DateTimeOffset NextCheckAt,
    bool StatusChanged);

/// <summary>
/// The domain verification state machine and check cadence of design section 8 as pure functions. States:
/// Pending, Verifying, Verified, TemporaryFailure, Failed. Pending, Verifying and Failed block sending; TemporaryFailure keeps sending
/// (with a banner). Verified moves to TemporaryFailure after two consecutive failed checks; TemporaryFailure returns to Verified when
/// the records come back or becomes Failed (and pauses sending) after the grace period. DNS temporary failures never change a status.
/// </summary>
public sealed class VerificationSchedule
{
    private readonly VerificationScheduleOptions _options;

    /// <summary>Creates a schedule with the given (or default proposed) options.</summary>
    public VerificationSchedule(VerificationScheduleOptions? options = null)
    {
        _options = options ?? new VerificationScheduleOptions();
        _options.Validate();
    }

    /// <summary>Applies a check result: returns the new status, counters, pause flag and next check time.</summary>
    /// <param name="state">The domain's current state.</param>
    /// <param name="result">The result of the check that just ran.</param>
    /// <param name="now">The time of the check.</param>
    public VerificationOutcome Evaluate(in VerificationState state, VerificationCheckResult result, DateTimeOffset now)
    {
        DomainStatus status = state.Status;
        int failures = state.ConsecutiveFailures;
        DateTimeOffset? since = state.TemporaryFailureSince;
        bool paused = state.SendingPaused;

        if (result == VerificationCheckResult.DnsTemporaryFailure)
        {
            // No information about the records: keep everything, look again soon. A pending domain is "being verified" from its first check.
            DomainStatus kept = status == DomainStatus.Pending ? DomainStatus.Verifying : status;
            return new VerificationOutcome(kept, failures, since, paused, now + _options.DnsRetryInterval, kept != status);
        }

        bool ok = result == VerificationCheckResult.AllRecordsOk;
        switch (status)
        {
            case DomainStatus.Pending:
            case DomainStatus.Verifying:
                if (ok)
                {
                    return Verified(state, now, status);
                }

                return new VerificationOutcome(DomainStatus.Verifying, failures + 1, null, paused, now + UnverifiedInterval(state.CreatedAt, now), status != DomainStatus.Verifying);

            case DomainStatus.Verified:
                if (ok)
                {
                    return new VerificationOutcome(DomainStatus.Verified, 0, null, paused, now + _options.VerifiedInterval, false);
                }

                failures++;
                if (failures >= _options.FailuresBeforeTemporaryFailure)
                {
                    return new VerificationOutcome(DomainStatus.TemporaryFailure, failures, now, paused, now + _options.TemporaryFailureInterval, true);
                }

                return new VerificationOutcome(DomainStatus.Verified, failures, null, paused, now + _options.ConfirmFailureInterval, false);

            case DomainStatus.TemporaryFailure:
                if (ok)
                {
                    return Verified(state, now, status);
                }

                failures++;
                DateTimeOffset began = since ?? now;
                if (now - began >= _options.TemporaryFailureGrace)
                {
                    return new VerificationOutcome(DomainStatus.Failed, failures, began, true, now + _options.FailedInterval, true);
                }

                return new VerificationOutcome(DomainStatus.TemporaryFailure, failures, began, paused, now + _options.TemporaryFailureInterval, false);

            case DomainStatus.Failed:
                if (ok)
                {
                    return Verified(state, now, status);
                }

                return new VerificationOutcome(DomainStatus.Failed, failures + 1, since, true, now + _options.FailedInterval, false);

            default:
                throw new ArgumentOutOfRangeException(nameof(state), status, "Unknown domain status.");
        }
    }

    /// <summary>Applies <paramref name="result"/> to a domain record and returns the updated record (the caller persists it).</summary>
    /// <param name="domain">The record before the check.</param>
    /// <param name="result">The check result.</param>
    /// <param name="now">The time of the check.</param>
    /// <param name="error">A description of what failed, stored in <c>LastError</c>; cleared on success.</param>
    public DomainRecord Apply(DomainRecord domain, VerificationCheckResult result, DateTimeOffset now, string? error = null)
    {
        VerificationOutcome o = Evaluate(VerificationState.From(domain), result, now);
        return domain with
        {
            Status = o.Status,
            ConsecutiveFailures = o.ConsecutiveFailures,
            TemporaryFailureSince = o.TemporaryFailureSince,
            SendingPaused = o.SendingPaused,
            LastCheckedAt = now,
            NextCheckAt = o.NextCheckAt,
            LastError = result == VerificationCheckResult.AllRecordsOk ? null : error ?? domain.LastError,
        };
    }

    /// <summary>When the first check of a newly created domain is due.</summary>
    public DateTimeOffset FirstCheckAt(DateTimeOffset createdAt) => createdAt + _options.InitialInterval;

    /// <summary>The delay until the next check for an unverified domain created at <paramref name="createdAt"/>: fast, then medium, then hourly.</summary>
    public TimeSpan UnverifiedInterval(DateTimeOffset createdAt, DateTimeOffset now)
    {
        TimeSpan age = now - createdAt;
        if (age < _options.InitialPhase)
        {
            return _options.InitialInterval;
        }

        return age < _options.InitialPhase + _options.MediumPhase ? _options.MediumInterval : _options.SlowInterval;
    }

    /// <summary>
    /// "Verify now" rate limit: allowed only if the last check (scheduled or manual) was at least the minimum interval ago.
    /// </summary>
    /// <param name="lastCheckedAt">The domain's <c>LastCheckedAt</c>.</param>
    /// <param name="now">The current time.</param>
    /// <param name="retryAfter">When refused, how long the user must wait.</param>
    public bool CanVerifyNow(DateTimeOffset? lastCheckedAt, DateTimeOffset now, out TimeSpan retryAfter)
    {
        retryAfter = TimeSpan.Zero;
        if (lastCheckedAt is not { } last)
        {
            return true;
        }

        TimeSpan elapsed = now - last;
        if (elapsed >= _options.VerifyNowMinimumInterval || elapsed < TimeSpan.Zero)
        {
            return true;
        }

        retryAfter = _options.VerifyNowMinimumInterval - elapsed;
        return false;
    }

    /// <summary>True when the status allows sending (Verified, or TemporaryFailure with a banner) and sending is not paused.</summary>
    public static bool AllowsSending(DomainStatus status, bool sendingPaused) =>
        !sendingPaused && status is DomainStatus.Verified or DomainStatus.TemporaryFailure;

    private VerificationOutcome Verified(in VerificationState state, DateTimeOffset now, DomainStatus from)
    {
        // Only lift a pause that this state machine set (leaving Failed); a manual pause on a healthy domain stays.
        bool paused = from == DomainStatus.Failed ? false : state.SendingPaused;
        return new VerificationOutcome(DomainStatus.Verified, 0, null, paused, now + _options.VerifiedInterval, true);
    }
}
