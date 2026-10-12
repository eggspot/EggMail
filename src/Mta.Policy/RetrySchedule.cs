namespace Mta.Policy;

/// <summary>Configuration for <see cref="RetrySchedule"/>. All defaults are proposed values, not standards.</summary>
public sealed class RetryScheduleOptions
{
    /// <summary>Delay after the 1st, 2nd, ... failed attempt. Must be positive; should be non-decreasing. Default (proposed): 2m, 5m, 15m, 30m, 1h, 2h, 4h.</summary>
    public IReadOnlyList<TimeSpan> Delays { get; init; } =
        [TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(30),
         TimeSpan.FromHours(1), TimeSpan.FromHours(2), TimeSpan.FromHours(4)];

    /// <summary>Delay used once <see cref="Delays"/> is exhausted, repeated until the delivery expires. Default (proposed): 4 hours.</summary>
    public TimeSpan RepeatInterval { get; init; } = TimeSpan.FromHours(4);

    /// <summary>Random spread applied to every delay, as a fraction (0.10 is plus/minus 10%). Default 0.10.</summary>
    public double JitterFraction { get; init; } = 0.10;

    /// <summary>For connection-level problems (no reply, 421, 4.4.x), the delay after the first attempt, when shorter than the schedule. Default 1 minute.</summary>
    public TimeSpan FirstConnectionRetryDelay { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>Lower bound for greylisting retries. Default 5 minutes (most greylisters refuse earlier retries).</summary>
    public TimeSpan GreylistMinDelay { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Upper bound for greylisting retries. Default 15 minutes.</summary>
    public TimeSpan GreylistMaxDelay { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>Multiplier applied to the scheduled delay for throttling replies (4.7.x, rate limits). Default 2.</summary>
    public double ThrottleMultiplier { get; init; } = 2.0;

    /// <summary>Minimum delay for throttling replies. Default 10 minutes.</summary>
    public TimeSpan ThrottleMinDelay { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>Upper bound for any computed delay (before a server hint raises it). Default 8 hours.</summary>
    public TimeSpan MaxDelay { get; init; } = TimeSpan.FromHours(8);

    /// <summary>Server hints ("try again in N seconds") smaller than this are raised to it. Default 30 seconds.</summary>
    public TimeSpan MinHint { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Server hints larger than this are capped to it. Default 4 hours.</summary>
    public TimeSpan MaxHint { get; init; } = TimeSpan.FromHours(4);

    /// <summary>
    /// When the next retry would fall after the expiry, schedule one last attempt this long before <c>ExpiresAt</c> instead of giving up early,
    /// provided at least twice this much time remains. <see cref="TimeSpan.Zero"/> disables the final attempt. Default 1 minute.
    /// </summary>
    public TimeSpan FinalAttemptMargin { get; init; } = TimeSpan.FromMinutes(1);

    internal void Validate()
    {
        if (Delays is null || Delays.Count == 0)
        {
            throw new ArgumentException("At least one retry delay is required.", nameof(Delays));
        }

        foreach (TimeSpan d in Delays)
        {
            if (d <= TimeSpan.Zero)
            {
                throw new ArgumentException("Retry delays must be positive.", nameof(Delays));
            }
        }

        RequirePositive(RepeatInterval, nameof(RepeatInterval));
        RequirePositive(FirstConnectionRetryDelay, nameof(FirstConnectionRetryDelay));
        RequirePositive(GreylistMinDelay, nameof(GreylistMinDelay));
        RequirePositive(MaxDelay, nameof(MaxDelay));
        RequirePositive(MinHint, nameof(MinHint));
        if (GreylistMaxDelay < GreylistMinDelay)
        {
            throw new ArgumentException("GreylistMaxDelay must not be smaller than GreylistMinDelay.", nameof(GreylistMaxDelay));
        }

        if (MaxHint < MinHint)
        {
            throw new ArgumentException("MaxHint must not be smaller than MinHint.", nameof(MaxHint));
        }

        if (JitterFraction is < 0 or >= 1 || double.IsNaN(JitterFraction))
        {
            throw new ArgumentOutOfRangeException(nameof(JitterFraction), "Jitter must be in [0, 1).");
        }

        if (ThrottleMultiplier < 1 || double.IsNaN(ThrottleMultiplier))
        {
            throw new ArgumentOutOfRangeException(nameof(ThrottleMultiplier), "Throttle multiplier must be at least 1.");
        }

        if (FinalAttemptMargin < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(FinalAttemptMargin));
        }
    }

    private static void RequirePositive(TimeSpan value, string name)
    {
        if (value <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(name, "Must be positive.");
        }
    }
}

/// <summary>The scheduler's decision after a failed attempt.</summary>
/// <param name="Expire">True when the delivery must be expired (bounced as undeliverable) now instead of retried.</param>
/// <param name="NextAttemptAt">When to retry (meaningless when <paramref name="Expire"/> is true; then equals <c>now</c>).</param>
/// <param name="Delay">The delay used (zero when expiring).</param>
/// <param name="Reason">A short constant describing how the delay was chosen.</param>
public readonly record struct RetryDecision(bool Expire, DateTimeOffset NextAttemptAt, TimeSpan Delay, string Reason);

/// <summary>
/// Computes when to retry a deferred delivery: a configurable ladder of delays with jitter, shorter for connection problems,
/// longer for throttling, 5 to 15 minutes for greylisting, raised to a server's "try again in N" hint, and never past the
/// delivery's expiry. Immutable and thread-safe (the random source must be thread-safe).
/// </summary>
public sealed class RetrySchedule
{
    private readonly TimeSpan[] _delays;
    private readonly RetryScheduleOptions _options;
    private readonly IRandomSource _random;
    private readonly ReplyClassifier _classifier;

    /// <summary>Creates a schedule.</summary>
    /// <param name="options">Options; null for the proposed defaults.</param>
    /// <param name="random">Random source for jitter; null for the system source.</param>
    /// <param name="classifier">Classifier used to interpret raw replies; null for the default.</param>
    public RetrySchedule(RetryScheduleOptions? options = null, IRandomSource? random = null, ReplyClassifier? classifier = null)
    {
        _options = options ?? new RetryScheduleOptions();
        _options.Validate();
        _delays = [.. _options.Delays];
        _random = random ?? SystemRandomSource.Instance;
        _classifier = classifier ?? ReplyClassifier.Default;
    }

    /// <summary>The scheduled delay (no jitter, no reply-specific adjustment) after <paramref name="attemptsMade"/> failed attempts (1 = the first attempt just failed).</summary>
    public TimeSpan GetBaseDelay(int attemptsMade)
    {
        int index = Math.Max(attemptsMade, 1) - 1;
        return index < _delays.Length ? _delays[index] : _options.RepeatInterval;
    }

    /// <summary>
    /// Decides the next attempt from a raw reply. A null <paramref name="lastReply"/> means no reply was obtained (connect failure,
    /// timeout, dropped connection) and is treated as a connection problem.
    /// </summary>
    /// <param name="attemptsMade">Number of attempts made including the one that just failed (<c>ClaimedDelivery.Attempt + 1</c>).</param>
    /// <param name="now">Current time.</param>
    /// <param name="expiresAt">The delivery's expiry (<c>ClaimedDelivery.ExpiresAt</c>).</param>
    /// <param name="lastReply">The reply that caused the deferral, if any.</param>
    /// <param name="stage">Stage at which the reply arrived.</param>
    public RetryDecision NextAttemptAt(int attemptsMade, DateTimeOffset now, DateTimeOffset expiresAt, RemoteReply? lastReply = null, SmtpStage stage = SmtpStage.EndOfData)
    {
        DeliveryClass cls = lastReply is { } reply ? _classifier.Classify(reply, stage).Class : DeliveryClass.Transient;
        return NextAttemptAt(attemptsMade, now, expiresAt, cls, lastReply);
    }

    /// <summary>Decides the next attempt when the reply has already been classified.</summary>
    public RetryDecision NextAttemptAt(int attemptsMade, DateTimeOffset now, DateTimeOffset expiresAt, DeliveryClass lastClass, RemoteReply? lastReply = null)
    {
        if (now >= expiresAt)
        {
            return new RetryDecision(true, now, TimeSpan.Zero, "lifetime exceeded");
        }

        TimeSpan baseDelay = GetBaseDelay(attemptsMade);
        string reason;
        TimeSpan delay;
        switch (lastClass)
        {
            case DeliveryClass.TransientGreylist:
                delay = Clamp(baseDelay, _options.GreylistMinDelay, _options.GreylistMaxDelay);
                reason = "greylisting";
                break;
            case DeliveryClass.TransientThrottle:
                delay = TimeSpan.FromTicks((long)Math.Min(baseDelay.Ticks * _options.ThrottleMultiplier, _options.MaxDelay.Ticks));
                if (delay < _options.ThrottleMinDelay)
                {
                    delay = _options.ThrottleMinDelay;
                }

                reason = "throttled: backing off";
                break;
            default:
                if (attemptsMade <= 1 && IsConnectionProblem(lastReply) && _options.FirstConnectionRetryDelay < baseDelay)
                {
                    delay = _options.FirstConnectionRetryDelay;
                    reason = "connection problem: early first retry";
                }
                else
                {
                    delay = baseDelay;
                    reason = "scheduled retry";
                }

                break;
        }

        if (delay > _options.MaxDelay)
        {
            delay = _options.MaxDelay;
        }

        if (_options.JitterFraction > 0)
        {
            double factor = 1.0 + (((_random.NextDouble() * 2.0) - 1.0) * _options.JitterFraction);
            delay = TimeSpan.FromTicks((long)(delay.Ticks * factor));
        }

        if (lastClass == DeliveryClass.TransientGreylist)
        {
            delay = Clamp(delay, _options.GreylistMinDelay, _options.GreylistMaxDelay);
        }

        if (lastReply is { Text: { Length: > 0 } text } && RetryAfterHint.TryParse(text, out TimeSpan hint))
        {
            hint = Clamp(hint, _options.MinHint, _options.MaxHint);
            if (hint > delay)
            {
                delay = hint;
                reason = "server retry hint";
            }
        }

        DateTimeOffset next = now + delay;
        if (next < expiresAt)
        {
            return new RetryDecision(false, next, delay, reason);
        }

        // The next retry would land at or after the expiry. Use one final attempt shortly before it, if there is room.
        TimeSpan margin = _options.FinalAttemptMargin;
        if (margin > TimeSpan.Zero && expiresAt - now >= margin + margin)
        {
            DateTimeOffset last = expiresAt - margin;
            return new RetryDecision(false, last, last - now, "final attempt before expiry");
        }

        return new RetryDecision(true, now, TimeSpan.Zero, "lifetime exceeded");
    }

    private static bool IsConnectionProblem(RemoteReply? reply)
    {
        if (reply is not { } r)
        {
            return true;
        }

        if (r.Code == 421)
        {
            return true;
        }

        EnhancedStatus es = r.GetEnhancedStatus();
        return es.IsValid && es.Class == 4 && es.Subject == 4;
    }

    private static TimeSpan Clamp(TimeSpan value, TimeSpan min, TimeSpan max) => value < min ? min : value > max ? max : value;
}
