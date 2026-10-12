namespace Mta.Webhooks;

public sealed class WebhookOptions
{
    /// <summary>Timeout for one delivery attempt (the Standard Webhooks spec suggests 15-30 s; Svix uses 15 s).</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>Allow plain http endpoints (default false: HTTPS only).</summary>
    public bool AllowHttp { get; init; }

    /// <summary>Concurrent deliveries per endpoint so one slow endpoint cannot hog the workers.</summary>
    public int MaxConcurrencyPerEndpoint { get; init; } = 4;

    public int MaxConcurrency { get; init; } = 32;
    public int BatchSize { get; init; } = 64;
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromMilliseconds(500);
    public TimeSpan Lease { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>An endpoint failing continuously for this long is disabled and the tenant notified.</summary>
    public TimeSpan DisableAfter { get; init; } = TimeSpan.FromDays(5);

    /// <summary>Retry delays after attempt 1..n (immediate first attempt, then 5 s, 5 m, 30 m, 2 h, 5 h, 10 h, 10 h: identical to Svix/Resend).</summary>
    public IReadOnlyList<TimeSpan> RetrySchedule { get; init; } =
    [
        TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(30), TimeSpan.FromHours(2),
        TimeSpan.FromHours(5), TimeSpan.FromHours(10), TimeSpan.FromHours(10),
    ];

    /// <summary>Extra delay applied when the receiver answers 429/502/504 (throttling).</summary>
    public TimeSpan ThrottleExtraDelay { get; init; } = TimeSpan.FromMinutes(1);

    public int MaxResponseSnippetBytes { get; init; } = 1024;
    public string UserAgent { get; init; } = "EggMail-Webhooks/1.0";
}
