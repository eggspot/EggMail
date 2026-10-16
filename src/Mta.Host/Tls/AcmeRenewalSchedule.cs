using System.Text.Json;
using System.Text.Json.Serialization;

namespace Mta.Host.Tls;

/// <summary>
/// What is known about the CA's renewal advice (ACME Renewal Information, RFC 9773) for ONE certificate; stored as JSON in the
/// <c>acme_renewal.ari_json</c> column on both backends and moved by a backend switch with the rest of the renewal row.
/// </summary>
/// <param name="Thumbprint">The certificate this state belongs to (the leaf's thumbprint); a different certificate starts from scratch.</param>
/// <param name="WindowStart">Start of the suggested renewal window; null when the CA gave no usable advice (see <paramref name="DirectoryHasNoRenewalInfo"/>, <paramref name="Error"/>).</param>
/// <param name="WindowEnd">End of the suggested window.</param>
/// <param name="RenewAt">The moment inside the window chosen at random when the window was first seen; kept while the CA repeats (about) the same window.</param>
/// <param name="CheckedAt">When the CA was last asked.</param>
/// <param name="NextCheckAt">Do not ask again before this (the CA's Retry-After within sane bounds, or the error back-off).</param>
/// <param name="ExplanationUrl">The CA's explanation of a window that is not the default one (revocation, a shortened lifetime); https only, at most 2 KB.</param>
/// <param name="Error">The last failure to get advice, at most 1 KB (the lifetime rule applies while there is no usable window).</param>
/// <param name="DirectoryHasNoRenewalInfo">The CA's directory does not advertise ARI.</param>
/// <param name="Failures">Consecutive failed requests for advice (drives the back-off after server errors).</param>
public sealed record AcmeRenewalAdvice(
    string Thumbprint,
    DateTimeOffset? WindowStart,
    DateTimeOffset? WindowEnd,
    DateTimeOffset? RenewAt,
    DateTimeOffset CheckedAt,
    DateTimeOffset NextCheckAt,
    string? ExplanationUrl = null,
    string? Error = null,
    bool DirectoryHasNoRenewalInfo = false,
    int Failures = 0)
{
    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault };

    /// <summary>True when the CA's window is known, so the lifetime rule is not needed.</summary>
    public bool HasWindow => RenewAt is not null;

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    /// <summary>The stored advice for <paramref name="thumbprint"/>; null when there is none, it is for another certificate, or the JSON is unreadable.</summary>
    public static AcmeRenewalAdvice? Parse(string? json, string thumbprint)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            var advice = JsonSerializer.Deserialize<AcmeRenewalAdvice>(json, Json);
            return advice is not null && string.Equals(advice.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase) ? advice : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>
/// The renewal timing rules, pure and clock-free so they are tested with fake clocks and fixed random numbers.
/// With ARI the CA's window decides (RFC 9773 section 4.2: renew at a random time inside it, at once if that time has passed or comes before the next check);
/// without ARI, or when asking fails, the lifetime rule decides (<see cref="AcmeRenewalService.NeedsRenewal"/>). Two limits hold in every case:
/// a certificate with only a small part of its lifetime left is renewed whatever the advice says (a CA with a wrong or stale window must not be able to let it
/// expire), and ARI alone never renews a certificate younger than <see cref="MinimumAge"/> (a CA that keeps answering "renew now" must not cause an order, and
/// a duplicate-certificate rate limit hit, at every check).
/// </summary>
public static class AcmeRenewalSchedule
{
    /// <summary>Asked again after this when the CA says nothing about it (RFC 9773 section 4.3.2 suggests a few times a day).</summary>
    public static readonly TimeSpan DefaultCheckInterval = TimeSpan.FromHours(6);

    /// <summary>Retry-After is honoured within these bounds: not more often than a minute, at least once a day.</summary>
    public static readonly TimeSpan MinCheckInterval = TimeSpan.FromMinutes(1);

    public static readonly TimeSpan MaxCheckInterval = TimeSpan.FromDays(1);

    /// <summary>After an error that is not a server error or a network failure (RFC 9773 section 4.3.3) the CA is asked again after this.</summary>
    public static readonly TimeSpan ErrorCheckInterval = TimeSpan.FromHours(6);

    /// <summary>After server errors and network failures the wait starts here and doubles with every consecutive failure up to <see cref="ErrorCheckInterval"/>.</summary>
    public static readonly TimeSpan TransientErrorCheckInterval = TimeSpan.FromMinutes(5);

    /// <summary>A directory without ARI is not asked about again for this long (a directory changes rarely).</summary>
    public static readonly TimeSpan NoRenewalInfoCheckInterval = TimeSpan.FromDays(1);

    /// <summary>Whatever the advice says, renew when this fraction of the lifetime or less is left (never more than the configured lifetime-rule fraction).</summary>
    public const double SafetyRemainingFraction = 1.0 / 6;

    /// <summary>A window that moved by no more than this (both ends) is the same window: its chosen time stays.</summary>
    public static readonly TimeSpan SameWindowTolerance = TimeSpan.FromMinutes(5);

    public const int MaxExplanationUrlLength = 2048;

    public const int MaxErrorLength = 1024;

    /// <summary>The age a certificate must have before ARI alone can make it due: a day, or a twentieth of its lifetime if that is longer.</summary>
    public static TimeSpan MinimumAge(TimeSpan lifetime) => TimeSpan.FromTicks(Math.Max(TimeSpan.FromDays(1).Ticks, lifetime.Ticks / 20));

    /// <summary>Records the CA's answer. A window the CA repeats (about) unchanged keeps the time chosen for it; a different window chooses again.</summary>
    /// <param name="nextRandom">A number in [0, 1); only the position inside a new window.</param>
    public static AcmeRenewalAdvice FromInfo(string thumbprint, AcmeRenewalInfo info, AcmeRenewalAdvice? previous, DateTimeOffset now, Func<double> nextRandom)
    {
        if (info.WindowEnd <= info.WindowStart)
        {
            // RFC 9773 section 4.2: a window that ends at or before its start is invalid. The CA answered, so this is not a server error.
            return FromFailure(thumbprint, previous, now, "the CA's suggested window ends before it starts", transient: false);
        }

        bool sameWindow = previous is { WindowStart: { } s, WindowEnd: { } e, RenewAt: { } kept }
            && (s - info.WindowStart).Duration() <= SameWindowTolerance && (e - info.WindowEnd).Duration() <= SameWindowTolerance
            && kept >= info.WindowStart && kept <= info.WindowEnd;
        DateTimeOffset renewAt = sameWindow
            ? previous!.RenewAt!.Value
            : info.WindowStart + (info.WindowEnd - info.WindowStart) * Math.Clamp(nextRandom(), 0.0, 1.0);
        var wait = Clamp(info.RetryAfter ?? DefaultCheckInterval);
        return new AcmeRenewalAdvice(thumbprint, info.WindowStart, info.WindowEnd, renewAt, now, now + wait, SafeExplanationUrl(info.ExplanationUrl));
    }

    /// <summary>
    /// Asking failed. RFC 9773 section 4.3.3: after a server error or a network failure (<paramref name="transient"/>) back off exponentially (5 minutes,
    /// doubling, at most 6 hours); after any other error wait 6 hours. An earlier window of the same certificate stays valid. A <c>Retry-After</c> on the refusal
    /// (<paramref name="retryAfter"/>) lengthens the wait when it is longer, up to a day.
    /// </summary>
    public static AcmeRenewalAdvice FromFailure(string thumbprint, AcmeRenewalAdvice? previous, DateTimeOffset now, string error, bool transient, TimeSpan? retryAfter = null)
    {
        int failures = Math.Min((previous?.Failures ?? 0) + 1, 30);
        var wait = transient
            ? TimeSpan.FromTicks(Math.Min(ErrorCheckInterval.Ticks, TransientErrorCheckInterval.Ticks << Math.Min(failures - 1, 10)))
            : ErrorCheckInterval;
        if (retryAfter is { } asked && asked > wait)
        {
            // The CA's refusal (a rate limit, a 503) said when to ask again: not before, within the usual bounds (at most a day).
            wait = Clamp(asked);
        }

        return new AcmeRenewalAdvice(thumbprint, previous?.WindowStart, previous?.WindowEnd, previous?.RenewAt, now, now + wait, previous?.ExplanationUrl,
            error.Length <= MaxErrorLength ? error : error[..MaxErrorLength], Failures: failures);
    }

    /// <summary>The CA's directory has no <c>renewalInfo</c>: the lifetime rule applies and the directory is looked at again tomorrow.</summary>
    public static AcmeRenewalAdvice FromDirectoryWithoutRenewalInfo(string thumbprint, DateTimeOffset now) =>
        new(thumbprint, null, null, null, now, now + NoRenewalInfoCheckInterval, DirectoryHasNoRenewalInfo: true);

    /// <summary>
    /// Is it time to ask the CA? Nothing known yet, the wait is over, or the stored wait is absurd (more than a day ahead: the clock stepped back or the
    /// stored value is damaged).
    /// </summary>
    public static bool ShouldCheck(AcmeRenewalAdvice? advice, DateTimeOffset now) =>
        advice is null || advice.NextCheckAt <= now || advice.NextCheckAt > now + MaxCheckInterval;

    /// <summary>
    /// Is the certificate due? With a window: its chosen time comes before the next check (RFC 9773 section 4.2 step 5), and the certificate is old enough
    /// (<see cref="MinimumAge"/>). Without: the lifetime rule. In both cases when little lifetime is left.
    /// </summary>
    /// <param name="lifetimeRuleRemainingFraction">The configured lifetime rule (a third); the safety limit is never above it.</param>
    /// <param name="checkInterval">How often the renewal check runs.</param>
    public static bool IsDue(AcmeRenewalAdvice? advice, DateTimeOffset notBefore, DateTimeOffset notAfter, DateTimeOffset now, double lifetimeRuleRemainingFraction, TimeSpan checkInterval)
    {
        var lifetime = notAfter - notBefore;
        if (notAfter - now <= lifetime * Math.Min(SafetyRemainingFraction, lifetimeRuleRemainingFraction))
        {
            return true;
        }

        if (advice is { HasWindow: true })
        {
            return advice.RenewAt!.Value <= now + checkInterval && now - notBefore >= MinimumAge(lifetime);
        }

        return notAfter - now <= lifetime * lifetimeRuleRemainingFraction;
    }

    private static string? SafeExplanationUrl(string? url) =>
        url is { Length: <= MaxExplanationUrlLength } && Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps && uri.AbsoluteUri.Length <= MaxExplanationUrlLength
            ? uri.AbsoluteUri
            : null;

    private static TimeSpan Clamp(TimeSpan value) => value < MinCheckInterval ? MinCheckInterval : value > MaxCheckInterval ? MaxCheckInterval : value;
}
