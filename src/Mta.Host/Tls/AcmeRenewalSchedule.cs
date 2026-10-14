using System.Text.Json;
using System.Text.Json.Serialization;

namespace Mta.Host.Tls;

/// <summary>
/// What is known about the CA's renewal advice (ACME Renewal Information, RFC 9773) for ONE certificate; stored as JSON in the
/// <c>acme_renewal.ari_json</c> column on both backends and moved by a backend switch with the rest of the renewal row.
/// </summary>
/// <param name="Thumbprint">The certificate this state belongs to (the leaf's thumbprint); a different certificate starts from scratch.</param>
/// <param name="WindowStart">Start of the suggested renewal window; null when the CA gave no usable advice (see <paramref name="Unsupported"/>, <paramref name="Error"/>).</param>
/// <param name="WindowEnd">End of the suggested window.</param>
/// <param name="RenewAt">The moment inside the window chosen at random when the window was first seen; kept while the CA repeats the same window.</param>
/// <param name="CheckedAt">When the CA was last asked.</param>
/// <param name="NextCheckAt">Do not ask again before this (the CA's Retry-After within sane bounds).</param>
/// <param name="ExplanationUrl">The CA's explanation of a window that is not the default one (revocation, a shortened lifetime).</param>
/// <param name="Error">The last failure to get advice (the lifetime rule applies while there is no usable window).</param>
/// <param name="Unsupported">The CA's directory does not advertise ARI.</param>
public sealed record AcmeRenewalAdvice(
    string Thumbprint,
    DateTimeOffset? WindowStart,
    DateTimeOffset? WindowEnd,
    DateTimeOffset? RenewAt,
    DateTimeOffset CheckedAt,
    DateTimeOffset NextCheckAt,
    string? ExplanationUrl = null,
    string? Error = null,
    bool Unsupported = false)
{
    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

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
/// With ARI the CA's window decides (RFC 9773 section 4.2: renew at a random time inside it, at once if that time has passed); without ARI, or when asking fails,
/// the lifetime rule decides (<see cref="AcmeRenewalService.NeedsRenewal"/>). In every case a certificate with only a small part of its lifetime left is renewed:
/// a CA with a wrong or stale window must not be able to let the certificate expire.
/// </summary>
public static class AcmeRenewalSchedule
{
    /// <summary>Asked again after this when the CA says nothing about it (RFC 9773 suggests checking a few times a day at most).</summary>
    public static readonly TimeSpan DefaultCheckInterval = TimeSpan.FromHours(6);

    /// <summary>Retry-After is honoured within these bounds (RFC 9773 section 4.3.2: no more often than about a minute, at least once a day).</summary>
    public static readonly TimeSpan MinCheckInterval = TimeSpan.FromMinutes(1);

    public static readonly TimeSpan MaxCheckInterval = TimeSpan.FromDays(1);

    /// <summary>After a failed request for advice the lifetime rule is used and the CA is asked again after this.</summary>
    public static readonly TimeSpan ErrorCheckInterval = TimeSpan.FromHours(1);

    /// <summary>A CA without ARI is not asked again for this long (a directory changes rarely).</summary>
    public static readonly TimeSpan UnsupportedCheckInterval = TimeSpan.FromDays(1);

    /// <summary>Whatever the advice says, renew when this fraction of the lifetime or less is left (half of the default lifetime rule).</summary>
    public const double SafetyRemainingFraction = 1.0 / 6;

    /// <summary>Records the CA's answer. A window the CA repeats unchanged keeps the time chosen for it; a new window chooses again.</summary>
    /// <param name="nextRandom">A number in [0, 1); only the position inside a new window.</param>
    public static AcmeRenewalAdvice FromInfo(string thumbprint, AcmeRenewalInfo info, AcmeRenewalAdvice? previous, DateTimeOffset now, Func<double> nextRandom)
    {
        if (info.WindowEnd <= info.WindowStart)
        {
            // RFC 9773 section 4.2: a window that ends at or before its start is invalid.
            return FromFailure(thumbprint, previous, now, "the CA's suggested window ends before it starts");
        }

        DateTimeOffset renewAt = previous is { WindowStart: { } s, WindowEnd: { } e, RenewAt: { } kept } && s == info.WindowStart && e == info.WindowEnd
            ? kept
            : info.WindowStart + (info.WindowEnd - info.WindowStart) * Math.Clamp(nextRandom(), 0.0, 1.0);
        var wait = Clamp(info.RetryAfter ?? DefaultCheckInterval);
        return new AcmeRenewalAdvice(thumbprint, info.WindowStart, info.WindowEnd, renewAt, now, now + wait, info.ExplanationUrl);
    }

    /// <summary>The CA has no ARI (<paramref name="unsupported"/>) or the request failed; an earlier window for the same certificate stays valid.</summary>
    public static AcmeRenewalAdvice FromFailure(string thumbprint, AcmeRenewalAdvice? previous, DateTimeOffset now, string error, bool unsupported = false) =>
        new(thumbprint, previous?.WindowStart, previous?.WindowEnd, previous?.RenewAt, now, now + (unsupported ? UnsupportedCheckInterval : ErrorCheckInterval),
            previous?.ExplanationUrl, unsupported ? null : error, unsupported);

    /// <summary>Is it time to ask the CA (nothing known yet, or the wait is over)?</summary>
    public static bool ShouldCheck(AcmeRenewalAdvice? advice, DateTimeOffset now) => advice is null || advice.NextCheckAt <= now;

    /// <summary>
    /// Is the certificate due? Window known: its chosen time has come. Otherwise the lifetime rule. Either way when little lifetime is left.
    /// </summary>
    public static bool IsDue(AcmeRenewalAdvice? advice, DateTimeOffset notBefore, DateTimeOffset notAfter, DateTimeOffset now, double lifetimeRuleRemainingFraction)
    {
        var lifetime = notAfter - notBefore;
        if (notAfter - now <= lifetime * SafetyRemainingFraction)
        {
            return true;
        }

        return advice is { HasWindow: true } ? advice.RenewAt!.Value <= now : notAfter - now <= lifetime * lifetimeRuleRemainingFraction;
    }

    private static TimeSpan Clamp(TimeSpan value) => value < MinCheckInterval ? MinCheckInterval : value > MaxCheckInterval ? MaxCheckInterval : value;
}
