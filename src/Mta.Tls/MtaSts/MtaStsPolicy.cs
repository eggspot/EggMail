namespace Mta.Tls.MtaSts;

/// <summary>The <c>mode</c> field of an MTA-STS policy (RFC 8461 section 3.2).</summary>
public enum MtaStsMode
{
    /// <summary>The domain has no active policy (used to withdraw a policy).</summary>
    None,

    /// <summary>Validate and report failures, but deliver regardless.</summary>
    Testing,

    /// <summary>Deliver only to listed MX hosts over validated TLS.</summary>
    Enforce,
}

/// <summary>A parsed MTA-STS policy (RFC 8461 section 3.2).</summary>
/// <param name="Mode">The policy mode.</param>
/// <param name="MxPatterns">Normalised (lower-case, A-label) MX patterns; a pattern may start with <c>*.</c>.</param>
/// <param name="MaxAgeSeconds">Lifetime in seconds, already clamped to <see cref="MtaStsPolicyParser.MaxAgeCeilingSeconds"/>.</param>
/// <param name="PolicyLines">The policy body as lines (without line terminators), for TLS-RPT <c>policy-string</c>.</param>
public sealed record MtaStsPolicy(
    MtaStsMode Mode,
    IReadOnlyList<string> MxPatterns,
    int MaxAgeSeconds,
    IReadOnlyList<string> PolicyLines)
{
    /// <summary>The only policy version defined by RFC 8461.</summary>
    public const string Version = "STSv1";

    /// <summary>Returns <see langword="true"/> if the policy allows delivery to <paramref name="mxHost"/>; see <see cref="MtaStsEvaluation.IsMxAllowed"/>.</summary>
    public bool IsMxAllowed(string mxHost) => MtaStsEvaluation.IsMxAllowed(this, mxHost);
}

/// <summary>The cached state of one domain's MTA-STS policy.</summary>
/// <param name="Domain">The policy domain (normalised).</param>
/// <param name="PolicyId">The <c>id</c> from the DNS TXT record the policy was fetched under.</param>
/// <param name="Policy">The policy.</param>
/// <param name="FetchedAt">When the policy was fetched.</param>
/// <param name="ExpiresAt"><paramref name="FetchedAt"/> plus <c>max_age</c>.</param>
public sealed record MtaStsCacheEntry(
    string Domain,
    string PolicyId,
    MtaStsPolicy Policy,
    DateTimeOffset FetchedAt,
    DateTimeOffset ExpiresAt);
