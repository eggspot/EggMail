namespace Mta.Tls.MtaSts;

/// <summary>MX pattern syntax and matching for MTA-STS (RFC 8461 section 4.1).</summary>
public static class MtaStsMxMatcher
{
    /// <summary>
    /// Normalises an <c>mx</c> value: lower-case, A-label, no trailing dot. A leading <c>*.</c> is kept and the
    /// remainder must be a valid host name.
    /// </summary>
    public static bool TryNormalizePattern(string? value, out string pattern)
    {
        pattern = string.Empty;
        if (value is null)
        {
            return false;
        }

        string v = value.Trim();
        bool wildcard = v.StartsWith("*.", StringComparison.Ordinal);
        string host = wildcard ? v[2..] : v;
        if (!DnsNames.TryNormalizeHost(host, out string normalized))
        {
            return false;
        }

        pattern = wildcard ? "*." + normalized : normalized;
        return true;
    }

    /// <summary>
    /// Matches <paramref name="mxHost"/> against <paramref name="pattern"/>. An exact pattern matches
    /// case-insensitively (a trailing dot on the host is ignored). A <c>*.suffix</c> pattern matches exactly one
    /// additional left-most label: <c>*.example.com</c> matches <c>mail.example.com</c> but neither
    /// <c>example.com</c> nor <c>a.b.example.com</c>.
    /// </summary>
    public static bool Matches(string pattern, string mxHost)
    {
        return DnsNames.TryNormalizeHost(mxHost, out string host) && MatchesNormalized(pattern, host);
    }

    internal static bool MatchesNormalized(string pattern, string host)
    {
        if (pattern.StartsWith("*.", StringComparison.Ordinal))
        {
            ReadOnlySpan<char> suffix = pattern.AsSpan(1); // ".example.com"
            if (host.Length <= suffix.Length || !host.AsSpan().EndsWith(suffix, StringComparison.Ordinal))
            {
                return false;
            }

            ReadOnlySpan<char> label = host.AsSpan(0, host.Length - suffix.Length);
            return label.IndexOf('.') < 0;
        }

        return string.Equals(pattern, host, StringComparison.Ordinal);
    }
}

/// <summary>What an MTA-STS policy demands of a connection to one MX host.</summary>
/// <param name="Mode">The policy mode.</param>
/// <param name="MxAllowed">Whether the MX host matches one of the policy's <c>mx</c> patterns.</param>
/// <param name="Enforced">True in <c>enforce</c> mode: a mismatch or a failed validation must stop delivery to this MX.</param>
/// <param name="RequireTls">True when TLS is required (enforce mode).</param>
/// <param name="RequireValidCertificate">True when the server certificate must chain to a trusted root and be valid.</param>
/// <param name="ExpectedCertificateName">The name the certificate must match (the MX host, not the recipient domain).</param>
/// <param name="ValidateButDoNotEnforce">True in <c>testing</c> mode: validate and report, but deliver regardless.</param>
public sealed record MtaStsMxEvaluation(
    MtaStsMode Mode,
    bool MxAllowed,
    bool Enforced,
    bool RequireTls,
    bool RequireValidCertificate,
    string ExpectedCertificateName,
    bool ValidateButDoNotEnforce);

/// <summary>Evaluation of an MTA-STS policy against an MX host (RFC 8461 section 4).</summary>
public static class MtaStsEvaluation
{
    /// <summary>
    /// Returns <see langword="true"/> if the policy permits <paramref name="mxHost"/>. A policy with mode
    /// <see cref="MtaStsMode.None"/> permits everything; otherwise the host must match a pattern. In testing mode the
    /// result is still computed (and should be reported) but callers must not refuse delivery because of it.
    /// </summary>
    public static bool IsMxAllowed(MtaStsPolicy policy, string mxHost)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.Mode == MtaStsMode.None)
        {
            return true;
        }

        if (!DnsNames.TryNormalizeHost(mxHost, out string host))
        {
            return false;
        }

        foreach (string pattern in policy.MxPatterns)
        {
            if (MtaStsMxMatcher.MatchesNormalized(pattern, host))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Computes the requirements the policy places on a session with <paramref name="mxHost"/>.</summary>
    public static MtaStsMxEvaluation Evaluate(MtaStsPolicy policy, string mxHost)
    {
        ArgumentNullException.ThrowIfNull(policy);
        bool allowed = IsMxAllowed(policy, mxHost);
        _ = DnsNames.TryNormalizeHost(mxHost, out string expected);
        bool enforce = policy.Mode == MtaStsMode.Enforce;
        return new MtaStsMxEvaluation(
            policy.Mode,
            allowed,
            Enforced: enforce,
            RequireTls: enforce,
            RequireValidCertificate: enforce,
            ExpectedCertificateName: expected,
            ValidateButDoNotEnforce: policy.Mode == MtaStsMode.Testing);
    }
}
