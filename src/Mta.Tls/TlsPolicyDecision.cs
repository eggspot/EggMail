using System.Security.Authentication;
using Mta.Dns;
using Mta.Tls.MtaSts;
using Mta.Tls.TlsRpt;

namespace Mta.Tls;

/// <summary>
/// The configured outbound TLS level for a recipient domain (modelled on Postfix <c>smtp_tls_security_level</c>).
/// MTA-STS and DANE can only raise the requirement above this level.
/// </summary>
public enum TlsSecurityLevel
{
    /// <summary>Never use TLS and ignore MTA-STS and DANE (an explicit operator override).</summary>
    None = 0,

    /// <summary>Opportunistic: use TLS when offered, accept any certificate, fall back to plaintext on failure. The default.</summary>
    May = 1,

    /// <summary>Require TLS but do not validate the certificate.</summary>
    Encrypt = 2,

    /// <summary>Require TLS and a certificate that validates (PKIX chain and the MX host name).</summary>
    Verify = 3,
}

/// <summary>Per-domain outbound TLS configuration.</summary>
public sealed record OutboundTlsConfiguration
{
    /// <summary>The default configuration: opportunistic TLS, MTA-STS and DANE enabled.</summary>
    public static OutboundTlsConfiguration Default { get; } = new();

    /// <summary>The configured level. Default <see cref="TlsSecurityLevel.May"/>.</summary>
    public TlsSecurityLevel Level { get; init; } = TlsSecurityLevel.May;

    /// <summary>Whether to look up and apply MTA-STS policies. Default true.</summary>
    public bool EnableMtaSts { get; init; } = true;

    /// <summary>Whether to look up and apply DANE TLSA records. Default true.</summary>
    public bool EnableDane { get; init; } = true;

    /// <summary>
    /// When true, delivery requires a usable DANE policy for every MX (like Postfix <c>dane-only</c>); an MX without one is
    /// blocked with <see cref="TlsResultType.DaneRequired"/>. Default false.
    /// </summary>
    public bool RequireDane { get; init; }
}

/// <summary>Tunables for <see cref="OutboundTlsPolicyResolver"/>.</summary>
public sealed class OutboundTlsOptions
{
    /// <summary>The protocols offered when TLS is not required (opportunistic). Default TLS 1.2 and 1.3.</summary>
    public SslProtocols OpportunisticProtocols { get; init; } = SslProtocols.Tls12 | SslProtocols.Tls13;
}

/// <summary>How the peer certificate is validated.</summary>
public enum TlsValidationMode
{
    /// <summary>Not validated (still inspected and recorded).</summary>
    None,

    /// <summary>PKIX: chain to a trusted root, valid in time, and a SAN matching the MX host name. Revocation is not checked.</summary>
    Pkix,

    /// <summary>DANE: authenticated by TLSA records (usage DANE-TA or DANE-EE).</summary>
    Dane,
}

/// <summary>Which rule produced a decision.</summary>
public enum TlsPolicyKind
{
    /// <summary>TLS disabled by configuration.</summary>
    Disabled,

    /// <summary>Opportunistic TLS (<see cref="TlsSecurityLevel.May"/>).</summary>
    Opportunistic,

    /// <summary>TLS required, no validation (<see cref="TlsSecurityLevel.Encrypt"/>).</summary>
    Encrypt,

    /// <summary>TLS required with PKIX validation (<see cref="TlsSecurityLevel.Verify"/>).</summary>
    Verify,

    /// <summary>MTA-STS policy in <c>testing</c> mode.</summary>
    MtaStsTesting,

    /// <summary>MTA-STS policy in <c>enforce</c> mode.</summary>
    MtaStsEnforce,

    /// <summary>DANE with usable secure TLSA records.</summary>
    Dane,
}

/// <summary>A pre-connection fact worth reporting through TLS-RPT.</summary>
/// <param name="PolicyType">The policy the fact belongs to.</param>
/// <param name="Failure">The classification, or <see langword="null"/> for an informational note.</param>
/// <param name="Message">Human-readable detail.</param>
public sealed record TlsPolicyReason(TlsPolicyType PolicyType, TlsResultType? Failure, string Message);

/// <summary>
/// What the delivery layer must do for one (recipient domain, MX host) connection: whether to offer STARTTLS, whether it
/// is required, how to validate the certificate and what a failure means.
/// </summary>
public sealed record TlsPolicyDecision
{
    /// <summary>The recipient (policy) domain.</summary>
    public required string RecipientDomain { get; init; }

    /// <summary>The MX host this decision is for (normalised).</summary>
    public required string MxHost { get; init; }

    /// <summary>The rule that produced the decision.</summary>
    public TlsPolicyKind Kind { get; init; }

    /// <summary>The policy type for TLS-RPT.</summary>
    public TlsPolicyType PolicyType { get; init; }

    /// <summary>False only when TLS is disabled: do not issue STARTTLS.</summary>
    public bool AttemptTls { get; init; } = true;

    /// <summary>True when the message must not be sent without a TLS session.</summary>
    public bool RequireTls { get; init; }

    /// <summary>How to validate the peer certificate.</summary>
    public TlsValidationMode Validation { get; init; }

    /// <summary>
    /// True when a failed validation must abort the session. False means validate and record, but accept
    /// (opportunistic, encrypt-only and MTA-STS testing mode).
    /// </summary>
    public bool EnforceValidation { get; init; }

    /// <summary>The TLS protocol versions to offer. Enforcing and DANE policies allow only TLS 1.2 and 1.3.</summary>
    public SslProtocols AllowedProtocols { get; init; } = SslProtocols.Tls12 | SslProtocols.Tls13;

    /// <summary>
    /// True when failing to establish or validate TLS must defer the message (4xx, retry later) rather than fall back to
    /// plaintext or bounce. Also true for blocked MX hosts.
    /// </summary>
    public bool FailureMustDefer { get; init; }

    /// <summary>True when this MX must not be contacted at all (not allowed by MTA-STS, or DANE unusable or unverifiable).</summary>
    public bool IsBlocked { get; init; }

    /// <summary>Why the MX is blocked.</summary>
    public string? BlockedReason { get; init; }

    /// <summary>The TLS-RPT classification of the block.</summary>
    public TlsResultType? BlockedFailure { get; init; }

    /// <summary>The name a PKIX certificate must match (the MX host).</summary>
    public string ExpectedHostname { get; init; } = string.Empty;

    /// <summary>The applicable MTA-STS policy, if any (also in testing mode).</summary>
    public MtaStsPolicy? StsPolicy { get; init; }

    /// <summary>The MX patterns allowed by the MTA-STS policy; <see langword="null"/> when there is no restriction.</summary>
    public IReadOnlyList<string>? AllowedMxPatterns { get; init; }

    /// <summary>The usable TLSA records for a DANE decision.</summary>
    public IReadOnlyList<TlsaRecord> TlsaRecords { get; init; } = [];

    /// <summary>TLSA records that were present but ignored or unusable.</summary>
    public IReadOnlyList<TlsaRecord> IgnoredTlsaRecords { get; init; } = [];

    /// <summary>Names a DANE-TA certificate may carry besides <see cref="ExpectedHostname"/>.</summary>
    public IReadOnlyList<string> DaneReferenceNames { get; init; } = [];

    /// <summary>Pre-connection facts for TLS-RPT (fetch errors, DANE problems, MX policy mismatch in testing mode).</summary>
    public IReadOnlyList<TlsPolicyReason> Reasons { get; init; } = [];

    /// <summary>True if the message may be sent in plaintext when TLS cannot be established.</summary>
    public bool AllowsPlaintextFallback => !RequireTls && !IsBlocked;

    /// <summary>The descriptor to use when recording this connection's outcome with <see cref="TlsRptCollector"/>.</summary>
    public TlsRptPolicyDescriptor TlsRptPolicy => PolicyType switch
    {
        TlsPolicyType.Sts when StsPolicy is not null => TlsRptPolicyDescriptor.FromMtaSts(StsPolicy),
        TlsPolicyType.Tlsa => TlsRptPolicyDescriptor.FromTlsa(TlsaRecords.Count > 0 ? TlsaRecords : IgnoredTlsaRecords),
        _ => TlsRptPolicyDescriptor.NoPolicy,
    };
}
