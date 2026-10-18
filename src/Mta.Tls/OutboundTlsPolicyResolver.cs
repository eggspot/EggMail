using System.Security.Authentication;
using Mta.Tls.Dane;
using Mta.Tls.MtaSts;

namespace Mta.Tls;

/// <summary>The per-domain part of a TLS policy decision: configuration plus the (domain-wide) MTA-STS lookup.</summary>
/// <param name="RecipientDomain">The normalised recipient domain.</param>
/// <param name="Configuration">The configuration applied.</param>
/// <param name="MtaSts">The MTA-STS lookup result (no policy when MTA-STS is disabled).</param>
public sealed record DomainTlsContext(string RecipientDomain, OutboundTlsConfiguration Configuration, MtaStsLookupResult MtaSts);

/// <summary>
/// Combines the configured TLS level, MTA-STS and DANE into a <see cref="TlsPolicyDecision"/> per MX host.
/// <para>
/// Precedence: <c>None</c> disables everything. Otherwise a usable secure DANE policy wins and is never overridden by
/// MTA-STS; a secure but unusable (or unverifiable) DANE state blocks the MX instead of downgrading. Without DANE, an
/// MTA-STS <c>enforce</c> policy requires an allowed MX and a validated certificate; <c>testing</c> validates and reports
/// but delivers. The configured level (<c>May</c>, <c>Encrypt</c>, <c>Verify</c>) is the floor underneath.
/// </para>
/// </summary>
public sealed class OutboundTlsPolicyResolver
{
    private readonly MtaStsPolicyStore? _sts;
    private readonly DaneTlsaLookup? _dane;
    private readonly OutboundTlsOptions _options;

    /// <summary>Creates a resolver. Either source may be <see langword="null"/> to disable it globally.</summary>
    public OutboundTlsPolicyResolver(MtaStsPolicyStore? mtaSts, DaneTlsaLookup? dane, OutboundTlsOptions? options = null)
    {
        _sts = mtaSts;
        _dane = dane;
        _options = options ?? new OutboundTlsOptions();
    }

    /// <summary>
    /// Resolves the domain-wide inputs (the MTA-STS lookup) once. Use with <see cref="ResolveForMxAsync"/> for each MX
    /// host to avoid repeating the lookup.
    /// </summary>
    public async ValueTask<DomainTlsContext> ResolveDomainAsync(string recipientDomain, OutboundTlsConfiguration? configuration = null, CancellationToken cancellationToken = default)
    {
        configuration ??= OutboundTlsConfiguration.Default;
        if (!DnsNames.TryNormalizeHost(recipientDomain, out string domain))
        {
            domain = recipientDomain?.Trim().TrimEnd('.').ToLowerInvariant() ?? string.Empty;
            return new DomainTlsContext(domain, configuration, MtaStsLookupResult.NoPolicy("invalid domain"));
        }

        MtaStsLookupResult sts = _sts is not null && configuration is { EnableMtaSts: true, Level: not TlsSecurityLevel.None }
            ? await _sts.GetPolicyAsync(domain, cancellationToken).ConfigureAwait(false)
            : MtaStsLookupResult.NoPolicy();
        return new DomainTlsContext(domain, configuration, sts);
    }

    /// <summary>Decides how to connect to <paramref name="mxHost"/> for a domain resolved with <see cref="ResolveDomainAsync"/>.</summary>
    /// <param name="context">The domain context.</param>
    /// <param name="mxHost">The MX host name.</param>
    /// <param name="mxRrsetAuthenticated">Whether the MX records were DNSSEC-authenticated (the AD bit); required for DANE to apply.</param>
    /// <param name="port">The SMTP port (default 25).</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async ValueTask<TlsPolicyDecision> ResolveForMxAsync(DomainTlsContext context, string mxHost, bool mxRrsetAuthenticated, int port = 25, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        DaneLookupResult dane = _dane is not null && context.Configuration is { EnableDane: true, Level: not TlsSecurityLevel.None }
            ? await _dane.LookupAsync(mxHost, port, mxRrsetAuthenticated, cancellationToken).ConfigureAwait(false)
            : DaneLookupResult.NotApplicable();
        return Decide(context.RecipientDomain, mxHost, context.Configuration, context.MtaSts, dane, _options);
    }

    /// <summary>Convenience: <see cref="ResolveDomainAsync"/> followed by <see cref="ResolveForMxAsync"/>.</summary>
    public async ValueTask<TlsPolicyDecision> ResolveAsync(string recipientDomain, string mxHost, OutboundTlsConfiguration? configuration, bool mxRrsetAuthenticated, int port = 25, CancellationToken cancellationToken = default)
    {
        DomainTlsContext context = await ResolveDomainAsync(recipientDomain, configuration, cancellationToken).ConfigureAwait(false);
        return await ResolveForMxAsync(context, mxHost, mxRrsetAuthenticated, port, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The pure decision function behind the resolver (no I/O), exposed for testing and for callers with their own lookups.</summary>
    public static TlsPolicyDecision Decide(
        string recipientDomain,
        string mxHost,
        OutboundTlsConfiguration configuration,
        MtaStsLookupResult sts,
        DaneLookupResult dane,
        OutboundTlsOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(sts);
        ArgumentNullException.ThrowIfNull(dane);
        options ??= new OutboundTlsOptions();
        if (!DnsNames.TryNormalizeHost(mxHost, out string mx))
        {
            mx = mxHost?.Trim().TrimEnd('.').ToLowerInvariant() ?? string.Empty;
        }

        const SslProtocols Enforced = SslProtocols.Tls12 | SslProtocols.Tls13;
        var reasons = new List<TlsPolicyReason>();

        if (configuration.Level == TlsSecurityLevel.None)
        {
            return new TlsPolicyDecision
            {
                RecipientDomain = recipientDomain,
                MxHost = mx,
                Kind = TlsPolicyKind.Disabled,
                PolicyType = TlsPolicyType.NoPolicyFound,
                AttemptTls = false,
                AllowedProtocols = SslProtocols.None,
                ExpectedHostname = mx,
                Reasons = [new TlsPolicyReason(TlsPolicyType.NoPolicyFound, null, "TLS disabled by configuration; MTA-STS and DANE not consulted")],
            };
        }

        // 1. DANE has precedence over everything else, including a failing DANE result.
        if (dane.Status == DaneStatus.Usable)
        {
            reasons.Add(new TlsPolicyReason(TlsPolicyType.Tlsa, null, "DANE: secure TLSA records found; MTA-STS ignored (RFC 8461 section 2)"));
            return new TlsPolicyDecision
            {
                RecipientDomain = recipientDomain,
                MxHost = mx,
                Kind = TlsPolicyKind.Dane,
                PolicyType = TlsPolicyType.Tlsa,
                RequireTls = true,
                Validation = TlsValidationMode.Dane,
                EnforceValidation = true,
                AllowedProtocols = Enforced,
                FailureMustDefer = true,
                ExpectedHostname = mx,
                TlsaRecords = dane.UsableRecords,
                IgnoredTlsaRecords = dane.IgnoredRecords,
                DaneReferenceNames = dane.ReferenceNames.Where(n => n != mx).ToArray(),
                Reasons = reasons,
            };
        }

        if (dane.Status is DaneStatus.Unusable or DaneStatus.LookupFailed)
        {
            string why = dane.Status == DaneStatus.Unusable
                ? "DANE: secure TLSA records are present but none is usable; refusing to downgrade"
                : "DANE: TLSA lookup failed; the MX cannot be used safely";
            var failure = dane.Failure ?? TlsResultType.TlsaInvalid;
            reasons.Add(new TlsPolicyReason(TlsPolicyType.Tlsa, failure, why));
            return Blocked(recipientDomain, mx, TlsPolicyType.Tlsa, failure, why, reasons, dane.IgnoredRecords);
        }

        if (configuration.RequireDane)
        {
            const string Why = "DANE required by configuration but the MX has no usable TLSA policy";
            reasons.Add(new TlsPolicyReason(TlsPolicyType.Tlsa, TlsResultType.DaneRequired, Why));
            return Blocked(recipientDomain, mx, TlsPolicyType.Tlsa, TlsResultType.DaneRequired, Why, reasons, []);
        }

        // 2. MTA-STS.
        if (sts.Failure is { } stsFailure)
        {
            reasons.Add(new TlsPolicyReason(TlsPolicyType.Sts, stsFailure, "MTA-STS: " + (sts.Detail ?? stsFailure.ToWireString())));
        }

        var level = configuration.Level;
        if (sts.Policy is { Mode: not MtaStsMode.None } policy)
        {
            bool mxAllowed = MtaStsEvaluation.IsMxAllowed(policy, mx);
            if (policy.Mode == MtaStsMode.Enforce)
            {
                if (!mxAllowed)
                {
                    const string Why = "MTA-STS enforce: MX host is not listed in the policy";
                    reasons.Add(new TlsPolicyReason(TlsPolicyType.Sts, TlsResultType.ValidationFailure, Why));
                    return Blocked(recipientDomain, mx, TlsPolicyType.Sts, TlsResultType.ValidationFailure, Why, reasons, [], policy);
                }

                return new TlsPolicyDecision
                {
                    RecipientDomain = recipientDomain,
                    MxHost = mx,
                    Kind = TlsPolicyKind.MtaStsEnforce,
                    PolicyType = TlsPolicyType.Sts,
                    RequireTls = true,
                    Validation = TlsValidationMode.Pkix,
                    EnforceValidation = true,
                    AllowedProtocols = Enforced,
                    FailureMustDefer = true,
                    ExpectedHostname = mx,
                    StsPolicy = policy,
                    AllowedMxPatterns = policy.MxPatterns,
                    Reasons = reasons,
                };
            }

            // Testing: validate and report, deliver regardless. The configured level can only add requirements.
            if (!mxAllowed)
            {
                reasons.Add(new TlsPolicyReason(TlsPolicyType.Sts, TlsResultType.ValidationFailure, "MTA-STS testing: MX host is not listed in the policy (delivering anyway)"));
            }

            bool require = level >= TlsSecurityLevel.Encrypt;
            bool enforceValidation = level == TlsSecurityLevel.Verify;
            return new TlsPolicyDecision
            {
                RecipientDomain = recipientDomain,
                MxHost = mx,
                Kind = TlsPolicyKind.MtaStsTesting,
                PolicyType = TlsPolicyType.Sts,
                RequireTls = require,
                Validation = TlsValidationMode.Pkix,
                EnforceValidation = enforceValidation,
                AllowedProtocols = require ? Enforced : options.OpportunisticProtocols,
                FailureMustDefer = require,
                ExpectedHostname = mx,
                StsPolicy = policy,
                ToleratedFailure = mxAllowed ? null : TlsResultType.ValidationFailure,
                Reasons = reasons,
            };
        }

        // 3. Configured level only.
        switch (level)
        {
            case TlsSecurityLevel.Verify:
                return new TlsPolicyDecision
                {
                    RecipientDomain = recipientDomain,
                    MxHost = mx,
                    Kind = TlsPolicyKind.Verify,
                    PolicyType = TlsPolicyType.NoPolicyFound,
                    RequireTls = true,
                    Validation = TlsValidationMode.Pkix,
                    EnforceValidation = true,
                    AllowedProtocols = Enforced,
                    FailureMustDefer = true,
                    ExpectedHostname = mx,
                    Reasons = reasons,
                };
            case TlsSecurityLevel.Encrypt:
                return new TlsPolicyDecision
                {
                    RecipientDomain = recipientDomain,
                    MxHost = mx,
                    Kind = TlsPolicyKind.Encrypt,
                    PolicyType = TlsPolicyType.NoPolicyFound,
                    RequireTls = true,
                    Validation = TlsValidationMode.None,
                    AllowedProtocols = Enforced,
                    FailureMustDefer = true,
                    ExpectedHostname = mx,
                    Reasons = reasons,
                };
            default:
                return new TlsPolicyDecision
                {
                    RecipientDomain = recipientDomain,
                    MxHost = mx,
                    Kind = TlsPolicyKind.Opportunistic,
                    PolicyType = TlsPolicyType.NoPolicyFound,
                    Validation = TlsValidationMode.None,
                    AllowedProtocols = options.OpportunisticProtocols,
                    ExpectedHostname = mx,
                    Reasons = reasons,
                };
        }
    }

    private static TlsPolicyDecision Blocked(
        string domain,
        string mx,
        TlsPolicyType policyType,
        TlsResultType failure,
        string reason,
        List<TlsPolicyReason> reasons,
        IReadOnlyList<Mta.Dns.TlsaRecord> ignored,
        MtaStsPolicy? sts = null) =>
        new()
        {
            RecipientDomain = domain,
            MxHost = mx,
            Kind = policyType == TlsPolicyType.Tlsa ? TlsPolicyKind.Dane : TlsPolicyKind.MtaStsEnforce,
            PolicyType = policyType,
            RequireTls = true,
            Validation = policyType == TlsPolicyType.Tlsa ? TlsValidationMode.Dane : TlsValidationMode.Pkix,
            EnforceValidation = true,
            AllowedProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            FailureMustDefer = true,
            IsBlocked = true,
            BlockedReason = reason,
            BlockedFailure = failure,
            ExpectedHostname = mx,
            StsPolicy = sts,
            AllowedMxPatterns = sts?.MxPatterns,
            IgnoredTlsaRecords = ignored,
            Reasons = reasons,
        };
}
