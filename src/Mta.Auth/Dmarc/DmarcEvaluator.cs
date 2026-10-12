using Mta.Auth.Domains;
using Mta.Auth.Spf;
using Mta.Core;
using Mta.Dns;

namespace Mta.Auth.Dmarc;

/// <summary>The DMARC verdict (RFC 7489 section 11.2, <c>dmarc=</c> in Authentication-Results).</summary>
public enum DmarcResult
{
    /// <summary>No DMARC policy was published for the From domain (or the record was unusable).</summary>
    None = 0,

    /// <summary>At least one of SPF or DKIM passed with an aligned identifier.</summary>
    Pass,

    /// <summary>Neither SPF nor DKIM passed with an aligned identifier.</summary>
    Fail,

    /// <summary>A transient DNS error prevented policy discovery.</summary>
    TempError,

    /// <summary>The input was invalid (for example an unusable From domain).</summary>
    PermError,
}

/// <summary>What the receiver should do with the message (the <c>disposition</c> of a report row).</summary>
public enum DmarcDisposition
{
    /// <summary>Accept normally.</summary>
    None = 0,

    /// <summary>Treat as suspicious.</summary>
    Quarantine,

    /// <summary>Reject.</summary>
    Reject,
}

/// <summary>The outcome of looking up a DMARC policy.</summary>
public enum DmarcLookupStatus
{
    /// <summary>A valid policy record was found.</summary>
    Found,

    /// <summary>No usable policy exists (no record, several records, or an invalid record).</summary>
    NotFound,

    /// <summary>A DNS error prevented the lookup.</summary>
    TempError,
}

/// <summary>An SPF result and the domain it authenticated, as input to DMARC.</summary>
/// <param name="Result">The SPF verdict.</param>
/// <param name="Domain">The domain SPF was checked for: the MAIL FROM domain, or the HELO domain when the reverse-path was null.</param>
public sealed record SpfAuthResult(SpfResult Result, string? Domain);

/// <summary>A DKIM signature verification result, as input to DMARC.</summary>
/// <param name="Domain">The signing domain (<c>d=</c>).</param>
/// <param name="Passed">True when the signature verified.</param>
/// <param name="Selector">The selector (<c>s=</c>); only used for reports.</param>
public sealed record DkimAuthResult(string Domain, bool Passed, string? Selector = null);

/// <summary>Everything DMARC evaluation needs about one message.</summary>
/// <param name="FromDomain">The domain of the RFC 5322 From address.</param>
/// <param name="Spf">The SPF result for the envelope identity.</param>
/// <param name="Dkim">The DKIM results, one per signature.</param>
public sealed record DmarcInput(string FromDomain, SpfAuthResult Spf, IReadOnlyList<DkimAuthResult> Dkim);

/// <summary>The result of DMARC policy discovery for a From domain.</summary>
/// <param name="Status">Whether a policy was found.</param>
/// <param name="Record">The record, when <see cref="Status"/> is Found.</param>
/// <param name="PolicyDomain">The domain the record was published for (the From domain or its organizational domain).</param>
/// <param name="FromOrganizationalDomain">True when the record came from the organizational domain fallback.</param>
/// <param name="Reason">A short description for NotFound and TempError.</param>
public sealed record DmarcPolicyLookup(DmarcLookupStatus Status, DmarcRecord? Record, string? PolicyDomain, bool FromOrganizationalDomain, string? Reason);

/// <summary>Identifier alignment for one mechanism (SPF or DKIM).</summary>
/// <param name="Authenticated">True when the mechanism itself passed (SPF pass, or any DKIM signature verified).</param>
/// <param name="Aligned">True when it passed with an identifier aligned to the From domain.</param>
/// <param name="Domain">The aligned authenticated domain; otherwise the first authenticated (or provided) domain, for diagnostics.</param>
/// <param name="Mode">The alignment mode that was applied.</param>
public sealed record DmarcAlignmentResult(bool Authenticated, bool Aligned, string? Domain, DmarcAlignmentMode Mode);

/// <summary>The complete outcome of a DMARC evaluation.</summary>
/// <param name="Result">The verdict.</param>
/// <param name="Disposition">The action to take after pct sampling (None unless the message failed).</param>
/// <param name="AppliedPolicy">The policy that was selected from the record (<c>p</c>, or <c>sp</c> for subdomains), before sampling; null without a record.</param>
/// <param name="FromDomain">The normalised From domain.</param>
/// <param name="PolicyDomain">The domain the policy record belongs to.</param>
/// <param name="OrganizationalDomain">The organizational domain of the From domain.</param>
/// <param name="UsedOrganizationalDomainRecord">True when the record was found at the organizational domain rather than the From domain.</param>
/// <param name="SubdomainPolicyApplied">True when <c>sp</c> (or its fallback to <c>p</c>) was chosen because the From domain is a subdomain.</param>
/// <param name="SampledOut">True when the policy was weakened by the <c>pct</c> sampling.</param>
/// <param name="Record">The policy record.</param>
/// <param name="Spf">SPF alignment details; null when there was no policy.</param>
/// <param name="Dkim">DKIM alignment details; null when there was no policy.</param>
/// <param name="Reason">A short explanation for None, TempError and PermError.</param>
public sealed record DmarcEvaluation(
    DmarcResult Result,
    DmarcDisposition Disposition,
    DmarcPolicy? AppliedPolicy,
    string FromDomain,
    string? PolicyDomain,
    string OrganizationalDomain,
    bool UsedOrganizationalDomainRecord,
    bool SubdomainPolicyApplied,
    bool SampledOut,
    DmarcRecord? Record,
    DmarcAlignmentResult? Spf,
    DmarcAlignmentResult? Dkim,
    string? Reason)
{
    /// <summary>The lower-case keyword for <c>dmarc=</c> in Authentication-Results.</summary>
    public string ResultKeyword => Result switch
    {
        DmarcResult.Pass => "pass",
        DmarcResult.Fail => "fail",
        DmarcResult.TempError => "temperror",
        DmarcResult.PermError => "permerror",
        _ => "none",
    };
}

/// <summary>Tunable behaviour of <see cref="DmarcEvaluator"/>.</summary>
public sealed class DmarcOptions
{
    /// <summary>The public suffix list used to find organizational domains. Default: the embedded list.</summary>
    public PublicSuffixList PublicSuffixList { get; init; } = PublicSuffixList.Default;

    /// <summary>The random source for <c>pct</c> sampling; inject a seeded instance for deterministic tests.</summary>
    public Random Random { get; init; } = Random.Shared;

    /// <summary>Maximum policy record length in characters; longer records are ignored.</summary>
    public int MaxRecordLength { get; init; } = DmarcRecord.DefaultMaxLength;

    /// <summary>The default options.</summary>
    public static DmarcOptions Default { get; } = new();
}

/// <summary>Evaluates DMARC (RFC 7489).</summary>
public interface IDmarcEvaluator
{
    /// <summary>Discovers the policy for the From domain and evaluates alignment of the SPF and DKIM results.</summary>
    /// <param name="input">The From domain and the authentication results.</param>
    /// <param name="cancellationToken">Cancels the DNS lookups.</param>
    ValueTask<DmarcEvaluation> EvaluateAsync(DmarcInput input, CancellationToken cancellationToken = default);

    /// <summary>Looks up the policy record for a From domain (RFC 7489 section 6.6.3).</summary>
    /// <param name="fromDomain">The RFC 5322 From domain.</param>
    /// <param name="cancellationToken">Cancels the DNS lookups.</param>
    ValueTask<DmarcPolicyLookup> LookupPolicyAsync(string fromDomain, CancellationToken cancellationToken = default);
}

/// <summary>
/// DMARC evaluator. Policy discovery queries <c>_dmarc.&lt;from&gt;</c> and falls back to the organizational domain
/// (RFC 7489 section 6.6.3); several records, a bad record, or no record mean "no policy"; DNS errors give TempError.
/// Instances are stateless and safe for concurrent use.
/// </summary>
public sealed class DmarcEvaluator : IDmarcEvaluator
{
    private readonly IDnsResolver _resolver;
    private readonly DmarcOptions _options;

    /// <summary>Creates an evaluator.</summary>
    /// <param name="resolver">The DNS resolver.</param>
    /// <param name="options">Options; null uses <see cref="DmarcOptions.Default"/>.</param>
    public DmarcEvaluator(IDnsResolver resolver, DmarcOptions? options = null)
    {
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _options = options ?? DmarcOptions.Default;
    }

    /// <inheritdoc />
    public async ValueTask<DmarcEvaluation> EvaluateAsync(DmarcInput input, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        DmarcPolicyLookup lookup = await LookupPolicyAsync(input.FromDomain, cancellationToken).ConfigureAwait(false);
        return Evaluate(input, lookup);
    }

    /// <summary>Evaluates a message against an already discovered policy (no DNS access). Use it to cache lookups.</summary>
    /// <param name="input">The From domain and the authentication results.</param>
    /// <param name="lookup">The policy lookup result for <see cref="DmarcInput.FromDomain"/>.</param>
    public DmarcEvaluation Evaluate(DmarcInput input, DmarcPolicyLookup lookup)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(lookup);
        if (!TryNormalize(input.FromDomain, out string? from))
        {
            return Empty(DmarcResult.PermError, (input.FromDomain ?? string.Empty).Trim().ToLowerInvariant(), "From domain is not a valid domain name");
        }

        PublicSuffixList psl = _options.PublicSuffixList;
        string org = psl.GetOrganizationalDomain(from);
        if (lookup.Status == DmarcLookupStatus.TempError)
        {
            return Empty(DmarcResult.TempError, from, lookup.Reason ?? "DNS error during DMARC policy lookup", org);
        }

        if (lookup.Status != DmarcLookupStatus.Found || lookup.Record is null)
        {
            return Empty(DmarcResult.None, from, lookup.Reason ?? "no DMARC policy", org);
        }

        DmarcRecord record = lookup.Record;
        DmarcAlignmentResult spf = AlignSpf(input.Spf, from, record.SpfAlignment, psl);
        DmarcAlignmentResult dkim = AlignDkim(input.Dkim, from, record.DkimAlignment, psl);

        bool subdomainPolicy = lookup.FromOrganizationalDomain && !string.Equals(from, org, StringComparison.Ordinal);
        DmarcPolicy applied = subdomainPolicy ? record.SubdomainPolicy ?? record.Policy : record.Policy;

        if (spf.Aligned || dkim.Aligned)
        {
            return new DmarcEvaluation(
                DmarcResult.Pass, DmarcDisposition.None, applied, from, lookup.PolicyDomain, org,
                lookup.FromOrganizationalDomain, subdomainPolicy, false, record, spf, dkim, null);
        }

        DmarcPolicy effective = applied;
        bool sampledOut = false;
        if (effective != DmarcPolicy.None && record.Percentage < 100 && _options.Random.Next(100) >= record.Percentage)
        {
            // Outside the sampled percentage: apply the next lower policy (RFC 7489 section 6.6.4).
            effective = effective == DmarcPolicy.Reject ? DmarcPolicy.Quarantine : DmarcPolicy.None;
            sampledOut = true;
        }

        return new DmarcEvaluation(
            DmarcResult.Fail, ToDisposition(effective), applied, from, lookup.PolicyDomain, org,
            lookup.FromOrganizationalDomain, subdomainPolicy, sampledOut, record, spf, dkim, null);
    }

    /// <inheritdoc />
    public async ValueTask<DmarcPolicyLookup> LookupPolicyAsync(string fromDomain, CancellationToken cancellationToken = default)
    {
        if (!TryNormalize(fromDomain, out string? from))
        {
            return new DmarcPolicyLookup(DmarcLookupStatus.NotFound, null, null, false, "From domain is not a valid domain name");
        }

        (DmarcPolicyLookup first, bool noRecordAtFrom) = await QueryPolicyAsync(from, false, cancellationToken).ConfigureAwait(false);
        if (!noRecordAtFrom)
        {
            return first;
        }

        string org = _options.PublicSuffixList.GetOrganizationalDomain(from);
        if (string.Equals(org, from, StringComparison.Ordinal))
        {
            return new DmarcPolicyLookup(DmarcLookupStatus.NotFound, null, null, false, "no DMARC record");
        }

        (DmarcPolicyLookup second, bool noRecordAtOrg) = await QueryPolicyAsync(org, true, cancellationToken).ConfigureAwait(false);
        return noRecordAtOrg ? second with { Reason = "no DMARC record" } : second;
    }

    /// <summary>Queries one name; the flag is true when the name has no DMARC candidate record (so the caller may fall back).</summary>
    private async ValueTask<(DmarcPolicyLookup Lookup, bool NoRecord)> QueryPolicyAsync(string domain, bool organizational, CancellationToken ct)
    {
        DnsResponse response;
        try
        {
            response = await _resolver.QueryAsync("_dmarc." + domain, DnsRecordType.TXT, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
#pragma warning disable CA1031 // Any resolver failure is a transient error for policy discovery.
        catch (Exception)
#pragma warning restore CA1031
        {
            return (new DmarcPolicyLookup(DmarcLookupStatus.TempError, null, domain, organizational, "DNS error looking up _dmarc." + domain), false);
        }

        if (response.Rcode is not (DnsRcode.NoError or DnsRcode.NameError))
        {
            return (new DmarcPolicyLookup(DmarcLookupStatus.TempError, null, domain, organizational, "DNS error looking up _dmarc." + domain), false);
        }

        string? candidate = null;
        foreach (TxtRecord txt in response.Get<TxtRecord>())
        {
            if (!DmarcRecord.HasVersionTag(txt.Text))
            {
                continue;
            }

            if (candidate is not null)
            {
                return (new DmarcPolicyLookup(DmarcLookupStatus.NotFound, null, domain, organizational, "multiple DMARC records at _dmarc." + domain), false);
            }

            candidate = txt.Text;
        }

        if (candidate is null)
        {
            return (new DmarcPolicyLookup(DmarcLookupStatus.NotFound, null, domain, organizational, "no DMARC record at _dmarc." + domain), true);
        }

        if (!DmarcRecord.TryParse(candidate, _options.MaxRecordLength, out DmarcRecord? record, out string? error))
        {
            return (new DmarcPolicyLookup(DmarcLookupStatus.NotFound, null, domain, organizational, "invalid DMARC record: " + error), false);
        }

        return (new DmarcPolicyLookup(DmarcLookupStatus.Found, record, domain, organizational, null), false);
    }

    private static DmarcAlignmentResult AlignSpf(SpfAuthResult spf, string from, DmarcAlignmentMode mode, PublicSuffixList psl)
    {
        string? domain = spf?.Domain is { Length: > 0 } d ? Normalize(d) : null;
        bool passed = spf is { Result: SpfResult.Pass } && domain is not null;
        bool aligned = passed && IsAligned(domain!, from, mode, psl);
        return new DmarcAlignmentResult(passed, aligned, domain, mode);
    }

    private static DmarcAlignmentResult AlignDkim(IReadOnlyList<DkimAuthResult>? results, string from, DmarcAlignmentMode mode, PublicSuffixList psl)
    {
        bool anyPassed = false;
        string? firstPassed = null;
        if (results is not null)
        {
            foreach (DkimAuthResult r in results)
            {
                if (r is null || !r.Passed || string.IsNullOrWhiteSpace(r.Domain))
                {
                    continue;
                }

                anyPassed = true;
                string domain = Normalize(r.Domain);
                firstPassed ??= domain;
                if (IsAligned(domain, from, mode, psl))
                {
                    return new DmarcAlignmentResult(true, true, domain, mode);
                }
            }
        }

        return new DmarcAlignmentResult(anyPassed, false, firstPassed, mode);
    }

    /// <summary>
    /// Identifier alignment (RFC 7489 section 3.1): strict requires identical domains, relaxed the same organizational domain.
    /// </summary>
    /// <param name="authenticatedDomain">The SPF or DKIM domain.</param>
    /// <param name="fromDomain">The From domain.</param>
    /// <param name="mode">Strict or relaxed.</param>
    /// <param name="publicSuffixList">The suffix list for relaxed mode.</param>
    public static bool IsAligned(string authenticatedDomain, string fromDomain, DmarcAlignmentMode mode, PublicSuffixList publicSuffixList)
    {
        ArgumentNullException.ThrowIfNull(publicSuffixList);
        string a = Normalize(authenticatedDomain ?? string.Empty);
        string f = Normalize(fromDomain ?? string.Empty);
        if (a.Length == 0 || f.Length == 0)
        {
            return false;
        }

        return mode == DmarcAlignmentMode.Strict
            ? string.Equals(a, f, StringComparison.Ordinal)
            : publicSuffixList.HaveSameOrganizationalDomain(a, f);
    }

    private static DmarcDisposition ToDisposition(DmarcPolicy policy) => policy switch
    {
        DmarcPolicy.Reject => DmarcDisposition.Reject,
        DmarcPolicy.Quarantine => DmarcDisposition.Quarantine,
        _ => DmarcDisposition.None,
    };

    private static string Normalize(string domain)
    {
        string d = domain.Trim();
        if (d.EndsWith('.'))
        {
            d = d[..^1];
        }

        return d.ToLowerInvariant();
    }

    private static bool TryNormalize(string? domain, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(domain))
        {
            return false;
        }

        string d = Normalize(domain);
        if (!EmailAddress.IsValidHostName(d))
        {
            return false;
        }

        normalized = d;
        return true;
    }

    private DmarcEvaluation Empty(DmarcResult result, string from, string reason, string? organizational = null) =>
        new(result, DmarcDisposition.None, null, from, null, organizational ?? from, false, false, false, null, null, null, reason);
}
