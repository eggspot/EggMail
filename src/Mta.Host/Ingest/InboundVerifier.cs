using System.Net;
using Mta.Auth.Arc;
using Mta.Auth.AuthenticationResults;
using Mta.Auth.Dmarc;
using Mta.Auth.Domains;
using Mta.Auth.Spf;
using Mta.Core;
using Mta.Dkim;
using Mta.Dns;
using Mta.Mime;
using Mta.Storage;
using Mta.Storage.Logic;

namespace Mta.Host.Ingest;

/// <summary>What the verification of one inbound message found (design section 11.5).</summary>
public sealed class InboundVerification
{
    /// <summary>The verdicts as recorded on the stored message and shown in the API.</summary>
    public required InboundAuthResults Auth { get; init; }

    /// <summary>The DMARC evaluation the decision uses (the strictest one when the message names several From domains); null when there was no usable From domain.</summary>
    public DmarcEvaluation? Dmarc { get; init; }

    /// <summary>
    /// The DMARC verdict could not be settled: the policy lookup failed temporarily, the time ran out, or a failure depends on a mechanism that failed temporarily (a
    /// DKIM key that could not be fetched may have been the aligned pass). Under the action <c>reject</c> such a message is not accepted unverified, and not rejected either: the sender retries.
    /// </summary>
    public bool Unsettled { get; init; }

    /// <summary>The last seal of a valid ARC chain belongs to a trusted sealer and vouches for the From domain: a DMARC failure is treated as a pass for the decision (the recorded verdicts stay).</summary>
    public bool ArcOverridesDmarc { get; init; }

    public bool TimedOut { get; init; }

    /// <summary>The complete <c>Authentication-Results</c> header line, CRLF terminated.</summary>
    public required string AuthenticationResultsHeader { get; init; }
}

/// <summary>
/// Verifies an inbound message with the libraries of <c>Mta.Auth</c> and <c>Mta.Dkim</c> through the DNS client (design section 11.5): SPF for the MAIL FROM identity (HELO when the reverse-path is null)
/// and for the HELO name, DKIM, DMARC for every From domain, and the ARC chain. One total timeout bounds it all; whatever did not finish is a <c>temperror</c>, never a pass.
/// </summary>
public sealed class InboundVerifier
{
    private readonly IDnsResolver _dns;
    private readonly InboundReceiveOptions _options;
    private readonly IClock _clock;
    private readonly SpfEvaluator _spf;
    private readonly DkimVerifier _dkim;
    private readonly DmarcEvaluator _dmarc;
    private readonly ArcValidator _arc;
    private readonly string _authservId;

    public InboundVerifier(IDnsResolver dns, InboundReceiveOptions options, string hostname, IClock clock)
    {
        _dns = dns;
        _options = options;
        _clock = clock;
        _authservId = string.IsNullOrWhiteSpace(options.AuthenticationResultsId) ? hostname : options.AuthenticationResultsId.Trim();
        _spf = new SpfEvaluator(dns, new SpfOptions { ReceivingHostName = hostname, EvaluateExplanations = false, Clock = clock });
        _dkim = new DkimVerifier(dns, new DkimVerifierOptions { Clock = clock });
        _dmarc = new DmarcEvaluator(dns);
        _arc = new ArcValidator(dns, new ArcValidatorOptions { MaxInstances = InboundReceiveOptions.MaxArcInstances });
    }

    /// <summary>The authserv-id of the header this verifier writes (also what the receive path removes from incoming mail).</summary>
    public string AuthservId => _authservId;

    /// <param name="client">The address the sender connected from (an IPv4-mapped address is normalized).</param>
    /// <param name="helo">The name the client gave in HELO/EHLO.</param>
    /// <param name="mailFrom">The reverse-path as <c>local@domain</c>; empty for the null reverse-path.</param>
    /// <param name="message">The message exactly as received (CRLF lines), without the headers we add.</param>
    /// <param name="headers">The parsed header block of <paramref name="message"/>.</param>
    /// <param name="fromDomains">The distinct domains of the From header(s), lower-case; empty when there is none.</param>
    /// <param name="cancellationToken">Stops everything (shutdown): the caller's reply is not needed any more. The verification timeout is a result, not a cancellation.</param>
    public async ValueTask<InboundVerification> VerifyAsync(IPAddress client, string? helo, string mailFrom, ReadOnlyMemory<byte> message, HeaderList headers, IReadOnlyList<string> fromDomains, CancellationToken cancellationToken)
    {
        long started = _clock.Timestamp;
        client = NetworkKey.Normalize(client);
        helo = string.IsNullOrWhiteSpace(helo) ? string.Empty : helo.Trim();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.VerificationTimeout);
        bool timedOut = false;

        Task<SpfSessionResult?> spfTask = RunAsync(() => _spf.CheckSessionAsync(client, helo, mailFrom, timeout.Token).AsTask(), cancellationToken);
        Task<IReadOnlyList<DkimVerificationResult>?> dkimTask = RunAsync(() => _dkim.VerifyAsync(message, timeout.Token).AsTask(), cancellationToken);
        Task<ArcChainResult?> arcTask = RunAsync(() => _arc.ValidateAsync(message, timeout.Token).AsTask(), cancellationToken);
        await Task.WhenAll(spfTask, dkimTask, arcTask).ConfigureAwait(false);

        SpfSessionResult spf = spfTask.Result ?? TimedOutSpf(helo, mailFrom);
        IReadOnlyList<DkimVerificationResult> dkim = dkimTask.Result ?? [new DkimVerificationResult(DkimStatus.TempError, "verification timed out", DkimFailure.KeyDnsError)];
        ArcChainResult arc = arcTask.Result ?? new ArcChainResult(ArcChainStatus.Fail, "verification timed out", ArcFailure.KeyDnsError);
        timedOut = spfTask.Result is null || dkimTask.Result is null || arcTask.Result is null;
        if (arc.Failure == ArcFailure.TooManyInstances)
        {
            arc = new ArcChainResult(ArcChainStatus.Fail, "too_long", ArcFailure.TooManyInstances);
        }

        // DMARC for every From domain; the strictest evaluation decides (a second From header must not be a way around a policy).
        var evaluations = new List<DmarcEvaluation>(fromDomains.Count);
        var spfForDmarc = new SpfAuthResult(spf.Effective.Result, spf.Effective.Domain);
        var dkimForDmarc = dkim.Where(r => r.Domain is not null).Select(r => new DkimAuthResult(r.Domain!, r.IsPass, r.Selector)).ToList();
        foreach (string fromDomain in fromDomains)
        {
            if (timedOut)
            {
                evaluations.Add(TempErrorEvaluation(fromDomain, "verification timed out"));
                continue;
            }

            try
            {
                evaluations.Add(await _dmarc.EvaluateAsync(new DmarcInput(fromDomain, spfForDmarc, dkimForDmarc), timeout.Token).ConfigureAwait(false));
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                timedOut = true;
                evaluations.Add(TempErrorEvaluation(fromDomain, "verification timed out"));
            }
        }

        DmarcEvaluation? dmarc = evaluations.Count == 0 ? null : evaluations.MaxBy(Rank);
        bool temporaryFailureBehindFail = spf.Effective.Result == SpfResult.TempError || dkim.Any(r => r.Status == DkimStatus.TempError);
        bool unsettled = timedOut || dmarc?.Result == DmarcResult.TempError || (dmarc?.Result == DmarcResult.Fail && temporaryFailureBehindFail);
        bool arcOverride = !unsettled && dmarc?.Result == DmarcResult.Fail && evaluations.Count == 1 && ArcVouches(arc, headers, fromDomains[0]);

        (InboundVerdict dkimVerdict, string? dkimDomain) = ReduceDkim(dkim);
        InboundVerdict dmarcVerdict = dmarc is null ? InboundVerdict.PermError : unsettled ? InboundVerdict.TempError : ToVerdict(dmarc.Result);
        var auth = new InboundAuthResults(
            ToVerdict(spf.Effective.Result), spf.Effective.Domain,
            ToVerdict(spf.Helo.Result),
            dkimVerdict, dkimDomain,
            dmarcVerdict, dmarc?.AppliedPolicy?.ToString().ToLowerInvariant(),
            arc.Status switch { ArcChainStatus.Pass => InboundVerdict.Pass, ArcChainStatus.Fail => InboundVerdict.Fail, _ => InboundVerdict.None });

        RecordMetrics(auth, spf);
        InboundMetrics.VerificationSeconds.Record(_clock.GetElapsedTime(started).TotalSeconds);
        return new InboundVerification
        {
            Auth = auth,
            Dmarc = dmarc,
            Unsettled = unsettled,
            ArcOverridesDmarc = arcOverride,
            TimedOut = timedOut,
            AuthenticationResultsHeader = BuildHeader(client, helo, mailFrom, spf, dkim, dmarc, dmarcVerdict, arc),
        };
    }

    // A stage that ran out of time (the shared timeout, not the caller's cancellation) gives null; a cancellation by the caller propagates.
    private static async Task<T?> RunAsync<T>(Func<Task<T>> stage, CancellationToken caller) where T : class
    {
        try
        {
            return await stage().ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!caller.IsCancellationRequested)
        {
            return null;
        }
    }

    private static SpfSessionResult TimedOutSpf(string helo, string mailFrom)
    {
        var helored = new SpfCheckResult(SpfResult.TempError, helo.ToLowerInvariant(), Reason: "verification timed out");
        if (string.IsNullOrEmpty(mailFrom))
        {
            return new SpfSessionResult(helored, null);
        }

        int at = mailFrom.LastIndexOf('@');
        return new SpfSessionResult(helored, new SpfCheckResult(SpfResult.TempError, (at >= 0 ? mailFrom[(at + 1)..] : mailFrom).ToLowerInvariant(), Reason: "verification timed out"));
    }

    private static DmarcEvaluation TempErrorEvaluation(string fromDomain, string reason) =>
        new(DmarcResult.TempError, DmarcDisposition.None, null, fromDomain, null, fromDomain, false, false, false, null, null, null, reason);

    // The strictest evaluation: a failure under reject, under quarantine, any other failure, a temporary error, a permanent error, no policy, a pass.
    private static int Rank(DmarcEvaluation e) => e.Result switch
    {
        DmarcResult.Fail => 10 + (int)e.Disposition,
        DmarcResult.TempError => 8,
        DmarcResult.PermError => 7,
        DmarcResult.None => 6,
        _ => 0,
    };

    private static InboundVerdict ToVerdict(SpfResult result) => result switch
    {
        SpfResult.Pass => InboundVerdict.Pass,
        SpfResult.Fail => InboundVerdict.Fail,
        SpfResult.SoftFail => InboundVerdict.SoftFail,
        SpfResult.Neutral => InboundVerdict.Neutral,
        SpfResult.TempError => InboundVerdict.TempError,
        SpfResult.PermError => InboundVerdict.PermError,
        _ => InboundVerdict.None,
    };

    private static InboundVerdict ToVerdict(DmarcResult result) => result switch
    {
        DmarcResult.Pass => InboundVerdict.Pass,
        DmarcResult.Fail => InboundVerdict.Fail,
        DmarcResult.TempError => InboundVerdict.TempError,
        DmarcResult.PermError => InboundVerdict.PermError,
        _ => InboundVerdict.None,
    };

    private static InboundVerdict ToVerdict(DkimStatus status) => status switch
    {
        DkimStatus.Pass => InboundVerdict.Pass,
        DkimStatus.Fail => InboundVerdict.Fail,
        DkimStatus.Neutral => InboundVerdict.Neutral,
        DkimStatus.TempError => InboundVerdict.TempError,
        DkimStatus.PermError => InboundVerdict.PermError,
        _ => InboundVerdict.None,
    };

    /// <summary>Pass when any signature passed (its domain), otherwise the strongest failure: fail, permerror, temperror, neutral; none without signatures.</summary>
    internal static (InboundVerdict, string?) ReduceDkim(IReadOnlyList<DkimVerificationResult> results)
    {
        DkimVerificationResult? best = null;
        int bestRank = -1;
        foreach (DkimVerificationResult r in results)
        {
            int rank = r.Status switch { DkimStatus.Pass => 10, DkimStatus.Fail => 5, DkimStatus.PermError => 4, DkimStatus.TempError => 3, DkimStatus.Neutral => 2, _ => 0 };
            if (rank > bestRank)
            {
                best = r;
                bestRank = rank;
            }
        }

        return best is null ? (InboundVerdict.None, null) : (ToVerdict(best.Status), best.Domain);
    }

    private bool ArcVouches(ArcChainResult chain, HeaderList headers, string fromDomain)
    {
        if (chain.Status != ArcChainStatus.Pass || chain.SealDomains.Count == 0 || chain.InstanceCount != chain.SealDomains.Count)
        {
            return false;
        }

        // Only the last seal counts: it vouches for the chain before it. A trusted sealer in the middle does not.
        string lastSealer = chain.SealDomains[^1];
        if (!_options.TrustedArcSealers.Contains(lastSealer, StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        foreach (MimeHeader header in headers)
        {
            if (!header.NameEquals(ArcHeaderNames.AuthenticationResults)
                || !ArcAuthenticationResultsHeader.TryParse(header.GetUnfoldedValueBytes(), out ArcAuthenticationResultsHeader? aar, out _)
                || aar.Instance != chain.InstanceCount
                || aar.Results is not { } results)
            {
                continue;
            }

            PublicSuffixList psl = PublicSuffixList.Default;
            bool Aligned(string? domain) => !string.IsNullOrEmpty(domain) && psl.HaveSameOrganizationalDomain(domain.Trim().TrimEnd('.').ToLowerInvariant(), fromDomain);
            if (results.ForMethod("dmarc").Any(r => r.Result == "pass"))
            {
                return true;
            }

            if (results.ForMethod("spf").Any(r => r.Result == "pass" && Aligned(DomainOf(r.GetProperty("smtp", "mailfrom")))))
            {
                return true;
            }

            if (results.ForMethod("dkim").Any(r => r.Result == "pass" && Aligned(r.GetProperty("header", "d"))))
            {
                return true;
            }
        }

        return false;
    }

    private static string? DomainOf(string? mailbox)
    {
        if (mailbox is null)
        {
            return null;
        }

        int at = mailbox.LastIndexOf('@');
        return at >= 0 ? mailbox[(at + 1)..] : mailbox;
    }

    private string BuildHeader(IPAddress client, string helo, string mailFrom, SpfSessionResult spf, IReadOnlyList<DkimVerificationResult> dkim, DmarcEvaluation? dmarc, InboundVerdict dmarcVerdict, ArcChainResult arc)
    {
        var builder = new AuthenticationResultsBuilder(_authservId);
        if (spf.MailFrom is { } mailFromResult)
        {
            builder.AddSpf(mailFromResult, SpfIdentityKind.MailFrom, mailFrom);
        }

        if (!string.IsNullOrEmpty(helo))
        {
            builder.AddSpf(spf.Helo, SpfIdentityKind.Helo, helo);
        }

        foreach (string fragment in DkimAuthenticationResults.FormatAll(dkim))
        {
            builder.TryAddFragment(fragment);
        }

        if (dmarc is not null && dmarcVerdict != InboundVerdict.TempError)
        {
            builder.AddDmarc(dmarc);
        }
        else
        {
            (string, string, string)[] properties = dmarc is null ? [] : [("header", "from", dmarc.FromDomain)];
            builder.Add("dmarc", InboundNames.Of(dmarcVerdict), properties, reason: dmarc is null ? "no usable From header" : "could not be settled");
        }

        builder.TryAddFragment(ArcAuthenticationResults.Format(arc, client));
        return builder.BuildHeader();
    }

    private static void RecordMetrics(InboundAuthResults auth, SpfSessionResult spf)
    {
        static void Count(string mechanism, InboundVerdict verdict) =>
            InboundMetrics.Auth.Add(1, new KeyValuePair<string, object?>("mechanism", mechanism), new KeyValuePair<string, object?>("result", InboundNames.Of(verdict)));
        Count("spf", auth.Spf);
        Count("spf_helo", auth.SpfHelo);
        Count("dkim", auth.Dkim);
        Count("dmarc", auth.Dmarc);
        Count("arc", auth.Arc);
    }
}
