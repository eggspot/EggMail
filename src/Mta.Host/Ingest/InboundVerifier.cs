using System.Net;
using System.Text.RegularExpressions;
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
    /// The DMARC verdict could not be settled for at least one From domain: the policy lookup failed temporarily, the time ran out, or a failure depends on a mechanism that failed temporarily <em>for the
    /// From domain's own identifiers</em> (a DKIM key of an aligned signature that could not be fetched may have been the pass; the SPF record of an unrelated domain could not have been). Under the action
    /// <c>reject</c> such a message is neither accepted unverified nor rejected: the sender retries.
    /// </summary>
    public bool Unsettled { get; init; }

    /// <summary>
    /// The strictest policy among the From domains whose DMARC failure is <b>settled</b> (<see cref="DmarcDisposition.Reject"/> or <see cref="DmarcDisposition.Quarantine"/>); <see cref="DmarcDisposition.None"/> when there is none.
    /// A settled failure decides on its own: another From domain whose verdict could not be settled (an attacker can make one of his own domains fail to resolve) must not hide it.
    /// </summary>
    public DmarcDisposition DecisiveFailure { get; init; }

    /// <summary>The message has no usable From (none, an empty or group-only one, or a mailbox that does not parse): there is no domain whose policy could be applied, which is treated as a DMARC failure under a reject policy.</summary>
    public bool NoUsableFrom { get; init; }

    /// <summary>The last seal of a valid ARC chain belongs to a trusted sealer and vouches for the From domain: a DMARC failure is treated as a pass for the action decision (the original verdicts stay recorded).</summary>
    public bool ArcOverridesDmarc { get; init; }

    public bool TimedOut { get; init; }

    /// <summary>The complete <c>Authentication-Results</c> header line, CRLF terminated.</summary>
    public required string AuthenticationResultsHeader { get; init; }
}

/// <summary>
/// Verifies an inbound message with the libraries of <c>Mta.Auth</c> and <c>Mta.Dkim</c> through the DNS client (design section 11.5): SPF for the MAIL FROM identity (HELO when the reverse-path is null) and for
/// the HELO name, DKIM, DMARC for every From domain, and the ARC chain. One total timeout bounds SPF, DKIM and ARC; whatever did not finish is a <c>temperror</c> for that mechanism only (DMARC still runs with
/// what finished). One query budget bounds all the DNS work of a message, so a hostile record set cannot turn the receiver into a DNS load generator.
/// </summary>
public sealed class InboundVerifier
{
    // The DNS work of a message is bounded per stage, by backstops over the RFC limits the libraries enforce themselves (SPF: 10 DNS-querying terms, 10 names per mx, 2 voids; DKIM: 5 signatures; ARC: 25 keys):
    // a record set that is legal but hostile costs a bounded number of queries, and a stage that uses its budget up cannot starve another one (the DMARC lookup of the victim's domain has its own).

    /// <summary>Queries the SPF check of the MAIL FROM identity may make (a legal record with ten <c>mx:</c> terms of ten hosts needs about 170).</summary>
    public const int MaxSpfQueries = 200;

    /// <summary>Queries the SPF check of the HELO name may make.</summary>
    public const int MaxHeloSpfQueries = 30;

    public const int MaxDkimQueries = 20;
    public const int MaxArcQueries = 40;
    public const int MaxDmarcQueries = 8;

    /// <summary>The most queries all the checks of one message can make together.</summary>
    public const int MaxQueriesPerMessage = MaxSpfQueries + MaxHeloSpfQueries + MaxDkimQueries + MaxArcQueries + MaxDmarcQueries;

    /// <summary>DMARC needs one or two lookups; it gets its own short time so a stage that used up the total still leaves it room.</summary>
    private static readonly TimeSpan DmarcTimeLimit = TimeSpan.FromSeconds(5);

    private static readonly Regex DomainTag = new(@"(?:^|;)\s*d\s*=\s*([^;\s]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    private readonly IDnsResolver _dns;
    private readonly InboundReceiveOptions _options;
    private readonly IClock _clock;
    private readonly string _hostname;
    private readonly string _authservId;

    public InboundVerifier(IDnsResolver dns, InboundReceiveOptions options, string hostname, IClock clock)
    {
        _dns = dns;
        _options = options;
        _clock = clock;
        _hostname = hostname;
        _authservId = string.IsNullOrWhiteSpace(options.AuthenticationResultsId) ? hostname : options.AuthenticationResultsId.Trim();
    }

    /// <summary>The authserv-id of the header this verifier writes (also what the receive path removes from incoming mail).</summary>
    public string AuthservId => _authservId;

    /// <param name="client">The address the sender connected from (an IPv4-mapped address is normalized).</param>
    /// <param name="helo">The name the client gave in HELO/EHLO.</param>
    /// <param name="mailFrom">The reverse-path as <c>local@domain</c>; empty for the null reverse-path.</param>
    /// <param name="message">The message exactly as received (CRLF lines), without the headers we add.</param>
    /// <param name="headers">The parsed header block of <paramref name="message"/>.</param>
    /// <param name="fromDomains">The distinct domains of the From header(s), lower-case; empty when there is none.</param>
    /// <param name="fromUsable">Whether the From header(s) gave a usable identity: every mailbox parsed, at least one. False sets <see cref="InboundVerification.NoUsableFrom"/>.</param>
    /// <param name="cancellationToken">Stops everything (shutdown): the caller's reply is not needed any more. The verification timeout is a result, not a cancellation.</param>
    public async ValueTask<InboundVerification> VerifyAsync(IPAddress client, string? helo, string mailFrom, ReadOnlyMemory<byte> message, HeaderList headers, IReadOnlyList<string> fromDomains, bool fromUsable, CancellationToken cancellationToken)
    {
        long started = _clock.Timestamp;
        client = NetworkKey.Normalize(client);
        helo = string.IsNullOrWhiteSpace(helo) ? string.Empty : helo.Trim();
        var spfHelo = new SpfEvaluator(new QueryBudgetResolver(_dns, MaxHeloSpfQueries), new SpfOptions { ReceivingHostName = _hostname, EvaluateExplanations = false, Clock = _clock, MaxDnsLookups = 4, MaxVoidLookups = 1, MaxMxPtrNames = 3 });
        var spfMail = new SpfEvaluator(new QueryBudgetResolver(_dns, MaxSpfQueries), new SpfOptions { ReceivingHostName = _hostname, EvaluateExplanations = false, Clock = _clock });
        var dkim = new DkimVerifier(new QueryBudgetResolver(_dns, MaxDkimQueries), new DkimVerifierOptions { Clock = _clock });
        var arcValidator = new ArcValidator(new QueryBudgetResolver(_dns, MaxArcQueries), new ArcValidatorOptions { MaxInstances = InboundReceiveOptions.MaxArcInstances });

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.VerificationTimeout);

        // Behind source NAT the address is the NAT's, not the sender's: an SPF verdict for it would be wrong either way. No check is better than a wrong one (unless the operator says the clients are real).
        bool checkSpf = _options.CheckSpfForInternalClients || !NetworkKey.IsInternal(client);
        Task<SpfCheckResult?> helloTask = checkSpf ? RunAsync(() => spfHelo.CheckHostAsync(SpfCheckRequest.ForHelo(client, helo), timeout.Token).AsTask(), cancellationToken) : Task.FromResult<SpfCheckResult?>(NotChecked(helo));
        Task<SpfCheckResult?> mailTask = string.IsNullOrEmpty(mailFrom) ? Task.FromResult<SpfCheckResult?>(null)
            : checkSpf ? RunAsync(() => spfMail.CheckHostAsync(SpfCheckRequest.ForMailFrom(client, helo, mailFrom), timeout.Token).AsTask(), cancellationToken) : Task.FromResult<SpfCheckResult?>(NotChecked(DomainOf(mailFrom) ?? string.Empty));
        Task<IReadOnlyList<DkimVerificationResult>?> dkimTask = RunAsync(() => dkim.VerifyAsync(message, timeout.Token).AsTask(), cancellationToken);
        Task<ArcChainResult?> arcTask = RunAsync(() => arcValidator.ValidateAsync(message, timeout.Token).AsTask(), cancellationToken);
        await Task.WhenAll(helloTask, mailTask, dkimTask, arcTask).ConfigureAwait(false);

        // What did not finish is a temporary error of that mechanism, and only of it.
        bool mailRequested = !string.IsNullOrEmpty(mailFrom);
        SpfCheckResult heloResult = helloTask.Result ?? TimedOutSpf(helo);
        SpfCheckResult? mailResult = mailRequested ? mailTask.Result ?? TimedOutSpf(DomainOf(mailFrom) ?? string.Empty) : null;
        SpfCheckResult effective = mailResult ?? heloResult;
        bool dkimTimedOut = dkimTask.Result is null;
        IReadOnlyList<DkimVerificationResult> dkimResults = dkimTask.Result ?? [];
        bool arcTimedOut = arcTask.Result is null;
        ArcChainResult arc = arcTask.Result ?? new ArcChainResult(ArcChainStatus.None, "verification timed out");
        bool timedOut = helloTask.Result is null || (mailRequested && mailTask.Result is null) || dkimTimedOut || arcTimedOut;
        if (arc.Failure == ArcFailure.TooManyInstances)
        {
            arc = new ArcChainResult(ArcChainStatus.Fail, "too_long", ArcFailure.TooManyInstances);
        }

        // DMARC for every From domain, with what finished; the strictest evaluation decides what is shown, and any unsettled one makes the verdict unsettled.
        var evaluations = new List<(DmarcEvaluation Evaluation, bool Unsettled)>(fromDomains.Count);
        var spfForDmarc = new SpfAuthResult(effective.Result, effective.Domain);
        var dkimForDmarc = dkimResults.Where(r => r.Domain is not null).Select(r => new DkimAuthResult(r.Domain!, r.IsPass, r.Selector)).ToList();
        if (fromDomains.Count > 0)
        {
            var dmarc = new DmarcEvaluator(new QueryBudgetResolver(_dns, MaxDmarcQueries));   // its own budget: nothing the SPF record of the sender does can make the policy lookup fail
            using var dmarcTime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            dmarcTime.CancelAfter(_options.VerificationTimeout < DmarcTimeLimit ? _options.VerificationTimeout : DmarcTimeLimit);
            foreach (string fromDomain in fromDomains)
            {
                DmarcEvaluation evaluation;
                try
                {
                    evaluation = await dmarc.EvaluateAsync(new DmarcInput(fromDomain, spfForDmarc, dkimForDmarc), dmarcTime.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    timedOut = true;
                    evaluation = TempErrorEvaluation(fromDomain, "verification timed out");
                }

                bool unsettled = evaluation.Result == DmarcResult.TempError
                    || (evaluation.Result == DmarcResult.Fail && TemporaryFailureCouldMatter(fromDomain, effective, dkimResults, dkimTimedOut, headers));
                evaluations.Add((evaluation, unsettled));
            }
        }

        DmarcEvaluation? chosen = evaluations.Count == 0 ? null : evaluations.Select(e => e.Evaluation).MaxBy(Rank);
        bool anyUnsettled = evaluations.Any(e => e.Unsettled);

        // A settled failure under a quarantine or reject policy decides for its own domain whatever another From domain does; the strictest of them wins.
        DmarcDisposition decisive = DmarcDisposition.None;
        foreach ((DmarcEvaluation evaluation, bool unsettled) in evaluations)
        {
            if (!unsettled && evaluation.Result == DmarcResult.Fail && evaluation.Disposition > decisive)
            {
                decisive = evaluation.Disposition;
            }
        }

        bool arcOverride = !anyUnsettled && chosen?.Result == DmarcResult.Fail && evaluations.Count == 1 && ArcVouches(arc, headers, fromDomains[0]);

        (InboundVerdict dkimVerdict, string? dkimDomain) = dkimTimedOut ? (InboundVerdict.TempError, null) : ReduceDkim(dkimResults);
        InboundVerdict dmarcVerdict = chosen is null ? InboundVerdict.PermError : decisive != DmarcDisposition.None ? InboundVerdict.Fail : anyUnsettled ? InboundVerdict.TempError : ToVerdict(chosen.Result);
        var auth = new InboundAuthResults(
            ToVerdict(effective.Result), effective.Domain,
            ToVerdict(heloResult.Result),
            dkimVerdict, dkimDomain,
            dmarcVerdict, chosen?.AppliedPolicy?.ToString().ToLowerInvariant(),
            arcTimedOut ? InboundVerdict.TempError : arc.Status switch { ArcChainStatus.Pass => InboundVerdict.Pass, ArcChainStatus.Fail => InboundVerdict.Fail, _ => InboundVerdict.None });

        RecordMetrics(auth);
        InboundMetrics.VerificationSeconds.Record(_clock.GetElapsedTime(started).TotalSeconds);
        return new InboundVerification
        {
            Auth = auth,
            Dmarc = chosen,
            Unsettled = anyUnsettled && decisive != DmarcDisposition.Reject,   // a settled failure under reject needs no more information
            DecisiveFailure = decisive,
            NoUsableFrom = !fromUsable || fromDomains.Count == 0,
            ArcOverridesDmarc = arcOverride,
            TimedOut = timedOut,
            AuthenticationResultsHeader = BuildHeader(client, helo, mailFrom, heloResult, mailResult, dkimResults, dkimTimedOut, decisive != DmarcDisposition.None ? evaluations.First(e => !e.Unsettled && e.Evaluation.Result == DmarcResult.Fail && e.Evaluation.Disposition == decisive).Evaluation : chosen, dmarcVerdict, arc, arcTimedOut),
        };
    }

    /// <summary>
    /// Whether a mechanism that failed temporarily could have been the aligned pass that makes a DMARC failure a pass: the SPF identity must be aligned with the From domain, a DKIM result that failed temporarily must
    /// come from a signature whose <c>d=</c> is, and a DKIM stage that did not finish matters only if the message carries a signature whose <c>d=</c> is. A temporary failure of an unrelated domain's record
    /// cannot change the verdict, so it must not be a way to keep a failure from being counted.
    /// </summary>
    private static bool TemporaryFailureCouldMatter(string fromDomain, SpfCheckResult spf, IReadOnlyList<DkimVerificationResult> dkim, bool dkimTimedOut, HeaderList headers)
    {
        if (spf.Result == SpfResult.TempError && Aligned(spf.Domain, fromDomain))
        {
            return true;
        }

        foreach (DkimVerificationResult r in dkim)
        {
            if (r.Status == DkimStatus.TempError && (r.Domain is null || Aligned(r.Domain, fromDomain)))
            {
                return true;
            }
        }

        return dkimTimedOut && SignatureDomains(headers).Any(d => Aligned(d, fromDomain));
    }

    private static bool Aligned(string? a, string b) =>
        !string.IsNullOrEmpty(a) && PublicSuffixList.Default.HaveSameOrganizationalDomain(a.Trim().TrimEnd('.').ToLowerInvariant(), b);

    /// <summary>The <c>d=</c> of every DKIM-Signature header of the message (what a stage that timed out would have had to check).</summary>
    private static IEnumerable<string> SignatureDomains(HeaderList headers)
    {
        int count = 0;
        foreach (MimeHeader header in headers)
        {
            if (header.IsMalformed || !header.NameEquals(HeaderNames.DkimSignature) || ++count > 20)
            {
                continue;
            }

            Match m;
            try
            {
                m = DomainTag.Match(header.GetValue(16 * 1024));
            }
            catch (RegexMatchTimeoutException)
            {
                continue;
            }

            if (m.Success)
            {
                yield return m.Groups[1].Value;
            }
        }
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

    private static string? DomainOf(string mailbox)
    {
        int at = mailbox.LastIndexOf('@');
        return at >= 0 ? mailbox[(at + 1)..].ToLowerInvariant() : null;
    }

    private static SpfCheckResult NotChecked(string domain) => new(SpfResult.None, domain.ToLowerInvariant(), Reason: "client address is internal; SPF not checked");

    private static SpfCheckResult TimedOutSpf(string domain) => new(SpfResult.TempError, domain.ToLowerInvariant(), Reason: "verification timed out");

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

            // The sealer must vouch for this From domain: a dmarc=pass for another header.from says nothing about it.
            if (results.ForMethod("dmarc").Any(r => r.Result == "pass" && Aligned(r.GetProperty("header", "from"), fromDomain)))
            {
                return true;
            }

            if (results.ForMethod("spf").Any(r => r.Result == "pass" && Aligned(DomainOf(r.GetProperty("smtp", "mailfrom") ?? string.Empty) ?? r.GetProperty("smtp", "mailfrom"), fromDomain)))
            {
                return true;
            }

            if (results.ForMethod("dkim").Any(r => r.Result == "pass" && Aligned(r.GetProperty("header", "d"), fromDomain)))
            {
                return true;
            }
        }

        return false;
    }

    private string BuildHeader(IPAddress client, string helo, string mailFrom, SpfCheckResult heloResult, SpfCheckResult? mailResult, IReadOnlyList<DkimVerificationResult> dkim, bool dkimTimedOut, DmarcEvaluation? dmarc, InboundVerdict dmarcVerdict, ArcChainResult arc, bool arcTimedOut)
    {
        var builder = new AuthenticationResultsBuilder(_authservId);
        if (mailResult is not null)
        {
            builder.AddSpf(mailResult, SpfIdentityKind.MailFrom, mailFrom);
        }

        if (!string.IsNullOrEmpty(helo))
        {
            builder.AddSpf(heloResult, SpfIdentityKind.Helo, helo);
        }

        if (dkimTimedOut)
        {
            builder.TryAddFragment("dkim=temperror reason=\"verification timed out\"");
        }
        else
        {
            foreach (string fragment in DkimAuthenticationResults.FormatAll(dkim))
            {
                builder.TryAddFragment(fragment);
            }
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

        builder.TryAddFragment(arcTimedOut ? "arc=temperror reason=\"verification timed out\"" : ArcAuthenticationResults.Format(arc, client));
        return builder.BuildHeader();
    }

    private static void RecordMetrics(InboundAuthResults auth)
    {
        static void Count(string mechanism, InboundVerdict verdict) =>
            InboundMetrics.Auth.Add(1, new KeyValuePair<string, object?>("mechanism", mechanism), new KeyValuePair<string, object?>("result", InboundNames.Of(verdict)));
        Count("spf", auth.Spf);
        Count("spf_helo", auth.SpfHelo);
        Count("dkim", auth.Dkim);
        Count("dmarc", auth.Dmarc);
        Count("arc", auth.Arc);
    }

    /// <summary>Counts the queries of one message and answers SERVFAIL (a temporary error to every checker) once the budget is used up.</summary>
    private sealed class QueryBudgetResolver(IDnsResolver inner, int limit) : IDnsResolver
    {
        private int _used;

        public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default) =>
            Interlocked.Increment(ref _used) > limit
                ? ValueTask.FromResult(new DnsResponse { Rcode = DnsRcode.ServerFailure })
                : inner.QueryAsync(name, type, cancellationToken);
    }
}
