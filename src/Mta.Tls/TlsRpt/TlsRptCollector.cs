using Mta.Core;
using Mta.Dns;
using Mta.Tls.Dane;
using Mta.Tls.MtaSts;

namespace Mta.Tls.TlsRpt;

/// <summary>Identifies the policy a TLS session was subject to, as TLS-RPT reports it.</summary>
/// <param name="Type">The policy type.</param>
/// <param name="PolicyString">The policy text lines (MTA-STS policy lines, or TLSA records in presentation form).</param>
/// <param name="MxHosts">For MTA-STS, the policy's <c>mx</c> patterns.</param>
public sealed record TlsRptPolicyDescriptor(TlsPolicyType Type, IReadOnlyList<string> PolicyString, IReadOnlyList<string> MxHosts)
{
    /// <summary>The descriptor used when neither MTA-STS nor DANE applied.</summary>
    public static TlsRptPolicyDescriptor NoPolicy { get; } = new(TlsPolicyType.NoPolicyFound, [], []);

    /// <summary>Describes an MTA-STS policy.</summary>
    public static TlsRptPolicyDescriptor FromMtaSts(MtaStsPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return new(TlsPolicyType.Sts, policy.PolicyLines, policy.MxPatterns);
    }

    /// <summary>Describes a DANE TLSA record set.</summary>
    public static TlsRptPolicyDescriptor FromTlsa(IEnumerable<TlsaRecord> records)
    {
        ArgumentNullException.ThrowIfNull(records);
        return new(TlsPolicyType.Tlsa, records.Select(TlsaRecordClassifier.ToPresentation).ToArray(), []);
    }

    internal string Key => Type.ToWireString() + "\n" + string.Join("\n", PolicyString);
}

/// <summary>One outbound session outcome to aggregate.</summary>
/// <param name="PolicyDomain">The recipient (policy) domain.</param>
/// <param name="Policy">The policy that applied.</param>
/// <param name="MxHost">The receiving MX host name.</param>
/// <param name="Success">Whether the session satisfied the policy.</param>
/// <param name="Failure">The failure classification when <paramref name="Success"/> is false.</param>
/// <param name="SendingMtaIp">Our sending IP address.</param>
/// <param name="ReceivingIp">The receiving MX IP address.</param>
/// <param name="ReceivingMxHelo">The receiving MX's greeting host name.</param>
/// <param name="AdditionalInformation">Free text (a URI to more detail, or a short description).</param>
/// <param name="FailureReasonCode">A vendor code such as an SMTP or TLS alert code.</param>
public sealed record TlsRptSessionOutcome(
    string PolicyDomain,
    TlsRptPolicyDescriptor Policy,
    string MxHost,
    bool Success,
    TlsResultType? Failure = null,
    string? SendingMtaIp = null,
    string? ReceivingIp = null,
    string? ReceivingMxHelo = null,
    string? AdditionalInformation = null,
    string? FailureReasonCode = null);

/// <summary>One aggregated failure line of a report (RFC 8460 section 4.4 <c>failure-details</c>).</summary>
/// <param name="ResultType">The failure classification.</param>
/// <param name="SendingMtaIp">Sending address, if recorded.</param>
/// <param name="ReceivingMxHostname">The receiving MX host.</param>
/// <param name="ReceivingMxHelo">The receiving MX greeting host name, if recorded.</param>
/// <param name="ReceivingIp">The receiving MX address, if recorded.</param>
/// <param name="FailedSessionCount">How many sessions failed this way.</param>
/// <param name="AdditionalInformation">Free text, if recorded.</param>
/// <param name="FailureReasonCode">Vendor code, if recorded.</param>
public sealed record TlsRptFailureDetail(
    TlsResultType ResultType,
    string? SendingMtaIp,
    string? ReceivingMxHostname,
    string? ReceivingMxHelo,
    string? ReceivingIp,
    long FailedSessionCount,
    string? AdditionalInformation,
    string? FailureReasonCode);

/// <summary>The aggregate for one policy of one domain on one day.</summary>
/// <param name="Policy">The policy.</param>
/// <param name="SuccessCount">Successful sessions.</param>
/// <param name="FailureCount">Failed sessions (all of them, including those not listed in <paramref name="FailureDetails"/>).</param>
/// <param name="FailureDetails">Per-reason failure lines (bounded).</param>
/// <param name="DroppedFailureDetailCount">Failed sessions whose detail line was dropped because of the per-policy bound.</param>
public sealed record TlsRptPolicyAggregate(
    TlsRptPolicyDescriptor Policy,
    long SuccessCount,
    long FailureCount,
    IReadOnlyList<TlsRptFailureDetail> FailureDetails,
    long DroppedFailureDetailCount);

/// <summary>Everything to report to one policy domain for one UTC day.</summary>
/// <param name="PolicyDomain">The policy domain.</param>
/// <param name="Day">The UTC day covered.</param>
/// <param name="Policies">One aggregate per distinct policy seen that day.</param>
public sealed record TlsRptDomainReportData(string PolicyDomain, DateOnly Day, IReadOnlyList<TlsRptPolicyAggregate> Policies);

/// <summary>Bounds for <see cref="TlsRptCollector"/> so hostile or high-cardinality traffic cannot grow memory without limit.</summary>
public sealed class TlsRptCollectorOptions
{
    /// <summary>Maximum number of (domain, day) buckets. Further sessions are counted in <see cref="TlsRptCollector.DroppedSessionCount"/>. Default 100,000.</summary>
    public int MaxDomainDays { get; init; } = 100_000;

    /// <summary>Maximum distinct policies per (domain, day). Default 16.</summary>
    public int MaxPoliciesPerDomain { get; init; } = 16;

    /// <summary>Maximum distinct failure lines per policy. Default 500.</summary>
    public int MaxFailureDetailsPerPolicy { get; init; } = 500;

    /// <summary>Maximum length of free-text fields; longer values are truncated. Default 256.</summary>
    public int MaxTextLength { get; init; } = 256;
}

/// <summary>
/// Thread-safe aggregator of session outcomes by (policy domain, UTC day, policy, failure kind). Counts are exact; the
/// number of distinct lines is bounded by <see cref="TlsRptCollectorOptions"/>.
/// </summary>
public sealed class TlsRptCollector
{
    private readonly IClock _clock;
    private readonly TlsRptCollectorOptions _options;
    private readonly Dictionary<(string Domain, DateOnly Day), DomainBucket> _buckets = [];
    private readonly object _gate = new();
    private long _dropped;

    /// <summary>Creates a collector.</summary>
    public TlsRptCollector(IClock? clock = null, TlsRptCollectorOptions? options = null)
    {
        _clock = clock ?? SystemClock.Instance;
        _options = options ?? new TlsRptCollectorOptions();
    }

    /// <summary>Sessions that could not be recorded because of the bounds.</summary>
    public long DroppedSessionCount => Interlocked.Read(ref _dropped);

    /// <summary>Records one session (attributed to the current UTC day).</summary>
    public void Record(TlsRptSessionOutcome outcome)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        if (!DnsNames.TryNormalizeHost(outcome.PolicyDomain, out string domain))
        {
            Interlocked.Increment(ref _dropped);
            return;
        }

        var day = DateOnly.FromDateTime(_clock.UtcNow.UtcDateTime);
        lock (_gate)
        {
            if (!_buckets.TryGetValue((domain, day), out var bucket))
            {
                if (_buckets.Count >= _options.MaxDomainDays)
                {
                    Interlocked.Increment(ref _dropped);
                    return;
                }

                bucket = new DomainBucket();
                _buckets[(domain, day)] = bucket;
            }

            string key = outcome.Policy.Key;
            if (!bucket.Policies.TryGetValue(key, out var policy))
            {
                if (bucket.Policies.Count >= _options.MaxPoliciesPerDomain)
                {
                    Interlocked.Increment(ref _dropped);
                    return;
                }

                policy = new PolicyBucket(outcome.Policy);
                bucket.Policies[key] = policy;
            }

            if (outcome.Success)
            {
                policy.Success++;
                return;
            }

            policy.Failure++;
            var detailKey = new DetailKey(
                outcome.Failure ?? TlsResultType.ValidationFailure,
                Trim(outcome.SendingMtaIp),
                Trim(outcome.MxHost),
                Trim(outcome.ReceivingMxHelo),
                Trim(outcome.ReceivingIp),
                Trim(outcome.AdditionalInformation),
                Trim(outcome.FailureReasonCode));
            if (policy.Details.TryGetValue(detailKey, out long count))
            {
                policy.Details[detailKey] = count + 1;
            }
            else if (policy.Details.Count < _options.MaxFailureDetailsPerPolicy)
            {
                policy.Details[detailKey] = 1;
            }
            else
            {
                policy.DroppedDetails++;
            }
        }
    }

    /// <summary>Records a successful session.</summary>
    public void RecordSuccess(string policyDomain, TlsRptPolicyDescriptor policy, string mxHost, string? sendingMtaIp = null, string? receivingIp = null) =>
        Record(new TlsRptSessionOutcome(policyDomain, policy, mxHost, true, SendingMtaIp: sendingMtaIp, ReceivingIp: receivingIp));

    /// <summary>Records a failed session.</summary>
    public void RecordFailure(
        string policyDomain,
        TlsRptPolicyDescriptor policy,
        string mxHost,
        TlsResultType failure,
        string? sendingMtaIp = null,
        string? receivingIp = null,
        string? receivingMxHelo = null,
        string? additionalInformation = null,
        string? failureReasonCode = null) =>
        Record(new TlsRptSessionOutcome(policyDomain, policy, mxHost, false, failure, sendingMtaIp, receivingIp, receivingMxHelo, additionalInformation, failureReasonCode));

    /// <summary>Returns a copy of everything collected so far without clearing it.</summary>
    public IReadOnlyList<TlsRptDomainReportData> Snapshot()
    {
        lock (_gate)
        {
            return _buckets.Select(kv => ToReportData(kv.Key.Domain, kv.Key.Day, kv.Value)).ToList();
        }
    }

    /// <summary>Removes and returns all buckets for days before the current UTC day.</summary>
    public IReadOnlyList<TlsRptDomainReportData> DrainCompletedDays()
    {
        var today = DateOnly.FromDateTime(_clock.UtcNow.UtcDateTime);
        lock (_gate)
        {
            var keys = _buckets.Keys.Where(k => k.Day < today).ToList();
            var result = new List<TlsRptDomainReportData>(keys.Count);
            foreach (var key in keys)
            {
                result.Add(ToReportData(key.Domain, key.Day, _buckets[key]));
                _buckets.Remove(key);
            }

            return result;
        }
    }

    /// <summary>Removes and returns the buckets of one UTC day.</summary>
    public IReadOnlyList<TlsRptDomainReportData> Drain(DateOnly day)
    {
        lock (_gate)
        {
            var keys = _buckets.Keys.Where(k => k.Day == day).ToList();
            var result = new List<TlsRptDomainReportData>(keys.Count);
            foreach (var key in keys)
            {
                result.Add(ToReportData(key.Domain, key.Day, _buckets[key]));
                _buckets.Remove(key);
            }

            return result;
        }
    }

    private string? Trim(string? value) =>
        value is null || value.Length <= _options.MaxTextLength ? value : value[.._options.MaxTextLength];

    private static TlsRptDomainReportData ToReportData(string domain, DateOnly day, DomainBucket bucket) =>
        new(domain, day, bucket.Policies.Values.Select(p => new TlsRptPolicyAggregate(
            p.Descriptor,
            p.Success,
            p.Failure,
            p.Details
                .OrderByDescending(d => d.Value)
                .ThenBy(d => d.Key.Type)
                .Select(d => new TlsRptFailureDetail(d.Key.Type, d.Key.SendingIp, d.Key.MxHost, d.Key.Helo, d.Key.ReceivingIp, d.Value, d.Key.Info, d.Key.Code))
                .ToArray(),
            p.DroppedDetails)).ToArray());

    private sealed class DomainBucket
    {
        public Dictionary<string, PolicyBucket> Policies { get; } = [];
    }

    private sealed class PolicyBucket(TlsRptPolicyDescriptor descriptor)
    {
        public TlsRptPolicyDescriptor Descriptor { get; } = descriptor;

        public long Success;
        public long Failure;
        public long DroppedDetails;
        public Dictionary<DetailKey, long> Details { get; } = [];
    }

    private readonly record struct DetailKey(TlsResultType Type, string? SendingIp, string? MxHost, string? Helo, string? ReceivingIp, string? Info, string? Code);
}
