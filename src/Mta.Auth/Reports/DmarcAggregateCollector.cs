using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Mta.Auth.Dmarc;
using Mta.Auth.Spf;
using Mta.Core;

namespace Mta.Auth.Reports;

/// <summary>One received message as the aggregate report sees it.</summary>
/// <param name="ReceivedAt">When the message was received (decides the report day, UTC).</param>
/// <param name="SourceIp">The connecting client address.</param>
/// <param name="Input">The DMARC input (From domain, SPF and DKIM results).</param>
/// <param name="Evaluation">The DMARC evaluation of that input.</param>
/// <param name="SpfScope">Whether <see cref="DmarcInput.Spf"/> is about the MAIL FROM or the HELO identity.</param>
/// <param name="EnvelopeTo">The recipient domain, or null to omit it.</param>
/// <param name="Overrides">Extra override reasons (forwarded, mailing list, local policy); <c>sampled_out</c> is added automatically.</param>
public sealed record DmarcAggregateObservation(
    DateTimeOffset ReceivedAt,
    IPAddress SourceIp,
    DmarcInput Input,
    DmarcEvaluation Evaluation,
    SpfReportScope SpfScope = SpfReportScope.MailFrom,
    string? EnvelopeTo = null,
    IReadOnlyList<DmarcPolicyOverrideReason>? Overrides = null);

/// <summary>A finished report together with the addresses it should be sent to.</summary>
/// <param name="Report">The report.</param>
/// <param name="Destinations">The <c>rua</c> addresses published for the policy domain (not yet checked for external authorization).</param>
public sealed record DmarcPendingReport(DmarcAggregateReport Report, IReadOnlyList<DmarcReportUri> Destinations);

/// <summary>Settings of <see cref="DmarcAggregateCollector"/>.</summary>
public sealed class DmarcAggregateCollectorOptions
{
    /// <summary>The reporting organization (<c>org_name</c>).</summary>
    public string OrganizationName { get; init; } = "EggMail";

    /// <summary>The contact address (<c>email</c>); its domain names the receiver in file names. Set it to a real address you control.</summary>
    public string ContactEmail { get; init; } = "postmaster@localhost";

    /// <summary>Optional <c>extra_contact_info</c>.</summary>
    public string? ExtraContactInfo { get; init; }

    /// <summary>Maximum distinct rows per policy domain and day; further new combinations are dropped and noted in the report. Default 10000.</summary>
    public int MaxRecordsPerReport { get; init; } = 10_000;

    /// <summary>Maximum number of policy domain / day buckets held in memory; observations for new buckets are dropped beyond it. Default 100000.</summary>
    public int MaxPendingReports { get; init; } = 100_000;

    /// <summary>Collect messages for domains whose policy has no <c>mailto:</c> report address. Default false (nothing would be sent).</summary>
    public bool CollectWithoutReportAddress { get; init; }

    /// <summary>The time source for <see cref="DmarcAggregateCollector.DrainCompleted"/>.</summary>
    public IClock Clock { get; init; } = SystemClock.Instance;
}

/// <summary>
/// Accumulates DMARC evaluations into per-day aggregate reports (RFC 7489 section 7.2). Rows are keyed by policy
/// domain, UTC day, source IP, disposition, alignment results, override reasons, identifiers and authentication
/// results, and counted. Memory is bounded by <see cref="DmarcAggregateCollectorOptions.MaxRecordsPerReport"/> and
/// <see cref="DmarcAggregateCollectorOptions.MaxPendingReports"/>. Safe for concurrent use.
/// </summary>
public sealed class DmarcAggregateCollector
{
    private readonly DmarcAggregateCollectorOptions _options;
    private readonly ConcurrentDictionary<(string PolicyDomain, DateOnly Day), Bucket> _buckets = new();
    private long _dropped;

    /// <summary>Creates a collector.</summary>
    /// <param name="options">Settings; null uses the defaults.</param>
    public DmarcAggregateCollector(DmarcAggregateCollectorOptions? options = null)
    {
        _options = options ?? new DmarcAggregateCollectorOptions();
    }

    /// <summary>The number of policy domain / day buckets currently held.</summary>
    public int PendingReportCount => _buckets.Count;

    /// <summary>How many observations were dropped because of the memory bounds.</summary>
    public long DroppedObservationCount => Interlocked.Read(ref _dropped);

    /// <summary>Counts one observation.</summary>
    /// <param name="observation">The message.</param>
    /// <returns>True when it was counted; false when it was skipped (no policy found, no report address) or dropped by a bound.</returns>
    public bool Add(DmarcAggregateObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        DmarcEvaluation evaluation = observation.Evaluation;
        if (evaluation.Record is null || evaluation.PolicyDomain is null || evaluation.Result is not (DmarcResult.Pass or DmarcResult.Fail))
        {
            return false;
        }

        if (!_options.CollectWithoutReportAddress && !evaluation.Record.AggregateReportUris.Any(u => u.IsMailTo))
        {
            return false;
        }

        DateOnly day = DateOnly.FromDateTime(observation.ReceivedAt.UtcDateTime);
        var key = (evaluation.PolicyDomain, day);
        (string rowKey, DmarcAggregateRecord template) = DmarcRowFactory.Create(observation);

        while (true)
        {
            if (!_buckets.TryGetValue(key, out Bucket? bucket))
            {
                if (_buckets.Count >= _options.MaxPendingReports)
                {
                    Interlocked.Increment(ref _dropped);
                    return false;
                }

                bucket = _buckets.GetOrAdd(key, _ => new Bucket());
            }

            lock (bucket)
            {
                if (bucket.Closed)
                {
                    continue; // drained concurrently; start a fresh bucket
                }

                bucket.Policy = DmarcPublishedPolicy.FromRecord(evaluation.PolicyDomain, evaluation.Record);
                bucket.Destinations = evaluation.Record.AggregateReportUris;
                if (bucket.Rows.TryGetValue(rowKey, out DmarcAggregateRecord? existing))
                {
                    bucket.Rows[rowKey] = existing with { Count = existing.Count + 1 };
                    return true;
                }

                if (bucket.Rows.Count >= _options.MaxRecordsPerReport)
                {
                    bucket.DroppedObservations++;
                    Interlocked.Increment(ref _dropped);
                    return false;
                }

                bucket.Rows[rowKey] = template;
                return true;
            }
        }
    }

    /// <summary>Removes and returns the reports for all days before today (UTC, by the configured clock).</summary>
    public IReadOnlyList<DmarcPendingReport> DrainCompleted() =>
        Drain(DateOnly.FromDateTime(_options.Clock.UtcNow.UtcDateTime));

    /// <summary>Removes and returns the reports for all days strictly before <paramref name="beforeDay"/>.</summary>
    /// <param name="beforeDay">The first UTC day to keep.</param>
    public IReadOnlyList<DmarcPendingReport> Drain(DateOnly beforeDay) => DrainWhere(day => day < beforeDay);

    /// <summary>Removes and returns every report, including the current day's (use at shutdown).</summary>
    public IReadOnlyList<DmarcPendingReport> DrainAll() => DrainWhere(_ => true);

    private List<DmarcPendingReport> DrainWhere(Func<DateOnly, bool> selectDay)
    {
        var reports = new List<DmarcPendingReport>();
        foreach (var key in _buckets.Keys.Where(k => selectDay(k.Day)).OrderBy(k => k.Day).ThenBy(k => k.PolicyDomain, StringComparer.Ordinal).ToList())
        {
            if (!_buckets.TryRemove(key, out Bucket? bucket))
            {
                continue;
            }

            DmarcPendingReport? report;
            lock (bucket)
            {
                bucket.Closed = true;
                report = BuildReport(key.PolicyDomain, key.Day, bucket);
            }

            if (report is not null)
            {
                reports.Add(report);
            }
        }

        return reports;
    }

    private DmarcPendingReport? BuildReport(string policyDomain, DateOnly day, Bucket bucket)
    {
        if (bucket.Policy is null || bucket.Rows.Count == 0)
        {
            return null;
        }

        DateTimeOffset begin = new(day.ToDateTime(TimeOnly.MinValue), TimeSpan.Zero);
        DateTimeOffset end = begin.AddDays(1).AddSeconds(-1);
        var errors = new List<string>();
        if (bucket.DroppedObservations > 0)
        {
            errors.Add(bucket.DroppedObservations.ToString(CultureInfo.InvariantCulture) + " messages are not included because the report reached its record limit");
        }

        var metadata = new DmarcReportMetadata(
            _options.OrganizationName,
            _options.ContactEmail,
            Ids.ToCompact(Ids.New(begin)) + "@" + policyDomain,
            begin,
            end,
            _options.ExtraContactInfo,
            errors);
        var records = bucket.Rows.Values
            .OrderByDescending(r => r.Count)
            .ThenBy(r => r.SourceIp, StringComparer.Ordinal)
            .ThenBy(r => r.HeaderFrom, StringComparer.Ordinal)
            .ThenBy(r => r.EnvelopeFrom, StringComparer.Ordinal)
            .ToList();
        return new DmarcPendingReport(new DmarcAggregateReport(metadata, bucket.Policy, records), bucket.Destinations);
    }

    private sealed class Bucket
    {
        public bool Closed;
        public long DroppedObservations;
        public DmarcPublishedPolicy? Policy;
        public IReadOnlyList<DmarcReportUri> Destinations = [];
        public Dictionary<string, DmarcAggregateRecord> Rows { get; } = [];
    }
}

/// <summary>Builds the aggregated row for an observation together with a collision-free identity string.</summary>
internal static class DmarcRowFactory
{
    private const int MaxTextLength = 255;
    private const int MaxDkimResults = 16;

    public static (string Key, DmarcAggregateRecord Template) Create(DmarcAggregateObservation o)
    {
        DmarcEvaluation e = o.Evaluation;
        IPAddress ip = o.SourceIp.IsIPv4MappedToIPv6 ? o.SourceIp.MapToIPv4() : o.SourceIp;
        var reasons = new List<DmarcPolicyOverrideReason>(o.Overrides ?? []);
        if (e.SampledOut && !reasons.Any(r => r.Type == DmarcPolicyOverride.SampledOut))
        {
            reasons.Add(new DmarcPolicyOverrideReason(DmarcPolicyOverride.SampledOut));
        }

        string spfDomain = Clean(o.Input.Spf?.Domain);
        var dkim = (o.Input.Dkim ?? [])
            .Where(d => d is not null && !string.IsNullOrWhiteSpace(d.Domain))
            .Select(d => new DkimReportAuthResult(Clean(d.Domain), string.IsNullOrEmpty(d.Selector) ? null : Truncate(d.Selector), d.Passed ? DkimReportResult.Pass : DkimReportResult.Fail))
            .DistinctBy(d => (d.Domain, d.Selector, d.Result))
            .OrderBy(d => d.Domain, StringComparer.Ordinal)
            .ThenBy(d => d.Selector, StringComparer.Ordinal)
            .Take(MaxDkimResults)
            .ToList();
        var spf = new List<SpfReportAuthResult>();
        if (spfDomain.Length > 0 && o.Input.Spf is { } spfInput)
        {
            spf.Add(new SpfReportAuthResult(spfDomain, o.SpfScope, spfInput.Result));
        }

        string? envelopeTo = string.IsNullOrWhiteSpace(o.EnvelopeTo) ? null : Clean(o.EnvelopeTo);
        var template = new DmarcAggregateRecord(
            ip.ToString(),
            1,
            e.Disposition,
            e.Dkim?.Aligned ?? false,
            e.Spf?.Aligned ?? false,
            reasons,
            envelopeTo,
            spfDomain.Length == 0 ? e.FromDomain : spfDomain,
            e.FromDomain,
            dkim,
            spf);

        var key = new System.Text.StringBuilder();
        Part(key, template.SourceIp);
        Part(key, ((int)template.Disposition).ToString(CultureInfo.InvariantCulture));
        Part(key, template.DkimAligned ? "1" : "0");
        Part(key, template.SpfAligned ? "1" : "0");
        Part(key, envelopeTo ?? string.Empty);
        Part(key, template.EnvelopeFrom);
        Part(key, template.HeaderFrom);
        foreach (DmarcPolicyOverrideReason r in reasons)
        {
            Part(key, "r" + (int)r.Type + (r.Comment ?? string.Empty));
        }

        foreach (DkimReportAuthResult d in dkim)
        {
            Part(key, "d" + d.Domain);
            Part(key, d.Selector ?? string.Empty);
            Part(key, ((int)d.Result).ToString(CultureInfo.InvariantCulture));
        }

        foreach (SpfReportAuthResult s in spf)
        {
            Part(key, "s" + s.Domain);
            Part(key, ((int)s.Scope).ToString(CultureInfo.InvariantCulture));
            Part(key, ((int)s.Result).ToString(CultureInfo.InvariantCulture));
        }

        return (key.ToString(), template);
    }

    private static void Part(System.Text.StringBuilder sb, string value) =>
        sb.Append(value.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(value).Append(';');

    private static string Clean(string? domain) => Truncate((domain ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant());

    private static string Truncate(string value) => value.Length > MaxTextLength ? value[..MaxTextLength] : value;
}
