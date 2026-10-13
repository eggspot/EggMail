using System.Text.Json;
using System.Text.Json.Serialization;
using Mta.Core;
using Mta.Storage;
using Mta.Tls.TlsRpt;

namespace Mta.Host.Reports;

/// <summary>A completed day's counters for one policy domain, merged from the persisted pieces and ready to be reported.</summary>
/// <param name="Data">The merged counters.</param>
/// <param name="Attempts">How many times sending this report has failed so far.</param>
/// <param name="BucketIds">The persisted pieces <paramref name="Data"/> was merged from.</param>
public sealed record PendingTlsReport(TlsRptDomainReportData Data, int Attempts, IReadOnlyList<Guid> BucketIds);

/// <summary>
/// Persists the TLS-RPT counters so a restart does not lose them. The delivery engine keeps recording into the in-memory <see cref="TlsRptCollector"/> (cheap, no I/O on the delivery path);
/// <see cref="FlushAsync"/> (every minute and at shutdown) moves what was collected since the last flush into the config store as one append-only <see cref="TlsRptBucketRecord"/> per policy domain
/// and day, so replicas and restarts never overwrite each other's counts. The report sender reads the completed days back (<see cref="GetCompletedAsync"/>), merges the pieces of each
/// domain and day into one report, and removes them once the report is sent (<see cref="CompleteAsync"/>) or keeps the merged counters for a retry (<see cref="RetryLaterAsync"/>), so
/// pending (unsent) reports survive a restart too. A crash loses at most the counts of the last flush interval.
/// </summary>
public sealed class TlsReportJournal
{
    private static readonly JsonSerializerOptions Json = new()
    {
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Counters of a day older than this are dropped instead of reported: RFC 8460 reports are about the last 24 hours, and a report weeks late is of no use.</summary>
    public const int MaxReportAgeDays = 7;

    private static readonly int UnixEpochDayNumber = DateOnly.FromDateTime(DateTime.UnixEpoch).DayNumber;

    private readonly TlsRptCollector _collector;
    private readonly IRuntimeStateStore _store;
    private readonly IClock _clock;
    private readonly IMtaLog _log;
    private readonly SemaphoreSlim _flushing = new(1, 1);

    public TlsReportJournal(TlsRptCollector collector, IRuntimeStateStore store, IClock clock, IMtaLog? log = null)
    {
        _collector = collector;
        _store = store;
        _clock = clock;
        _log = log ?? NullMtaLog.Instance;
    }

    /// <summary>Days since 1970-01-01, the form the store keys the buckets by.</summary>
    public static int DayNumber(DateOnly day) => day.DayNumber - UnixEpochDayNumber;

    /// <summary>Writes everything collected since the last flush to the store. Returns the number of buckets written. When the store is unavailable the counts go back into the collector.</summary>
    public async Task<int> FlushAsync(CancellationToken cancellationToken)
    {
        await _flushing.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var delta = _collector.DrainAll();
            if (delta.Count == 0)
            {
                return 0;
            }

            DateTimeOffset now = _clock.UtcNow;
            var rows = delta.Select(d => new TlsRptBucketRecord(Ids.New(now), DayNumber(d.Day), d.PolicyDomain, Serialize(d), 0, now)).ToList();
            try
            {
                await _store.AddTlsRptBucketsAsync(rows, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                foreach (var d in delta)
                {
                    _collector.Absorb(d);
                }

                throw;
            }

            return rows.Count;
        }
        finally
        {
            _flushing.Release();
        }
    }

    /// <summary>
    /// The reports of every completed UTC day (before today), at most <paramref name="maxBuckets"/> persisted pieces at a time. A piece that cannot be read is logged and dropped: one damaged
    /// row must never block the reports of the others.
    /// </summary>
    public async Task<IReadOnlyList<PendingTlsReport>> GetCompletedAsync(int maxBuckets, CancellationToken cancellationToken)
    {
        int today = DayNumber(DateOnly.FromDateTime(_clock.UtcNow.UtcDateTime));
        var rows = await _store.GetTlsRptBucketsAsync(today, maxBuckets, cancellationToken).ConfigureAwait(false);
        var stale = rows.Where(r => r.Day < today - MaxReportAgeDays).Select(r => r.Id).ToList();
        if (stale.Count > 0)
        {
            _log.Write(MtaLogLevel.Information, "tlsrpt", $"dropping {stale.Count} TLS-RPT counter row(s) older than {MaxReportAgeDays} days");
            await _store.ReplaceTlsRptBucketsAsync(stale, null, cancellationToken).ConfigureAwait(false);
        }

        var reports = new List<PendingTlsReport>();
        foreach (var group in rows.Where(r => r.Day >= today - MaxReportAgeDays).GroupBy(r => (r.Day, r.PolicyDomain)))
        {
            var pieces = new List<TlsRptDomainReportData>();
            var readable = new List<Guid>();
            foreach (var row in group)
            {
                try
                {
                    pieces.Add(Deserialize(row.DataJson));
                    readable.Add(row.Id);
                }
                catch (Exception ex) when (ex is JsonException or NotSupportedException or ArgumentException)
                {
                    _log.Write(MtaLogLevel.Warning, "tlsrpt", $"dropping an unreadable TLS-RPT counter row for {row.PolicyDomain}", ex);
                    await _store.ReplaceTlsRptBucketsAsync([row.Id], null, cancellationToken).ConfigureAwait(false);
                }
            }

            if (pieces.Count > 0)
            {
                reports.Add(new PendingTlsReport(TlsRptCollector.Merge(pieces), group.Max(r => r.Attempts), readable));
            }
        }

        return reports;
    }

    /// <summary>The report was sent, or the domain no longer asks for reports: forget its counters.</summary>
    public async Task CompleteAsync(PendingTlsReport report, CancellationToken cancellationToken) =>
        await _store.ReplaceTlsRptBucketsAsync(report.BucketIds, null, cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Sending failed: replace the pieces by their merged counters with one more failed attempt (<see cref="CompleteAsync"/> instead once <paramref name="giveUp"/> says the attempts are used up).
    /// </summary>
    public async Task RetryLaterAsync(PendingTlsReport report, bool giveUp, CancellationToken cancellationToken)
    {
        if (giveUp)
        {
            await CompleteAsync(report, cancellationToken).ConfigureAwait(false);
            return;
        }

        DateTimeOffset now = _clock.UtcNow;
        var merged = new TlsRptBucketRecord(Ids.New(now), DayNumber(report.Data.Day), report.Data.PolicyDomain, Serialize(report.Data), report.Attempts + 1, now);
        await _store.ReplaceTlsRptBucketsAsync(report.BucketIds, merged, cancellationToken).ConfigureAwait(false);
    }

    internal static string Serialize(TlsRptDomainReportData data) => JsonSerializer.Serialize(data, Json);

    internal static TlsRptDomainReportData Deserialize(string json) =>
        JsonSerializer.Deserialize<TlsRptDomainReportData>(json, Json) ?? throw new JsonException("The TLS-RPT counters are empty.");
}
