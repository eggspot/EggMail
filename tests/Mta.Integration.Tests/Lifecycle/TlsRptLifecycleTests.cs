using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Mta.Host.Reports;
using Mta.Mime;
using Mta.Storage;
using Mta.TestSupport;
using Mta.Tls;
using Mta.Tls.TlsRpt;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>
/// TLS-RPT over 30 virtual days with the real collector, journal and sender over the storage of each backend (RFC 8460): one report per policy domain and UTC day, sent after the day is over
/// (and the 10 minute grace), with exactly that day's counts, to the mailto endpoint through the normal queue or to the HTTPS endpoint; an endpoint that is down is retried at every run and the
/// report is dropped after the 6th failed attempt; counters survive a restart; a sender that was away for longer than 7 days reports only the last 7 days; the journal never holds more than the open day.
/// </summary>
public class TlsRptLifecycleTests
{
    private static readonly TlsRptPolicyDescriptor Policy = TlsRptPolicyDescriptor.FromTlsa([]);
    private static readonly TimeSpan RunEvery = TimeSpan.FromHours(6);
    private const int Domains = 8;

    [Fact]
    public async Task Thirty_days_of_reports_on_sqlite()
    {
        var clock = new VirtualClock(new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero));
        await using HostBackend backend = await HostBackend.SqliteAsync(clock);
        await RunAsync(backend, clock);
    }

    [PostgresFact]
    public async Task Thirty_days_of_reports_on_postgres()
    {
        var clock = new VirtualClock(new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero));
        await using HostBackend backend = await HostBackend.PostgresAsync(clock);
        await RunAsync(backend, clock);
    }

    private sealed record Delivered(string Domain, DateOnly Day, long Success, long Failure, DateTimeOffset At, string Via);

    /// <summary>An HTTPS endpoint that answers 200, or 500 while the test says it is down; remembers every body it received.</summary>
    private sealed class ReportEndpoint(VirtualClock clock) : HttpMessageHandler
    {
        public Func<string, DateTimeOffset, bool> IsDown { get; set; } = (_, _) => false;

        public List<(string Host, DateOnly Day, long Success, long Failure, DateTimeOffset At, bool Accepted)> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            byte[] body = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            (string domain, DateOnly day, long ok, long bad) = Summarize(TlsRptReportBuilder.Decompress(body));
            bool down = IsDown(request.RequestUri!.Host, clock.UtcNow);
            Requests.Add((request.RequestUri.Host, day, ok, bad, clock.UtcNow, !down));
            _ = domain;
            return new HttpResponseMessage(down ? HttpStatusCode.InternalServerError : HttpStatusCode.OK);
        }
    }

    private static (string Domain, DateOnly Day, long Success, long Failure) Summarize(byte[] json)
    {
        JsonNode root = JsonNode.Parse(Encoding.UTF8.GetString(json))!;
        DateTimeOffset start = DateTimeOffset.Parse(root["date-range"]!["start-datetime"]!.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture);
        DateTimeOffset end = DateTimeOffset.Parse(root["date-range"]!["end-datetime"]!.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture);
        Assert.Equal(TimeSpan.Zero, start.TimeOfDay);   // the window is one UTC day: 00:00:00 to 23:59:59
        Assert.Equal(new TimeSpan(23, 59, 59), end - start);
        long ok = 0, bad = 0;
        string? domain = null;
        foreach (JsonNode? policy in root["policies"]!.AsArray())
        {
            ok += policy!["summary"]!["total-successful-session-count"]!.GetValue<long>();
            bad += policy["summary"]!["total-failure-session-count"]!.GetValue<long>();
            domain = policy["policy"]!["policy-domain"]!.GetValue<string>();
        }

        return (domain!, DateOnly.FromDateTime(start.UtcDateTime), ok, bad);
    }

    /// <summary>One "process": a collector, its journal and the sender over the backend's current storage.</summary>
    private sealed class Process(HostBackend backend, VirtualClock clock, LifecycleDns dns, TlsRptHttpsSender https)
    {
        public TlsRptCollector Collector { get; } = new(clock);

        public TlsReportJournal Journal => field ??= new TlsReportJournal(Collector, backend.Storage.Config, clock);

        public TlsReportSender Sender => field ??= new TlsReportSender(Journal, backend.Storage.Config, new TlsRptRecordLookup(dns), https, backend.Storage.Intake, clock, "egg.test", "postmaster@egg.test");
    }

    private static async Task RunAsync(HostBackend backend, VirtualClock clock)
    {
        int seed = Accelerated.Seed(8460);
        var random = new Random(seed);
        DateTimeOffset start = clock.UtcNow;
        var dns = new LifecycleDns();
        var endpoint = new ReportEndpoint(clock);
        using var https = new TlsRptHttpsSender(endpoint);
        for (int i = 0; i < Domains; i++)
        {
            dns.SetTxt($"_smtp._tls.d{i}.example", i % 2 == 0 ? $"v=TLSRPTv1; rua=mailto:tlsrpt@d{i}.example" : $"v=TLSRPTv1; rua=https://reports.d{i}.example/tlsrpt");
        }

        // d1's endpoint is down on day 4 until 14:00 (the report of day 3 is sent at the 18:00 run, the 3rd attempt); d3's is down from day 8 to the end of day 10 (the reports of days 7 and 8 fail six
        // times each and are dropped, the report of day 9 gets through at 00:00 on day 11); d5 publishes no record from day 9 on (nothing is sent and nothing is kept).
        endpoint.IsDown = (host, at) =>
            (host == "reports.d1.example" && at >= start.AddDays(4) && at < start.AddDays(4).AddHours(14))
            || (host == "reports.d3.example" && at >= start.AddDays(8) && at < start.AddDays(11));

        var model = new Dictionary<(int Domain, DateOnly Day), (long Success, long Failure)>();
        var mailto = new List<Delivered>();
        var seenMessages = new HashSet<Guid>();
        var process = new Process(backend, clock, dns, https);
        
        async Task CollectMailtoAsync()
        {
            // Everything the sender queued since the last look, taken out of the normal queue with a lease that never ends in this test.
            foreach (ClaimedDelivery d in await backend.Storage.Deliveries.ClaimAsync("tlsrpt-test", 1000, clock.UtcNow, TimeSpan.FromDays(10_000), default))
            {
                Assert.Equal(MessageSource.System, d.Source);
                if (!seenMessages.Add(d.MessageId))
                {
                    continue;   // a restart of the SQLite store hands leased, unfinished deliveries out again; this test never finishes them
                }

                MimeMessage message = MimeMessage.Parse((await backend.Storage.Deliveries.GetRawAsync(d.MessageId, default))!);
                byte[] gz = message.EnumerateParts().Single(p => p.FileName is not null).GetDecodedBytes();
                (string domain, DateOnly day, long ok, long bad) = Summarize(TlsRptReportBuilder.Decompress(gz));
                mailto.Add(new Delivered(domain, day, ok, bad, clock.UtcNow, "mailto"));
            }
        }

        async Task SenderRunAsync()
        {
            await process.Sender.RunOnceAsync(default);
            await CollectMailtoAsync();
            // The journal holds the open day's counters (one row per domain and flush) and what is waiting for a retry; nothing of earlier, finished days.
            var rows = await backend.Storage.Config.GetTlsRptBucketsAsync(int.MaxValue, 100_000, default);
            int today = TlsReportJournal.DayNumber(DateOnly.FromDateTime(clock.UtcNow.UtcDateTime));
            Assert.All(rows.Where(r => r.Day < today - 1), r => Assert.True(r.Attempts > 0, "a finished day's counters are only kept while a report is being retried"));
            Assert.InRange(rows.Count, 0, Domains * 10);
        }

        int days = 30;
        DateOnly dayZero = DateOnly.FromDateTime(start.UtcDateTime);
        for (int hour = 1; hour <= days * 24; hour++)
        {
            clock.Advance(TimeSpan.FromHours(1));
            int clockDay = DateOnly.FromDateTime((clock.UtcNow - TimeSpan.FromSeconds(1)).UtcDateTime).DayNumber - dayZero.DayNumber;   // the day that contains the hour that just ended

            // A few sessions of random domains in the hour that has just passed.
            DateTimeOffset now = clock.UtcNow;
            for (int n = random.Next(0, 4); n > 0; n--)
            {
                int d = random.Next(0, Domains);
                bool ok = random.Next(0, 5) != 0;
                clock.Set(now - TimeSpan.FromMinutes(30));
                if (ok)
                {
                    process.Collector.RecordSuccess($"d{d}.example", Policy, $"mx.d{d}.example");
                }
                else
                {
                    process.Collector.RecordFailure($"d{d}.example", Policy, $"mx.d{d}.example", TlsResultType.CertificateExpired);
                }

                var key = (d, DateOnly.FromDateTime(clock.UtcNow.UtcDateTime));
                model.TryGetValue(key, out var counts);
                model[key] = ok ? (counts.Success + 1, counts.Failure) : (counts.Success, counts.Failure + 1);
                clock.Set(now);
            }

            if (clockDay == 9 && hour % 24 == 1)
            {
                dns.Remove("_smtp._tls.d5.example");   // d5 stops asking for reports
            }

            if (clockDay == 11 && hour % 24 == 13)
            {
                // A graceful restart in the middle of a day: the counters are flushed, the new process starts empty over the same storage.
                await process.Journal.FlushAsync(default);
                await backend.RestartAsync();
                process = new Process(backend, clock, dns, https);
            }

            if (clockDay is >= 14 and < 22)
            {
                // The report sender is not running for ten days, while the processes that serve mail keep writing their counters.
                await process.Journal.FlushAsync(default);
            }
            else if (hour % (int)RunEvery.TotalHours == 0)
            {
                await SenderRunAsync();
            }
        }

        clock.Advance(RunEvery);   // the reports of the last day
        await SenderRunAsync();

        var all = mailto.Concat(endpoint.Requests.Where(r => r.Accepted).Select(r => new Delivered(r.Host.Replace("reports.", string.Empty), r.Day, r.Success, r.Failure, r.At, "https"))).ToList();
        int expectedReports = 0;
        int droppedTooOld = 0;
        foreach (var ((domainIndex, day), counts) in model.OrderBy(kv => kv.Key.Day).ThenBy(kv => kv.Key.Domain))
        {
            string domain = $"d{domainIndex}.example";
            var found = all.Where(r => r.Domain == domain && r.Day == day).ToList();
            int dayIndex = day.DayNumber - dayZero.DayNumber;
            DateTimeOffset dayEnd = dayZero.AddDays(dayIndex + 1).ToDateTime(TimeOnly.MinValue) is var e ? new DateTimeOffset(e, TimeSpan.Zero) : default;

            // The first run after the day (and the 10 minute grace) is at 03:00 the next day, unless the sender was away: then it is the first run when it is back (day 30, 03:00).
            DateTimeOffset firstRun = dayEnd + RunEvery;
            DateTimeOffset away = start.AddDays(14) + RunEvery, back = start.AddDays(22) + RunEvery;
            if (firstRun >= away && firstRun < back)
            {
                firstRun = back;
            }

            bool tooOld = day.DayNumber < DateOnly.FromDateTime((firstRun - TlsReportJournal.CompletionGrace).UtcDateTime).DayNumber - TlsReportJournal.MaxReportAgeDays;
            bool gaveUp = domainIndex == 3 && dayIndex is 7 or 8;   // the endpoint was down for each of the six attempts of these reports
            bool noRecord = domainIndex == 5 && dayIndex >= 8;              // the record was gone when the report was due
            if (tooOld || gaveUp || noRecord)
            {
                Assert.True(found.Count == 0, $"{domain} {day} must not be reported (seed {seed})");
                droppedTooOld += tooOld ? 1 : 0;
                continue;
            }

            Assert.True(found.Count == 1, $"{domain} {day}: {found.Count} reports (seed {seed}): " + string.Join("; ", found.Select(f => $"{f.At:u} {f.Success}/{f.Failure} {f.Via}")));
            Delivered report = found[0];
            Assert.Equal(counts.Success, report.Success);
            Assert.Equal(counts.Failure, report.Failure);
            // Sent at the first run once the day is over (and the grace), except where the endpoint was down.
            DateTimeOffset expectedAt = (domainIndex, dayIndex) switch
            {
                (1, 3) => dayEnd + TimeSpan.FromHours(18),    // attempts at 06:00 and 12:00 fail, the 3rd at 18:00 is accepted
                (3, 9) => dayEnd + TimeSpan.FromHours(24),    // 06:00, 12:00 and 18:00 fail; at 00:00 the endpoint is back
                _ => firstRun,
            };
            Assert.Equal(expectedAt, report.At);
            expectedReports++;
        }

        Assert.True(expectedReports > 150, "reports were produced");
        Assert.True(droppedTooOld > 0, "the days the sender missed for more than a week were dropped");

        // The failing endpoint of d3 was asked exactly six times for each report it never accepted, and not once more.
        var d3Attempts = endpoint.Requests.Where(r => r.Host == "reports.d3.example" && !r.Accepted).GroupBy(r => r.Day).ToDictionary(g => g.Key.DayNumber - dayZero.DayNumber, g => g.Count());
        Assert.Equal(TlsReportSender.MaxAttempts, d3Attempts[7]);
        Assert.Equal(TlsReportSender.MaxAttempts, d3Attempts[8]);
        Assert.Equal(3, d3Attempts[9]);
        Assert.Equal(3, d3Attempts.Count);

        // Nothing is left in the journal but the open day.
        var left = await backend.Storage.Config.GetTlsRptBucketsAsync(int.MaxValue, 100_000, default);
        Assert.Empty(left);
    }
}
