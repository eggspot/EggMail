using Mta.Auth.Dmarc;
using Mta.Auth.Reports;
using Mta.Auth.Spf;
using static Mta.Auth.Tests.Reports.ReportTestSupport;

namespace Mta.Auth.Tests.Reports;

public class DmarcAggregateCollectorTests
{
    private static readonly DateTimeOffset Day1 = new(2026, 10, 11, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Day2 = Day1.AddDays(1);

    private static DmarcAggregateCollector Collector(DmarcAggregateCollectorOptions? options = null) =>
        new(options ?? new DmarcAggregateCollectorOptions { OrganizationName = "EggMail Test", ContactEmail = "dmarc@mx.test", Clock = new TestClock(Day2.AddHours(1)) });

    private sealed class TestClock(DateTimeOffset now) : Mta.Core.IClock
    {
        public DateTimeOffset UtcNow => now;

        public long Timestamp => 0;
    }

    [Fact]
    public async Task Identical_messages_are_counted_in_one_row()
    {
        var collector = Collector();
        for (int i = 0; i < 5; i++)
        {
            Assert.True(collector.Add(await ObservationAsync(Day1.AddMinutes(i))));
        }

        var report = Assert.Single(collector.DrainAll()).Report;
        var row = Assert.Single(report.Records);
        Assert.Equal(5, row.Count);
        Assert.Equal("203.0.113.5", row.SourceIp);
        Assert.Equal("example.com", row.HeaderFrom);
        Assert.Equal("example.com", row.EnvelopeFrom);
        Assert.False(row.DkimAligned);
        Assert.True(row.SpfAligned);
        Assert.Equal(DmarcDisposition.None, row.Disposition);
        Assert.Equal(SpfResult.Pass, Assert.Single(row.SpfResults).Result);
        Assert.Equal(SpfReportScope.MailFrom, row.SpfResults[0].Scope);
    }

    [Fact]
    public async Task Rows_are_split_by_source_ip_disposition_and_identifiers()
    {
        var collector = Collector();
        collector.Add(await ObservationAsync(Day1, ip: "203.0.113.5"));
        collector.Add(await ObservationAsync(Day1, ip: "203.0.113.6"));
        collector.Add(await ObservationAsync(Day1, ip: "2001:db8::1"));
        collector.Add(await ObservationAsync(Day1, ip: "203.0.113.5", spf: SpfResult.Fail, spfDomain: "evil.net")); // fails: reject
        collector.Add(await ObservationAsync(Day1, ip: "203.0.113.5", envelopeTo: "Rcpt.Example"));
        collector.Add(await ObservationAsync(Day1, ip: "203.0.113.5", dkim: [new DkimAuthResult("example.com", true, "s1")]));

        var report = Assert.Single(collector.DrainAll()).Report;
        Assert.Equal(6, report.Records.Count);
        Assert.Contains(report.Records, r => r.SourceIp == "2001:db8::1");
        Assert.Contains(report.Records, r => r.Disposition != DmarcDisposition.None);
        Assert.Contains(report.Records, r => r.EnvelopeTo == "rcpt.example");
        Assert.Contains(report.Records, r => r.DkimResults.Count == 1 && r.DkimAligned);
    }

    [Fact]
    public async Task Ipv4_mapped_addresses_are_reported_as_ipv4()
    {
        var collector = Collector();
        collector.Add(await ObservationAsync(Day1, ip: "::ffff:203.0.113.5"));
        collector.Add(await ObservationAsync(Day1, ip: "203.0.113.5"));
        var row = Assert.Single(Assert.Single(collector.DrainAll()).Report.Records);
        Assert.Equal(2, row.Count);
        Assert.Equal("203.0.113.5", row.SourceIp);
    }

    [Fact]
    public async Task Dkim_result_order_does_not_split_rows()
    {
        var collector = Collector();
        collector.Add(await ObservationAsync(Day1, dkim: [new DkimAuthResult("a.example", true, "1"), new DkimAuthResult("b.example", false, "2")]));
        collector.Add(await ObservationAsync(Day1, dkim: [new DkimAuthResult("b.example", false, "2"), new DkimAuthResult("a.example", true, "1")]));
        var row = Assert.Single(Assert.Single(collector.DrainAll()).Report.Records);
        Assert.Equal(2, row.Count);
        Assert.Equal(2, row.DkimResults.Count);
        Assert.Equal(DkimReportResult.Pass, row.DkimResults[0].Result);
    }

    [Fact]
    public async Task Rows_with_hostile_separator_characters_do_not_collide()
    {
        var collector = Collector();
        collector.Add(await ObservationAsync(Day1, dkim: [new DkimAuthResult("a/b", true, "c")]));
        collector.Add(await ObservationAsync(Day1, dkim: [new DkimAuthResult("a", true, "b/c")]));
        collector.Add(await ObservationAsync(Day1, dkim: [new DkimAuthResult("a|b", true, "c")]));
        Assert.Equal(3, Assert.Single(collector.DrainAll()).Report.Records.Count);
    }

    [Fact]
    public async Task Days_are_separate_reports_and_days_are_utc()
    {
        var collector = Collector();
        collector.Add(await ObservationAsync(Day1));
        collector.Add(await ObservationAsync(Day1.AddHours(11).AddMinutes(59))); // still 2026-10-11 23:59 UTC
        collector.Add(await ObservationAsync(new DateTimeOffset(2026, 10, 12, 1, 0, 0, TimeSpan.FromHours(3)))); // 2026-10-11 22:00 UTC
        collector.Add(await ObservationAsync(Day2));
        Assert.Equal(2, collector.PendingReportCount);
        var reports = collector.DrainAll();
        Assert.Equal(2, reports.Count);
        Assert.Equal(3, reports[0].Report.Records.Sum(r => r.Count));
        Assert.Equal(1, reports[1].Report.Records.Sum(r => r.Count));
        Assert.Equal(new DateTimeOffset(2026, 10, 11, 0, 0, 0, TimeSpan.Zero), reports[0].Report.Metadata.Begin);
        Assert.Equal(new DateTimeOffset(2026, 10, 11, 23, 59, 59, TimeSpan.Zero), reports[0].Report.Metadata.End);
    }

    [Fact]
    public async Task Drain_completed_returns_only_finished_days()
    {
        var collector = Collector(new DmarcAggregateCollectorOptions { Clock = new TestClock(Day2.AddHours(1)) });
        collector.Add(await ObservationAsync(Day1));
        collector.Add(await ObservationAsync(Day2));
        var done = collector.DrainCompleted();
        Assert.Single(done);
        Assert.Equal(1, collector.PendingReportCount);
        Assert.Empty(collector.DrainCompleted());
        Assert.Single(collector.DrainAll());
        Assert.Equal(0, collector.PendingReportCount);
    }

    [Fact]
    public async Task Drain_before_a_given_day()
    {
        var collector = Collector();
        collector.Add(await ObservationAsync(Day1));
        collector.Add(await ObservationAsync(Day2));
        Assert.Empty(collector.Drain(DateOnly.FromDateTime(Day1.UtcDateTime)));
        Assert.Single(collector.Drain(DateOnly.FromDateTime(Day2.UtcDateTime)));
    }

    [Fact]
    public async Task Report_carries_metadata_published_policy_and_destinations()
    {
        var collector = Collector();
        collector.Add(await ObservationAsync(Day1));
        var pending = Assert.Single(collector.DrainAll());
        var report = pending.Report;
        Assert.Equal("EggMail Test", report.Metadata.OrganizationName);
        Assert.Equal("dmarc@mx.test", report.Metadata.ContactEmail);
        Assert.EndsWith("@example.com", report.Metadata.ReportId);
        Assert.Equal("example.com", report.PolicyPublished.Domain);
        Assert.Equal(DmarcPolicy.Reject, report.PolicyPublished.Policy);
        Assert.Equal(DmarcPolicy.Quarantine, report.PolicyPublished.SubdomainPolicy);
        Assert.Equal(DmarcAlignmentMode.Strict, report.PolicyPublished.DkimAlignment);
        Assert.Equal(50, report.PolicyPublished.Percentage);
        Assert.Equal(["agg@example.com", "other@example.net"], pending.Destinations.Select(d => d.MailAddress));
        Assert.Equal(5L * 1024 * 1024, pending.Destinations[0].MaxSizeBytes);
        Assert.Empty(Validate(DmarcAggregateReportWriter.ToXmlString(report)));
    }

    [Fact]
    public async Task Subdomain_mail_is_reported_under_the_policy_domain()
    {
        var collector = Collector();
        collector.Add(await ObservationAsync(Day1, from: "news.example.com", spfDomain: "news.example.com"));
        var report = Assert.Single(collector.DrainAll()).Report;
        Assert.Equal("example.com", report.PolicyPublished.Domain);
        Assert.Equal("news.example.com", report.Records[0].HeaderFrom);
    }

    [Fact]
    public async Task Sampled_out_messages_carry_the_reason_and_the_weaker_disposition()
    {
        var collector = Collector();
        // pct=50, draw >= 50 means outside the sample; a failing message gets sampled out.
        collector.Add(await ObservationAsync(Day1, spf: SpfResult.Fail, random: new FixedDrawRandom(99)));
        var row = Assert.Single(Assert.Single(collector.DrainAll()).Report.Records);
        Assert.Equal(DmarcDisposition.Quarantine, row.Disposition);
        Assert.Equal(DmarcPolicyOverride.SampledOut, Assert.Single(row.Reasons).Type);
    }

    [Fact]
    public async Task Explicit_override_reasons_are_kept()
    {
        var collector = Collector();
        var (input, evaluation) = await EvaluateAsync();
        var observation = new DmarcAggregateObservation(Day1, System.Net.IPAddress.Parse("203.0.113.5"), input, evaluation, SpfReportScope.MailFrom, null,
            [new DmarcPolicyOverrideReason(DmarcPolicyOverride.MailingList, "list.example")]);
        collector.Add(observation);
        var row = Assert.Single(Assert.Single(collector.DrainAll()).Report.Records);
        Assert.Equal(new DmarcPolicyOverrideReason(DmarcPolicyOverride.MailingList, "list.example"), Assert.Single(row.Reasons));
    }

    [Fact]
    public async Task Messages_without_a_policy_or_report_address_are_skipped()
    {
        var collector = Collector();
        Assert.False(collector.Add(await ObservationAsync(Day1, policy: "v=DMARC1; p=reject")));
        Assert.False(collector.Add(await ObservationAsync(Day1, policy: "v=DMARC1; p=reject; rua=https://example.com/report")));
        Assert.False(collector.Add(await ObservationAsync(Day1, from: "other.org", spfDomain: "other.org")));
        Assert.Equal(0, collector.PendingReportCount);

        var lenient = Collector(new DmarcAggregateCollectorOptions { CollectWithoutReportAddress = true });
        Assert.True(lenient.Add(await ObservationAsync(Day1, policy: "v=DMARC1; p=reject")));
    }

    [Fact]
    public async Task Row_limit_drops_new_rows_and_notes_it_in_the_report()
    {
        var collector = Collector(new DmarcAggregateCollectorOptions { MaxRecordsPerReport = 3 });
        for (int i = 1; i <= 5; i++)
        {
            bool added = collector.Add(await ObservationAsync(Day1, ip: $"203.0.113.{i}"));
            Assert.Equal(i <= 3, added);
        }

        // An existing row can still be incremented after the limit is reached.
        Assert.True(collector.Add(await ObservationAsync(Day1, ip: "203.0.113.1")));
        Assert.Equal(2, collector.DroppedObservationCount);
        var report = Assert.Single(collector.DrainAll()).Report;
        Assert.Equal(3, report.Records.Count);
        Assert.Equal(4, report.Records.Sum(r => r.Count));
        Assert.Contains(report.Metadata.Errors!, e => e.StartsWith("2 messages"));
    }

    [Fact]
    public async Task Bucket_limit_drops_observations_for_new_policy_days()
    {
        var collector = Collector(new DmarcAggregateCollectorOptions { MaxPendingReports = 1 });
        Assert.True(collector.Add(await ObservationAsync(Day1)));
        Assert.False(collector.Add(await ObservationAsync(Day2)));
        Assert.True(collector.Add(await ObservationAsync(Day1)));
        Assert.Equal(1, collector.DroppedObservationCount);
    }

    [Fact]
    public async Task Concurrent_adds_and_drains_lose_nothing()
    {
        var collector = Collector();
        var observation = await ObservationAsync(Day1);
        var observation2 = await ObservationAsync(Day1, ip: "198.51.100.9");
        const int Threads = 8;
        const int PerThread = 2000;
        long drainedTotal = 0;
        using var stop = new CancellationTokenSource();
        var drainer = Task.Run(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                foreach (var pending in collector.DrainAll())
                {
                    Interlocked.Add(ref drainedTotal, pending.Report.Records.Sum(r => r.Count));
                }
            }
        });

        await Task.WhenAll(Enumerable.Range(0, Threads).Select(t => Task.Run(() =>
        {
            for (int i = 0; i < PerThread; i++)
            {
                Assert.True(collector.Add(i % 2 == 0 ? observation : observation2));
            }
        })));
        await stop.CancelAsync();
        await drainer;
        foreach (var pending in collector.DrainAll())
        {
            drainedTotal += pending.Report.Records.Sum(r => r.Count);
        }

        Assert.Equal(Threads * PerThread, drainedTotal);
    }

    [Fact]
    public async Task Drained_reports_round_trip_through_gzip_and_the_reader()
    {
        var collector = Collector();
        for (int i = 0; i < 20; i++)
        {
            collector.Add(await ObservationAsync(Day1, ip: $"203.0.113.{i}", dkim: [new DkimAuthResult("example.com", i % 2 == 0, "s" + i)]));
        }

        var report = Assert.Single(collector.DrainAll()).Report;
        byte[] gz = DmarcAggregateReportWriter.ToGzip(report);
        Assert.True(DmarcAggregateReportReader.TryRead(gz, out var parsed));
        Assert.Equal(report.Records.Count, parsed.Records.Count);
        Assert.Equal(report.Records.Sum(r => r.Count), parsed.Records.Sum(r => r.Count));
        Assert.Equal(report.PolicyPublished, parsed.PolicyPublished);
    }

    [Fact]
    public void Null_observation_throws() =>
        Assert.Throws<ArgumentNullException>(() => Collector().Add(null!));

    private sealed class FixedDrawRandom(int value) : Random
    {
        public override int Next(int maxValue) => value % maxValue;
    }
}
