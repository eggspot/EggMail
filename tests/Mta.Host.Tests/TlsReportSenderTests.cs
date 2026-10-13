using System.Text;
using Mta.Core;
using Mta.Dns;
using Mta.Host.Reports;
using Mta.Mime;
using Mta.Storage;
using Mta.Storage.InMemory;
using Mta.Tls;
using Mta.Tls.TlsRpt;

namespace Mta.Host.Tests;

public class TlsReportSenderTests
{
    private sealed class FakeClock(DateTimeOffset start) : IClock
    {
        public DateTimeOffset Now { get; set; } = start;
        public DateTimeOffset UtcNow => Now;
        public long Timestamp => Now.UtcTicks;
    }

    private static readonly TlsRptPolicyDescriptor Policy = TlsRptPolicyDescriptor.FromTlsa([]);

    /// <summary>One "process": a collector, its journal and the sender over a (shared) storage. A restart is a new <see cref="Process"/> over the same storage.</summary>
    private sealed class Process(FakeClock clock, IStorage storage, StaticDnsResolver dns, TlsRptHttpsSender https)
    {
        public TlsRptCollector Collector { get; } = new(clock);

        public TlsReportJournal Journal => field ??= new TlsReportJournal(Collector, storage.Config, clock);

        public TlsReportSender Sender => field ??= new TlsReportSender(Journal, storage.Config, new TlsRptRecordLookup(dns), https, storage.Intake, clock, "egg.test", "postmaster@egg.test");
    }

    private static async Task<InMemoryStorage> NewStorageAsync(IClock clock)
    {
        var storage = new InMemoryStorage(new StorageOptions(), clock);
        await storage.InitializeAsync(default);
        return storage;
    }

    [Fact]
    public async Task Completed_days_are_reported_to_the_mailto_endpoint_through_the_normal_queue()
    {
        var clock = new FakeClock(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
        var dns = new StaticDnsResolver().AddTxt("_smtp._tls.example.net", "v=TLSRPTv1; rua=mailto:tlsrpt@example.net");
        await using var storage = await NewStorageAsync(clock);
        using var https = new TlsRptHttpsSender();
        var p = new Process(clock, storage, dns, https);
        p.Collector.RecordSuccess("example.net", Policy, "mx.example.net");
        p.Collector.RecordSuccess("example.net", Policy, "mx.example.net");
        p.Collector.RecordFailure("example.net", Policy, "mx.example.net", TlsResultType.CertificateExpired);
        p.Collector.RecordSuccess("quiet.example", Policy, "mx.quiet.example");
        clock.Now = new DateTimeOffset(2026, 10, 12, 1, 0, 0, TimeSpan.Zero);

        int sent = await p.Sender.RunOnceAsync(default);

        // quiet.example publishes no TLS-RPT record, so nothing is sent for it.
        Assert.Equal(1, sent);
        var claimed = await storage.Deliveries.ClaimAsync("t", 10, clock.Now.AddSeconds(1), TimeSpan.FromMinutes(1), default);
        var delivery = Assert.Single(claimed);
        Assert.Equal("tlsrpt@example.net", delivery.Recipient.ToString());
        Assert.Equal(MessageSource.System, delivery.Source);
        var raw = await storage.Deliveries.GetRawAsync(delivery.MessageId, default);
        var message = MimeMessage.Parse(raw!);
        Assert.Contains("Report Domain: example.net", message.Headers.GetFirstValue("Subject"));
        var attachment = message.EnumerateParts().Single(p => p.FileName is not null);
        Assert.EndsWith(".json.gz", attachment.FileName);
        string json = Encoding.UTF8.GetString(TlsRptReportBuilder.Decompress(attachment.GetDecodedBytes()));
        Assert.Contains("\"organization-name\"", json);
        Assert.Contains("\"total-successful-session-count\":2", json);
        Assert.Contains("\"total-failure-session-count\":1", json);
        Assert.Contains("certificate-expired", json);

        // Nothing is sent twice, and nothing is left in the store.
        Assert.Equal(0, await p.Sender.RunOnceAsync(default));
        Assert.Empty(await storage.Config.GetTlsRptBucketsAsync(int.MaxValue, 100, default));
    }

    private sealed class CountingHandler : HttpMessageHandler
    {
        public int Requests;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Requests);
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.InternalServerError));
        }
    }

    [Fact]
    public async Task A_report_that_cannot_be_delivered_is_retried_later_and_given_up_after_the_limit()
    {
        var clock = new FakeClock(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
        var dns = new StaticDnsResolver().AddTxt("_smtp._tls.example.net", "v=TLSRPTv1; rua=https://reports.example.net/tlsrpt");
        await using var storage = await NewStorageAsync(clock);
        var handler = new CountingHandler();
        using var https = new TlsRptHttpsSender(handler);
        var p = new Process(clock, storage, dns, https);
        p.Collector.RecordSuccess("example.net", Policy, "mx.example.net");
        clock.Now = clock.Now.AddDays(1);

        for (int i = 0; i < TlsReportSender.MaxAttempts + 3; i++)
        {
            Assert.Equal(0, await p.Sender.RunOnceAsync(default));
        }

        Assert.Equal(TlsReportSender.MaxAttempts, handler.Requests);
        Assert.Empty(await storage.Config.GetTlsRptBucketsAsync(int.MaxValue, 100, default));
    }

    [Fact]
    public async Task Counters_flushed_before_a_restart_are_reported_by_the_new_process()
    {
        var clock = new FakeClock(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
        var dns = new StaticDnsResolver().AddTxt("_smtp._tls.example.net", "v=TLSRPTv1; rua=mailto:tlsrpt@example.net");
        await using var storage = await NewStorageAsync(clock);
        using var https = new TlsRptHttpsSender();

        var before = new Process(clock, storage, dns, https);
        before.Collector.RecordSuccess("example.net", Policy, "mx.example.net");
        before.Collector.RecordFailure("example.net", Policy, "mx.example.net", TlsResultType.CertificateExpired, receivingIp: "192.0.2.1");
        Assert.Equal(1, await before.Journal.FlushAsync(default));
        // More sessions of the same day after the flush, flushed at shutdown: a second piece of the same report.
        clock.Now = clock.Now.AddHours(3);
        before.Collector.RecordSuccess("example.net", Policy, "mx.example.net");
        before.Collector.RecordFailure("example.net", Policy, "mx.example.net", TlsResultType.CertificateExpired, receivingIp: "192.0.2.1");
        Assert.Equal(1, await before.Journal.FlushAsync(default));
        Assert.Equal(2, (await storage.Config.GetTlsRptBucketsAsync(int.MaxValue, 100, default)).Count);

        // The process is gone. The next one starts with an empty collector over the same storage and sends the report the next day.
        clock.Now = new DateTimeOffset(2026, 10, 12, 2, 0, 0, TimeSpan.Zero);
        var after = new Process(clock, storage, dns, https);
        Assert.Equal(1, await after.Sender.RunOnceAsync(default));

        var delivery = Assert.Single(await storage.Deliveries.ClaimAsync("t", 10, clock.Now.AddSeconds(1), TimeSpan.FromMinutes(1), default));
        var message = MimeMessage.Parse((await storage.Deliveries.GetRawAsync(delivery.MessageId, default))!);
        string json = Encoding.UTF8.GetString(TlsRptReportBuilder.Decompress(message.EnumerateParts().Single(p => p.FileName is not null).GetDecodedBytes()));
        Assert.Contains("\"total-successful-session-count\":2", json);
        Assert.Contains("\"total-failure-session-count\":2", json);
        Assert.Contains("\"failed-session-count\":2", json);   // the same failure line, counted across both pieces
        Assert.Contains("192.0.2.1", json);
        Assert.Contains("2026-10-11T00:00:00Z", json);
    }

    [Fact]
    public async Task A_pending_report_and_its_attempt_count_survive_a_restart()
    {
        var clock = new FakeClock(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
        var dns = new StaticDnsResolver().AddTxt("_smtp._tls.example.net", "v=TLSRPTv1; rua=https://reports.example.net/tlsrpt");
        await using var storage = await NewStorageAsync(clock);
        var handler = new CountingHandler();
        using var https = new TlsRptHttpsSender(handler);

        var first = new Process(clock, storage, dns, https);
        first.Collector.RecordSuccess("example.net", Policy, "mx.example.net");
        clock.Now = clock.Now.AddDays(1);
        Assert.Equal(0, await first.Sender.RunOnceAsync(default));   // attempt 1 fails: the merged counters stay in the store
        Assert.Equal(1, handler.Requests);
        var kept = Assert.Single(await storage.Config.GetTlsRptBucketsAsync(int.MaxValue, 10, default));
        Assert.Equal(1, kept.Attempts);

        // Restarting after every failed attempt does not reset the attempts: the report is given up after MaxAttempts in total.
        for (int i = 0; i < TlsReportSender.MaxAttempts + 2; i++)
        {
            var restarted = new Process(clock, storage, dns, https);
            Assert.Equal(0, await restarted.Sender.RunOnceAsync(default));
        }

        Assert.Equal(TlsReportSender.MaxAttempts, handler.Requests);
        Assert.Empty(await storage.Config.GetTlsRptBucketsAsync(int.MaxValue, 10, default));
    }

    [Fact]
    public async Task Todays_counters_are_kept_for_the_day_and_not_reported_early()
    {
        var clock = new FakeClock(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
        var dns = new StaticDnsResolver().AddTxt("_smtp._tls.example.net", "v=TLSRPTv1; rua=mailto:tlsrpt@example.net");
        await using var storage = await NewStorageAsync(clock);
        using var https = new TlsRptHttpsSender();
        var p = new Process(clock, storage, dns, https);
        p.Collector.RecordSuccess("example.net", Policy, "mx.example.net");

        Assert.Equal(0, await p.Sender.RunOnceAsync(default));   // the run flushes the counters, but the day is not over
        Assert.Single(await storage.Config.GetTlsRptBucketsAsync(int.MaxValue, 10, default));

        clock.Now = clock.Now.AddDays(1);
        Assert.Equal(1, await p.Sender.RunOnceAsync(default));
    }

    [Fact]
    public async Task Only_one_replica_sends_a_report_at_a_time()
    {
        var clock = new FakeClock(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
        var dns = new StaticDnsResolver().AddTxt("_smtp._tls.example.net", "v=TLSRPTv1; rua=mailto:tlsrpt@example.net");
        await using var storage = await NewStorageAsync(clock);
        using var https = new TlsRptHttpsSender();
        var p = new Process(clock, storage, dns, https);
        p.Collector.RecordSuccess("example.net", Policy, "mx.example.net");
        clock.Now = clock.Now.AddDays(1);

        // Another replica is in the middle of a run.
        Assert.NotNull(await storage.Config.TryAcquireLeaseAsync("tls-rpt-sender", "another-replica", TimeSpan.FromMinutes(30), clock.Now, default));
        Assert.Equal(0, await p.Sender.RunOnceAsync(default));
        Assert.Single(await storage.Config.GetTlsRptBucketsAsync(int.MaxValue, 10, default));

        // Its lease ran out (it died): this one takes over.
        clock.Now = clock.Now.AddMinutes(31);
        Assert.Equal(1, await p.Sender.RunOnceAsync(default));
    }

    private sealed class FailingStore(IRuntimeStateStore inner) : IRuntimeStateStore
    {
        public bool Fail { get; set; }

        public ValueTask AddTlsRptBucketsAsync(IReadOnlyList<TlsRptBucketRecord> buckets, CancellationToken ct) =>
            Fail ? throw new InvalidOperationException("storage unavailable") : inner.AddTlsRptBucketsAsync(buckets, ct);

        public ValueTask<IReadOnlyList<TlsRptBucketRecord>> GetTlsRptBucketsAsync(int beforeDay, int max, CancellationToken ct) => inner.GetTlsRptBucketsAsync(beforeDay, max, ct);

        public ValueTask ReplaceTlsRptBucketsAsync(IReadOnlyCollection<Guid> removeIds, TlsRptBucketRecord? replacement, CancellationToken ct) => inner.ReplaceTlsRptBucketsAsync(removeIds, replacement, ct);

        public ValueTask<IReadOnlyList<DomainRecordCheckRecord>> GetDomainRecordChecksAsync(Guid domainId, CancellationToken ct) => inner.GetDomainRecordChecksAsync(domainId, ct);

        public ValueTask ReplaceDomainRecordChecksAsync(Guid domainId, IReadOnlyList<DomainRecordCheckRecord> checks, CancellationToken ct) => inner.ReplaceDomainRecordChecksAsync(domainId, checks, ct);

        public ValueTask<IReadOnlyList<SendingCounterRecord>> GetSendingCountersAsync(long minHourIndex, long minDayIndex, CancellationToken ct) => inner.GetSendingCountersAsync(minHourIndex, minDayIndex, ct);

        public ValueTask AddSendingCountersAsync(IReadOnlyList<SendingCounterRecord> deltas, long pruneBeforeHour, long pruneBeforeDay, CancellationToken ct) => inner.AddSendingCountersAsync(deltas, pruneBeforeHour, pruneBeforeDay, ct);
    }

    [Fact]
    public async Task A_flush_that_cannot_write_keeps_the_counters_in_memory_for_the_next_flush()
    {
        var clock = new FakeClock(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
        await using var storage = await NewStorageAsync(clock);
        var store = new FailingStore(storage.Config);
        var collector = new TlsRptCollector(clock);
        var journal = new TlsReportJournal(collector, store, clock);
        collector.RecordSuccess("example.net", Policy, "mx.example.net");
        collector.RecordFailure("example.net", Policy, "mx.example.net", TlsResultType.CertificateExpired);

        store.Fail = true;
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await journal.FlushAsync(default));
        Assert.Empty(await storage.Config.GetTlsRptBucketsAsync(int.MaxValue, 10, default));

        store.Fail = false;
        Assert.Equal(1, await journal.FlushAsync(default));
        clock.Now = clock.Now.AddDays(1);
        var report = Assert.Single(await journal.GetCompletedAsync(10, default));
        var policy = Assert.Single(report.Data.Policies);
        Assert.Equal((1L, 1L), (policy.SuccessCount, policy.FailureCount));
    }

    [Fact]
    public async Task Counters_of_a_day_more_than_a_week_old_are_dropped_not_reported()
    {
        var clock = new FakeClock(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
        var dns = new StaticDnsResolver().AddTxt("_smtp._tls.example.net", "v=TLSRPTv1; rua=mailto:tlsrpt@example.net");
        await using var storage = await NewStorageAsync(clock);
        using var https = new TlsRptHttpsSender();
        var p = new Process(clock, storage, dns, https);
        p.Collector.RecordSuccess("example.net", Policy, "mx.example.net");
        await p.Journal.FlushAsync(default);

        clock.Now = clock.Now.AddDays(TlsReportJournal.MaxReportAgeDays + 1);
        Assert.Equal(0, await p.Sender.RunOnceAsync(default));
        Assert.Empty(await storage.Config.GetTlsRptBucketsAsync(int.MaxValue, 10, default));
        Assert.Empty(await storage.Deliveries.ClaimAsync("t", 10, clock.Now.AddSeconds(1), TimeSpan.FromMinutes(1), default));
    }

    [Fact]
    public async Task A_read_that_stops_at_the_limit_never_hands_out_half_a_domain_and_day()
    {
        var clock = new FakeClock(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
        await using var storage = await NewStorageAsync(clock);
        var collector = new TlsRptCollector(clock);
        var journal = new TlsReportJournal(collector, storage.Config, clock);
        for (int piece = 0; piece < 3; piece++)
        {
            collector.RecordSuccess("a.example", Policy, "mx.a.example");
            collector.RecordSuccess("b.example", Policy, "mx.b.example");
            clock.Now = clock.Now.AddMinutes(1);
            await journal.FlushAsync(default);
        }

        clock.Now = new DateTimeOffset(2026, 10, 12, 1, 0, 0, TimeSpan.Zero);
        // Six pieces, a read of four: it would cut b.example in two, so only a.example (all three pieces) is returned.
        var first = Assert.Single(await journal.GetCompletedAsync(4, default));
        Assert.Equal(("a.example", 3L), (first.Data.PolicyDomain, first.Data.Policies.Sum(p => p.SuccessCount)));
        await journal.CompleteAsync(first, default);
        var second = Assert.Single(await journal.GetCompletedAsync(4, default));
        Assert.Equal(("b.example", 3L), (second.Data.PolicyDomain, second.Data.Policies.Sum(p => p.SuccessCount)));
        Assert.Equal(3, second.BucketIds.Count);
    }

    [Fact]
    public async Task A_day_counts_as_completed_only_after_the_grace_period_so_a_late_flush_joins_the_same_report()
    {
        var clock = new FakeClock(new DateTimeOffset(2026, 10, 11, 23, 59, 0, TimeSpan.Zero));
        await using var storage = await NewStorageAsync(clock);
        var collector = new TlsRptCollector(clock);
        var journal = new TlsReportJournal(collector, storage.Config, clock);
        collector.RecordSuccess("a.example", Policy, "mx.a.example");
        await journal.FlushAsync(default);

        clock.Now = new DateTimeOffset(2026, 10, 12, 0, 5, 0, TimeSpan.Zero);
        Assert.Empty(await journal.GetCompletedAsync(100, default));
        clock.Now = clock.Now + TlsReportJournal.CompletionGrace;
        Assert.Single(await journal.GetCompletedAsync(100, default));
    }

    [Fact]
    public async Task An_unreadable_counter_row_is_dropped_without_blocking_the_other_reports()
    {
        var clock = new FakeClock(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
        var dns = new StaticDnsResolver().AddTxt("_smtp._tls.example.net", "v=TLSRPTv1; rua=mailto:tlsrpt@example.net");
        await using var storage = await NewStorageAsync(clock);
        using var https = new TlsRptHttpsSender();
        var p = new Process(clock, storage, dns, https);
        p.Collector.RecordSuccess("example.net", Policy, "mx.example.net");
        await p.Journal.FlushAsync(default);
        int day = TlsReportJournal.DayNumber(DateOnly.FromDateTime(clock.Now.UtcDateTime));
        await storage.Config.AddTlsRptBucketsAsync([new TlsRptBucketRecord(Ids.New(), day, "broken.example", "{ not json", 0, clock.Now)], default);
        clock.Now = clock.Now.AddDays(1);

        Assert.Equal(1, await p.Sender.RunOnceAsync(default));
        Assert.Empty(await storage.Config.GetTlsRptBucketsAsync(int.MaxValue, 10, default));
    }
}
