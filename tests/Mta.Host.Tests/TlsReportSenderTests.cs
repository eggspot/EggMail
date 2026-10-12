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

    [Fact]
    public async Task Completed_days_are_reported_to_the_mailto_endpoint_through_the_normal_queue()
    {
        var clock = new FakeClock(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
        var collector = new TlsRptCollector(clock);
        var policy = TlsRptPolicyDescriptor.FromTlsa([]);
        collector.RecordSuccess("example.net", policy, "mx.example.net");
        collector.RecordSuccess("example.net", policy, "mx.example.net");
        collector.RecordFailure("example.net", policy, "mx.example.net", TlsResultType.CertificateExpired);
        collector.RecordSuccess("quiet.example", policy, "mx.quiet.example");
        clock.Now = new DateTimeOffset(2026, 10, 12, 1, 0, 0, TimeSpan.Zero);

        var dns = new StaticDnsResolver().AddTxt("_smtp._tls.example.net", "v=TLSRPTv1; rua=mailto:tlsrpt@example.net");
        await using var storage = new InMemoryStorage(new StorageOptions(), clock);
        await storage.InitializeAsync(default);
        using var https = new TlsRptHttpsSender();
        var sender = new TlsReportSender(collector, new TlsRptRecordLookup(dns), https, storage.Intake, clock, "egg.test", "postmaster@egg.test");

        int sent = await sender.RunOnceAsync(default);

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

        // Nothing is sent twice.
        Assert.Equal(0, await sender.RunOnceAsync(default));
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
        var collector = new TlsRptCollector(clock);
        collector.RecordSuccess("example.net", TlsRptPolicyDescriptor.FromTlsa([]), "mx.example.net");
        clock.Now = clock.Now.AddDays(1);
        var dns = new StaticDnsResolver().AddTxt("_smtp._tls.example.net", "v=TLSRPTv1; rua=https://reports.example.net/tlsrpt");
        await using var storage = new InMemoryStorage(new StorageOptions(), clock);
        await storage.InitializeAsync(default);
        var handler = new CountingHandler();
        using var https = new TlsRptHttpsSender(handler);
        var sender = new TlsReportSender(collector, new TlsRptRecordLookup(dns), https, storage.Intake, clock, "egg.test", "postmaster@egg.test");

        for (int i = 0; i < TlsReportSender.MaxAttempts + 3; i++)
        {
            Assert.Equal(0, await sender.RunOnceAsync(default));
        }

        Assert.Equal(TlsReportSender.MaxAttempts, handler.Requests);
    }
}
