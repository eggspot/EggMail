using System.Net;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Mta.Core;
using Mta.Delivery;
using Mta.Host.Backup;
using Mta.Host.Configuration;
using Mta.Host.Tls;
using Mta.Observability;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

/// <summary>
/// A real scrape of <c>/metrics</c> over a SQLite-backed API: the exporter is created with the host, so what happened before the first scrape is
/// there, and the gauges of storage, queue, certificates and backups appear without any of them touching the database per scrape.
/// </summary>
[Collection("api")]
public class ApiMetricsScrapeTests : IAsyncLifetime
{
    private ApiFixture _f = null!;

    public async Task InitializeAsync() => _f = await ApiFixture.StartAsync(new ApiFixtureOptions
    {
        Sqlite = true,
        ConfigureServices = s => s.AddMtaObservability(new ObservabilityOptions()),
    });

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private async Task<string> ScrapeAsync()
    {
        ApiClient c = _f.NewClient();
        c.RemoteIp = "127.0.0.1";
        Reply r = await c.GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("text/plain", r.ContentType);
        return r.Body;
    }

    [Fact]
    public async Task The_scrape_carries_storage_queue_certificate_and_backup_metrics()
    {
        // Queue: attach the sampler the way the host does and take one sample.
        var gauges = new QueueGauges(_f.Storage.Deliveries, _f.Clock, NullMtaLog.Instance, TimeSpan.FromSeconds(15));
        using IDisposable queue = DeliveryMetrics.AttachQueueGauges(gauges);
        await gauges.SampleOnceAsync(default);

        // Certificates: the provider generates its first-run certificate.
        var provider = new DatabaseCertificateProvider(_f.Storage.Config, _f.Protector, "scrape.example", new TlsSection(), _f.Clock);
        await provider.InitializeAsync(default);
        await using var certificates = TlsMetrics.Attach(provider, _f.Clock);

        // Backup: one successful run into a directory next to the data.
        string backups = Path.Combine(Path.GetTempPath(), "eggmail-scrape-backups-" + Guid.NewGuid().ToString("N"));
        try
        {
            var scheduler = new BackupScheduler(_f.Storage, _f.Clock, backups, TimeSpan.FromHours(24), keep: 1);
            Assert.NotNull(await scheduler.RunOnceAsync(default));

            string text = await ScrapeAsync();

            // Every metric family is announced with HELP and TYPE, and the values we know are there.
            Assert.Contains("# TYPE mta_delivery_queue_depth gauge", text);
            Assert.Contains("mta_delivery_queue_depth{state=\"queued\"} 0\n", text);
            Assert.Contains("mta_delivery_queue_oldest_due_age_seconds 0\n", text);
            Assert.Contains("mta_delivery_queue_sample_age_seconds ", text);
            Assert.Contains("# TYPE mta_storage_sqlite_commit_duration_seconds histogram", text);   // the fixture's own tenants and users were committed
            Assert.Contains("mta_storage_sqlite_commit_duration_seconds_count{file=\"config.db\"} ", text);
            Assert.Contains("mta_storage_sqlite_writer_queue_depth{file=\"queue.db\"} ", text);
            Assert.Contains("mta_storage_sqlite_sync_off{file=\"config.db\"} 0\n", text);   // config.db defaults to FULL
            Assert.Contains("mta_storage_sqlite_wal_size_bytes{file=\"stats.db\"} ", text);
            Assert.Contains("mta_storage_sqlite_quarantined{file=\"queue.db\"} 0\n", text);
            Assert.Contains("mta_tls_certificate_expiry_seconds{name=", text);
            Assert.Contains("source=\"selfsigned\"", text);
            Assert.Contains("# TYPE mta_backup_runs_total counter", text);
            Assert.Contains("mta_backup_runs_total{outcome=\"success\"} ", text);
            Assert.Contains("mta_backup_last_success_timestamp_seconds ", text);

            // Exposition sanity: every sample line is "name{labels} number", and HELP/TYPE appear once per family.
            foreach (string line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.StartsWith('#'))
                {
                    continue;
                }

                int space = line.LastIndexOf(' ');
                Assert.True(space > 0 && double.TryParse(line[(space + 1)..], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out _), "not a sample line: " + line);
            }

            string[] types = text.Split('\n').Where(l => l.StartsWith("# TYPE ", StringComparison.Ordinal)).ToArray();
            Assert.Equal(types.Length, types.Distinct().Count());
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(backups))
            {
                Directory.Delete(backups, recursive: true);   // created above under a unique name; holds only this test's backup
            }
        }
    }

    [Fact]
    public async Task Queue_gauges_follow_the_queue_after_the_next_sample_and_not_before()
    {
        var gauges = new QueueGauges(_f.Storage.Deliveries, _f.Clock, NullMtaLog.Instance, TimeSpan.FromSeconds(15));
        using IDisposable queue = DeliveryMetrics.AttachQueueGauges(gauges);
        await gauges.SampleOnceAsync(default);
        Assert.Contains("mta_delivery_queue_depth{state=\"queued\"} 0\n", await ScrapeAsync());

        await _f.Storage.Intake.AcceptAsync(new AcceptedMessage
        {
            MessageId = Ids.New(_f.Clock.UtcNow),
            TenantId = ApiFixture.TenantAId,
            Source = MessageSource.Api,
            EnvelopeFrom = EmailAddress.Parse("a@example.com"),
            Recipients = [new AcceptedRecipient(Ids.New(_f.Clock.UtcNow), EmailAddress.Parse("r@example.net"))],
            Raw = System.Text.Encoding.ASCII.GetBytes("From: a@example.com\r\nTo: r@example.net\r\nSubject: s\r\nMessage-ID: <1@example.com>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n\r\nbody\r\n"),
            ReceivedAt = _f.Clock.UtcNow,
            ExpiresAt = _f.Clock.UtcNow.AddDays(5),
            SendingDomain = "example.com",
        }, default);

        Assert.Contains("mta_delivery_queue_depth{state=\"queued\"} 0\n", await ScrapeAsync());   // scraping does not look at the queue

        _f.Clock.Advance(TimeSpan.FromMinutes(5));
        await gauges.SampleOnceAsync(default);
        string text = await ScrapeAsync();
        Assert.Contains("mta_delivery_queue_depth{state=\"queued\"} 1\n", text);
        Assert.Contains("mta_delivery_queue_oldest_due_age_seconds 300\n", text);
    }
}
