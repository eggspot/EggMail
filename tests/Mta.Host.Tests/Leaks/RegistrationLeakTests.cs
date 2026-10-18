using System.Reflection;
using Mta.Core;
using Mta.Host.Backup;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Tls;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.InMemory;
using Mta.Storage.Sqlite;
using Mta.TestSupport;
using Xunit.Abstractions;

namespace Mta.Host.Tests.Leaks;

/// <summary>
/// Accelerated lifecycle, leaks: registrations that outlive the object that made them. The metric gauges of the SQLite storage, the backup scheduler and
/// the certificate provider read a process-wide table of live instances: an instance that is disposed without detaching stays reachable for the life of the
/// process, with everything it references. And a CLR <c>event</c> subscribed per iteration and never unsubscribed does the same; there is none in the code base
/// today, and a guard says so, so that the first one comes with a test of its own.
/// </summary>
[Collection(LeakCollection.Name)]
public sealed class RegistrationLeakTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Leak_backup_schedulers_detach_from_the_gauges_when_disposed()
    {
        string dir = Directory.CreateTempSubdirectory("eggmail-leak-backup-").FullName;
        try
        {
            var clock = new VirtualClock();
            await using var storage = new InMemoryStorage(new StorageOptions(), clock, null, TimeSpan.Zero);
            int before = BackupMetrics.AttachedCount;   // other tests of the assembly may have left schedulers attached; only this test's must be gone
            using var probe = new LeakProbe(output.WriteLine);
            probe.Track("schedulers attached to the backup gauges", () => BackupMetrics.AttachedCount);
            LeakReport report = await probe.RunAsync(_ =>
            {
                using var scheduler = new BackupScheduler(storage, clock, dir, TimeSpan.FromHours(24), keep: 2);
                Assert.True(BackupMetrics.IsAttached(scheduler));
            }, Accelerated.Scaled(1000));
            report.AssertNoGrowth();
            Assert.Equal(before, BackupMetrics.AttachedCount);
        }
        finally
        {
            try
            {
                Directory.Delete(dir, recursive: true);   // created by this test, empty
            }
            catch (IOException)
            {
            }
        }
    }

    [Fact]
    public async Task Leak_certificate_providers_detach_from_the_gauges_when_their_meters_are_disposed()
    {
        var clock = new VirtualClock();
        await using var storage = new InMemoryStorage(new StorageOptions(), clock, null, TimeSpan.Zero);
        var protector = new TestProtector();
        int before = TlsMetrics.AttachedCount;   // other tests of the assembly may have left providers attached; only this test's must be gone
        using var probe = new LeakProbe(output.WriteLine);
        probe.Track("providers attached to the certificate gauges", () => TlsMetrics.AttachedCount);
        LeakReport report = await probe.RunAsync(async _ =>
        {
            var provider = new DatabaseCertificateProvider(storage.Config, protector, "leak.example", new TlsSection(), clock);
            await using (TlsMetrics.Attach(provider, clock))
            {
                Assert.True(TlsMetrics.IsAttached(provider));
            }

            Assert.False(TlsMetrics.IsAttached(provider));
        }, Accelerated.Scaled(1000));
        report.AssertNoGrowth();
        Assert.Equal(before, TlsMetrics.AttachedCount);
    }

    [Fact]
    public async Task Leak_creating_and_disposing_sqlite_storages_detaches_them_and_finalizes_their_statements()
    {
        string dir = Directory.CreateTempSubdirectory("eggmail-leak-registry-").FullName;
        try
        {
            int before = SqliteMetrics.AttachedCount;   // other tests of the assembly may have left storages attached; only this test's must be gone
            using var probe = new LeakProbe(output.WriteLine);
            probe.Track("storages attached to the SQLite gauges", () => SqliteMetrics.AttachedCount);
            LeakReport report = await probe.RunAsync(async _ =>
            {
                await using SqliteStorage storage = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = dir, StatsFlushInterval = TimeSpan.Zero } });
                await storage.InitializeAsync(default);
                Assert.True(SqliteMetrics.IsAttached(storage));
            }, Accelerated.Scaled(15));
            report.AssertNoGrowth();
            Assert.Equal(before, SqliteMetrics.AttachedCount);
        }
        finally
        {
            try
            {
                Directory.Delete(dir, recursive: true);   // created by this test
            }
            catch (IOException)
            {
            }
        }
    }

    [Fact]
    public void Leak_guard_no_assembly_of_the_product_declares_a_clr_event()
    {
        // A long-lived object with an event that short-lived objects subscribe to (and forget to unsubscribe from) keeps every subscriber alive. The product has none; if
        // one is added, add its subscribe/unsubscribe churn to this class and list it here.
        var allowed = new HashSet<string>(StringComparer.Ordinal);
        Assembly[] assemblies =
        [
            typeof(IClock).Assembly, typeof(SmtpServer).Assembly, typeof(Mta.Smtp.Client.SmtpConnectionPool).Assembly, typeof(Mta.Dns.DnsClient).Assembly, typeof(Mta.Mime.MimeMessage).Assembly,
            typeof(Mta.Dkim.DkimSigner).Assembly, typeof(Mta.Auth.Spf.SpfEvaluator).Assembly, typeof(Mta.Delivery.DeliveryEngine).Assembly, typeof(Mta.Policy.DestinationThrottle).Assembly,
            typeof(Mta.Tls.MtaSts.MtaStsPolicyStore).Assembly, typeof(Mta.Webhooks.WebhookDispatcher).Assembly, typeof(IStorage).Assembly, typeof(SqliteStorage).Assembly,
            typeof(EggMailRuntime).Assembly, typeof(Mta.Observability.PrometheusTextExporter).Assembly,
        ];
        var events = new List<string>();
        foreach (Assembly assembly in assemblies.Distinct())
        {
            foreach (Type type in assembly.GetTypes())
            {
                foreach (EventInfo e in type.GetEvents(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
                {
                    events.Add($"{type.FullName}.{e.Name}");
                }
            }
        }

        List<string> unexpected = events.Where(e => !allowed.Contains(e)).ToList();
        Assert.True(unexpected.Count == 0, "CLR events found: " + string.Join(", ", unexpected));
    }

    [Fact]
    public async Task Leak_creating_and_disposing_the_whole_runtime_releases_threads_files_timers_and_registrations()
    {
        string dir = Directory.CreateTempSubdirectory("eggmail-leak-restart-").FullName;
        try
        {
            // The same data directory every time: a process that restarts over its own files (the first cycle generates the certificate).
            long statementsBefore = PreparedCommand.LiveCount;   // other tests of the assembly may have left storages open; only this test's must be gone
            int attachedBefore = SqliteMetrics.AttachedCount;
            using var probe = new LeakProbe(output.WriteLine) { WarmupBatches = 1 };
            probe.Allow("threads", 12);
            probe.Track("prepared SQLite statements", () => PreparedCommand.LiveCount);
            probe.Track("storages attached to the SQLite gauges", () => SqliteMetrics.AttachedCount);
            LeakReport report = await probe.RunAsync(async _ =>
            {
                var config = new MtaConfig
                {
                    Hostname = "egg.test",
                    Storage = new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = dir, StatsFlushInterval = TimeSpan.Zero } },
                    Smtp = new SmtpSection { Listeners = new Dictionary<string, ListenerSection> { ["submission"] = new() { Port = 0, BindAddress = "127.0.0.1", Mode = ListenerMode.StartTls, AuthRequired = true } } },
                    Webhooks = new Mta.Webhooks.WebhookOptions { AllowHttp = true, PollInterval = TimeSpan.FromMilliseconds(20) },
                    Delivery = new DeliverySection { AllowPrivateMxAddresses = true, PollInterval = TimeSpan.FromMilliseconds(20) },
                };
                SqliteStorage storage = SqliteStorage.Create(config.Storage);
                await storage.InitializeAsync(default);
                EggMailRuntime runtime = await EggMailRuntime.CreateAsync(config, storage, SystemClock.Instance, NullMtaLog.Instance, default);
                using var stop = new CancellationTokenSource();
                runtime.SmtpServer.Start();
                Task engine = Task.Run(() => runtime.Delivery.RunAsync(stop.Token));
                Task dispatcher = Task.Run(() => runtime.Webhooks.RunAsync(stop.Token));

                // The shutdown order of the host: stop the loops, then the listeners, then the runtime, then the storage.
                await stop.CancelAsync();
                await Task.WhenAll(engine, dispatcher);
                await runtime.SmtpServer.StopAsync(TimeSpan.FromSeconds(2));
                await runtime.DisposeAsync();
                await storage.DisposeAsync();
            }, Accelerated.Scaled(4));
            report.AssertNoGrowth();
            Assert.Equal(statementsBefore, PreparedCommand.LiveCount);
            Assert.Equal(attachedBefore, SqliteMetrics.AttachedCount);
        }
        finally
        {
            try
            {
                Directory.Delete(dir, recursive: true);   // created by this test
            }
            catch (IOException)
            {
            }
        }
    }
}
