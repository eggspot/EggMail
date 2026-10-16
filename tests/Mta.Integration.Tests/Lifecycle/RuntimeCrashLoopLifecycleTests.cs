using System.Collections.Concurrent;
using System.Net;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Mta.Core;
using Mta.Dns;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Security;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.Sqlite;
using Mta.TestSupport;
using Xunit.Abstractions;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>
/// The whole runtime (SMTP submission over loopback with STARTTLS and AUTH, the delivery engine, bounce generation) is killed and started again over the same SQLite files or the same
/// PostgreSQL database, several times in a row, while mail is being submitted and delivered to an unreliable remote (refusals, greylisting, connections cut after the data was forwarded).
/// A kill is the abrupt one: the storage is closed under the running engine, whose in-flight deliveries are never reported, the runtime state service is not stopped, nothing is flushed
/// gracefully. The cycles share one virtual clock that the test advances (the delivery retry schedule and the claim lease run in virtual time; after a kill the clock passes the claim lease,
/// as it does while the server is down). The configuration (tenant, domain, SMTP credential) is written once, in the first cycle, so every later sign-in proves that acknowledged
/// configuration survived the kills.
/// <para>
/// Invariants at the end, after the queue drained (<see cref="ChaosInvariants"/>): every message the server answered 250 to reaches exactly one final state per recipient, nothing is
/// missing at the remote, nothing was delivered twice unless it is flagged <c>possible_duplicate</c>, every hard bounce is explained to the sender and suppressed.
/// </para>
/// </summary>
[Collection("Runtime")]
public abstract class RuntimeCrashLoopLifecycleTests(ITestOutputHelper output) : IAsyncLifetime
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    protected readonly string Dir = Directory.CreateTempSubdirectory("eggmail-crashloop-").FullName;
    protected bool Unavailable;
    private readonly VirtualClock _clock = new(DateTimeOffset.UtcNow);
    private readonly RecordingLog _log = new();
    private readonly CancellationTokenSource _pumpStop = new();
    private ChaosInternet _internet = null!;
    private SmtpServer _remote = null!;
    private FlakyProxy _proxy = null!;
    private StaticDnsResolver _dns = null!;
    private Task _pump = Task.CompletedTask;
    private int _remotePort;
    private readonly ConcurrentBag<Task> _abandonedEngines = [];

    protected abstract StorageOptions StorageOptionsFor();

    protected abstract IStorage CreateStorage(StorageOptions options);

    protected virtual Task PrepareAsync() => Task.CompletedTask;

    protected virtual Task CleanupAsync() => Task.CompletedTask;

    public async Task InitializeAsync()
    {
        await PrepareAsync();
        if (Unavailable)
        {
            return;
        }

        int seed = Accelerated.Seed(8800);
        _internet = new ChaosInternet(seed, _log) { ReplyDelay = TimeSpan.FromMilliseconds(250) };   // wide window between "the remote has the message" and "we know it"
        _remote = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "mx.crash.example",
            Listeners = [new SmtpListenerOptions { Name = "mx", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce }],
        }, _internet);
        _remote.Start();
        _proxy = new FlakyProxy(_remote.LocalEndPoints["mx"].Port, 0.05, seed + 2);
        _remotePort = _proxy.Port;
        _dns = new StaticDnsResolver();
        foreach (string domain in new[] { "dest1.example", "dest2.example", "dest3.example", "example.org" })
        {
            _dns.AddMx(domain, 10, "mx." + domain).AddA("mx." + domain, "127.0.0.1");
        }

        // The virtual clock runs ahead of the real one while the test is alive: retries become due without waiting, a lease of 15 minutes lasts several real minutes.
        _pump = Task.Run(async () =>
        {
            while (!_pumpStop.IsCancellationRequested)
            {
                _clock.Advance(TimeSpan.FromSeconds(5));
                try
                {
                    await Task.Delay(40, _pumpStop.Token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        });
    }

    public async Task DisposeAsync()
    {
        if (Unavailable)
        {
            return;
        }

        foreach (Task engine in _abandonedEngines)
        {
            try
            {
                await engine.WaitAsync(TimeSpan.FromSeconds(60));
            }
            catch (TimeoutException)
            {
                Assert.Fail("an abandoned engine never finished");
            }
            catch (Exception)
            {
                // it met the closed storage
            }
        }

        await _pumpStop.CancelAsync();
        await _pump;
        await _proxy.DisposeAsync();
        await _remote.DisposeAsync();
        await CleanupAsync();
        try
        {
            Directory.Delete(Dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private sealed class Instance
    {
        public required EggMailRuntime Runtime { get; init; }
        public required CancellationTokenSource Stop { get; init; }
        public required Task Engine { get; init; }
        public required int SubmissionPort { get; init; }
    }

    private async Task<Instance> StartAsync(bool first)
    {
        var config = new MtaConfig
        {
            Hostname = "egg.test",
            Storage = StorageOptionsFor(),
            Smtp = new SmtpSection { Listeners = new Dictionary<string, ListenerSection> { ["submission"] = new() { Port = 0, BindAddress = "127.0.0.1", Mode = ListenerMode.StartTls, AuthRequired = true } } },
            Delivery = new DeliverySection
            {
                BounceDomain = "bounces.egg.test", RemotePort = _remotePort, AllowPrivateMxAddresses = true, PollInterval = TimeSpan.FromMilliseconds(20),
                RetryDelays = [TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(200)], Workers = 8,
                Throttle = new ThrottleSection { MaxConnections = 8, InitialConnections = 8, MaxMessagesPerMinute = 600_000, InitialMessagesPerMinute = 600_000, MaxMessagesPerConnection = 1000 },
            },
        };
        IStorage storage = CreateStorage(config.Storage);
        await storage.InitializeAsync(default);
        EggMailRuntime runtime = await EggMailRuntime.CreateAsync(config, storage, _clock, _log, default, _dns);
        if (first)
        {
            DateTimeOffset now = _clock.UtcNow;
            await storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, now, false), default);
            await storage.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), TenantId, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
            await storage.Config.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), TenantId, "acme-user", PasswordHasher.Hash("s3cret", 2000), true, now), default);
        }

        runtime.SmtpServer.Start();
        var stop = new CancellationTokenSource();
        return new Instance
        {
            Runtime = runtime,
            Stop = stop,
            Engine = Task.Run(() => runtime.Delivery.RunAsync(stop.Token)),
            SubmissionPort = runtime.SmtpServer.LocalEndPoints["submission"].Port,
        };
    }

    /// <summary>
    /// The abrupt end: the storage is closed under the engine (what its in-flight deliveries would have reported is lost: the processor retries a failed recording for about 4 seconds and then
    /// gives up, which a real kill never waits for), the engine is told to stop but not awaited (it finishes in the background against the closed storage, so it cannot touch the next runtime's
    /// data), the listeners are closed. No runtime state flush, no quiesce that works.
    /// </summary>
    private async Task KillAsync(Instance instance)
    {
        await instance.Runtime.Storage.DisposeAsync();
        await instance.Stop.CancelAsync();
        _abandonedEngines.Add(instance.Engine);
        await instance.Runtime.SmtpServer.StopAsync(TimeSpan.Zero);
        await instance.Runtime.DisposeAsync();
    }

    [Fact]
    public async Task Killing_the_whole_runtime_repeatedly_loses_no_acknowledged_message_and_duplicates_only_flagged_ones()
    {
        if (Unavailable)
        {
            return;   // no PostgreSQL on this machine (CI provides one)
        }

        int seed = Accelerated.Seed(8800);
        int cycles = Accelerated.Scaled(3);
        var rng = new Random(seed);
        output.WriteLine($"runtime crash loop: seed {seed}, {cycles} kills (replay: EGGMAIL_ACCEL_SEED={seed})");
        var plan = new ConcurrentQueue<(string Subject, string[] Recipients)>();
        int submitted = 0;
        int sendErrors = 0;
        Instance instance = await StartAsync(first: true);
        try
        {
            for (int cycle = 0; cycle <= cycles; cycle++)
            {
                int port = instance.SubmissionPort;
                var senders = Enumerable.Range(0, 2).Select(s => Task.Run(async () =>
                {
                    try
                    {
                        using var client = new SmtpClient { CheckCertificateRevocation = false, ServerCertificateValidationCallback = (_, _, _, _) => true, Timeout = 20_000 };
                        await client.ConnectAsync("127.0.0.1", port, SecureSocketOptions.StartTls);
                        await client.AuthenticateAsync("acme-user", "s3cret");
                        for (int i = 0; i < 4; i++)
                        {
                            string subject = $"chaos-{cycle}-{s}-{i}";
                            int count;
                            string[] rcpts;
                            lock (rng)
                            {
                                count = rng.Next(1, 4);
                                var set = new HashSet<string>();
                                while (set.Count < count)
                                {
                                    set.Add((rng.NextDouble() < 0.08 ? $"gone{rng.Next(1000)}" : $"user{rng.Next(1000)}") + $"@dest{rng.Next(1, 4)}.example");
                                }

                                rcpts = [.. set];
                            }

                            var msg = new MimeMessage();
                            msg.From.Add(MailboxAddress.Parse("news@example.org"));
                            foreach (string r in rcpts)
                            {
                                msg.To.Add(MailboxAddress.Parse(r));
                            }

                            msg.Subject = subject;
                            msg.Body = new TextPart("plain") { Text = "crash loop body\r\n" };
                            await client.SendAsync(msg);   // returned: the server answered 250, the message is acknowledged
                            plan.Enqueue((subject, rcpts));
                            Interlocked.Increment(ref submitted);
                        }

                        await client.DisconnectAsync(true);
                    }
                    catch (Exception)
                    {
                        // the runtime was killed under this connection: what it did not acknowledge is not promised
                        Interlocked.Increment(ref sendErrors);
                    }
                })).ToArray();

                if (cycle == cycles)
                {
                    await Task.WhenAll(senders);
                    break;
                }

                await Task.Delay(rng.Next(80, 450));   // a random moment of the submission and the first deliveries
                _clock.Advance(TimeSpan.FromMinutes(1));
                await KillAsync(instance);
                await Task.WhenAll(senders);
                _clock.Advance(TimeSpan.FromMinutes(16));   // the server was down for longer than a claim lease
                instance = await StartAsync(first: false);
                output.WriteLine($"  kill {cycle + 1}: {submitted} acknowledged so far, {sendErrors} interrupted submissions");
            }

            // Last cycle runs to the end: the queue drains with the virtual clock.
            var deadline = DateTime.UtcNow.AddSeconds(120);
            QueueStats stats;
            int stable = 0;
            do
            {
                await Task.Delay(100);
                stats = await instance.Runtime.Storage.Deliveries.GetQueueStatsAsync(default);
                stable = stats is { Queued: 0, Leased: 0, Deferred: 0 } ? stable + 1 : 0;
                Assert.True(DateTime.UtcNow < deadline, $"queue did not drain (seed {seed}): {stats}; pending groups {instance.Runtime.Delivery.PendingGroups}\n{string.Join('\n', _log.Lines.TakeLast(25))}");
            }
            while (stable < 10);

            Assert.True(submitted >= 8, $"only {submitted} messages were acknowledged (seed {seed})");
            await ChaosInvariants.AssertAsync(instance.Runtime.Storage, TenantId, [.. plan], _internet, $" (seed {seed}, {submitted} acknowledged messages, {cycles} kills)");
            int receivedTwice = _internet.Accepted.GroupBy(a => a).Count(g => g.Count() > 1);
            output.WriteLine($"runtime crash loop: {submitted} acknowledged messages over {cycles} kills, {_proxy.Drops} connections cut after the data, {_internet.Accepted.Count} receipts at the remote, {receivedTwice} recipients received twice (all flagged possible_duplicate)");
        }
        finally
        {
            await instance.Stop.CancelAsync();
            try
            {
                await instance.Engine;
            }
            catch (Exception)
            {
            }

            await instance.Runtime.SmtpServer.StopAsync(TimeSpan.FromSeconds(2));
            await instance.Runtime.DisposeAsync();
            await instance.Runtime.Storage.DisposeAsync();
        }
    }
}

public sealed class RuntimeCrashLoopLifecycleOnSqlite(ITestOutputHelper output) : RuntimeCrashLoopLifecycleTests(output)
{
    protected override StorageOptions StorageOptionsFor() => new() { Sqlite = new SqliteOptions { DataDirectory = Dir } };

    protected override IStorage CreateStorage(StorageOptions options) => SqliteStorage.Create(options);
}

public sealed class RuntimeCrashLoopLifecycleOnPostgres(ITestOutputHelper output) : RuntimeCrashLoopLifecycleTests(output)
{
    private Mta.Storage.Postgres.Tests.TestDatabase? _database;

    protected override async Task PrepareAsync()
    {
        if (Mta.Storage.Postgres.Tests.PostgresTestServer.UnavailableReason is not null)
        {
            Unavailable = true;
            return;
        }

        _database = await Mta.Storage.Postgres.Tests.PostgresTestServer.Instance.CreateDatabaseAsync();
    }

    protected override async Task CleanupAsync()
    {
        if (_database is not null)
        {
            await _database.DisposeAsync();
        }
    }

    protected override StorageOptions StorageOptionsFor() => new()
    {
        Backend = StorageBackend.Postgres,
        Postgres = new PostgresOptions { OwnerConnectionString = _database!.ConnectionString, RuntimeConnectionString = _database.ConnectionString },
    };

    protected override IStorage CreateStorage(StorageOptions options) => Mta.Storage.Postgres.PostgresStorage.Create(options);
}
