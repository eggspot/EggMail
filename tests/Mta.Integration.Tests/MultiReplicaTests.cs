using System.Collections.Concurrent;
using System.Net;
using System.Text;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Mta.Core;
using Mta.Dns;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Security;
using Mta.Policy;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.Postgres;
using Mta.Storage.Postgres.Tests;
using Mta.Tls;
using Mta.Tls.TlsRpt;
using Npgsql;

namespace Mta.Integration.Tests;

/// <summary>
/// A <c>[Fact]</c> that needs a PostgreSQL server: reported as skipped when there is none (locally, without installed binaries or <c>EGGMAIL_TEST_POSTGRES</c>), but never when the
/// environment promises one: under CI (<c>CI</c> is set) or with <c>EGGMAIL_TEST_POSTGRES</c> set the test runs and fails if the server is not there, so a broken CI service cannot
/// turn the proof into a pass.
/// </summary>
public sealed class PostgresFactAttribute : FactAttribute
{
    private static bool ServerPromised =>
        !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CI")) || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("EGGMAIL_TEST_POSTGRES"));

    public override string Skip
    {
        get => base.Skip ?? (ServerPromised ? null : PostgresTestServer.UnavailableReason)!;
        set => base.Skip = value;
    }
}

/// <summary>
/// Several replicas of EggMail (separate <see cref="EggMailRuntime"/> instances, each with its own storage object and connection pool) on one PostgreSQL database. The tests need a
/// server (<c>EGGMAIL_TEST_POSTGRES</c> in CI, or locally installed binaries) and return at once without one, like the other PostgreSQL pipeline tests.
/// </summary>
internal static class ReplicaHarness
{
    public static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    public static StorageOptions StorageFor(TestDatabase database) => new()
    {
        Backend = StorageBackend.Postgres,
        Postgres = new PostgresOptions { OwnerConnectionString = database.ConnectionString, RuntimeConnectionString = database.ConnectionString },
    };

    public static MtaConfig ConfigFor(StorageOptions storage, int remotePort = 25, TimeSpan? claimLease = null, int workers = 8) => new()
    {
        Hostname = "egg.test",
        Storage = storage,
        Smtp = new SmtpSection { Listeners = new Dictionary<string, ListenerSection> { ["submission"] = new() { Port = 0, BindAddress = "127.0.0.1", Mode = ListenerMode.StartTls, AuthRequired = true } } },
        Delivery = new DeliverySection
        {
            BounceDomain = "bounces.egg.test", RemotePort = remotePort, AllowPrivateMxAddresses = true, PollInterval = TimeSpan.FromMilliseconds(20),
            RetryDelays = [TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(200)], Workers = workers, ClaimBatchSize = 3,
            ClaimLease = claimLease ?? TimeSpan.FromMinutes(15),
            Throttle = new ThrottleSection { MaxConnections = 16, InitialConnections = 16, MaxMessagesPerMinute = 600_000, InitialMessagesPerMinute = 600_000, MaxMessagesPerConnection = 1000 },
        },
    };

    /// <summary>Starts one replica: its own storage object over the shared database, initialized, with its runtime, which has joined the replica set (as the host does before the delivery engine starts).</summary>
    public static async Task<EggMailRuntime> StartAsync(MtaConfig config, IClock clock, IMtaLog log, IDnsResolver dns)
    {
        var storage = PostgresStorage.Create(config.Storage, clock, log);
        await storage.InitializeAsync(default);
        var runtime = await EggMailRuntime.CreateAsync(config, storage, clock, log, default, dns);
        await runtime.ReplicaCoordinator!.RunOnceAsync(default);
        return runtime;
    }

    public static async Task SeedAsync(IStorage storage, params string[] domains)
    {
        var now = DateTimeOffset.UtcNow;
        await storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, now, false), default);
        foreach (string domain in domains)
        {
            await storage.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), TenantId, domain, DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        }

        await storage.Config.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), TenantId, "acme-user", PasswordHasher.Hash("s3cret", 2000), true, now), default);
    }

    public static int SubmissionPort(EggMailRuntime runtime) => runtime.SmtpServer.LocalEndPoints["submission"].Port;

    public static async Task<long> CountAsync(TestDatabase database, string sql)
    {
        await using var connection = new NpgsqlConnection(database.ConnectionString);
        await connection.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, connection);
        return Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }

    public static async Task StopAsync(EggMailRuntime runtime)
    {
        await runtime.SmtpServer.StopAsync(TimeSpan.FromSeconds(2));
        if (runtime.ReplicaCoordinator is { } exchange)
        {
            await exchange.LeaveAsync(default);
        }

        await runtime.DisposeAsync();
        await runtime.Storage.DisposeAsync();
    }
}

/// <summary>What replicas share through the database, with real runtimes over a real PostgreSQL: the live set and the destination limits, what remote destinations did, and the failed-login budget.</summary>
[Collection("Runtime")]
public sealed class MultiReplicaStateTests : IAsyncLifetime
{
    private TestDatabase? _database;
    private readonly List<EggMailRuntime> _replicas = [];

    public async Task InitializeAsync()
    {
        _database = await PostgresTestServer.Instance.CreateDatabaseAsync();
        var config = ReplicaHarness.ConfigFor(ReplicaHarness.StorageFor(_database));
        // One after the other: each generates (the first) or loads (the next) the shared TLS certificate for its submission listener.
        for (int i = 0; i < 2; i++)
        {
            var runtime = await ReplicaHarness.StartAsync(config, SystemClock.Instance, NullMtaLog.Instance, new StaticDnsResolver());
            runtime.SmtpServer.Start();
            _replicas.Add(runtime);
        }

        await ReplicaHarness.SeedAsync(_replicas[0].Storage);
    }

    public async Task DisposeAsync()
    {
        foreach (var replica in _replicas)
        {
            await ReplicaHarness.StopAsync(replica);
        }

        if (_database is not null)
        {
            await _database.DisposeAsync();
        }
    }

    private EggMailRuntime A => _replicas[0];

    private EggMailRuntime B => _replicas[1];

    private async Task CoordinateAllAsync()
    {
        foreach (var replica in _replicas)
        {
            await replica.ReplicaCoordinator!.RunOnceAsync(default);
        }
    }

    [PostgresFact]
    public async Task Replicas_find_each_other_and_share_the_destination_ceilings_until_one_leaves()
    {
        await CoordinateAllAsync();
        await CoordinateAllAsync();
        Assert.Equal(2, A.ReplicaCoordinator!.ReplicaCount);
        Assert.Equal(2, B.ReplicaCoordinator!.ReplicaCount);
        Assert.NotEqual(A.ReplicaCoordinator.ReplicaIndex, B.ReplicaCoordinator.ReplicaIndex);
        Assert.Equal(2, await ReplicaHarness.CountAsync(_database!, "SELECT count(*) FROM replica_heartbeat"));

        var key = new ThrottleKey("big.example");
        var leasesA = new List<ThrottleLease>();
        var leasesB = new List<ThrottleLease>();
        while (A.DestinationThrottle.TryAcquire(key) is { Acquired: true } a)
        {
            leasesA.Add(a.Lease);
        }

        while (B.DestinationThrottle.TryAcquire(key) is { Acquired: true } b)
        {
            leasesB.Add(b.Lease);
        }

        // The configured ceiling of 16 connections to one destination holds for both together.
        Assert.Equal(8, leasesA.Count);
        Assert.Equal(8, leasesB.Count);

        foreach (var lease in leasesA.Concat(leasesB))
        {
            lease.Dispose();
        }

        await B.ReplicaCoordinator.LeaveAsync(default);
        await A.ReplicaCoordinator.RunOnceAsync(default);
        Assert.Equal(1, A.ReplicaCoordinator.ReplicaCount);
        Assert.Equal(16, A.DestinationThrottle.GetSnapshot(key)!.ConcurrencyCeiling);
        Assert.Equal(1, await ReplicaHarness.CountAsync(_database!, "SELECT count(*) FROM replica_heartbeat"));
    }

    [PostgresFact]
    public async Task A_destination_that_slows_one_replica_down_and_an_unreachable_server_are_known_to_the_other_replica_within_one_round()
    {
        await CoordinateAllAsync();
        var destination = new ThrottleKey("gmail.example");
        var mx = RouteHealthKey.ForMxHost("mx.down.example");
        B.DestinationThrottle.TryAcquire(destination).Lease!.Dispose();
        double rateBefore = B.DestinationThrottle.GetSnapshot(destination)!.MessagesPerMinute;

        A.DestinationThrottle.Report(destination, ThrottleSignal.Throttled);
        for (int i = 0; i < 5; i++)
        {
            A.Health.ReportFailure(mx, "connection timed out");
        }

        Assert.Equal(CircuitState.Closed, B.Health.GetSnapshot(mx).State);
        await A.ReplicaCoordinator!.RunOnceAsync(default);
        await B.ReplicaCoordinator!.RunOnceAsync(default);

        Assert.Equal(rateBefore / 2, B.DestinationThrottle.GetSnapshot(destination)!.MessagesPerMinute);
        Assert.Equal(CircuitState.Open, B.Health.GetSnapshot(mx).State);
        // The signal is a duration, aged by the database: the retry times agree up to the time the round trips took.
        Assert.InRange((A.Health.GetSnapshot(mx).RetryAt!.Value - B.Health.GetSnapshot(mx).RetryAt!.Value).Duration(), TimeSpan.Zero, TimeSpan.FromSeconds(2));
        Assert.Equal(RouteAdmission.Rejected, B.Health.TryAdmit(mx));
    }

    private static async Task<bool> LoginSucceedsAsync(EggMailRuntime runtime, string password)
    {
        using var client = new SmtpClient { CheckCertificateRevocation = false, ServerCertificateValidationCallback = (_, _, _, _) => true };
        await client.ConnectAsync("127.0.0.1", ReplicaHarness.SubmissionPort(runtime), SecureSocketOptions.StartTls);
        client.AuthenticationMechanisms.Clear();
        client.AuthenticationMechanisms.Add("PLAIN");   // one attempt per call: MailKit would otherwise try every mechanism, and each failure counts
        try
        {
            await client.AuthenticateAsync("acme-user", password);
            return true;
        }
        catch (Exception ex) when (ex is AuthenticationException or SmtpCommandException)
        {
            return false;
        }
    }

    /// <summary>Wrong-password logins, alternately against the two replicas, at the same time (the server delays each failure by a second).</summary>
    private async Task FailLoginsAsync(int count)
    {
        bool[] results = await Task.WhenAll(Enumerable.Range(0, count).Select(i => LoginSucceedsAsync(i % 2 == 0 ? A : B, "wrong")));
        Assert.DoesNotContain(true, results);
    }

    [PostgresFact]
    public async Task Failed_logins_count_against_one_budget_for_all_replicas()
    {
        Assert.True(A.AuthThrottle.IsShared);

        // Nine failures spread over both replicas (budget: 10 per address and per user in 15 minutes): neither replica has seen more than five, and sign-in still works.
        await FailLoginsAsync(9);

        Assert.True(await LoginSucceedsAsync(B, "s3cret"));   // a success clears the counts

        // Ten failures, five on each replica: neither replica alone reached its budget, together they did.
        await FailLoginsAsync(10);

        Assert.False(await LoginSucceedsAsync(A, "s3cret"));   // locked out, even with the right password, on both replicas
        Assert.False(await LoginSucceedsAsync(B, "s3cret"));

        // The database holds keyed digests only: no address, no user name, and not even their plain hashes.
        long rows = await ReplicaHarness.CountAsync(_database!, "SELECT count(*) FROM auth_failure");
        Assert.True(rows >= 2);
        Assert.Equal(0, await ReplicaHarness.CountAsync(_database!, "SELECT count(*) FROM auth_failure WHERE key_digest !~ '^[0-9A-F]{64}$'"));
        string plain = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData("127.0.0.1"u8));
        Assert.Equal(0, await ReplicaHarness.CountAsync(_database!, $"SELECT count(*) FROM auth_failure WHERE key_digest = '{plain}'"));
    }
}

/// <summary>Exactly one replica sends each TLS-RPT report, with the counters of all of them.</summary>
[Collection("Runtime")]
public sealed class MultiReplicaTlsReportTests : IAsyncLifetime
{
    private sealed class SettableClock(DateTimeOffset start) : IClock
    {
        private long _ticks = start.UtcTicks;

        public DateTimeOffset UtcNow => new(Interlocked.Read(ref _ticks), TimeSpan.Zero);

        public long Timestamp => Interlocked.Read(ref _ticks);

        public void Set(DateTimeOffset value) => Interlocked.Exchange(ref _ticks, value.UtcTicks);
    }

    private static readonly TlsRptPolicyDescriptor Policy = TlsRptPolicyDescriptor.FromTlsa([]);
    private static readonly string[] Domains = ["one.example", "two.example", "three.example", "four.example", "five.example", "six.example"];

    private readonly SettableClock _clock = new(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
    private TestDatabase? _database;
    private readonly List<EggMailRuntime> _replicas = [];

    public async Task InitializeAsync()
    {
        _database = await PostgresTestServer.Instance.CreateDatabaseAsync();
        var dns = new StaticDnsResolver();
        foreach (string domain in Domains)
        {
            dns.AddTxt("_smtp._tls." + domain, "v=TLSRPTv1; rua=mailto:tlsrpt@" + domain);
        }

        var config = ReplicaHarness.ConfigFor(ReplicaHarness.StorageFor(_database));
        for (int i = 0; i < 3; i++)
        {
            var runtime = await ReplicaHarness.StartAsync(config, _clock, NullMtaLog.Instance, dns);
            _replicas.Add(runtime);
        }
    }

    public async Task DisposeAsync()
    {
        foreach (var replica in _replicas)
        {
            await ReplicaHarness.StopAsync(replica);
        }

        if (_database is not null)
        {
            await _database.DisposeAsync();
        }
    }

    [PostgresFact]
    public async Task Three_replicas_that_all_saw_sessions_send_one_report_per_domain_with_everyones_counts()
    {
        // Every replica delivered to every domain during the day: 1 + 2 + 3 successful sessions, and replica 0 and 2 also one failure each.
        for (int r = 0; r < _replicas.Count; r++)
        {
            foreach (string domain in Domains)
            {
                for (int i = 0; i <= r; i++)
                {
                    _replicas[r].TlsCollector!.RecordSuccess(domain, Policy, "mx." + domain);
                }

                if (r != 1)
                {
                    _replicas[r].TlsCollector!.RecordFailure(domain, Policy, "mx." + domain, TlsResultType.CertificateExpired);
                }
            }

            await _replicas[r].TlsJournal!.FlushAsync(default);
        }

        _clock.Set(new DateTimeOffset(2026, 10, 12, 1, 0, 0, TimeSpan.Zero));

        // All replicas run their hourly report job at the same moment.
        int[] sent = await Task.WhenAll(_replicas.Select(r => Task.Run(() => r.TlsReports!.RunOnceAsync(default))));
        Assert.Equal(Domains.Length, sent.Sum());

        // The next round (the next hour) finds nothing left to send on any of them.
        int[] again = await Task.WhenAll(_replicas.Select(r => Task.Run(() => r.TlsReports!.RunOnceAsync(default))));
        Assert.Equal(0, again.Sum());

        var storage = _replicas[0].Storage;
        var claimed = await storage.Deliveries.ClaimAsync("test", 100, _clock.UtcNow.AddSeconds(1), TimeSpan.FromMinutes(1), default);
        Assert.Equal(Domains.Length, claimed.Count);
        Assert.Equal(Domains.Order(), claimed.Select(c => c.Recipient.ToString()["tlsrpt@".Length..]).Order());
        foreach (var delivery in claimed)
        {
            var message = Mta.Mime.MimeMessage.Parse((await storage.Deliveries.GetRawAsync(delivery.MessageId, default))!);
            var attachment = message.EnumerateParts().Single(p => p.FileName is not null);
            string json = Encoding.UTF8.GetString(TlsRptReportBuilder.Decompress(attachment.GetDecodedBytes()));
            Assert.Contains("\"total-successful-session-count\":6", json);   // 1 + 2 + 3
            Assert.Contains("\"total-failure-session-count\":2", json);
        }

        Assert.Empty(await storage.Config.GetTlsRptBucketsAsync(int.MaxValue, 100, default));
    }
}

/// <summary>
/// The delivery promise with two replicas working one queue under a randomized, unreliable remote: every recipient reaches exactly one final state, nothing is lost, and nothing
/// reaches the remote twice unless it is flagged <c>possible_duplicate</c>. Some answers are slow enough for a claim to run out (a one-second claim), so takeovers happen too; that they
/// do is proven deterministically by <see cref="MultiReplicaTakeoverTests"/>, here they are one more thing the invariants must survive.
/// </summary>
[Collection("Runtime")]
public sealed class MultiReplicaChaosTests : IAsyncLifetime
{
    private readonly CancellationTokenSource _stop = new();
    private readonly RecordingLog _log = new();
    private readonly List<EggMailRuntime> _replicas = [];
    private readonly List<Task> _engines = [];
    private TestDatabase? _database;
    private ChaosInternet _internet = null!;
    private SmtpServer _remote = null!;
    private FlakyProxy _proxy = null!;
    private int _seed;

    public async Task InitializeAsync()
    {
        _seed = int.TryParse(Environment.GetEnvironmentVariable("EGGMAIL_CHAOS_SEED"), out int s) ? s : Environment.TickCount;
        _internet = new ChaosInternet(_seed, _log)
        {
            IsSlow = subject => subject.StartsWith("chaos-", StringComparison.Ordinal) && int.Parse(subject["chaos-".Length..]) % 6 == 0,
            SlowDelay = TimeSpan.FromSeconds(4),
        };
        _remote = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "mx.chaos.example",
            Listeners = [new SmtpListenerOptions { Name = "mx", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce }],
        }, _internet);
        _remote.Start();
        _proxy = new FlakyProxy(_remote.LocalEndPoints["mx"].Port, 0.04, _seed + 2);

        var dns = new StaticDnsResolver();
        foreach (string domain in new[] { "dest1.example", "dest2.example", "dest3.example", "example.org" })
        {
            dns.AddMx(domain, 10, "mx." + domain).AddA("mx." + domain, "127.0.0.1");
        }

        _database = await PostgresTestServer.Instance.CreateDatabaseAsync();
        // A claim of one second against a remote that takes four seconds to answer some messages: the claim runs out while the sender still waits.
        var config = ReplicaHarness.ConfigFor(ReplicaHarness.StorageFor(_database), _proxy.Port, claimLease: TimeSpan.FromSeconds(1));
        for (int i = 0; i < 2; i++)
        {
            var runtime = await ReplicaHarness.StartAsync(config, SystemClock.Instance, _log, dns);
            runtime.SmtpServer.Start();
            _replicas.Add(runtime);
        }

        await ReplicaHarness.SeedAsync(_replicas[0].Storage, "example.org");
        foreach (var runtime in _replicas)
        {
            _engines.Add(Task.Run(() => runtime.Delivery.RunAsync(_stop.Token)));
            _engines.Add(Task.Run(() => runtime.ReplicaCoordinator!.RunAsync(_stop.Token)));   // the replicas beat and share their limits while they work
        }
    }

    public async Task DisposeAsync()
    {
        await _stop.CancelAsync();
        foreach (var engine in _engines)
        {
            try { await engine; } catch (OperationCanceledException) { }
        }

        foreach (var runtime in _replicas)
        {
            await ReplicaHarness.StopAsync(runtime);
        }

        await _proxy.DisposeAsync();
        await _remote.DisposeAsync();
        if (_database is not null)
        {
            await _database.DisposeAsync();
        }
    }

    [PostgresFact]
    public async Task Two_replicas_on_one_queue_deliver_every_recipient_once_and_flag_what_may_have_been_sent_twice()
    {
        int messages = int.TryParse(Environment.GetEnvironmentVariable("EGGMAIL_CHAOS_MESSAGES"), out int m) ? Math.Min(m, 90) : 90;
        var rng = new Random(_seed + 1);
        var plan = new List<(string Subject, string[] Recipients)>();
        for (int i = 0; i < messages; i++)
        {
            int count = rng.Next(1, 4);
            var recipients = new HashSet<string>();
            while (recipients.Count < count)
            {
                string domain = $"dest{rng.Next(1, 4)}.example";
                string local = rng.NextDouble() < 0.08 ? $"gone{rng.Next(1000)}" : $"user{rng.Next(1000)}";
                recipients.Add($"{local}@{domain}");
            }

            plan.Add(($"chaos-{i}", recipients.ToArray()));
        }

        // Submit over SMTP, alternately to the two replicas, from several connections at once.
        var queue = new ConcurrentQueue<(string Subject, string[] Recipients)>(plan);
        var senders = Enumerable.Range(0, 8).Select(n => Task.Run(async () =>
        {
            using var client = new SmtpClient { CheckCertificateRevocation = false, ServerCertificateValidationCallback = (_, _, _, _) => true };
            await client.ConnectAsync("127.0.0.1", ReplicaHarness.SubmissionPort(_replicas[n % 2]), SecureSocketOptions.StartTls);
            await client.AuthenticateAsync("acme-user", "s3cret");
            while (queue.TryDequeue(out var item))
            {
                var msg = new MimeKit.MimeMessage();
                msg.From.Add(MailboxAddress.Parse("news@example.org"));
                foreach (string r in item.Recipients)
                {
                    msg.To.Add(MailboxAddress.Parse(r));
                }

                msg.Subject = item.Subject;
                msg.Body = new TextPart("plain") { Text = "chaos body\r\n" };
                await client.SendAsync(msg);
            }

            await client.DisconnectAsync(true);
        })).ToArray();
        try
        {
            await Task.WhenAll(senders);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"submission failed (seed {_seed}): {ex.Message}\n" + string.Join('\n', _log.Lines.Where(l => l.Contains(" Error ") || l.Contains(" Warning ")).Take(20)), ex);
        }

        // Wait for the queue (including the bounce messages it generates) to drain.
        var deadline = DateTime.UtcNow.AddSeconds(120);
        QueueStats stats;
        int stable = 0;
        do
        {
            await Task.Delay(100);
            stats = await _replicas[0].Storage.Deliveries.GetQueueStatsAsync(default);
            stable = stats is { Queued: 0, Leased: 0, Deferred: 0 } ? stable + 1 : 0;
            Assert.True(DateTime.UtcNow < deadline, $"queue did not drain (seed {_seed}): {stats}\n" + string.Join('\n', _log.Lines.TakeLast(25)));
        }
        while (stable < 10);

        string context = $" (seed {_seed})";
        await ChaosInvariants.AssertAsync(_replicas[0].Storage, ReplicaHarness.TenantId, plan, _internet, context);
    }
}

/// <summary>
/// A replica whose claim runs out while it is still waiting for the remote's answer: the other replica takes the delivery over, both send, and whichever reports first, the
/// delivery is reported as a possible duplicate. Deterministic: the remote holds both conversations open until both have arrived.
/// </summary>
[Collection("Runtime")]
public sealed class MultiReplicaTakeoverTests : IAsyncLifetime
{
    /// <summary>A remote that answers only when told to, and counts the messages that reached it.</summary>
    private sealed class HoldingRemote : ISmtpServerHandler
    {
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _arrived;

        public int Arrived => Volatile.Read(ref _arrived);

        public void Release() => _release.TrySetResult();

        public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken ct) => ValueTask.FromResult<SmtpReply?>(null);

        public ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct) => ValueTask.FromResult(SmtpAuthResult.Failed);

        public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.SenderOk);

        public ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters p, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.RecipientOk);

        public async ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
        {
            Interlocked.Increment(ref _arrived);
            await _release.Task.WaitAsync(ct);
            return SmtpReply.Create(250, "2.0.0", "Accepted");
        }

        public void OnDisconnected(SmtpSessionContext session)
        {
        }
    }

    private readonly CancellationTokenSource _stop = new();
    private readonly HoldingRemote _remote = new();
    private readonly List<EggMailRuntime> _replicas = [];
    private readonly List<Task> _running = [];
    private SmtpServer _server = null!;
    private TestDatabase? _database;

    public async Task InitializeAsync()
    {
        _server = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "mx.hold.example",
            Listeners = [new SmtpListenerOptions { Name = "mx", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce }],
        }, _remote);
        _server.Start();
        var dns = new StaticDnsResolver();
        foreach (string domain in new[] { "dest.example", "example.org" })
        {
            dns.AddMx(domain, 10, "mx." + domain).AddA("mx." + domain, "127.0.0.1");
        }

        _database = await PostgresTestServer.Instance.CreateDatabaseAsync();
        var config = ReplicaHarness.ConfigFor(ReplicaHarness.StorageFor(_database), _server.LocalEndPoints["mx"].Port, claimLease: TimeSpan.FromSeconds(1));
        for (int i = 0; i < 2; i++)
        {
            var runtime = await ReplicaHarness.StartAsync(config, SystemClock.Instance, NullMtaLog.Instance, dns);
            runtime.SmtpServer.Start();
            _replicas.Add(runtime);
        }

        await ReplicaHarness.SeedAsync(_replicas[0].Storage, "example.org");
    }

    public async Task DisposeAsync()
    {
        _remote.Release();
        await _stop.CancelAsync();
        foreach (var task in _running)
        {
            try { await task; } catch (OperationCanceledException) { }
        }

        foreach (var runtime in _replicas)
        {
            await ReplicaHarness.StopAsync(runtime);
        }

        await _server.DisposeAsync();
        if (_database is not null)
        {
            await _database.DisposeAsync();
        }
    }

    [PostgresFact]
    public async Task A_claim_that_runs_out_during_the_send_makes_the_other_replica_send_too_and_the_delivery_is_flagged()
    {
        using (var client = new SmtpClient { CheckCertificateRevocation = false, ServerCertificateValidationCallback = (_, _, _, _) => true })
        {
            await client.ConnectAsync("127.0.0.1", ReplicaHarness.SubmissionPort(_replicas[0]), SecureSocketOptions.StartTls);
            await client.AuthenticateAsync("acme-user", "s3cret");
            var msg = new MimeKit.MimeMessage();
            msg.From.Add(MailboxAddress.Parse("news@example.org"));
            msg.To.Add(MailboxAddress.Parse("user@dest.example"));
            msg.Subject = "takeover";
            msg.Body = new TextPart("plain") { Text = "body\r\n" };
            await client.SendAsync(msg);
        }

        foreach (var runtime in _replicas)
        {
            _running.Add(Task.Run(() => runtime.Delivery.RunAsync(_stop.Token)));
        }

        // One replica claims the delivery and waits for the remote; its one-second claim runs out; a replica claims it again and sends too. Wait for the event, not for time.
        var deadline = DateTime.UtcNow.AddSeconds(60);
        while (_remote.Arrived < 2)
        {
            Assert.True(DateTime.UtcNow < deadline, "the delivery was never taken over");
            await Task.Delay(50);
        }

        _remote.Release();
        QueueStats stats;
        do
        {
            Assert.True(DateTime.UtcNow < deadline, "the queue did not drain");
            await Task.Delay(50);
            stats = await _replicas[0].Storage.Deliveries.GetQueueStatsAsync(default);
        }
        while (stats is not { Queued: 0, Leased: 0, Deferred: 0 });

        Assert.Equal(2, _remote.Arrived);
        var summary = Assert.Single((await _replicas[0].Storage.History.SearchAsync(new MessageQuery(ReplicaHarness.TenantId, Limit: 10), default)).Items, s => s.Subject == "takeover");
        var events = await _replicas[0].Storage.History.GetEventsAsync(ReplicaHarness.TenantId, summary.MessageId, default);
        Assert.Single(events, e => e.Type == MessageEventType.Delivered);
        Assert.Contains(events, e => e.Type == MessageEventType.PossibleDuplicate);
    }
}
