using System.Net;
using System.Security.Cryptography;
using System.Text;
using Mta.Core;
using Mta.Delivery;
using Mta.Dkim;
using Mta.Dns;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Security;
using Mta.Observability;
using Mta.Smtp.Client;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.Postgres;
using Mta.Storage.Postgres.Tests;
using Mta.Storage.Sqlite;
using Mta.TestSupport;
using Mta.Webhooks;
using Xunit.Abstractions;

namespace Mta.Host.Tests.Leaks;

/// <summary>
/// Accelerated lifecycle, leaks: the real runtime (SMTP submission with STARTTLS and AUTH, delivery engine, DKIM signing, STARTTLS to the
/// remote MX, recording, statistics, signed webhook delivery to an HTTP receiver) over a real storage, with the whole path repeated: submission
/// session, delivery, history, webhook. One iteration is one authenticated session that submits a few messages and waits until every one is
/// delivered and its webhook received. Also the configuration refresh of the engine. The real clock is used (the path crosses sockets); only the
/// loop count is accelerated, <c>EGGMAIL_ACCEL_SCALE</c> multiplies it.
/// </summary>
[Collection(LeakCollection.Name)]
public sealed class RuntimeLeakTests(ITestOutputHelper output)
{
    private const int MessagesPerSession = 5;
    private const int ConcurrentSessions = 4;

    /// <summary>Rounds per batch: 4 sessions x 5 messages x 5 rounds = 80 messages a batch, 400 in all with the two warm-up batches; EGGMAIL_ACCEL_SCALE=25 makes it 10,000 in all.</summary>
    private static int RoundsPerBatch => Accelerated.Scaled(4);

    [Fact]
    public async Task Leak_submit_deliver_record_and_webhook_on_the_sqlite_runtime_does_not_grow()
    {
        await using var harness = await RuntimeLeakHarness.StartAsync(backend: null);
        await RunSubmissionLeakCheck(harness);
    }

    [PostgresFact]
    public async Task Leak_submit_deliver_record_and_webhook_on_the_postgres_runtime_does_not_grow()
    {
        await using TestDatabase db = await PostgresTestServer.Instance.CreateDatabaseAsync();
        await using var harness = await RuntimeLeakHarness.StartAsync(db.ConnectionString);
        await RunSubmissionLeakCheck(harness);
    }

    [Fact]
    public async Task Leak_delivery_engine_configuration_refreshes_do_not_grow()
    {
        await using var harness = await RuntimeLeakHarness.StartAsync(backend: null);
        DeliveryEngine engine = harness.Runtime.Delivery;

        using var probe = new LeakProbe(output.WriteLine);
        probe.TrackArrayPoolBalance(ignoreRentalsFrom: ["Microsoft.EntityFrameworkCore"]);
        LeakReport report = await probe.RunAsync(async _ =>
        {
            long before = engine.ConfigRefreshCount;
            engine.RequestConfigRefresh();
            await RuntimeLeakHarness.WaitUntilAsync(() => engine.ConfigRefreshCount > before);
        }, Accelerated.Scaled(100));
        report.AssertNoGrowth();
    }

    [Fact]
    public async Task Leak_runtime_state_write_behind_flushes_do_not_grow()
    {
        // The sending counters and TLS-RPT counters the runtime keeps in memory are written behind to the database every few seconds; a flush per iteration, with traffic to count.
        await using var harness = await RuntimeLeakHarness.StartAsync(backend: null);
        EggMailRuntime runtime = harness.Runtime;
        Guid tenant = Guid.Parse("a0000000-0000-7000-8000-000000000001");

        using var probe = new LeakProbe(output.WriteLine);
        probe.TrackArrayPoolBalance(ignoreRentalsFrom: ["Microsoft.EntityFrameworkCore"]);
        probe.Track("prepared SQLite statements", () => PreparedCommand.LiveCount, absolute: 2);
        probe.Allow("threads", 12);
        LeakReport report = await probe.RunAsync(async _ =>
        {
            runtime.Limits.TryReserve(tenant, "example.org");
            await runtime.FlushRuntimeStateAsync(default);
        }, Accelerated.Scaled(100));
        report.AssertNoGrowth();
    }

    private async Task RunSubmissionLeakCheck(RuntimeLeakHarness harness)
    {
        SmtpClientOptions options = new()
        {
            HeloName = "client.test",
            BannerTimeout = TimeSpan.FromSeconds(60),
            CommandTimeout = TimeSpan.FromSeconds(60),
            EndOfDataTimeout = TimeSpan.FromSeconds(60),
            DataBlockTimeout = TimeSpan.FromSeconds(60),
            DataInitiationTimeout = TimeSpan.FromSeconds(60),
        };
        var target = new SmtpRemoteTarget
        {
            Host = "localhost",
            Address = IPAddress.Loopback,
            Port = harness.SubmissionPort,
            Tls = new SmtpTlsPolicy { Mode = SmtpTlsMode.StartTls, Require = true, TargetHost = "localhost", ValidationCallback = (_, _, _, _) => true },
            Credentials = new SmtpCredentials { UserName = RuntimeLeakHarness.User, Password = RuntimeLeakHarness.Password },
        };
        byte[] message = Encoding.UTF8.GetBytes("From: Acme <news@example.org>\r\nTo: rcpt@dest.example\r\nSubject: Leak check\r\nMessage-ID: <leak@example.org>\r\nDate: Mon, 12 Oct 2026 12:30:00 +0000\r\n\r\nHello from EggMail\r\n");

        using var probe = new LeakProbe(output.WriteLine);
        probe.TrackArrayPoolBalance(ignoreRentalsFrom: ["Microsoft.EntityFrameworkCore"]);
        probe.WarmupBatches = 2;
        probe.Allow("open file descriptors", 4);
        probe.Allow("threads", 12);   // thread-pool threads come and go with the load
        probe.Allow("timers", 6);   // sockets of the outbound pool and of the PostgreSQL pool come and go
        probe.Track("open submission sessions", () => harness.Runtime.SmtpServer.ActiveConnections, absolute: 2);
        probe.Track("delivery groups in flight", () => harness.Runtime.Delivery.PendingGroups, absolute: 2);
        probe.Track("idle pooled outbound connections", () => harness.Runtime.Pool.IdleConnections, absolute: 2);
        if (harness.Sqlite)
        {
            probe.Track("prepared SQLite statements", () => PreparedCommand.LiveCount, absolute: 2);   // a statement is prepared on first use, and a rare one (maintenance) may first run late

            // Native SQLite memory is not judged by growth here: the page caches of the four files (16 MiB for each writer) fill while the database grows, which is bounded
            // growth. It is judged by the bound below. The storage test, where retention keeps the files at one size, judges it by growth.
        }

        // Every Mta.* meter, with the series the process has recorded so far: a label that took a message id, an address or a domain would multiply the series per batch.
        using var exporter = new PrometheusTextExporter();
        long Series() => exporter.Render().Split('\n').Count(l => l.Length > 0 && l[0] != '#');
        probe.Track("series in the Prometheus text", Series);
        probe.Track("tracked destinations (throttle)", () => harness.Runtime.DestinationThrottle.TrackedKeyCount, absolute: 0);
        probe.Track("tracked MX hosts and routes (circuit breakers)", () => harness.Runtime.Health.TrackedCount, absolute: 0);
        long droppedBefore = PrometheusTextExporter.DroppedSeries;

        long sent = 0;
        int session = 0;
        LeakReport report = await probe.RunAsync(async _ =>
        {
            await Task.WhenAll(Enumerable.Range(0, ConcurrentSessions).Select(async _ =>
            {
                // Recipients spread over 25 destination domains, all answered by the one remote MX.
                var envelope = new SmtpEnvelope(EmailAddress.Parse("news@example.org"), [EmailAddress.Parse($"rcpt@d{Interlocked.Increment(ref session) % RuntimeLeakHarness.DestinationDomains}.dest.example")], false, false);
                await using SmtpClientConnection connection = await SmtpClientConnection.ConnectAsync(target, options);
                for (int i = 0; i < MessagesPerSession; i++)
                {
                    SmtpSendResult result = await connection.SendAsync(envelope, message);
                    Assert.True(result.Delivered, result.FinalReply?.ToString());
                }

                await connection.QuitAsync();
            }));

            sent += ConcurrentSessions * MessagesPerSession;
            long expected = sent;
            await RuntimeLeakHarness.WaitUntilAsync(() => harness.Remote.Messages >= expected && harness.WebhookDeliveries >= expected);
        }, RoundsPerBatch);
        report.AssertNoGrowth();
        Assert.Equal(sent, harness.Remote.Messages);
        Assert.Equal(droppedBefore, PrometheusTextExporter.DroppedSeries);   // no metric hit its series ceiling, i.e. no label is unbounded
        if (harness.Sqlite)
        {
            // Four files with a 16 MiB writer cache each, a few 2 MiB reader caches, statements and the rest: far below this, and a leak per message would pass it quickly at a higher scale.
            Assert.InRange(SQLitePCL.raw.sqlite3_memory_used(), 0, 160L * 1024 * 1024);
        }
    }
}

/// <summary>A runtime over SQLite files or a PostgreSQL database, a remote MX that counts what it receives, and a webhook receiver on loopback.</summary>
internal sealed class RuntimeLeakHarness : IAsyncDisposable
{
    public const string User = "acme-user";
    public const string Password = "s3cret";
    public const int DestinationDomains = 25;
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    private readonly string? _directory;
    private readonly CancellationTokenSource _stop = new();
    private readonly HttpListener _hook = new();
    private readonly SmtpServer _remote;
    private readonly RSA _dkimKey = DkimKeyTools.GenerateRsa2048();
    private Task _engine = Task.CompletedTask;
    private Task _dispatcher = Task.CompletedTask;
    private Task _receiver = Task.CompletedTask;
    private long _webhooks;

    private RuntimeLeakHarness(string? directory)
    {
        _directory = directory;
        Remote = new MessageCounter();
        _remote = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "mx.dest.example",
            MaxConnectionsPerIp = 10_000,
            Listeners = [new SmtpListenerOptions { Name = "mx", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce }],
        }, Remote);
    }

    public bool Sqlite => _directory is not null;

    public EggMailRuntime Runtime { get; private set; } = null!;

    public MessageCounter Remote { get; }

    public int SubmissionPort { get; private set; }

    public long WebhookDeliveries => Interlocked.Read(ref _webhooks);

    public static async Task<RuntimeLeakHarness> StartAsync(string? backend)
    {
        var harness = new RuntimeLeakHarness(backend is null ? Directory.CreateTempSubdirectory("eggmail-leak-runtime-").FullName : null);
        await harness.InitializeAsync(backend);
        return harness;
    }

    private async Task InitializeAsync(string? postgresConnectionString)
    {
        _remote.Start();
        int remotePort = _remote.LocalEndPoints["mx"].Port;
        var dns = new StaticDnsResolver();
        foreach (string domain in new[] { "dest.example", "example.org" })
        {
            dns.AddMx(domain, 10, "mx." + domain).AddA("mx." + domain, "127.0.0.1");
        }

        for (int d = 0; d < DestinationDomains; d++)
        {
            dns.AddMx($"d{d}.dest.example", 10, "mx.dest.example");
        }

        StorageOptions storageOptions = _directory is not null
            ? new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _directory } }
            : new StorageOptions { Backend = StorageBackend.Postgres, Postgres = new PostgresOptions { RuntimeConnectionString = postgresConnectionString, MaxPoolSize = 12, RetentionDeletePause = TimeSpan.FromMilliseconds(1) } };
        var config = new MtaConfig
        {
            Hostname = "egg.test",
            Storage = storageOptions,
            Smtp = new SmtpSection
            {
                Listeners = new Dictionary<string, ListenerSection>
                {
                    ["submission"] = new() { Port = 0, BindAddress = "127.0.0.1", Mode = ListenerMode.StartTls, AuthRequired = true },
                },
            },
            Webhooks = new WebhookOptions { AllowHttp = true, PollInterval = TimeSpan.FromMilliseconds(20) },
            Delivery = new DeliverySection
            {
                BounceDomain = "bounces.egg.test",
                RemotePort = remotePort,
                AllowPrivateMxAddresses = true,
                PollInterval = TimeSpan.FromMilliseconds(20),
                // The per-destination ceilings are a policy for the public internet (2 messages a second at first); this test sends to one domain as fast as it can.
                Throttle = new ThrottleSection { MaxConnections = 20, InitialConnections = 20, MaxMessagesPerMinute = 6_000_000, InitialMessagesPerMinute = 6_000_000 },
            },
        };
        IStorage storage = _directory is not null ? SqliteStorage.Create(storageOptions) : PostgresStorage.Create(storageOptions);
        await storage.InitializeAsync(default);
        Runtime = await EggMailRuntime.CreateAsync(config, storage, SystemClock.Instance, NullMtaLog.Instance, default, dns);

        DateTimeOffset now = DateTimeOffset.UtcNow;
        Guid domainId = Ids.New();
        await storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, now, false), default);
        await storage.Config.UpsertDomainAsync(new DomainRecord(domainId, TenantId, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        await storage.Config.AddDkimKeyAsync(new Mta.Storage.DkimKeyRecord(
            Ids.New(), domainId, "egg1", Runtime.Secrets.Protect(_dkimKey.ExportPkcs8PrivateKey(), SecretPurposes.DkimKey), DkimKeyTools.ExportPublicKeyBase64(_dkimKey), now, true, null), default);
        await storage.Config.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), TenantId, User, PasswordHasher.Hash(Password, 2000), true, now), default);

        // The webhook receiver: any free loopback port; answers 200 and counts.
        int port;
        while (true)
        {
            port = Random.Shared.Next(20000, 40000);
            _hook.Prefixes.Clear();
            _hook.Prefixes.Add($"http://127.0.0.1:{port}/hook/");
            try
            {
                _hook.Start();
                break;
            }
            catch (HttpListenerException)
            {
            }
        }

        _receiver = Task.Run(ReceiveAsync);
        string secret = StandardWebhooksSigner.GenerateSecret();
        await storage.Config.UpsertWebhookEndpointAsync(new WebhookEndpointRecord(
            Ids.New(), TenantId, $"http://127.0.0.1:{port}/hook/", Runtime.Secrets.Protect(Encoding.UTF8.GetBytes(secret), SecretPurposes.WebhookSecret),
            [WebhookEventFactory.Delivered], true, null, null, now, null), default);
        Runtime.Webhooks.AllowlistProvider = _ => [IpNetwork.Parse("127.0.0.0/8")];

        Runtime.SmtpServer.Start();
        SubmissionPort = Runtime.SmtpServer.LocalEndPoints["submission"].Port;
        _engine = Task.Run(() => Runtime.Delivery.RunAsync(_stop.Token));
        _dispatcher = Task.Run(() => Runtime.Webhooks.RunAsync(_stop.Token));
    }

    private async Task ReceiveAsync()
    {
        try
        {
            while (true)
            {
                HttpListenerContext context = await _hook.GetContextAsync();
                using var sink = new MemoryStream();
                await context.Request.InputStream.CopyToAsync(sink);
                context.Response.StatusCode = 200;
                context.Response.Close();
                Interlocked.Increment(ref _webhooks);
            }
        }
        catch (Exception ex) when (ex is HttpListenerException or ObjectDisposedException or InvalidOperationException)
        {
        }
    }

    /// <summary>Polls a condition with a deadline far above any plausible load (a signal wait, not a timing assertion).</summary>
    public static async Task WaitUntilAsync(Func<bool> condition)
    {
        DateTime until = DateTime.UtcNow.AddSeconds(120);
        while (!condition())
        {
            if (DateTime.UtcNow > until)
            {
                throw new TimeoutException("The condition did not become true within 120 s.");
            }

            await Task.Delay(2);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        try
        {
            await Task.WhenAll(_engine, _dispatcher);
        }
        catch (OperationCanceledException)
        {
        }

        _hook.Close();
        await _receiver;
        await Runtime.SmtpServer.StopAsync(TimeSpan.FromSeconds(2));
        await _remote.DisposeAsync();
        await Runtime.DisposeAsync();
        await Runtime.Storage.DisposeAsync();
        _dkimKey.Dispose();
        _stop.Dispose();
        if (_directory is not null)
        {
            try
            {
                // The directory was created by this harness (a unique name under the temp folder) and holds only its own files.
                Directory.Delete(_directory, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }

    /// <summary>The remote MX: accepts every message and counts it, keeps nothing.</summary>
    internal sealed class MessageCounter : ISmtpServerHandler
    {
        private long _messages;

        public long Messages => Interlocked.Read(ref _messages);

        public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken ct) => ValueTask.FromResult<SmtpReply?>(null);

        public ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct) =>
            ValueTask.FromResult(SmtpAuthResult.Failed);

        public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.SenderOk);

        public ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters p, CancellationToken ct) =>
            ValueTask.FromResult(SmtpReplies.RecipientOk);

        public ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
        {
            Interlocked.Increment(ref _messages);
            return ValueTask.FromResult(SmtpReply.Create(250, "2.0.0", "Accepted"));
        }

        public void OnDisconnected(SmtpSessionContext session)
        {
        }
    }
}
