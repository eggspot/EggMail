using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Mta.Core;
using Mta.Delivery;
using Mta.Dns;
using Mta.Dsn;
using Mta.Policy;
using Mta.Smtp.Client;
using Mta.Storage;
using Mta.Storage.InMemory;
using Mta.Tls;
using Mta.Tls.Dane;
using Mta.Tls.MtaSts;
using Mta.Tls.TlsRpt;

namespace Mta.RemoteMta.Tests.Harness;

/// <summary>What a lab is built with. Everything has a default that makes the delivery engine behave as configured in production, except the timing tweaks that keep hang tests short.</summary>
public sealed record LabSettings
{
    /// <summary>The TLS level for every destination (the per-domain table can still override it).</summary>
    public TlsSecurityLevel TlsLevel { get; init; } = TlsSecurityLevel.May;

    /// <summary>Wire the MTA-STS policy store (DNS TXT plus HTTPS fetch from <see cref="MtaLab.StsWeb"/>).</summary>
    public bool MtaSts { get; init; }

    /// <summary>Wire DANE (TLSA lookups through <see cref="MtaLab.Dns"/>).</summary>
    public bool Dane { get; init; }

    public bool RequireDane { get; init; }

    public RetryScheduleOptions? Retry { get; init; }

    /// <summary>Jitter off by default so a retry time is exactly the scheduled delay; pass a different source to test the spread.</summary>
    public IRandomSource? RetryRandom { get; init; }

    public DestinationThrottleOptions? Throttle { get; init; }

    public SmtpClientOptions? Client { get; init; }

    public TimeSpan? PoolIdleTimeout { get; init; }

    public MxAddressPreference AddressPreference { get; init; } = MxAddressPreference.Ipv4First;

    /// <summary>Seed of the shuffle among equal-preference MX hosts.</summary>
    public int MxSeed { get; init; } = 7;

    public int MaxMxHostsPerAttempt { get; init; } = 5;

    public int MaxAddressesPerHost { get; init; } = 2;

    public int MaxRecipientsPerTransaction { get; init; } = 100;

    public bool StartEngine { get; init; } = true;

    public string? BounceDomain { get; init; }

    public bool ReportNonPublicSendingIp { get; init; } = true;

    public TimeSpan MtaStsLookupTimeout { get; init; } = TimeSpan.FromSeconds(20);

    public TimeSpan MtaStsFetchTimeout { get; init; } = TimeSpan.FromSeconds(10);
}

/// <summary>A source of fixed "random" numbers: jitter 0.5 means a factor of exactly 1.</summary>
public sealed class FixedRandom(double value = 0.5) : IRandomSource
{
    public double NextDouble() => value;
}

/// <summary>
/// The whole outbound pipeline over in-memory storage, a fake clock, fake DNS zones and any number of loopback fake MTAs: the real delivery engine,
/// processor, SMTP client, connection pool, TLS policy resolver (MTA-STS and DANE), retry schedule, throttle and DSN service. Nothing in the engine is replaced
/// except the outside world: DNS, the peers, the web server of MTA-STS and time.
/// </summary>
public sealed class MtaLab : IAsyncDisposable
{
    public static readonly Guid Tenant = Guid.Parse("a0000000-0000-7000-8000-0000000000aa");

    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<string, int> _ports = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FakeMta> _mtas = [];
    private readonly Dictionary<string, X509Certificate2> _certificates = new(StringComparer.OrdinalIgnoreCase);
    private readonly TcpListener _deadPortHolder = new(IPAddress.Loopback, 0);
    private Task _run = Task.CompletedTask;

    public MtaLab(LabSettings? settings = null)
    {
        Settings = settings ?? new LabSettings();
        _deadPortHolder.Start();
        DeadPort = ((IPEndPoint)_deadPortHolder.LocalEndpoint).Port;
        _deadPortHolder.Stop();   // nothing listens on it from now on: connecting is refused

        Clock = new FakeClock();
        Ca = TestPki.CreateRoot();
        Storage = new InMemoryStorage(new StorageOptions { History = new HistoryOptions { Mode = HistoryMode.Full } }, Clock);
        Storage.InitializeAsync(CancellationToken.None).GetAwaiter().GetResult();
        TlsReports = new TlsRptCollector(Clock);

        var tlsOptions = new OutboundTlsConfiguration { Level = Settings.TlsLevel, RequireDane = Settings.RequireDane };
        MtaStsPolicyStore? sts = null;
        if (Settings.MtaSts)
        {
            StsWeb = new FakeMtaStsWebServer(sni => Cert(sni ?? "mta-sts.unknown.test"));
            var fetcher = new MtaStsPolicyFetcher(StsWeb.CreateHandler(Ca.Public), new MtaStsFetchOptions { Timeout = Settings.MtaStsFetchTimeout });
            StsStore = sts = new MtaStsPolicyStore(Dns, fetcher, new InMemoryMtaStsCache(Clock), Clock, new MtaStsStoreOptions { LookupTimeout = Settings.MtaStsLookupTimeout });
        }

        Options = new DeliveryOptions
        {
            Owner = "lab",
            Hostname = "egg.test",
            IdlePoll = TimeSpan.FromMilliseconds(20),
            ExpirySweepInterval = TimeSpan.FromMilliseconds(100),
            BounceDomain = Settings.BounceDomain,
            RemotePortResolver = host => _ports.TryGetValue(host, out int p) ? p : DeadPort,
            MaxMxHostsPerAttempt = Settings.MaxMxHostsPerAttempt,
            MaxAddressesPerHost = Settings.MaxAddressesPerHost,
            MaxRecipientsPerTransaction = Settings.MaxRecipientsPerTransaction,
            ReportNonPublicSendingIp = Settings.ReportNonPublicSendingIp,
            DefaultTls = tlsOptions,
        };

        RouteHealth = new RouteHealth(Clock);
        Throttle = new DestinationThrottle(Clock, Settings.Throttle);
        Services = new DeliveryServices
        {
            Storage = Storage,
            Clock = Clock,
            Mx = new MxResolver(Dns, new MxResolverOptions { ExcludeSpecialAddresses = false, AddressPreference = Settings.AddressPreference }, new Random(Settings.MxSeed)),
            Tls = new OutboundTlsPolicyResolver(sts, Settings.Dane ? new DaneTlsaLookup(Dns) : null),
            TlsReports = TlsReports,
            TlsPolicies = new TlsPolicyTable(tlsOptions),
            Pool = new SmtpConnectionPool(Settings.Client ?? new SmtpClientOptions { HeloName = "egg.test" }, Clock, idleTimeout: Settings.PoolIdleTimeout),
            Routes = new RoutePlanner(RouteHealth),
            Throttle = Throttle,
            Limits = new SendingLimits(Clock, null, null),
            Retry = new RetrySchedule(Settings.Retry, Settings.RetryRandom ?? new FixedRandom()),
            Log = NullMtaLog.Instance,
            CertificateValidation = new RemoteCertificateValidatorOptions { CustomTrustAnchors = [Ca.Public], Now = () => Clock.UtcNow },
        };
        var processor = new DeliveryProcessor(Services, Options, new DsnService(Storage, Clock, Options));
        Engine = new DeliveryEngine(processor, Services, Options);
        if (Settings.StartEngine)
        {
            StartEngine();
        }
    }

    public LabSettings Settings { get; }

    public FakeClock Clock { get; }

    public FakeDns Dns { get; } = new();

    public IssuedCertificate Ca { get; }

    public InMemoryStorage Storage { get; }

    public TlsRptCollector TlsReports { get; }

    public DeliveryServices Services { get; }

    public DeliveryOptions Options { get; }

    public DeliveryEngine Engine { get; }

    public RouteHealth RouteHealth { get; }

    public DestinationThrottle Throttle { get; }

    public FakeMtaStsWebServer? StsWeb { get; }

    public MtaStsPolicyStore? StsStore { get; }

    /// <summary>A port nothing listens on: connecting to a host registered with it is refused.</summary>
    public int DeadPort { get; }

    public IReadOnlyList<FakeMta> Mtas => _mtas;

    public void StartEngine() => _run = Task.Run(() => Engine.RunAsync(_stop.Token));

    /// <summary>A server certificate for <paramref name="names"/> from the lab's private CA (the engine trusts that CA).</summary>
    public X509Certificate2 Cert(params string[] names)
    {
        string key = string.Join(',', names);
        if (!_certificates.TryGetValue(key, out var cert))
        {
            _certificates[key] = cert = TestPki.Leaf(Ca, names).ForServer();
        }

        return cert;
    }

    /// <summary>
    /// Starts a fake MTA on a loopback port, makes <paramref name="host"/> resolve to <paramref name="address"/> (A or AAAA by its family) and
    /// routes connections for that host name to the port. The listener binds the address' loopback family.
    /// </summary>
    public FakeMta AddMta(string host, MtaPersonality personality, string address = "127.0.0.1")
    {
        var ip = IPAddress.Parse(address);
        var mta = new FakeMta(personality, ip.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Loopback : IPAddress.Loopback);
        _mtas.Add(mta);
        _ports[host] = mta.Port;
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            Dns.Aaaa(host, address);
        }
        else
        {
            Dns.A(host, address);
        }

        return mta;
    }

    /// <summary>Gives <paramref name="host"/> an address record but no listener: connections are refused.</summary>
    public void AddRefusingHost(string host, string address = "127.0.0.1")
    {
        Dns.A(host, address);
        _ports[host] = DeadPort;
    }

    /// <summary>Publishes <c>domain MX preference host</c>.</summary>
    public MtaLab Mx(string domain, ushort preference, string host)
    {
        Dns.Mx(domain, preference, host);
        return this;
    }

    /// <summary>The sending side's own mail server, so that bounce messages sent back to <c>sender@example.org</c> have somewhere to go.</summary>
    public FakeMta AddSenderSide(string domain = "example.org")
    {
        var mta = AddMta("mx." + domain, Personalities.Plain("mx." + domain));
        Dns.Mx(domain, 10, "mx." + domain);
        return mta;
    }

    public async Task<Guid> SendAsync(string[] to, string from = "sender@example.org", string subject = "Hello", string? sendingDomain = "example.org", TimeSpan? lifetime = null, byte[]? raw = null, MessageSource source = MessageSource.Smtp)
    {
        var now = Clock.UtcNow;
        raw ??= Encoding.ASCII.GetBytes($"From: {from}\r\nTo: {string.Join(", ", to)}\r\nSubject: {subject}\r\nMessage-ID: <{Guid.NewGuid():N}@example.org>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n\r\nBody line\r\n");
        var id = Ids.New(now);
        await Storage.Intake.AcceptAsync(new AcceptedMessage
        {
            MessageId = id,
            TenantId = Tenant,
            Source = source,
            EnvelopeFrom = EmailAddress.Parse(from),
            Recipients = to.Select(t => new AcceptedRecipient(Ids.New(now), EmailAddress.Parse(t))).ToList(),
            Raw = raw,
            ReceivedAt = now,
            ExpiresAt = now + (lifetime ?? TimeSpan.FromDays(5)),
            SendingDomain = sendingDomain,
        }, CancellationToken.None);
        Engine.Wake();
        return id;
    }

    /// <summary>Moves the clock and wakes the engine, which then picks up whatever has become due.</summary>
    public void Advance(TimeSpan by)
    {
        Clock.Advance(by);
        Engine.Wake();
    }

    public async Task<IReadOnlyList<MessageEvent>> EventsAsync(Guid messageId) => await Storage.History.GetEventsAsync(Tenant, messageId, CancellationToken.None);

    public async Task<IReadOnlyList<MessageEvent>> WaitForEventAsync(Guid messageId, MessageEventType type, int count = 1)
    {
        IReadOnlyList<MessageEvent> events = [];
        await Wait.UntilAsync(async () =>
        {
            events = await EventsAsync(messageId);
            return events.Count(e => e.Type == type) >= count;
        }, $"{count} {type} event(s) for message {messageId:N}");
        return events;
    }

    /// <summary>Waits until the message has been through <paramref name="attempts"/> deferrals, then returns when the engine will try again (the due time on the fake clock).</summary>
    public async Task<DateTimeOffset> WaitForRetryScheduleAsync(Guid messageId, int deferrals = 1)
    {
        await WaitForEventAsync(messageId, MessageEventType.Deferred, deferrals);
        QueueStats stats = default!;
        await Wait.UntilAsync(async () =>
        {
            stats = await Storage.Deliveries.GetQueueStatsAsync(CancellationToken.None);
            return stats is { Leased: 0, Deferred: > 0 };
        }, "the deferred delivery to be released from its lease");
        return stats.OldestDueAt ?? throw new InvalidOperationException("no due time");
    }

    private FakeMta? _sentinel;
    private int _sentinelCount;

    /// <summary>
    /// Proves that the engine has looked at the queue at the current fake time: a message to an unrelated healthy domain is delivered, which can only
    /// happen in a claim that ran after the last <see cref="Advance"/>. Use it to assert that something did NOT happen yet (a retry before its due time).
    /// </summary>
    public async Task SettleAsync()
    {
        if (_sentinel is null)
        {
            _sentinel = AddMta("mx.sentinel.example", Personalities.Plain("mx.sentinel.example"));
            Dns.Mx("sentinel.example", 10, "mx.sentinel.example");
        }

        int wanted = Interlocked.Increment(ref _sentinelCount);
        await SendAsync(["probe@sentinel.example"], sendingDomain: null);
        await _sentinel.WaitForMessagesAsync(wanted);
    }

    /// <summary>Advances the clock by <paramref name="step"/> again and again until <paramref name="condition"/> holds (the retry schedule, run without waiting).</summary>
    public async Task AdvanceUntilAsync(Func<bool> condition, TimeSpan step, string what, int maxSteps = 100_000)
    {
        for (int i = 0; !condition(); i++)
        {
            if (i >= maxSteps)
            {
                throw new TimeoutException("gave up waiting for " + what + " after " + (step * i));
            }

            Advance(step);
            await Task.Delay(5);
        }
    }

    public async Task<QueueStats> QueueAsync() => await Storage.Deliveries.GetQueueStatsAsync(CancellationToken.None);

    /// <summary>Waits until nothing is queued, leased or deferred any more.</summary>
    public Task WaitForIdleAsync() => Wait.UntilAsync(async () => await QueueAsync() is { Queued: 0, Leased: 0, Deferred: 0 }, "the queue to drain");

    /// <summary>The TLS-RPT aggregates collected so far for <paramref name="policyDomain"/>.</summary>
    public IReadOnlyList<TlsRptPolicyAggregate> TlsRptFor(string policyDomain) =>
        TlsReports.Snapshot().Where(d => string.Equals(d.PolicyDomain, policyDomain, StringComparison.OrdinalIgnoreCase)).SelectMany(d => d.Policies).ToArray();

    /// <summary>Subscribes a webhook endpoint of the lab tenant to <paramref name="eventTypes"/>.</summary>
    public async Task SubscribeWebhookAsync(params string[] eventTypes) =>
        await Storage.Config.UpsertWebhookEndpointAsync(new WebhookEndpointRecord(Guid.NewGuid(), Tenant, "https://hooks.example.com/x", [1], eventTypes, true, null, null, Clock.UtcNow, null), default);

    /// <summary>The JSON payloads queued for the webhook endpoints, oldest first.</summary>
    public async Task<IReadOnlyList<string>> WebhookPayloadsAsync()
    {
        var items = await Storage.Webhooks.ClaimDueAsync("reader", 1000, Clock.UtcNow.AddYears(1), TimeSpan.FromMinutes(1), default);
        return items.OrderBy(i => i.CreatedAt).Select(i => i.PayloadJson).ToArray();
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        try
        {
            await _run;
        }
        catch (OperationCanceledException)
        {
        }

        await Services.Pool.DisposeAsync();
        foreach (var mta in _mtas)
        {
            await mta.DisposeAsync();
        }

        if (StsWeb is not null)
        {
            await StsWeb.DisposeAsync();
        }

        await Storage.DisposeAsync();
    }
}
