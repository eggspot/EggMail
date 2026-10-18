using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mta.Core;
using Mta.Dkim;
using Mta.Dns;
using Mta.Dsn;
using Mta.Host.Hosting;
using Mta.Host.Ingest;
using Mta.Host.Security;
using Mta.Host.Submission;
using Mta.Policy;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests.Inbound;

/// <summary>A clock a test moves by hand: the rate-limit windows are decided by it, so no test depends on which second of the minute it runs in.</summary>
internal sealed class ManualClock : IClock
{
    private long _ticks;

    public ManualClock(DateTimeOffset start) => Now = start;

    public DateTimeOffset Now { get; private set; }

    public DateTimeOffset UtcNow => Now;

    public long Timestamp => Interlocked.Read(ref _ticks);

    public void Advance(TimeSpan by)
    {
        Now += by;
        Interlocked.Add(ref _ticks, (long)(by.TotalSeconds * System.Diagnostics.Stopwatch.Frequency));
    }
}

internal sealed class SelfSignedCertificates : IServerCertificateProvider
{
    private readonly X509Certificate2 _cert;

    public SelfSignedCertificates()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var temp = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        _cert = X509CertificateLoader.LoadPkcs12(temp.Export(X509ContentType.Pfx, "x"), "x", X509KeyStorageFlags.Exportable);
    }

    public X509Certificate2? GetCertificate(string? serverName) => _cert;
}

/// <summary>
/// A real SMTP server on loopback with the inbound receive path in front of the in-memory store, scripted DNS and a client address the test chooses (the real one is always loopback).
/// Seeded: <c>example.org</c> (tenant Acme, routes <c>support</c> store, <c>billing-*</c> forward, <c>old</c> discard), <c>example.net</c> (tenant Globex, a catch-all store route).
/// </summary>
internal sealed class InboundFixture : IAsyncDisposable
{
    public static readonly Guid Acme = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    public static readonly Guid Globex = Guid.Parse("a0000000-0000-7000-8000-000000000002");
    public static readonly Guid Suspended = Guid.Parse("a0000000-0000-7000-8000-000000000003");
    public const string BounceDomain = "bounces.egg.test";

    public InMemoryStorage Storage { get; private set; } = null!;
    public StaticDnsResolver Dns { get; } = new();
    public ManualClock Clock { get; } = new(new DateTimeOffset(2026, 10, 16, 12, 0, 30, TimeSpan.Zero));
    public InboundReceiveOptions Options { get; private set; } = null!;
    public VerpCodec Verp { get; } = new(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey() }, 1);
    public IngestHandler Handler { get; private set; } = null!;
    public InboundReceiver Receiver { get; private set; } = null!;
    public InboundConfigurationCache Config { get; private set; } = null!;
    public VerificationSlots Slots { get; private set; } = null!;
    public InboundRateLimiter Limiter { get; private set; } = null!;
    public SmtpServer Server { get; private set; } = null!;
    public int Port { get; private set; }
    public IPAddress ClientIp { get; set; } = IPAddress.Parse("203.0.113.9");
    public Guid ExampleOrg { get; private set; }
    public Guid ExampleNet { get; private set; }
    public Guid PendingDomain { get; private set; }
    public Guid SuspendedDomain { get; private set; }
    public Guid ForwardRouteId { get; private set; }
    public int Accepted;

    private readonly CapturingLog _log = new();

    /// <param name="options">The receive path's options; the default is everything at its default with inbound on.</param>
    /// <param name="mode">The listener mode (STARTTLS offered, or plain).</param>
    /// <param name="beforeStart">Runs after the receive path is built and before the listener opens (publish DNS records, seed more data).</param>
    /// <param name="wrapDns">Replaces the resolver the receive path uses (a resolver that hangs, for the timeout tests); the scripted <see cref="Dns"/> stays the place to publish records.</param>
    /// <param name="wrapStore">Replaces the inbound store the receive path writes to (a store that fails).</param>
    /// <param name="loadConfiguration">Whether the receive path's configuration is loaded before the first connection (a cold start otherwise).</param>
    public static async Task<InboundFixture> CreateAsync(InboundReceiveOptions? options = null, ListenerMode mode = ListenerMode.Plain, Action<InboundFixture>? beforeStart = null,
        bool bounceDomain = true, Func<StaticDnsResolver, IDnsResolver>? wrapDns = null, Func<IInboundStore, IInboundStore>? wrapStore = null, bool loadConfiguration = true,
        long? listenerMaxInFlightBytes = null)
    {
        var f = new InboundFixture();
        await f.InitializeAsync(options ?? new InboundReceiveOptions { Enabled = true }, mode, beforeStart, bounceDomain, wrapDns, wrapStore, loadConfiguration, listenerMaxInFlightBytes);
        return f;
    }

    private async Task InitializeAsync(InboundReceiveOptions options, ListenerMode mode, Action<InboundFixture>? beforeStart, bool bounceDomain, Func<StaticDnsResolver, IDnsResolver>? wrapDns, Func<IInboundStore, IInboundStore>? wrapStore, bool loadConfiguration, long? listenerMaxInFlightBytes)
    {
        Options = options;
        Storage = new InMemoryStorage(new StorageOptions());
        await Storage.InitializeAsync(default);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await Storage.Config.UpsertTenantAsync(new Tenant(Acme, "Acme", "acme", true, now, false), default);
        await Storage.Config.UpsertTenantAsync(new Tenant(Globex, "Globex", "globex", true, now, false), default);
        await Storage.Config.UpsertTenantAsync(new Tenant(Suspended, "Suspended", "suspended", false, now, false), default);
        ExampleOrg = await AddDomainAsync(Acme, "example.org", DomainStatus.Verified);
        ExampleNet = await AddDomainAsync(Globex, "example.net", DomainStatus.Verified);
        PendingDomain = await AddDomainAsync(Acme, "pending.example", DomainStatus.Pending);
        SuspendedDomain = await AddDomainAsync(Suspended, "suspended.example", DomainStatus.Verified);
        await Storage.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), Acme, "registered-only.example", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        Guid dedicated = Ids.New();
        await Storage.Config.UpsertDomainAsync(new DomainRecord(dedicated, Acme, "dedicated.example", DomainStatus.Verified, "bounce.dedicated.example", true, now, now, now, 0, null, false, null), default);

        foreach ((Guid domain, Guid tenant) in new[] { (ExampleOrg, Acme), (ExampleNet, Globex), (PendingDomain, Acme), (SuspendedDomain, Suspended) })
        {
            await EnableAsync(domain, tenant);
        }

        await AddRouteAsync(ExampleOrg, Acme, 10, InboundMatchKind.Address, "support", InboundActionKind.Store);
        ForwardRouteId = await AddRouteAsync(ExampleOrg, Acme, 20, InboundMatchKind.Wildcard, "billing-*", InboundActionKind.Forward, ["archive@elsewhere.test"]);
        await AddRouteAsync(ExampleOrg, Acme, 30, InboundMatchKind.Address, "old", InboundActionKind.Discard);
        await AddRouteAsync(ExampleNet, Globex, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
        await AddRouteAsync(PendingDomain, Acme, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
        await AddRouteAsync(SuspendedDomain, Suspended, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);

        var submission = new SubmissionService(Storage, Clock, new SenderPolicy(), new StorageOptions(), new SubmissionOptions { MessageIdDomain = "egg.test" });
        var bounces = new BounceProcessor(Verp, Storage.Config, Storage.Stats, new StorageWebhookPublisher(Storage), Clock);
        Handler = new IngestHandler(Storage, submission, new AuthThrottle(), new IngestOptions { BounceDomain = bounceDomain ? BounceDomain : null }, bounces, log: _log);
        Config = new InboundConfigurationCache(Storage.Inbound, Clock, options, _log);
        if (loadConfiguration)
        {
            await Config.RefreshAsync(default);
        }

        IDnsResolver resolver = wrapDns?.Invoke(Dns) ?? Dns;
        Slots = new VerificationSlots(options.VerificationMaxConcurrency, options.VerificationMaxConcurrencyPerRemote);
        Limiter = new InboundRateLimiter();
        Receiver = new InboundReceiver(
            Handler, wrapStore?.Invoke(Storage.Inbound) ?? Storage.Inbound, Config, new InboundVerifier(resolver, options, "mx.egg.test", Clock), Slots, Limiter,
            new DnsblChecker(resolver, options.DnsblZones, options.DnsblTimeout), new SrsCodec(Verp, options.SrsMaxAgeDays), new ForwardHopMarker(Verp), options, "mx.egg.test", Clock, _log,
            clientAddress: _ => ClientIp, onAccepted: () => Interlocked.Increment(ref Accepted));
        Handler.UseInbound(Receiver);
        beforeStart?.Invoke(this);

        Server = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "mx.egg.test",
            Certificates = mode == ListenerMode.Plain ? null : new SelfSignedCertificates(),
            Listeners = [ConfiguredListener(mode, options, listenerMaxInFlightBytes)],
        }, Handler, log: _log);
        Server.Start();
        Port = Server.LocalEndPoints["inbound"].Port;
    }

    // The listener exactly as the host configures the port-25 listener for these options (role, limits, shares), with the test's address and mode.
    private static SmtpListenerOptions ConfiguredListener(ListenerMode mode, InboundReceiveOptions options, long? maxInFlightBytes)
    {
        SmtpListenerOptions configured = EggMailRuntime.InboundListener(
            new SmtpListenerOptions { Name = "inbound", BindAddress = IPAddress.Loopback, Port = 0, Mode = mode, Role = ListenerRole.Bounce, AuthRequired = false }, options);
        return maxInFlightBytes is { } budget
            ? configured.With(configured.Role, configured.MaxMessageSize, configured.MaxRecipients, configured.MaxConnections, budget, configured.MaxInFlightBytesPerRemote, configured.MaxSessionDuration, authRequired: false)
            : configured;
    }

    public async Task<Guid> AddDomainAsync(Guid tenant, string name, DomainStatus status)
    {
        Guid id = Ids.New();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await Storage.Config.UpsertDomainAsync(new DomainRecord(id, tenant, name, status, null, false, now, status == DomainStatus.Verified ? now : null, now, 0, null, false, null), default);
        return id;
    }

    public async Task EnableAsync(Guid domain, Guid tenant, InboundDmarcAction action = InboundDmarcAction.RecordOnly, Func<InboundDomainSettings, InboundDomainSettings>? change = null)
    {
        InboundDomainSettings settings = new(domain, tenant, true, action, null, null, null, null, null, DateTimeOffset.UtcNow);
        await Storage.Inbound.UpsertSettingsAsync(change?.Invoke(settings) ?? settings, default);
    }

    public async Task<Guid> AddRouteAsync(Guid domain, Guid tenant, int order, InboundMatchKind match, string? local, InboundActionKind action, IReadOnlyList<string>? forwardTo = null, bool plus = false, bool enabled = true)
    {
        Guid id = Ids.New();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await Storage.Inbound.UpsertRouteAsync(new InboundRouteRecord(id, tenant, domain, local ?? "catch-all", order, enabled, match, local, plus, action, null, InboundWebhookFormat.Json, forwardTo ?? [], now, now), default);
        return id;
    }

    /// <summary>Makes the receive path see what the storage holds now (the periodic refresh, on demand).</summary>
    public Task RefreshConfigAsync() => Config.RefreshAsync(default);

    public async Task<IReadOnlyList<InboundMessage>> StoredAsync(Guid tenant) =>
        (await Storage.Inbound.SearchAsync(new InboundMessageQuery(tenant, Limit: 200), default)).Items;

    public async Task<string> RawAsync(InboundMessage message) => System.Text.Encoding.UTF8.GetString((await Storage.Inbound.GetRawAsync(message.TenantId, message.Id, default))!);

    public Task<FakeMta> ConnectAsync() => FakeMta.ConnectAsync(Port);

    /// <summary>An ordinary connection that has said EHLO.</summary>
    public async Task<FakeMta> ConnectedAsync(string helo = "mail.sender.test")
    {
        FakeMta mta = await ConnectAsync();
        Assert.Equal(250, (await mta.EhloAsync(helo)).Code);
        return mta;
    }

    public static string Message(string from = "Bob <bob@sender.test>", string to = "support@example.org", string subject = "Hello", string body = "Hi there.", string extraHeaders = "") =>
        $"From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nDate: Fri, 16 Oct 2026 12:00:00 +0000\r\nMessage-ID: <{Guid.NewGuid():N}@sender.test>\r\n{extraHeaders}\r\n{body}\r\n";

    /// <summary>Publishes an SPF record that authorizes the client address, and signs nothing.</summary>
    public void PublishSpf(string domain, bool authorizeClient = true) =>
        Dns.AddTxt(domain, authorizeClient ? $"v=spf1 ip4:{ClientIp} -all" : "v=spf1 -all");

    public void PublishDmarc(string domain, string policy, string extra = "") => Dns.AddTxt("_dmarc." + domain, $"v=DMARC1; p={policy}{extra}");

    /// <summary>Signs a message with a fresh key and publishes the key; returns the message with its DKIM-Signature on top.</summary>
    public string DkimSign(string message, string domain, string selector = "s1")
    {
        using RSA key = DkimKeyTools.GenerateRsa2048();
        Dns.AddTxt(DkimKeyTools.GetDnsName(domain, selector), DkimKeyTools.FormatDnsTxtValue(key));
        using var signer = new DkimSigner(new DkimSignerOptions { Domain = domain, Selector = selector, Clock = Clock }, key);
        return signer.Sign(System.Text.Encoding.UTF8.GetBytes(message)) + message;
    }

    public async ValueTask DisposeAsync()
    {
        await Server.DisposeAsync();
        await Storage.DisposeAsync();
    }

    /// <summary>A log that remembers the warnings, so the tests can see what an operator would.</summary>
    private sealed class CapturingLog : IMtaLog
    {
        public bool IsEnabled(MtaLogLevel level) => true;

        public void Write(MtaLogLevel level, string source, string message, Exception? exception = null)
        {
            if (level >= MtaLogLevel.Warning)
            {
                lock (Lines)
                {
                    Lines.Add($"{level} {source}: {message}");
                }
            }
        }

        public List<string> Lines { get; } = [];
    }

    public IReadOnlyList<string> LogLines
    {
        get
        {
            lock (_log.Lines)
            {
                return [.. _log.Lines];
            }
        }
    }
}
