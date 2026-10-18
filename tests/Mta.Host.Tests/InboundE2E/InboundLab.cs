using System.Net;
using System.Security.Cryptography;
using System.Text;
using Mta.Core;
using Mta.Dkim;
using Mta.Dns;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Tests.Api;
using Mta.Host.Tests.Inbound;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.Postgres;
using Mta.Storage.Postgres.Tests;
using Mta.Storage.Sqlite;
using Mta.TestSupport;

namespace Mta.Host.Tests.InboundE2E;

/// <summary>The storage backend an end-to-end inbound scenario runs on. The scenarios are written once, in an abstract class, and each backend has a small subclass.</summary>
public enum LabBackend
{
    Sqlite,
    Postgres,
}

/// <summary>What a scenario changes about the server it runs against.</summary>
internal sealed record LabOptions
{
    /// <summary>The <c>Inbound:*</c> settings; the default has inbound on, the test sender (127.0.0.1) checked by SPF, and everything else at its default.</summary>
    public InboundSection Inbound { get; init; } = new() { Enabled = true, CheckSpfForInternalClients = true };

    public ListenerMode Mode { get; init; } = ListenerMode.Plain;

    /// <summary>The <c>Smtp:*</c> limits (the listener itself is always the one the lab defines).</summary>
    public SmtpSection Smtp { get; init; } = new() { Listeners = [] };

    public bool WithApi { get; init; }

    /// <summary>Whether the lab seeds <c>example.org</c> (tenant Acme: support store, billing-* forward, old discard) and <c>example.net</c> (tenant Globex: catch-all store).</summary>
    public bool Seed { get; init; } = true;

    public string? BounceDomain { get; init; } = InboundLab.BounceDomain;

    /// <summary>Whether the runner of the webhook and forward actions runs (in the background, polling every 50 ms); off, the test runs it by hand with <c>RunOnceAsync</c>.</summary>
    public bool RunActions { get; init; }

    /// <summary>The webhook HTTP stack of the runtime: plain http is allowed (the receivers are on loopback), the allowlist lets the tenants call 127.0.0.0/8.</summary>
    public Mta.Webhooks.WebhookOptions Webhooks { get; init; } = new() { AllowHttp = true, Timeout = TimeSpan.FromSeconds(20) };

    /// <summary>Whether the delivery engine runs (the forward action queues mail for it); its connections go to <see cref="RemotePort"/> whatever the MX says.</summary>
    public bool RunDelivery { get; init; }

    /// <summary>The port every outbound connection goes to (a fake remote MTA, or another lab's listener); the MX records of the scripted DNS name the hosts.</summary>
    public int? RemotePort { get; init; }

    /// <summary>The port of the listener; 0 is an ephemeral port. Two labs that forward to each other need each other's port before they start (see <see cref="InboundLab.ReservePort"/>).</summary>
    public int ListenerPort { get; init; }

    /// <summary>The retention keys of the storage (<c>Inbound:RetentionDays</c>, <c>Inbound:MaxRetentionDays</c>).</summary>
    public InboundStorageOptions InboundStorage { get; init; } = new();

    /// <summary>Replaces the resolver the runtime uses (one that hangs, one that counts); the scripted <see cref="InboundLab.Dns"/> stays the place to publish records.</summary>
    public Func<StaticDnsResolver, IDnsResolver>? WrapDns { get; init; }
}

/// <summary>
/// A resolver that answers from the scripted records except for the names it is told to hold: those queries wait until <see cref="Release"/> (a test that wants a verification to be in progress
/// while something else happens), or until the caller gives up. <see cref="Entered"/> completes when the first held query has arrived, so the test never guesses.
/// </summary>
internal sealed class GatedResolver(StaticDnsResolver inner, Func<string, bool> hold) : IDnsResolver
{
    private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _released = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemaphoreSlim _arrivals = new(0);

    public Task Entered => _entered.Task;

    /// <summary>Completes when <paramref name="count"/> held queries have arrived (not counting the ones that arrive after).</summary>
    public async Task WaitForArrivalsAsync(int count)
    {
        for (int i = 0; i < count; i++)
        {
            await _arrivals.WaitAsync(TimeSpan.FromSeconds(30));
        }
    }

    public void Release() => _released.TrySetResult();

    public async ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
    {
        if (hold(name))
        {
            _entered.TrySetResult();
            _arrivals.Release();
            await _released.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        return await inner.QueryAsync(name, type, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>A resolver that answers from the scripted records except for the names it is told to hold: those queries wait until the caller gives up.</summary>
internal sealed class HoldingResolver(StaticDnsResolver inner, Func<string, bool> hold) : IDnsResolver
{
    public async ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
    {
        if (hold(name))
        {
            await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
        }

        return await inner.QueryAsync(name, type, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// A real <see cref="EggMailRuntime"/> (configuration, port-25 listener of role Inbound, receive path, the real inbound store of SQLite or PostgreSQL, the certificate provider) with a scripted
/// DNS, a clock the test moves by hand, and optionally the HTTP API over the very same storage. The listener is on an ephemeral loopback port; the sender is the test, from 127.0.0.1.
/// </summary>
internal sealed class InboundLab : IAsyncDisposable
{
    public const string Hostname = "mx.egg.test";
    public const string BounceDomain = "bounces.egg.test";
    public static readonly Guid Acme = ApiFixture.TenantAId;
    public static readonly Guid Globex = ApiFixture.TenantBId;

    private readonly string? _directory;
    private TestDatabase? _database;
    private CancellationTokenSource? _refresh;
    private Task _refreshTask = Task.CompletedTask;
    private CancellationTokenSource? _actions;
    private Task _actionsTask = Task.CompletedTask;
    private CancellationTokenSource? _delivery;
    private Task _deliveryTask = Task.CompletedTask;

    private InboundLab(LabBackend backend, string? directory, TestDatabase? database)
    {
        Backend = backend;
        _directory = directory;
        _database = database;
    }

    public LabBackend Backend { get; }
    public TestClock Clock { get; } = new(ApiFixture.Start);
    public StaticDnsResolver Dns { get; } = new();
    public StorageOptions StorageOptions { get; private set; } = null!;
    public MtaConfig Config { get; private set; } = null!;
    public EggMailRuntime Runtime { get; private set; } = null!;
    public IStorage Storage => Runtime.Storage;
    public ApiFixture? Api { get; private set; }
    public int Port { get; private set; }
    public Guid ExampleOrg { get; private set; }
    public Guid ExampleNet { get; private set; }
    public Guid SupportRoute { get; private set; }
    public Guid BillingRoute { get; private set; }
    public Guid OldRoute { get; private set; }
    public Guid NetRoute { get; private set; }
    public List<string> Warnings { get; } = [];

    /// <summary>The address the receive path sees the sender at (the real one is always 127.0.0.1); a test sets it to be a public sender, an IPv6 client or a listed address.</summary>
    public IPAddress ClientIp { get; set; } = IPAddress.Loopback;

    private LabOptions _options = null!;

    /// <summary>Starts the lab; null when the PostgreSQL scenario has no server to run on (and none is promised).</summary>
    public static async Task<InboundLab?> StartAsync(LabBackend backend, LabOptions? options = null)
    {
        options ??= new LabOptions();
        TestDatabase? database = null;
        string? directory = null;
        if (backend == LabBackend.Postgres)
        {
            if (!PostgresPromise.Available())
            {
                return null;
            }

            database = await PostgresTestServer.Instance.CreateDatabaseAsync();
        }
        else
        {
            directory = Directory.CreateTempSubdirectory("eggmail-inbound-e2e-").FullName;
        }

        var lab = new InboundLab(backend, directory, database);
        try
        {
            await lab.OpenAsync(options);
        }
        catch
        {
            await lab.DisposeAsync();
            throw;
        }

        return lab;
    }

    private StorageOptions NewStorageOptions() => Backend == LabBackend.Sqlite
        ? new StorageOptions
        {
            Inbound = _options.InboundStorage,
            Sqlite = new SqliteOptions { DataDirectory = _directory!, ConfigSyncMode = SqliteSyncMode.Off, StatsFlushInterval = TimeSpan.Zero, RetentionDeletePause = TimeSpan.FromMilliseconds(1) },
        }
        : new StorageOptions
        {
            Inbound = _options.InboundStorage,
            Backend = StorageBackend.Postgres,
            Postgres = new PostgresOptions
            {
                OwnerConnectionString = _database!.ConnectionString,
                RuntimeConnectionString = _database.ConnectionString,
                MaxPoolSize = 12,
                StatsFlushInterval = TimeSpan.Zero,
                RetentionDeletePause = TimeSpan.FromMilliseconds(1),
            },
        };

    private IStorage CreateStorage() => Backend == LabBackend.Sqlite ? SqliteStorage.Create(StorageOptions, Clock) : PostgresStorage.Create(StorageOptions, Clock);

    private async Task OpenAsync(LabOptions options)
    {
        _options = options;
        StorageOptions = NewStorageOptions();
        IStorage storage = CreateStorage();
        await storage.InitializeAsync(default);
        await StartRuntimeAsync(storage);
        DateTimeOffset now = Clock.UtcNow;
        await Storage.Config.UpsertTenantAsync(new Tenant(Acme, "Acme Corp", "acme", true, now, false), default);
        await Storage.Config.UpsertTenantAsync(new Tenant(Globex, "Globex", "globex", true, now, false), default);
        if (options.WithApi)
        {
            Api = await ApiFixture.StartAsync(new ApiFixtureOptions { ExistingStorage = Storage, ExistingClock = Clock, ExistingStorageOptions = StorageOptions, ConfigureApi = o => { o.PasswordHashIterations = 1000; o.Inbound = Mta.Host.Api.EggMailApiExtensions.InboundDefaultsFrom(Config); } });
        }

        if (options.Seed)
        {
            ExampleOrg = await AddDomainAsync(Acme, "example.org");
            ExampleNet = await AddDomainAsync(Globex, "example.net");
            SupportRoute = await AddRouteAsync(ExampleOrg, Acme, 10, InboundMatchKind.Address, "support", InboundActionKind.Store);
            BillingRoute = await AddRouteAsync(ExampleOrg, Acme, 20, InboundMatchKind.Wildcard, "billing-*", InboundActionKind.Forward, ["archive@elsewhere.test"]);
            OldRoute = await AddRouteAsync(ExampleOrg, Acme, 30, InboundMatchKind.Address, "old", InboundActionKind.Discard);
            NetRoute = await AddRouteAsync(ExampleNet, Globex, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
        }

        await RefreshAsync();
    }

    private async Task StartRuntimeAsync(IStorage storage)
    {
        var listeners = new Dictionary<string, ListenerSection>
        {
            ["bounce"] = new() { Port = _options.ListenerPort, BindAddress = "127.0.0.1", Mode = _options.Mode, Role = ListenerRole.Bounce, AuthRequired = false },
        };
        Config = new MtaConfig
        {
            Hostname = Hostname,
            Storage = StorageOptions,
            Inbound = _options.Inbound,
            Smtp = new SmtpSection
            {
                Listeners = listeners,
                MaxConnections = _options.Smtp.MaxConnections,
                MaxConnectionsPerIp = _options.Smtp.MaxConnectionsPerIp,
                MaxRecipients = _options.Smtp.MaxRecipients,
                MaxMessageSize = _options.Smtp.MaxMessageSize,
                MaxInFlightBytes = _options.Smtp.MaxInFlightBytes,
                Chunking = _options.Smtp.Chunking,
            },
            Delivery = new DeliverySection { BounceDomain = _options.BounceDomain, PollInterval = TimeSpan.FromMilliseconds(50), AllowPrivateMxAddresses = true, RemotePort = _options.RemotePort ?? 25 },
            Webhooks = _options.Webhooks,
        };
        Runtime = await EggMailRuntime.CreateAsync(Config, storage, Clock, new WarningLog(Warnings), default, _options.WrapDns?.Invoke(Dns) ?? Dns, inboundClientAddress: _ => ClientIp);
        Runtime.Webhooks.AllowlistProvider = _ => [Mta.Webhooks.IpNetwork.Parse("127.0.0.0/8")];
        Runtime.SmtpServer.Start();
        Port = Runtime.SmtpServer.LocalEndPoints["bounce"].Port;
        if (_options.RunActions)
        {
            _actions = new CancellationTokenSource();
            _actionsTask = Runtime.InboundActions.RunAsync(_actions.Token);
        }

        if (_options.RunDelivery)
        {
            _delivery = new CancellationTokenSource();
            _deliveryTask = Task.Run(() => Runtime.Delivery.RunAsync(_delivery.Token));
        }
    }

    private async Task StopDeliveryAsync()
    {
        if (_delivery is not null)
        {
            await _delivery.CancelAsync();
            try { await _deliveryTask; } catch (OperationCanceledException) { }
            _delivery.Dispose();
            _delivery = null;
        }
    }

    /// <summary>A free loopback port, found by binding and releasing it (for a lab that must know its own port before it starts; the small race is acceptable on a test machine).</summary>
    public static int ReservePort()
    {
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    /// <summary>Gives the domain an active DKIM key (the private half protected as the server stores it), publishes the public half in the scripted DNS and returns the key (the caller disposes it).</summary>
    public async Task<RSA> AddDkimKeyAsync(Guid domainId, string domainName, string selector = "egg1")
    {
        RSA key = DkimKeyTools.GenerateRsa2048();
        DateTimeOffset now = Clock.UtcNow;
        await Storage.Config.AddDkimKeyAsync(new Mta.Storage.DkimKeyRecord(Ids.New(now), domainId, selector, Runtime.Secrets.Protect(key.ExportPkcs8PrivateKey(), SecretPurposes.DkimKey), DkimKeyTools.ExportPublicKeyBase64(key), now, true, null), default);
        Dns.AddTxt(DkimKeyTools.GetDnsName(domainName, selector), DkimKeyTools.FormatDnsTxtValue(key));
        return key;
    }

    private async Task StopActionsAsync()
    {
        if (_actions is not null)
        {
            await _actions.CancelAsync();
            try { await _actionsTask; } catch (OperationCanceledException) { }
            _actions.Dispose();
            _actions = null;
        }
    }

    /// <summary>A webhook endpoint of a tenant that the runtime can call (its secret is protected the way the API protects it).</summary>
    public async Task<WebhookEndpointRecord> AddWebhookEndpointAsync(Guid tenant, string url, string? secret = null, bool enabled = true)
    {
        string whsec = secret ?? "whsec_" + Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(24));
        var endpoint = new WebhookEndpointRecord(
            Ids.New(Clock.UtcNow), tenant, url, Runtime.Secrets.Protect(Encoding.UTF8.GetBytes(whsec), SecretPurposes.WebhookSecret), ["*"], enabled, enabled ? null : "off", enabled ? null : Clock.UtcNow, Clock.UtcNow, null);
        await Storage.Config.UpsertWebhookEndpointAsync(endpoint, default);
        Secrets[endpoint.Id] = whsec;
        return endpoint;
    }

    /// <summary>The secrets this lab generated for its endpoints (what a receiver would be given).</summary>
    public Dictionary<Guid, string> Secrets { get; } = [];

    /// <summary>
    /// What a process restart (or a crash) looks like to the data: the runtime and the storage are closed without any flush of the state kept in memory, a new storage is opened over the very same files
    /// or database, and a new runtime starts on a new port. The inbound configuration is loaded again before the listener opens.
    /// </summary>
    public async Task RestartAsync(bool crash = false, Func<LabOptions, LabOptions>? reconfigure = null)
    {
        if (reconfigure is not null)
        {
            _options = reconfigure(_options);
        }

        await StopRefreshAsync();
        await StopActionsAsync();
        await StopDeliveryAsync();
        if (!crash)
        {
            await Runtime.SmtpServer.StopAsync(TimeSpan.FromSeconds(2));
        }

        await Runtime.DisposeAsync();
        await Runtime.Storage.DisposeAsync();
        IStorage storage = CreateStorage();
        await storage.InitializeAsync(default);
        await StartRuntimeAsync(storage);
        await RefreshAsync();
    }

    /// <summary>Moves the clock and lets the receive path reload its configuration (the periodic refresh would have done it; without it the cache is too old after minutes and the listener answers 451).</summary>
    public async Task AdvanceAsync(TimeSpan by)
    {
        Clock.Advance(by);
        await RefreshAsync();
    }

    /// <summary>Makes the receive path see what the storage holds now (the periodic refresh, on demand).</summary>
    public async Task RefreshAsync()
    {
        if (Runtime.InboundConfiguration is { } cache)
        {
            await cache.RefreshAsync(default);
        }
    }

    /// <summary>Lets the cache follow the storage in the background, as the host does (every change signal and interval), until the lab is disposed.</summary>
    public void FollowConfiguration()
    {
        _refresh = new CancellationTokenSource();
        _refreshTask = Runtime.InboundConfiguration!.RunAsync(_refresh.Token);
    }

    private async Task StopRefreshAsync()
    {
        if (_refresh is not null)
        {
            await _refresh.CancelAsync();
            try { await _refreshTask; } catch (OperationCanceledException) { }
            _refresh.Dispose();
            _refresh = null;
        }
    }

    // ---------------------------------------------------------------- seeding

    public async Task<Guid> AddDomainAsync(Guid tenant, string name, bool enableInbound = true, InboundDmarcAction action = InboundDmarcAction.RecordOnly, DomainStatus status = DomainStatus.Verified,
        Func<InboundDomainSettings, InboundDomainSettings>? change = null)
    {
        Guid id = Ids.New(Clock.UtcNow);
        DateTimeOffset now = Clock.UtcNow;
        await Storage.Config.UpsertDomainAsync(new DomainRecord(id, tenant, name, status, "bounce." + name, false, now, status == DomainStatus.Verified ? now : null, now, 0, null, false, null), default);
        if (enableInbound)
        {
            InboundDomainSettings settings = new(id, tenant, true, action, null, null, null, null, null, now);
            await Storage.Inbound.UpsertSettingsAsync(change?.Invoke(settings) ?? settings, default);
        }

        return id;
    }

    public async Task<Guid> AddRouteAsync(Guid domain, Guid tenant, int order, InboundMatchKind match, string? local, InboundActionKind action, IReadOnlyList<string>? forwardTo = null, Guid? webhookEndpoint = null,
        InboundWebhookFormat format = InboundWebhookFormat.Json, bool enabled = true, bool plus = false)
    {
        Guid id = Ids.New(Clock.UtcNow);
        DateTimeOffset now = Clock.UtcNow;
        await Storage.Inbound.UpsertRouteAsync(new InboundRouteRecord(id, tenant, domain, local ?? "catch-all", order, enabled, match, local, plus, action, webhookEndpoint, format, forwardTo ?? [], now, now), default);
        return id;
    }

    public async Task SetSettingsAsync(Guid domain, Guid tenant, Func<InboundDomainSettings, InboundDomainSettings> change)
    {
        InboundDomainSettings current = await Storage.Inbound.GetSettingsAsync(domain, default) ?? new InboundDomainSettings(domain, tenant, true, InboundDmarcAction.RecordOnly, null, null, null, null, null, Clock.UtcNow);
        await Storage.Inbound.UpsertSettingsAsync(change(current), default);
        await RefreshAsync();
    }

    // ---------------------------------------------------------------- DNS

    /// <summary>An SPF record that authorizes the sender (<see cref="ClientIp"/>).</summary>
    public void PublishSpf(string domain, bool authorize = true, string qualifier = "-") =>
        Dns.AddTxt(domain, authorize ? $"v=spf1 {(ClientIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "ip4" : "ip6")}:{ClientIp} {qualifier}all" : $"v=spf1 {qualifier}all");

    public void PublishDmarc(string domain, string policy, string extra = "") => Dns.AddTxt("_dmarc." + domain, $"v=DMARC1; p={policy}{extra}");

    /// <summary>Publishes a key for the selector and returns the private key (the caller disposes it).</summary>
    public RSA PublishDkimKey(string domain, string selector = "s1")
    {
        RSA key = DkimKeyTools.GenerateRsa2048();
        Dns.AddTxt(DkimKeyTools.GetDnsName(domain, selector), DkimKeyTools.FormatDnsTxtValue(key));
        return key;
    }

    /// <summary>The message with a DKIM signature of the library signer on top (the key is published).</summary>
    public string DkimSign(string message, string domain, string selector = "s1")
    {
        using RSA key = PublishDkimKey(domain, selector);
        using var signer = new DkimSigner(new DkimSignerOptions { Domain = domain, Selector = selector, Clock = Clock }, key);
        return signer.Sign(Encoding.UTF8.GetBytes(message)) + message;
    }

    // ---------------------------------------------------------------- senders and observers

    public Task<FakeMta> ConnectAsync() => FakeMta.ConnectAsync(Port);

    public async Task<FakeMta> ConnectedAsync(string helo = "mail.sender.test")
    {
        FakeMta mta = await ConnectAsync();
        Assert.Equal(250, (await mta.EhloAsync(helo)).Code);
        return mta;
    }

    /// <summary>One transaction on a connection of its own; returns the reply to the end of DATA or the first refusal on the way.</summary>
    public async Task<FakeMta.Reply> SendAsync(string from, string to, string message, string mailParameters = "")
    {
        await using FakeMta mta = await ConnectedAsync();
        FakeMta.Reply reply = await mta.SendAsync(from, to, message, mailParameters);
        await mta.QuitAsync();
        return reply;
    }

    /// <summary>The signed bounce local part of the shared bounce domain for a message of the tenant (what a real sender would put in the return path).</summary>
    public string BounceLocalPart(string destination = "dest.example") => Runtime.Verp.CreateLocalPart(Acme, ExampleOrg, Clock.UtcNow, destination);

    public Mta.Dsn.SrsCodec Srs => new(Runtime.Verp);

    public static string Dsn(string to, string finalRecipient) =>
        $"From: MAILER-DAEMON@remote.example\r\nTo: {to}\r\nSubject: Undelivered Mail Returned to Sender\r\nAuto-Submitted: auto-replied\r\n" +
        "Content-Type: multipart/report; report-type=delivery-status; boundary=\"BB\"\r\n\r\n" +
        "--BB\r\nContent-Type: text/plain\r\n\r\nCould not deliver.\r\n" +
        $"--BB\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; remote.example\r\n\r\nFinal-Recipient: rfc822; {finalRecipient}\r\nAction: failed\r\nStatus: 5.1.1\r\nDiagnostic-Code: smtp; 550 5.1.1 No such user\r\n\r\n" +
        "--BB\r\nContent-Type: text/rfc822-headers\r\n\r\nMessage-ID: <orig@egg.test>\r\nSubject: x\r\n\r\n--BB--\r\n";

    public static string Message(string from = "Bob <bob@sender.test>", string to = "support@example.org", string subject = "Hello", string body = "Hi there.", string extraHeaders = "") =>
        InboundFixture.Message(from, to, subject, body, extraHeaders);

    public async Task<IReadOnlyList<InboundMessage>> MessagesAsync(Guid tenant, InboundMessageQuery? query = null) =>
        (await Storage.Inbound.SearchAsync(query ?? new InboundMessageQuery(tenant, Limit: 200), default)).Items;

    public async Task<string> RawAsync(InboundMessage message) => Encoding.UTF8.GetString((await Storage.Inbound.GetRawAsync(message.TenantId, message.Id, default))!);

    /// <summary>
    /// The backscatter oracle: nothing at all was created on the outbound side. No delivery can be claimed, and the webhook outbox holds nothing (a bounce, a notice and an event would each show here).
    /// </summary>
    public async Task AssertNothingWasSentAsync()
    {
        DateTimeOffset later = Clock.UtcNow.AddDays(30);
        Assert.Empty(await Storage.Deliveries.ClaimAsync("oracle", 100, later, TimeSpan.FromMinutes(1), default));
        Assert.Empty(await Storage.Webhooks.ClaimDueAsync("oracle", 100, later, TimeSpan.FromMinutes(1), default));
    }

    /// <summary>Whatever the runtime logged as an error while the test ran is a failure the sender may not have seen (a 451 for a reason that is the server's own, an exception in a background task).</summary>
    public void AssertNoErrorsLogged()
    {
        lock (Warnings)
        {
            Assert.DoesNotContain(Warnings, w => w.StartsWith("Error", StringComparison.Ordinal));
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopRefreshAsync();
        await StopActionsAsync();
        await StopDeliveryAsync();
        if (Api is not null)
        {
            await Api.DisposeAsync();
        }

        if (Runtime is not null)
        {
            try { await Runtime.SmtpServer.StopAsync(TimeSpan.FromSeconds(2)); } catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException) { }
            await Runtime.DisposeAsync();
            await Runtime.Storage.DisposeAsync();
        }

        if (_database is not null)
        {
            await _database.DisposeAsync();
            _database = null;
        }

        if (_directory is not null)
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try
            {
                // A directory this lab created itself (a unique name under the temp folder) and the only owner of its files.
                Directory.Delete(_directory, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }

    private sealed class WarningLog(List<string> lines) : IMtaLog
    {
        public bool IsEnabled(MtaLogLevel level) => level >= MtaLogLevel.Warning;

        public void Write(MtaLogLevel level, string source, string message, Exception? exception = null)
        {
            if (level >= MtaLogLevel.Warning)
            {
                lock (lines)
                {
                    lines.Add($"{level} {source}: {message}{(exception is null ? "" : " " + exception.GetType().Name + ": " + exception.Message)}");
                }
            }
        }
    }
}
