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

public enum LabBackend
{
    Sqlite,
    Postgres,
}

internal sealed record LabOptions
{
    public InboundSection Inbound { get; init; } = new() { Enabled = true, CheckSpfForInternalClients = true };

    public ListenerMode Mode { get; init; } = ListenerMode.Plain;

    public SmtpSection Smtp { get; init; } = new() { Listeners = [] };

    public bool WithApi { get; init; }

    public bool Seed { get; init; } = true;

    public string? BounceDomain { get; init; } = InboundLab.BounceDomain;

    public bool RunActions { get; init; }

    public Mta.Webhooks.WebhookOptions Webhooks { get; init; } = new() { AllowHttp = true, Timeout = TimeSpan.FromSeconds(20) };

    public bool RunDelivery { get; init; }

    public int? RemotePort { get; init; }

    public int ListenerPort { get; init; }

    public InboundStorageOptions InboundStorage { get; init; } = new();

    public Func<StaticDnsResolver, IDnsResolver>? WrapDns { get; init; }
}

internal sealed class GatedResolver(StaticDnsResolver inner, Func<string, bool> hold) : IDnsResolver
{
    private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _released = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemaphoreSlim _arrivals = new(0);

    public Task Entered => _entered.Task;

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

internal sealed class InboundLab : IAsyncDisposable
{
    public const string Hostname = "mx.egg.test";
    public const string BounceDomain = "bounces.egg.test";
    public static readonly Guid Acme = ApiFixture.TenantAId;
    public static readonly Guid Globex = ApiFixture.TenantBId;

    private readonly string? _ownTemporaryDirectory;
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
        _ownTemporaryDirectory = directory;
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

    public IPAddress ClientIp { get; set; } = IPAddress.Loopback;

    private LabOptions _options = null!;

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
            Sqlite = new SqliteOptions { DataDirectory = _ownTemporaryDirectory!, ConfigSyncMode = SqliteSyncMode.Off, StatsFlushInterval = TimeSpan.Zero, RetentionDeletePause = TimeSpan.FromMilliseconds(1) },
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

    public static int ReservePort()
    {
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

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

    public async Task<WebhookEndpointRecord> AddWebhookEndpointAsync(Guid tenant, string url, string? secret = null, bool enabled = true)
    {
        string whsec = secret ?? "whsec_" + Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(24));
        var endpoint = new WebhookEndpointRecord(
            Ids.New(Clock.UtcNow), tenant, url, Runtime.Secrets.Protect(Encoding.UTF8.GetBytes(whsec), SecretPurposes.WebhookSecret), ["*"], enabled, enabled ? null : "off", enabled ? null : Clock.UtcNow, Clock.UtcNow, null);
        await Storage.Config.UpsertWebhookEndpointAsync(endpoint, default);
        Secrets[endpoint.Id] = whsec;
        return endpoint;
    }

    public Dictionary<Guid, string> Secrets { get; } = [];

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

    public async Task AdvanceAsync(TimeSpan by)
    {
        Clock.Advance(by);
        await RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        if (Runtime.InboundConfiguration is { } cache)
        {
            await cache.RefreshAsync(default);
        }
    }

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

    public void PublishSpf(string domain, bool authorize = true, string qualifier = "-") =>
        Dns.AddTxt(domain, authorize ? $"v=spf1 {(ClientIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "ip4" : "ip6")}:{ClientIp} {qualifier}all" : $"v=spf1 {qualifier}all");

    public void PublishDmarc(string domain, string policy, string extra = "") => Dns.AddTxt("_dmarc." + domain, $"v=DMARC1; p={policy}{extra}");

    public RSA PublishDkimKey(string domain, string selector = "s1")
    {
        RSA key = DkimKeyTools.GenerateRsa2048();
        Dns.AddTxt(DkimKeyTools.GetDnsName(domain, selector), DkimKeyTools.FormatDnsTxtValue(key));
        return key;
    }

    public string DkimSign(string message, string domain, string selector = "s1")
    {
        using RSA key = PublishDkimKey(domain, selector);
        using var signer = new DkimSigner(new DkimSignerOptions { Domain = domain, Selector = selector, Clock = Clock }, key);
        return signer.Sign(Encoding.UTF8.GetBytes(message)) + message;
    }

    public Task<FakeMta> ConnectAsync() => FakeMta.ConnectAsync(Port);

    public async Task<FakeMta> ConnectedAsync(string helo = "mail.sender.test")
    {
        FakeMta mta = await ConnectAsync();
        Assert.Equal(250, (await mta.EhloAsync(helo)).Code);
        return mta;
    }

    public async Task<FakeMta.Reply> SendAsync(string from, string to, string message, string mailParameters = "")
    {
        await using FakeMta mta = await ConnectedAsync();
        FakeMta.Reply reply = await mta.SendAsync(from, to, message, mailParameters);
        await mta.QuitAsync();
        return reply;
    }

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

    public async Task AssertNothingWasSentAsync()
    {
        foreach (DateTimeOffset at in new[] { Clock.UtcNow.AddMinutes(1), Clock.UtcNow.AddDays(30) })
        {
            Assert.Empty(await Storage.Deliveries.ClaimAsync("oracle", 100, at, TimeSpan.FromMinutes(1), default));
            Assert.Empty(await Storage.Webhooks.ClaimDueAsync("oracle", 100, at, TimeSpan.FromMinutes(1), default));
        }
    }

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

        if (_ownTemporaryDirectory is not null)
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try
            {
                Directory.Delete(_ownTemporaryDirectory, recursive: true);
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
