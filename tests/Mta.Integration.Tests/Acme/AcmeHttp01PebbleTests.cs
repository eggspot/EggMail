using System.Security.Cryptography.X509Certificates;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Host.Tls;
using Mta.Storage;
using Mta.Storage.Sqlite;

namespace Mta.Integration.Tests.Acme;

/// <summary>
/// Every test that binds the port Pebble validates HTTP-01 on is in this collection: xUnit runs the classes of one collection one after the other.
/// </summary>
[CollectionDefinition(Name)]
public sealed class Http01PortCollection : ICollectionFixture<Http01PortCollection>
{
    public const string Name = "Pebble HTTP-01 port";
}

/// <summary>
/// An HTTP-01 world on top of <see cref="AcmeHarness"/>: the challenge store of "this replica" and the real built-in listener on the port Pebble connects to.
/// The listener answers through <see cref="Responder"/>, which a test can switch off (to see the CA's validation fail) or swap.
/// </summary>
internal sealed class Http01Rig : IAsyncDisposable
{
    private readonly CancellationTokenSource _stop = new();
    private Task _serving = Task.CompletedTask;

    private Http01Rig(AcmeHarness harness)
    {
        Harness = harness;
        Challenges = new Http01Challenges(harness.Storage.Config, harness.Clock, harness.Log, refreshInterval: TimeSpan.Zero);
        Responder = new SwitchableResponder(Challenges);
    }

    public AcmeHarness Harness { get; }

    /// <summary>This replica's token store.</summary>
    public Http01Challenges Challenges { get; }

    public SwitchableResponder Responder { get; }

    public AcmeHttpChallengeListener? Listener { get; private set; }

    public static async Task<Http01Rig> CreateAsync(IStorage storage, Func<Task>? cleanup = null, string? directoryUrl = null) =>
        new(await AcmeHarness.CreateAsync(storage, cleanup, directoryUrl));

    /// <summary>Binds the port of Pebble's validation authority; returns null or the message the listener reports when it cannot.</summary>
    public string? StartListener()
    {
        Challenges.ExpectListener();
        Listener = new AcmeHttpChallengeListener(Responder, "::", Pebble.HttpPort, Challenges, Harness.Log);
        string? problem = Listener.TryBind();
        if (problem is null)
        {
            _serving = Listener.ServeAsync(_stop.Token);
        }

        return problem;
    }

    /// <summary>A renewal service of this replica: HTTP-01 only (no DNS provider).</summary>
    public AcmeRenewalService Service(params string[] domains) => Harness.CreateService(null, domains, challenges: Challenges);

    public CertificateHealthContributor Banner(params string[] domains) =>
        new(Harness.Storage, Harness.Clock, new MtaConfig { Acme = Harness.Section(domains) });

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        if (Listener is not null)
        {
            await Listener.DisposeAsync();
        }

        await _serving.WaitAsync(TimeSpan.FromSeconds(30));
        await Harness.DisposeAsync();
    }

    /// <summary>Answers like the store until told to stop (then every token is unknown: the CA's request gets a 404).</summary>
    public sealed class SwitchableResponder(IHttpChallengeResponder inner) : IHttpChallengeResponder
    {
        public volatile bool Answering = true;

        public ValueTask<string?> FindKeyAuthorizationAsync(string token, CancellationToken cancellationToken) =>
            Answering ? inner.FindKeyAuthorizationAsync(token, cancellationToken) : ValueTask.FromResult<string?>(null);
    }
}

/// <summary>
/// HTTP-01 against the Pebble test CA (decision 87): the CA really connects to our built-in listener, so a token that is not answered fails the
/// order. Needs the port Pebble validates on (<c>httpPort</c>, 5002) to be free and the names to resolve to this host (pebble-challtestsrv's default).
/// </summary>
[Collection(Http01PortCollection.Name)]
public abstract class AcmeHttp01PebbleTests : IAsyncLifetime
{
    private Http01Rig _rig = null!;

    protected abstract Task<(IStorage Storage, Func<Task>? Cleanup)> CreateStorageAsync();

    public async Task InitializeAsync()
    {
        var (storage, cleanup) = await CreateStorageAsync();
        _rig = await Http01Rig.CreateAsync(storage, cleanup);
    }

    public async Task DisposeAsync() => await _rig.DisposeAsync();

    private AcmeHarness H => _rig.Harness;

    private string Diagnostics => string.Join('\n', H.Log.Lines);

    private static async Task<bool> WithTimeout(Task<bool> task) => await task.WaitAsync(TimeSpan.FromMinutes(2));

    // ---------------------------------------------------------------------------------------------------------------------------------

    protected async Task Issues_a_certificate_over_HTTP_01_from_the_built_in_listenerAsync()
    {
        string host = AcmeTestNames.Unique();
        Assert.Null(_rig.StartListener());
        var service = _rig.Service(host);

        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics);

        var row = Assert.Single(await H.Storage.Config.GetCertificatesAsync(default));
        Assert.Equal(("default", "acme", true), (row.Name, row.Source, row.Active));
        Assert.Equal([host], row.Subjects);
        await AcmeIssuanceTests.AssertTrustedByPebbleAsync(row);
        var (leaf, _) = CertificateMaterial.Load(row, H.Secrets);
        Assert.Contains(host, CertificateMaterial.SubjectsOf(leaf));

        // The CA really asked our listener, and the answer is gone from the store afterwards.
        Assert.Contains(H.Log.Lines, l => l.Contains("answered the ACME HTTP-01 challenge", StringComparison.Ordinal));
        var renewal = Assert.Single(await H.Storage.Config.GetAcmeRenewalsAsync(default));
        Assert.Equal(("issued", 0), (renewal.Status, renewal.Failures));
        Assert.Null(renewal.ChallengeStateJson);
        Assert.Contains("HTTP-01", Diagnostics);
        Assert.Equal(1, H.Http.CountPosts(H.Endpoints.NewOrder));

        // Nothing to do while the certificate is fresh, and the banner has nothing to say about ACME.
        Assert.False(await service.CheckOnceAsync(default));
        Assert.DoesNotContain((await _rig.Banner(host).CheckAsync(default)).Warnings, w => w.Code.StartsWith("acme_", StringComparison.Ordinal));
    }

    protected async Task Renewal_over_HTTP_01_replaces_the_row_and_reuses_the_accountAsync()
    {
        H.UseRenewalInfo = false;
        string host = AcmeTestNames.Unique();
        Assert.Null(_rig.StartListener());
        var service = _rig.Service(host);
        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics);
        var before = Assert.Single(await H.Storage.Config.GetCertificatesAsync(default));
        TimeSpan lifetime = before.NotAfter - before.NotBefore;

        H.Clock.Advance(lifetime * 0.6);
        Assert.False(await service.CheckOnceAsync(default));
        H.Clock.Advance(lifetime * 0.1);
        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics);

        var after = Assert.Single(await H.Storage.Config.GetCertificatesAsync(default));
        Assert.Equal(before.Id, after.Id);
        Assert.NotEqual(before.Thumbprint, after.Thumbprint);
        Assert.Equal(2, H.Http.CountPosts(H.Endpoints.NewOrder));
        Assert.Equal(1, H.Http.CountPosts(H.Endpoints.NewAccount, p => !p.Contains("onlyReturnExisting", StringComparison.Ordinal)));   // one account
        await AcmeIssuanceTests.AssertTrustedByPebbleAsync(after);
        Assert.Equal("issued", Assert.Single(await H.Storage.Config.GetAcmeRenewalsAsync(default)).Status);
    }

    protected async Task Another_replica_answers_the_challenge_the_ordering_replica_publishedAsync()
    {
        string host = AcmeTestNames.Unique();
        // Replica A orders and has no listener at all; replica B is whichever replica the CA happens to reach. They share only the config store.
        var replicaB = new Http01Challenges(H.Storage.Config, H.Clock, H.Log, refreshInterval: TimeSpan.Zero);
        var listenerB = new AcmeHttpChallengeListener(replicaB, "::", Pebble.HttpPort, replicaB, H.Log);
        using var stop = new CancellationTokenSource();
        Assert.Null(listenerB.TryBind());
        Task serving = listenerB.ServeAsync(stop.Token);
        try
        {
            var replicaA = H.CreateService(null, [host], challenges: _rig.Challenges);

            Assert.True(await WithTimeout(replicaA.CheckOnceAsync(default)), Diagnostics);

            Assert.Equal([host], Assert.Single(await H.Storage.Config.GetCertificatesAsync(default)).Subjects);
            Assert.Contains(H.Log.Lines, l => l.Contains("answered the ACME HTTP-01 challenge", StringComparison.Ordinal));
            Assert.Null(_rig.Listener);   // replica A never listened: the answer came from replica B, which read the token from the store
            Assert.Null(Assert.Single(await H.Storage.Config.GetAcmeRenewalsAsync(default)).ChallengeStateJson);
        }
        finally
        {
            await stop.CancelAsync();
            await listenerB.DisposeAsync();
            await serving.WaitAsync(TimeSpan.FromSeconds(30));
        }
    }

    protected async Task A_failed_validation_shows_in_the_banner_with_the_cas_reason_and_recoversAsync()
    {
        string host = AcmeTestNames.Unique();
        Assert.Null(_rig.StartListener());
        _rig.Responder.Answering = false;   // the port is open but nothing answers the token: what a wrong reverse proxy does
        var service = _rig.Service(host);
        var banner = _rig.Banner(host);

        Assert.False(await WithTimeout(service.CheckOnceAsync(default)));

        Assert.Empty(await H.Storage.Config.GetCertificatesAsync(default));
        var renewal = Assert.Single(await H.Storage.Config.GetAcmeRenewalsAsync(default));
        Assert.Equal(("failed", 1), (renewal.Status, renewal.Failures));
        Assert.Null(renewal.ChallengeStateJson);   // the token was removed although the order failed
        Assert.Contains(host, renewal.LastError);
        Assert.Contains("404", renewal.LastError);   // the CA's own explanation: it got a 404 from our listener
        Assert.Contains("port 80", renewal.LastError);   // and the hint what to check
        var warning = Assert.Single((await banner.CheckAsync(default)).Warnings, w => w.Code == "acme_failing");
        Assert.Contains("failed 1 time in a row", warning.Message);
        Assert.Contains("the CA could not validate the challenge", warning.Message);   // a category; the CA's own words ("404") are in the admin view
        Assert.DoesNotContain("404", warning.Message);
        Assert.Contains("Next attempt:", warning.Message);

        // The proxy is fixed; after the back-off the order succeeds and the warning is gone.
        _rig.Responder.Answering = true;
        Assert.False(await service.CheckOnceAsync(default));   // still inside the back-off
        H.Clock.Advance(TimeSpan.FromMinutes(11));
        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics);
        Assert.Equal("issued", Assert.Single(await H.Storage.Config.GetAcmeRenewalsAsync(default)).Status);
        Assert.DoesNotContain((await banner.CheckAsync(default)).Warnings, w => w.Code.StartsWith("acme_", StringComparison.Ordinal));
    }

    protected async Task A_port_that_cannot_be_bound_asks_the_ca_nothing_and_the_order_follows_when_it_canAsync()
    {
        string host = AcmeTestNames.Unique();
        await using var occupant = new AcmeHttpChallengeListener(_rig.Responder, "::", Pebble.HttpPort);
        Assert.Null(occupant.TryBind());   // something else holds the port
        string? problem = _rig.StartListener();
        Assert.NotNull(problem);
        Assert.Contains("already in use", problem);
        var service = _rig.Service(host);
        var banner = _rig.Banner(host);

        Assert.False(await WithTimeout(service.CheckOnceAsync(default)));

        Assert.Equal(0, H.Http.CountPosts(H.Endpoints.NewOrder));   // the CA was never asked: no failed validation counted against the name
        Assert.Equal(0, H.Http.CountPosts(H.Endpoints.NewAccount));
        var renewal = Assert.Single(await H.Storage.Config.GetAcmeRenewalsAsync(default));
        Assert.Equal(("failed", 1), (renewal.Status, renewal.Failures));
        Assert.Contains("already in use", renewal.LastError);
        Assert.Contains("Acme:Http01ListenPort", renewal.LastError);
        var warning = Assert.Single((await banner.CheckAsync(default)).Warnings, w => w.Code == "acme_failing");
        Assert.Contains("the port for the HTTP-01 challenge could not be bound", warning.Message);
        Assert.DoesNotContain("already in use", warning.Message);

        await occupant.DisposeAsync();
        Assert.Null(_rig.Listener!.TryBind());   // (the listener's own retry loop does this once a minute)
        _ = _rig.Listener.ServeAsync(default);
        H.Clock.Advance(TimeSpan.FromMinutes(6));
        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics);
        Assert.DoesNotContain((await banner.CheckAsync(default)).Warnings, w => w.Code.StartsWith("acme_", StringComparison.Ordinal));
    }

    protected async Task An_internationalized_name_is_ordered_and_certified_in_its_ASCII_formAsync()
    {
        string label = "bücher-" + Guid.NewGuid().ToString("N")[..8];
        string unicodeHost = label + ".acme-test.example";
        string asciiHost = new System.Globalization.IdnMapping().GetAscii(unicodeHost);
        Assert.StartsWith("xn--", asciiHost);
        Assert.Null(_rig.StartListener());

        Assert.True(await WithTimeout(_rig.Service(unicodeHost).CheckOnceAsync(default)), Diagnostics);

        var row = Assert.Single(await H.Storage.Config.GetCertificatesAsync(default));
        Assert.Equal([asciiHost], row.Subjects);
        var (leaf, _) = CertificateMaterial.Load(row, H.Secrets);
        Assert.Contains(asciiHost, CertificateMaterial.SubjectsOf(leaf));
        Assert.False(await _rig.Service(unicodeHost).CheckOnceAsync(default));   // the same name written in Unicode is not a change
    }
}

public sealed class AcmeHttp01OnSqlite : AcmeHttp01PebbleTests
{
    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-acme-http01-").FullName;

    protected override Task<(IStorage Storage, Func<Task>? Cleanup)> CreateStorageAsync() => Task.FromResult<(IStorage, Func<Task>?)>((
        SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _dir } }),
        () =>
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(_dir, recursive: true);
            return Task.CompletedTask;
        }));

    [PebbleFact]
    public Task Issues_a_certificate_over_HTTP_01_from_the_built_in_listener() => Issues_a_certificate_over_HTTP_01_from_the_built_in_listenerAsync();

    [PebbleFact]
    public Task Renewal_over_HTTP_01_replaces_the_row_and_reuses_the_account() => Renewal_over_HTTP_01_replaces_the_row_and_reuses_the_accountAsync();

    [PebbleFact]
    public Task Another_replica_answers_the_challenge_the_ordering_replica_published() => Another_replica_answers_the_challenge_the_ordering_replica_publishedAsync();

    [PebbleFact]
    public Task A_failed_validation_shows_in_the_banner_with_the_cas_reason_and_recovers() => A_failed_validation_shows_in_the_banner_with_the_cas_reason_and_recoversAsync();

    [PebbleFact]
    public Task A_port_that_cannot_be_bound_asks_the_ca_nothing_and_the_order_follows_when_it_can() => A_port_that_cannot_be_bound_asks_the_ca_nothing_and_the_order_follows_when_it_canAsync();

    [PebbleFact]
    public Task An_internationalized_name_is_ordered_and_certified_in_its_ASCII_form() => An_internationalized_name_is_ordered_and_certified_in_its_ASCII_formAsync();
}

/// <summary>The same flow with the challenge state in PostgreSQL (the replica that answers reads the token from the shared database).</summary>
public sealed class AcmeHttp01OnPostgres : AcmeHttp01PebbleTests
{
    protected override async Task<(IStorage Storage, Func<Task>? Cleanup)> CreateStorageAsync()
    {
        var database = await Mta.Storage.Postgres.Tests.PostgresTestServer.Instance.CreateDatabaseAsync();
        var options = new StorageOptions
        {
            Backend = StorageBackend.Postgres,
            Postgres = new PostgresOptions { OwnerConnectionString = database.ConnectionString, RuntimeConnectionString = database.ConnectionString },
        };
        return (Mta.Storage.Postgres.PostgresStorage.Create(options), async () => await database.DisposeAsync());
    }

    [PebbleFact(RequiresPostgres = true)]
    public Task Issues_a_certificate_over_HTTP_01_from_the_built_in_listener() => Issues_a_certificate_over_HTTP_01_from_the_built_in_listenerAsync();

    [PebbleFact(RequiresPostgres = true)]
    public Task Another_replica_answers_the_challenge_the_ordering_replica_published() => Another_replica_answers_the_challenge_the_ordering_replica_publishedAsync();

    [PebbleFact(RequiresPostgres = true)]
    public Task A_failed_validation_shows_in_the_banner_with_the_cas_reason_and_recovers() => A_failed_validation_shows_in_the_banner_with_the_cas_reason_and_recoversAsync();
}

/// <summary>
/// External account binding (RFC 8555 section 7.3.4) against a second Pebble that refuses accounts without it (<c>externalAccountBindingRequired</c>;
/// <c>EGGMAIL_TEST_ACME_EAB_DIRECTORY</c>). The orders use HTTP-01 through the built-in listener.
/// </summary>
[Collection(Http01PortCollection.Name)]
public sealed class AcmeExternalAccountBindingTests : IAsyncLifetime
{
    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-acme-eab-").FullName;
    private Http01Rig? _rig;

    public async Task InitializeAsync()
    {
        if (Pebble.UnavailableReason is not null || Pebble.EabDirectory is null)
        {
            return;
        }

        _rig = await Http01Rig.CreateAsync(SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _dir } }), directoryUrl: Pebble.EabDirectory);
        Assert.Null(_rig.StartListener());
    }

    public async Task DisposeAsync()
    {
        if (_rig is not null)
        {
            await _rig.DisposeAsync();
        }

        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, recursive: true);
    }

    private AcmeHarness H => _rig!.Harness;

    private static async Task<bool> WithTimeout(Task<bool> task) => await task.WaitAsync(TimeSpan.FromMinutes(2));

    [PebbleEabFact]
    public async Task An_account_is_registered_with_the_binding_and_the_certificate_issued()
    {
        H.Eab = (Pebble.EabKeyId, Pebble.EabHmacKey);
        string host = AcmeTestNames.Unique();

        Assert.True(await WithTimeout(_rig!.Service(host).CheckOnceAsync(default)), string.Join('\n', H.Log.Lines));

        Assert.Equal([host], Assert.Single(await H.Storage.Config.GetCertificatesAsync(default)).Subjects);
        Assert.NotNull(await H.Storage.Config.GetAcmeAccountAsync(H.DirectoryUrl, default));
        // The registration carried the binding: a JWS whose payload names the key id (HS256 over the account key).
        Assert.Contains(H.Http.Requests, r => r.Method == "POST" && r.Payload.Contains("externalAccountBinding", StringComparison.Ordinal));

        // A renewal does not repeat it: the account exists.
        int bindings = H.Http.Requests.Count(r => r.Payload.Contains("externalAccountBinding", StringComparison.Ordinal));
        H.UseRenewalInfo = false;
        var renewal = _rig.Service(host);
        TimeSpan lifetime = Assert.Single(await H.Storage.Config.GetCertificatesAsync(default)) is { } c ? c.NotAfter - c.NotBefore : default;
        H.Clock.Advance(lifetime * 0.7);
        Assert.True(await WithTimeout(renewal.CheckOnceAsync(default)), string.Join('\n', H.Log.Lines));
        Assert.Equal(bindings, H.Http.Requests.Count(r => r.Payload.Contains("externalAccountBinding", StringComparison.Ordinal)));
    }

    [PebbleEabFact]
    public async Task A_key_with_URL_safe_base64_characters_registers_an_account()
    {
        Assert.Contains('-', Pebble.EabHmacKeyUrlSafe);
        Assert.Contains('_', Pebble.EabHmacKeyUrlSafe);
        H.Eab = (Pebble.EabKeyIdUrlSafe, Pebble.EabHmacKeyUrlSafe);
        string host = AcmeTestNames.Unique();

        Assert.True(await WithTimeout(_rig!.Service(host).CheckOnceAsync(default)), string.Join('\n', H.Log.Lines));

        Assert.Equal([host], Assert.Single(await H.Storage.Config.GetCertificatesAsync(default)).Subjects);
        Assert.NotNull(await H.Storage.Config.GetAcmeAccountAsync(H.DirectoryUrl, default));
    }

    [PebbleEabFact]
    public async Task A_ca_that_requires_a_binding_is_named_when_none_is_configured()
    {
        string host = AcmeTestNames.Unique();

        Assert.False(await WithTimeout(_rig!.Service(host).CheckOnceAsync(default)));

        var renewal = Assert.Single(await H.Storage.Config.GetAcmeRenewalsAsync(default));
        Assert.Equal("failed", renewal.Status);
        Assert.Contains("external account binding", renewal.LastError);
        Assert.Contains("Acme:EabKeyId", renewal.LastError);
        Assert.Null(await H.Storage.Config.GetAcmeAccountAsync(H.DirectoryUrl, default));
    }

    [PebbleEabFact]
    public async Task A_key_the_ca_does_not_know_or_a_wrong_hmac_is_a_recorded_failure_and_no_account_is_kept()
    {
        string host = AcmeTestNames.Unique();

        H.Eab = ("no-such-key", Pebble.EabHmacKey);
        Assert.False(await WithTimeout(_rig!.Service(host).CheckOnceAsync(default)));
        var unknown = Assert.Single(await H.Storage.Config.GetAcmeRenewalsAsync(default));
        Assert.Equal("failed", unknown.Status);
        Assert.False(string.IsNullOrWhiteSpace(unknown.LastError));

        H.Clock.Advance(TimeSpan.FromMinutes(11));
        H.Eab = (Pebble.EabKeyId, "b10lLJs8l1GPIzsLP0s6pMt8O0XVGnfTaCeROxQM0BIt2XrJMDHJZBM5NuQmQJQH");   // kid-2's key for kid-1
        Assert.False(await WithTimeout(_rig.Service(host).CheckOnceAsync(default)));
        var wrong = Assert.Single(await H.Storage.Config.GetAcmeRenewalsAsync(default));
        Assert.Equal(("failed", 2), (wrong.Status, wrong.Failures));
        Assert.Null(await H.Storage.Config.GetAcmeAccountAsync(H.DirectoryUrl, default));

        H.Clock.Advance(TimeSpan.FromMinutes(21));
        H.Eab = (Pebble.EabKeyId, Pebble.EabHmacKey);
        Assert.True(await WithTimeout(_rig.Service(host).CheckOnceAsync(default)), string.Join('\n', H.Log.Lines));   // and the right key works
    }
}

/// <summary>
/// ACME on a real runtime with HTTP-01 (what <c>mta</c> does when only a host name and an email are configured): the runtime builds the built-in
/// listener itself. The first-run self-signed certificate serves while the order is pending and while it fails; the issued certificate replaces it.
/// </summary>
[Collection(Http01PortCollection.Name)]
public sealed class AcmeHttp01RuntimeTests : IAsyncLifetime
{
    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-acme-http01-rt-").FullName;
    private readonly string _host = AcmeTestNames.Unique();
    private readonly AdvanceableClock _clock = new(DateTimeOffset.UtcNow);
    private readonly RecordingLog _log = new();
    private readonly CancellationTokenSource _stop = new();
    private Mta.Host.Hosting.EggMailRuntime _runtime = null!;
    private readonly List<Task> _loops = [];

    public async Task InitializeAsync()
    {
        if (Pebble.UnavailableReason is not null)
        {
            return;
        }

        var config = new MtaConfig
        {
            Hostname = _host,
            Storage = new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _dir, StatsFlushInterval = TimeSpan.Zero } },
            Tls = new TlsSection { PollInterval = TimeSpan.FromMilliseconds(50), ReportingEnabled = false },
            Acme = new AcmeSection
            {
                Enabled = true, DirectoryUrl = Pebble.Directory, Email = "ops@acme-test.example", Domains = [_host], PropagationDelay = TimeSpan.Zero,
                Http01ListenPort = Pebble.HttpPort,   // no Cloudflare token: HTTP-01 on the built-in listener
            },
            Smtp = new SmtpSection { Listeners = new Dictionary<string, ListenerSection> { ["submission"] = new() { Port = 0, BindAddress = "127.0.0.1", Mode = Mta.Smtp.Server.ListenerMode.StartTls, AuthRequired = true } } },
        };
        var storage = SqliteStorage.Create(config.Storage, _clock);
        await storage.InitializeAsync(default);
        _runtime = await Mta.Host.Hosting.EggMailRuntime.CreateAsync(config, storage, _clock, _log, default, new Mta.Dns.StaticDnsResolver(), new CertesOrderRunner(Pebble.CreateTransport()));
    }

    public async Task DisposeAsync()
    {
        await _stop.CancelAsync();
        try { await Task.WhenAll(_loops).WaitAsync(TimeSpan.FromSeconds(30)); } catch (OperationCanceledException) { }
        if (Pebble.UnavailableReason is null)
        {
            await _runtime.DisposeAsync();
            await _runtime.Storage.DisposeAsync();
        }

        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, recursive: true);
    }

    private void StartLoops()
    {
        _loops.Add(Task.Run(() => _runtime.Certificates.RunAsync(_stop.Token)));
        _loops.Add(Task.Run(() => _runtime.Acme!.RunAsync(_stop.Token)));
        _loops.Add(Task.Run(() => _runtime.AcmeHttpListener!.RunAsync(_stop.Token)));
    }

    private static async Task WaitAsync(Func<Task<bool>> condition, string what, RecordingLog log)
    {
        var deadline = DateTime.UtcNow.AddMinutes(2);
        while (DateTime.UtcNow < deadline)
        {
            if (await condition())
            {
                return;
            }

            await Task.Delay(25);
        }

        throw new TimeoutException(what + ":\n" + string.Join('\n', log.Lines));
    }

    [PebbleFact]
    public async Task Host_name_and_email_only_the_runtime_answers_HTTP_01_itself_and_swaps_the_certificate_in()
    {
        Assert.NotNull(_runtime.AcmeHttpListener);   // built because no DNS credentials are configured
        Assert.True(_runtime.Certificates.UsingSelfSignedOnly);
        string selfSigned = _runtime.Certificates.GetCertificate(_host)!.Thumbprint;

        StartLoops();
        await WaitAsync(async () => (await _runtime.Storage.Config.GetCertificatesAsync(default)).Any(c => c.Source == "acme"), "no ACME certificate was stored", _log);
        var row = Assert.Single(await _runtime.Storage.Config.GetCertificatesAsync(default), c => c.Source == "acme");
        await WaitAsync(() => Task.FromResult(_runtime.Certificates.GetCertificate(_host)?.Thumbprint == row.Thumbprint), "the provider never served the ACME certificate", _log);

        Assert.False(_runtime.Certificates.UsingSelfSignedOnly);
        Assert.NotEqual(selfSigned, row.Thumbprint);
        await AcmeIssuanceTests.AssertTrustedByPebbleAsync(row);
        Assert.Contains(_log.Lines, l => l.Contains("answered the ACME HTTP-01 challenge", StringComparison.Ordinal));
    }

    [PebbleFact]
    public async Task While_the_port_cannot_be_bound_the_self_signed_certificate_keeps_serving_with_a_loud_log_and_a_banner()
    {
        string selfSigned = _runtime.Certificates.GetCertificate(_host)!.Thumbprint;
        await using var occupant = new AcmeHttpChallengeListener(new Http01Challenges(_runtime.Storage.Config), "::", Pebble.HttpPort);
        Assert.Null(occupant.TryBind());

        StartLoops();
        await WaitAsync(async () => (await _runtime.Storage.Config.GetAcmeRenewalsAsync(default)).Any(r => r.Status == "failed"), "the failure was not recorded", _log);

        Assert.True(_runtime.Certificates.UsingSelfSignedOnly);
        Assert.Equal(selfSigned, _runtime.Certificates.GetCertificate(_host)!.Thumbprint);
        Assert.Contains(_log.Lines, l => l.Contains("Error acme", StringComparison.Ordinal) && l.Contains("already in use", StringComparison.Ordinal));
        var warnings = (await new CertificateHealthContributor(_runtime.Storage, _clock, _runtime.Config).CheckAsync(default)).Warnings;
        var failing = Assert.Single(warnings, w => w.Code == "acme_failing");
        Assert.Contains("the port for the HTTP-01 challenge could not be bound", failing.Message);
        Assert.Contains("self-signed", failing.Message);
        Assert.Contains(warnings, w => w.Code == "self_signed_certificate");
    }
}
