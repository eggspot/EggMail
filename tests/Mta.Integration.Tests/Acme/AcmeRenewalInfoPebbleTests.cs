using Certes;
using Certes.Acme;
using Mta.Core;
using Mta.Host.Tls;
using Mta.Storage;
using Mta.Storage.Sqlite;

namespace Mta.Integration.Tests.Acme;

/// <summary>
/// ACME Renewal Information (ARI, RFC 9773) against Pebble: the certificate id is accepted by the CA, its window is stored in the renewal row and
/// followed (earlier and later than the lifetime rule, at once for a window in the past), a failing answer falls back to the lifetime rule, and
/// the renewal order names the certificate it replaces. The renewal-information answers are set through Pebble's management API.
/// </summary>
public abstract class AcmeRenewalInfoPebbleTests : IAsyncLifetime
{
    private AcmeHarness _h = null!;

    protected abstract Task<(IStorage Storage, Func<Task>? Cleanup)> CreateStorageAsync();

    public async Task InitializeAsync()
    {
        var (storage, cleanup) = await CreateStorageAsync();
        _h = await AcmeHarness.CreateAsync(storage, cleanup);
    }

    public async Task DisposeAsync() => await _h.DisposeAsync();

    private string Diagnostics => string.Join('\n', _h.Log.Lines);

    private static async Task<bool> WithTimeout(Task<bool> task) => await task.WaitAsync(TimeSpan.FromMinutes(2));

    /// <summary>
    /// Orders the first certificate for a fresh name (the one order of the recorded transport), one that Pebble can look up when it is named in <c>replaces</c>: a certificate
    /// with a padded serial (<see cref="Pebble.HasPaddedSerial"/>, about 1 in 250) is replaced by another one first, through a transport that is not recorded. The service
    /// always picks the start of a suggested window (random number 0).
    /// </summary>
    private async Task<(AcmeRenewalService Service, string Host, CertificateRecord Cert)> IssueAsync()
    {
        string host = AcmeTestNames.Unique();
        var dns = new ChallengeServerDns();
        var service = _h.CreateService(dns, [host], random: () => 0);
        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics);
        var cert = Assert.Single(await _h.Storage.Config.GetCertificatesAsync(default));
        if (Pebble.HasPaddedSerial(cert.ChainPem))
        {
            using var unrecorded = new RecordingHandler(Pebble.CreateTransport());
            var reissue = _h.CreateService(dns, [host], http: unrecorded, random: () => 0);
            for (int attempt = 1; Pebble.HasPaddedSerial(cert.ChainPem); attempt++)
            {
                Assert.True(attempt <= 20, "twenty certificates in a row with a padded serial: Pebble's serials are not what this assumes");
                Assert.True(await WithTimeout(reissue.RequestAsync([host], default)), Diagnostics);
                cert = Assert.Single(await _h.Storage.Config.GetCertificatesAsync(default));
            }
        }

        await WaitUntilThePebbleCanReplaceAsync(host, cert);
        return (service, host, cert);
    }

    /// <summary>
    /// Pebble 2.10 marks an order valid (and lets the client download the certificate) before it records which order issued the certificate, in a goroutine of its own:
    /// an order that names the certificate in <c>replaces</c> in that moment gets a 500 ("could not find order resulting in the given certificate serial number").
    /// The tests that follow the renewal order must not depend on that race, so this asks for such an order (through a transport that is not recorded, with the account of the
    /// service; the order is never finalized, so it replaces nothing) until Pebble answers it. The service itself falls back to a plain order on such a 500 (unit-tested).
    /// </summary>
    private async Task WaitUntilThePebbleCanReplaceAsync(string host, CertificateRecord cert)
    {
        var account = await _h.Storage.Config.GetAcmeAccountAsync(_h.DirectoryUrl, default);
        string accountKey = System.Text.Encoding.UTF8.GetString(_h.Secrets.Unprotect(account!.AccountKeyProtected, SecretPurposes.AcmeAccountKey));
        using var transport = Pebble.CreateTransport();
        using var http = Pebble.NewClient(transport);
        var directory = new Uri(_h.DirectoryUrl);
        var acme = new AcmeContext(directory, KeyFactory.FromPem(accountKey), new AcmeHttpClient(directory, http));
        string certificateId = new CertificateChain(cert.ChainPem).GetRenewalInfoCertificateId();
        var deadline = DateTime.UtcNow.AddSeconds(30);   // a generous bound for a goroutine; polling asserts nothing about time
        while (true)
        {
            try
            {
                await acme.NewReplacementOrder([host], certificateId);
                return;
            }
            catch (AcmeRequestException ex) when (DateTime.UtcNow < deadline && (int)(ex.Error?.Status ?? 0) == 500)
            {
                await Task.Delay(20);
            }
        }
    }

    private async Task<AcmeRenewalAdvice?> AdviceAsync(CertificateRecord cert) =>
        AcmeRenewalAdvice.Parse(Assert.Single(await _h.Storage.Config.GetAcmeRenewalsAsync(default)).AriJson, cert.Thumbprint);

    /// <summary>The renewal orders (POSTs to newOrder) that named a certificate they replace.</summary>
    private int OrdersNamingAReplacedCertificate() => _h.Http.CountPosts(_h.Endpoints.NewOrder, p => p.Contains("\"replaces\"", StringComparison.Ordinal));

    // ---------------------------------------------------------------------------------------------------------------------------------

    protected async Task The_window_of_the_CA_is_fetched_stored_and_followed_by_the_renewal_orderAsync()
    {
        var (service, _, cert) = await IssueAsync();
        Assert.Equal(1, _h.Http.CountPosts(_h.Endpoints.NewOrder));
        Assert.Equal(0, OrdersNamingAReplacedCertificate()); // a first certificate replaces nothing
        TimeSpan lifetime = cert.NotAfter - cert.NotBefore;

        // The first check after issuing asks Pebble (this also proves that the certificate id AKI.serial is the one the CA expects).
        Assert.False(await service.CheckOnceAsync(default));
        var advice = await AdviceAsync(cert);
        Assert.NotNull(advice);
        Assert.True(advice.HasWindow, advice.Error);
        Assert.Null(advice.Error);
        Assert.False(advice.DirectoryHasNoRenewalInfo);
        Assert.InRange(advice.WindowStart!.Value, cert.NotBefore.AddSeconds(-1), cert.NotAfter);
        Assert.InRange(advice.WindowEnd!.Value, advice.WindowStart.Value, cert.NotAfter.AddSeconds(1));
        Assert.Equal(advice.WindowStart, advice.RenewAt); // random number 0: the start of the window
        Assert.True(advice.NextCheckAt > advice.CheckedAt); // Pebble asks for a 6 hour Retry-After

        // Pebble advises a window around two thirds of the lifetime. Not due at 40 %, due at 70 %, by the CA's window.
        _h.Clock.Advance(lifetime * 0.4);
        Assert.False(await service.CheckOnceAsync(default));
        _h.Clock.Advance(lifetime * 0.3);
        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics);

        // The renewal order named the certificate it replaces, and the CA accepted it (a rejected link would have fallen back to a plain order).
        Assert.Equal(1, OrdersNamingAReplacedCertificate());
        Assert.Equal(2, _h.Http.CountPosts(_h.Endpoints.NewOrder));
        var renewed = Assert.Single(await _h.Storage.Config.GetCertificatesAsync(default));
        Assert.Equal(cert.Id, renewed.Id);
        Assert.NotEqual(cert.Thumbprint, renewed.Thumbprint);
        Assert.Null(await AdviceAsync(renewed)); // advice belongs to the certificate it was given for
        Assert.Equal("issued", Assert.Single(await _h.Storage.Config.GetAcmeRenewalsAsync(default)).Status);
    }

    protected async Task A_window_in_the_future_overrides_the_lifetime_ruleAsync()
    {
        var (service, _, cert) = await IssueAsync();
        var now = _h.Clock.UtcNow;
        await Pebble.SetRenewalInfoAsync(cert.ChainPem, Pebble.Window(now.AddDays(5), now.AddDays(6)));

        Assert.False(await service.CheckOnceAsync(default));
        var advice = await AdviceAsync(cert);
        Assert.Equal(now.AddDays(5).ToUnixTimeSeconds(), advice!.RenewAt!.Value.ToUnixTimeSeconds());

        _h.Clock.Advance(TimeSpan.FromDays(1));
        Assert.False(await service.CheckOnceAsync(default));

        // Four and a half days: Pebble issues 6 or 90 day certificates at random, and the lifetime rule (a third left) would renew the 6 day ones by now,
        // the 90 day ones in two months. The CA's window has not opened, so nothing is ordered.
        _h.Clock.Advance(TimeSpan.FromDays(3.5));
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(1, _h.Http.CountPosts(_h.Endpoints.NewOrder));

        // Five days and an hour: the window has opened.
        _h.Clock.Advance(TimeSpan.FromDays(0.5) + TimeSpan.FromHours(1));
        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics);
        Assert.Equal(1, OrdersNamingAReplacedCertificate());
        Assert.NotEqual(cert.Thumbprint, Assert.Single(await _h.Storage.Config.GetCertificatesAsync(default)).Thumbprint);
    }

    protected async Task A_window_in_the_past_renews_the_certificate_at_onceAsync()
    {
        var (service, _, cert) = await IssueAsync();
        var now = _h.Clock.UtcNow;
        await Pebble.SetRenewalInfoAsync(cert.ChainPem, Pebble.Window(now.AddHours(-2), now.AddHours(-1))); // what Pebble answers for a revoked certificate

        // A certificate minutes old is not renewed on advice alone (a CA that always says "now" must not cause an order at every check) ...
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(1, _h.Http.CountPosts(_h.Endpoints.NewOrder));

        // ... an old enough one is, at the next check.
        _h.Clock.Advance(AcmeRenewalSchedule.MinimumAge(cert.NotAfter - cert.NotBefore) + TimeSpan.FromHours(1));
        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics);

        Assert.Equal(1, OrdersNamingAReplacedCertificate());
        var renewed = Assert.Single(await _h.Storage.Config.GetCertificatesAsync(default));
        Assert.NotEqual(cert.Thumbprint, renewed.Thumbprint);
        Assert.Equal(cert.Id, renewed.Id);
    }

    protected async Task Unusable_advice_falls_back_to_the_lifetime_ruleAsync()
    {
        var (service, _, cert) = await IssueAsync();
        TimeSpan lifetime = cert.NotAfter - cert.NotBefore;
        await Pebble.SetRenewalInfoAsync(cert.ChainPem, "this is not json {");

        Assert.False(await service.CheckOnceAsync(default));
        var advice = await AdviceAsync(cert);
        Assert.False(advice!.HasWindow);
        Assert.False(string.IsNullOrEmpty(advice.Error));

        // Asked again after an hour, still unusable; the lifetime rule renews when a third is left (here at 70 %).
        _h.Clock.Advance(lifetime * 0.7);
        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics);
        Assert.Equal(2, _h.Http.CountPosts(_h.Endpoints.NewOrder));
    }

    protected async Task A_replacement_the_CA_refuses_is_ordered_as_a_plain_orderAsync()
    {
        var (_, host, cert) = await IssueAsync();
        using var dns = new ChallengeServerDns();
        var runner = new CertesOrderRunner(_h.Http);
        var account = await _h.Storage.Config.GetAcmeAccountAsync(_h.DirectoryUrl, default);
        string accountKey = System.Text.Encoding.UTF8.GetString(_h.Secrets.Unprotect(account!.AccountKeyProtected, SecretPurposes.AcmeAccountKey));
        AcmeOrderRequest Request() => new(_h.DirectoryUrl, "ops@acme-test.example", [host], accountKey, TimeSpan.Zero, ReplacesCertificatePem: cert.ChainPem);

        await runner.IssueAsync(Request(), dns, default).WaitAsync(TimeSpan.FromMinutes(2));
        int ordersBefore = _h.Http.CountPosts(_h.Endpoints.NewOrder);
        int namingBefore = OrdersNamingAReplacedCertificate();

        // The certificate has now been replaced by the order above: the CA refuses (alreadyReplaced) a second order for the same one. The renewal
        // must not fail because of that: the order is repeated without the link and succeeds.
        var second = await runner.IssueAsync(Request(), dns, default).WaitAsync(TimeSpan.FromMinutes(2));

        Assert.NotNull(second.ChainPem);
        Assert.Equal(ordersBefore + 2, _h.Http.CountPosts(_h.Endpoints.NewOrder));
        Assert.Equal(namingBefore + 1, OrdersNamingAReplacedCertificate());
    }
}

public sealed class AcmeRenewalInfoOnSqlite : AcmeRenewalInfoPebbleTests
{
    protected override Task<(IStorage Storage, Func<Task>? Cleanup)> CreateStorageAsync()
    {
        string dir = Directory.CreateTempSubdirectory("eggmail-ari-").FullName;
        IStorage storage = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = dir } });
        return Task.FromResult<(IStorage, Func<Task>?)>((storage, () => { Directory.Delete(dir, recursive: true); return Task.CompletedTask; }));
    }

    [PebbleFact]
    public Task The_window_of_the_CA_is_fetched_stored_and_followed_by_the_renewal_order() => The_window_of_the_CA_is_fetched_stored_and_followed_by_the_renewal_orderAsync();

    [PebbleFact]
    public Task A_window_in_the_future_overrides_the_lifetime_rule() => A_window_in_the_future_overrides_the_lifetime_ruleAsync();

    [PebbleFact]
    public Task A_window_in_the_past_renews_the_certificate_at_once() => A_window_in_the_past_renews_the_certificate_at_onceAsync();

    [PebbleFact]
    public Task Unusable_advice_falls_back_to_the_lifetime_rule() => Unusable_advice_falls_back_to_the_lifetime_ruleAsync();

    [PebbleFact]
    public Task A_replacement_the_CA_refuses_is_ordered_as_a_plain_order() => A_replacement_the_CA_refuses_is_ordered_as_a_plain_orderAsync();
}

/// <summary>The advice is stored in the renewal row of either backend.</summary>
public sealed class AcmeRenewalInfoOnPostgres : AcmeRenewalInfoPebbleTests
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
    public Task The_window_of_the_CA_is_fetched_stored_and_followed_by_the_renewal_order() => The_window_of_the_CA_is_fetched_stored_and_followed_by_the_renewal_orderAsync();

    [PebbleFact(RequiresPostgres = true)]
    public Task A_window_in_the_past_renews_the_certificate_at_once() => A_window_in_the_past_renews_the_certificate_at_onceAsync();
}
