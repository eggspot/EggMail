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

    /// <summary>Orders the first certificate for a fresh name. The service always picks the start of a suggested window (random number 0).</summary>
    private async Task<(AcmeRenewalService Service, string Host, CertificateRecord Cert)> IssueAsync()
    {
        string host = AcmeTestNames.Unique();
        var dns = new ChallengeServerDns();
        var service = _h.CreateService(dns, [host], random: () => 0);
        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics);
        return (service, host, Assert.Single(await _h.Storage.Config.GetCertificatesAsync(default)));
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
        Assert.False(advice.Unsupported);
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
        await Pebble.SetRenewalInfoAsync(cert.ChainPem, Pebble.Window(now.AddDays(2), now.AddDays(3)));

        Assert.False(await service.CheckOnceAsync(default));
        var advice = await AdviceAsync(cert);
        Assert.Equal(now.AddDays(2).ToUnixTimeSeconds(), advice!.RenewAt!.Value.ToUnixTimeSeconds());

        _h.Clock.Advance(TimeSpan.FromDays(1));
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(1, _h.Http.CountPosts(_h.Endpoints.NewOrder));

        // Two days and an hour: the CA's window has opened. The lifetime rule would not renew a 90 day certificate for another 58 days.
        _h.Clock.Advance(TimeSpan.FromDays(1) + TimeSpan.FromHours(1));
        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics);
        Assert.Equal(1, OrdersNamingAReplacedCertificate());
        Assert.NotEqual(cert.Thumbprint, Assert.Single(await _h.Storage.Config.GetCertificatesAsync(default)).Thumbprint);
    }

    protected async Task A_window_in_the_past_renews_the_certificate_at_onceAsync()
    {
        var (service, _, cert) = await IssueAsync();
        var now = _h.Clock.UtcNow;
        await Pebble.SetRenewalInfoAsync(cert.ChainPem, Pebble.Window(now.AddHours(-2), now.AddHours(-1))); // what Pebble answers for a revoked certificate

        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics); // no time has passed

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
