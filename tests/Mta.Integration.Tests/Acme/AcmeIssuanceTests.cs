using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certes;
using Mta.Core;
using Mta.Host.Tls;
using Mta.Storage;
using Mta.Storage.Sqlite;

namespace Mta.Integration.Tests.Acme;

/// <summary>
/// The real issuance and renewal flow (<see cref="AcmeRenewalService"/> with <see cref="CertesOrderRunner"/> and the DNS-01 challenge) against
/// the Pebble test CA: new order, challenge, finalize, certificate stored encrypted, renewal replaces the row, failure and back-off paths,
/// account key persistence. Skipped unless <c>EGGMAIL_TEST_ACME_DIRECTORY</c> is set (CI starts Pebble; docs/development.md).
/// </summary>
public abstract class AcmeIssuanceTests : IAsyncLifetime
{
    private AcmeHarness _h = null!;

    protected abstract Task<(IStorage Storage, Func<Task>? Cleanup)> CreateStorageAsync();

    public async Task InitializeAsync()
    {
        var (storage, cleanup) = await CreateStorageAsync();
        _h = await AcmeHarness.CreateAsync(storage, cleanup);
    }

    public async Task DisposeAsync() => await _h.DisposeAsync();

    /// <summary>The stores keep timestamps to the millisecond.</summary>
    internal static void AssertSameMillisecond(DateTimeOffset expected, DateTimeOffset? actual) =>
        Assert.Equal(expected.ToUnixTimeMilliseconds(), actual?.ToUnixTimeMilliseconds());

    private string Diagnostics => string.Join('\n', _h.Log.Lines);

    private static async Task<bool> WithTimeout(Task<bool> task) => await task.WaitAsync(TimeSpan.FromMinutes(2));

    /// <summary>Does the stored chain (leaf plus the intermediate the CA sent) lead to the CA's root?</summary>
    internal static async Task AssertTrustedByPebbleAsync(CertificateRecord row)
    {
        var presented = new X509Certificate2Collection();
        presented.ImportFromPem(row.ChainPem);
        Assert.Equal(2, presented.Count); // leaf + one intermediate: the intermediate must be stored to be served
        var roots = await Pebble.FetchRootsAsync();
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ExtraStore.Add(presented[1]);
        Assert.True(chain.Build(presented[0]), string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation)));
    }

    // ---------------------------------------------------------------------------------------------------------------------------------

    protected async Task Issues_a_certificate_for_a_new_order_and_stores_it_encryptedAsync()
    {
        string host = AcmeTestNames.Unique();
        using var dns = new ChallengeServerDns();
        var service = _h.CreateService(dns, [host]);

        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics);

        // The certificate row: one, active, ACME, for exactly the requested name, with the chain the CA sent.
        var row = Assert.Single(await _h.Storage.Config.GetCertificatesAsync(default));
        Assert.Equal("default", row.Name);
        Assert.Equal("acme", row.Source);
        Assert.True(row.Active);
        Assert.Equal([host], row.Subjects);
        await AssertTrustedByPebbleAsync(row);

        // The private key is only in the database as ciphertext, and it is the key of the issued leaf.
        byte[] pkcs8 = _h.Secrets.Unprotect(row.PrivateKeyProtected, SecretPurposes.TlsPrivateKey);
        Assert.False(row.PrivateKeyProtected.AsSpan().IndexOf(pkcs8) >= 0, "the private key is stored in clear");
        Assert.DoesNotContain("PRIVATE KEY", row.ChainPem);
        var (leaf, intermediates) = CertificateMaterial.Load(row, _h.Secrets);
        Assert.True(leaf.HasPrivateKey);
        Assert.Single(intermediates);
        Assert.Equal(row.Thumbprint, leaf.Thumbprint);
        Assert.Contains(host, CertificateMaterial.SubjectsOf(leaf));
        using (var ecdsa = leaf.GetECDsaPrivateKey())
        {
            Assert.NotNull(ecdsa);
        }

        // The DNS-01 record was published at the challenge name and removed afterwards.
        Assert.Equal("_acme-challenge." + host, Assert.Single(dns.Created).Fqdn);
        Assert.Equal(["_acme-challenge." + host], dns.Deleted);

        // Renewal bookkeeping.
        var renewal = Assert.Single(await _h.Storage.Config.GetAcmeRenewalsAsync(default));
        Assert.Equal(("default", "issued", 0), (renewal.CertificateName, renewal.Status, renewal.Failures));
        Assert.Null(renewal.LastError);
        Assert.Null(renewal.NextAttemptAt);

        // Nothing to do while the certificate is fresh.
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(1, _h.Http.CountPosts(_h.Endpoints.NewOrder));
    }

    protected async Task A_wildcard_and_its_base_name_share_one_challenge_nameAsync()
    {
        string zone = AcmeTestNames.Unique("zone");
        using var dns = new ChallengeServerDns();
        var service = _h.CreateService(dns, ["*." + zone, zone]);

        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics);

        var row = Assert.Single(await _h.Storage.Config.GetCertificatesAsync(default));
        Assert.Equal(["*." + zone, zone], row.Subjects.Order(StringComparer.Ordinal));
        await AssertTrustedByPebbleAsync(row);
        var (leaf, _) = CertificateMaterial.Load(row, _h.Secrets);
        Assert.Equal(["*." + zone, zone], CertificateMaterial.SubjectsOf(leaf).Order(StringComparer.Ordinal));
        // Two authorizations, one TXT name, two different values.
        Assert.Equal(2, dns.Created.Count);
        Assert.Single(dns.Created.Select(c => c.Fqdn).Distinct());
        Assert.Equal(2, dns.Created.Select(c => c.Value).Distinct().Count());
        Assert.Equal("_acme-challenge." + zone, dns.Created.First().Fqdn);
    }

    protected async Task The_account_key_is_stored_encrypted_and_reused_after_a_restartAsync()
    {
        string first = AcmeTestNames.Unique();
        string second = AcmeTestNames.Unique();
        using var dns = new ChallengeServerDns();
        Assert.True(await WithTimeout(_h.CreateService(dns, [first]).CheckOnceAsync(default)), Diagnostics);

        var account = await _h.Storage.Config.GetAcmeAccountAsync(_h.DirectoryUrl, default);
        Assert.NotNull(account);
        Assert.False(string.IsNullOrEmpty(account.AccountUrl));
        Assert.Equal("ops@acme-test.example", account.Email);
        byte[] pem = _h.Secrets.Unprotect(account.AccountKeyProtected, SecretPurposes.AcmeAccountKey);
        Assert.StartsWith("-----BEGIN", System.Text.Encoding.ASCII.GetString(pem));
        Assert.False(account.AccountKeyProtected.AsSpan().IndexOf(pem) >= 0, "the account key is stored in clear");
        Assert.NotNull(KeyFactory.FromPem(System.Text.Encoding.UTF8.GetString(pem))); // it is a usable key
        Assert.Equal(1, Registrations(_h.Http));

        // "Restart": a new service and runner with nothing in memory; the names changed, so a new certificate is ordered with the same account.
        using var restarted = new RecordingHandler(Pebble.CreateTransport());
        Assert.True(await WithTimeout(_h.CreateService(dns, [first, second], restarted).CheckOnceAsync(default)), Diagnostics);
        Assert.Equal(0, Registrations(restarted)); // no second account was registered
        Assert.Equal(1, restarted.CountPosts(_h.Endpoints.NewOrder));
        // The first name's authorization was still valid (PEBBLE_AUTHZREUSE=100) and was not challenged again; only the new name was.
        Assert.Equal(["_acme-challenge." + first, "_acme-challenge." + second], dns.Created.Select(c => c.Fqdn));
        var sameAccount = await _h.Storage.Config.GetAcmeAccountAsync(_h.DirectoryUrl, default);
        Assert.Equal(account.Id, sameAccount!.Id);
        Assert.Equal(account.AccountKeyProtected, sameAccount.AccountKeyProtected);

        // The changed set of names replaced the row of the certificate instead of leaving the old one active next to it.
        var row = Assert.Single(await _h.Storage.Config.GetCertificatesAsync(default));
        Assert.Equal(new[] { first, second }.Order(StringComparer.Ordinal), row.Subjects.Order(StringComparer.Ordinal));
    }

    /// <summary>Account registrations: POSTs to newAccount that are not look-ups of an existing account.</summary>
    private int Registrations(RecordingHandler http) => http.CountPosts(_h.Endpoints.NewAccount, payload => !payload.Contains("onlyReturnExisting", StringComparison.Ordinal));

    protected async Task Renewal_replaces_the_row_when_a_third_of_the_lifetime_is_leftAsync()
    {
        _h.UseRenewalInfo = false; // the lifetime rule; the CA's advice is tested in AcmeRenewalInfoPebbleTests
        string host = AcmeTestNames.Unique();
        using var dns = new ChallengeServerDns();
        var service = _h.CreateService(dns, [host]);
        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics);
        var before = Assert.Single(await _h.Storage.Config.GetCertificatesAsync(default));
        long versionBefore = await _h.Storage.Config.GetCertificateVersionAsync(default);
        // Pebble picks one of its profiles at random for an order (90 days or 6 days), so the schedule is taken from the certificate itself.
        TimeSpan lifetime = before.NotAfter - before.NotBefore;
        Assert.True(lifetime > TimeSpan.FromDays(1), lifetime.ToString());

        _h.Clock.Advance(lifetime * 0.6);
        Assert.False(await service.CheckOnceAsync(default)); // still more than a third left
        Assert.Equal(1, _h.Http.CountPosts(_h.Endpoints.NewOrder));

        _h.Clock.Advance(lifetime * 0.1);
        Assert.True(await WithTimeout(service.CheckOnceAsync(default)), Diagnostics);

        var after = Assert.Single(await _h.Storage.Config.GetCertificatesAsync(default)); // replaced, not added
        Assert.Equal(before.Id, after.Id);
        Assert.NotEqual(before.Thumbprint, after.Thumbprint);
        Assert.True(after.NotBefore >= before.NotBefore); // a newer certificate (its length may differ: Pebble picks a profile at random)
        Assert.True(await _h.Storage.Config.GetCertificateVersionAsync(default) > versionBefore); // pollers see the change
        Assert.True(after.Active);
        Assert.Equal(2, _h.Http.CountPosts(_h.Endpoints.NewOrder));
        Assert.Equal(1, Registrations(_h.Http)); // same account for the renewal
        // The CA (run with PEBBLE_AUTHZREUSE=100) handed back the still valid authorization of the first order: nothing was proven again.
        Assert.Single(dns.Created);
        await AssertTrustedByPebbleAsync(after);
    }

    protected async Task A_failed_validation_is_recorded_backs_off_keeps_the_account_and_recoversAsync()
    {
        string host = AcmeTestNames.Unique();
        var silent = new SilentDns(); // never publishes the TXT record
        var failing = _h.CreateService(silent, [host]);

        Assert.False(await WithTimeout(failing.CheckOnceAsync(default)));

        Assert.Empty(await _h.Storage.Config.GetCertificatesAsync(default));
        var renewal = Assert.Single(await _h.Storage.Config.GetAcmeRenewalsAsync(default));
        Assert.Equal("failed", renewal.Status);
        Assert.Equal(1, renewal.Failures);
        AssertSameMillisecond(_h.Clock.UtcNow + AcmeRenewalService.Backoff(1), renewal.NextAttemptAt);
        Assert.Contains(host, renewal.LastError);
        Assert.Contains("Invalid", renewal.LastError);
        // The CA's own explanation reaches the operator.
        Assert.True(renewal.LastError!.Length > $"Authorization for {host} ended as Invalid".Length, renewal.LastError);

        // The account was registered and stored although the order failed, so retries do not register new ones.
        Assert.NotNull(await _h.Storage.Config.GetAcmeAccountAsync(_h.DirectoryUrl, default));
        Assert.Equal(1, Registrations(_h.Http));

        // Inside the back-off window nothing is ordered.
        Assert.False(await failing.CheckOnceAsync(default));
        Assert.Equal(1, silent.Requests);
        Assert.Equal(1, _h.Http.CountPosts(_h.Endpoints.NewOrder));

        // After it, a working DNS provider gets the certificate, the failure state is cleared, and the account is the same.
        _h.Clock.Advance(TimeSpan.FromMinutes(11));
        using var dns = new ChallengeServerDns();
        Assert.True(await WithTimeout(_h.CreateService(dns, [host]).CheckOnceAsync(default)), Diagnostics);
        renewal = Assert.Single(await _h.Storage.Config.GetAcmeRenewalsAsync(default));
        Assert.Equal(("issued", 0), (renewal.Status, renewal.Failures));
        Assert.Null(renewal.LastError);
        Assert.Null(renewal.NextAttemptAt);
        Assert.Single(await _h.Storage.Config.GetCertificatesAsync(default));
        Assert.Equal(1, Registrations(_h.Http));
    }

    protected async Task Back_off_grows_with_consecutive_failuresAsync()
    {
        string host = AcmeTestNames.Unique();
        var silent = new SilentDns();
        var service = _h.CreateService(silent, [host]);
        for (int failures = 1; failures <= 3; failures++)
        {
            Assert.False(await WithTimeout(service.CheckOnceAsync(default)));
            var renewal = Assert.Single(await _h.Storage.Config.GetAcmeRenewalsAsync(default));
            Assert.Equal(failures, renewal.Failures);
            AssertSameMillisecond(_h.Clock.UtcNow + AcmeRenewalService.Backoff(failures), renewal.NextAttemptAt);
            _h.Clock.Advance(AcmeRenewalService.Backoff(failures) + TimeSpan.FromSeconds(1));
        }

        Assert.Equal(TimeSpan.FromMinutes(40), AcmeRenewalService.Backoff(3));
        Assert.Equal(3, silent.Requests);
        // One account for all three attempts.
        Assert.Equal(1, Registrations(_h.Http));
    }

    protected async Task An_identifier_the_ca_refuses_is_a_recorded_failureAsync()
    {
        using var dns = new ChallengeServerDns();
        var service = _h.CreateService(dns, ["blocked-domain.example"]); // on Pebble's domain blocklist
        Assert.False(await WithTimeout(service.CheckOnceAsync(default)));
        var renewal = Assert.Single(await _h.Storage.Config.GetAcmeRenewalsAsync(default));
        Assert.Equal("failed", renewal.Status);
        Assert.StartsWith("ACME server error:", renewal.LastError);
        Assert.Contains("blocked-domain.example", renewal.LastError);
        Assert.Empty(dns.Created); // refused before any challenge
        Assert.Empty(await _h.Storage.Config.GetCertificatesAsync(default));
    }

    protected async Task Only_one_replica_orders_at_a_time_and_a_dashboard_request_bypasses_the_back_offAsync()
    {
        string host = AcmeTestNames.Unique();
        var gated = new GatedDns();
        var first = _h.CreateService(gated, [host]);
        Task<bool> ordering = Task.Run(() => first.CheckOnceAsync(default));
        await gated.Entered.Task.WaitAsync(TimeSpan.FromMinutes(1));

        // A second replica (own runner, same store) sees the lease and stays away: it neither asks the CA nor publishes anything.
        var silent = new SilentDns();
        using var otherReplica = new RecordingHandler(Pebble.CreateTransport());
        var second = _h.CreateService(silent, [host], otherReplica);
        Assert.Equal("ordering", Assert.Single(await _h.Storage.Config.GetAcmeRenewalsAsync(default)).Status);
        Assert.False(await second.CheckOnceAsync(default));
        Assert.Equal(0, silent.Requests);
        Assert.Empty(otherReplica.Requests);

        gated.Release.SetResult();
        Assert.True(await WithTimeout(ordering), Diagnostics);
        Assert.Equal("issued", Assert.Single(await _h.Storage.Config.GetAcmeRenewalsAsync(default)).Status);

        // The lease is released: the second replica now finds a fresh certificate and still does nothing.
        Assert.False(await second.CheckOnceAsync(default));
        // It may ask the CA about renewal timing (GET), but orders nothing and registers nothing.
        Assert.Equal(0, otherReplica.CountPosts(_h.Endpoints.NewOrder));
        Assert.Equal(0, otherReplica.CountPosts(_h.Endpoints.NewAccount));
        gated.Dispose();
    }

    protected async Task A_dashboard_requested_certificate_is_ordered_inside_the_back_off_windowAsync()
    {
        string host = AcmeTestNames.Unique();
        Assert.False(await WithTimeout(_h.CreateService(new SilentDns(), [host]).CheckOnceAsync(default)));
        Assert.Equal(1, Assert.Single(await _h.Storage.Config.GetAcmeRenewalsAsync(default)).Failures);

        using var dns = new ChallengeServerDns();
        var service = _h.CreateService(dns, [host]);
        Assert.False(await service.CheckOnceAsync(default)); // scheduled renewal respects the back-off
        Assert.True(await WithTimeout(service.RequestAsync([host], default)), Diagnostics); // "request a certificate" does not
        Assert.Equal("issued", Assert.Single(await _h.Storage.Config.GetAcmeRenewalsAsync(default)).Status);
    }

    /// <summary>Holds the order inside the challenge step until the test lets go.</summary>
    private sealed class GatedDns : ChallengeServerDns
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override async ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken cancellationToken)
        {
            Entered.TrySetResult();
            await Release.Task.WaitAsync(cancellationToken);
            return await base.CreateTxtAsync(fqdn, value, cancellationToken);
        }
    }
}

public sealed class AcmeIssuanceOnSqlite : AcmeIssuanceTests
{
    protected override Task<(IStorage Storage, Func<Task>? Cleanup)> CreateStorageAsync()
    {
        string dir = Directory.CreateTempSubdirectory("eggmail-acme-").FullName;
        IStorage storage = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = dir } });
        return Task.FromResult<(IStorage, Func<Task>?)>((storage, () => { Directory.Delete(dir, recursive: true); return Task.CompletedTask; }));
    }

    [PebbleFact]
    public Task Issues_a_certificate_for_a_new_order_and_stores_it_encrypted() => Issues_a_certificate_for_a_new_order_and_stores_it_encryptedAsync();

    [PebbleFact]
    public Task A_wildcard_and_its_base_name_share_one_challenge_name() => A_wildcard_and_its_base_name_share_one_challenge_nameAsync();

    [PebbleFact]
    public Task The_account_key_is_stored_encrypted_and_reused_after_a_restart() => The_account_key_is_stored_encrypted_and_reused_after_a_restartAsync();

    [PebbleFact]
    public Task Renewal_replaces_the_row_when_a_third_of_the_lifetime_is_left() => Renewal_replaces_the_row_when_a_third_of_the_lifetime_is_leftAsync();

    [PebbleFact]
    public Task A_failed_validation_is_recorded_backs_off_keeps_the_account_and_recovers() => A_failed_validation_is_recorded_backs_off_keeps_the_account_and_recoversAsync();

    [PebbleFact]
    public Task Back_off_grows_with_consecutive_failures() => Back_off_grows_with_consecutive_failuresAsync();

    [PebbleFact]
    public Task An_identifier_the_ca_refuses_is_a_recorded_failure() => An_identifier_the_ca_refuses_is_a_recorded_failureAsync();

    [PebbleFact]
    public Task Only_one_replica_orders_at_a_time_and_a_dashboard_request_bypasses_the_back_off() => Only_one_replica_orders_at_a_time_and_a_dashboard_request_bypasses_the_back_offAsync();

    [PebbleFact]
    public Task A_dashboard_requested_certificate_is_ordered_inside_the_back_off_window() => A_dashboard_requested_certificate_is_ordered_inside_the_back_off_windowAsync();
}

/// <summary>The same flow on the PostgreSQL config store (lease, account and certificate rows behave identically on both backends).</summary>
public sealed class AcmeIssuanceOnPostgres : AcmeIssuanceTests
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
    public Task Issues_a_certificate_for_a_new_order_and_stores_it_encrypted() => Issues_a_certificate_for_a_new_order_and_stores_it_encryptedAsync();

    [PebbleFact(RequiresPostgres = true)]
    public Task The_account_key_is_stored_encrypted_and_reused_after_a_restart() => The_account_key_is_stored_encrypted_and_reused_after_a_restartAsync();

    [PebbleFact(RequiresPostgres = true)]
    public Task Renewal_replaces_the_row_when_a_third_of_the_lifetime_is_left() => Renewal_replaces_the_row_when_a_third_of_the_lifetime_is_leftAsync();

    [PebbleFact(RequiresPostgres = true)]
    public Task A_failed_validation_is_recorded_backs_off_keeps_the_account_and_recovers() => A_failed_validation_is_recorded_backs_off_keeps_the_account_and_recoversAsync();

    [PebbleFact(RequiresPostgres = true)]
    public Task Only_one_replica_orders_at_a_time_and_a_dashboard_request_bypasses_the_back_off() => Only_one_replica_orders_at_a_time_and_a_dashboard_request_bypasses_the_back_offAsync();
}

/// <summary>Failures that need no CA at all: it is unreachable or too slow. These always run.</summary>
public sealed class AcmeUnreachableCaTests : IAsyncLifetime
{
    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-acme-down-").FullName;
    private AcmeHarness _h = null!;

    public async Task InitializeAsync() =>
        _h = await AcmeHarness.CreateAsync(SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _dir } }), directoryUrl: "https://127.0.0.1:1/dir");

    public async Task DisposeAsync()
    {
        await _h.DisposeAsync();
        Directory.Delete(_dir, recursive: true);
    }

    [Fact]
    public async Task A_refused_connection_is_a_recorded_failure_with_back_off()
    {
        var service = _h.CreateService(new SilentDns(), ["mx.acme-test.example"]);

        Assert.False(await service.CheckOnceAsync(default));

        var renewal = Assert.Single(await _h.Storage.Config.GetAcmeRenewalsAsync(default));
        Assert.Equal(("failed", 1), (renewal.Status, renewal.Failures));
        AcmeIssuanceTests.AssertSameMillisecond(_h.Clock.UtcNow + TimeSpan.FromMinutes(10), renewal.NextAttemptAt);
        Assert.False(string.IsNullOrEmpty(renewal.LastError));
        Assert.Null(await _h.Storage.Config.GetAcmeAccountAsync(_h.DirectoryUrl, default)); // nothing was registered
        Assert.False(await service.CheckOnceAsync(default)); // inside the back-off window
    }

    [Fact]
    public async Task A_server_that_does_not_answer_in_time_is_a_recorded_failure_and_does_not_end_the_renewal_loop()
    {
        var service = _h.CreateService(new SilentDns(), ["mx.acme-test.example"], runner: new CertesOrderRunner(new TimingOutHandler()));

        // The renewal loop's first check runs into the timeout. HttpClient reports it as a cancellation, which must neither escape (it would end
        // the loop silently until the next restart) nor leave the state at "ordering": it is a failed attempt with a back-off.
        using var stop = new CancellationTokenSource();
        Task loop = service.RunAsync(stop.Token);
        AcmeRenewalRecord? renewal = null;
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < deadline && renewal?.Status != "failed")
        {
            await Task.Delay(20);
            renewal = (await _h.Storage.Config.GetAcmeRenewalsAsync(default)).SingleOrDefault();
        }

        Assert.NotNull(renewal);
        Assert.Equal(("failed", 1), (renewal.Status, renewal.Failures));
        Assert.Contains("did not answer in time", renewal.LastError);
        Assert.False(loop.IsCompleted, "the renewal loop ended");
        await stop.CancelAsync();
        await loop.WaitAsync(TimeSpan.FromSeconds(30));
    }
}
