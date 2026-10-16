using System.Net;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Host.Tls;
using Mta.Storage;

namespace Mta.Host.Tests.Acme;

/// <summary>
/// <see cref="AcmeRenewalService"/> with the real runner against the scriptable mock CA and a fake clock: what is stored when the CA misbehaves, the back-off and
/// the banner, a rate limit's <c>Retry-After</c>, accounts that went away, replicas racing for the lease, a lease that expires, a store that fails at the last step,
/// a restart, and the exact instants at which a certificate becomes due.
/// </summary>
public class AcmeServiceMockCaTests
{
    // ---------------------------------------------------------------------------------------------------------------------------------
    // What gets stored

    [Fact]
    public async Task A_certificate_is_issued_verified_and_stored_with_its_chain_and_the_renewal_row_says_issued()
    {
        using var rig = new AcmeServiceRig();

        Assert.True(await rig.Service().CheckOnceAsync(default));

        var certificate = await rig.OnlyCertificateAsync();
        Assert.Equal([AcmeServiceRig.Host], certificate.Subjects);
        Assert.Equal("acme", certificate.Source);
        Assert.True(certificate.Active);
        var (leaf, intermediates) = CertificateMaterial.Load(certificate, rig.Protector);
        Assert.True(leaf.HasPrivateKey);
        Assert.Single(intermediates);
        var renewal = await rig.RenewalAsync();
        Assert.Equal(("issued", 0, null), (renewal.Status, renewal.Failures, renewal.NextAttemptAt));
        Assert.Equal(0, rig.Dns.LiveRecords);
    }

    [Theory]
    [InlineData(MockCertificateMode.WrongNames, "does not cover 'mx.service.test'")]
    [InlineData(MockCertificateMode.WrongKey, "no certificate for the key of this order")]
    [InlineData(MockCertificateMode.NoLeaf, "no certificate for the key of this order")]
    [InlineData(MockCertificateMode.Truncated, "damaged or cut off")]
    [InlineData(MockCertificateMode.Garbage, "The CA sent no certificate")]
    [InlineData(MockCertificateMode.Empty, "The CA sent no certificate")]
    [InlineData(MockCertificateMode.AlreadyExpired, "already expired")]
    public async Task A_certificate_that_is_not_the_answer_to_the_order_is_never_stored_and_the_old_one_keeps_serving(MockCertificateMode mode, string expected)
    {
        using var rig = new AcmeServiceRig();
        var service = rig.Service();
        Assert.True(await service.CheckOnceAsync(default));
        var before = await rig.OnlyCertificateAsync();
        long versionBefore = await rig.Config.GetCertificateVersionAsync(default);
        rig.Clock.Advance(TimeSpan.FromDays(70));
        rig.Ca.CertificateMode = mode;

        Assert.False(await service.CheckOnceAsync(default));

        var after = await rig.OnlyCertificateAsync();
        Assert.Equal(before.Thumbprint, after.Thumbprint);
        Assert.Equal(versionBefore, await rig.Config.GetCertificateVersionAsync(default));
        var renewal = await rig.RenewalAsync();
        Assert.Equal(("failed", 1), (renewal.Status, renewal.Failures));
        Assert.Contains(expected, renewal.LastError);
        Assert.Equal(rig.Clock.UtcNow + TimeSpan.FromMinutes(10), renewal.NextAttemptAt);
    }

    [Theory]
    [InlineData(MockCertificateMode.WrongOrder, 2)]
    [InlineData(MockCertificateMode.LeafOnly, 1)]
    public async Task A_chain_in_the_wrong_order_or_without_its_intermediate_is_stored_leaf_first_and_usable(MockCertificateMode mode, int count)
    {
        using var rig = new AcmeServiceRig();
        rig.Ca.CertificateMode = mode;

        Assert.True(await rig.Service().CheckOnceAsync(default));

        var certificate = await rig.OnlyCertificateAsync();
        var (leaf, intermediates) = CertificateMaterial.Load(certificate, rig.Protector);
        Assert.Equal("CN=" + AcmeServiceRig.Host, leaf.Subject);
        Assert.Equal(count - 1, intermediates.Count);
    }

    [Fact]
    public async Task A_new_certificate_replaces_the_row_of_the_old_one_and_a_wildcard_with_its_base_name_is_stored_for_both()
    {
        using var rig = new AcmeServiceRig();
        var options = rig.Options(domains: ["service.test", "*.service.test"]);
        var service = rig.Service(options);
        Assert.True(await service.CheckOnceAsync(default));
        var first = await rig.OnlyCertificateAsync();
        rig.Clock.Advance(TimeSpan.FromDays(70));

        Assert.True(await service.CheckOnceAsync(default));

        var second = await rig.OnlyCertificateAsync();
        Assert.Equal(first.Id, second.Id);
        Assert.NotEqual(first.Thumbprint, second.Thumbprint);
        Assert.Equal(["*.service.test", "service.test"], second.Subjects.Order(StringComparer.Ordinal));
        // The second order is a renewal of the first for a CA with ARI; here the CA has none, so there is no link to carry.
        Assert.All(rig.Ca.OrdersCreated, order => Assert.Null(order.Replaces));
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // Back-off, banner, Retry-After

    [Fact]
    public async Task Failures_back_off_10_20_40_80_160_320_minutes_then_stay_at_six_hours_and_nothing_is_asked_a_second_early()
    {
        using var rig = new AcmeServiceRig();
        var service = rig.Service();
        rig.Ca.Fail("newOrder", 500, "serverInternal", "database is down", times: 100);
        int[] expectedMinutes = [10, 20, 40, 80, 160, 320, 360, 360, 360];

        for (int i = 0; i < expectedMinutes.Length; i++)
        {
            Assert.False(await service.CheckOnceAsync(default));
            var renewal = await rig.RenewalAsync();
            Assert.Equal(("failed", i + 1), (renewal.Status, renewal.Failures));
            Assert.Equal(rig.Clock.UtcNow + TimeSpan.FromMinutes(expectedMinutes[i]), renewal.NextAttemptAt);

            int orders = rig.Ca.Count("newOrder");
            rig.Clock.Advance(TimeSpan.FromMinutes(expectedMinutes[i]) - TimeSpan.FromSeconds(1));
            Assert.False(await service.CheckOnceAsync(default));
            Assert.Equal(orders, rig.Ca.Count("newOrder")); // still inside the back-off: the CA is not asked
            rig.Clock.Advance(TimeSpan.FromSeconds(1)); // exactly at the time: due
        }

        Assert.Equal(expectedMinutes.Length, rig.Ca.Count("newOrder"));
    }

    [Theory]
    [InlineData(1, 10)]
    [InlineData(2, 20)]
    [InlineData(3, 40)]
    [InlineData(6, 320)]
    [InlineData(7, 360)]
    [InlineData(30, 360)]
    [InlineData(1000, 360)]
    [InlineData(0, 10)]
    public void The_back_off_schedule(int failures, int expectedMinutes) =>
        Assert.Equal(TimeSpan.FromMinutes(expectedMinutes), AcmeRenewalService.Backoff(failures));

    [Fact]
    public async Task The_banner_goes_from_pending_to_failing_with_a_category_only_and_clears_on_success()
    {
        using var rig = new AcmeServiceRig();
        var config = new MtaConfig { Acme = rig.Options() };
        var banner = new CertificateHealthContributor(rig.Storage, rig.Clock, config);
        var service = rig.Service();

        var pending = Assert.Single((await banner.CheckAsync(default)).Warnings, w => w.Code.StartsWith("acme_", StringComparison.Ordinal));
        Assert.Equal("acme_pending", pending.Code);

        rig.Ca.Fail("newOrder", 429, "rateLimited", "secret detail with https://ca.internal/path and token abc123", times: 2);
        Assert.False(await service.CheckOnceAsync(default));
        var failing = Assert.Single((await banner.CheckAsync(default)).Warnings, w => w.Code.StartsWith("acme_", StringComparison.Ordinal));
        Assert.Equal("acme_failing", failing.Code);
        Assert.Contains("failed 1 time in a row", failing.Message);
        Assert.Contains("the CA refused the request", failing.Message);
        Assert.DoesNotContain("secret detail", failing.Message);
        Assert.DoesNotContain("ca.internal", failing.Message);
        Assert.Contains((rig.Clock.UtcNow + TimeSpan.FromMinutes(10)).ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture), failing.Message);

        rig.Clock.Advance(TimeSpan.FromMinutes(10));
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Contains("failed 2 times in a row", Assert.Single((await banner.CheckAsync(default)).Warnings, w => w.Code == "acme_failing").Message);

        rig.Clock.Advance(TimeSpan.FromMinutes(20));
        Assert.True(await service.CheckOnceAsync(default));
        Assert.DoesNotContain((await banner.CheckAsync(default)).Warnings, w => w.Code.StartsWith("acme_", StringComparison.Ordinal));
    }

    [Fact]
    public async Task While_a_renewal_fails_the_banner_names_the_certificate_still_in_use()
    {
        using var rig = new AcmeServiceRig();
        var banner = new CertificateHealthContributor(rig.Storage, rig.Clock, new MtaConfig { Acme = rig.Options() });
        var service = rig.Service();
        Assert.True(await service.CheckOnceAsync(default));
        var expires = (await rig.OnlyCertificateAsync()).NotAfter;
        rig.Clock.Advance(TimeSpan.FromDays(70));
        rig.Ca.Fail("newOrder", 503, "serverInternal", "maintenance");

        Assert.False(await service.CheckOnceAsync(default));

        var warning = Assert.Single((await banner.CheckAsync(default)).Warnings, w => w.Code == "acme_failing");
        Assert.Contains("The previous certificate stays in use until " + expires.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture), warning.Message);
    }

    [Theory]
    [InlineData(3 * 3600, 3 * 3600)]            // longer than the back-off: asking earlier cannot work
    [InlineData(60, 10 * 60)]                   // shorter: the back-off wins
    [InlineData(5 * 86400, 86400)]              // days: a day at most
    [InlineData(10 * 60, 10 * 60)]
    public async Task A_rate_limit_postpones_the_next_attempt_by_its_retry_after_within_bounds(int retryAfterSeconds, int expectedSeconds)
    {
        using var rig = new AcmeServiceRig();
        var service = rig.Service();
        rig.Ca.Fail("newOrder", 429, "rateLimited", "too many certificates", retryAfterSeconds: retryAfterSeconds);

        Assert.False(await service.CheckOnceAsync(default));

        var renewal = await rig.RenewalAsync();
        Assert.Equal(rig.Clock.UtcNow + TimeSpan.FromSeconds(expectedSeconds), renewal.NextAttemptAt);
        // The renewal loop wakes at that time, not at the next hourly check, unless that comes first.
        var expectedDelay = TimeSpan.FromSeconds(Math.Min(expectedSeconds, 3600));
        Assert.Equal(expectedDelay, await service.NextCheckDelayAsync(default));
    }

    [Fact]
    public async Task A_retry_after_longer_than_the_back_off_of_a_later_failure_is_still_honoured()
    {
        using var rig = new AcmeServiceRig();
        var service = rig.Service();
        rig.Ca.Fail("newOrder", 500, "serverInternal", "x");
        rig.Ca.Fail("newOrder", 429, "rateLimited", "slow down", retryAfterSeconds: 30 * 60);
        Assert.False(await service.CheckOnceAsync(default));
        rig.Clock.Advance(TimeSpan.FromMinutes(10));

        Assert.False(await service.CheckOnceAsync(default));

        var renewal = await rig.RenewalAsync();
        Assert.Equal(2, renewal.Failures);
        Assert.Equal(rig.Clock.UtcNow + TimeSpan.FromMinutes(30), renewal.NextAttemptAt); // back-off for the second failure is 20 minutes: the CA's 30 win
    }

    [Fact]
    public async Task A_dashboard_request_ignores_the_back_off_but_a_successful_one_resets_it()
    {
        using var rig = new AcmeServiceRig();
        var service = rig.Service();
        rig.Ca.Fail("newOrder", 500, "serverInternal", "x");
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(1, (await rig.RenewalAsync()).Failures);

        Assert.True(await service.RequestAsync([AcmeServiceRig.Host], default)); // no wait for the 10 minutes

        var renewal = await rig.RenewalAsync();
        Assert.Equal(("issued", 0, null), (renewal.Status, renewal.Failures, renewal.NextAttemptAt));
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // Accounts

    [Fact]
    public async Task An_account_the_CA_forgot_is_replaced_once_in_the_same_row_and_the_order_then_succeeds()
    {
        using var rig = new AcmeServiceRig();
        var service = rig.Service();
        Assert.True(await service.CheckOnceAsync(default));
        var oldAccount = (await rig.Config.GetAcmeAccountAsync(MockAcmeServer.DirectoryUrl, default))!;
        rig.Ca.ForgetAccounts();
        rig.Clock.Advance(TimeSpan.FromDays(70));

        Assert.True(await service.CheckOnceAsync(default));

        var newAccount = (await rig.Config.GetAcmeAccountAsync(MockAcmeServer.DirectoryUrl, default))!;
        Assert.Equal(oldAccount.Id, newAccount.Id); // one account per directory
        Assert.NotEqual(oldAccount.AccountKeyProtected, newAccount.AccountKeyProtected);
        Assert.Equal(1, rig.Ca.AccountCount);
        Assert.Contains(rig.Log.Lines, l => l.Contains("does not know the stored ACME account", StringComparison.Ordinal));
        Assert.Equal(("issued", 0), ((await rig.RenewalAsync()).Status, (await rig.RenewalAsync()).Failures));
    }

    [Fact]
    public async Task A_forgotten_account_with_external_account_binding_registers_again_with_the_binding()
    {
        using var rig = new AcmeServiceRig();
        rig.Ca.ExternalAccountRequired = true;
        string hmac = System.Buffers.Text.Base64Url.EncodeToString(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        rig.Ca.EabKeys["kid-7"] = hmac;
        var service = rig.Service(rig.Options(eabKeyId: "kid-7", eabKey: hmac));
        Assert.True(await service.CheckOnceAsync(default));
        rig.Ca.ForgetAccounts();
        rig.Clock.Advance(TimeSpan.FromDays(70));

        Assert.True(await service.CheckOnceAsync(default));

        Assert.Equal(1, rig.Ca.AccountCount);
        Assert.Equal(2, rig.Ca.Count("newAccount", 201));
    }

    [Fact]
    public async Task An_account_the_CA_deactivated_is_a_recorded_failure_and_no_second_account_is_registered_by_itself()
    {
        using var rig = new AcmeServiceRig();
        var service = rig.Service();
        Assert.True(await service.CheckOnceAsync(default));
        rig.Ca.DeactivateAccounts();
        rig.Clock.Advance(TimeSpan.FromDays(70));

        Assert.False(await service.CheckOnceAsync(default));

        var renewal = await rig.RenewalAsync();
        Assert.Equal("failed", renewal.Status);
        Assert.Contains("deactivated", renewal.LastError);
        Assert.Equal(1, rig.Ca.Count("newAccount", 201));
    }

    [Fact]
    public async Task A_rate_limited_registration_stores_no_account_and_the_next_order_registers_again()
    {
        using var rig = new AcmeServiceRig();
        var service = rig.Service();
        rig.Ca.Fail("newAccount", 429, "rateLimited", "too many registrations", retryAfterSeconds: 900);

        Assert.False(await service.CheckOnceAsync(default));

        Assert.Null(await rig.Config.GetAcmeAccountAsync(MockAcmeServer.DirectoryUrl, default));
        Assert.Equal(rig.Clock.UtcNow + TimeSpan.FromMinutes(15), (await rig.RenewalAsync()).NextAttemptAt);
        rig.Clock.Advance(TimeSpan.FromMinutes(15));
        Assert.True(await service.CheckOnceAsync(default));
        Assert.NotNull(await rig.Config.GetAcmeAccountAsync(MockAcmeServer.DirectoryUrl, default));
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // DNS-01 and HTTP-01 failures

    [Fact]
    public async Task A_DNS_provider_that_cannot_create_the_record_is_a_recorded_failure_and_the_CA_never_validates()
    {
        using var rig = new AcmeServiceRig();
        rig.Dns.FailCreate[1] = new AcmeException("Cloudflare: no active zone found for _acme-challenge.mx.service.test (does the API token have access?)");
        var service = rig.Service();

        Assert.False(await service.CheckOnceAsync(default));

        var renewal = await rig.RenewalAsync();
        Assert.Contains("no active zone found", renewal.LastError);
        Assert.Equal(0, rig.Ca.Count("finalize"));
        Assert.DoesNotContain(rig.Ca.Requests, r => r.Endpoint == "challenge" && r.Payload is not null); // no challenge was ever answered
    }

    [Fact]
    public async Task A_CA_that_cannot_see_the_record_fails_the_order_with_its_explanation_and_the_record_is_removed()
    {
        using var rig = new AcmeServiceRig();
        rig.Ca.Validator = _ => ChallengeVerdict.Invalid("dns", "DNS problem: NXDOMAIN looking up TXT for _acme-challenge.mx.service.test");
        var service = rig.Service();

        Assert.False(await service.CheckOnceAsync(default));

        var renewal = await rig.RenewalAsync();
        Assert.Contains("NXDOMAIN", renewal.LastError);
        Assert.Equal(0, rig.Dns.LiveRecords);
        Assert.Equal("the CA could not validate the challenge", AcmeFailureCategory.Describe(renewal.LastError));
    }

    [Fact]
    public async Task The_Cloudflare_token_is_in_no_renewal_row_log_line_banner_or_exception_of_a_failing_service()
    {
        using var rig = new AcmeServiceRig();
        var cloudflare = new FakeCloudflare(() => rig.Clock.UtcNow);
        cloudflare.AddZone("service.test");
        cloudflare.Fail("zones", 403, 9109, "Invalid access token", times: 3);
        var provider = new CloudflareDnsChallengeProvider(new HttpClient(cloudflare), FakeCloudflare.ValidToken + "\n", pause: (_, _) => Task.CompletedTask);
        var service = rig.Service(dns: provider);
        var banner = new CertificateHealthContributor(rig.Storage, rig.Clock, new MtaConfig { Acme = rig.Options() });

        Assert.False(await service.CheckOnceAsync(default));
        rig.Clock.Advance(TimeSpan.FromMinutes(10));
        Assert.False(await service.CheckOnceAsync(default));

        var renewal = await rig.RenewalAsync();
        Assert.Contains("9109: Invalid access token", renewal.LastError);
        Assert.DoesNotContain(FakeCloudflare.ValidToken, renewal.LastError);
        Assert.All(rig.Log.Lines, l => Assert.DoesNotContain(FakeCloudflare.ValidToken, l));
        Assert.All((await banner.CheckAsync(default)).Warnings, w => Assert.DoesNotContain(FakeCloudflare.ValidToken, w.Message));
        Assert.Equal("the DNS provider (Cloudflare) could not publish or remove the challenge record", AcmeFailureCategory.Describe(renewal.LastError));
    }

    [Fact]
    public async Task An_http_order_with_a_listener_that_is_not_running_never_reaches_the_CA()
    {
        using var rig = new AcmeServiceRig();
        var http = new RecordingHttpPublisher { Unavailable = "ACME HTTP-01: :: port 80 is already in use (a web server or proxy on this host?)" };
        var service = rig.Service(rig.Options(challenge: AcmeChallengeMode.Http01), http: http);

        Assert.False(await service.CheckOnceAsync(default));

        Assert.Empty(rig.Ca.Requests);
        var renewal = await rig.RenewalAsync();
        Assert.Equal(rig.Clock.UtcNow + TimeSpan.FromMinutes(5), renewal.NextAttemptAt);
        Assert.Equal("the port for the HTTP-01 challenge could not be bound", AcmeFailureCategory.Describe(renewal.LastError));
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // Replicas, leases, crashes and restarts

    [Fact]
    public async Task Two_replicas_racing_for_the_same_renewal_cause_exactly_one_order()
    {
        using var rig = new AcmeServiceRig();
        var gate = new GatedDnsProvider(rig.Dns);
        var first = rig.Service(dns: gate);
        var second = rig.Service();
        var running = Task.Run(() => first.CheckOnceAsync(default));
        await gate.Reached; // the first replica holds the lease and waits inside its order

        bool got = await second.CheckOnceAsync(default);
        Assert.False(got, string.Join("\n", rig.Log.Lines));

        Assert.Equal(1, rig.Ca.Count("newOrder"));
        Assert.Contains(rig.Log.Lines, l => l.Contains("another replica is renewing 'default'", StringComparison.Ordinal));
        gate.Release();
        Assert.True(await running);
        Assert.False(await second.CheckOnceAsync(default)); // the certificate is fresh now, and the lease is free again
        Assert.Equal(1, rig.Ca.Count("newOrder"));
        Assert.Single(await rig.Config.GetCertificatesAsync(default));
    }

    [Fact]
    public async Task A_replica_that_died_holding_the_lease_is_taken_over_exactly_when_the_lease_expires()
    {
        using var rig = new AcmeServiceRig();
        // The crashed replica: it took the lease (20 minutes) and marked the order, then the process was gone.
        var lease = await rig.Config.TryAcquireLeaseAsync(AcmeRenewalService.LeaseName("default"), "dead-replica", AcmeRenewalService.LeaseDuration, rig.Clock.UtcNow, default);
        Assert.NotNull(lease);
        await rig.Config.UpsertAcmeRenewalAsync(new AcmeRenewalRecord("default", "ordering", rig.Clock.UtcNow, null, 0, null, null, null), default);
        var survivor = rig.Service();

        rig.Clock.Advance(AcmeRenewalService.LeaseDuration - TimeSpan.FromSeconds(1));
        Assert.False(await survivor.CheckOnceAsync(default));
        Assert.Equal(0, rig.Ca.Count("newOrder"));

        rig.Clock.Advance(TimeSpan.FromSeconds(1));
        Assert.True(await survivor.CheckOnceAsync(default));
        Assert.Equal(("issued", 0), ((await rig.RenewalAsync()).Status, (await rig.RenewalAsync()).Failures));
    }

    [Fact]
    public async Task A_slow_replica_whose_lease_was_taken_over_discards_its_certificate_and_leaves_the_others_result_alone()
    {
        using var rig = new AcmeServiceRig();
        var gate = new GatedDnsProvider(rig.Dns);
        var slow = rig.Service(dns: gate);
        var other = rig.Service();
        var running = Task.Run(() => slow.CheckOnceAsync(default));
        await gate.Reached;
        rig.Clock.Advance(AcmeRenewalService.LeaseDuration + TimeSpan.FromSeconds(1)); // the slow order outlived its lease

        Assert.True(await other.CheckOnceAsync(default)); // the other replica takes over and finishes
        var theirs = await rig.OnlyCertificateAsync();
        gate.Release();
        Assert.False(await running); // the slow one finds the lease gone when it is about to store

        var stored = await rig.OnlyCertificateAsync();
        Assert.Equal(theirs.Thumbprint, stored.Thumbprint);
        Assert.Equal(theirs.Id, stored.Id);
        Assert.Equal(("issued", 0), ((await rig.RenewalAsync()).Status, (await rig.RenewalAsync()).Failures));
        Assert.Contains(rig.Log.Lines, l => l.Contains("was taken over by another replica", StringComparison.Ordinal));
        Assert.Equal(2, rig.Ca.OrdersCreated.Count); // the CA saw both orders; only one result is kept
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_slow_replica_whose_lease_was_taken_over_and_whose_order_then_fails_does_not_overwrite_the_other_replicas_issued_row(bool listenerProblem)
    {
        using var rig = new AcmeServiceRig();
        Exception failure = listenerProblem ? new AcmeListenerUnavailableException("ACME HTTP-01: port 80 is already in use") : new AcmeException("Cloudflare: could not create the TXT record (HTTP 500)");
        var gate = new GatedDnsProvider(rig.Dns, failure);
        var slow = rig.Service(dns: gate);
        var other = rig.Service();
        var running = Task.Run(() => slow.CheckOnceAsync(default));
        await gate.Reached;
        rig.Clock.Advance(AcmeRenewalService.LeaseDuration + TimeSpan.FromSeconds(1));
        Assert.True(await other.CheckOnceAsync(default));
        gate.Release();

        Assert.False(await running);

        var renewal = await rig.RenewalAsync();
        Assert.Equal(("issued", 0, null), (renewal.Status, renewal.Failures, renewal.LastError)); // the other replica's row is untouched
        Assert.Contains(rig.Log.Lines, l => l.Contains("was taken over by another replica; the order", StringComparison.Ordinal));
        Assert.DoesNotContain(rig.Log.Lines, l => l.StartsWith("Error acme: certificate order for 'default' failed", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_replica_that_still_holds_its_lease_records_its_failure()
    {
        using var rig = new AcmeServiceRig();
        rig.Dns.FailCreate[1] = new AcmeException("Cloudflare: could not create the TXT record (HTTP 500)");

        Assert.False(await rig.Service().CheckOnceAsync(default));

        Assert.Equal(("failed", 1), ((await rig.RenewalAsync()).Status, (await rig.RenewalAsync()).Failures));
    }

    [Fact]
    public async Task A_store_that_fails_after_the_CA_issued_is_a_recorded_failure_with_nothing_stored_and_the_lease_released()
    {
        using var rig = new AcmeServiceRig();
        var (faulty, control) = FaultyConfig.Wrap(rig.Config);
        var service = rig.Service(config: faulty);
        control.Fail(nameof(IConfigStore.UpsertCertificateAsync));

        Assert.False(await service.CheckOnceAsync(default));

        Assert.Empty(await rig.Config.GetCertificatesAsync(default)); // finalize happened at the CA, nothing was stored: no partial certificate
        Assert.Equal(1, rig.Ca.Count("finalize"));
        var renewal = await rig.RenewalAsync();
        Assert.Equal(("failed", 1), (renewal.Status, renewal.Failures));
        Assert.Contains("database is unavailable", renewal.LastError);
        Assert.NotNull(await rig.Config.TryAcquireLeaseAsync(AcmeRenewalService.LeaseName("default"), "someone-else", TimeSpan.FromMinutes(1), rig.Clock.UtcNow, default)); // released

        // The next attempt, after the back-off, orders again and stores the certificate.
        await rig.Config.ReleaseLeaseAsync(AcmeRenewalService.LeaseName("default"), "someone-else", default);
        rig.Clock.Advance(TimeSpan.FromMinutes(10));
        Assert.True(await service.CheckOnceAsync(default));
        Assert.Single(await rig.Config.GetCertificatesAsync(default));
        Assert.Equal(2, rig.Ca.Count("finalize"));
    }

    [Fact]
    public async Task A_restarted_process_continues_with_the_stored_account_and_the_recorded_back_off()
    {
        using var rig = new AcmeServiceRig();
        rig.Dns.FailCreate[1] = new AcmeException("Cloudflare: could not create TXT record (HTTP 500)");
        Assert.False(await rig.Service().CheckOnceAsync(default)); // the first process: account registered, order failed
        Assert.Equal(1, rig.Ca.AccountCount);

        var restarted = rig.Service(); // a new process: new owner id, new runner, nothing in memory
        Assert.False(await restarted.CheckOnceAsync(default)); // still inside the 10 minutes recorded in the store
        Assert.Equal(1, rig.Ca.Count("newOrder"));
        rig.Clock.Advance(TimeSpan.FromMinutes(10));

        Assert.True(await restarted.CheckOnceAsync(default));

        Assert.Equal(1, rig.Ca.AccountCount); // the account of the first process was reused
        Assert.Equal(1, rig.Ca.Count("newAccount", 201));
        Assert.Equal(("issued", 0), ((await rig.RenewalAsync()).Status, (await rig.RenewalAsync()).Failures));
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // The clock: the exact instants at which a certificate is due

    [Fact]
    public async Task By_the_lifetime_rule_the_certificate_is_due_exactly_when_a_third_of_its_lifetime_is_left()
    {
        using var rig = new AcmeServiceRig();
        var service = rig.Service(rig.Options(useRenewalInfo: false));
        Assert.True(await service.CheckOnceAsync(default));
        var certificate = await rig.OnlyCertificateAsync();
        var due = certificate.NotAfter - (certificate.NotAfter - certificate.NotBefore) / 3;

        rig.Clock.Advance(due - rig.Clock.UtcNow - TimeSpan.FromTicks(1));
        Assert.False(await service.CheckOnceAsync(default));
        rig.Clock.Advance(TimeSpan.FromTicks(1));
        Assert.True(await service.CheckOnceAsync(default)); // at the boundary itself the certificate is due

        Assert.Equal(2, rig.Ca.Count("newOrder"));
    }

    [Fact]
    public async Task With_ARI_the_chosen_time_is_due_exactly_one_check_interval_before_it()
    {
        using var rig = new AcmeServiceRig();
        var options = rig.Options(useRenewalInfo: true);
        rig.Ca.AdvertiseRenewalInfo = true;
        var service = rig.Service(options, random: 0.0); // the chosen time is the start of the window
        Assert.True(await service.CheckOnceAsync(default));
        var certificate = await rig.OnlyCertificateAsync();
        var start = rig.Clock.UtcNow + TimeSpan.FromDays(30);
        rig.Ca.RenewalInfo = AcmeServiceRig.Window(start, start.AddHours(2));
        rig.Clock.Advance(TimeSpan.FromDays(1));
        Assert.False(await service.CheckOnceAsync(default)); // asks the CA, stores the window
        var due = start - options.CheckInterval; // renew when the chosen time falls before the next check (RFC 9773 section 4.2)

        rig.Clock.Advance(due - rig.Clock.UtcNow - TimeSpan.FromTicks(1));
        Assert.False(await service.CheckOnceAsync(default));
        rig.Clock.Advance(TimeSpan.FromTicks(1));
        Assert.True(await service.CheckOnceAsync(default));

        Assert.NotEqual(certificate.Thumbprint, (await rig.OnlyCertificateAsync()).Thumbprint);
        Assert.NotNull(Assert.Single(rig.Ca.OrdersCreated, o => o.Replaces is not null).Replaces); // the renewal carries the id of the certificate it replaces
    }

    [Fact]
    public async Task With_ARI_a_certificate_is_never_renewed_before_its_minimum_age_and_is_at_exactly_that_age()
    {
        using var rig = new AcmeServiceRig();
        rig.Ca.AdvertiseRenewalInfo = true;
        var service = rig.Service(rig.Options(useRenewalInfo: true), random: 0.0);
        Assert.True(await service.CheckOnceAsync(default));
        var certificate = await rig.OnlyCertificateAsync();
        // The CA says "renew now" (a window in the past, as for a revoked certificate) however often it is asked.
        rig.Ca.RenewalInfo = AcmeServiceRig.Window(rig.Clock.UtcNow.AddDays(-2), rig.Clock.UtcNow.AddDays(-1), retryAfterSeconds: 3600);
        var minimumAge = AcmeRenewalSchedule.MinimumAge(certificate.NotAfter - certificate.NotBefore);
        Assert.Equal(TimeSpan.FromDays(4.5) + TimeSpan.FromTicks((certificate.NotAfter - certificate.NotBefore - TimeSpan.FromDays(90)).Ticks / 20), minimumAge);
        var due = certificate.NotBefore + minimumAge;

        rig.Clock.Advance(TimeSpan.FromHours(1));
        Assert.False(await service.CheckOnceAsync(default));
        rig.Clock.Advance(due - rig.Clock.UtcNow - TimeSpan.FromTicks(1));
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(1, rig.Ca.Count("newOrder"));
        rig.Clock.Advance(TimeSpan.FromTicks(1));
        Assert.True(await service.CheckOnceAsync(default));

        Assert.Equal(2, rig.Ca.Count("newOrder"));
    }

    [Fact]
    public async Task A_safety_limit_renews_whatever_ARI_says_when_a_sixth_of_the_lifetime_is_left()
    {
        using var rig = new AcmeServiceRig();
        rig.Ca.AdvertiseRenewalInfo = true;
        var service = rig.Service(rig.Options(useRenewalInfo: true), random: 0.5);
        Assert.True(await service.CheckOnceAsync(default));
        var certificate = await rig.OnlyCertificateAsync();
        // A wrong CA: the window is after the expiry.
        rig.Ca.RenewalInfo = AcmeServiceRig.Window(certificate.NotAfter.AddDays(10), certificate.NotAfter.AddDays(20), retryAfterSeconds: 3600);
        var due = certificate.NotAfter - (certificate.NotAfter - certificate.NotBefore) / 6;

        rig.Clock.Advance(due - rig.Clock.UtcNow - TimeSpan.FromTicks(1));
        Assert.False(await service.CheckOnceAsync(default));
        rig.Clock.Advance(TimeSpan.FromTicks(1));
        Assert.True(await service.CheckOnceAsync(default));
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // ARI endpoint behaviour

    [Fact]
    public async Task A_directory_without_renewalInfo_is_not_asked_and_looked_at_again_after_a_day()
    {
        using var rig = new AcmeServiceRig();
        var service = rig.Service(rig.Options(useRenewalInfo: true));
        Assert.True(await service.CheckOnceAsync(default));
        rig.Clock.Advance(TimeSpan.FromDays(1));

        Assert.False(await service.CheckOnceAsync(default));
        var certificate = await rig.OnlyCertificateAsync();
        var advice = AcmeRenewalAdvice.Parse((await rig.RenewalAsync()).AriJson, certificate.Thumbprint)!;

        Assert.True(advice.DirectoryHasNoRenewalInfo);
        Assert.Equal(rig.Clock.UtcNow + TimeSpan.FromDays(1), advice.NextCheckAt);
        Assert.Equal(0, rig.Ca.Count("renewalInfo"));
    }

    [Theory]
    [InlineData(429, "rateLimited", 20 * 3600, 20 * 3600, 1)]   // the CA's Retry-After on a refusal is honoured now, when it is longer than the usual wait
    [InlineData(429, "rateLimited", 7200, 6 * 3600, 1)]         // shorter than the usual wait after a refusal: the usual wait
    [InlineData(429, "rateLimited", 10 * 86400, 86400, 1)]      // at most a day
    [InlineData(503, "serverInternal", null, 300, 1)]     // a server error: 5 minutes, doubling
    [InlineData(500, "serverInternal", 14400, 14400, 1)]
    [InlineData(404, "malformed", null, 6 * 3600, 1)]     // any other refusal: six hours
    public async Task An_ARI_error_postpones_the_next_question_as_the_CA_and_RFC_9773_say(int status, string type, int? retryAfterSeconds, int expectedSeconds, int failures)
    {
        using var rig = new AcmeServiceRig();
        rig.Ca.AdvertiseRenewalInfo = true;
        var service = rig.Service(rig.Options(useRenewalInfo: true));
        Assert.True(await service.CheckOnceAsync(default));
        rig.Clock.Advance(TimeSpan.FromDays(1));
        rig.Ca.Fail("renewalInfo", status, type, "scripted", retryAfterSeconds: retryAfterSeconds);

        Assert.False(await service.CheckOnceAsync(default)); // the lifetime rule applies meanwhile

        var certificate = await rig.OnlyCertificateAsync();
        var advice = AcmeRenewalAdvice.Parse((await rig.RenewalAsync()).AriJson, certificate.Thumbprint)!;
        Assert.Equal(failures, advice.Failures);
        Assert.Equal(rig.Clock.UtcNow + TimeSpan.FromSeconds(expectedSeconds), advice.NextCheckAt);
        Assert.Contains("scripted", advice.Error);
    }

    [Fact]
    public async Task A_renewal_information_answer_that_is_garbage_is_a_failure_and_never_blocks_a_renewal_by_the_lifetime_rule()
    {
        using var rig = new AcmeServiceRig();
        rig.Ca.AdvertiseRenewalInfo = true;
        var service = rig.Service(rig.Options(useRenewalInfo: true));
        Assert.True(await service.CheckOnceAsync(default));
        rig.Ca.RenewalInfo = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"suggestedWindow\":", System.Text.Encoding.UTF8, "application/json") };
        var certificate = await rig.OnlyCertificateAsync();
        rig.Clock.Advance(certificate.NotAfter - rig.Clock.UtcNow - (certificate.NotAfter - certificate.NotBefore) / 3 + TimeSpan.FromMinutes(1)); // past the lifetime rule

        Assert.True(await service.CheckOnceAsync(default));
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // What the banner can say about the messages above (a category, never the text)

    [Theory]
    [InlineData("Cloudflare: could not look up the zone (HTTP 403, 9109: Invalid access token).", "the DNS provider (Cloudflare) could not publish or remove the challenge record")]
    [InlineData("Cloudflare: no active zone found for _acme-challenge.mx.example.com (does the API token have access?)", "the DNS provider (Cloudflare) could not publish or remove the challenge record")]
    [InlineData("Authorization for mx.example.com is still Pending after 45 checks", "the CA could not validate the challenge")]
    [InlineData("The CA issued a certificate that does not cover 'mx.example.com' (it covers other.example.com).", "the CA sent a certificate that does not match the order")]
    [InlineData("The CA's certificate chain has no certificate for the key of this order (it sent another CA's certificate or one for another key).", "the CA sent a certificate that does not match the order")]
    [InlineData("The CA sent no certificate (the answer is empty or not PEM).", "the CA sent a certificate that does not match the order")]
    [InlineData("The CA's certificate chain is damaged or cut off: 2 certificates start but 0 are complete.", "the CA sent a certificate that does not match the order")]
    [InlineData("The ACME server sent an answer this client cannot read (JsonException: x).", "the CA's answer could not be understood")]
    [InlineData("The CA's directory does not offer an endpoint this client needs (ACME operation not supported).", "the CA's answer could not be understood")]
    [InlineData("The order is still Processing after it was finalized after 45 checks", "the CA did not finish the order")]
    [InlineData("The CA marked the order invalid after it was finalized: CAA record prohibits issuance", "the CA did not finish the order")]
    [InlineData("ACME server error: slow down (rateLimited)", "the CA refused the request")]
    public void The_new_failure_messages_have_a_category_for_the_banner(string error, string expected) => Assert.Equal(expected, AcmeFailureCategory.Describe(error));

    // ---------------------------------------------------------------------------------------------------------------------------------
    // The service does not trust a runner: what it is handed is checked again

    [Theory]
    [InlineData("wrong-names", "does not cover 'mx.service.test'")]
    [InlineData("wrong-key", "does not belong to the certificate")]
    [InlineData("empty", "The CA sent no certificate")]
    [InlineData("garbage", "The CA sent no certificate")]
    public async Task A_runner_that_hands_back_a_certificate_that_is_not_the_orders_is_a_recorded_failure_and_nothing_is_stored(string kind, string expected)
    {
        using var rig = new AcmeServiceRig();
        var service = new AcmeRenewalService(rig.Config, rig.Protector, new BadAnswerRunner(kind), rig.Dns, rig.Options(), rig.Clock, rig.Log);

        Assert.False(await service.CheckOnceAsync(default));

        Assert.Empty(await rig.Config.GetCertificatesAsync(default));
        var renewal = await rig.RenewalAsync();
        Assert.Equal("failed", renewal.Status);
        Assert.Contains(expected, renewal.LastError);
    }

    [Fact]
    public async Task The_same_fake_runner_with_a_correct_answer_is_stored_so_the_checks_above_are_what_refuse_it()
    {
        using var rig = new AcmeServiceRig();
        var service = new AcmeRenewalService(rig.Config, rig.Protector, new BadAnswerRunner("correct"), rig.Dns, rig.Options(), rig.Clock, rig.Log);

        Assert.True(await service.CheckOnceAsync(default));

        Assert.Single(await rig.Config.GetCertificatesAsync(default));
    }

    private sealed class BadAnswerRunner(string kind) : IAcmeOrderRunner
    {
        public Task<AcmeIssuedCertificate> IssueAsync(AcmeOrderRequest request, IDnsChallengeProvider dns, CancellationToken cancellationToken)
        {
            using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            using var other = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            string name = kind == "wrong-names" ? "someone-else.service.test" : request.Domains[0];
            var certificateRequest = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=" + name, key, System.Security.Cryptography.HashAlgorithmName.SHA256);
            var san = new System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder();
            san.AddDnsName(name);
            certificateRequest.CertificateExtensions.Add(san.Build());
            using var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(90));
            string chain = kind switch { "empty" => "", "garbage" => "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n", _ => certificate.ExportCertificatePem() };
            byte[] pkcs8 = (kind == "wrong-key" ? other : key).ExportPkcs8PrivateKey();
            return Task.FromResult(new AcmeIssuedCertificate(chain, pkcs8, "-----BEGIN PRIVATE KEY-----\nQUNNRQ==\n-----END PRIVATE KEY-----", "https://ca.example/acct/1", certificate.NotAfter.ToUniversalTime()));
        }
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // The cost of a call: nothing is slept

    [Fact]
    public async Task No_order_in_this_suite_waits_for_real_the_runner_only_records_what_it_would_wait()
    {
        using var rig = new AcmeServiceRig();
        rig.Ca.FinalizeProcessingPolls = 2;
        rig.Ca.ValidationPolls = 3;

        Assert.True(await rig.Service().CheckOnceAsync(default));

        Assert.Equal([200, 400, 200, 400], rig.Pauses.Select(p => (int)p.TotalMilliseconds));
    }
}
