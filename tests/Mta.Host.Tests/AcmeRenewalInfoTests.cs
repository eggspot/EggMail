using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Tests.Api;
using Mta.Host.Tls;
using Mta.Storage;
using Mta.Storage.Sqlite;

namespace Mta.Host.Tests;

/// <summary>The renewal timing rules with ACME Renewal Information (RFC 9773): pure rules with fixed clocks and random numbers.</summary>
public class AcmeRenewalScheduleTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 14, 8, 0, 0, TimeSpan.Zero);
    private const string Thumb = "AB12";

    private static AcmeRenewalInfo Window(TimeSpan startFromNow, TimeSpan endFromNow, TimeSpan? retryAfter = null, string? explanation = null) =>
        new(Now + startFromNow, Now + endFromNow, retryAfter, explanation);

    [Theory]
    [InlineData(0.0, 10)]
    [InlineData(0.5, 15)]
    [InlineData(0.999, 20)]
    public void The_renewal_time_is_chosen_inside_the_window_by_the_random_number(double random, int expectedDay)
    {
        var advice = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(10), TimeSpan.FromDays(20)), null, Now, () => random);

        Assert.Equal(Now.AddDays(expectedDay), advice.RenewAt!.Value, TimeSpan.FromDays(0.02));
        Assert.True(advice.HasWindow);
        Assert.Equal(Now.AddDays(10), advice.WindowStart);
        Assert.Equal(Now.AddDays(20), advice.WindowEnd);
    }

    [Fact]
    public void The_same_window_keeps_the_chosen_time_and_a_new_window_chooses_again()
    {
        var first = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(10), TimeSpan.FromDays(20)), null, Now, () => 0.25);

        var later = Now.AddHours(6);
        var same = AcmeRenewalSchedule.FromInfo(Thumb, new AcmeRenewalInfo(first.WindowStart!.Value, first.WindowEnd!.Value, null, null), first, later, () => 0.9);
        Assert.Equal(first.RenewAt, same.RenewAt); // not re-rolled on every poll: that would drift to the end of the window

        var moved = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(1), TimeSpan.FromDays(3)), first, later, () => 0.5);
        Assert.Equal(Now.AddDays(2), moved.RenewAt!.Value, TimeSpan.FromSeconds(1)); // the CA changed its mind (revocation, shorter lifetime)
    }

    [Theory]
    [InlineData(null, 6 * 60)]       // the CA said nothing: a few times a day
    [InlineData(30, 1)]              // never more often than a minute
    [InlineData(2 * 3600, 2 * 60)]   // honoured
    [InlineData(10 * 86400, 24 * 60)] // at least once a day
    public void The_next_check_follows_Retry_After_within_bounds(int? retryAfterSeconds, int expectedMinutes)
    {
        var info = Window(TimeSpan.FromDays(10), TimeSpan.FromDays(20), retryAfterSeconds is null ? null : TimeSpan.FromSeconds(retryAfterSeconds.Value));

        var advice = AcmeRenewalSchedule.FromInfo(Thumb, info, null, Now, () => 0.5);

        Assert.Equal(Now.AddMinutes(expectedMinutes), advice.NextCheckAt);
        Assert.False(AcmeRenewalSchedule.ShouldCheck(advice, Now.AddMinutes(expectedMinutes - 1)));
        Assert.True(AcmeRenewalSchedule.ShouldCheck(advice, Now.AddMinutes(expectedMinutes)));
        Assert.True(AcmeRenewalSchedule.ShouldCheck(null, Now));
    }

    [Fact]
    public void A_window_that_ends_before_it_starts_is_not_advice()
    {
        var bad = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(5), TimeSpan.FromDays(5)), null, Now, () => 0.5);

        Assert.False(bad.HasWindow);
        Assert.Contains("ends before it starts", bad.Error);
        Assert.Equal(Now + AcmeRenewalSchedule.ErrorCheckInterval, bad.NextCheckAt);
    }

    [Fact]
    public void A_failed_request_keeps_an_earlier_window_of_the_same_certificate_and_a_missing_ARI_is_asked_about_daily()
    {
        var good = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(10), TimeSpan.FromDays(20)), null, Now, () => 0.5);

        var failed = AcmeRenewalSchedule.FromFailure(Thumb, good, Now.AddHours(7), "HTTP 503");
        Assert.Equal(good.RenewAt, failed.RenewAt);
        Assert.Equal("HTTP 503", failed.Error);
        Assert.Equal(Now.AddHours(8), failed.NextCheckAt);

        var none = AcmeRenewalSchedule.FromFailure(Thumb, null, Now, "", unsupported: true);
        Assert.True(none.Unsupported);
        Assert.False(none.HasWindow);
        Assert.Null(none.Error);
        Assert.Equal(Now.AddDays(1), none.NextCheckAt);
    }

    [Fact]
    public void Due_means_the_chosen_time_has_come_whatever_the_lifetime_rule_says()
    {
        var notBefore = Now;
        var notAfter = Now.AddDays(90);
        var early = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(20), TimeSpan.FromDays(30)), null, Now, () => 0.5); // day 25
        var late = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(70), TimeSpan.FromDays(80)), null, Now, () => 0.5);  // day 75

        // The lifetime rule (a third left) would renew at day 60; the CA's window wins in both directions.
        Assert.False(AcmeRenewalSchedule.IsDue(early, notBefore, notAfter, Now.AddDays(24), 1.0 / 3));
        Assert.True(AcmeRenewalSchedule.IsDue(early, notBefore, notAfter, Now.AddDays(25), 1.0 / 3));
        Assert.False(AcmeRenewalSchedule.IsDue(late, notBefore, notAfter, Now.AddDays(65), 1.0 / 3));
        Assert.True(AcmeRenewalSchedule.IsDue(late, notBefore, notAfter, Now.AddDays(75), 1.0 / 3));
    }

    [Fact]
    public void A_window_in_the_past_means_renew_now()
    {
        var immediate = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromHours(-1), TimeSpan.FromHours(-1) + TimeSpan.FromSeconds(1)), null, Now, () => 0.5);

        Assert.True(AcmeRenewalSchedule.IsDue(immediate, Now.AddDays(-10), Now.AddDays(80), Now, 1.0 / 3));
    }

    [Fact]
    public void A_wrong_window_cannot_let_the_certificate_expire()
    {
        var notBefore = Now;
        var notAfter = Now.AddDays(90);
        var absurd = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(300), TimeSpan.FromDays(400)), null, Now, () => 0.5);

        Assert.False(AcmeRenewalSchedule.IsDue(absurd, notBefore, notAfter, Now.AddDays(74), 1.0 / 3));
        Assert.True(AcmeRenewalSchedule.IsDue(absurd, notBefore, notAfter, Now.AddDays(75), 1.0 / 3)); // a sixth of the lifetime left
    }

    [Fact]
    public void Without_a_window_the_lifetime_rule_decides()
    {
        var notBefore = Now;
        var notAfter = Now.AddDays(90);

        Assert.False(AcmeRenewalSchedule.IsDue(null, notBefore, notAfter, Now.AddDays(59), 1.0 / 3));
        Assert.True(AcmeRenewalSchedule.IsDue(null, notBefore, notAfter, Now.AddDays(60), 1.0 / 3));
        var unsupported = AcmeRenewalSchedule.FromFailure(Thumb, null, Now, "", unsupported: true);
        Assert.False(AcmeRenewalSchedule.IsDue(unsupported, notBefore, notAfter, Now.AddDays(59), 1.0 / 3));
        Assert.True(AcmeRenewalSchedule.IsDue(unsupported, notBefore, notAfter, Now.AddDays(60), 1.0 / 3));
    }

    [Fact]
    public void The_advice_round_trips_through_JSON_and_belongs_to_one_certificate()
    {
        var advice = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(10), TimeSpan.FromDays(20), TimeSpan.FromHours(3), "https://ca.example/why"), null, Now, () => 0.5);

        var read = AcmeRenewalAdvice.Parse(advice.ToJson(), "ab12");

        Assert.Equal(advice, read);
        Assert.Null(AcmeRenewalAdvice.Parse(advice.ToJson(), "OTHER")); // a renewed certificate starts from scratch
        Assert.Null(AcmeRenewalAdvice.Parse("{not json", Thumb));
        Assert.Null(AcmeRenewalAdvice.Parse(null, Thumb));
        Assert.Null(AcmeRenewalAdvice.Parse("{\"ari\":1}", Thumb)); // other content of the column (older data) is ignored
    }
}

/// <summary>
/// <see cref="AcmeRenewalService"/> with ARI over a real SQLite config store, a controllable clock and a CA that answers as scripted. The same
/// flow against Pebble is in <c>tests/Mta.Integration.Tests/Acme</c>.
/// </summary>
public class AcmeRenewalInfoServiceTests : IAsyncLifetime
{
    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-ari-").FullName;
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 10, 14, 8, 0, 0, TimeSpan.Zero));
    private readonly TestProtector _protector = new();
    private readonly ScriptedCa _ca;
    private SqliteStorage _storage = null!;
    private const string Host = "mx.ari.example";

    public AcmeRenewalInfoServiceTests() => _ca = new ScriptedCa(_clock);

    public async Task InitializeAsync()
    {
        _storage = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _dir } }, _clock);
        await _storage.InitializeAsync(default);
    }

    public async Task DisposeAsync()
    {
        await _storage.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, recursive: true);
    }

    private AcmeRenewalService Service(bool useRenewalInfo = true, double random = 0.5) => new(
        _storage.Config, _protector, _ca, new NoDns(),
        new AcmeSection { Enabled = true, Email = "ops@ari.example", Domains = [Host], PropagationDelay = TimeSpan.Zero, UseRenewalInfo = useRenewalInfo, DirectoryUrl = "https://ca.example/dir" },
        _clock, random: () => random);

    private async Task<AcmeRenewalAdvice?> StoredAdviceAsync()
    {
        var cert = Assert.Single(await _storage.Config.GetCertificatesAsync(default));
        return AcmeRenewalAdvice.Parse((await _storage.Config.GetAcmeRenewalsAsync(default)).Single().AriJson, cert.Thumbprint);
    }

    private async Task<AcmeRenewalService> IssuedAsync(double random = 0.5)
    {
        var service = Service(random: random);
        _ca.Info = () => null;
        Assert.True(await service.CheckOnceAsync(default));
        Assert.Single(_ca.Orders);
        Assert.Equal(0, _ca.InfoRequests); // the first order is not a renewal: nothing to ask about
        return service;
    }

    [Fact]
    public async Task The_CAs_window_decides_earlier_than_the_lifetime_rule_and_later_than_it()
    {
        var service = await IssuedAsync();
        var issuedAt = _clock.UtcNow;
        _ca.Info = () => new AcmeRenewalInfo(issuedAt.AddDays(20), issuedAt.AddDays(30), null, "https://ca.example/why"); // day 25 with random 0.5

        _clock.Advance(TimeSpan.FromDays(24));
        Assert.False(await service.CheckOnceAsync(default)); // asked, not due: the lifetime rule would say "not yet" as well
        Assert.Equal(1, _ca.InfoRequests);
        var advice = await StoredAdviceAsync();
        Assert.Equal(issuedAt.AddDays(25), advice!.RenewAt!.Value, TimeSpan.FromSeconds(1));
        Assert.Equal("https://ca.example/why", advice.ExplanationUrl);

        _clock.Advance(TimeSpan.FromDays(1.1));
        Assert.True(await service.CheckOnceAsync(default)); // day 25: due by the CA's window, 35 days before the lifetime rule
        Assert.Equal(2, _ca.Orders.Count);

        // The new certificate has no advice yet; a window far in the future is followed up to the safety limit (a sixth of the lifetime left).
        Assert.Null(await StoredAdviceAsync());
        var renewedAt = _clock.UtcNow;
        _ca.Info = () => new AcmeRenewalInfo(renewedAt.AddDays(70), renewedAt.AddDays(80), null, null);
        _clock.Advance(TimeSpan.FromDays(65)); // the lifetime rule would have renewed at day 60
        Assert.False(await service.CheckOnceAsync(default));
        _clock.Advance(TimeSpan.FromDays(10));  // day 75 = window middle
        Assert.True(await service.CheckOnceAsync(default));
        Assert.Equal(3, _ca.Orders.Count);
    }

    [Fact]
    public async Task A_window_in_the_past_renews_at_once_and_the_order_names_the_certificate_it_replaces()
    {
        var service = await IssuedAsync();
        var old = Assert.Single(await _storage.Config.GetCertificatesAsync(default));
        _ca.Info = () => new AcmeRenewalInfo(_clock.UtcNow.AddHours(-1), _clock.UtcNow.AddHours(-1).AddSeconds(1), null, "https://ca.example/revoked");

        Assert.True(await service.CheckOnceAsync(default)); // no time passed at all

        Assert.Equal(2, _ca.Orders.Count);
        Assert.Null(_ca.Orders[0].ReplacesCertificatePem);
        Assert.Equal(old.ChainPem, _ca.Orders[1].ReplacesCertificatePem);
        var renewed = Assert.Single(await _storage.Config.GetCertificatesAsync(default));
        Assert.Equal(old.Id, renewed.Id);
        Assert.NotEqual(old.Thumbprint, renewed.Thumbprint);
    }

    [Fact]
    public async Task The_CA_is_asked_again_only_when_Retry_After_has_passed_and_a_changed_window_is_followed()
    {
        var service = await IssuedAsync();
        var t = _clock.UtcNow;
        _ca.Info = () => new AcmeRenewalInfo(t.AddDays(20), t.AddDays(30), TimeSpan.FromHours(3), null);

        Assert.False(await service.CheckOnceAsync(default));
        _clock.Advance(TimeSpan.FromHours(2));
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(1, _ca.InfoRequests); // inside Retry-After: the stored advice is used

        _clock.Advance(TimeSpan.FromHours(1));
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(2, _ca.InfoRequests);

        // The CA moves the window to "now" (for example after an incident): followed at the next question.
        _ca.Info = () => new AcmeRenewalInfo(_clock.UtcNow.AddHours(-1), _clock.UtcNow, TimeSpan.FromHours(3), null);
        _clock.Advance(TimeSpan.FromHours(3));
        Assert.True(await service.CheckOnceAsync(default));
    }

    [Fact]
    public async Task A_CA_without_ARI_or_with_a_failing_one_falls_back_to_the_lifetime_rule()
    {
        var service = await IssuedAsync();
        _ca.Info = () => null; // directory without renewalInfo

        _clock.Advance(TimeSpan.FromDays(59));
        Assert.False(await service.CheckOnceAsync(default));
        var advice = await StoredAdviceAsync();
        Assert.True(advice!.Unsupported);
        Assert.Equal(1, _ca.InfoRequests);
        _clock.Advance(TimeSpan.FromHours(23));
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(1, _ca.InfoRequests); // a CA without ARI is not asked every hour

        _ca.Info = () => throw new AcmeException("ACME server error: 503");
        _clock.Advance(TimeSpan.FromHours(2)); // day 60 + 1 h: the lifetime rule says renew; the failing ARI must not block that
        Assert.True(await service.CheckOnceAsync(default));
        Assert.Equal(2, _ca.InfoRequests);
        Assert.Equal(2, _ca.Orders.Count);
    }

    [Fact]
    public async Task A_failing_ARI_is_recorded_and_retried_after_an_hour_not_at_every_check()
    {
        var service = await IssuedAsync();
        _ca.Info = () => throw new AcmeException("ACME server error: 503");

        Assert.False(await service.CheckOnceAsync(default));
        var advice = await StoredAdviceAsync();
        Assert.Contains("503", advice!.Error);
        Assert.False(advice.Unsupported);
        _clock.Advance(TimeSpan.FromMinutes(30));
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(1, _ca.InfoRequests);
        _clock.Advance(TimeSpan.FromMinutes(31));
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(2, _ca.InfoRequests);
    }

    [Fact]
    public async Task Turned_off_the_CA_is_never_asked_and_the_lifetime_rule_decides()
    {
        var service = Service(useRenewalInfo: false);
        Assert.True(await service.CheckOnceAsync(default));
        _ca.Info = () => new AcmeRenewalInfo(_clock.UtcNow.AddHours(-1), _clock.UtcNow, null, null); // "renew now", ignored

        Assert.False(await service.CheckOnceAsync(default));
        _clock.Advance(TimeSpan.FromDays(61));
        Assert.True(await service.CheckOnceAsync(default));

        Assert.Equal(0, _ca.InfoRequests);
    }

    [Fact]
    public async Task A_failed_renewal_order_keeps_the_advice_and_waits_for_the_back_off()
    {
        var service = await IssuedAsync();
        var t = _clock.UtcNow;
        _ca.Info = () => new AcmeRenewalInfo(t.AddHours(-2), t.AddHours(-1), null, null);
        _ca.FailOrders = true;

        Assert.False(await service.CheckOnceAsync(default)); // due, the order fails
        var renewal = Assert.Single(await _storage.Config.GetAcmeRenewalsAsync(default));
        Assert.Equal(("failed", 1), (renewal.Status, renewal.Failures));
        Assert.NotNull(renewal.AriJson); // the advice about the certificate in use survives the failed attempt
        Assert.True((await StoredAdviceAsync())!.HasWindow);

        Assert.False(await service.CheckOnceAsync(default)); // back-off
        Assert.Equal(2, _ca.Orders.Count);

        _ca.FailOrders = false;
        _clock.Advance(TimeSpan.FromMinutes(11));
        Assert.True(await service.CheckOnceAsync(default)); // due still, the window is in the past
        Assert.Equal(3, _ca.Orders.Count);
        Assert.Null(await StoredAdviceAsync()); // a new certificate: advice cleared
    }

    [Fact]
    public async Task Other_names_are_ordered_without_asking_the_CA()
    {
        await IssuedAsync();
        var changed = new AcmeRenewalService(_storage.Config, _protector, _ca, new NoDns(),
            new AcmeSection { Enabled = true, Domains = [Host, "other.ari.example"], PropagationDelay = TimeSpan.Zero, DirectoryUrl = "https://ca.example/dir" }, _clock);

        Assert.True(await changed.CheckOnceAsync(default));

        Assert.Equal(0, _ca.InfoRequests);
        Assert.Equal(2, _ca.Orders.Count);
    }

    private sealed class NoDns : IDnsChallengeProvider
    {
        public ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken cancellationToken) => ValueTask.FromResult("h");

        public ValueTask DeleteTxtAsync(string handle, CancellationToken cancellationToken) => ValueTask.CompletedTask;
    }

    /// <summary>A CA that issues 90-day self-signed certificates and answers renewal-information requests as the test scripts.</summary>
    private sealed class ScriptedCa(TestClock clock) : IAcmeOrderRunner
    {
        public List<AcmeOrderRequest> Orders { get; } = [];

        public int InfoRequests { get; private set; }

        public bool FailOrders { get; set; }

        public Func<AcmeRenewalInfo?> Info { get; set; } = () => null;

        public Task<AcmeIssuedCertificate> IssueAsync(AcmeOrderRequest request, IDnsChallengeProvider dns, CancellationToken cancellationToken)
        {
            Orders.Add(request);
            if (FailOrders)
            {
                throw new AcmeException("ACME server error: try later");
            }

            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var req = new CertificateRequest("CN=" + request.Domains[0], key, HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();
            foreach (string d in request.Domains)
            {
                san.AddDnsName(d);
            }

            req.CertificateExtensions.Add(san.Build());
            // Every certificate differs (serial), as a CA's would.
            using X509Certificate2 cert = req.CreateSelfSigned(clock.UtcNow.AddMinutes(-5), clock.UtcNow.AddDays(90));
            return Task.FromResult(new AcmeIssuedCertificate(cert.ExportCertificatePem(), key.ExportPkcs8PrivateKey(), "-----BEGIN PRIVATE KEY-----\nQUNNRQ==\n-----END PRIVATE KEY-----", "https://ca.example/acct/1", cert.NotAfter.ToUniversalTime()));
        }

        public Task<AcmeRenewalInfo?> GetRenewalInfoAsync(string directoryUrl, string certificateChainPem, CancellationToken cancellationToken)
        {
            InfoRequests++;
            return Task.FromResult(Info());
        }
    }
}
