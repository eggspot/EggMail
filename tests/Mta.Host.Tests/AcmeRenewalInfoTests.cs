using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
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
    private static readonly TimeSpan Hourly = TimeSpan.FromHours(1);
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
        Assert.Equal(0, advice.Failures);
    }

    [Fact]
    public void The_same_window_keeps_the_chosen_time_and_a_different_window_chooses_again()
    {
        var first = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(10), TimeSpan.FromDays(20)), null, Now, () => 0.25);
        var later = Now.AddHours(6);

        var same = AcmeRenewalSchedule.FromInfo(Thumb, new AcmeRenewalInfo(first.WindowStart!.Value, first.WindowEnd!.Value, null, null), first, later, () => 0.9);
        Assert.Equal(first.RenewAt, same.RenewAt); // not re-rolled on every poll: that would drift to the end of the window

        // A window that merely slides by a few minutes (a CA that computes it from the current time) is the same window.
        var slid = AcmeRenewalSchedule.FromInfo(Thumb, new AcmeRenewalInfo(first.WindowStart.Value.AddMinutes(3), first.WindowEnd.Value.AddMinutes(-4), null, null), first, later, () => 0.9);
        Assert.Equal(first.RenewAt, slid.RenewAt);

        // The CA changed its mind (revocation, shorter lifetime): a few minutes is not that, ten is.
        var moved = AcmeRenewalSchedule.FromInfo(Thumb, new AcmeRenewalInfo(first.WindowStart.Value.AddMinutes(10), first.WindowEnd.Value, null, null), first, later, () => 0.5);
        Assert.NotEqual(first.RenewAt, moved.RenewAt);
        var elsewhere = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(1), TimeSpan.FromDays(3)), first, later, () => 0.5);
        Assert.Equal(Now.AddDays(2), elsewhere.RenewAt!.Value, TimeSpan.FromSeconds(1));
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
    public void A_stored_wait_further_away_than_a_day_is_not_trusted()
    {
        var advice = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(10), TimeSpan.FromDays(20)), null, Now, () => 0.5);

        Assert.False(AcmeRenewalSchedule.ShouldCheck(advice, Now));
        // The clock was stepped back by a week (or the stored value is damaged): the CA is asked at the next check instead of waiting a week.
        Assert.True(AcmeRenewalSchedule.ShouldCheck(advice, Now.AddDays(-7)));
        Assert.True(AcmeRenewalSchedule.ShouldCheck(advice with { NextCheckAt = Now.AddYears(50) }, Now));
    }

    [Fact]
    public void A_window_that_ends_before_it_starts_is_not_advice()
    {
        var bad = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(5), TimeSpan.FromDays(5)), null, Now, () => 0.5);

        Assert.False(bad.HasWindow);
        Assert.Contains("ends before it starts", bad.Error);
        Assert.Equal(Now + AcmeRenewalSchedule.ErrorCheckInterval, bad.NextCheckAt); // the CA answered: not a server error
    }

    [Fact]
    public void After_an_error_that_is_not_a_server_error_the_CA_is_asked_again_in_six_hours()
    {
        var good = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(10), TimeSpan.FromDays(20)), null, Now, () => 0.5);

        var failed = AcmeRenewalSchedule.FromFailure(Thumb, good, Now.AddHours(7), "HTTP 404", transient: false);

        Assert.Equal(good.RenewAt, failed.RenewAt); // an earlier window of the same certificate stays valid
        Assert.Equal("HTTP 404", failed.Error);
        Assert.Equal(Now.AddHours(13), failed.NextCheckAt);
        Assert.Equal(1, failed.Failures);
        Assert.Equal(Now.AddHours(13 + 6), AcmeRenewalSchedule.FromFailure(Thumb, failed, Now.AddHours(13), "HTTP 404", transient: false).NextCheckAt);
    }

    [Fact]
    public void After_server_errors_and_network_failures_the_wait_doubles_up_to_six_hours()
    {
        AcmeRenewalAdvice? advice = null;
        var expected = new[] { 5, 10, 20, 40, 80, 160, 320, 360, 360 };
        var now = Now;
        foreach (int minutes in expected)
        {
            advice = AcmeRenewalSchedule.FromFailure(Thumb, advice, now, "HTTP 503", transient: true);
            Assert.Equal(now.AddMinutes(minutes), advice.NextCheckAt);
            now = advice.NextCheckAt;
        }

        Assert.Equal(expected.Length, advice!.Failures);
        // A good answer ends the series.
        Assert.Equal(0, AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(10), TimeSpan.FromDays(20)), advice, now, () => 0.5).Failures);
    }

    [Fact]
    public void A_directory_without_ARI_is_looked_at_again_tomorrow()
    {
        var none = AcmeRenewalSchedule.FromDirectoryWithoutRenewalInfo(Thumb, Now);

        Assert.True(none.DirectoryHasNoRenewalInfo);
        Assert.False(none.HasWindow);
        Assert.Null(none.Error);
        Assert.Equal(Now.AddDays(1), none.NextCheckAt);
        Assert.False(AcmeRenewalSchedule.ShouldCheck(none, Now.AddHours(23)));
    }

    [Fact]
    public void Text_from_the_CA_is_bounded_and_the_explanation_must_be_a_short_https_URL()
    {
        string Url(string? url) => AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(1), TimeSpan.FromDays(2), null, url), null, Now, () => 0.5).ExplanationUrl ?? "(none)";

        Assert.Equal("https://ca.example/why", Url("https://ca.example/why"));
        Assert.Equal("(none)", Url("http://ca.example/why"));
        Assert.Equal("(none)", Url("/relative/why"));
        Assert.Equal("(none)", Url("javascript:alert(1)"));
        Assert.Equal("(none)", Url("https://ca.example/" + new string('a', 2100)));
        Assert.Equal("(none)", Url(null));

        var failed = AcmeRenewalSchedule.FromFailure(Thumb, null, Now, new string('x', 5000), transient: false);
        Assert.Equal(AcmeRenewalSchedule.MaxErrorLength, failed.Error!.Length);
    }

    [Fact]
    public void Due_means_the_chosen_time_comes_before_the_next_check_whatever_the_lifetime_rule_says()
    {
        var notBefore = Now;
        var notAfter = Now.AddDays(90);
        var early = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(20), TimeSpan.FromDays(30)), null, Now, () => 0.5);    // day 25
        var late = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(62), TimeSpan.FromDays(68)), null, Now, () => 0.5);     // day 65

        // The lifetime rule (a third left) would renew at day 60; the CA's window wins in both directions.
        Assert.False(AcmeRenewalSchedule.IsDue(early, notBefore, notAfter, Now.AddDays(24), 1.0 / 3, Hourly));
        Assert.True(AcmeRenewalSchedule.IsDue(early, notBefore, notAfter, Now.AddDays(25) - Hourly, 1.0 / 3, Hourly)); // RFC 9773 4.2 step 5: before the next check
        Assert.False(AcmeRenewalSchedule.IsDue(late, notBefore, notAfter, Now.AddDays(61), 1.0 / 3, Hourly)); // the lifetime rule alone would say yes since day 60
        Assert.False(AcmeRenewalSchedule.IsDue(late, notBefore, notAfter, Now.AddDays(64), 1.0 / 3, Hourly));
        Assert.True(AcmeRenewalSchedule.IsDue(late, notBefore, notAfter, Now.AddDays(65), 1.0 / 3, Hourly));
    }

    [Fact]
    public void A_window_in_the_past_means_renew_now_for_a_certificate_old_enough()
    {
        var immediate = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromHours(-1), TimeSpan.FromHours(-1) + TimeSpan.FromSeconds(1)), null, Now, () => 0.5);

        Assert.True(AcmeRenewalSchedule.IsDue(immediate, Now.AddDays(-10), Now.AddDays(80), Now, 1.0 / 3, Hourly));
    }

    [Fact]
    public void ARI_alone_never_renews_a_young_certificate()
    {
        var lifetime = TimeSpan.FromDays(90);
        var immediate = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromHours(-2), TimeSpan.FromHours(-1)), null, Now, () => 0.5);

        // A day, or a twentieth of the lifetime if that is longer (4.5 days here).
        Assert.Equal(TimeSpan.FromDays(4.5), AcmeRenewalSchedule.MinimumAge(lifetime));
        Assert.Equal(TimeSpan.FromDays(1), AcmeRenewalSchedule.MinimumAge(TimeSpan.FromDays(6)));
        Assert.False(AcmeRenewalSchedule.IsDue(immediate, Now.AddDays(-4.4), Now.AddDays(85.6), Now, 1.0 / 3, Hourly));
        Assert.True(AcmeRenewalSchedule.IsDue(immediate, Now.AddDays(-4.5), Now.AddDays(85.5), Now, 1.0 / 3, Hourly));
        Assert.False(AcmeRenewalSchedule.IsDue(immediate, Now.AddMinutes(-5), Now.AddDays(90), Now, 1.0 / 3, Hourly)); // just issued
    }

    [Fact]
    public void A_wrong_window_cannot_let_the_certificate_expire_and_the_limit_never_exceeds_the_configured_rule()
    {
        var notBefore = Now;
        var notAfter = Now.AddDays(90);
        var absurd = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(300), TimeSpan.FromDays(400)), null, Now, () => 0.5);

        Assert.False(AcmeRenewalSchedule.IsDue(absurd, notBefore, notAfter, Now.AddDays(74), 1.0 / 3, Hourly));
        Assert.True(AcmeRenewalSchedule.IsDue(absurd, notBefore, notAfter, Now.AddDays(75), 1.0 / 3, Hourly)); // a sixth of the lifetime left

        // An operator who asks for renewal only in the last tenth must not be renewed earlier than that by the safety limit.
        Assert.False(AcmeRenewalSchedule.IsDue(absurd, notBefore, notAfter, Now.AddDays(75), 0.1, Hourly));
        Assert.True(AcmeRenewalSchedule.IsDue(absurd, notBefore, notAfter, Now.AddDays(81), 0.1, Hourly));
    }

    [Fact]
    public void Without_a_window_the_lifetime_rule_decides()
    {
        var notBefore = Now;
        var notAfter = Now.AddDays(90);
        var none = AcmeRenewalSchedule.FromDirectoryWithoutRenewalInfo(Thumb, Now);
        var failed = AcmeRenewalSchedule.FromFailure(Thumb, null, Now, "HTTP 500", transient: true);

        foreach (AcmeRenewalAdvice? advice in new[] { null, none, failed })
        {
            Assert.False(AcmeRenewalSchedule.IsDue(advice, notBefore, notAfter, Now.AddDays(59), 1.0 / 3, Hourly));
            Assert.True(AcmeRenewalSchedule.IsDue(advice, notBefore, notAfter, Now.AddDays(60), 1.0 / 3, Hourly));
        }
    }

    [Fact]
    public void The_advice_round_trips_through_JSON_and_belongs_to_one_certificate()
    {
        var advice = AcmeRenewalSchedule.FromInfo(Thumb, Window(TimeSpan.FromDays(10), TimeSpan.FromDays(20), TimeSpan.FromHours(3), "https://ca.example/why"), null, Now, () => 0.5);

        var read = AcmeRenewalAdvice.Parse(advice.ToJson(), "ab12");

        Assert.Equal(advice, read);
        Assert.Equal(AcmeRenewalSchedule.FromDirectoryWithoutRenewalInfo(Thumb, Now), AcmeRenewalAdvice.Parse(AcmeRenewalSchedule.FromDirectoryWithoutRenewalInfo(Thumb, Now).ToJson(), Thumb));
        Assert.Null(AcmeRenewalAdvice.Parse(advice.ToJson(), "OTHER")); // a renewed certificate starts from scratch
        Assert.Null(AcmeRenewalAdvice.Parse("{not json", Thumb));
        Assert.Null(AcmeRenewalAdvice.Parse(null, Thumb));
        Assert.Null(AcmeRenewalAdvice.Parse("{\"ari\":1}", Thumb)); // other content of the column (older data) is ignored
    }
}

public class AcmeRenewalInfoConfigTests
{
    [Fact]
    public void The_switch_binds_from_configuration_and_is_on_by_default()
    {
        LoadedConfig Load(params (string Key, string? Value)[] values) =>
            ConfigLoader.Load(new ConfigurationBuilder().AddInMemoryCollection(values.ToDictionary(v => v.Key, v => v.Value)).Build());

        Assert.True(Load().Config.Acme.UseRenewalInfo);
        var off = Load(("Acme:UseRenewalInfo", "false"));
        Assert.True(off.IsValid, string.Join("; ", off.Errors));
        Assert.False(off.Config.Acme.UseRenewalInfo);
        Assert.True(Load(("Acme:UseRenewalInfo", "true")).Config.Acme.UseRenewalInfo);
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
    private IConfigStore _config = null!;
    private const string Host = "mx.ari.example";
    private static readonly TimeSpan MinAge = AcmeRenewalSchedule.MinimumAge(TimeSpan.FromDays(90));

    public AcmeRenewalInfoServiceTests() => _ca = new ScriptedCa(_clock);

    public async Task InitializeAsync()
    {
        _storage = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _dir } }, _clock);
        await _storage.InitializeAsync(default);
        _config = _storage.Config;
    }

    public async Task DisposeAsync()
    {
        await _storage.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, recursive: true);
    }

    private AcmeRenewalService Service(bool useRenewalInfo = true, double random = 0.5, IConfigStore? config = null, params string[] domains) => new(
        config ?? _config, _protector, _ca, new NoDns(),
        new AcmeSection { Enabled = true, Email = "ops@ari.example", Domains = domains.Length > 0 ? [.. domains] : [Host], PropagationDelay = TimeSpan.Zero, UseRenewalInfo = useRenewalInfo, DirectoryUrl = "https://ca.example/dir" },
        _clock, random: () => random);

    private async Task<AcmeRenewalAdvice?> StoredAdviceAsync()
    {
        var cert = Assert.Single(await _config.GetCertificatesAsync(default));
        return AcmeRenewalAdvice.Parse((await _config.GetAcmeRenewalsAsync(default)).Single().AriJson, cert.Thumbprint);
    }

    private async Task<AcmeRenewalService> IssuedAsync(double random = 0.5, IConfigStore? config = null)
    {
        var service = Service(random: random, config: config);
        _ca.Info = () => null;
        Assert.True(await service.CheckOnceAsync(default));
        Assert.Single(_ca.Orders);
        Assert.Equal(0, _ca.InfoRequests); // the first order is not a renewal: nothing to ask about
        return service;
    }

    [Fact]
    public async Task The_CAs_window_decides_earlier_than_the_lifetime_rule()
    {
        var service = await IssuedAsync();
        var issuedAt = _clock.UtcNow;
        _ca.Info = () => new AcmeRenewalInfo(issuedAt.AddDays(20), issuedAt.AddDays(30), null, "https://ca.example/why"); // day 25 with random 0.5

        _clock.Advance(TimeSpan.FromDays(24));
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(1, _ca.InfoRequests);
        var advice = await StoredAdviceAsync();
        Assert.Equal(issuedAt.AddDays(25), advice!.RenewAt!.Value, TimeSpan.FromSeconds(1));
        Assert.Equal("https://ca.example/why", advice.ExplanationUrl);

        _clock.Advance(TimeSpan.FromDays(1.1));
        Assert.True(await service.CheckOnceAsync(default)); // day 25: due by the CA's window, 35 days before the lifetime rule
        Assert.Equal(2, _ca.Orders.Count);
        Assert.Null(await StoredAdviceAsync()); // the new certificate has no advice yet
    }

    [Fact]
    public async Task The_CAs_window_decides_later_than_the_lifetime_rule_until_the_safety_limit()
    {
        var service = await IssuedAsync();
        var issuedAt = _clock.UtcNow;
        _ca.Info = () => new AcmeRenewalInfo(issuedAt.AddDays(62), issuedAt.AddDays(68), null, null); // day 65; the lifetime rule says day 60

        _clock.Advance(TimeSpan.FromDays(61));
        Assert.False(await service.CheckOnceAsync(default));
        _clock.Advance(TimeSpan.FromDays(3));
        Assert.False(await service.CheckOnceAsync(default)); // day 64
        _clock.Advance(TimeSpan.FromDays(1));
        Assert.True(await service.CheckOnceAsync(default)); // day 65
        Assert.Equal(2, _ca.Orders.Count);

        // A window far in the future is followed up to the safety limit: a sixth of the lifetime (day 75) at the latest.
        var renewedAt = _clock.UtcNow;
        _ca.Info = () => new AcmeRenewalInfo(renewedAt.AddDays(300), renewedAt.AddDays(400), null, null);
        _clock.Advance(TimeSpan.FromDays(74));
        Assert.False(await service.CheckOnceAsync(default));
        _clock.Advance(TimeSpan.FromDays(1.1));
        Assert.True(await service.CheckOnceAsync(default));
        Assert.Equal(3, _ca.Orders.Count);
    }

    [Fact]
    public async Task A_window_in_the_past_renews_a_certificate_that_is_old_enough_and_the_order_names_the_certificate_it_replaces()
    {
        var service = await IssuedAsync();
        var old = Assert.Single(await _config.GetCertificatesAsync(default));
        _ca.Info = () => new AcmeRenewalInfo(_clock.UtcNow.AddHours(-1), _clock.UtcNow.AddHours(-1).AddSeconds(1), null, "https://ca.example/revoked");
        _clock.Advance(MinAge);

        Assert.True(await service.CheckOnceAsync(default));

        Assert.Equal(2, _ca.Orders.Count);
        Assert.Null(_ca.Orders[0].ReplacesCertificatePem);
        Assert.Equal(old.ChainPem, _ca.Orders[1].ReplacesCertificatePem);
        var renewed = Assert.Single(await _config.GetCertificatesAsync(default));
        Assert.Equal(old.Id, renewed.Id);
        Assert.NotEqual(old.Thumbprint, renewed.Thumbprint);
    }

    [Fact]
    public async Task A_CA_that_keeps_answering_renew_now_causes_one_order_not_one_per_check()
    {
        var service = await IssuedAsync();
        _ca.Info = () => new AcmeRenewalInfo(_clock.UtcNow.AddHours(-2), _clock.UtcNow.AddHours(-1), null, null); // always "now"

        Assert.False(await service.CheckOnceAsync(default)); // the certificate is minutes old: not renewed on advice alone
        Assert.Single(_ca.Orders);
        _clock.Advance(MinAge + TimeSpan.FromHours(1));
        Assert.True(await service.CheckOnceAsync(default)); // old enough now: one renewal
        Assert.Equal(2, _ca.Orders.Count);

        // The new certificate meets the same answer at every hourly check for days, and is not renewed again until it is old enough.
        for (int hour = 0; hour < 24 * 4; hour++)
        {
            _clock.Advance(TimeSpan.FromHours(1));
            Assert.False(await service.CheckOnceAsync(default));
        }

        Assert.Equal(2, _ca.Orders.Count);
        _clock.Advance(TimeSpan.FromDays(1)); // 5 days after the renewal: past the minimum age of 4.5 days
        Assert.True(await service.CheckOnceAsync(default));
        Assert.Equal(3, _ca.Orders.Count);
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

        // The CA moves the window to "now" (for example after an incident), when the certificate is old enough: followed at the next question.
        _clock.Advance(MinAge);
        _ca.Info = () => new AcmeRenewalInfo(_clock.UtcNow.AddHours(-1), _clock.UtcNow, TimeSpan.FromHours(3), null);
        Assert.True(await service.CheckOnceAsync(default));
    }

    [Fact]
    public async Task A_CA_without_ARI_falls_back_to_the_lifetime_rule_and_is_asked_again_tomorrow()
    {
        var service = await IssuedAsync();
        _ca.Info = () => null; // directory without renewalInfo

        _clock.Advance(TimeSpan.FromDays(59));
        Assert.False(await service.CheckOnceAsync(default));
        Assert.True((await StoredAdviceAsync())!.DirectoryHasNoRenewalInfo);
        _clock.Advance(TimeSpan.FromHours(23));
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(1, _ca.InfoRequests); // a CA without ARI is not asked every hour

        _clock.Advance(TimeSpan.FromHours(2)); // day 60 + 1 h: the lifetime rule says renew
        Assert.True(await service.CheckOnceAsync(default));
        Assert.Equal(2, _ca.Orders.Count);
    }

    [Fact]
    public async Task A_failing_ARI_is_recorded_and_the_lifetime_rule_still_renews()
    {
        var service = await IssuedAsync();
        _ca.Info = () => throw new AcmeException("ACME server error: 503", transient: true);

        _clock.Advance(TimeSpan.FromDays(59));
        Assert.False(await service.CheckOnceAsync(default));
        var advice = await StoredAdviceAsync();
        Assert.Contains("503", advice!.Error);
        Assert.Equal(1, advice.Failures);
        Assert.Equal(_clock.UtcNow.AddMinutes(5), advice.NextCheckAt); // server error: exponential back-off from five minutes

        _clock.Advance(TimeSpan.FromMinutes(4));
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(1, _ca.InfoRequests); // not at every check
        _clock.Advance(TimeSpan.FromDays(1)); // day 60: the lifetime rule renews although the ARI keeps failing
        Assert.True(await service.CheckOnceAsync(default));
        Assert.Equal(2, _ca.InfoRequests);
        Assert.Equal(2, _ca.Orders.Count);
    }

    [Fact]
    public async Task An_error_that_is_not_a_server_error_is_asked_again_after_six_hours()
    {
        var service = await IssuedAsync();
        _ca.Info = () => throw new AcmeException("ACME server error: no such certificate");

        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(_clock.UtcNow.AddHours(6), (await StoredAdviceAsync())!.NextCheckAt);
        _clock.Advance(TimeSpan.FromHours(5));
        Assert.False(await service.CheckOnceAsync(default));
        Assert.Equal(1, _ca.InfoRequests);
        _clock.Advance(TimeSpan.FromHours(1));
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
    public async Task A_failed_renewal_order_keeps_the_advice_and_waits_for_the_back_off_although_the_CA_says_now()
    {
        var service = await IssuedAsync();
        _clock.Advance(MinAge);
        _ca.Info = () => new AcmeRenewalInfo(_clock.UtcNow.AddHours(-2), _clock.UtcNow.AddHours(-1), null, null);
        _ca.FailOrders = true;

        Assert.False(await service.CheckOnceAsync(default)); // due, the order fails
        var renewal = Assert.Single(await _config.GetAcmeRenewalsAsync(default));
        Assert.Equal(("failed", 1), (renewal.Status, renewal.Failures));
        Assert.NotNull(renewal.AriJson); // the advice about the certificate in use survives the failed attempt
        Assert.True((await StoredAdviceAsync())!.HasWindow);

        Assert.False(await service.CheckOnceAsync(default)); // back-off: ARI says now, no second order
        Assert.Equal(2, _ca.Orders.Count);

        _ca.FailOrders = false;
        _clock.Advance(TimeSpan.FromMinutes(11));
        Assert.True(await service.CheckOnceAsync(default)); // due still, the window is in the past
        Assert.Equal(3, _ca.Orders.Count);
        Assert.Null(await StoredAdviceAsync()); // a new certificate: advice cleared
    }

    [Fact]
    public async Task Other_names_are_ordered_without_asking_the_CA_and_replace_a_certificate_that_shares_a_name()
    {
        await IssuedAsync();
        var old = Assert.Single(await _config.GetCertificatesAsync(default));

        Assert.True(await Service(domains: [Host, "other.ari.example"]).CheckOnceAsync(default));

        Assert.Equal(0, _ca.InfoRequests);
        Assert.Equal(2, _ca.Orders.Count);
        Assert.Equal(old.ChainPem, _ca.Orders[1].ReplacesCertificatePem); // one name in common: this order renews that certificate
        var second = Assert.Single(await _config.GetCertificatesAsync(default));

        // No name in common: nothing to replace.
        Assert.True(await Service(domains: ["unrelated.ari.example"]).CheckOnceAsync(default));
        Assert.Null(_ca.Orders[2].ReplacesCertificatePem);
        Assert.NotEqual(second.Thumbprint, Assert.Single(await _config.GetCertificatesAsync(default)).Thumbprint);
    }

    [Fact]
    public async Task A_database_error_while_saving_the_advice_does_not_stop_the_renewal()
    {
        var failing = FailingConfig.Wrap(_config);
        var service = await IssuedAsync(config: failing);
        _clock.Advance(MinAge);
        _ca.Info = () => new AcmeRenewalInfo(_clock.UtcNow.AddHours(-2), _clock.UtcNow.AddHours(-1), null, null);
        ((FailingConfig)(object)failing).FailAdviceWrites = true;

        Assert.True(await service.CheckOnceAsync(default)); // the advice in hand decides, the failed save is only logged

        Assert.Equal(2, _ca.Orders.Count);
        Assert.Equal(1, ((FailingConfig)(object)failing).FailedAdviceWrites);
    }

    [Fact]
    public async Task Saving_the_advice_does_not_overwrite_the_back_off_another_replica_wrote_meanwhile()
    {
        var service = await IssuedAsync();
        var t = _clock.UtcNow;
        _ca.Info = () =>
        {
            // While this replica waits for the CA, another one fails an order and sets its back-off in the shared row.
            _config.UpsertAcmeRenewalAsync(new AcmeRenewalRecord("default", "failed", t, t.AddHours(1), 2, "dns timeout", null, null), default).AsTask().GetAwaiter().GetResult();
            return new AcmeRenewalInfo(t.AddDays(20), t.AddDays(30), null, null);
        };

        Assert.False(await service.CheckOnceAsync(default));

        var renewal = Assert.Single(await _config.GetAcmeRenewalsAsync(default));
        Assert.Equal(("failed", 2, "dns timeout"), (renewal.Status, renewal.Failures, renewal.LastError));
        Assert.Equal(t.AddHours(1), renewal.NextAttemptAt);
        Assert.True((await StoredAdviceAsync())!.HasWindow); // and the advice was saved
    }

    [Fact]
    public async Task A_back_off_set_by_another_replica_during_the_question_is_honoured()
    {
        var service = await IssuedAsync();
        _clock.Advance(MinAge);
        var t = _clock.UtcNow;
        _ca.Info = () =>
        {
            _config.UpsertAcmeRenewalAsync(new AcmeRenewalRecord("default", "failed", t, t.AddHours(1), 1, "dns timeout", null, null), default).AsTask().GetAwaiter().GetResult();
            return new AcmeRenewalInfo(t.AddHours(-2), t.AddHours(-1), null, null); // due now
        };

        Assert.False(await service.CheckOnceAsync(default)); // the stale row read before the question said "no back-off"

        Assert.Single(_ca.Orders);
    }

    private sealed class NoDns : IDnsChallengeProvider
    {
        public ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken cancellationToken) => ValueTask.FromResult("h");

        public ValueTask DeleteTxtAsync(string handle, CancellationToken cancellationToken) => ValueTask.CompletedTask;
    }

    /// <summary>Forwards every call to the real config store; saving renewal advice can be made to fail.</summary>
    public class FailingConfig : DispatchProxy
    {
        private IConfigStore _inner = null!;

        public bool FailAdviceWrites { get; set; }

        public int FailedAdviceWrites { get; private set; }

        public static IConfigStore Wrap(IConfigStore inner)
        {
            var proxy = Create<IConfigStore, FailingConfig>();
            ((FailingConfig)(object)proxy)._inner = inner;
            return proxy;
        }

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            if (FailAdviceWrites && targetMethod!.Name == nameof(IConfigStore.SetAcmeRenewalAdviceAsync))
            {
                FailedAdviceWrites++;
                throw new InvalidOperationException("the database is unavailable");
            }

            try
            {
                return targetMethod!.Invoke(_inner, args);
            }
            catch (TargetInvocationException ex)
            {
                throw ex.InnerException ?? ex;
            }
        }
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

/// <summary>
/// <see cref="CertesOrderRunner"/> against a stub CA that serves exactly what a test says: what Certes does with real wire formats (offsets, Retry-After,
/// size, errors) and which refusals of the <c>replaces</c> link lead to a plain order.
/// </summary>
public class CertesRenewalInfoWireTests
{
    private const string Dir = "https://ca.test/dir";

    private static (string Pem, X509Certificate2 Cert) CertificateWithAuthorityKeyIdentifier()
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootReq = new CertificateRequest("CN=Stub Root", rootKey, HashAlgorithmName.SHA256);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootReq.PublicKey, false));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(300));
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafReq = new CertificateRequest("CN=mx.stub.example", leafKey, HashAlgorithmName.SHA256);
        leafReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false));
        byte[] serial = [0x0a, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x01, 0x02];
        using var leaf = leafReq.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(80), serial);
        return (leaf.ExportCertificatePem(), X509CertificateLoader.LoadCertificate(leaf.RawData));
    }

    [Fact]
    public async Task Window_times_with_any_UTC_offset_are_read_as_the_same_instants()
    {
        var (pem, _) = CertificateWithAuthorityKeyIdentifier();
        var ca = new StubCa { Renewal = _ => Json("""{"suggestedWindow":{"start":"2026-10-20T12:00:00+02:00","end":"2026-10-20T08:30:00-03:00"},"explanationURL":"https://ca.test/why"}""", retryAfter: "7200") };

        var info = await new CertesOrderRunner(ca).GetRenewalInfoAsync(Dir, pem, default);

        Assert.NotNull(info);
        Assert.Equal(new DateTimeOffset(2026, 10, 20, 10, 0, 0, TimeSpan.Zero), info.WindowStart);
        Assert.Equal(new DateTimeOffset(2026, 10, 20, 11, 30, 0, TimeSpan.Zero), info.WindowEnd);
        Assert.Equal(TimeSpan.FromHours(2), info.RetryAfter);
        Assert.Equal("https://ca.test/why", info.ExplanationUrl);
        // The certificate id the CA was asked about: base64url(AKI) "." base64url(serial), without padding.
        string id = ca.RenewalRequests.Single();
        Assert.Matches(@"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", id);
        Assert.Equal("CrHC0-T1AQI", id.Split('.')[1]);
    }

    [Theory]
    [InlineData("99999999999999")]
    [InlineData("-5")]
    [InlineData("soon")]
    [InlineData("Wed, 21 Oct 2099 07:28:00 GMT")]
    public async Task Whatever_Retry_After_says_the_next_question_is_between_a_minute_and_a_day_away(string retryAfter)
    {
        var (pem, _) = CertificateWithAuthorityKeyIdentifier();
        var ca = new StubCa { Renewal = _ => Json("""{"suggestedWindow":{"start":"2026-10-20T12:00:00Z","end":"2026-10-21T12:00:00Z"}}""", retryAfter) };
        var now = DateTimeOffset.UtcNow;

        var info = await new CertesOrderRunner(ca).GetRenewalInfoAsync(Dir, pem, default);
        var advice = AcmeRenewalSchedule.FromInfo("T", info!, null, now, () => 0.5);

        Assert.InRange(advice.NextCheckAt - now, AcmeRenewalSchedule.MinCheckInterval, AcmeRenewalSchedule.MaxCheckInterval);
    }

    [Fact]
    public async Task A_directory_without_renewalInfo_answers_null_and_an_error_answer_is_an_AcmeException_with_its_class()
    {
        var (pem, _) = CertificateWithAuthorityKeyIdentifier();
        Assert.Null(await new CertesOrderRunner(new StubCa { RenewalInfoInDirectory = false }).GetRenewalInfoAsync(Dir, pem, default));

        var notFound = new StubCa { Renewal = _ => Problem(HttpStatusCode.NotFound, "urn:ietf:params:acme:error:malformed", "no such certificate") };
        var refusal = await Assert.ThrowsAsync<AcmeException>(() => new CertesOrderRunner(notFound).GetRenewalInfoAsync(Dir, pem, default));
        Assert.False(refusal.Transient);

        var broken = new StubCa { Renewal = _ => Problem(HttpStatusCode.ServiceUnavailable, "urn:ietf:params:acme:error:serverInternal", "down for maintenance") };
        var outage = await Assert.ThrowsAsync<AcmeException>(() => new CertesOrderRunner(broken).GetRenewalInfoAsync(Dir, pem, default));
        Assert.True(outage.Transient);
    }

    [Fact]
    public async Task An_answer_larger_than_a_megabyte_is_refused()
    {
        var (pem, _) = CertificateWithAuthorityKeyIdentifier();
        string huge = "{\"suggestedWindow\":{\"start\":\"2026-10-20T12:00:00Z\",\"end\":\"2026-10-21T12:00:00Z\"},\"padding\":\"" + new string('x', 2 * 1024 * 1024) + "\"}";
        var ca = new StubCa { Renewal = _ => Json(huge) };

        await Assert.ThrowsAnyAsync<Exception>(() => new CertesOrderRunner(ca).GetRenewalInfoAsync(Dir, pem, default));
    }

    [Theory]
    [InlineData("urn:ietf:params:acme:error:alreadyReplaced", 409, true)]
    [InlineData("urn:ietf:params:acme:error:malformed", 400, true)]
    [InlineData("urn:ietf:params:acme:error:conflict", 409, true)]
    [InlineData("urn:ietf:params:acme:error:unauthorized", 403, true)]
    [InlineData("urn:ietf:params:acme:error:rateLimited", 429, false)]
    [InlineData("urn:ietf:params:acme:error:serverInternal", 500, true)]   // a CA that has not indexed the certificate it just issued (Pebble), or a hiccup
    [InlineData("urn:ietf:params:acme:error:serverInternal", 503, true)]
    public async Task Only_a_refused_link_or_a_failing_ca_leads_to_a_plain_order(string type, int status, bool fallsBack)
    {
        var (pem, _) = CertificateWithAuthorityKeyIdentifier();
        var log = new ListLog();
        var ca = new StubCa
        {
            // The order with the link is refused as scripted; the plain one is refused too (what comes after is not under test) so that the count shows what was tried.
            Order = payload => payload.Contains("\"replaces\"", StringComparison.Ordinal)
                ? Problem((HttpStatusCode)status, type, "scripted refusal")
                : Problem(HttpStatusCode.Forbidden, "urn:ietf:params:acme:error:unauthorized", "stop here"),
        };
        var request = new AcmeOrderRequest(Dir, "ops@stub.example", ["mx.stub.example"], KeyFactoryPem(), TimeSpan.Zero, ReplacesCertificatePem: pem);

        await Assert.ThrowsAsync<AcmeException>(() => new CertesOrderRunner(ca, log).IssueAsync(request, new NoDns(), default));

        Assert.Equal(fallsBack ? 2 : 1, ca.OrderPayloads.Count);
        Assert.Equal(fallsBack, ca.OrderPayloads.Count == 2 && !ca.OrderPayloads[1].Contains("\"replaces\"", StringComparison.Ordinal));
        Assert.Equal(fallsBack ? 1 : 0, log.Lines.Count(l => l.Contains("refused the replaces link", StringComparison.Ordinal)));
    }

    private static string KeyFactoryPem() => Certes.KeyFactory.NewKey(Certes.KeyAlgorithm.ES256).ToPem();

    private static HttpResponseMessage Json(string body, string? retryAfter = null)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        if (retryAfter is not null)
        {
            response.Headers.TryAddWithoutValidation("Retry-After", retryAfter);
        }

        return response;
    }

    private static HttpResponseMessage Problem(HttpStatusCode status, string type, string detail) =>
        new(status) { Content = new StringContent(JsonSerializer.Serialize(new { type, detail, status = (int)status }), Encoding.UTF8, "application/problem+json") };

    private sealed class NoDns : IDnsChallengeProvider
    {
        public ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken cancellationToken) => ValueTask.FromResult("h");

        public ValueTask DeleteTxtAsync(string handle, CancellationToken cancellationToken) => ValueTask.CompletedTask;
    }

    private sealed class ListLog : IMtaLog
    {
        public List<string> Lines { get; } = [];

        public bool IsEnabled(MtaLogLevel level) => true;

        public void Write(MtaLogLevel level, string source, string message, Exception? exception = null) => Lines.Add($"{level} {source}: {message}");
    }

    /// <summary>A CA reduced to the requests of an ARI query and of a new order.</summary>
    private sealed class StubCa : HttpMessageHandler
    {
        private int _nonce;

        public bool RenewalInfoInDirectory { get; init; } = true;

        public Func<string, HttpResponseMessage> Renewal { get; init; } = _ => Json("{}");

        public Func<string, HttpResponseMessage> Order { get; init; } = _ => Problem(HttpStatusCode.InternalServerError, "urn:ietf:params:acme:error:serverInternal", "not scripted");

        public List<string> RenewalRequests { get; } = [];

        public List<string> OrderPayloads { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string path = request.RequestUri!.AbsolutePath;
            HttpResponseMessage response;
            if (path == "/dir")
            {
                response = Json(JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["newNonce"] = "https://ca.test/nonce", ["newAccount"] = "https://ca.test/acct", ["newOrder"] = "https://ca.test/order",
                    ["revokeCert"] = "https://ca.test/revoke", ["keyChange"] = "https://ca.test/rollover",
                    ["renewalInfo"] = RenewalInfoInDirectory ? "https://ca.test/renewal" : null,
                }, new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull }));
            }
            else if (path == "/nonce")
            {
                response = new HttpResponseMessage(HttpStatusCode.NoContent);
            }
            else if (path == "/acct")
            {
                response = Json("""{"status":"valid"}""");
                response.Headers.Location = new Uri("https://ca.test/acct/1");
            }
            else if (path.StartsWith("/renewal/", StringComparison.Ordinal))
            {
                string id = path["/renewal/".Length..];
                RenewalRequests.Add(id);
                response = Renewal(id);
            }
            else if (path == "/order")
            {
                string payload = JwsPayload(request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult());
                OrderPayloads.Add(payload);
                response = Order(payload);
            }
            else
            {
                response = new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            response.Headers.TryAddWithoutValidation("Replay-Nonce", "nonce-" + Interlocked.Increment(ref _nonce));
            return Task.FromResult(response);
        }

        private static string JwsPayload(string body)
        {
            using var jws = JsonDocument.Parse(body);
            string s = jws.RootElement.GetProperty("payload").GetString()!.Replace('-', '+').Replace('_', '/');
            return Encoding.UTF8.GetString(Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=')));
        }
    }
}
