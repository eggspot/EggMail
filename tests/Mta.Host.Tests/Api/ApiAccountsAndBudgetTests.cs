using System.Net;
using Microsoft.AspNetCore.Http;
using Mta.Host.Api;
using Mta.Host.Security;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

[Collection("api")]
public class ApiAccountsTests : IAsyncLifetime
{
    private ApiFixture _f = null!;

    public async Task InitializeAsync() => _f = await ApiFixture.StartAsync();

    public async Task DisposeAsync() => await _f.DisposeAsync();

    [Fact]
    public async Task Accounts_are_created_with_hashed_passwords_and_validated_roles()
    {
        DashboardUser user = await DashboardAccounts.CreateAsync(_f.Storage.Config, _f.Clock, "  New.User ", "a long enough password", DashboardRole.Tenant, ApiFixture.TenantAId, default, 1000);
        Assert.Equal("new.user", (await _f.Storage.Config.FindDashboardUserAsync("NEW.user", default))!.UserName);
        Assert.True(PasswordHasher.Verify("a long enough password", user.PasswordHash));
        Assert.DoesNotContain("a long enough password", user.PasswordHash);

        await Assert.ThrowsAsync<StorageConflictException>(async () => await DashboardAccounts.CreateAsync(_f.Storage.Config, _f.Clock, "new.user", "another long password", DashboardRole.Admin, null, default, 1000));
        await Assert.ThrowsAsync<ArgumentException>(async () => await DashboardAccounts.CreateAsync(_f.Storage.Config, _f.Clock, "x", "short", DashboardRole.Admin, null, default));
        await Assert.ThrowsAsync<ArgumentException>(async () => await DashboardAccounts.CreateAsync(_f.Storage.Config, _f.Clock, "x", "long enough password", DashboardRole.Tenant, null, default));
        await Assert.ThrowsAsync<ArgumentException>(async () => await DashboardAccounts.CreateAsync(_f.Storage.Config, _f.Clock, "x", "long enough password", DashboardRole.Admin, ApiFixture.TenantAId, default));
        await Assert.ThrowsAsync<ArgumentException>(async () => await DashboardAccounts.CreateAsync(_f.Storage.Config, _f.Clock, "  ", "long enough password", DashboardRole.Admin, null, default));
    }

    [Fact]
    public async Task The_first_admin_is_created_only_when_there_is_none()
    {
        Assert.False(await DashboardAccounts.EnsureAdminAsync(_f.Storage.Config, _f.Clock, "admin", "a long enough password", default, 1000)); // "root" exists
        await using ApiFixture empty = await ApiFixture.StartAsync();
        foreach (DashboardUser u in await empty.Storage.Config.GetDashboardUsersAsync(default))
        {
            await empty.Storage.Config.DeleteDashboardUserAsync(u.Id, default);
        }

        Assert.True(await DashboardAccounts.EnsureAdminAsync(empty.Storage.Config, empty.Clock, "admin", "a long enough password", default, 1000));
        Assert.False(await DashboardAccounts.EnsureAdminAsync(empty.Storage.Config, empty.Clock, "admin2", "a long enough password", default, 1000));
        Reply login = await empty.NewClient().PostAsync("/api/v1/session", new { user = "admin", password = "a long enough password" });
        Assert.Equal(HttpStatusCode.OK, login.Status);
        Assert.Equal("admin", login.Str("role"));
    }

    [Fact]
    public async Task Changing_a_password_signs_the_user_out_everywhere()
    {
        ApiClient first = await _f.SignedInAsync("alice");
        ApiClient second = await _f.SignedInAsync("alice");
        var alice = (await _f.Storage.Config.FindDashboardUserAsync("alice", default))!;
        await DashboardAccounts.SetPasswordAsync(_f.Storage.Config, alice.Id, "a brand new password", default, 1000);

        (await first.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        (await second.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        (await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password })).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        Assert.Equal(HttpStatusCode.OK, (await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = "a brand new password" })).Status);
        await Assert.ThrowsAsync<KeyNotFoundException>(async () => await DashboardAccounts.SetPasswordAsync(_f.Storage.Config, Guid.NewGuid(), "a brand new password", default));
    }

    [Fact]
    public async Task Old_password_hashes_are_upgraded_at_the_next_sign_in()
    {
        var user = (await _f.Storage.Config.FindDashboardUserAsync("bob", default))!;
        Assert.True(PasswordHasher.NeedsRehash(user.PasswordHash)); // the fixture uses 1,000 iterations
        Assert.Equal(HttpStatusCode.OK, (await _f.NewClient().PostAsync("/api/v1/session", new { user = "bob", password = ApiFixture.Password })).Status);
        var after = (await _f.Storage.Config.FindDashboardUserAsync("bob", default))!;
        Assert.False(PasswordHasher.NeedsRehash(after.PasswordHash));
        Assert.True(PasswordHasher.Verify(ApiFixture.Password, after.PasswordHash));
    }
}

[Collection("api")]
public class ApiHostingTests : IAsyncLifetime
{
    private ApiFixture _f = null!;
    private string _dir = null!;

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync();
        _dir = Path.Combine(Path.GetTempPath(), "eggmail-boot-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        foreach (DashboardUser u in await _f.Storage.Config.GetDashboardUsersAsync(default))
        {
            await _f.Storage.Config.DeleteDashboardUserAsync(u.Id, default);
        }
    }

    public async Task DisposeAsync()
    {
        await _f.DisposeAsync();
        Directory.Delete(_dir, recursive: true); // created by this test
    }

    private Mta.Host.Configuration.MtaConfig Config(string? passwordFile, string user = "admin") =>
        new() { Dashboard = new Mta.Host.Configuration.DashboardSection { BootstrapAdminPasswordFile = passwordFile, BootstrapAdminUser = user } };

    [Fact]
    public async Task The_bootstrap_admin_is_created_from_the_password_file_once()
    {
        string file = Path.Combine(_dir, "pw");
        await File.WriteAllTextAsync(file, "first-run-password\n");
        await Mta.Host.Hosting.ApiHosting.EnsureBootstrapAdminAsync(Config(file, "boss"), _f.Storage, _f.Clock, Mta.Core.NullMtaLog.Instance, default);

        Reply login = await _f.NewClient().PostAsync("/api/v1/session", new { user = "boss", password = "first-run-password" });
        Assert.Equal(HttpStatusCode.OK, login.Status);
        Assert.Equal("admin", login.Str("role"));

        await File.WriteAllTextAsync(file, "a-different-password\n");
        await Mta.Host.Hosting.ApiHosting.EnsureBootstrapAdminAsync(Config(file, "second"), _f.Storage, _f.Clock, Mta.Core.NullMtaLog.Instance, default);
        Assert.Single(await _f.Storage.Config.GetDashboardUsersAsync(default)); // an admin exists: nothing more is created
    }

    [Fact]
    public async Task A_missing_or_weak_password_file_is_a_problem_to_report_and_creates_nobody()
    {
        var missing = await Mta.Host.Hosting.ApiHosting.EnsureBootstrapAdminAsync(Config(Path.Combine(_dir, "missing")), _f.Storage, _f.Clock, Mta.Core.NullMtaLog.Instance, default);
        string weak = Path.Combine(_dir, "weak");
        await File.WriteAllTextAsync(weak, "short");
        var tooShort = await Mta.Host.Hosting.ApiHosting.EnsureBootstrapAdminAsync(Config(weak), _f.Storage, _f.Clock, Mta.Core.NullMtaLog.Instance, default);

        Assert.Equal(Mta.Host.Hosting.BootstrapAdminOutcome.Problem, missing.Outcome);
        Assert.Contains("cannot be read", missing.Problem, StringComparison.Ordinal);
        Assert.Equal(Mta.Host.Hosting.BootstrapAdminOutcome.Problem, tooShort.Outcome);
        Assert.Contains("at least 10", tooShort.Problem, StringComparison.Ordinal);
        Assert.Empty(await _f.Storage.Config.GetDashboardUsersAsync(default));
    }

    [Fact]
    public async Task Without_any_configured_password_one_is_generated_returned_once_and_works()
    {
        var first = await Mta.Host.Hosting.ApiHosting.EnsureBootstrapAdminAsync(Config(null), _f.Storage, _f.Clock, Mta.Core.NullMtaLog.Instance, default);
        var again = await Mta.Host.Hosting.ApiHosting.EnsureBootstrapAdminAsync(Config(null), _f.Storage, _f.Clock, Mta.Core.NullMtaLog.Instance, default);

        Assert.Equal(Mta.Host.Hosting.BootstrapAdminOutcome.CreatedWithGeneratedPassword, first.Outcome);
        Assert.Equal(24, first.GeneratedPassword!.Length);
        Assert.Equal(Mta.Host.Hosting.BootstrapAdminOutcome.AlreadyExists, again.Outcome);   // the next start creates and prints nothing
        Assert.Null(again.GeneratedPassword);
        Reply login = await _f.NewClient().PostAsync("/api/v1/session", new { user = "admin", password = first.GeneratedPassword });
        Assert.Equal(HttpStatusCode.OK, login.Status);
    }

    [Fact]
    public async Task The_dispatchers_view_of_the_webhook_allowlist_is_read_from_settings_and_cached()
    {
        var settings = _f.Get<SettingsService>();
        Assert.Empty(settings.GetWebhookAllowlistSnapshot(ApiFixture.TenantAId));

        await _f.Storage.Config.SetSettingAsync(new SettingRecord(SettingsService.WebhookAllowlistKey, ApiFixture.TenantAId, "\"10.0.0.0/8\"", _f.Clock.UtcNow), default);
        _f.Clock.Advance(TimeSpan.FromMinutes(1)); // past the cache time
        settings.GetWebhookAllowlistSnapshot(ApiFixture.TenantAId); // returns the old view and refreshes in the background
        for (int i = 0; i < 1500 && settings.GetWebhookAllowlistSnapshot(ApiFixture.TenantAId).Count == 0; i++)
        {
            await Task.Delay(20);
        }

        var networks = settings.GetWebhookAllowlistSnapshot(ApiFixture.TenantAId);
        Assert.Single(networks);
        Assert.True(networks[0].Contains(System.Net.IPAddress.Parse("10.2.3.4")));
        Assert.Empty(settings.GetWebhookAllowlistSnapshot(ApiFixture.TenantBId));
    }
}

[Collection("api")]
public class SendBudgetTests
{
    private static DefaultHttpContext Request(long length) => new() { Request = { ContentLength = length } };

    [Fact]
    public void Requests_beyond_the_in_flight_budget_are_told_to_retry_and_release_on_dispose()
    {
        var budget = new SendBudget(new ApiOptions { MaxSendBodyBytes = 600, MaxInFlightSendBytes = 1000 });
        using SendBudget.Lease first = budget.Reserve(Request(600));
        Assert.Equal(600, budget.InFlightBytes);

        ApiException busy = Assert.Throws<ApiException>(() => budget.Reserve(Request(600)));
        Assert.Equal(429, busy.Status);
        Assert.Equal(ApiCodes.RateLimited, busy.Code);
        Assert.Equal("1", busy.Headers!["Retry-After"]);
        Assert.Equal(600, budget.InFlightBytes); // the refused request holds nothing

        using (budget.Reserve(Request(400)))
        {
            Assert.Equal(1000, budget.InFlightBytes);
        }

        Assert.Equal(600, budget.InFlightBytes);
    }

    [Fact]
    public void An_undeclared_length_reserves_the_maximum_and_a_single_large_request_still_passes_when_idle()
    {
        var budget = new SendBudget(new ApiOptions { MaxSendBodyBytes = 5000, MaxInFlightSendBytes = 1000 });
        using (budget.Reserve(new DefaultHttpContext()))
        {
            Assert.Equal(5000, budget.InFlightBytes);
        }

        Assert.Equal(0, budget.InFlightBytes);
    }
}
