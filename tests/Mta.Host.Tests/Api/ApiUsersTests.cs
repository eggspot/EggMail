using System.Net;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Mta.Host.Api;
using Mta.Host.Security;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

/// <summary>Collects log lines so tests can assert what the user management API writes (and does not write) to the log.</summary>
internal sealed class CapturingLoggerProvider : ILoggerProvider
{
    private readonly List<string> _lines = [];

    public IReadOnlyList<string> Lines
    {
        get
        {
            lock (_lines)
            {
                return [.. _lines];
            }
        }
    }

    public ILogger CreateLogger(string categoryName) => new Capture(this);

    public void Dispose()
    {
    }

    private sealed class Capture(CapturingLoggerProvider owner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (owner._lines)
            {
                owner._lines.Add(formatter(state, exception) + (exception is null ? "" : " " + exception));
            }
        }
    }
}

[Collection("api")]
public class ApiUsersTests : IAsyncLifetime
{
    private const string NewPassword = "a brand new password";
    private ApiFixture _f = null!;
    private ApiClient _admin = null!;
    private readonly CapturingLoggerProvider _logs = new();

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync(new ApiFixtureOptions
        {
            ConfigureApi = o => o.PasswordHashIterations = 1000,
            ConfigureServices = s => s.AddSingleton<ILoggerProvider>(_logs),
        });
        _admin = await _f.SignedInAsync("root");
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private static string TenantA => ApiFixture.TenantAId.ToString("N");

    private async Task<(string Id, string Password)> CreateTenantUserAsync(string name, string? tenantId = null)
    {
        Reply r = await _admin.PostAsync("/api/v1/admin/users", new { userName = name, role = "tenant", tenantId = tenantId ?? TenantA });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        return (r.Str("id"), r.Str("password"));
    }

    // Create, list, read

    [Fact]
    public async Task An_admin_creates_a_user_whose_generated_password_is_shown_once_and_works()
    {
        Reply created = await _admin.PostAsync("/api/v1/admin/users", new { userName = "  Carol.Smith ", role = "tenant", tenantId = TenantA });
        Assert.Equal(HttpStatusCode.Created, created.Status);
        string id = created.Str("id");
        Assert.Equal("/api/v1/admin/users/" + id, created.Header("Location"));
        Assert.Equal("carol.smith", created.Str("userName"));
        Assert.Equal("tenant", created.Str("role"));
        Assert.Equal(TenantA, created.Str("tenantId"));
        Assert.True(created["enabled"].GetBoolean());
        string password = created.Str("password");
        Assert.True(password.Length >= DashboardAccounts.MinimumPasswordLength);
        Assert.False(created.Json.TryGetProperty("passwordHash", out _));

        ApiClient carol = _f.NewClient();
        Reply login = await carol.SignInAsync("Carol.Smith", password);
        Assert.Equal(HttpStatusCode.OK, login.Status);
        Assert.Equal("tenant", login.Str("role"));

        Reply one = await _admin.GetAsync("/api/v1/admin/users/" + id);
        Assert.Equal("carol.smith", one.Str("userName"));
        Assert.False(one.Json.TryGetProperty("password", out _));
        Reply list = await _admin.GetAsync("/api/v1/admin/users");
        Assert.Equal(["alice", "bob", "carol.smith", "root"], list.Json.EnumerateArray().Select(u => u.GetProperty("userName").GetString()!));
        Assert.DoesNotContain(password, list.Body);
        Assert.DoesNotContain("pbkdf2", list.Body);
        Assert.DoesNotContain("pbkdf2", one.Body);
        Assert.DoesNotContain("pbkdf2", created.Body);
        Assert.Equal("admin", list.Json.EnumerateArray().Single(u => u.GetProperty("userName").GetString() == "root").GetProperty("role").GetString());
    }

    [Fact]
    public async Task A_supplied_password_is_stored_hashed_and_never_echoed()
    {
        Reply created = await _admin.PostAsync("/api/v1/admin/users", new { userName = "second.admin", role = "admin", password = "chosen by the admin" });
        Assert.Equal(HttpStatusCode.Created, created.Status);
        Assert.False(created.Json.TryGetProperty("password", out _));
        Assert.False(created.Json.TryGetProperty("tenantId", out JsonElement tid) && tid.ValueKind != JsonValueKind.Null);
        Assert.DoesNotContain("chosen by the admin", created.Body);
        var stored = (await _f.Storage.Config.FindDashboardUserAsync("second.admin", default))!;
        Assert.True(PasswordHasher.Verify("chosen by the admin", stored.PasswordHash));
        Assert.Equal(DashboardRole.Admin, stored.Role);
        Assert.Equal(HttpStatusCode.OK, (await _f.NewClient().SignInAsync("second.admin", "chosen by the admin")).Status);
    }

    [Theory]
    [InlineData("""{"userName":"","role":"admin"}""", "userName")]
    [InlineData("""{"userName":"bad\u0007name","role":"admin"}""", "userName")]
    [InlineData("""{"userName":"x","role":"superuser"}""", "role")]
    [InlineData("""{"userName":"x"}""", "role")]
    [InlineData("""{"userName":"x","role":"admin","password":"short"}""", "password")]
    [InlineData("""{"userName":"x","role":"tenant"}""", "tenantId")]
    [InlineData("""{"userName":"x","role":"tenant","tenantId":"not-an-id"}""", "tenantId")]
    [InlineData("""{"userName":"x","role":"tenant","tenantId":"ffffffffffffffffffffffffffffffff"}""", "tenantId")]
    [InlineData("""{"userName":"x","role":"admin","tenantId":"a0000000000070008000000000000001"}""", "tenantId")]
    [InlineData("""{"userName":"alice","role":"admin"}""", "userName")]
    [InlineData("""{"userName":"ALICE ","role":"admin"}""", "userName")]
    [InlineData("""{"userName":"x","role":"admin","isAdmin":true}""", "isAdmin")]
    public async Task Invalid_creations_are_validation_failures_naming_the_field(string json, string field)
    {
        Reply r = await _admin.SendRawAsync(HttpMethod.Post, "/api/v1/admin/users", json, "application/json");
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains(field, r.ErrorFields);
        Assert.Equal(3, (await _f.Storage.Config.GetDashboardUsersAsync(default)).Count);
    }

    [Fact]
    public async Task A_password_over_the_limit_is_refused_before_it_is_hashed()
    {
        string huge = new('x', DashboardAccounts.MaximumPasswordLength + 1);
        Reply r = await _admin.PostAsync("/api/v1/admin/users", new { userName = "big", role = "admin", password = huge });
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["password"], r.ErrorFields);
    }

    [Fact]
    public async Task A_user_cannot_be_given_to_a_suspended_tenant()
    {
        await _admin.PatchAsync("/api/v1/admin/tenants/" + TenantA, new { status = "suspended" });
        Reply r = await _admin.PostAsync("/api/v1/admin/users", new { userName = "late", role = "tenant", tenantId = TenantA });
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["tenantId"], r.ErrorFields);
    }

    // Authorization

    [Fact]
    public async Task Only_an_admin_session_reaches_user_management()
    {
        (string id, _) = await CreateTenantUserAsync("target");
        ApiClient alice = await _f.SignedInAsync("alice");
        ApiClient key = await _f.KeyClientAsync(ApiFixture.TenantAId);
        (string Method, string Path, object? Body)[] calls =
        [
            ("GET", "/api/v1/admin/users", null),
            ("POST", "/api/v1/admin/users", new { userName = "evil", role = "admin" }),
            ("GET", "/api/v1/admin/users/" + id, null),
            ("PATCH", "/api/v1/admin/users/" + id, new { enabled = false }),
            ("DELETE", "/api/v1/admin/users/" + id, null),
            ("POST", "/api/v1/admin/users/" + id + "/reset-password", new { }),
        ];
        foreach (var (method, path, body) in calls)
        {
            (await alice.SendAsync(new HttpMethod(method), path, body)).Problem(HttpStatusCode.Forbidden, "forbidden");
            (await key.SendAsync(new HttpMethod(method), path, body)).Problem(HttpStatusCode.Forbidden, "forbidden");
            (await _f.NewClient().SendAsync(new HttpMethod(method), path, body)).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        }

        Assert.Null(await _f.Storage.Config.FindDashboardUserAsync("evil", default));
        Assert.True((await _f.Storage.Config.GetDashboardUserAsync(Guid.Parse(id), default))!.Enabled);
    }

    [Fact]
    public async Task Cookie_mutations_need_the_csrf_token()
    {
        (string id, _) = await CreateTenantUserAsync("target");
        _admin.SendCsrf = false;
        (await _admin.PostAsync("/api/v1/admin/users", new { userName = "x1", role = "admin" })).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await _admin.PatchAsync("/api/v1/admin/users/" + id, new { enabled = false })).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await _admin.DeleteAsync("/api/v1/admin/users/" + id)).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await _admin.PostAsync("/api/v1/admin/users/" + id + "/reset-password", new { })).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await _admin.PostAsync("/api/v1/me/password", new { currentPassword = ApiFixture.Password, newPassword = NewPassword })).Problem(HttpStatusCode.Forbidden, "forbidden");
        Assert.True((await _f.Storage.Config.GetDashboardUserAsync(Guid.Parse(id), default))!.Enabled);
        Assert.True(PasswordHasher.Verify(ApiFixture.Password, (await _f.Storage.Config.FindDashboardUserAsync("root", default))!.PasswordHash));
    }

    [Fact]
    public async Task Unknown_or_malformed_user_ids_are_404()
    {
        (await _admin.GetAsync("/api/v1/admin/users/ffffffffffffffffffffffffffffffff")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _admin.GetAsync("/api/v1/admin/users/nope")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _admin.PatchAsync("/api/v1/admin/users/nope", new { enabled = false })).Problem(HttpStatusCode.NotFound, "not_found");
        (await _admin.DeleteAsync("/api/v1/admin/users/nope")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _admin.PostAsync("/api/v1/admin/users/nope/reset-password", new { })).Problem(HttpStatusCode.NotFound, "not_found");
    }

    // Disable, enable, role

    [Fact]
    public async Task Disabling_a_user_ends_the_sessions_and_blocks_sign_in_until_enabled_again()
    {
        ApiClient first = await _f.SignedInAsync("alice");
        ApiClient second = await _f.SignedInAsync("alice");
        string id = (await _f.Storage.Config.FindDashboardUserAsync("alice", default))!.Id.ToString("N");
        Assert.Equal(HttpStatusCode.OK, (await first.GetAsync("/api/v1/me")).Status);

        Reply disabled = await _admin.PatchAsync("/api/v1/admin/users/" + id, new { enabled = false });
        Assert.False(disabled["enabled"].GetBoolean());
        (await first.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        (await second.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        (await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password })).Problem(HttpStatusCode.Unauthorized, "unauthorized");

        Reply enabled = await _admin.PatchAsync("/api/v1/admin/users/" + id, new { enabled = true });
        Assert.True(enabled["enabled"].GetBoolean());
        Assert.Equal(HttpStatusCode.OK, (await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password })).Status);
        (await first.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized"); // the old sessions stay gone
    }

    [Fact]
    public async Task Changing_the_role_or_tenant_ends_the_sessions_and_a_promotion_drops_the_tenant()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        string id = (await _f.Storage.Config.FindDashboardUserAsync("alice", default))!.Id.ToString("N");

        Reply moved = await _admin.PatchAsync("/api/v1/admin/users/" + id, new { tenantId = ApiFixture.TenantBId.ToString("N") });
        Assert.Equal(ApiFixture.TenantBId.ToString("N"), moved.Str("tenantId"));
        (await alice.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");

        ApiClient again = await _f.SignedInAsync("alice");
        Reply promoted = await _admin.PatchAsync("/api/v1/admin/users/" + id, new { role = "admin" });
        Assert.Equal("admin", promoted.Str("role"));
        Assert.False(promoted.Json.TryGetProperty("tenantId", out JsonElement t) && t.ValueKind != JsonValueKind.Null);
        (await again.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        ApiClient admin = await _f.SignedInAsync("alice");
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/api/v1/admin/tenants")).Status);

        Reply demoted = await _admin.PatchAsync("/api/v1/admin/users/" + id, new { role = "tenant", tenantId = TenantA });
        Assert.Equal("tenant", demoted.Str("role"));
        Assert.Equal(TenantA, demoted.Str("tenantId"));
        (await admin.GetAsync("/api/v1/admin/tenants")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
    }

    [Theory]
    [InlineData("""{}""", "$")]
    [InlineData("""{"role":"owner"}""", "role")]
    [InlineData("""{"tenantId":"zzz"}""", "tenantId")]
    [InlineData("""{"role":"admin","tenantId":"a0000000000070008000000000000001"}""", "tenantId")]
    [InlineData("""{"password":"x"}""", "password")]
    public async Task Invalid_updates_are_validation_failures(string json, string field)
    {
        (string id, _) = await CreateTenantUserAsync("target");
        Reply r = await _admin.SendRawAsync(HttpMethod.Patch, "/api/v1/admin/users/" + id, json, "application/json");
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains(field, r.ErrorFields);
    }

    [Fact]
    public async Task Making_an_admin_a_tenant_user_needs_a_tenant()
    {
        Reply other = await _admin.PostAsync("/api/v1/admin/users", new { userName = "admin2", role = "admin", password = "an admin password" });
        Reply r = await _admin.PatchAsync("/api/v1/admin/users/" + other.Str("id"), new { role = "tenant" });
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["tenantId"], r.ErrorFields);
    }

    // Reset password

    [Fact]
    public async Task Resetting_a_password_ends_all_sessions_and_the_generated_password_is_shown_once()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        string id = (await _f.Storage.Config.FindDashboardUserAsync("alice", default))!.Id.ToString("N");

        Reply reset = await _admin.PostAsync($"/api/v1/admin/users/{id}/reset-password", new { });
        Assert.Equal(HttpStatusCode.OK, reset.Status);
        string generated = reset.Str("password");
        Assert.True(generated.Length >= DashboardAccounts.MinimumPasswordLength);
        (await alice.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        (await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password })).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        Assert.Equal(HttpStatusCode.OK, (await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = generated })).Status);
        Assert.False((await _admin.GetAsync("/api/v1/admin/users/" + id)).Json.TryGetProperty("password", out _));

        Reply supplied = await _admin.PostAsync($"/api/v1/admin/users/{id}/reset-password", new { password = NewPassword });
        Assert.False(supplied.Json.TryGetProperty("password", out _));
        Assert.DoesNotContain(NewPassword, supplied.Body);
        Assert.Equal(HttpStatusCode.OK, (await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = NewPassword })).Status);
    }

    [Fact]
    public async Task A_reset_is_validated_and_an_admin_cannot_reset_their_own_password_that_way()
    {
        string rootId = (await _f.Storage.Config.FindDashboardUserAsync("root", default))!.Id.ToString("N");
        (await _admin.PostAsync($"/api/v1/admin/users/{rootId}/reset-password", new { })).Problem(HttpStatusCode.Conflict, "conflict");
        Assert.Equal(HttpStatusCode.OK, (await _admin.GetAsync("/api/v1/me")).Status);

        (string id, _) = await CreateTenantUserAsync("target");
        Reply weak = await _admin.PostAsync($"/api/v1/admin/users/{id}/reset-password", new { password = "short" });
        weak.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["password"], weak.ErrorFields);
    }

    // Own password

    [Fact]
    public async Task Changing_your_own_password_ends_the_other_sessions_and_keeps_this_one()
    {
        ApiClient mine = await _f.SignedInAsync("alice");
        ApiClient other = await _f.SignedInAsync("alice");
        Reply r = await mine.PostAsync("/api/v1/me/password", new { currentPassword = ApiFixture.Password, newPassword = NewPassword });
        Assert.Equal(HttpStatusCode.NoContent, r.Status);

        Assert.Equal(HttpStatusCode.OK, (await mine.GetAsync("/api/v1/me")).Status);
        (await other.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        (await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password })).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        Assert.Equal(HttpStatusCode.OK, (await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = NewPassword })).Status);
    }

    [Fact]
    public async Task A_wrong_current_password_is_refused_and_counts_towards_the_lockout()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        for (int i = 0; i < 5; i++)
        {
            Reply wrong = await alice.PostAsync("/api/v1/me/password", new { currentPassword = "not the password", newPassword = NewPassword });
            wrong.Problem(HttpStatusCode.BadRequest, "validation_failed");
            Assert.Equal(["currentPassword"], wrong.ErrorFields);
        }

        // The sixth attempt is locked out, even with the right password (shared with sign-in and SMTP AUTH).
        Reply locked = await alice.PostAsync("/api/v1/me/password", new { currentPassword = ApiFixture.Password, newPassword = NewPassword });
        locked.Problem(HttpStatusCode.TooManyRequests, "rate_limited");
        Assert.NotNull(locked.Header("Retry-After"));
        (await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password })).Problem(HttpStatusCode.TooManyRequests, "rate_limited");
        Assert.True(PasswordHasher.Verify(ApiFixture.Password, (await _f.Storage.Config.FindDashboardUserAsync("alice", default))!.PasswordHash));

        _f.Clock.Advance(TimeSpan.FromMinutes(11));
        Assert.Equal(HttpStatusCode.NoContent, (await alice.PostAsync("/api/v1/me/password", new { currentPassword = ApiFixture.Password, newPassword = NewPassword })).Status);
    }

    [Fact]
    public async Task The_new_password_is_validated_and_must_differ()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        Reply weak = await alice.PostAsync("/api/v1/me/password", new { currentPassword = ApiFixture.Password, newPassword = "short" });
        weak.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["newPassword"], weak.ErrorFields);
        (await alice.PostAsync("/api/v1/me/password", new { currentPassword = ApiFixture.Password, newPassword = ApiFixture.Password })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await alice.PostAsync("/api/v1/me/password", new { newPassword = NewPassword })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.True(PasswordHasher.Verify(ApiFixture.Password, (await _f.Storage.Config.FindDashboardUserAsync("alice", default))!.PasswordHash));
    }

    [Fact]
    public async Task An_api_key_or_no_session_cannot_change_a_password()
    {
        ApiClient key = await _f.KeyClientAsync(ApiFixture.TenantAId);
        (await key.PostAsync("/api/v1/me/password", new { currentPassword = ApiFixture.Password, newPassword = NewPassword })).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await _f.NewClient().PostAsync("/api/v1/me/password", new { currentPassword = ApiFixture.Password, newPassword = NewPassword })).Problem(HttpStatusCode.Unauthorized, "unauthorized");
    }

    // Delete

    [Fact]
    public async Task Deleting_a_user_ends_their_sessions_and_frees_the_name()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        string id = (await _f.Storage.Config.FindDashboardUserAsync("alice", default))!.Id.ToString("N");
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync("/api/v1/admin/users/" + id)).Status);
        (await alice.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        (await _admin.GetAsync("/api/v1/admin/users/" + id)).Problem(HttpStatusCode.NotFound, "not_found");
        (await _admin.DeleteAsync("/api/v1/admin/users/" + id)).Problem(HttpStatusCode.NotFound, "not_found");
        Assert.Equal(HttpStatusCode.Created, (await _admin.PostAsync("/api/v1/admin/users", new { userName = "alice", role = "tenant", tenantId = TenantA })).Status);
    }

    // Last administrator

    [Fact]
    public async Task The_only_enabled_admin_cannot_be_disabled_demoted_or_deleted()
    {
        string rootId = (await _f.Storage.Config.FindDashboardUserAsync("root", default))!.Id.ToString("N");
        string path = "/api/v1/admin/users/" + rootId;
        Reply a = (await _admin.PatchAsync(path, new { enabled = false })).Problem(HttpStatusCode.Conflict, "conflict");
        Assert.Equal("last_admin", a.Str("reason"));
        (await _admin.PatchAsync(path, new { role = "tenant", tenantId = TenantA })).Problem(HttpStatusCode.Conflict, "conflict");
        (await _admin.DeleteAsync(path)).Problem(HttpStatusCode.Conflict, "conflict");
        var root = (await _f.Storage.Config.GetDashboardUserAsync(Guid.Parse(rootId), default))!;
        Assert.True(root.Enabled);
        Assert.Equal(DashboardRole.Admin, root.Role);
        Assert.Equal(HttpStatusCode.OK, (await _admin.GetAsync("/api/v1/me")).Status); // the refused change did not end the session

        // A no-op on the admin is fine, and so is changing nothing that matters.
        Assert.Equal(HttpStatusCode.OK, (await _admin.PatchAsync(path, new { enabled = true })).Status);
    }

    [Fact]
    public async Task With_another_enabled_admin_an_admin_may_be_disabled_even_themselves()
    {
        Reply second = await _admin.PostAsync("/api/v1/admin/users", new { userName = "admin2", role = "admin", password = "an admin password" });
        string rootId = (await _f.Storage.Config.FindDashboardUserAsync("root", default))!.Id.ToString("N");
        Assert.Equal(HttpStatusCode.OK, (await _admin.PatchAsync("/api/v1/admin/users/" + rootId, new { enabled = false })).Status);
        (await _admin.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");

        // admin2 is the last one now.
        ApiClient admin2 = await SignInAsAsync("admin2", "an admin password");
        (await admin2.PatchAsync("/api/v1/admin/users/" + second.Str("id"), new { enabled = false })).Problem(HttpStatusCode.Conflict, "conflict");
        (await admin2.DeleteAsync("/api/v1/admin/users/" + second.Str("id"))).Problem(HttpStatusCode.Conflict, "conflict");
        // A disabled admin does not count: enabling root again is what makes admin2 removable.
        Assert.Equal(HttpStatusCode.OK, (await admin2.PatchAsync("/api/v1/admin/users/" + rootId, new { enabled = true })).Status);
        Assert.Equal(HttpStatusCode.NoContent, (await admin2.DeleteAsync("/api/v1/admin/users/" + second.Str("id"))).Status);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Two_admins_cannot_remove_each_other_concurrently(bool sqlite)
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { Sqlite = sqlite, ConfigureApi = o => o.PasswordHashIterations = 1000 });
        ApiClient a = await f.SignedInAsync("root");
        await f.AddUserAsync("root2", DashboardRole.Admin, null);
        ApiClient b = await f.SignedInAsync("root2");
        string aId = (await f.Storage.Config.FindDashboardUserAsync("root", default))!.Id.ToString("N");
        string bId = (await f.Storage.Config.FindDashboardUserAsync("root2", default))!.Id.ToString("N");

        for (int round = 0; round < 5; round++)
        {
            // Each admin tries to disable the other, at the same moment.
            Task<Reply> first = Task.Run(() => a.PatchAsync("/api/v1/admin/users/" + bId, new { enabled = false }));
            Task<Reply> second = Task.Run(() => b.PatchAsync("/api/v1/admin/users/" + aId, new { enabled = false }));
            Reply[] replies = await Task.WhenAll(first, second);
            Assert.Equal(1, replies.Count(r => r.Status == HttpStatusCode.OK));
            Assert.Equal(1, replies.Count(r => r.Status is HttpStatusCode.Conflict or HttpStatusCode.Unauthorized));
            var users = await f.Storage.Config.GetDashboardUsersAsync(default);
            Assert.Equal(1, users.Count(u => u.Role == DashboardRole.Admin && u.Enabled));

            // Re-enable the loser through the survivor for the next round.
            var survivor = users.Single(u => u.Enabled && u.Role == DashboardRole.Admin);
            var loser = users.Single(u => u.Role == DashboardRole.Admin && u.Id != survivor.Id);
            await f.Storage.Config.UpsertDashboardUserAsync(loser with { Enabled = true }, default);
            a = await f.SignedInAsync("root");
            b = await f.SignedInAsync("root2");
        }

        // Deleting the other while being deleted by the other is guarded the same way.
        Task<Reply> d1 = Task.Run(() => a.DeleteAsync("/api/v1/admin/users/" + bId));
        Task<Reply> d2 = Task.Run(() => b.DeleteAsync("/api/v1/admin/users/" + aId));
        Reply[] deleted = await Task.WhenAll(d1, d2);
        Assert.Equal(1, deleted.Count(r => r.Status == HttpStatusCode.NoContent));
        Assert.Equal(1, (await f.Storage.Config.GetDashboardUsersAsync(default)).Count(u => u.Role == DashboardRole.Admin && u.Enabled));
    }

    [Fact]
    public async Task A_concurrent_password_change_does_not_undo_a_disable()
    {
        string id = (await _f.Storage.Config.FindDashboardUserAsync("alice", default))!.Id.ToString("N");
        string current = ApiFixture.Password;
        for (int i = 0; i < 5; i++)
        {
            await _admin.PatchAsync("/api/v1/admin/users/" + id, new { enabled = true });
            ApiClient alice = await SignInAsAsync("alice", current);
            string next = NewPassword + i;
            Task<Reply> disable = Task.Run(() => _admin.PatchAsync("/api/v1/admin/users/" + id, new { enabled = false }));
            Task<Reply> change = Task.Run(() => alice.PostAsync("/api/v1/me/password", new { currentPassword = current, newPassword = next }));
            await Task.WhenAll(disable, change);

            // Whatever the order, the password change was made on the fresh record: the account stays disabled.
            var stored = (await _f.Storage.Config.GetDashboardUserAsync(Guid.Parse(id), default))!;
            Assert.False(stored.Enabled);
            if (PasswordHasher.Verify(next, stored.PasswordHash))
            {
                current = next;
            }
        }
    }

    // Logs

    [Fact]
    public async Task Changes_are_logged_with_actor_and_target_but_never_with_passwords_or_hashes()
    {
        Reply created = await _admin.PostAsync("/api/v1/admin/users", new { userName = "logged", role = "tenant", tenantId = TenantA });
        string generated = created.Str("password");
        string id = created.Str("id");
        Reply reset = await _admin.PostAsync($"/api/v1/admin/users/{id}/reset-password", new { password = NewPassword });
        string stored = (await _f.Storage.Config.FindDashboardUserAsync("logged", default))!.PasswordHash;
        await _admin.PatchAsync("/api/v1/admin/users/" + id, new { enabled = false });
        await _admin.DeleteAsync("/api/v1/admin/users/" + id);
        ApiClient alice = await _f.SignedInAsync("alice");
        await alice.PostAsync("/api/v1/me/password", new { currentPassword = ApiFixture.Password, newPassword = NewPassword + "x" });

        string all = string.Join('\n', _logs.Lines);
        Assert.Contains("created", all);
        Assert.Contains("password reset", all);
        Assert.Contains("password changed", all);
        Assert.Contains("actor root", all);
        Assert.Contains("logged", all);
        Assert.DoesNotContain(generated, all);
        Assert.DoesNotContain(NewPassword, all);
        Assert.DoesNotContain(ApiFixture.Password, all);
        Assert.DoesNotContain("pbkdf2", all);
        Assert.DoesNotContain(stored, all);
        Assert.Equal(HttpStatusCode.OK, reset.Status);
    }

    private async Task<ApiClient> SignInAsAsync(string user, string password)
    {
        ApiClient client = _f.NewClient();
        Assert.Equal(HttpStatusCode.OK, (await client.SignInAsync(user, password)).Status);
        return client;
    }
}
