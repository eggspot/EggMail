using System.Net;
using Mta.Host.Api;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

public class ApiAuthTests : IAsyncLifetime
{
    private ApiFixture _f = null!;

    public async Task InitializeAsync() => _f = await ApiFixture.StartAsync();

    public async Task DisposeAsync() => await _f.DisposeAsync();

    // Bearer API keys

    [Fact]
    public async Task Missing_credentials_are_401_with_a_problem_and_a_bearer_challenge()
    {
        Reply r = await _f.NewClient().GetAsync("/api/v1/domains");
        r.Problem(HttpStatusCode.Unauthorized, "unauthorized");
        Assert.Equal("Bearer", r.Header("WWW-Authenticate"));
        Assert.Equal(r.Str("request_id"), r.Header("X-Request-Id"));
        Assert.Equal("no-store", r.Header("Cache-Control"));
    }

    [Theory]
    [InlineData("Basic dXNlcjpwYXNz")]
    [InlineData("Bearer")]
    [InlineData("Bearer not-a-key")]
    [InlineData("Bearer egm_AAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task Malformed_or_unknown_keys_are_401(string header)
    {
        ApiClient c = _f.NewClient();
        Reply r = await c.GetAsync("/api/v1/domains", ("Authorization", header));
        r.Problem(HttpStatusCode.Unauthorized, "unauthorized");
    }

    [Fact]
    public async Task A_valid_key_authenticates_and_is_touched_at_most_once_per_interval()
    {
        string token = await _f.AddKeyAsync(ApiFixture.TenantAId, "read", "domains");
        ApiClient c = _f.NewClient().WithBearer(token);
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/api/v1/domains")).Status);

        byte[] digest = Mta.Host.Security.ApiKeys.Digest(token);
        ApiKeyRecord key = (await _f.Storage.Config.FindApiKeyAsync(digest, default))!;
        Assert.Equal(_f.Clock.UtcNow, key.LastUsedAt);

        _f.Clock.Advance(TimeSpan.FromSeconds(10));
        await c.GetAsync("/api/v1/domains");
        Assert.Equal(_f.Clock.UtcNow.AddSeconds(-10), (await _f.Storage.Config.FindApiKeyAsync(digest, default))!.LastUsedAt);

        _f.Clock.Advance(TimeSpan.FromMinutes(2));
        await c.GetAsync("/api/v1/domains");
        Assert.Equal(_f.Clock.UtcNow, (await _f.Storage.Config.FindApiKeyAsync(digest, default))!.LastUsedAt);
    }

    [Fact]
    public async Task A_revoked_key_stops_working()
    {
        string token = await _f.AddKeyAsync(ApiFixture.TenantAId, "read", "domains", "keys");
        ApiClient c = _f.NewClient().WithBearer(token);
        Reply keys = await c.GetAsync("/api/v1/api-keys");
        string id = keys.Json[0].GetProperty("id").GetString()!;
        Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync("/api/v1/api-keys/" + id)).Status);
        (await c.GetAsync("/api/v1/domains")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
    }

    [Fact]
    public async Task A_key_without_the_scope_is_403_forbidden()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId, "read");
        Reply r = (await c.PostAsync("/api/v1/messages", new { from = "a@example.com", to = new[] { "b@x.test" }, subject = "s", text = "t" }));
        r.Problem(HttpStatusCode.Forbidden, "forbidden");
        Assert.Contains("'send'", r.Str("detail"));
        (await c.GetAsync("/api/v1/domains")).Problem(HttpStatusCode.Forbidden, "forbidden");
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/api/v1/messages")).Status);
    }

    [Fact]
    public async Task A_key_never_reaches_admin_endpoints_or_other_tenants()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId);
        (await c.GetAsync("/api/v1/admin/tenants")).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await c.GetAsync("/api/v1/admin/status")).Problem(HttpStatusCode.Forbidden, "forbidden");

        // Naming another tenant does not switch to it.
        c.TenantId = ApiFixture.TenantBId;
        (await c.GetAsync("/api/v1/domains")).Problem(HttpStatusCode.Forbidden, "forbidden");
        c.TenantId = ApiFixture.TenantAId;
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/api/v1/domains")).Status);
    }

    [Fact]
    public async Task A_key_of_a_suspended_tenant_is_refused()
    {
        string token = await _f.AddKeyAsync(ApiFixture.TenantAId, "read");
        await _f.Storage.Config.UpsertTenantAsync(_f.TenantA with { Enabled = false }, default);
        (await _f.NewClient().WithBearer(token).GetAsync("/api/v1/messages")).Problem(HttpStatusCode.Forbidden, "tenant_disabled");
    }

    // Sessions

    [Fact]
    public async Task Login_sets_a_hardened_cookie_and_returns_user_role_and_tenant()
    {
        ApiClient c = _f.NewClient();
        Reply r = await c.SignInAsync("alice", ApiFixture.Password);
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("alice", r.Str("user"));
        Assert.Equal("tenant", r.Str("role"));
        Assert.Equal(ApiFixture.TenantAId.ToString("N"), r.Str("tenantId"));

        string cookie = Assert.Single(r.SetCookies);
        Assert.StartsWith("eggmail_session=", cookie);
        Assert.Contains("httponly", cookie.ToLowerInvariant());
        Assert.Contains("samesite=strict", cookie.ToLowerInvariant());
        Assert.Contains("path=/", cookie.ToLowerInvariant());
        Assert.DoesNotContain("secure", cookie.ToLowerInvariant()); // plain HTTP on a loopback/unknown peer: development

        // The browser holds a random secret; storage holds only its digest.
        string secret = cookie["eggmail_session=".Length..cookie.IndexOf(';')];
        Assert.True(secret.Length >= 43);
        Assert.NotNull(await _f.Storage.Config.FindDashboardSessionAsync(SessionService.HashSecret(secret), default));
        Assert.Null(await _f.Storage.Config.FindDashboardSessionAsync(System.Text.Encoding.UTF8.GetBytes(secret), default));
    }

    [Theory]
    [InlineData("https", "127.0.0.1", true)]
    [InlineData("http", "127.0.0.1", false)]
    [InlineData("http", "203.0.113.7", true)]
    [InlineData("https", "203.0.113.7", true)]
    public async Task The_cookie_is_Secure_except_for_plain_http_on_loopback(string scheme, string ip, bool secure)
    {
        ApiClient c = _f.NewClient();
        c.Scheme = scheme;
        c.RemoteIp = ip;
        Reply r = await c.SignInAsync("alice", ApiFixture.Password);
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal(secure, r.SetCookies.Single().ToLowerInvariant().Contains("secure"));
    }

    [Fact]
    public async Task Cookie_secure_mode_can_be_forced()
    {
        await using ApiFixture always = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.CookieSecure = CookieSecureMode.Always });
        Reply r = await always.NewClient().SignInAsync("alice", ApiFixture.Password);
        Assert.Contains("secure", r.SetCookies.Single().ToLowerInvariant());
    }

    [Fact]
    public async Task Wrong_password_and_unknown_user_look_the_same()
    {
        Reply wrong = await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = "nope" });
        Reply unknown = await _f.NewClient().PostAsync("/api/v1/session", new { user = "mallory", password = "nope" });
        wrong.Problem(HttpStatusCode.Unauthorized, "unauthorized");
        unknown.Problem(HttpStatusCode.Unauthorized, "unauthorized");
        Assert.Equal(wrong.Str("detail"), unknown.Str("detail"));
        Assert.Empty(wrong.SetCookies);
    }

    [Fact]
    public async Task Login_validates_the_body()
    {
        Reply r = await _f.NewClient().PostAsync("/api/v1/session", new { user = "", password = "" });
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["user", "password"], r.ErrorFields);
    }

    [Fact]
    public async Task Failed_logins_are_throttled_per_ip_and_user_and_share_the_smtp_auth_lockout()
    {
        ApiClient c = _f.NewClient();
        c.RemoteIp = "198.51.100.9";
        for (int i = 0; i < 5; i++)
        {
            (await c.PostAsync("/api/v1/session", new { user = "alice", password = "bad" + i })).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        }

        Reply locked = await c.PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password });
        locked.Problem(HttpStatusCode.TooManyRequests, "rate_limited");
        Assert.True(int.Parse(locked.Header("Retry-After")!) > 0);

        // The same keys that SMTP AUTH uses (ip, "user:<name>"): failures counted by the SMTP listener lock the API too.
        _f.Throttle.RecordFailure("198.51.100.77", "user:bob");
        for (int i = 0; i < 4; i++)
        {
            _f.Throttle.RecordFailure("198.51.100.77", "user:bob");
        }

        ApiClient other = _f.NewClient();
        other.RemoteIp = "198.51.100.77";
        (await other.PostAsync("/api/v1/session", new { user = "bob", password = ApiFixture.Password })).Problem(HttpStatusCode.TooManyRequests, "rate_limited");

        // After the window the lockout ends.
        _f.Clock.Advance(TimeSpan.FromMinutes(11));
        Assert.Equal(HttpStatusCode.OK, (await c.PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password })).Status);
    }

    [Fact]
    public async Task A_successful_login_clears_the_failure_count()
    {
        ApiClient c = _f.NewClient();
        for (int i = 0; i < 4; i++)
        {
            await c.PostAsync("/api/v1/session", new { user = "alice", password = "bad" });
        }

        Assert.Equal(HttpStatusCode.OK, (await c.SignInAsync("alice", ApiFixture.Password)).Status);
        for (int i = 0; i < 4; i++)
        {
            await c.PostAsync("/api/v1/session", new { user = "alice", password = "bad" });
        }

        Assert.Equal(HttpStatusCode.OK, (await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password })).Status);
    }

    [Fact]
    public async Task Me_returns_identity_and_the_csrf_token()
    {
        ApiClient c = await _f.SignedInAsync("alice");
        Reply me = await c.GetAsync("/api/v1/me");
        Assert.Equal("alice", me.Str("user"));
        Assert.Equal("tenant", me.Str("role"));
        Assert.Equal(ApiFixture.TenantAId.ToString("N"), me.Str("tenantId"));
        Assert.False(string.IsNullOrEmpty(me.Str("csrfToken")));
        Assert.Equal("Acme Corp", me.Str("tenantName"));

        ApiClient admin = await _f.SignedInAsync("root");
        Reply a = await admin.GetAsync("/api/v1/me");
        Assert.Equal("admin", a.Str("role"));
        Assert.Equal(System.Text.Json.JsonValueKind.Null, a["tenantId"].ValueKind);
    }

    [Fact]
    public async Task Me_for_an_api_key_has_no_csrf_token_and_lists_scopes()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId, "read", "send");
        Reply me = await c.GetAsync("/api/v1/me");
        Assert.Equal("api_key", me.Str("authenticatedBy"));
        Assert.Equal(["read", "send"], me["scopes"].EnumerateArray().Select(s => s.GetString()!).ToArray());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, me["csrfToken"].ValueKind);
    }

    [Fact]
    public async Task Cookie_mutations_need_the_csrf_token()
    {
        ApiClient c = await _f.SignedInAsync("alice");
        string body = """{"name":"example.net"}""";

        c.SendCsrf = false;
        (await c.SendAsync(HttpMethod.Post, "/api/v1/domains", body)).Problem(HttpStatusCode.Forbidden, "forbidden");

        c.SendCsrf = true;
        string good = c.Csrf!;
        c.Csrf = "wrong-token";
        (await c.SendAsync(HttpMethod.Post, "/api/v1/domains", body)).Problem(HttpStatusCode.Forbidden, "forbidden");

        c.Csrf = good;
        Assert.Equal(HttpStatusCode.Created, (await c.SendAsync(HttpMethod.Post, "/api/v1/domains", body)).Status);

        // Reads never need the token, and neither do bearer calls.
        c.SendCsrf = false;
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/api/v1/domains")).Status);
    }

    [Fact]
    public async Task Bearer_mutations_do_not_need_csrf()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId, "domains");
        Assert.Equal(HttpStatusCode.Created, (await c.PostAsync("/api/v1/domains", new { name = "example.net" })).Status);
    }

    [Fact]
    public async Task Logout_ends_the_session_and_is_idempotent()
    {
        ApiClient c = await _f.SignedInAsync("alice");
        string cookie = c.Cookie!;
        Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync("/api/v1/session")).Status);
        (await c.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");

        // Replaying the old cookie fails: the server-side session is gone.
        ApiClient replay = _f.NewClient();
        replay.Cookie = cookie;
        (await replay.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        Assert.Equal(HttpStatusCode.NoContent, (await _f.NewClient().DeleteAsync("/api/v1/session")).Status);
    }

    [Fact]
    public async Task Logout_needs_the_csrf_token_while_the_session_is_live()
    {
        ApiClient c = await _f.SignedInAsync("alice");
        c.SendCsrf = false;
        (await c.DeleteAsync("/api/v1/session")).Problem(HttpStatusCode.Forbidden, "forbidden");
        c.SendCsrf = true;
        Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync("/api/v1/session")).Status);
    }

    [Fact]
    public async Task A_new_login_replaces_the_session_of_the_presented_cookie()
    {
        ApiClient c = await _f.SignedInAsync("alice");
        string first = c.Cookie!;
        Assert.Equal(HttpStatusCode.OK, (await c.SignInAsync("alice", ApiFixture.Password)).Status);
        ApiClient old = _f.NewClient();
        old.Cookie = first;
        (await old.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/api/v1/me")).Status);
    }

    [Fact]
    public async Task Sessions_expire_absolutely_and_when_idle()
    {
        ApiClient absolute = await _f.SignedInAsync("alice");
        // Stays active, so only the absolute lifetime (12 h) ends it.
        for (int i = 0; i < 7; i++)
        {
            _f.Clock.Advance(TimeSpan.FromHours(1.9));
            if (i < 6)
            {
                Assert.Equal(HttpStatusCode.OK, (await absolute.GetAsync("/api/v1/me")).Status);
            }
        }

        (await absolute.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");

        ApiClient idle = await _f.SignedInAsync("bob");
        _f.Clock.Advance(TimeSpan.FromHours(2.5));
        (await idle.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
    }

    [Fact]
    public async Task A_disabled_user_loses_the_session_and_cannot_sign_in()
    {
        ApiClient c = await _f.SignedInAsync("alice");
        var user = (await _f.Storage.Config.FindDashboardUserAsync("alice", default))!;
        await _f.Storage.Config.UpsertDashboardUserAsync(user with { Enabled = false }, default);
        (await c.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        (await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password })).Problem(HttpStatusCode.Unauthorized, "unauthorized");
    }

    [Fact]
    public async Task A_user_of_a_suspended_tenant_cannot_sign_in_or_continue()
    {
        ApiClient c = await _f.SignedInAsync("alice");
        await _f.Storage.Config.UpsertTenantAsync(_f.TenantA with { Enabled = false }, default);
        (await c.GetAsync("/api/v1/domains")).Problem(HttpStatusCode.Forbidden, "tenant_disabled");
        (await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password })).Problem(HttpStatusCode.Unauthorized, "unauthorized");
    }

    // Roles and tenant selection

    [Fact]
    public async Task Tenant_users_cannot_use_admin_endpoints()
    {
        ApiClient c = await _f.SignedInAsync("alice");
        foreach (string path in new[] { "/api/v1/admin/tenants", "/api/v1/admin/status", "/api/v1/admin/settings", "/api/v1/admin/certificates", "/api/v1/admin/storage/switch" })
        {
            (await c.GetAsync(path)).Problem(HttpStatusCode.Forbidden, "forbidden");
        }

        (await c.PostAsync("/api/v1/admin/maintenance/run")).Problem(HttpStatusCode.Forbidden, "forbidden");
    }

    [Fact]
    public async Task Admins_must_choose_a_tenant_for_tenant_endpoints()
    {
        ApiClient admin = await _f.SignedInAsync("root");
        Reply none = await admin.GetAsync("/api/v1/domains");
        none.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["X-Tenant-Id"], none.ErrorFields);

        admin.TenantId = Guid.NewGuid();
        (await admin.GetAsync("/api/v1/domains")).Problem(HttpStatusCode.NotFound, "not_found");

        admin.TenantId = ApiFixture.TenantAId;
        Reply a = await admin.GetAsync("/api/v1/domains");
        Assert.Equal("example.com", a.Json[0].GetProperty("name").GetString());
        admin.TenantId = ApiFixture.TenantBId;
        Reply b = await admin.GetAsync("/api/v1/domains");
        Assert.Equal("globex.test", b.Json[0].GetProperty("name").GetString());

        // Admin endpoints need no tenant.
        admin.TenantId = null;
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/api/v1/admin/tenants")).Status);
    }

    [Fact]
    public async Task A_tenant_user_cannot_name_another_tenant()
    {
        ApiClient c = await _f.SignedInAsync("alice");
        c.TenantId = ApiFixture.TenantBId;
        (await c.GetAsync("/api/v1/domains")).Problem(HttpStatusCode.Forbidden, "forbidden");
        c.TenantId = ApiFixture.TenantAId;
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/api/v1/domains")).Status);
    }

    [Fact]
    public async Task Capabilities_need_no_authentication()
    {
        Assert.Equal(HttpStatusCode.OK, (await _f.NewClient().GetAsync("/api/v1/capabilities")).Status);
    }
}
