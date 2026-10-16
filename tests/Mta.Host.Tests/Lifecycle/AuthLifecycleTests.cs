using System.Net;
using Mta.Host.Tests.Api;
using Mta.Storage;
using Mta.TestSupport;

namespace Mta.Host.Tests.Lifecycle;

/// <summary>
/// Dashboard sessions, API keys and the failed-login throttle over virtual months, through the real HTTP API (TestHost) over the SQLite backend with a controllable clock: the
/// absolute 12 hour session lifetime and the 2 hour idle timeout end a session at the exact instant; a key never expires on its own (there is no expiry on API keys: they end by
/// revocation or with the tenant) and stops working at the very next request after it is revoked; the lockout of the failed-login throttle ends when its window has passed, again and again.
/// </summary>
[Collection("api")]
public class AuthLifecycleTests : IAsyncLifetime
{
    private ApiFixture _f = null!;

    public async Task InitializeAsync() => _f = await ApiFixture.StartAsync(new ApiFixtureOptions { Sqlite = true });

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private async Task<HttpStatusCode> MeAsync(ApiClient client) => (await client.GetAsync("/api/v1/me")).Status;

    [Fact]
    public async Task A_session_ends_at_its_absolute_lifetime_however_active_it_is()
    {
        TimeSpan lifetime = _f.Options.SessionLifetime;   // 12 hours
        ApiClient client = await _f.SignedInAsync("alice");
        string csrf = client.Csrf!;
        DateTimeOffset signedIn = _f.Clock.UtcNow;

        // Active every hour: the idle timeout (2 hours) never fires, the absolute lifetime does.
        while (_f.Clock.UtcNow + TimeSpan.FromHours(1) < signedIn + lifetime)
        {
            _f.Clock.Advance(TimeSpan.FromHours(1));
            Assert.Equal(HttpStatusCode.OK, await MeAsync(client));
        }

        Assert.Equal(csrf, (await client.GetAsync("/api/v1/me")).Str("csrfToken"));   // the CSRF token is the session's, it does not change or age on its own

        _f.Clock.Advance(signedIn + lifetime - TimeSpan.FromSeconds(1) - _f.Clock.UtcNow);
        Assert.Equal(HttpStatusCode.OK, await MeAsync(client));   // one second before the end
        _f.Clock.Advance(TimeSpan.FromSeconds(1));
        Reply ended = await client.GetAsync("/api/v1/me");
        ended.Problem(HttpStatusCode.Unauthorized, "unauthorized");   // exactly at the end

        // A session that ended is gone from the store, and signing in again gives a new one with a new CSRF token.
        ApiClient again = await _f.SignedInAsync("alice");
        Assert.NotEqual(csrf, again.Csrf);
        Assert.Equal(HttpStatusCode.OK, await MeAsync(again));
    }

    [Fact]
    public async Task A_session_ends_after_the_idle_timeout_and_every_request_before_it_starts_the_timeout_again()
    {
        TimeSpan idle = _f.Options.SessionIdleTimeout;   // 2 hours
        ApiClient client = await _f.SignedInAsync("alice");

        // Exactly the idle timeout without a request is still inside it ("more than" the timeout ends the session), and that request starts the timeout again.
        for (int i = 0; i < 4; i++)
        {
            _f.Clock.Advance(idle);
            Assert.Equal(HttpStatusCode.OK, await MeAsync(client));
        }

        _f.Clock.Advance(idle + TimeSpan.FromSeconds(1));
        (await client.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        Assert.Equal(HttpStatusCode.Unauthorized, await MeAsync(client));   // and it stays ended
    }

    [Fact]
    public async Task A_sign_in_purges_the_sessions_that_ended_so_the_table_does_not_keep_them()
    {
        // Sign-ins are the only moment the store is cleaned (at most every 10 minutes); the row counts come from deleting "everything that expires by then".
        IConfigStore configuration = _f.Storage.Config;
        for (int i = 0; i < 3; i++)
        {
            await _f.SignedInAsync("alice");   // three browsers that are never used again
        }

        _f.Clock.Advance(_f.Options.SessionLifetime + TimeSpan.FromMinutes(1));
        await _f.SignedInAsync("bob");   // purges the three of alice (their lifetime is over) and stores its own
        Assert.Equal(1, await configuration.DeleteExpiredDashboardSessionsAsync(_f.Clock.UtcNow + TimeSpan.FromDays(2), default));
    }

    [Fact]
    public async Task An_api_key_does_not_expire_but_is_refused_at_the_next_request_after_it_is_revoked()
    {
        Guid tenant = ApiFixture.TenantAId;
        ApiClient admin = await _f.SignedInAsync("alice");
        string token = await _f.AddKeyAsync(tenant, "send", "read", "domains");
        ApiClient key = _f.NewClient().WithBearer(token);
        ApiKeyRecord created = (await _f.Storage.Config.GetApiKeysAsync(tenant, default)).Single(k => k.Prefix == token[..12]);
        Assert.Null(created.LastUsedAt);

        // Used now and a year later: nothing in the key ages (no expiry exists), and "last used" follows the use at the touch interval.
        Assert.Equal(HttpStatusCode.OK, await MeAsync(key));
        DateTimeOffset firstUse = _f.Clock.UtcNow;
        for (int month = 1; month <= 14; month++)
        {
            _f.Clock.Advance(TimeSpan.FromDays(30));
            Assert.Equal(HttpStatusCode.OK, await MeAsync(key));
            ApiKeyRecord used = (await _f.Storage.Config.GetApiKeysAsync(tenant, default)).Single(k => k.Id == created.Id);
            Assert.Equal(_f.Clock.UtcNow, used.LastUsedAt);
            Assert.Null(used.RevokedAt);
        }

        // Many requests inside the touch interval write "last used" once.
        DateTimeOffset lastTouch = (await _f.Storage.Config.GetApiKeysAsync(tenant, default)).Single(k => k.Id == created.Id).LastUsedAt!.Value;
        for (int i = 0; i < 50; i++)
        {
            _f.Clock.Advance(TimeSpan.FromSeconds(1));
            Assert.Equal(HttpStatusCode.OK, await MeAsync(key));
        }

        Assert.Equal(lastTouch, (await _f.Storage.Config.GetApiKeysAsync(tenant, default)).Single(k => k.Id == created.Id).LastUsedAt);
        Assert.True(_f.Clock.UtcNow - firstUse > TimeSpan.FromDays(400));

        // Revoked: the very next request is refused, with no cache keeping the key alive.
        Assert.True(await _f.Storage.Config.RevokeApiKeyAsync(tenant, created.Id, _f.Clock.UtcNow, default));
        Assert.Equal(HttpStatusCode.Unauthorized, await MeAsync(key));
        _f.Clock.Advance(TimeSpan.FromDays(365));
        Assert.Equal(HttpStatusCode.Unauthorized, await MeAsync(key));   // and a revoked key does not come back with time
        _ = admin;
    }

    [Fact]
    public async Task A_suspended_tenant_loses_its_keys_and_sessions_and_gets_them_back_when_it_is_enabled_again()
    {
        Guid tenant = ApiFixture.TenantAId;
        ApiClient key = await _f.KeyClientAsync(tenant);
        ApiClient session = await _f.SignedInAsync("alice");
        Assert.Equal(HttpStatusCode.OK, await MeAsync(key));
        Assert.Equal(HttpStatusCode.OK, await MeAsync(session));

        await _f.Storage.Config.UpsertTenantAsync(_f.TenantA with { Enabled = false }, default);
        _f.Clock.Advance(TimeSpan.FromHours(1));
        Assert.NotEqual(HttpStatusCode.OK, await MeAsync(key));
        Assert.NotEqual(HttpStatusCode.OK, await MeAsync(session));

        await _f.Storage.Config.UpsertTenantAsync(_f.TenantA with { Enabled = true }, default);
        _f.Clock.Advance(TimeSpan.FromMinutes(30));
        Assert.Equal(HttpStatusCode.OK, await MeAsync(key));
        Assert.Equal(HttpStatusCode.OK, await MeAsync(session));   // inside its 12 hours and 2 hours of idleness
    }

    [Fact]
    public async Task The_failed_login_lockout_ends_when_its_window_has_passed_again_and_again()
    {
        TimeSpan window = TimeSpan.FromMinutes(10);   // the fixture's throttle: 5 failures in 10 minutes
        int cycles = Accelerated.Scaled(2);   // a sign-in check costs a password hash; the long form of this is the throttle test in Mta.Integration.Tests
        for (int cycle = 0; cycle < cycles; cycle++)
        {
            ApiClient attacker = _f.NewClient();
            attacker.RemoteIp = "198.51.100." + (cycle % 200 + 1);
            DateTimeOffset firstFailure = _f.Clock.UtcNow;
            for (int i = 0; i < 5; i++)
            {
                Assert.Equal(HttpStatusCode.Unauthorized, (await attacker.PostAsync("/api/v1/session", new { user = "alice", password = "wrong password!" })).Status);
                _f.Clock.Advance(TimeSpan.FromSeconds(10));
            }

            // Locked, even with the right password, until the oldest of the five failures is older than the window.
            Reply locked = await attacker.PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password });
            locked.Problem(HttpStatusCode.TooManyRequests, "rate_limited");
            Assert.NotNull(locked.Header("Retry-After"));

            _f.Clock.Advance(firstFailure + window - _f.Clock.UtcNow);   // exactly the window after the first failure: it still counts ("older than" the window ends it)
            Assert.Equal(HttpStatusCode.TooManyRequests, (await attacker.PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password })).Status);
            _f.Clock.Advance(TimeSpan.FromSeconds(1));   // now the first failure has aged out: four are left, under the limit of five
            Assert.Equal(HttpStatusCode.OK, (await attacker.PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password })).Status);
            _f.Clock.Advance(TimeSpan.FromDays(1));
        }
    }
}
