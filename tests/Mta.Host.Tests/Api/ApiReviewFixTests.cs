using System.Net;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Mta.Host.Api;
using Mta.Observability;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

/// <summary>Regression tests for problems found in review of the API.</summary>
[Collection("api")]
public class ApiReviewFixTests : IAsyncLifetime
{
    private ApiFixture _f = null!;

    public async Task InitializeAsync() => _f = await ApiFixture.StartAsync();

    public async Task DisposeAsync() => await _f.DisposeAsync();

    [Fact]
    public async Task Padding_the_user_name_does_not_buy_a_fresh_failure_budget()
    {
        string[] variants = ["alice", "alice ", " alice", "ALICE", " Alice  ", "alice\t"];
        for (int i = 0; i < 5; i++)
        {
            ApiClient c = _f.NewClient();
            c.RemoteIp = "198.51.100." + (10 + i); // different addresses: only the user budget is shared
            (await c.PostAsync("/api/v1/session", new { user = variants[i], password = "bad" })).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        }

        ApiClient locked = _f.NewClient();
        locked.RemoteIp = "198.51.100.99";
        (await locked.PostAsync("/api/v1/session", new { user = variants[5], password = ApiFixture.Password })).Problem(HttpStatusCode.TooManyRequests, "rate_limited");
    }

    [Fact]
    public async Task A_successful_login_does_not_reset_the_address_limit()
    {
        ApiClient attacker = _f.NewClient();
        attacker.RemoteIp = "203.0.113.5";
        // The attacker owns a valid account (bob) and guesses alice's password; success with his own account must not clear the address count.
        for (int round = 0; round < 2; round++)
        {
            for (int i = 0; i < 2; i++)
            {
                await attacker.PostAsync("/api/v1/session", new { user = "alice", password = "guess" + round + i });
            }

            Assert.Equal(HttpStatusCode.OK, (await attacker.PostAsync("/api/v1/session", new { user = "bob", password = ApiFixture.Password })).Status);
        }

        // 4 failures so far; the fifth reaches the limit although two successes happened in between.
        await attacker.PostAsync("/api/v1/session", new { user = "alice", password = "guess-last" });
        (await attacker.PostAsync("/api/v1/session", new { user = "bob", password = ApiFixture.Password })).Problem(HttpStatusCode.TooManyRequests, "rate_limited");
    }

    private sealed class Throwing : IHealthContributor
    {
        public string Name => "database";

        public ValueTask<HealthReport> CheckAsync(CancellationToken cancellationToken) => throw new InvalidOperationException("password authentication failed for user \"eggmail\" at db.internal:5432");
    }

    [Fact]
    public async Task A_failing_health_check_never_shows_its_exception_text_to_anonymous_callers()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureServices = s => s.AddSingleton<IHealthContributor>(new Throwing()) });
        Reply ready = await f.NewClient().GetAsync("/readyz");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.Status);
        Assert.Contains("database_check_failed", ready.Body);
        Assert.DoesNotContain("db.internal", ready.Body);
        Assert.DoesNotContain("password", ready.Body);
        Reply caps = await f.NewClient().GetAsync("/api/v1/capabilities");
        Assert.DoesNotContain("db.internal", caps.Body);
    }

    private sealed class Unavailable : IStorageSwitchService
    {
        private static StorageUnavailableException Down() => new("PostgreSQL is unavailable: could not connect to db.internal:5432");

        public ValueTask<SwitchPreflightReport> PreflightAsync(SwitchRequestModel request, CancellationToken cancellationToken) => throw Down();

        public ValueTask<SwitchStatusReport> StartAsync(SwitchStartModel request, CancellationToken cancellationToken) => throw Down();

        public ValueTask<SwitchStatusReport> GetStatusAsync(CancellationToken cancellationToken) => throw Down();

        public ValueTask<SwitchStatusReport> ConfirmAsync(CancellationToken cancellationToken) => throw Down();

        public ValueTask<SwitchStatusReport> ActivateAsync(CancellationToken cancellationToken) => throw Down();

        public ValueTask<SwitchStatusReport> RollbackAsync(CancellationToken cancellationToken) => throw Down();

        public ValueTask<SwitchStatusReport> FinalizeAsync(CancellationToken cancellationToken) => throw Down();
    }

    [Fact]
    public async Task A_database_outage_is_503_not_ready_without_details()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureServices = s => s.AddSingleton<IStorageSwitchService>(new Unavailable()) });
        ApiClient admin = await f.SignedInAsync("root");
        Reply r = await admin.GetAsync("/api/v1/admin/storage/switch");
        r.Problem(HttpStatusCode.ServiceUnavailable, "not_ready");
        Assert.Equal("5", r.Header("Retry-After"));
        Assert.DoesNotContain("db.internal", r.Body);
    }

    [Fact]
    public async Task Null_array_elements_are_validation_errors_not_500s()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId);
        Reply nullAttachment = await c.SendAsync(HttpMethod.Post, "/api/v1/messages", """{"from":"a@example.com","to":["b@x.test"],"subject":"s","text":"t","attachments":[null]}""");
        nullAttachment.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains("attachments[0]", nullAttachment.ErrorFields);

        Reply nullHeader = await c.SendAsync(HttpMethod.Post, "/api/v1/messages", """{"from":"a@example.com","to":["b@x.test"],"subject":"s","text":"t","headers":{"X-A":null}}""");
        nullHeader.Problem(HttpStatusCode.BadRequest, "validation_failed");

        Reply nullTo = await c.SendAsync(HttpMethod.Post, "/api/v1/messages", """{"from":"a@example.com","to":[null],"subject":"s","text":"t","tags":[null]}""");
        nullTo.Problem(HttpStatusCode.BadRequest, "validation_failed");

        (await c.SendAsync(HttpMethod.Post, "/api/v1/webhooks", """{"url":"https://x.example.com/h","event_types":[null]}""")).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await c.SendAsync(HttpMethod.Post, "/api/v1/api-keys", """{"name":"n","scopes":[null]}""")).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await c.SendAsync(HttpMethod.Post, "/api/v1/messages/raw", """{"from":"a@example.com","to":[null],"raw":"QQ=="}""")).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task Extreme_timestamps_are_validation_errors()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId);
        (await c.GetAsync("/api/v1/stats?to=0001-01-01T00:00:00Z")).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await c.GetAsync("/api/v1/stats?from=9999-12-31T00:00:00Z")).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await c.GetAsync("/api/v1/messages?from=1000-01-01")).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Theory]
    [InlineData("text/plain; x=+json")]
    [InlineData("text/html")]
    [InlineData("application/jsonx")]
    public async Task Only_json_media_types_are_accepted(string contentType)
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId, "domains");
        (await c.SendRawAsync(HttpMethod.Post, "/api/v1/domains", """{"name":"x.example"}""", contentType)).Problem(HttpStatusCode.UnsupportedMediaType, "unsupported_media_type");
        Assert.Equal(HttpStatusCode.Created, (await c.SendRawAsync(HttpMethod.Post, "/api/v1/domains", """{"name":"x.example"}""", "application/json")).Status);
        Assert.Equal(HttpStatusCode.Created, (await c.SendRawAsync(HttpMethod.Post, "/api/v1/domains", """{"name":"y.example"}""", "application/vnd.eggmail+json")).Status);
    }

    [Fact]
    public async Task A_user_of_a_suspended_tenant_can_still_sign_out()
    {
        ApiClient c = await _f.SignedInAsync("alice");
        string cookie = c.Cookie!;
        await _f.Storage.Config.UpsertTenantAsync(_f.TenantA with { Enabled = false }, default);
        Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync("/api/v1/session")).Status);

        // The server-side session is gone: after re-enabling the tenant the old cookie does not work.
        await _f.Storage.Config.UpsertTenantAsync(_f.TenantA with { Enabled = true }, default);
        ApiClient replay = _f.NewClient();
        replay.Cookie = cookie;
        (await replay.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");

        // Without the CSRF token it is still refused.
        ApiClient again = await _f.SignedInAsync("alice");
        await _f.Storage.Config.UpsertTenantAsync(_f.TenantA with { Enabled = false }, default);
        again.SendCsrf = false;
        (await again.DeleteAsync("/api/v1/session")).Problem(HttpStatusCode.Forbidden, "forbidden");
    }

    [Fact]
    public async Task Creating_an_smtp_credential_needs_the_send_scope_as_well()
    {
        ApiClient keysOnly = await _f.KeyClientAsync(ApiFixture.TenantAId, "keys");
        (await keysOnly.PostAsync("/api/v1/smtp-credentials", new { username = "sneaky" })).Problem(HttpStatusCode.Forbidden, "forbidden");
        Assert.Equal(HttpStatusCode.OK, (await keysOnly.GetAsync("/api/v1/smtp-credentials")).Status);
        ApiClient both = await _f.KeyClientAsync(ApiFixture.TenantAId, "keys", "send");
        Assert.Equal(HttpStatusCode.Created, (await both.PostAsync("/api/v1/smtp-credentials", new { username = "allowed" })).Status);
    }

    [Fact]
    public async Task A_pending_rotation_can_be_cancelled_and_then_started_again()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId, "domains");
        string id = (await c.PostAsync("/api/v1/domains", new { name = "cancel.example" })).Str("id");
        (await c.DeleteAsync($"/api/v1/domains/{id}/dkim/rotate")).Problem(HttpStatusCode.NotFound, "not_found");

        _f.Clock.Advance(TimeSpan.FromHours(1));
        Reply rotated = await c.PostAsync($"/api/v1/domains/{id}/dkim/rotate");
        Assert.Equal(2, rotated["dkimKeys"].GetArrayLength());
        (await c.PostAsync($"/api/v1/domains/{id}/dkim/rotate")).Problem(HttpStatusCode.Conflict, "conflict");

        Reply cancelled = await c.DeleteAsync($"/api/v1/domains/{id}/dkim/rotate");
        Assert.Equal(HttpStatusCode.OK, cancelled.Status);
        Assert.Equal(1, cancelled["dkimKeys"].GetArrayLength());
        Assert.True(cancelled["dkim"].GetProperty("active").GetBoolean());

        _f.Clock.Advance(TimeSpan.FromHours(1));
        Reply again = await c.PostAsync($"/api/v1/domains/{id}/dkim/rotate");
        Assert.Equal(HttpStatusCode.OK, again.Status);
        // The cancelled selector is not reused: the new key gets the next free name.
        Assert.Equal("egg202610-2", again["dkim"].GetProperty("selector").GetString());

        ApiClient other = await _f.KeyClientAsync(ApiFixture.TenantBId, "domains");
        (await other.DeleteAsync($"/api/v1/domains/{id}/dkim/rotate")).Problem(HttpStatusCode.NotFound, "not_found");
    }

    [Fact]
    public async Task Concurrent_rotations_create_one_key()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId, "domains");
        string id = (await c.PostAsync("/api/v1/domains", new { name = "race.example" })).Str("id");
        _f.Clock.Advance(TimeSpan.FromHours(1));
        Reply[] replies = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => c.PostAsync($"/api/v1/domains/{id}/dkim/rotate")));
        Assert.Equal(1, replies.Count(r => r.Status == HttpStatusCode.OK));
        Assert.All(replies.Where(r => r.Status != HttpStatusCode.OK), r => Assert.Equal(HttpStatusCode.Conflict, r.Status));
        Assert.Equal(2, (await _f.Storage.Config.GetDkimKeysAsync(Guid.Parse(id), default)).Count);
    }
}
