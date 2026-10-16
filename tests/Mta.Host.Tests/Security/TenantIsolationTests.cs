using System.Net;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Tests.Api;
using Mta.Storage;

namespace Mta.Host.Tests.Security;

/// <summary>
/// Security regression tests for tenant isolation (docs/security-test-map.md, TENANT-*): tenant A creates one of everything, then tenant B, as a
/// dashboard user, with an API key, and as an administrator acting for B, goes through every route that takes an id with A's ids. The oracle is
/// "A's id is answered exactly like an id that does not exist", which also means the answer does not reveal that the resource exists.
/// The in-house review, not an independent audit.
/// </summary>
[Collection("api")]
public class TenantIsolationTests : IAsyncLifetime
{
    private ApiFixture _f = null!;
    private ApiClient _aAlice = null!;
    private ApiClient _aKey = null!;
    private string _domainId = "", _messageId = "", _webhookId = "", _keyId = "", _smtpId = "", _outboxId = "", _suppressed = "";

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.PasswordHashIterations = 1000 });
        _aAlice = await _f.SignedInAsync("alice");
        _aKey = await _f.KeyClientAsync(ApiFixture.TenantAId);

        _domainId = (await _aAlice.GetAsync("/api/v1/domains")).Json.EnumerateArray().Single().GetProperty("id").GetString()!;
        Reply sent = await _aKey.PostAsync("/api/v1/messages", new { from = "noreply@example.com", to = new[] { "a-recipient@gmail.test" }, subject = "A's private subject", text = "A's private body", tags = new[] { "a-private-tag" } });
        Assert.Equal(HttpStatusCode.Accepted, sent.Status);
        _messageId = sent.Str("id");
        Reply hook = await _aAlice.PostAsync("/api/v1/webhooks", new { url = "https://hooks.example.com/a-only", event_types = new[] { "*" } });
        Assert.Equal(HttpStatusCode.Created, hook.Status);
        _webhookId = hook.Str("id");
        Reply key = await _aAlice.PostAsync("/api/v1/api-keys", new { name = "a-private-key", scopes = new[] { "read" } });
        _keyId = key.Str("id");
        Reply smtp = await _aAlice.PostAsync("/api/v1/smtp-credentials", new { username = "a-private-user" });
        _smtpId = smtp.Str("id");
        _suppressed = "a-private-suppressed@example.org";
        Assert.Equal(HttpStatusCode.Created, (await _aAlice.PostAsync("/api/v1/suppressions", new { address = _suppressed })).Status);

        // A finished (failed) webhook event of A: the only kind a replay accepts.
        Reply test = await _aAlice.PostAsync($"/api/v1/webhooks/{_webhookId}/test");
        Assert.Equal(HttpStatusCode.Accepted, test.Status);
        Guid outbox = Guid.Parse(test.Str("outboxId"));
        var claimed = await _f.Storage.Webhooks.ClaimDueAsync("t", 10, _f.Clock.UtcNow.AddMinutes(1), TimeSpan.FromMinutes(1), default);
        var item = claimed.Single(c => c.Id == outbox);
        await _f.Storage.Webhooks.CompleteAsync(item.Id, new WebhookAttemptRecord(item.Id, _f.Clock.UtcNow, 500, TimeSpan.FromMilliseconds(5), "http_500", null), WebhookOutboxState.Failed, null, default);
        _outboxId = ApiJson.Id(outbox);
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private IEnumerable<(string Method, string Pattern, string? Body)> IdRoutes() =>
    [
        ("GET", "/api/v1/domains/{id}", null),
        ("DELETE", "/api/v1/domains/{id}", null),
        ("GET", "/api/v1/domains/{id}/records", null),
        ("POST", "/api/v1/domains/{id}/verify", "{}"),
        ("POST", "/api/v1/domains/{id}/dkim/rotate", "{}"),
        ("DELETE", "/api/v1/domains/{id}/dkim/rotate", null),
        ("GET", "/api/v1/domains/{id}/inbound", null),
        ("PATCH", "/api/v1/domains/{id}/inbound", """{"enabled":true}"""),
        ("GET", "/api/v1/domains/{id}/inbound/routes", null),
        ("POST", "/api/v1/domains/{id}/inbound/routes", "{}"),
        ("GET", "/api/v1/domains/{id}/inbound/routes/match?address=x%40example.com", null),
        ("GET", "/api/v1/domains/{id}/inbound/routes/{routeId}", null),
        ("PATCH", "/api/v1/domains/{id}/inbound/routes/{routeId}", "{}"),
        ("DELETE", "/api/v1/domains/{id}/inbound/routes/{routeId}", null),
        ("GET", "/api/v1/messages/{id}", null),
        ("GET", "/api/v1/messages/{id}/events", null),
        ("GET", "/api/v1/messages/{id}/content", null),
        ("POST", "/api/v1/messages/{id}/resend", "{}"),
        ("POST", "/api/v1/messages/{id}/cancel", "{}"),
        ("GET", "/api/v1/webhooks/{id}", null),
        ("PATCH", "/api/v1/webhooks/{id}", """{"enabled":false}"""),
        ("PATCH", "/api/v1/webhooks/{id}", """{"url":"https://hooks.example.com/stolen"}"""),
        ("DELETE", "/api/v1/webhooks/{id}", null),
        ("POST", "/api/v1/webhooks/{id}/rotate-secret", "{}"),
        ("DELETE", "/api/v1/webhooks/{id}/previous-secret", null),
        ("POST", "/api/v1/webhooks/{id}/test", "{}"),
        ("GET", "/api/v1/webhooks/{id}/attempts", null),
        ("POST", "/api/v1/webhook-events/{outboxId}/replay", "{}"),
        ("DELETE", "/api/v1/api-keys/{id}", null),
        ("DELETE", "/api/v1/smtp-credentials/{id}", null),
        ("DELETE", "/api/v1/suppressions/{address}", null),
    ];

    private string Real(string pattern) => pattern
        .Replace("{address}", Uri.EscapeDataString(_suppressed), StringComparison.Ordinal)
        .Replace("{outboxId}", _outboxId, StringComparison.Ordinal)
        .Replace("{routeId}", Guid.NewGuid().ToString("N"), StringComparison.Ordinal)
        .Replace("{id}", pattern.Contains("/domains/", StringComparison.Ordinal) ? _domainId
            : pattern.Contains("/messages/", StringComparison.Ordinal) ? _messageId
            : pattern.Contains("/api-keys/", StringComparison.Ordinal) ? _keyId
            : pattern.Contains("/smtp-credentials/", StringComparison.Ordinal) ? _smtpId
            : _webhookId, StringComparison.Ordinal);

    private static string Missing(string pattern) => pattern
        .Replace("{address}", Uri.EscapeDataString("nobody-" + Guid.NewGuid().ToString("N") + "@example.org"), StringComparison.Ordinal)
        .Replace("{outboxId}", Guid.NewGuid().ToString("N"), StringComparison.Ordinal)
        .Replace("{routeId}", Guid.NewGuid().ToString("N"), StringComparison.Ordinal)
        .Replace("{id}", Guid.NewGuid().ToString("N"), StringComparison.Ordinal);

    private async Task<IReadOnlyList<ApiClient>> OutsidersAsync() =>
    [
        await _f.SignedInAsync("bob"),
        await _f.KeyClientAsync(ApiFixture.TenantBId),
        (await _f.SignedInAsync("root")).ActingAs(ApiFixture.TenantBId),
    ];

    [Fact]
    public async Task Another_tenants_resource_is_answered_exactly_like_one_that_does_not_exist_on_every_route_that_takes_an_id()
    {
        foreach (ApiClient outsider in await OutsidersAsync())
        {
            foreach (var (method, pattern, body) in IdRoutes())
            {
                Reply foreign = await outsider.SendRawAsync(new HttpMethod(method), Real(pattern), body, body is null ? null : "application/json");
                Reply missing = await outsider.SendRawAsync(new HttpMethod(method), Missing(pattern), body, body is null ? null : "application/json");

                string where = $"{method} {pattern} as {(outsider.Bearer is not null ? "key" : outsider.TenantId is not null ? "admin" : "user")}";
                Assert.True(foreign.Status == missing.Status, $"{where}: {(int)foreign.Status} {foreign.Body} versus a missing id: {(int)missing.Status} {missing.Body}");
                if (foreign.ContentType == "application/problem+json")
                {
                    Assert.Equal(missing.Code, foreign.Code);
                    Assert.Equal(missing.Json.GetProperty("title").GetString(), foreign.Json.GetProperty("title").GetString());
                }

                Assert.DoesNotContain("a-private", foreign.Body, StringComparison.Ordinal);
                Assert.DoesNotContain("A's private", foreign.Body, StringComparison.Ordinal);
                Assert.DoesNotContain("a-recipient", foreign.Body, StringComparison.Ordinal);
                Assert.DoesNotContain("a-only", foreign.Body, StringComparison.Ordinal);
            }
        }

        await AssertTenantAUntouchedAsync();
    }

    [Fact]
    public async Task No_list_of_another_tenant_contains_anything_of_tenant_A()
    {
        foreach (ApiClient outsider in await OutsidersAsync())
        {
            foreach (string path in new[]
            {
                "/api/v1/domains", "/api/v1/messages", "/api/v1/messages?limit=200", "/api/v1/messages?recipient=a-recipient%40gmail.test", "/api/v1/messages?subject=private",
                "/api/v1/messages?tag=a-private-tag", "/api/v1/messages?sender=noreply%40example.com", "/api/v1/messages?status=queued",
                "/api/v1/webhooks", "/api/v1/api-keys", "/api/v1/smtp-credentials", "/api/v1/suppressions", "/api/v1/stats", "/api/v1/stats?domain=example.com",
                "/api/v1/stats/recent-events", "/api/v1/settings",
            })
            {
                Reply reply = await outsider.GetAsync(path);
                Assert.Equal(HttpStatusCode.OK, reply.Status);
                foreach (string secret in new[] { "example.com", _domainId, _messageId, _webhookId, _keyId, _smtpId, _suppressed, "a-private", "A's private", "a-recipient", "a-only", "noreply@example.com" })
                {
                    Assert.False(reply.Body.Contains(secret, StringComparison.Ordinal) && !path.Contains(secret, StringComparison.Ordinal) && !path.Contains(Uri.EscapeDataString(secret), StringComparison.Ordinal), $"{path} shows '{secret}' of tenant A: {reply.Body}");
                }
            }
        }
    }

    [Fact]
    public async Task A_cursor_from_one_tenant_shows_nothing_of_another_when_used_there()
    {
        // Tenant B gets a message, and its first page cursor is replayed by tenant A and the other way round.
        ApiClient bKey = await _f.KeyClientAsync(ApiFixture.TenantBId);
        for (int i = 0; i < 3; i++)
        {
            Assert.Equal(HttpStatusCode.Accepted, (await bKey.PostAsync("/api/v1/messages", new { from = "me@globex.test", to = new[] { $"b{i}@gmail.test" }, subject = "B's private subject " + i, text = "t" })).Status);
            Assert.Equal(HttpStatusCode.Accepted, (await _aKey.PostAsync("/api/v1/messages", new { from = "noreply@example.com", to = new[] { $"a{i}@gmail.test" }, subject = "A's private subject " + i, text = "t" })).Status);
        }

        Reply bFirst = await bKey.GetAsync("/api/v1/messages?limit=1");
        string? cursor = bFirst.Json.GetProperty("next_cursor").GetString();
        Assert.NotNull(cursor);
        Reply aWithBCursor = await _aKey.GetAsync("/api/v1/messages?limit=200&cursor=" + Uri.EscapeDataString(cursor!));
        Assert.True(aWithBCursor.Status is HttpStatusCode.OK or HttpStatusCode.BadRequest);
        Assert.DoesNotContain("B's private", aWithBCursor.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("globex", aWithBCursor.Body, StringComparison.Ordinal);

        Reply aFirst = await _aKey.GetAsync("/api/v1/messages?limit=1");
        string aCursor = aFirst.Json.GetProperty("next_cursor").GetString()!;
        Reply bWithACursor = await bKey.GetAsync("/api/v1/messages?limit=200&cursor=" + Uri.EscapeDataString(aCursor));
        Assert.DoesNotContain("A's private", bWithACursor.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("example.com", bWithACursor.Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task One_tenants_settings_do_not_show_in_or_change_another()
    {
        Assert.Equal(HttpStatusCode.OK, (await _aAlice.PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { ["Content:StoreAttachments"] = true } })).Status);
        ApiClient bob = await _f.SignedInAsync("bob");

        Reply b = await bob.GetAsync("/api/v1/settings");
        Assert.Equal(HttpStatusCode.OK, b.Status);
        Assert.Contains((await _f.Storage.Config.GetSettingsAsync(ApiFixture.TenantAId, default)), s => s.Key.Contains("StoreAttachments", StringComparison.Ordinal));
        Assert.DoesNotContain((await _f.Storage.Config.GetSettingsAsync(ApiFixture.TenantBId, default)), s => s.Key.Contains("StoreAttachments", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_message_sent_by_one_tenant_cannot_use_another_tenants_domain_or_suppression_list()
    {
        ApiClient bKey = await _f.KeyClientAsync(ApiFixture.TenantBId);
        // B cannot send as A's domain, whether the message is composed or raw, and whichever way the address is spelled.
        foreach (string from in new[] { "noreply@example.com", "NOREPLY@EXAMPLE.COM", "x@sub.example.com", "x@example.com.", "Acme <noreply@example.com>" })
        {
            Reply r = await bKey.PostAsync("/api/v1/messages", new { from, to = new[] { "victim@gmail.test" }, subject = "s", text = "t" });
            Assert.True(r.Status is HttpStatusCode.BadRequest or HttpStatusCode.Forbidden, $"{from}: {(int)r.Status} {r.Body}");
        }

        // A suppression of A is not B's: a recipient A suppressed is still sent to for B.
        Assert.Equal(HttpStatusCode.Accepted, (await bKey.PostAsync("/api/v1/messages", new { from = "me@globex.test", to = new[] { _suppressed }, subject = "s", text = "t" })).Status);
        Reply bMessages = await bKey.GetAsync("/api/v1/messages");
        Assert.Equal("queued", bMessages["items"][0].GetProperty("status").GetString());
    }

    private async Task AssertTenantAUntouchedAsync()
    {
        Assert.NotNull(await _f.Storage.Config.GetDomainAsync(Guid.Parse(_domainId), default));
        var hook = Assert.Single(await _f.Storage.Config.GetWebhookEndpointsAsync(ApiFixture.TenantAId, default));
        Assert.Equal("https://hooks.example.com/a-only", hook.Url);
        Assert.True(hook.Enabled);
        Assert.Equal(1, (await _f.Storage.Config.GetApiKeysAsync(ApiFixture.TenantAId, default)).Count(k => k.Name == "a-private-key" && k.RevokedAt is null));
        Assert.Contains(await _f.Storage.Config.GetSmtpCredentialsAsync(ApiFixture.TenantAId, default), c => c.UserName == "a-private-user");
        Assert.True(await _f.Storage.Config.IsSuppressedAsync(ApiFixture.TenantAId, _suppressed, default));
        Reply detail = await _aKey.GetAsync("/api/v1/messages/" + _messageId);
        Assert.Equal(HttpStatusCode.OK, detail.Status);
        Assert.Equal("queued", detail.Str("status"));
        Reply failed = await _aAlice.GetAsync($"/api/v1/webhooks/{_webhookId}/attempts");
        Assert.Single(failed.Json.EnumerateArray());   // not replayed by anybody else: the attempt count is unchanged
    }
}
