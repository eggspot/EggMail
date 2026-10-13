using System.Net;
using System.Text;
using System.Text.Json;
using Mta.Core;
using Mta.Host.Api;
using Mta.Storage;
using Mta.Webhooks;

namespace Mta.Host.Tests.Api;

[Collection("api")]
public class ApiSuppressionsTests : IAsyncLifetime
{
    private ApiFixture _f = null!;
    private ApiClient _a = null!;

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync();
        _a = await _f.KeyClientAsync(ApiFixture.TenantAId);
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    [Fact]
    public async Task Adding_listing_and_removing_an_address()
    {
        Assert.Equal(0, (await _a.GetAsync("/api/v1/suppressions"))["items"].GetArrayLength());

        Reply added = await _a.PostAsync("/api/v1/suppressions", new { address = "  Bounce@Example.ORG ", reason = "manual" });
        Assert.Equal(HttpStatusCode.Created, added.Status);
        Assert.Equal("bounce@example.org", added.Str("address"));
        Assert.Equal("manual", added.Str("reason"));
        Assert.Equal("2026-10-12T12:30:00.000Z", added.Str("createdAt"));

        Reply list = await _a.GetAsync("/api/v1/suppressions");
        Assert.Equal(["bounce@example.org"], list["items"].EnumerateArray().Select(i => i.GetProperty("address").GetString()!));
        Assert.Equal(JsonValueKind.Null, list["next_cursor"].ValueKind);
        Assert.True(await _f.Storage.Config.IsSuppressedAsync(ApiFixture.TenantAId, "BOUNCE@example.org", default));

        Assert.Equal(HttpStatusCode.NoContent, (await _a.DeleteAsync("/api/v1/suppressions/bounce%40example.org")).Status);
        (await _a.DeleteAsync("/api/v1/suppressions/bounce%40example.org")).Problem(HttpStatusCode.NotFound, "not_found");
        Assert.False(await _f.Storage.Config.IsSuppressedAsync(ApiFixture.TenantAId, "bounce@example.org", default));
    }

    [Fact]
    public async Task Adding_the_same_address_again_updates_it_and_answers_200()
    {
        await _a.PostAsync("/api/v1/suppressions", new { address = "x@example.org" });
        Reply again = await _a.PostAsync("/api/v1/suppressions", new { address = "X@example.org", reason = "complaint" });
        Assert.Equal(HttpStatusCode.OK, again.Status);
        Assert.Equal("complaint", again.Str("reason"));
        Assert.Single((await _a.GetAsync("/api/v1/suppressions"))["items"].EnumerateArray());
    }

    [Fact]
    public async Task Reasons_map_to_the_stored_kinds()
    {
        foreach (var (reason, stored) in new[] { ("bounce", SuppressionReason.HardBounce), ("complaint", SuppressionReason.Complaint), ("unsubscribe", SuppressionReason.Unsubscribe), ("manual", SuppressionReason.Manual) })
        {
            string address = reason + "@example.org";
            Assert.Equal(HttpStatusCode.Created, (await _a.PostAsync("/api/v1/suppressions", new { address, reason })).Status);
            var page = await _f.Storage.Config.GetSuppressionsAsync(ApiFixture.TenantAId, null, 50, default);
            Assert.Equal(stored, page.Items.Single(s => s.Address == address).Reason);
        }

        Reply list = await _a.GetAsync("/api/v1/suppressions");
        Assert.Equal(["bounce", "complaint", "manual", "unsubscribe"], list["items"].EnumerateArray().Select(i => i.GetProperty("reason").GetString()!).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Invalid_input_is_validation_failed()
    {
        Reply r = await _a.PostAsync("/api/v1/suppressions", new { address = "not an address", reason = "spite" });
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["address", "reason"], r.ErrorFields);
        (await _a.PostAsync("/api/v1/suppressions", new { reason = "manual" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task The_list_is_paged_in_address_order()
    {
        for (int i = 0; i < 7; i++)
        {
            await _a.PostAsync("/api/v1/suppressions", new { address = $"user{i}@example.org" });
        }

        var seen = new List<string>();
        string? cursor = null;
        int pages = 0;
        do
        {
            Reply page = await _a.GetAsync("/api/v1/suppressions?limit=3" + (cursor is null ? "" : "&cursor=" + Uri.EscapeDataString(cursor)));
            seen.AddRange(page["items"].EnumerateArray().Select(i => i.GetProperty("address").GetString()!));
            cursor = page["next_cursor"].GetString();
            pages++;
        }
        while (cursor is not null && pages < 10);

        Assert.Equal(3, pages);
        Assert.Equal(Enumerable.Range(0, 7).Select(i => $"user{i}@example.org"), seen);
        (await _a.GetAsync("/api/v1/suppressions?limit=0")).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task Suppressions_are_isolated_per_tenant()
    {
        ApiClient b = await _f.KeyClientAsync(ApiFixture.TenantBId);
        await _a.PostAsync("/api/v1/suppressions", new { address = "shared@example.org" });
        await b.PostAsync("/api/v1/suppressions", new { address = "only-b@example.org" });

        Assert.Equal(["shared@example.org"], (await _a.GetAsync("/api/v1/suppressions"))["items"].EnumerateArray().Select(i => i.GetProperty("address").GetString()!));
        (await _a.DeleteAsync("/api/v1/suppressions/only-b%40example.org")).Problem(HttpStatusCode.NotFound, "not_found");
        Assert.True(await _f.Storage.Config.IsSuppressedAsync(ApiFixture.TenantBId, "only-b@example.org", default));
        Assert.False(await _f.Storage.Config.IsSuppressedAsync(ApiFixture.TenantAId, "only-b@example.org", default));
    }

    [Fact]
    public async Task Suppressions_need_their_scope()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId, "read", "send");
        (await c.GetAsync("/api/v1/suppressions")).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await c.PostAsync("/api/v1/suppressions", new { address = "a@b.test" })).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await c.DeleteAsync("/api/v1/suppressions/a%40b.test")).Problem(HttpStatusCode.Forbidden, "forbidden");
    }
}

[Collection("api")]
public class ApiWebhooksTests : IAsyncLifetime
{
    private ApiFixture _f = null!;
    private ApiClient _a = null!;

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync();
        _a = await _f.KeyClientAsync(ApiFixture.TenantAId);
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private async Task<JsonElement> CreateAsync(string url = "https://hooks.acme.example/eggmail", ApiClient? client = null, params string[] events)
    {
        Reply r = await (client ?? _a).PostAsync("/api/v1/webhooks", new { url, event_types = events.Length == 0 ? new[] { "message.delivered", "message.bounced" } : events });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        return r.Json.Clone();
    }

    private async Task<string[]> StoredSecretsAsync(string id)
    {
        var ep = (await _f.Storage.Config.GetWebhookEndpointAsync(Guid.Parse(id), default))!;
        return Encoding.UTF8.GetString(_f.Protector.Unprotect(ep.SecretProtected, SecretPurposes.WebhookSecret)).Split(' ');
    }

    [Fact]
    public async Task Creating_an_endpoint_shows_the_signing_secret_once()
    {
        Reply r = await _a.PostAsync("/api/v1/webhooks", new { url = "https://hooks.acme.example/eggmail", event_types = new[] { "message.delivered", "message.bounced", "message.delivered" } });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        Assert.Matches("^/api/v1/webhooks/[0-9a-f]{32}$", r.Header("Location"));
        string secret = r.Str("secret");
        Assert.StartsWith("whsec_", secret);
        Assert.Equal(24, Convert.FromBase64String(secret["whsec_".Length..]).Length);
        Assert.Equal("https://hooks.acme.example/eggmail", r.Str("url"));
        Assert.Equal(["message.delivered", "message.bounced"], r["event_types"].EnumerateArray().Select(e => e.GetString()!));
        Assert.True(r["enabled"].GetBoolean());
        Assert.Equal(JsonValueKind.Null, r["disabledReason"].ValueKind);
        Assert.False(r["secretRotationPending"].GetBoolean());

        string id = r.Str("id");
        Assert.Equal([secret], await StoredSecretsAsync(id));
        Assert.DoesNotContain(secret, (await _a.GetAsync("/api/v1/webhooks/" + id)).Body);
        Assert.DoesNotContain(secret, (await _a.GetAsync("/api/v1/webhooks")).Body);
        Assert.False((await _a.GetAsync("/api/v1/webhooks/" + id)).Json.TryGetProperty("secret", out _));
    }

    [Theory]
    [InlineData("http://hooks.example.com/x", "https")]
    [InlineData("https://localhost/x", "host")]
    [InlineData("https://127.0.0.1/x", "non-public")]
    [InlineData("https://10.1.2.3/x", "non-public")]
    [InlineData("https://192.168.0.5/x", "non-public")]
    [InlineData("https://169.254.169.254/latest/meta-data", "non-public")]
    [InlineData("https://[::1]/x", "non-public")]
    [InlineData("https://[fd00::1]/x", "non-public")]
    [InlineData("https://user:secret@hooks.example.com/x", "Credentials")]
    [InlineData("ftp://hooks.example.com/x", "https")]
    [InlineData("not a url", "valid")]
    [InlineData("", "valid")]
    public async Task Unsafe_urls_are_refused_by_the_ssrf_guard(string url, string reason)
    {
        Reply r = await _a.PostAsync("/api/v1/webhooks", new { url, event_types = new[] { "message.delivered" } });
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["url"], r.ErrorFields);
        Assert.Contains(reason, r["errors"][0].GetProperty("message").GetString());
        Assert.Empty(await _f.Storage.Config.GetWebhookEndpointsAsync(ApiFixture.TenantAId, default));
    }

    [Fact]
    public async Task Internal_endpoints_need_an_allowlist_that_only_an_admin_can_set()
    {
        string body = """{"url":"https://10.0.0.5/hook","event_types":["message.delivered"]}""";
        (await _a.SendAsync(HttpMethod.Post, "/api/v1/webhooks", body)).Problem(HttpStatusCode.BadRequest, "validation_failed");

        // The tenant cannot lift its own SSRF protection.
        ApiClient alice = await _f.SignedInAsync("alice");
        Reply denied = await alice.PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { ["Webhooks:AllowedNetworks"] = "10.0.0.0/8" } });
        denied.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["Webhooks:AllowedNetworks"], denied.ErrorFields);
        Assert.Contains("administrator", denied["errors"][0].GetProperty("message").GetString());
        Reply view = await alice.GetAsync("/api/v1/settings");
        Assert.True(view["items"].EnumerateArray().Single(i => i.GetProperty("key").GetString() == "Webhooks:AllowedNetworks").GetProperty("locked").GetBoolean());

        ApiClient admin = (await _f.SignedInAsync("root")).ActingAs(ApiFixture.TenantAId);
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { ["Webhooks:AllowedNetworks"] = "10.0.0.0/8, fd00::/8" } })).Status);
        Assert.Equal(HttpStatusCode.Created, (await _a.SendAsync(HttpMethod.Post, "/api/v1/webhooks", body)).Status);

        // Other tenants are unaffected, and addresses outside the allowlist stay refused.
        ApiClient b = await _f.KeyClientAsync(ApiFixture.TenantBId);
        (await b.SendAsync(HttpMethod.Post, "/api/v1/webhooks", body)).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _a.SendAsync(HttpMethod.Post, "/api/v1/webhooks", """{"url":"https://172.16.0.9/hook","event_types":["message.delivered"]}""")).Problem(HttpStatusCode.BadRequest, "validation_failed");

        // The allowlist is what the dispatcher is wired to.
        var networks = await _f.Get<SettingsService>().GetWebhookAllowlistAsync(ApiFixture.TenantAId, default);
        Assert.Equal(2, networks.Count);
        Assert.True(networks[0].Contains(System.Net.IPAddress.Parse("10.9.9.9")));
        Assert.Empty(await _f.Get<SettingsService>().GetWebhookAllowlistAsync(ApiFixture.TenantBId, default));
    }

    [Fact]
    public async Task A_malformed_allowlist_is_refused()
    {
        ApiClient admin = (await _f.SignedInAsync("root")).ActingAs(ApiFixture.TenantAId);
        Reply r = await admin.PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { ["Webhooks:AllowedNetworks"] = "10.0.0.0/8, banana" } });
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains("banana", r["errors"][0].GetProperty("message").GetString());
    }

    [Fact]
    public async Task Http_endpoints_can_be_allowed_by_the_operator()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.Webhooks = new WebhookOptions { AllowHttp = true } });
        ApiClient c = await f.KeyClientAsync(ApiFixture.TenantAId);
        Assert.Equal(HttpStatusCode.Created, (await c.PostAsync("/api/v1/webhooks", new { url = "http://hooks.example.com/x", event_types = new[] { "message.delivered" } })).Status);
        (await c.PostAsync("/api/v1/webhooks", new { url = "http://127.0.0.1/x", event_types = new[] { "message.delivered" } })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task Event_types_are_validated()
    {
        foreach (object types in new object[] { new string[0], new[] { "message.exploded" }, new[] { "message.delivered", "nope" } })
        {
            Reply r = await _a.PostAsync("/api/v1/webhooks", new { url = "https://hooks.example.com/x", event_types = types });
            r.Problem(HttpStatusCode.BadRequest, "validation_failed");
            Assert.Equal(["event_types"], r.ErrorFields);
        }

        Assert.Equal(HttpStatusCode.Created, (await _a.PostAsync("/api/v1/webhooks", new { url = "https://hooks.example.com/x", event_types = new[] { "*" } })).Status);
        Assert.Equal(HttpStatusCode.Created, (await _a.PostAsync("/api/v1/webhooks", new { url = "https://hooks.example.com/y", event_types = new[] { "webhook.test", "message.complained", "webhook.endpoint.disabled" } })).Status);
        (await _a.PostAsync("/api/v1/webhooks", new { url = "https://hooks.example.com/x" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task Updating_changes_the_url_events_and_enabled_state()
    {
        JsonElement w = await CreateAsync();
        string id = w.GetProperty("id").GetString()!;

        Reply patched = await _a.PatchAsync("/api/v1/webhooks/" + id, new { url = "https://new.acme.example/hook", event_types = new[] { "message.complained" } });
        Assert.Equal("https://new.acme.example/hook", patched.Str("url"));
        Assert.Equal(["message.complained"], patched["event_types"].EnumerateArray().Select(e => e.GetString()!));

        Reply off = await _a.PatchAsync("/api/v1/webhooks/" + id, new { enabled = false });
        Assert.False(off["enabled"].GetBoolean());
        Assert.NotEqual(JsonValueKind.Null, off["disabledReason"].ValueKind);
        Assert.Equal("https://new.acme.example/hook", off.Str("url")); // untouched members stay

        Reply on = await _a.PatchAsync("/api/v1/webhooks/" + id, new { enabled = true });
        Assert.True(on["enabled"].GetBoolean());
        Assert.Equal(JsonValueKind.Null, on["disabledReason"].ValueKind);

        (await _a.PatchAsync("/api/v1/webhooks/" + id, new { url = "http://insecure.example.com" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _a.PatchAsync("/api/v1/webhooks/" + id, new { secret = "x" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["whsec_"], (await StoredSecretsAsync(id)).Select(s => s[..6]));
    }

    [Fact]
    public async Task Deleting_removes_the_endpoint()
    {
        string id = (await CreateAsync()).GetProperty("id").GetString()!;
        Assert.Equal(HttpStatusCode.NoContent, (await _a.DeleteAsync("/api/v1/webhooks/" + id)).Status);
        (await _a.GetAsync("/api/v1/webhooks/" + id)).Problem(HttpStatusCode.NotFound, "not_found");
        Assert.Empty((await _a.GetAsync("/api/v1/webhooks")).Json.EnumerateArray());
    }

    [Fact]
    public async Task Rotating_keeps_the_old_secret_signing_until_it_is_removed()
    {
        JsonElement w = await CreateAsync();
        string id = w.GetProperty("id").GetString()!;
        string first = w.GetProperty("secret").GetString()!;

        Reply rotated = await _a.PostAsync($"/api/v1/webhooks/{id}/rotate-secret");
        Assert.Equal(HttpStatusCode.OK, rotated.Status);
        string second = rotated.Str("secret");
        Assert.NotEqual(first, second);
        Assert.True(rotated["secretRotationPending"].GetBoolean());
        Assert.Equal([second, first], await StoredSecretsAsync(id));
        Assert.True((await _a.GetAsync("/api/v1/webhooks/" + id))["secretRotationPending"].GetBoolean());

        // A receiver that still verifies with the old secret (or already with the new one) accepts the signature header.
        string[] signing = await StoredSecretsAsync(id);
        byte[] payload = "{}"u8.ToArray();
        string header = StandardWebhooksSigner.Sign("msg_1", _f.Clock.UtcNow.ToUnixTimeSeconds(), payload, signing);
        Assert.True(StandardWebhooksSigner.Verify("msg_1", _f.Clock.UtcNow.ToUnixTimeSeconds().ToString(), header, payload, [first], _f.Clock.UtcNow));
        Assert.True(StandardWebhooksSigner.Verify("msg_1", _f.Clock.UtcNow.ToUnixTimeSeconds().ToString(), header, payload, [second], _f.Clock.UtcNow));

        // Rotating again drops the secret that is older than the previous one: two sign at most.
        Reply again = await _a.PostAsync($"/api/v1/webhooks/{id}/rotate-secret");
        string third = again.Str("secret");
        Assert.Equal([third, second], await StoredSecretsAsync(id));

        Assert.Equal(HttpStatusCode.NoContent, (await _a.DeleteAsync($"/api/v1/webhooks/{id}/previous-secret")).Status);
        Assert.Equal([third], await StoredSecretsAsync(id));
        Assert.False((await _a.GetAsync("/api/v1/webhooks/" + id))["secretRotationPending"].GetBoolean());
        (await _a.DeleteAsync($"/api/v1/webhooks/{id}/previous-secret")).Problem(HttpStatusCode.NotFound, "not_found");
    }

    [Fact]
    public async Task A_test_event_goes_to_that_endpoint_whatever_it_subscribes_to()
    {
        string id = (await CreateAsync(events: "message.bounced")).GetProperty("id").GetString()!;
        await CreateAsync("https://other.acme.example/hook", events: "*");

        Reply r = await _a.PostAsync($"/api/v1/webhooks/{id}/test");
        Assert.Equal(HttpStatusCode.Accepted, r.Status);
        Guid outboxId = Guid.Parse(r.Str("outboxId"));

        var due = await _f.Storage.Webhooks.ClaimDueAsync("t", 10, _f.Clock.UtcNow, TimeSpan.FromMinutes(1), default);
        WebhookOutboxItem item = Assert.Single(due);
        Assert.Equal(outboxId, item.Id);
        Assert.Equal(Guid.Parse(id), item.EndpointId);
        Assert.Equal("webhook.test", item.EventType);
        using JsonDocument payload = JsonDocument.Parse(item.PayloadJson);
        Assert.Equal("webhook.test", payload.RootElement.GetProperty("type").GetString());
        Assert.StartsWith("evt_", payload.RootElement.GetProperty("id").GetString());
        Assert.Equal(id, payload.RootElement.GetProperty("data").GetProperty("endpoint_id").GetString());
    }

    [Fact]
    public async Task A_disabled_endpoint_cannot_be_tested()
    {
        string id = (await CreateAsync()).GetProperty("id").GetString()!;
        await _a.PatchAsync("/api/v1/webhooks/" + id, new { enabled = false });
        (await _a.PostAsync($"/api/v1/webhooks/{id}/test")).Problem(HttpStatusCode.Conflict, "conflict");
    }

    [Fact]
    public async Task Attempts_and_replay_follow_the_outbox()
    {
        string id = (await CreateAsync()).GetProperty("id").GetString()!;
        Guid outboxId = Guid.Parse((await _a.PostAsync($"/api/v1/webhooks/{id}/test")).Str("outboxId"));
        Assert.Empty((await _a.GetAsync($"/api/v1/webhooks/{id}/attempts")).Json.EnumerateArray());
        (await _a.PostAsync($"/api/v1/webhook-events/{outboxId:N}/replay")).Problem(HttpStatusCode.NotFound, "not_found"); // still pending

        var item = (await _f.Storage.Webhooks.ClaimDueAsync("t", 10, _f.Clock.UtcNow, TimeSpan.FromMinutes(1), default)).Single();
        await _f.Storage.Webhooks.CompleteAsync(item.Id, new WebhookAttemptRecord(item.Id, _f.Clock.UtcNow, 500, TimeSpan.FromMilliseconds(1210), "http_5xx", "<html>Internal Server Error</html>"), WebhookOutboxState.Failed, null, default);
        _f.Clock.Advance(TimeSpan.FromMinutes(1));
        await _f.Storage.Webhooks.CompleteAsync(item.Id, new WebhookAttemptRecord(item.Id, _f.Clock.UtcNow, 200, TimeSpan.FromMilliseconds(80), null, "ok"), WebhookOutboxState.Delivered, null, default);

        Reply attempts = await _a.GetAsync($"/api/v1/webhooks/{id}/attempts");
        JsonElement[] list = attempts.Json.EnumerateArray().ToArray();
        Assert.Equal(2, list.Length);
        Assert.Equal([200, 500], list.Select(a => a.GetProperty("status").GetInt32()));
        JsonElement newest = list[0];
        Assert.Equal(outboxId.ToString("N"), newest.GetProperty("outboxId").GetString());
        Assert.Equal(80, newest.GetProperty("durationMs").GetInt64());
        Assert.Equal("ok", newest.GetProperty("snippet").GetString());
        Assert.Equal(JsonValueKind.Null, newest.GetProperty("errorClass").ValueKind);
        Assert.Equal("http_5xx", list[1].GetProperty("errorClass").GetString());
        Assert.NotEqual(list[0].GetProperty("id").GetString(), list[1].GetProperty("id").GetString());
        Assert.Single((await _a.GetAsync($"/api/v1/webhooks/{id}/attempts?limit=1")).Json.EnumerateArray());
        (await _a.GetAsync($"/api/v1/webhooks/{id}/attempts?limit=500")).Problem(HttpStatusCode.BadRequest, "validation_failed");

        Reply replay = await _a.PostAsync($"/api/v1/webhook-events/{outboxId:N}/replay");
        Assert.Equal(HttpStatusCode.Accepted, replay.Status);
        Assert.Equal(outboxId.ToString("N"), replay.Str("outboxId"));
        Assert.Single(await _f.Storage.Webhooks.ClaimDueAsync("t", 10, _f.Clock.UtcNow, TimeSpan.FromMinutes(1), default));
        (await _a.PostAsync($"/api/v1/webhook-events/{Guid.NewGuid():N}/replay")).Problem(HttpStatusCode.NotFound, "not_found");
    }

    [Fact]
    public async Task Webhooks_are_isolated_per_tenant()
    {
        ApiClient b = await _f.KeyClientAsync(ApiFixture.TenantBId);
        string idB = (await CreateAsync("https://hooks.globex.example/x", b)).GetProperty("id").GetString()!;
        await CreateAsync();

        Assert.Equal(1, (await _a.GetAsync("/api/v1/webhooks")).Json.GetArrayLength());
        (await _a.GetAsync("/api/v1/webhooks/" + idB)).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.PatchAsync("/api/v1/webhooks/" + idB, new { enabled = false })).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.PostAsync($"/api/v1/webhooks/{idB}/rotate-secret")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.DeleteAsync($"/api/v1/webhooks/{idB}/previous-secret")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.PostAsync($"/api/v1/webhooks/{idB}/test")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.GetAsync($"/api/v1/webhooks/{idB}/attempts")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.DeleteAsync("/api/v1/webhooks/" + idB)).Problem(HttpStatusCode.NotFound, "not_found");

        // B's endpoint is untouched.
        var stored = (await _f.Storage.Config.GetWebhookEndpointAsync(Guid.Parse(idB), default))!;
        Assert.True(stored.Enabled);
        Assert.Single(await StoredSecretsAsync(idB));

        // B's outbox event cannot be replayed by A.
        Guid outboxB = Guid.Parse((await b.PostAsync($"/api/v1/webhooks/{idB}/test")).Str("outboxId"));
        var item = (await _f.Storage.Webhooks.ClaimDueAsync("t", 10, _f.Clock.UtcNow, TimeSpan.FromMinutes(1), default)).Single(i => i.Id == outboxB);
        await _f.Storage.Webhooks.CompleteAsync(item.Id, new WebhookAttemptRecord(item.Id, _f.Clock.UtcNow, 200, TimeSpan.FromMilliseconds(5), null, null), WebhookOutboxState.Delivered, null, default);
        (await _a.PostAsync($"/api/v1/webhook-events/{outboxB:N}/replay")).Problem(HttpStatusCode.NotFound, "not_found");
    }

    [Fact]
    public async Task The_number_of_endpoints_is_limited_and_the_scope_is_required()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.MaxWebhooksPerTenant = 1 });
        ApiClient c = await f.KeyClientAsync(ApiFixture.TenantAId);
        await CreateAsync("https://one.example.com/x", c);
        (await c.PostAsync("/api/v1/webhooks", new { url = "https://two.example.com/x", event_types = new[] { "*" } })).Problem(HttpStatusCode.BadRequest, "validation_failed");

        ApiClient noScope = await _f.KeyClientAsync(ApiFixture.TenantAId, "read", "send");
        (await noScope.GetAsync("/api/v1/webhooks")).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await noScope.PostAsync("/api/v1/webhook-events/" + Guid.NewGuid().ToString("N") + "/replay")).Problem(HttpStatusCode.Forbidden, "forbidden");
    }

    [Fact]
    public async Task Webhook_endpoints_work_on_sqlite()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { Sqlite = true });
        ApiClient c = await f.KeyClientAsync(ApiFixture.TenantAId);
        JsonElement w = await CreateAsync("https://disk.example.com/x", c);
        string id = w.GetProperty("id").GetString()!;
        Reply test = await c.PostAsync($"/api/v1/webhooks/{id}/test");
        Assert.Equal(HttpStatusCode.Accepted, test.Status);
        var item = Assert.Single(await f.Storage.Webhooks.ClaimDueAsync("t", 10, f.Clock.UtcNow, TimeSpan.FromMinutes(1), default));
        Assert.Equal("webhook.test", item.EventType);
        Assert.Equal(HttpStatusCode.OK, (await c.PostAsync($"/api/v1/webhooks/{id}/rotate-secret")).Status);
    }
}
