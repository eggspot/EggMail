using System.Net;
using System.Text.Json;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Security;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

public class ApiCredentialsTests : IAsyncLifetime
{
    private ApiFixture _f = null!;
    private ApiClient _a = null!;

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync();
        _a = await _f.KeyClientAsync(ApiFixture.TenantAId);
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    // API keys

    [Fact]
    public async Task A_created_key_is_shown_once_and_works_immediately()
    {
        Reply created = await _a.PostAsync("/api/v1/api-keys", new { name = "Reporting", scopes = new[] { "suppressions", "read" } });
        Assert.Equal(HttpStatusCode.Created, created.Status);
        string key = created.Str("key");
        Assert.StartsWith("egm_", key);
        Assert.True(ApiKeys.LooksLikeKey(key));
        Assert.Equal(key[..12], created.Str("prefix"));
        Assert.Equal("Reporting", created.Str("name"));
        Assert.Equal(["read", "suppressions"], created["scopes"].EnumerateArray().Select(s => s.GetString()!)); // in the documented order
        Assert.Equal(JsonValueKind.Null, created["lastUsedAt"].ValueKind);

        // Only the digest is stored.
        ApiKeyRecord stored = (await _f.Storage.Config.FindApiKeyAsync(ApiKeys.Digest(key), default))!;
        Assert.Equal(ApiFixture.TenantAId, stored.TenantId);
        Assert.Equal("read,suppressions", stored.Scopes);
        Assert.DoesNotContain(key, (await _a.GetAsync("/api/v1/api-keys")).Body);

        Reply me = await _f.NewClient().WithBearer(key).GetAsync("/api/v1/me");
        Assert.Equal("Reporting", me.Str("user"));
    }

    [Fact]
    public async Task Listing_hides_revoked_keys_and_revoking_is_per_tenant()
    {
        Reply k = await _a.PostAsync("/api/v1/api-keys", new { name = "Temp", scopes = new[] { "read" } });
        string id = k.Str("id");
        ApiClient b = await _f.KeyClientAsync(ApiFixture.TenantBId);
        (await b.DeleteAsync("/api/v1/api-keys/" + id)).Problem(HttpStatusCode.NotFound, "not_found");
        Assert.NotNull(await _f.Storage.Config.FindApiKeyAsync(ApiKeys.Digest(k.Str("key")), default));
        Assert.Equal(HttpStatusCode.OK, (await _f.NewClient().WithBearer(k.Str("key")).GetAsync("/api/v1/messages")).Status);

        Assert.Equal(HttpStatusCode.NoContent, (await _a.DeleteAsync("/api/v1/api-keys/" + id)).Status);
        (await _a.DeleteAsync("/api/v1/api-keys/" + id)).Problem(HttpStatusCode.NotFound, "not_found");
        Assert.DoesNotContain(id, (await _a.GetAsync("/api/v1/api-keys")).Body);
        (await _f.NewClient().WithBearer(k.Str("key")).GetAsync("/api/v1/messages")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        Assert.DoesNotContain((await b.GetAsync("/api/v1/api-keys")).Json.EnumerateArray(), x => x.GetProperty("id").GetString() == id);
    }

    [Fact]
    public async Task Key_creation_is_validated()
    {
        Reply r = await _a.PostAsync("/api/v1/api-keys", new { name = "", scopes = new string[0] });
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["name", "scopes"], r.ErrorFields);
        (await _a.PostAsync("/api/v1/api-keys", new { name = "x", scopes = new[] { "root" } })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _a.PostAsync("/api/v1/api-keys", new { name = new string('n', 81), scopes = new[] { "read" } })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task A_key_can_only_create_keys_with_its_own_scopes()
    {
        ApiClient limited = await _f.KeyClientAsync(ApiFixture.TenantAId, "keys", "read");
        Reply tooMuch = await limited.PostAsync("/api/v1/api-keys", new { name = "escalate", scopes = new[] { "read", "send" } });
        tooMuch.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains("scopes", tooMuch.ErrorFields);
        Assert.Equal(HttpStatusCode.Created, (await limited.PostAsync("/api/v1/api-keys", new { name = "ok", scopes = new[] { "read" } })).Status);

        // A signed-in user holds every scope.
        ApiClient alice = await _f.SignedInAsync("alice");
        Assert.Equal(HttpStatusCode.Created, (await alice.PostAsync("/api/v1/api-keys", new { name = "all", scopes = ApiScopes.All })).Status);
    }

    [Fact]
    public async Task The_number_of_active_keys_is_limited()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.MaxApiKeysPerTenant = 2 });
        ApiClient c = await f.KeyClientAsync(ApiFixture.TenantAId); // uses one
        Assert.Equal(HttpStatusCode.Created, (await c.PostAsync("/api/v1/api-keys", new { name = "two", scopes = new[] { "read" } })).Status);
        (await c.PostAsync("/api/v1/api-keys", new { name = "three", scopes = new[] { "read" } })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task Credentials_need_the_keys_scope()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId, "read", "send", "domains");
        foreach (string path in new[] { "/api/v1/api-keys", "/api/v1/smtp-credentials" })
        {
            (await c.GetAsync(path)).Problem(HttpStatusCode.Forbidden, "forbidden");
        }
    }

    // SMTP credentials

    [Fact]
    public async Task An_smtp_credential_is_created_with_a_generated_password_that_is_stored_hashed()
    {
        Reply created = await _a.PostAsync("/api/v1/smtp-credentials", new { username = "app-mailer" });
        Assert.Equal(HttpStatusCode.Created, created.Status);
        string password = created.Str("password");
        Assert.True(password.Length >= 24);
        Assert.Equal("app-mailer", created.Str("username"));

        SmtpCredential stored = (await _f.Storage.Config.FindSmtpCredentialAsync("app-mailer", default))!;
        Assert.Equal(ApiFixture.TenantAId, stored.TenantId);
        Assert.True(stored.Enabled);
        Assert.DoesNotContain(password, stored.PasswordHash);
        Assert.True(PasswordHasher.Verify(password, stored.PasswordHash));
        Assert.False(PasswordHasher.Verify(password + "x", stored.PasswordHash));

        Reply list = await _a.GetAsync("/api/v1/smtp-credentials");
        Assert.Equal(["app-mailer"], list.Json.EnumerateArray().Select(c => c.GetProperty("username").GetString()!));
        Assert.DoesNotContain(password, list.Body);
        Assert.DoesNotContain("pbkdf2", list.Body);
    }

    [Theory]
    [InlineData("")]
    [InlineData("ab")]
    [InlineData("has space")]
    [InlineData("semi;colon")]
    public async Task Smtp_user_names_are_validated(string username)
    {
        (await _a.PostAsync("/api/v1/smtp-credentials", new { username })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task Smtp_user_names_are_unique_across_the_server_and_credentials_are_deleted_per_tenant()
    {
        Reply mine = await _a.PostAsync("/api/v1/smtp-credentials", new { username = "shared-name" });
        ApiClient b = await _f.KeyClientAsync(ApiFixture.TenantBId);
        (await b.PostAsync("/api/v1/smtp-credentials", new { username = "shared-name" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _a.PostAsync("/api/v1/smtp-credentials", new { username = "shared-name" })).Problem(HttpStatusCode.BadRequest, "validation_failed");

        string id = mine.Str("id");
        (await b.DeleteAsync("/api/v1/smtp-credentials/" + id)).Problem(HttpStatusCode.NotFound, "not_found");
        Assert.NotNull(await _f.Storage.Config.FindSmtpCredentialAsync("shared-name", default));
        Assert.Empty((await b.GetAsync("/api/v1/smtp-credentials")).Json.EnumerateArray());

        Assert.Equal(HttpStatusCode.NoContent, (await _a.DeleteAsync("/api/v1/smtp-credentials/" + id)).Status);
        Assert.Null(await _f.Storage.Config.FindSmtpCredentialAsync("shared-name", default));
        (await _a.DeleteAsync("/api/v1/smtp-credentials/" + id)).Problem(HttpStatusCode.NotFound, "not_found");
    }
}

public class ApiStatsTests : IAsyncLifetime
{
    private ApiFixture _f = null!;
    private ApiClient _a = null!;

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync();
        _a = await _f.KeyClientAsync(ApiFixture.TenantAId);
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private async Task SeedAsync()
    {
        DateTimeOffset hour = Mta.Storage.Logic.StorageTime.HourStart(_f.Clock.UtcNow);
        _f.Storage.Stats.Add(new StatKey(hour, ApiFixture.TenantAId, "example.com", "gmail.com"), StatCounter.Accepted, 10);
        _f.Storage.Stats.Add(new StatKey(hour, ApiFixture.TenantAId, "example.com", "gmail.com"), StatCounter.Delivered, 8);
        _f.Storage.Stats.Add(new StatKey(hour, ApiFixture.TenantAId, "example.com", "gmail.com"), StatCounter.HardBounce, 1);
        _f.Storage.Stats.Add(new StatKey(hour, ApiFixture.TenantAId, "mail.example.com", "outlook.com"), StatCounter.Accepted, 3);
        _f.Storage.Stats.Add(new StatKey(hour, ApiFixture.TenantBId, "globex.test", "gmail.com"), StatCounter.Accepted, 99);
        await _f.Storage.Stats.FlushAsync(default);
    }

    [Fact]
    public async Task Statistics_rows_have_the_documented_shape_and_only_the_tenants_data()
    {
        await SeedAsync();
        Reply r = await _a.GetAsync("/api/v1/stats");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("hour", r.Str("granularity"));
        JsonElement[] rows = r["rows"].EnumerateArray().ToArray();
        Assert.Equal(2, rows.Length);
        JsonElement gmail = rows.Single(x => x.GetProperty("recipientDomain").GetString() == "gmail.com");
        Assert.Equal("2026-10-12T12:00:00.000Z", gmail.GetProperty("period").GetString());
        Assert.Equal("example.com", gmail.GetProperty("sendingDomain").GetString());
        Assert.Equal(10, gmail.GetProperty("accepted").GetInt64());
        Assert.Equal(8, gmail.GetProperty("delivered").GetInt64());
        Assert.Equal(1, gmail.GetProperty("hardBounce").GetInt64());
        foreach (string counter in new[] { "deferred", "softBounce", "expired", "complained", "rejected", "suppressed" })
        {
            Assert.Equal(0, gmail.GetProperty(counter).GetInt64());
        }

        Assert.DoesNotContain("globex.test", r.Body);
        Assert.DoesNotContain("99", r["rows"].EnumerateArray().Select(x => x.GetProperty("accepted").GetInt64().ToString()));
    }

    [Fact]
    public async Task Statistics_can_be_filtered_by_sending_domain_and_range()
    {
        await SeedAsync();
        Reply byDomain = await _a.GetAsync("/api/v1/stats?domain=mail.example.com");
        Assert.Equal(["outlook.com"], byDomain["rows"].EnumerateArray().Select(x => x.GetProperty("recipientDomain").GetString()!));

        string from = Uri.EscapeDataString(_f.Clock.UtcNow.AddHours(1).ToString("O"));
        Assert.Equal(0, (await _a.GetAsync($"/api/v1/stats?from={from}&to={Uri.EscapeDataString(_f.Clock.UtcNow.AddHours(3).ToString("O"))}"))["rows"].GetArrayLength());

        Reply day = await _a.GetAsync("/api/v1/stats?granularity=day");
        Assert.Equal("day", day.Str("granularity"));
        Assert.Equal(JsonValueKind.Array, day["rows"].ValueKind);
    }

    [Fact]
    public async Task Bad_statistics_parameters_are_validation_failed()
    {
        Reply r = await _a.GetAsync("/api/v1/stats?granularity=week&from=never");
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["granularity", "from"], r.ErrorFields);

        string to = Uri.EscapeDataString(_f.Clock.UtcNow.ToString("O"));
        string later = Uri.EscapeDataString(_f.Clock.UtcNow.AddDays(1).ToString("O"));
        (await _a.GetAsync($"/api/v1/stats?from={later}&to={to}")).Problem(HttpStatusCode.BadRequest, "validation_failed");
        string wide = Uri.EscapeDataString(_f.Clock.UtcNow.AddDays(-90).ToString("O"));
        (await _a.GetAsync($"/api/v1/stats?from={wide}&to={to}")).Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(HttpStatusCode.OK, (await _a.GetAsync($"/api/v1/stats?granularity=day&from={wide}&to={to}")).Status);
    }

    [Fact]
    public async Task Too_many_rows_ask_for_a_narrower_range()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.MaxStatsRows = 2 });
        DateTimeOffset hour = Mta.Storage.Logic.StorageTime.HourStart(f.Clock.UtcNow);
        for (int i = 0; i < 3; i++)
        {
            f.Storage.Stats.Add(new StatKey(hour, ApiFixture.TenantAId, "example.com", $"d{i}.test"), StatCounter.Accepted, 1);
        }

        await f.Storage.Stats.FlushAsync(default);
        ApiClient c = await f.KeyClientAsync(ApiFixture.TenantAId);
        (await c.GetAsync("/api/v1/stats")).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task The_recent_events_ring_is_content_free_and_per_tenant()
    {
        ApiClient send = await _f.KeyClientAsync(ApiFixture.TenantAId);
        await send.PostAsync("/api/v1/messages", new { from = "a@example.com", to = new[] { "x@gmail.test" }, subject = "s", text = "t" });
        foreach (ClaimedDelivery d in await _f.Storage.Deliveries.ClaimAsync("t", 10, _f.Clock.UtcNow, TimeSpan.FromMinutes(1), default))
        {
            await _f.Storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = _f.Clock.UtcNow, SmtpCode = 250 }, default);
        }

        await _f.Storage.Stats.FlushAsync(default);
        Reply r = await _a.GetAsync("/api/v1/stats/recent-events?limit=10");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        JsonElement e = Assert.Single(r.Json.EnumerateArray());
        Assert.Equal("delivered", e.GetProperty("type").GetString());
        Assert.Equal("gmail.test", e.GetProperty("recipientDomain").GetString());
        Assert.Equal(ApiFixture.TenantAId.ToString("N"), e.GetProperty("tenantId").GetString());
        Assert.DoesNotContain("x@gmail.test", r.Body); // recipient domain only

        ApiClient b = await _f.KeyClientAsync(ApiFixture.TenantBId);
        Assert.Empty((await b.GetAsync("/api/v1/stats/recent-events")).Json.EnumerateArray());
        (await _a.GetAsync("/api/v1/stats/recent-events?limit=0")).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task Statistics_need_the_read_scope()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId, "send");
        (await c.GetAsync("/api/v1/stats")).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await c.GetAsync("/api/v1/stats/recent-events")).Problem(HttpStatusCode.Forbidden, "forbidden");
    }
}

public class ApiTenantSettingsTests : IAsyncLifetime
{
    private ApiFixture _f = null!;

    public async Task InitializeAsync() => _f = await ApiFixture.StartAsync();

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private static JsonElement Item(Reply r, string key) => r["items"].EnumerateArray().Single(i => i.GetProperty("key").GetString() == key);

    [Fact]
    public async Task Settings_list_the_catalog_with_types_and_locks()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        Reply r = await alice.GetAsync("/api/v1/settings");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        JsonElement store = Item(r, "Content:StoreAttachments");
        Assert.Equal("boolean", store.GetProperty("type").GetString());
        Assert.False(store.GetProperty("value").GetBoolean());
        Assert.False(store.GetProperty("locked").GetBoolean());
        Assert.False(string.IsNullOrEmpty(store.GetProperty("description").GetString()));
        Assert.True(Item(r, "Smtp:MaxRecipients").GetProperty("locked").GetBoolean());
        Assert.Equal(50, Item(r, "Smtp:MaxRecipients").GetProperty("value").GetInt32());
        Assert.True(Item(r, "Webhooks:AllowedNetworks").GetProperty("locked").GetBoolean()); // admin-only for tenant users
    }

    [Fact]
    public async Task Storing_attachments_can_be_switched_on_per_tenant_and_changes_what_a_send_retains()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        Reply put = await alice.PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { ["Content:StoreAttachments"] = true } });
        Assert.Equal(HttpStatusCode.OK, put.Status);
        Assert.True(Item(put, "Content:StoreAttachments").GetProperty("value").GetBoolean());
        Assert.True((await _f.Storage.Config.GetTenantAsync(ApiFixture.TenantAId, default))!.StoreAttachments);
        Assert.False((await _f.Storage.Config.GetTenantAsync(ApiFixture.TenantBId, default))!.StoreAttachments);

        ApiClient key = await _f.KeyClientAsync(ApiFixture.TenantAId);
        Reply sent = await key.PostAsync("/api/v1/messages", new
        {
            from = "a@example.com",
            to = new[] { "x@gmail.test" },
            subject = "s",
            text = "t",
            attachments = new[] { new { filename = "a.bin", content_type = "application/octet-stream", content = Convert.ToBase64String([1, 2, 3]) } },
        });
        foreach (ClaimedDelivery d in await _f.Storage.Deliveries.ClaimAsync("t", 10, _f.Clock.UtcNow, TimeSpan.FromMinutes(1), default))
        {
            await _f.Storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = _f.Clock.UtcNow, SmtpCode = 250 }, default);
        }

        Assert.True((await key.GetAsync("/api/v1/messages/" + sent.Str("id")))["rawRetained"].GetBoolean());
    }

    [Fact]
    public async Task Attachment_storage_is_locked_when_the_operator_has_not_allowed_it()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { AllowAttachmentStorage = false });
        ApiClient alice = await f.SignedInAsync("alice");
        Assert.True(Item(await alice.GetAsync("/api/v1/settings"), "Content:StoreAttachments").GetProperty("locked").GetBoolean());
        (await alice.PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { ["Content:StoreAttachments"] = true } })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task Invalid_updates_name_the_setting()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        Reply r = await alice.PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { ["Nope"] = 1, ["Content:StoreAttachments"] = "yes", ["Smtp:MaxRecipients"] = 10 } });
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["Nope", "Content:StoreAttachments", "Smtp:MaxRecipients"], r.ErrorFields);
        Assert.False((await _f.Storage.Config.GetTenantAsync(ApiFixture.TenantAId, default))!.StoreAttachments);
        (await alice.PutAsync("/api/v1/settings", new { })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await alice.PutAsync("/api/v1/settings", new { values = new { }, extra = 1 })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task Api_keys_can_read_but_never_change_settings()
    {
        ApiClient key = await _f.KeyClientAsync(ApiFixture.TenantAId);
        Assert.Equal(HttpStatusCode.OK, (await key.GetAsync("/api/v1/settings")).Status);
        (await key.PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { ["Content:StoreAttachments"] = true } })).Problem(HttpStatusCode.Forbidden, "forbidden");
    }

    [Fact]
    public async Task Settings_belong_to_the_acting_tenant()
    {
        ApiClient admin = await _f.SignedInAsync("root");
        (await admin.GetAsync("/api/v1/settings")).Problem(HttpStatusCode.BadRequest, "validation_failed");
        admin.TenantId = ApiFixture.TenantBId;
        await admin.PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { ["Content:StoreAttachments"] = true } });
        Assert.True((await _f.Storage.Config.GetTenantAsync(ApiFixture.TenantBId, default))!.StoreAttachments);
        Assert.False((await _f.Storage.Config.GetTenantAsync(ApiFixture.TenantAId, default))!.StoreAttachments);
    }
}
