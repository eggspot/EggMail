using System.Net;
using System.Text;
using System.Text.Json;
using Mta.Core;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

/// <summary>Inbound mail over the HTTP API (decision 95): settings, routes, received messages, authorization and tenant isolation.</summary>
[Collection("api")]
public class ApiInboundTests : IAsyncLifetime
{
    private ApiFixture _f = null!;
    private ApiClient _a = null!;
    private ApiClient _b = null!;
    private DomainRecord _domainA = null!;
    private string _base = "";

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync();
        _a = await _f.KeyClientAsync(ApiFixture.TenantAId);
        _b = await _f.KeyClientAsync(ApiFixture.TenantBId);
        _domainA = (await _f.Storage.Config.GetDomainsAsync(ApiFixture.TenantAId, default)).Single();
        _base = $"/api/v1/domains/{_domainA.Id:N}/inbound";
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private async Task<Guid> EndpointAsync(Guid tenant)
    {
        var endpoint = new WebhookEndpointRecord(Ids.New(), tenant, "https://hooks.example.com/in", [1, 2, 3], ["*"], true, null, null, _f.Clock.UtcNow, null);
        await _f.Storage.Config.UpsertWebhookEndpointAsync(endpoint, default);
        return endpoint.Id;
    }

    private async Task EnableAsync() => Assert.Equal(HttpStatusCode.OK, (await _a.PatchAsync(_base, new { enabled = true })).Status);

    private static object CatchAll(string action = "store") => new { name = "rest", order = 1000, match = new { kind = "catch_all" }, action = new { kind = action } };

    // Settings

    [Fact]
    public async Task A_domain_that_was_never_configured_has_inbound_off_and_shows_the_server_defaults()
    {
        Reply r = await _a.GetAsync(_base);

        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.False(r["enabled"].GetBoolean());
        Assert.Equal("record_only", r.Str("dmarcAction"));
        Assert.Equal(JsonValueKind.Null, r["maxStoredBytes"].ValueKind);
        Assert.Equal(JsonValueKind.Null, r["updatedAt"].ValueKind);
        Assert.Equal(7, r["effective"].GetProperty("retentionDays").GetInt32());
        Assert.Equal(600, r["effective"].GetProperty("maxMessagesPerMinute").GetInt32());
        Assert.Equal(25L * 1024 * 1024, r["effective"].GetProperty("maxMessageBytes").GetInt64());
        Assert.Equal(10, r["mx"].GetProperty("priority").GetInt32());
        Assert.False(r.Json.TryGetProperty("warnings", out _));
    }

    [Fact]
    public async Task Settings_are_patched_member_by_member_and_null_resets_a_limit()
    {
        Reply first = await _a.PatchAsync(_base, new Dictionary<string, object?> { ["enabled"] = true, ["dmarcAction"] = "quarantine_flag", ["maxMessageBytes"] = 1_000_000, ["retentionDays"] = 30, ["maxMessagesPerMinute"] = 5 });
        Assert.Equal(HttpStatusCode.OK, first.Status);
        Assert.True(first["enabled"].GetBoolean());
        Assert.Equal("quarantine_flag", first.Str("dmarcAction"));
        Assert.Equal(1_000_000, first["maxMessageBytes"].GetInt64());
        Assert.Equal(30, first["effective"].GetProperty("retentionDays").GetInt32());
        Assert.Equal(1_000_000, first["effective"].GetProperty("maxMessageBytes").GetInt64());
        Assert.Equal("2026-10-12T12:30:00.000Z", first.Str("updatedAt"));

        // Absent members stay, null resets.
        Reply second = await _a.PatchAsync(_base, new Dictionary<string, object?> { ["retentionDays"] = null, ["maxMessagesPerMinute"] = 9 });
        Assert.True(second["enabled"].GetBoolean());
        Assert.Equal(1_000_000, second["maxMessageBytes"].GetInt64());
        Assert.Equal(JsonValueKind.Null, second["retentionDays"].ValueKind);
        Assert.Equal(7, second["effective"].GetProperty("retentionDays").GetInt32());
        Assert.Equal(9, second["maxMessagesPerMinute"].GetInt32());

        Assert.Equal(second.Json.GetRawText(), (await _a.GetAsync(_base)).Json.GetRawText());
    }

    [Fact]
    public async Task Keeping_forever_is_zero_and_comes_with_a_warning()
    {
        Reply r = await _a.PatchAsync(_base, new { retentionDays = 0 });

        Assert.Equal(0, r["retentionDays"].GetInt32());
        Assert.Equal("retention_unlimited", r["warnings"][0].GetProperty("code").GetString());
        Assert.Equal("retention_unlimited", (await _a.GetAsync(_base))["warnings"][0].GetProperty("code").GetString());
    }

    [Theory]
    [InlineData("dmarcAction", "burn", "dmarcAction")]
    [InlineData("maxMessageBytes", 10, "maxMessageBytes")]
    [InlineData("maxMessagesPerMinute", 0, "maxMessagesPerMinute")]
    [InlineData("maxMessagesPerMinutePerRemote", 20000, "maxMessagesPerMinutePerRemote")]
    [InlineData("maxStoredBytes", 5, "maxStoredBytes")]
    [InlineData("retentionDays", -1, "retentionDays")]
    [InlineData("retentionDays", 100000, "retentionDays")]
    [InlineData("retentionDays", "seven", "retentionDays")]
    [InlineData("maxMessagesPerMinute", 3_000_000_000, "maxMessagesPerMinute")]
    public async Task Invalid_settings_are_refused_with_the_field_name(string member, object value, string field)
    {
        Reply r = await _a.PatchAsync(_base, new Dictionary<string, object?> { [member] = value });

        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal([field], r.ErrorFields);
        Assert.Null(await _f.Storage.Inbound.GetSettingsAsync(_domainA.Id, default));
    }

    [Fact]
    public async Task Unknown_members_are_refused()
    {
        (await _a.PatchAsync(_base, new { enabled = true, bogus = 1 })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Theory]
    [InlineData(DomainStatus.Pending)]
    [InlineData(DomainStatus.Verifying)]
    [InlineData(DomainStatus.Failed)]
    public async Task A_domain_that_is_not_verified_cannot_receive_mail(DomainStatus status)
    {
        DomainRecord unverified = await _f.AddVerifiedDomainAsync(ApiFixture.TenantAId, "pending.example", status);

        Reply r = await _a.PatchAsync($"/api/v1/domains/{unverified.Id:N}/inbound", new { enabled = true });

        r.Problem(HttpStatusCode.Forbidden, "domain_not_verified");
        Assert.Equal("inbound_domain_not_verified", r["reason"].GetString());
        Assert.Null(await _f.Storage.Inbound.GetSettingsAsync(unverified.Id, default));

        // Preparing the other settings is fine, and so is disabling.
        Assert.Equal(HttpStatusCode.OK, (await _a.PatchAsync($"/api/v1/domains/{unverified.Id:N}/inbound", new { retentionDays = 3 })).Status);
        Assert.Equal(HttpStatusCode.OK, (await _a.PatchAsync($"/api/v1/domains/{unverified.Id:N}/inbound", new { enabled = false })).Status);
    }

    [Fact]
    public async Task A_domain_in_temporary_failure_keeps_receiving()
    {
        DomainRecord shaky = await _f.AddVerifiedDomainAsync(ApiFixture.TenantAId, "shaky.example", DomainStatus.TemporaryFailure);

        Assert.True((await _a.PatchAsync($"/api/v1/domains/{shaky.Id:N}/inbound", new { enabled = true }))["enabled"].GetBoolean());
    }

    [Fact]
    public async Task Another_tenants_domain_is_not_found_and_a_key_needs_the_inbound_scope()
    {
        DomainRecord theirs = (await _f.Storage.Config.GetDomainsAsync(ApiFixture.TenantBId, default)).Single();
        (await _a.GetAsync($"/api/v1/domains/{theirs.Id:N}/inbound")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.PatchAsync($"/api/v1/domains/{theirs.Id:N}/inbound", new { enabled = true })).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.GetAsync($"/api/v1/domains/{theirs.Id:N}/inbound/routes")).Problem(HttpStatusCode.NotFound, "not_found");
        Assert.Null(await _f.Storage.Inbound.GetSettingsAsync(theirs.Id, default));

        ApiClient noScope = await _f.KeyClientAsync(ApiFixture.TenantAId, "read", "domains", "send");
        (await noScope.GetAsync(_base)).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await noScope.GetAsync("/api/v1/inbound/messages")).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await _f.NewClient().GetAsync(_base)).Problem(HttpStatusCode.Unauthorized, "unauthorized");
    }

    [Fact]
    public async Task A_key_can_be_created_with_the_inbound_scope()
    {
        ApiClient admin = await _f.SignedInAsync("alice");
        Reply r = await admin.PostAsync("/api/v1/api-keys", new { name = "inbox reader", scopes = new[] { "inbound" } });

        Assert.Equal(HttpStatusCode.Created, r.Status);
        Assert.Equal("inbound", r["scopes"][0].GetString());
        ApiClient reader = _f.NewClient().WithBearer(r.Str("key"));
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync(_base)).Status);
        (await reader.GetAsync("/api/v1/messages")).Problem(HttpStatusCode.Forbidden, "forbidden");
    }

    // Routes

    [Fact]
    public async Task Routes_are_created_listed_in_evaluation_order_changed_and_deleted()
    {
        Guid endpoint = await EndpointAsync(ApiFixture.TenantAId);
        Reply catchAll = await _a.PostAsync(_base + "/routes", CatchAll("discard"));
        Assert.Equal(HttpStatusCode.Created, catchAll.Status);
        Assert.Matches($"^{_base}/routes/[0-9a-f]{{32}}$", catchAll.Header("Location"));
        Assert.Equal("discard", catchAll["action"].GetProperty("kind").GetString());
        Assert.Equal("catch_all", catchAll["match"].GetProperty("kind").GetString());
        Assert.Equal(JsonValueKind.Null, catchAll["match"].GetProperty("localPart").ValueKind);

        Reply hook = await _a.PostAsync(_base + "/routes", new
        {
            name = "billing", order = 10, match = new { kind = "wildcard", localPart = "billing-*", plusAddressing = true },
            action = new { kind = "webhook", webhookEndpointId = endpoint.ToString("N"), webhookFormat = "raw_mime" },
        });
        Assert.Equal(HttpStatusCode.Created, hook.Status);
        Assert.Equal("raw_mime", hook["action"].GetProperty("webhookFormat").GetString());
        Assert.True(hook["match"].GetProperty("plusAddressing").GetBoolean());

        Reply forward = await _a.PostAsync(_base + "/routes", new { name = "support", order = 20, match = new { kind = "address", localPart = "support" }, action = new { kind = "forward", forwardTo = new[] { "a@example.org", "b@example.org" } } });
        Assert.Equal(HttpStatusCode.Created, forward.Status);
        Assert.Equal(["a@example.org", "b@example.org"], forward["action"].GetProperty("forwardTo").EnumerateArray().Select(e => e.GetString()!).ToArray());

        Reply list = await _a.GetAsync(_base + "/routes");
        Assert.Equal(["billing", "support", "rest"], list.Json.EnumerateArray().Select(e => e.GetProperty("name").GetString()!).ToArray());

        string id = hook.Str("id");
        Reply patched = await _a.PatchAsync($"{_base}/routes/{id}", new { name = "invoices", enabled = false, match = new { kind = "address", localPart = "invoices" } });
        Assert.Equal(HttpStatusCode.OK, patched.Status);
        Assert.Equal(("invoices", false, "address", "invoices"), (patched.Str("name"), patched["enabled"].GetBoolean(), patched["match"].GetProperty("kind").GetString()!, patched["match"].GetProperty("localPart").GetString()!));
        Assert.Equal(endpoint.ToString("N"), patched["action"].GetProperty("webhookEndpointId").GetString());   // the action was not in the request: unchanged
        Assert.Equal(10, patched["order"].GetInt32());

        Assert.Equal(patched.Json.GetRawText(), (await _a.GetAsync($"{_base}/routes/{id}")).Json.GetRawText());
        Assert.Equal(HttpStatusCode.NoContent, (await _a.DeleteAsync($"{_base}/routes/{id}")).Status);
        (await _a.GetAsync($"{_base}/routes/{id}")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.DeleteAsync($"{_base}/routes/{id}")).Problem(HttpStatusCode.NotFound, "not_found");
    }

    [Theory]
    [InlineData("""{ "match": { "kind": "address" }, "action": { "kind": "store" } }""", "match.localPart")]
    [InlineData("""{ "match": { "kind": "catch_all", "localPart": "x" }, "action": { "kind": "store" } }""", "match.localPart")]
    [InlineData("""{ "match": { "kind": "address", "localPart": "Upper" }, "action": { "kind": "store" } }""", "match.localPart")]
    [InlineData("""{ "match": { "kind": "address", "localPart": "a*b" }, "action": { "kind": "store" } }""", "match.localPart")]
    [InlineData("""{ "match": { "kind": "wildcard", "localPart": "plain" }, "action": { "kind": "store" } }""", "match.localPart")]
    [InlineData("""{ "match": { "kind": "nonsense" }, "action": { "kind": "store" } }""", "match.kind")]
    [InlineData("""{ "match": { "kind": "catch_all" }, "action": { "kind": "nonsense" } }""", "action.kind")]
    [InlineData("""{ "match": { "kind": "catch_all" }, "action": { "kind": "webhook" } }""", "action.webhookEndpointId")]
    [InlineData("""{ "match": { "kind": "catch_all" }, "action": { "kind": "forward" } }""", "action.forwardTo")]
    [InlineData("""{ "match": { "kind": "catch_all" }, "action": { "kind": "forward", "forwardTo": ["a@example.org", "nope"] } }""", "action.forwardTo[1]")]
    [InlineData("""{ "match": { "kind": "catch_all" }, "action": { "kind": "store", "forwardTo": ["a@example.org"] } }""", "action.forwardTo")]
    [InlineData("""{ "match": { "kind": "catch_all" }, "action": { "kind": "store", "webhookFormat": "xml" } }""", "action.webhookFormat")]
    [InlineData("""{ "order": -3, "match": { "kind": "catch_all" }, "action": { "kind": "store" } }""", "order")]
    [InlineData("""{ "action": { "kind": "store" } }""", "match")]
    [InlineData("""{ "match": { "kind": "catch_all" } }""", "action")]
    public async Task Invalid_routes_are_refused_with_the_nested_field_name(string json, string field)
    {
        Reply r = await _a.SendAsync(HttpMethod.Post, _base + "/routes", json);

        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains(field, r.ErrorFields);
        Assert.Empty(await _f.Storage.Inbound.GetRoutesAsync(_domainA.Id, default));
    }

    [Fact]
    public async Task A_webhook_route_needs_an_endpoint_of_the_same_tenant()
    {
        Guid theirs = await EndpointAsync(ApiFixture.TenantBId);
        Reply r = await _a.PostAsync(_base + "/routes", new { match = new { kind = "catch_all" }, action = new { kind = "webhook", webhookEndpointId = theirs.ToString("N") } });
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["action.webhookEndpointId"], r.ErrorFields);

        r = await _a.PostAsync(_base + "/routes", new { match = new { kind = "catch_all" }, action = new { kind = "webhook", webhookEndpointId = Ids.New().ToString("N") } });
        Assert.Equal(["action.webhookEndpointId"], r.ErrorFields);
    }

    [Fact]
    public async Task The_number_of_routes_per_domain_is_limited()
    {
        await _f.DisposeAsync();
        _f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.MaxInboundRoutesPerDomain = 2 });
        _a = await _f.KeyClientAsync(ApiFixture.TenantAId);
        _domainA = (await _f.Storage.Config.GetDomainsAsync(ApiFixture.TenantAId, default)).Single();
        _base = $"/api/v1/domains/{_domainA.Id:N}/inbound";

        for (int i = 0; i < 2; i++)
        {
            Assert.Equal(HttpStatusCode.Created, (await _a.PostAsync(_base + "/routes", new { match = new { kind = "address", localPart = "u" + i }, action = new { kind = "store" } })).Status);
        }

        Reply r = await _a.PostAsync(_base + "/routes", CatchAll());
        r.Problem(HttpStatusCode.Conflict, "conflict");
        Assert.Equal("route_limit", r["reason"].GetString());
    }

    [Fact]
    public async Task A_route_of_another_domain_or_tenant_is_not_found()
    {
        DomainRecord second = await _f.AddVerifiedDomainAsync(ApiFixture.TenantAId, "second.example");
        string id = (await _a.PostAsync(_base + "/routes", CatchAll())).Str("id");

        (await _a.GetAsync($"/api/v1/domains/{second.Id:N}/inbound/routes/{id}")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.DeleteAsync($"/api/v1/domains/{second.Id:N}/inbound/routes/{id}")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _b.GetAsync($"{_base}/routes/{id}")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _b.PatchAsync($"{_base}/routes/{id}", new { name = "mine now" })).Problem(HttpStatusCode.NotFound, "not_found");
        Assert.Single(await _f.Storage.Inbound.GetRoutesAsync(_domainA.Id, default));
        (await _a.GetAsync($"{_base}/routes/not-an-id")).Problem(HttpStatusCode.NotFound, "not_found");
    }

    [Fact]
    public async Task A_forward_route_warns_when_the_spf_record_of_the_domain_is_not_ok_and_deleting_the_domain_deletes_its_routes()
    {
        Reply r = await _a.PostAsync(_base + "/routes", new { match = new { kind = "address", localPart = "info" }, action = new { kind = "forward", forwardTo = new[] { "a@example.org" } } });

        Assert.Equal(HttpStatusCode.Created, r.Status);
        Assert.Equal("spf_not_ok", r["warnings"][0].GetProperty("code").GetString());
        Reply store = await _a.PostAsync(_base + "/routes", CatchAll());
        Assert.False(store.Json.TryGetProperty("warnings", out _));

        Assert.Equal(HttpStatusCode.NoContent, (await _a.DeleteAsync($"/api/v1/domains/{_domainA.Id:N}")).Status);
        Assert.Empty(await _f.Storage.Inbound.GetRoutesAsync(_domainA.Id, default));
    }

    [Fact]
    public async Task The_route_test_answers_what_the_receive_path_would_answer()
    {
        string probe = _base + "/routes/match?address=";
        Reply off = await _a.GetAsync(probe + "support@example.com");
        Assert.Equal(("550 5.7.1", false), (off.Str("reply"), off["domainEnabled"].GetBoolean()));

        await EnableAsync();
        Assert.Equal("550 5.1.1", (await _a.GetAsync(probe + "support@example.com")).Str("reply"));

        await _a.PostAsync(_base + "/routes", new { name = "support", order = 10, match = new { kind = "address", localPart = "support", plusAddressing = true }, action = new { kind = "store" } });
        await _a.PostAsync(_base + "/routes", new { name = "off", order = 5, enabled = false, match = new { kind = "address", localPart = "other" }, action = new { kind = "store" } });
        Reply hit = await _a.GetAsync(probe + "Support%2Bbilling@Example.COM");
        Assert.Equal("250", hit.Str("reply"));
        Assert.Equal("support", hit["route"].GetProperty("name").GetString());
        Assert.Equal("support+billing@example.com", hit.Str("address"));
        Assert.Equal("550 5.1.1", (await _a.GetAsync(probe + "other@example.com")).Str("reply"));   // a disabled route does not match
        Assert.Equal(JsonValueKind.Null, (await _a.GetAsync(probe + "other@example.com"))["route"].ValueKind);

        (await _a.GetAsync(probe + "someone@elsewhere.test")).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _a.GetAsync(probe)).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _a.GetAsync(probe + "not an address")).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task A_webhook_endpoint_that_a_route_uses_cannot_be_deleted()
    {
        Guid endpoint = await EndpointAsync(ApiFixture.TenantAId);
        string routeId = (await _a.PostAsync(_base + "/routes", new { match = new { kind = "catch_all" }, action = new { kind = "webhook", webhookEndpointId = endpoint.ToString("N") } })).Str("id");

        Reply refused = await _a.DeleteAsync($"/api/v1/webhooks/{endpoint:N}");
        refused.Problem(HttpStatusCode.Conflict, "conflict");
        Assert.Equal("webhook_endpoint_in_use", refused["reason"].GetString());
        Assert.Equal(routeId, refused["routes"][0].GetString());
        Assert.NotNull(await _f.Storage.Config.GetWebhookEndpointAsync(endpoint, default));

        await _a.DeleteAsync($"{_base}/routes/{routeId}");
        Assert.Equal(HttpStatusCode.NoContent, (await _a.DeleteAsync($"/api/v1/webhooks/{endpoint:N}")).Status);
    }

    // Messages

    private static byte[] Mime(string subject, string text, string? html = null, params (string Name, string Type, string Body)[] attachments)
    {
        var sb = new StringBuilder();
        sb.Append("Received: from mail.sender.test (mail.sender.test [203.0.113.9]) by mx.egg.test; Mon, 12 Oct 2026 12:30:00 +0000\r\n");
        sb.Append("Authentication-Results: mx.egg.test; spf=pass; dkim=pass; dmarc=pass\r\n");
        sb.Append("From: Alice <alice@sender.test>\r\nTo: support@example.com\r\nSubject: ").Append(subject).Append("\r\nMIME-Version: 1.0\r\n");
        sb.Append("Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n");
        sb.Append("--b1\r\nContent-Type: multipart/alternative; boundary=\"b2\"\r\n\r\n");
        sb.Append("--b2\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n").Append(text).Append("\r\n");
        if (html is not null)
        {
            sb.Append("--b2\r\nContent-Type: text/html; charset=utf-8\r\n\r\n").Append(html).Append("\r\n");
        }

        sb.Append("--b2--\r\n");
        foreach (var (name, type, body) in attachments)
        {
            sb.Append("--b1\r\nContent-Type: ").Append(type).Append("; name=\"").Append(name).Append("\"\r\nContent-Disposition: attachment; filename=\"").Append(name)
              .Append("\"\r\nContent-Transfer-Encoding: base64\r\n\r\n").Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(body))).Append("\r\n");
        }

        sb.Append("--b1--\r\n");
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private async Task<InboundMessageDraft> StoreAsync(Guid tenant, DomainRecord domain, InboundActionKind kind, byte[]? raw = null, string to = "support@example.com", string from = "alice@sender.test",
        string subject = "Hello", TimeSpan? age = null, InboundDmarcDisposition disposition = InboundDmarcDisposition.None)
    {
        DateTimeOffset at = _f.Clock.UtcNow - (age ?? TimeSpan.Zero);
        var draft = new InboundMessageDraft
        {
            Id = Ids.New(at), TenantId = tenant, DomainId = domain.Id, Domain = domain.Name, ReceivedAt = at, RemoteAddress = "203.0.113.9", Helo = "mail.sender.test", TlsUsed = true, EnvelopeFrom = from, EnvelopeTo = to, Subject = subject,
            Auth = new InboundAuthResults(InboundVerdict.Pass, "sender.test", InboundVerdict.Pass, "sender.test", InboundVerdict.Fail, "reject", InboundVerdict.None), Disposition = disposition, RouteId = Ids.New(), ActionKind = kind,
            Raw = raw ?? Mime(subject, "plain body"),
        };
        await _f.Storage.Inbound.AcceptAsync([draft], default);
        return draft;
    }

    [Fact]
    public async Task A_message_is_listed_and_shown_with_its_verdicts_headers_bodies_and_attachments()
    {
        byte[] raw = Mime("Quarterly report", "Dear team,\nsee attached.", "<p>Dear team</p>", ("report.txt", "text/plain", "numbers"), ("chart.png", "image/png", "PNG"));
        InboundMessageDraft draft = await StoreAsync(ApiFixture.TenantAId, _domainA, InboundActionKind.Store, raw, subject: "Quarterly report", disposition: InboundDmarcDisposition.QuarantineFlagged);

        Reply list = await _a.GetAsync("/api/v1/inbound/messages");
        Assert.Equal(HttpStatusCode.OK, list.Status);
        JsonElement item = Assert.Single(list["items"].EnumerateArray());
        Assert.Equal(JsonValueKind.Null, list["next_cursor"].ValueKind);
        Assert.Equal(draft.Id.ToString("N"), item.GetProperty("id").GetString());
        Assert.Equal(("example.com", "alice@sender.test", "support@example.com", "Quarterly report", raw.Length), (item.GetProperty("domain").GetString(), item.GetProperty("from").GetString(), item.GetProperty("to").GetString(), item.GetProperty("subject").GetString(), item.GetProperty("size").GetInt32()));
        Assert.Equal(("203.0.113.9", "mail.sender.test", true, true), (item.GetProperty("remoteIp").GetString(), item.GetProperty("helo").GetString(), item.GetProperty("tls").GetBoolean(), item.GetProperty("quarantined").GetBoolean()));
        JsonElement auth = item.GetProperty("auth");
        Assert.Equal("pass", auth.GetProperty("spf").GetProperty("result").GetString());
        Assert.Equal("sender.test", auth.GetProperty("spf").GetProperty("domain").GetString());
        Assert.Equal("fail", auth.GetProperty("dmarc").GetProperty("result").GetString());
        Assert.Equal("reject", auth.GetProperty("dmarc").GetProperty("policy").GetString());
        Assert.Equal("none", auth.GetProperty("arc").GetProperty("result").GetString());
        JsonElement action = item.GetProperty("action");
        Assert.Equal(("store", "done", 0), (action.GetProperty("kind").GetString(), action.GetProperty("state").GetString(), action.GetProperty("attempts").GetInt32()));
        Assert.True(item.GetProperty("hasRaw").GetBoolean());
        Assert.False(item.TryGetProperty("content", out _));   // the list never carries content

        Reply detail = await _a.GetAsync("/api/v1/inbound/messages/" + draft.Id.ToString("N"));
        Assert.Equal(HttpStatusCode.OK, detail.Status);
        JsonElement content = detail["content"];
        Assert.Equal("available", content.GetProperty("state").GetString());
        Assert.Equal("Dear team,\nsee attached.", content.GetProperty("text").GetString());
        Assert.Equal("<p>Dear team</p>", content.GetProperty("html").GetString());
        Assert.False(content.GetProperty("truncated").GetBoolean());
        string[] headerNames = content.GetProperty("headers").EnumerateArray().Select(h => h.GetProperty("name").GetString()!).ToArray();
        Assert.Equal(["Received", "Authentication-Results", "From", "To", "Subject", "MIME-Version", "Content-Type"], headerNames);
        var attachments = content.GetProperty("attachments").EnumerateArray().ToList();
        Assert.Equal(["report.txt", "chart.png"], attachments.Select(a => a.GetProperty("filename").GetString()!).ToArray());
        Assert.Equal(["text/plain", "image/png"], attachments.Select(a => a.GetProperty("content_type").GetString()!).ToArray());
        Assert.Equal([7, 3], attachments.Select(a => a.GetProperty("size").GetInt32()).ToArray());
        Assert.Equal([0, 1], attachments.Select(a => a.GetProperty("index").GetInt32()).ToArray());
        Assert.All(attachments, a => Assert.Equal("attachment", a.GetProperty("disposition").GetString()));
    }

    [Fact]
    public async Task The_raw_message_and_the_attachments_are_downloads_that_a_browser_never_renders()
    {
        byte[] raw = Mime("Files", "see attachments", null, ("../../etc/pa\"ss;wd.html", "text/html", "<script>alert(1)</script>"));
        InboundMessageDraft draft = await StoreAsync(ApiFixture.TenantAId, _domainA, InboundActionKind.Store, raw);
        string baseUrl = "/api/v1/inbound/messages/" + draft.Id.ToString("N");

        using HttpResponseMessage rawResponse = await GetWithHeadersAsync(_a, baseUrl + "/raw");
        Assert.Equal(HttpStatusCode.OK, rawResponse.StatusCode);
        Assert.Equal("message/rfc822", rawResponse.Content.Headers.ContentType!.MediaType);
        Assert.Equal(raw, await rawResponse.Content.ReadAsByteArrayAsync());
        Assert.Equal($"attachment; filename=\"{draft.Id:N}.eml\"", rawResponse.Content.Headers.ContentDisposition!.ToString());
        Assert.Equal("nosniff", rawResponse.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("no-store", rawResponse.Headers.CacheControl!.ToString());

        using HttpResponseMessage part = await GetWithHeadersAsync(_a, baseUrl + "/attachments/0");
        Assert.Equal(HttpStatusCode.OK, part.StatusCode);
        Assert.Equal("application/octet-stream", part.Content.Headers.ContentType!.MediaType);   // whatever the sender claimed
        Assert.Equal("text/html", part.Headers.GetValues("X-Original-Content-Type").Single());
        Assert.Equal("<script>alert(1)</script>", await part.Content.ReadAsStringAsync());
        string disposition = part.Content.Headers.ContentDisposition!.ToString();
        Assert.StartsWith("attachment; filename=", disposition, StringComparison.Ordinal);
        Assert.DoesNotContain("..", disposition, StringComparison.Ordinal);
        Assert.DoesNotContain("/", disposition, StringComparison.Ordinal);
        Assert.Equal("nosniff", part.Headers.GetValues("X-Content-Type-Options").Single());

        (await _a.GetAsync(baseUrl + "/attachments/1")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.GetAsync(baseUrl + "/attachments/x")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.GetAsync(baseUrl + "/attachments/-1")).Problem(HttpStatusCode.NotFound, "not_found");
    }

    private async Task<HttpResponseMessage> GetWithHeadersAsync(ApiClient client, string path)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + client.Bearer);
        return await _f.Http.SendAsync(request);
    }

    [Fact]
    public async Task A_message_without_a_body_answers_gone_for_the_raw_download_and_shows_no_content()
    {
        InboundMessageDraft discarded = await StoreAsync(ApiFixture.TenantAId, _domainA, InboundActionKind.Discard);
        string baseUrl = "/api/v1/inbound/messages/" + discarded.Id.ToString("N");

        (await _a.GetAsync(baseUrl + "/raw")).Problem(HttpStatusCode.Gone, "inbound_body_gone");
        (await _a.GetAsync(baseUrl + "/attachments/0")).Problem(HttpStatusCode.Gone, "inbound_body_gone");
        Reply detail = await _a.GetAsync(baseUrl);
        Assert.Equal(HttpStatusCode.OK, detail.Status);
        Assert.False(detail["hasRaw"].GetBoolean());
        Assert.Equal("no_body", detail["content"].GetProperty("state").GetString());
        Assert.Equal(0, detail["content"].GetProperty("headers").GetArrayLength());
    }

    [Fact]
    public async Task Messages_are_filtered_and_paged_newest_first_and_never_leak_across_tenants()
    {
        DomainRecord globex = (await _f.Storage.Config.GetDomainsAsync(ApiFixture.TenantBId, default)).Single();
        var mine = new List<InboundMessageDraft>();
        for (int i = 0; i < 5; i++)
        {
            _f.Clock.Advance(TimeSpan.FromMinutes(1));
            mine.Add(await StoreAsync(ApiFixture.TenantAId, _domainA, i % 2 == 0 ? InboundActionKind.Webhook : InboundActionKind.Store, to: i < 3 ? "sales@example.com" : "info@example.com", from: i == 4 ? "bob@other.test" : "alice@sender.test", subject: "Invoice " + i));
        }

        InboundMessageDraft theirs = await StoreAsync(ApiFixture.TenantBId, globex, InboundActionKind.Store, to: "x@globex.test");

        string[] Ids(Reply r) => r["items"].EnumerateArray().Select(m => m.GetProperty("id").GetString()!).ToArray();
        string N(InboundMessageDraft d) => d.Id.ToString("N");

        Assert.Equal(mine.AsEnumerable().Reverse().Select(N), Ids(await _a.GetAsync("/api/v1/inbound/messages")));
        Assert.Equal([N(theirs)], Ids(await _b.GetAsync("/api/v1/inbound/messages")));
        Assert.Equal([N(mine[2]), N(mine[1]), N(mine[0])], Ids(await _a.GetAsync("/api/v1/inbound/messages?recipient=Sales@Example.com")));
        Assert.Equal([N(mine[4])], Ids(await _a.GetAsync("/api/v1/inbound/messages?sender=bob@other.test")));
        Assert.Equal([N(mine[3])], Ids(await _a.GetAsync("/api/v1/inbound/messages?subject=voice%203")));
        Assert.Equal(3, Ids(await _a.GetAsync("/api/v1/inbound/messages?action=webhook")).Length);
        Assert.Equal(3, Ids(await _a.GetAsync("/api/v1/inbound/messages?state=pending")).Length);
        Assert.Equal(5, Ids(await _a.GetAsync("/api/v1/inbound/messages?dmarc=fail")).Length);
        Assert.Empty(Ids(await _a.GetAsync("/api/v1/inbound/messages?quarantined=true")));
        Assert.Equal(5, Ids(await _a.GetAsync($"/api/v1/inbound/messages?domain={_domainA.Id:N}")).Length);
        Assert.Empty(Ids(await _a.GetAsync($"/api/v1/inbound/messages?domain={globex.Id:N}")));   // a foreign domain id finds nothing, it does not fail
        Assert.Equal([N(mine[2]), N(mine[1])], Ids(await _a.GetAsync($"/api/v1/inbound/messages?from={Uri.EscapeDataString(mine[1].ReceivedAt.ToString("O"))}&to={Uri.EscapeDataString(mine[3].ReceivedAt.ToString("O"))}")));

        Reply page1 = await _a.GetAsync("/api/v1/inbound/messages?limit=2");
        Reply page2 = await _a.GetAsync("/api/v1/inbound/messages?limit=2&cursor=" + Uri.EscapeDataString(page1["next_cursor"].GetString()!));
        Reply page3 = await _a.GetAsync("/api/v1/inbound/messages?limit=2&cursor=" + Uri.EscapeDataString(page2["next_cursor"].GetString()!));
        Assert.Equal(mine.AsEnumerable().Reverse().Select(N), Ids(page1).Concat(Ids(page2)).Concat(Ids(page3)));
        Assert.Equal(JsonValueKind.Null, page3["next_cursor"].ValueKind);

        // Their message is not found by id for me, in any of the ways to ask.
        string foreignUrl = "/api/v1/inbound/messages/" + N(theirs);
        (await _a.GetAsync(foreignUrl)).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.GetAsync(foreignUrl + "/raw")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.GetAsync(foreignUrl + "/attachments/0")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.DeleteAsync(foreignUrl)).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.PostAsync(foreignUrl + "/retry")).Problem(HttpStatusCode.NotFound, "not_found");
        Assert.NotNull(await _f.Storage.Inbound.GetAsync(ApiFixture.TenantBId, theirs.Id, default));
    }

    [Theory]
    [InlineData("limit=0")]
    [InlineData("limit=500")]
    [InlineData("domain=zzz")]
    [InlineData("route=zzz")]
    [InlineData("action=teleport")]
    [InlineData("state=stuck")]
    [InlineData("dmarc=maybe")]
    [InlineData("quarantined=perhaps")]
    [InlineData("from=yesterday")]
    public async Task Invalid_filters_are_refused(string query)
    {
        (await _a.GetAsync("/api/v1/inbound/messages?" + query)).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task A_bad_cursor_is_an_empty_page_not_an_error()
    {
        await StoreAsync(ApiFixture.TenantAId, _domainA, InboundActionKind.Store);
        Reply r = await _a.GetAsync("/api/v1/inbound/messages?cursor=garbage");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal(0, r["items"].GetArrayLength());
    }

    [Fact]
    public async Task Deleting_a_message_removes_it_and_its_body()
    {
        InboundMessageDraft draft = await StoreAsync(ApiFixture.TenantAId, _domainA, InboundActionKind.Store);
        string url = "/api/v1/inbound/messages/" + draft.Id.ToString("N");

        Assert.Equal(HttpStatusCode.NoContent, (await _a.DeleteAsync(url)).Status);
        (await _a.GetAsync(url)).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.DeleteAsync(url)).Problem(HttpStatusCode.NotFound, "not_found");
        Assert.Null(await _f.Storage.Inbound.GetRawAsync(ApiFixture.TenantAId, draft.Id, default));
        (await _a.GetAsync("/api/v1/inbound/messages/not-an-id")).Problem(HttpStatusCode.NotFound, "not_found");
    }

    [Fact]
    public async Task Retry_queues_a_failed_action_again_and_explains_why_it_cannot()
    {
        InboundMessageDraft hook = await StoreAsync(ApiFixture.TenantAId, _domainA, InboundActionKind.Webhook);
        InboundMessageDraft store = await StoreAsync(ApiFixture.TenantAId, _domainA, InboundActionKind.Store);
        string hookUrl = "/api/v1/inbound/messages/" + hook.Id.ToString("N");

        Reply pending = await _a.PostAsync(hookUrl + "/retry");
        pending.Problem(HttpStatusCode.Conflict, "conflict");
        Assert.Equal("already_pending", pending["reason"].GetString());

        var claimed = await _f.Storage.Inbound.ClaimActionsAsync("worker", 5, _f.Clock.UtcNow, TimeSpan.FromMinutes(1), default);
        Assert.Single(claimed);
        await _f.Storage.Inbound.CompleteActionAsync(hook.Id, "worker", new InboundActionOutcome(InboundActionState.Failed, _f.Clock.UtcNow, null, "HTTP 500"), default);
        Reply failed = await _a.GetAsync(hookUrl);
        Assert.Equal(("failed", "HTTP 500", 1), (failed["action"].GetProperty("state").GetString()!, failed["action"].GetProperty("lastError").GetString()!, failed["action"].GetProperty("attempts").GetInt32()));

        _f.Clock.Advance(TimeSpan.FromHours(1));
        Reply retried = await _a.PostAsync(hookUrl + "/retry");
        Assert.Equal(HttpStatusCode.Accepted, retried.Status);
        Assert.Equal(hook.Id.ToString("N"), retried.Str("id"));
        Assert.Equal(("pending", 0), (retried["action"].GetProperty("state").GetString()!, retried["action"].GetProperty("attempts").GetInt32()));
        Assert.Single(await _f.Storage.Inbound.ClaimActionsAsync("worker", 5, _f.Clock.UtcNow, TimeSpan.FromMinutes(1), default));

        Reply notRetryable = await _a.PostAsync("/api/v1/inbound/messages/" + store.Id.ToString("N") + "/retry");
        notRetryable.Problem(HttpStatusCode.Conflict, "conflict");
        Assert.Equal("not_retryable", notRetryable["reason"].GetString());
    }

    [Fact]
    public async Task Usage_counts_the_messages_of_the_tenant()
    {
        Assert.Equal(0, (await _a.GetAsync("/api/v1/inbound/usage"))["messages"].GetInt32());
        await StoreAsync(ApiFixture.TenantAId, _domainA, InboundActionKind.Webhook, age: TimeSpan.FromHours(2));
        InboundMessageDraft stored = await StoreAsync(ApiFixture.TenantAId, _domainA, InboundActionKind.Store);
        await StoreAsync(ApiFixture.TenantBId, (await _f.Storage.Config.GetDomainsAsync(ApiFixture.TenantBId, default)).Single(), InboundActionKind.Store);

        Reply usage = await _a.GetAsync("/api/v1/inbound/usage");
        Assert.Equal((2, 1, 0), (usage["messages"].GetInt32(), usage["pending"].GetInt32(), usage["failed"].GetInt32()));
        Assert.True(usage["bodyBytes"].GetInt64() > stored.Raw.Length);
        Assert.Equal("2026-10-12T10:30:00.000Z", usage.Str("oldestPendingAt"));
        Assert.Equal(1, (await _a.GetAsync($"/api/v1/inbound/usage?domain={_domainA.Id:N}"))["pending"].GetInt32());
        (await _a.GetAsync("/api/v1/inbound/usage?domain=zzz")).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task An_administrator_reads_the_mail_of_the_tenant_named_in_the_header()
    {
        await StoreAsync(ApiFixture.TenantBId, (await _f.Storage.Config.GetDomainsAsync(ApiFixture.TenantBId, default)).Single(), InboundActionKind.Store, to: "x@globex.test");
        ApiClient admin = await _f.SignedInAsync("root");

        (await admin.GetAsync("/api/v1/inbound/messages")).Problem(HttpStatusCode.BadRequest, "validation_failed");
        admin.ActingAs(ApiFixture.TenantBId);
        Assert.Equal(1, (await admin.GetAsync("/api/v1/inbound/messages"))["items"].GetArrayLength());
        admin.ActingAs(ApiFixture.TenantAId);
        Assert.Equal(0, (await admin.GetAsync("/api/v1/inbound/messages"))["items"].GetArrayLength());
    }

    [Fact]
    public async Task A_signed_in_tenant_user_needs_the_csrf_token_for_changes()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        Assert.Equal(HttpStatusCode.OK, (await alice.PatchAsync(_base, new { retentionDays = 14 })).Status);
        alice.SendCsrf = false;
        (await alice.PatchAsync(_base, new { retentionDays = 15 })).Problem(HttpStatusCode.Forbidden, "forbidden");
        Assert.Equal(14, (await _a.GetAsync(_base))["retentionDays"].GetInt32());
    }
}
