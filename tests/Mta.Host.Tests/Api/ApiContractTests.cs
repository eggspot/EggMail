using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.DependencyInjection;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Tls;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

/// <summary>
/// The dashboard is compiled against <c>dashboard/src/api/types.ts</c> and its mock server. These tests boot the real API, call every endpoint the SPA
/// calls (<c>dashboard/src/api/endpoints.ts</c>) with realistic data and check each response against the TypeScript type the SPA expects, and check that
/// every request member the SPA sends is one the API accepts.
/// </summary>
public class ApiContractTests : IAsyncLifetime
{
    private sealed class DashboardEngine : IStorageSwitchService
    {
        private static readonly DateTimeOffset Now = new(2026, 10, 12, 12, 30, 0, TimeSpan.Zero);

        private static SwitchStatusReport Status(string state) => new(
            state, Guid.Parse("c0000000-0000-7000-8000-000000000003"), new SwitchDirection("sqlite", "postgres"), "quiesce", ["queue", "history"],
            new SwitchProgress("exporting", 40, 10, 25), new SwitchVerifyReport(true, [new SwitchVerifyTable("config.tenants", 3, 3)], true, Now),
            new SwitchCutoverPatch("environment", "Storage__Backend=Postgres\n"), true, Now, Now, null);

        public ValueTask<SwitchPreflightReport> PreflightAsync(SwitchRequestModel request, CancellationToken cancellationToken) => ValueTask.FromResult(new SwitchPreflightReport(
            true, [new PreflightCheckModel("Target reachable", true, "Connected.", "info")], new PreflightCountsModel(17, 1000, 5000, 200), new PreflightEstimateModel(60, 1000, true), ["Ports stay with the deployment."], false));

        public ValueTask<SwitchStatusReport> StartAsync(SwitchStartModel request, CancellationToken cancellationToken) => ValueTask.FromResult(Status("exporting"));

        public ValueTask<SwitchStatusReport> GetStatusAsync(CancellationToken cancellationToken) => ValueTask.FromResult(Status("verified"));

        public ValueTask<SwitchStatusReport> ConfirmAsync(CancellationToken cancellationToken) => ValueTask.FromResult(Status("confirmed"));

        public ValueTask<SwitchStatusReport> ActivateAsync(CancellationToken cancellationToken) => ValueTask.FromResult(Status("active"));

        public ValueTask<SwitchStatusReport> RollbackAsync(CancellationToken cancellationToken) => ValueTask.FromResult(Status("rolled_back"));

        public ValueTask<SwitchStatusReport> FinalizeAsync(CancellationToken cancellationToken) => ValueTask.FromResult(Status("finalized"));
    }

    private ApiFixture _f = null!;
    private TsContract _ts = null!;
    private ApiClient _tenant = null!;
    private ApiClient _admin = null!;
    private string _messageId = "";
    private string _domainId = "";
    private string _webhookId = "";
    private string _outboxId = "";

    public async Task InitializeAsync()
    {
        _ts = TsContract.Load(TsContract.FindDashboardTypes());
        _f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureServices = s => s.AddSingleton<IStorageSwitchService>(new DashboardEngine()) });
        _tenant = await _f.SignedInAsync("alice");
        _admin = await _f.SignedInAsync("root");

        // A realistic tenant: a delivered message with TLS details, a domain, a webhook with attempts, stats and a certificate.
        Reply sent = await _tenant.PostAsync("/api/v1/messages", new { from = "Acme <noreply@example.com>", to = new[] { "alex@gmail.test" }, subject = "Welcome", text = "hello", html = "<p>hello</p>" });
        _messageId = sent.Str("id");
        foreach (ClaimedDelivery d in await _f.Storage.Deliveries.ClaimAsync("t", 10, _f.Clock.UtcNow, TimeSpan.FromMinutes(1), default))
        {
            await _f.Storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt
            {
                DeliveryId = d.DeliveryId,
                Outcome = DeliveryOutcome.Delivered,
                At = _f.Clock.UtcNow,
                SmtpCode = 250,
                EnhancedCode = "2.0.0",
                Message = "250 OK",
                MxHost = "mx.gmail.test",
                Route = "direct",
                Tls = new TlsInfo(true, "TLS 1.3", "TLS_AES_256_GCM_SHA384", "CN=mx.gmail.test", "CN=Test CA", "ABCD", null, true, "mta-sts", null, true, false),
            }, default);
        }

        await _f.Storage.Stats.FlushAsync(default);
        _domainId = (await _tenant.PostAsync("/api/v1/domains", new { name = "contract.example" })).Str("id");
        _webhookId = (await _tenant.PostAsync("/api/v1/webhooks", new { url = "https://hooks.example.com/x", event_types = new[] { "message.delivered" } })).Str("id");
        _outboxId = (await _tenant.PostAsync($"/api/v1/webhooks/{_webhookId}/test")).Str("outboxId");
        var item = (await _f.Storage.Webhooks.ClaimDueAsync("t", 10, _f.Clock.UtcNow, TimeSpan.FromMinutes(1), default)).Single();
        await _f.Storage.Webhooks.CompleteAsync(item.Id, new WebhookAttemptRecord(item.Id, _f.Clock.UtcNow, 500, TimeSpan.FromMilliseconds(1200), "http_5xx", "oops"), WebhookOutboxState.Failed, null, default);
        await _tenant.PostAsync("/api/v1/suppressions", new { address = "bounce@example.org", reason = "bounce" });
        await _tenant.PostAsync("/api/v1/smtp-credentials", new { username = "app-mailer" });
        await _tenant.PostAsync("/api/v1/api-keys", new { name = "CI", scopes = new[] { "send", "read" } });
        await _f.Storage.Config.UpsertCertificateAsync(CertificateMaterial.CreateSelfSigned("mx.egg.test", _f.Protector, _f.Clock.UtcNow), default);
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private void Conforms(Reply reply, string tsType, HttpStatusCode status = HttpStatusCode.OK)
    {
        Assert.Equal(status, reply.Status);
        var problems = _ts.Check(tsType, reply.Json);
        Assert.True(problems.Count == 0, $"The response does not match '{tsType}' in dashboard/src/api/types.ts:\n  " + string.Join("\n  ", problems) + "\n" + reply.Body);
    }

    [Fact]
    public void The_dashboard_types_were_found_and_parsed()
    {
        foreach (string name in new[] { "Me", "Capabilities", "MessageSummary", "MessageDetail", "DeliveryEvent", "Domain", "DnsRecord", "Webhook", "WebhookAttempt", "ApiKey", "SmtpCredential", "StatsRow", "SettingItem", "Tenant", "CertificateInfo", "AdminStatus", "PreflightReport", "SwitchStatus" })
        {
            Assert.True(_ts.Has(name), name + " is missing from types.ts (" + _ts + ")");
        }
    }

    [Fact]
    public async Task Session_and_capabilities()
    {
        Conforms(await _f.NewClient().GetAsync("/api/v1/capabilities"), "Capabilities");
        Conforms(await _tenant.GetAsync("/api/v1/me"), "Me");
        Conforms(await _admin.GetAsync("/api/v1/me"), "Me");
        Reply login = await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password });
        Assert.Equal(HttpStatusCode.OK, login.Status);
        foreach (string member in new[] { "user", "role", "tenantId" })
        {
            Assert.True(login.Json.TryGetProperty(member, out _), member);
        }
    }

    [Fact]
    public async Task Messages()
    {
        Conforms(await _tenant.GetAsync("/api/v1/messages"), "Page<MessageSummary>");
        Conforms(await _tenant.GetAsync("/api/v1/messages/" + _messageId), "MessageDetail");
        Conforms(await _tenant.GetAsync($"/api/v1/messages/{_messageId}/events"), "DeliveryEvent[]");
        Reply content = await _tenant.GetAsync($"/api/v1/messages/{_messageId}/content");
        Assert.Equal("hello", content.Str("text").Trim());
        Assert.Equal("<p>hello</p>", content.Str("html").Trim());
        Conforms(await _tenant.PostAsync($"/api/v1/messages/{_messageId}/resend"), "ResendResponse", HttpStatusCode.Accepted);
        Conforms(await _tenant.PostAsync("/api/v1/messages", new { from = "noreply@example.com", to = new[] { "a@b.test" }, subject = "s", text = "t" }), "SendMessageResponse", HttpStatusCode.Accepted);
    }

    [Fact]
    public async Task Domains()
    {
        Reply list = await _tenant.GetAsync("/api/v1/domains");
        Conforms(list, "Domain[]");
        Conforms(await _tenant.GetAsync("/api/v1/domains/" + _domainId), "Domain");
        Conforms(await _tenant.PostAsync("/api/v1/domains", new { name = "second.example" }), "Domain", HttpStatusCode.Created);
        Conforms(await _tenant.PostAsync($"/api/v1/domains/{_domainId}/verify"), "Domain");
        Conforms(await _tenant.PostAsync($"/api/v1/domains/{_domainId}/dkim/rotate"), "Domain");
    }

    [Fact]
    public async Task Suppressions_webhooks_and_credentials()
    {
        Conforms(await _tenant.GetAsync("/api/v1/suppressions"), "Page<Suppression>");
        Conforms(await _tenant.PostAsync("/api/v1/suppressions", new { address = "new@example.org", reason = "manual" }), "Suppression", HttpStatusCode.Created);

        Conforms(await _tenant.GetAsync("/api/v1/webhooks"), "Webhook[]");
        Conforms(await _tenant.GetAsync("/api/v1/webhooks/" + _webhookId), "Webhook");
        Reply created = await _tenant.PostAsync("/api/v1/webhooks", new { url = "https://hooks.example.com/y", event_types = new[] { "message.bounced" } });
        Conforms(created, "Webhook", HttpStatusCode.Created);
        Assert.StartsWith("whsec_", created.Str("secret"));
        Conforms(await _tenant.PatchAsync("/api/v1/webhooks/" + _webhookId, new { enabled = false }), "Webhook");
        Conforms(await _tenant.PostAsync($"/api/v1/webhooks/{_webhookId}/rotate-secret"), "Webhook");
        Conforms(await _tenant.GetAsync($"/api/v1/webhooks/{_webhookId}/attempts?limit=50"), "WebhookAttempt[]");
        Assert.Equal(HttpStatusCode.Accepted, (await _tenant.PostAsync($"/api/v1/webhook-events/{_outboxId}/replay")).Status);

        Conforms(await _tenant.GetAsync("/api/v1/api-keys"), "ApiKey[]");
        Reply key = await _tenant.PostAsync("/api/v1/api-keys", new { name = "Another", scopes = new[] { "read" } });
        Conforms(key, "ApiKey", HttpStatusCode.Created);
        Assert.StartsWith("egm_", key.Str("key"));
        Conforms(await _tenant.GetAsync("/api/v1/smtp-credentials"), "SmtpCredential[]");
        Reply smtp = await _tenant.PostAsync("/api/v1/smtp-credentials", new { username = "second-mailer" });
        Conforms(smtp, "SmtpCredential", HttpStatusCode.Created);
        Assert.False(string.IsNullOrEmpty(smtp.Str("password")));
    }

    [Fact]
    public async Task Statistics_and_settings()
    {
        Conforms(await _tenant.GetAsync("/api/v1/stats"), "StatsResponse");
        Conforms(await _tenant.GetAsync("/api/v1/stats?granularity=day"), "StatsResponse");
        Conforms(await _tenant.GetAsync("/api/v1/stats/recent-events?limit=50"), "RecentEvent[]");
        Conforms(await _tenant.GetAsync("/api/v1/settings"), "SettingsResponse");
        Conforms(await _tenant.PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { ["Content:StoreAttachments"] = true } }), "SettingsResponse");
    }

    [Fact]
    public async Task Admin()
    {
        Conforms(await _admin.GetAsync("/api/v1/admin/tenants"), "Tenant[]");
        Conforms(await _admin.PostAsync("/api/v1/admin/tenants", new { name = "Initech" }), "Tenant", HttpStatusCode.Created);
        Conforms(await _admin.PatchAsync("/api/v1/admin/tenants/" + ApiFixture.TenantBId.ToString("N"), new { status = "suspended" }), "Tenant");
        Conforms(await _admin.GetAsync("/api/v1/admin/status"), "AdminStatus");
        Conforms(await _admin.GetAsync("/api/v1/admin/settings"), "SettingsResponse");
        Conforms(await _admin.PutAsync("/api/v1/admin/settings", new { values = new Dictionary<string, object> { ["Retention:MetadataDays"] = 20 } }), "SettingsResponse");
        Conforms(await _admin.GetAsync("/api/v1/admin/certificates"), "CertificateInfo[]");

        using RSA rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=up.example.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("up.example.test");
        req.CertificateExtensions.Add(san.Build());
        using X509Certificate2 cert = req.CreateSelfSigned(_f.Clock.UtcNow.AddDays(-1), _f.Clock.UtcNow.AddDays(60));
        Conforms(await _admin.PostAsync("/api/v1/admin/certificates", new { certificatePem = cert.ExportCertificatePem(), privateKeyPem = rsa.ExportPkcs8PrivateKeyPem() }), "CertificateInfo", HttpStatusCode.Created);

        Reply acme = await _admin.PostAsync("/api/v1/admin/certificates/acme", new { domains = new[] { "mx.example.com" } });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, acme.Status); // ACME is not configured in this host
        Assert.Equal(HttpStatusCode.Accepted, (await _admin.PostAsync("/api/v1/admin/maintenance/run")).Status);
        await _f.Get<MaintenanceRunner>().Current;
    }

    [Fact]
    public async Task Storage_switch()
    {
        object target = new { host = "db.internal", database = "egg" };
        Conforms(await _admin.PostAsync("/api/v1/admin/storage/switch/preflight", new { to = "postgres", target, include = new[] { "queue", "history" }, mode = "quiesce" }), "PreflightReport");
        Conforms(await _admin.PostAsync("/api/v1/admin/storage/switch/start", new { to = "postgres", target, include = new[] { "queue", "history" }, mode = "quiesce", exportPassphrase = "twelve chars!", confirmation = "switch to postgres" }), "SwitchStatus", HttpStatusCode.Accepted);
        Conforms(await _admin.GetAsync("/api/v1/admin/storage/switch"), "SwitchStatus");
        foreach (string step in new[] { "confirm", "activate", "rollback", "finalize" })
        {
            Conforms(await _admin.PostAsync("/api/v1/admin/storage/switch/" + step), "SwitchStatus");
        }
    }

    [Fact]
    public async Task Without_an_engine_the_switch_status_still_matches()
    {
        await using ApiFixture f = await ApiFixture.StartAsync();
        ApiClient admin = await f.SignedInAsync("root");
        Reply r = await admin.GetAsync("/api/v1/admin/storage/switch");
        Assert.Empty(_ts.Check("SwitchStatus", r.Json));
    }

    [Fact]
    public async Task Errors_match_the_problem_type()
    {
        Reply unauthorized = await _f.NewClient().GetAsync("/api/v1/domains");
        Assert.Empty(_ts.Check("Problem", unauthorized.Json));
        Reply invalid = await _tenant.PostAsync("/api/v1/domains", new { name = "bad name" });
        Assert.Empty(_ts.Check("Problem", invalid.Json));
        Assert.Empty(_ts.Check("Problem", (await _tenant.GetAsync("/api/v1/messages/" + Guid.NewGuid().ToString("N"))).Json));
    }

    [Fact]
    public async Task Statsonly_responses_match_the_problem_type_too()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { History = HistoryMode.StatsOnly });
        ApiClient c = await f.SignedInAsync("alice");
        Reply r = await c.GetAsync("/api/v1/messages");
        Assert.Equal(HttpStatusCode.Gone, r.Status);
        Assert.Empty(_ts.Check("Problem", r.Json));
        Assert.Equal("statsonly", (await c.GetAsync("/api/v1/capabilities"))["history"].GetProperty("mode").GetString());
        Assert.Empty(_ts.Check("Capabilities", (await c.GetAsync("/api/v1/capabilities")).Json));
    }

    // Requests: every member the SPA sends must be one the API accepts

    private static string JsonName(PropertyInfo p) => p.GetCustomAttribute<JsonPropertyNameAttribute>()?.Name ?? JsonNamingPolicy.CamelCase.ConvertName(p.Name);

    private static IEnumerable<string> JsonMembers(Type type) => type.GetProperties(BindingFlags.Public | BindingFlags.Instance).Select(JsonName);

    [Theory]
    [InlineData("SendMessageRequest", typeof(SendRequest))]
    [InlineData("SwitchRequest", typeof(SwitchRequestModel))]
    [InlineData("SwitchStartRequest", typeof(SwitchStartModel))]
    [InlineData("SwitchTargetConfig", typeof(SwitchTargetModel))]
    public void Request_members_the_dashboard_sends_are_accepted(string tsType, Type clr)
    {
        var accepted = JsonMembers(clr).ToHashSet(StringComparer.Ordinal);
        foreach (string member in _ts.MembersOf(tsType))
        {
            Assert.True(accepted.Contains(member), $"The dashboard sends '{member}' in {tsType}, but {clr.Name} does not accept it.");
        }
    }

    [Fact]
    public void Attachment_and_credential_request_members_are_accepted()
    {
        // The inline attachment type of SendMessageRequest.
        var attachment = JsonMembers(typeof(AttachmentRequest)).ToHashSet();
        foreach (string member in new[] { "filename", "content_type", "content", "content_id" })
        {
            Assert.Contains(member, attachment);
        }

        Assert.Contains("name", JsonMembers(typeof(CreateApiKeyRequest)));
        Assert.Contains("scopes", JsonMembers(typeof(CreateApiKeyRequest)));
        Assert.Contains("username", JsonMembers(typeof(CreateSmtpCredentialRequest)));
        Assert.Equivalent(new[] { "url", "event_types" }, JsonMembers(typeof(CreateWebhookRequest)));
        Assert.Equivalent(new[] { "url", "event_types", "enabled" }, JsonMembers(typeof(UpdateWebhookRequest)));
        Assert.Equivalent(new[] { "name", "status" }, JsonMembers(typeof(UpdateTenantRequest)));
        Assert.Equivalent(new[] { "certificatePem", "privateKeyPem", "pfxBase64", "pfxPassword" }, JsonMembers(typeof(UploadCertificateRequest)));
        Assert.Equivalent(new[] { "address", "reason" }, JsonMembers(typeof(AddSuppressionRequest)));
    }
}
