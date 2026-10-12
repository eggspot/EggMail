using System.Net;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Mta.Host.Api;
using Mta.Observability;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

/// <summary>Error shapes, request limits, capabilities and the operational endpoints.</summary>
public class ApiBasicsTests : IAsyncLifetime
{
    private ApiFixture _f = null!;

    public async Task InitializeAsync() => _f = await ApiFixture.StartAsync(new ApiFixtureOptions
    {
        ConfigureApi = o => o.MaxBodyBytes = 2048,
        ConfigureServices = s => s.AddSingleton(new PrometheusTextExporter()),
    });

    public async Task DisposeAsync() => await _f.DisposeAsync();

    // Errors

    [Fact]
    public async Task Unknown_api_paths_are_a_problem_not_found()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId);
        Reply r = await c.GetAsync("/api/v1/nope/at/all");
        r.Problem(HttpStatusCode.NotFound, "not_found");
        Assert.Contains("/api/v1/nope/at/all", r.Str("detail"));
    }

    [Fact]
    public async Task Unknown_members_in_a_request_are_validation_failed_with_the_field()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId, "domains");
        Reply r = await c.PostAsync("/api/v1/domains", new { name = "example.net", colour = "blue" });
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["colour"], r.ErrorFields);
        Assert.Equal("Unknown member.", r["errors"][0].GetProperty("message").GetString());
    }

    [Fact]
    public async Task Malformed_json_and_wrong_types_are_validation_failed()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId, "domains");
        (await c.SendAsync(HttpMethod.Post, "/api/v1/domains", "{not json")).Problem(HttpStatusCode.BadRequest, "validation_failed");
        Reply wrongType = await c.SendAsync(HttpMethod.Post, "/api/v1/domains", """{"name":42}""");
        wrongType.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["name"], wrongType.ErrorFields);
        (await c.SendAsync(HttpMethod.Post, "/api/v1/domains", "null")).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await c.SendAsync(HttpMethod.Post, "/api/v1/domains", "[]")).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task A_body_must_be_json()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId, "domains");
        (await c.SendRawAsync(HttpMethod.Post, "/api/v1/domains", """{"name":"example.net"}""", "text/plain")).Problem(HttpStatusCode.UnsupportedMediaType, "unsupported_media_type");
        (await c.SendRawAsync(HttpMethod.Post, "/api/v1/domains", """{"name":"example.net"}""", null)).Problem(HttpStatusCode.UnsupportedMediaType, "unsupported_media_type");
        (await c.SendRawAsync(HttpMethod.Post, "/api/v1/domains", "", "application/json")).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task Oversized_bodies_are_refused_before_they_are_parsed()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId, "domains");
        string big = "{\"name\":\"" + new string('a', 4096) + ".test\"}";
        Reply r = await c.SendAsync(HttpMethod.Post, "/api/v1/domains", big);
        r.Problem(HttpStatusCode.RequestEntityTooLarge, "payload_too_large");
        Assert.Empty(await _f.Storage.Config.GetDomainsAsync(ApiFixture.TenantAId, default).AsTask().ContinueWith(t => t.Result.Where(d => d.Name != "example.com").ToList()));
    }

    [Fact]
    public async Task Every_response_carries_a_request_id_and_forbids_caching()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId);
        Reply ok = await c.GetAsync("/api/v1/domains");
        Assert.StartsWith("req_", ok.Header("X-Request-Id"));
        Assert.Equal("no-store", ok.Header("Cache-Control"));
        Reply a = await c.GetAsync("/api/v1/me");
        Reply b = await c.GetAsync("/api/v1/me");
        Assert.NotEqual(a.Header("X-Request-Id"), b.Header("X-Request-Id"));
    }

    [Fact]
    public async Task An_unexpected_failure_is_a_generic_500_without_internals()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureServices = s => s.AddSingleton<IStorageSwitchService>(new ExplodingSwitchService()) });
        ApiClient admin = await f.SignedInAsync("root");
        Reply r = await admin.GetAsync("/api/v1/admin/storage/switch");
        r.Problem(HttpStatusCode.InternalServerError, "server_error");
        Assert.DoesNotContain("connection string", r.Body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ExplodingSwitchService", r.Body);
    }

    private sealed class ExplodingSwitchService : IStorageSwitchService
    {
        public ValueTask<SwitchPreflightReport> PreflightAsync(SwitchRequestModel request, CancellationToken cancellationToken) => throw new InvalidOperationException("connection string Host=secret");

        public ValueTask<SwitchStatusReport> StartAsync(SwitchStartModel request, CancellationToken cancellationToken) => throw new InvalidOperationException("connection string Host=secret");

        public ValueTask<SwitchStatusReport> GetStatusAsync(CancellationToken cancellationToken) => throw new InvalidOperationException("connection string Host=secret");

        public ValueTask<SwitchStatusReport> ConfirmAsync(CancellationToken cancellationToken) => throw new InvalidOperationException("x");

        public ValueTask<SwitchStatusReport> ActivateAsync(CancellationToken cancellationToken) => throw new InvalidOperationException("x");

        public ValueTask<SwitchStatusReport> RollbackAsync(CancellationToken cancellationToken) => throw new InvalidOperationException("x");

        public ValueTask<SwitchStatusReport> FinalizeAsync(CancellationToken cancellationToken) => throw new InvalidOperationException("x");
    }

    // Capabilities

    [Fact]
    public async Task Capabilities_describe_the_server()
    {
        Reply r = await _f.NewClient().GetAsync("/api/v1/capabilities");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.False(string.IsNullOrEmpty(r.Str("version")));
        Assert.Equal("memory", r.Str("backend"));
        Assert.Equal("full", r["history"].GetProperty("mode").GetString());
        Assert.Equal(7, r["content"].GetProperty("retentionDays").GetInt32());
        Assert.False(r["content"].GetProperty("storeAttachments").GetBoolean());
        Assert.Equal(26214400, r["limits"].GetProperty("maxMessageBytes").GetInt64());
        Assert.Equal(50, r["limits"].GetProperty("maxRecipients").GetInt32());
        Assert.Equal(JsonValueKind.Array, r["warnings"].ValueKind);
    }

    [Fact]
    public async Task Capabilities_report_the_history_mode_not_the_backend_for_per_message_features()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { History = HistoryMode.StatsOnly });
        Reply r = await f.NewClient().GetAsync("/api/v1/capabilities");
        Assert.Equal("statsonly", r["history"].GetProperty("mode").GetString());
    }

    [Fact]
    public async Task Sqlite_with_synchronous_off_raises_the_sync_warning_with_text()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { Sqlite = true });
        Reply r = await f.NewClient().GetAsync("/api/v1/capabilities");
        Assert.Equal("sqlite", r.Str("backend"));
        JsonElement warning = r["warnings"].EnumerateArray().Single(w => w.GetProperty("code").GetString() == "sqlite_sync_off");
        Assert.Contains("synchronous=OFF", warning.GetProperty("message").GetString());
    }

    [Fact]
    public async Task A_self_signed_or_expiring_certificate_is_a_warning()
    {
        var cert = new CertificateRecord(Guid.NewGuid(), "selfsigned:mx.test", ["mx.test"], _f.Clock.UtcNow.AddDays(-1), _f.Clock.UtcNow.AddDays(300), "", [1], "selfsigned", "AA", true, 0, _f.Clock.UtcNow);
        await _f.Storage.Config.UpsertCertificateAsync(cert, default);
        _f.Clock.Advance(TimeSpan.FromSeconds(10)); // past the capabilities cache
        Reply r = await _f.NewClient().GetAsync("/api/v1/capabilities");
        Assert.Contains(r["warnings"].EnumerateArray(), w => w.GetProperty("code").GetString() == "self_signed_certificate");

        var acme = cert with { Id = Guid.NewGuid(), Name = "default", Source = "acme", NotAfter = _f.Clock.UtcNow.AddDays(5) };
        await _f.Storage.Config.UpsertCertificateAsync(acme, default);
        await _f.Storage.Config.UpsertCertificateAsync(cert with { Active = false }, default);
        _f.Clock.Advance(TimeSpan.FromSeconds(10));
        r = await _f.NewClient().GetAsync("/api/v1/capabilities");
        Assert.Contains(r["warnings"].EnumerateArray(), w => w.GetProperty("code").GetString() == "certificate_expiring");
        Assert.DoesNotContain(r["warnings"].EnumerateArray(), w => w.GetProperty("code").GetString() == "self_signed_certificate");
    }

    // Operational endpoints

    [Fact]
    public async Task Healthz_and_readyz_answer_without_authentication()
    {
        Reply health = await _f.NewClient().GetAsync("/healthz");
        Assert.Equal(HttpStatusCode.OK, health.Status);
        Assert.Equal("ok", health.Str("status"));

        Reply ready = await _f.NewClient().GetAsync("/readyz");
        Assert.Equal(HttpStatusCode.OK, ready.Status);
        Assert.Equal("ready", ready.Str("status"));
        Assert.Equal(JsonValueKind.Array, ready["warnings"].ValueKind);
    }

    [Fact]
    public async Task Readyz_fails_with_503_and_retry_after_when_storage_is_not_ready()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions
        {
            ConfigureServices = s => s.AddSingleton<IHealthContributor>(new NeverReady()),
        });
        Reply r = await f.NewClient().GetAsync("/readyz");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, r.Status);
        Assert.Equal("not_ready", r.Str("status"));
        Assert.Equal("5", r.Header("Retry-After"));
        Assert.Contains(r["warnings"].EnumerateArray(), w => w.GetProperty("code").GetString() == "database_down");
        Assert.DoesNotContain("secret-detail", r.Body); // internals (health details) never reach an unauthenticated caller
    }

    private sealed class NeverReady : IHealthContributor
    {
        public string Name => "test";

        public ValueTask<HealthReport> CheckAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(new HealthReport(false, [new HealthWarning("database_down", "The database is down.")], new Dictionary<string, string> { ["x"] = "secret-detail" }));
    }

    [Fact]
    public async Task Metrics_are_limited_to_configured_networks()
    {
        ApiClient local = _f.NewClient();
        local.RemoteIp = "127.0.0.1";
        Reply ok = await local.GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.OK, ok.Status);
        Assert.StartsWith("text/plain", ok.ContentType);

        ApiClient inner = _f.NewClient();
        inner.RemoteIp = "10.1.2.3";
        Assert.Equal(HttpStatusCode.OK, (await inner.GetAsync("/metrics")).Status);

        ApiClient outside = _f.NewClient();
        outside.RemoteIp = "203.0.113.50";
        Assert.Equal(HttpStatusCode.Forbidden, (await outside.GetAsync("/metrics")).Status);
    }

    [Fact]
    public async Task Metrics_can_be_switched_off()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.MetricsEnabled = false });
        ApiClient c = f.NewClient();
        c.RemoteIp = "127.0.0.1";
        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync("/metrics")).Status);
    }
}
