using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Host.Tls;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

[Collection("api")]
public class ApiAdminTests : IAsyncLifetime
{
    private ApiFixture _f = null!;
    private ApiClient _admin = null!;

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync(new ApiFixtureOptions
        {
            ConfigureApi = o => o.LockedKeys = new HashSet<string>(["Content:RetentionDays"], StringComparer.OrdinalIgnoreCase),
        });
        _admin = await _f.SignedInAsync("root");
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    // Tenants

    [Fact]
    public async Task Tenants_can_be_listed_created_renamed_and_suspended()
    {
        Reply list = await _admin.GetAsync("/api/v1/admin/tenants");
        Assert.Equal(["Acme Corp", "Globex"], list.Json.EnumerateArray().Select(t => t.GetProperty("name").GetString()!));
        JsonElement acme = list.Json[0];
        Assert.Equal("active", acme.GetProperty("status").GetString());
        Assert.Equal("acme", acme.GetProperty("slug").GetString());
        Assert.Equal(ApiFixture.TenantAId.ToString("N"), acme.GetProperty("id").GetString());

        Reply created = await _admin.PostAsync("/api/v1/admin/tenants", new { name = "  Initech Ltd  " });
        Assert.Equal(HttpStatusCode.Created, created.Status);
        Assert.Equal("Initech Ltd", created.Str("name"));
        Assert.Equal("initech-ltd", created.Str("slug"));
        Assert.Equal("active", created.Str("status"));
        string id = created.Str("id");
        Assert.NotNull(await _f.Storage.Config.GetTenantBySlugAsync("initech-ltd", default));

        Reply renamed = await _admin.PatchAsync("/api/v1/admin/tenants/" + id, new { name = "Initech" });
        Assert.Equal("Initech", renamed.Str("name"));
        Reply suspended = await _admin.PatchAsync("/api/v1/admin/tenants/" + id, new { status = "suspended" });
        Assert.Equal("suspended", suspended.Str("status"));
        Assert.False((await _f.Storage.Config.GetTenantAsync(Guid.Parse(id), default))!.Enabled);
        Assert.Equal("active", (await _admin.PatchAsync("/api/v1/admin/tenants/" + id, new { status = "active" })).Str("status"));
    }

    [Fact]
    public async Task Tenant_names_are_validated_and_slugs_made_unique()
    {
        Reply dup = await _admin.PostAsync("/api/v1/admin/tenants", new { name = "ACME CORP" });
        dup.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["name"], dup.ErrorFields);
        (await _admin.PostAsync("/api/v1/admin/tenants", new { name = "" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _admin.PostAsync("/api/v1/admin/tenants", new { name = new string('x', 81) })).Problem(HttpStatusCode.BadRequest, "validation_failed");

        Reply second = await _admin.PostAsync("/api/v1/admin/tenants", new { name = "Acme Corp!" });
        Assert.Equal("acme-corp", second.Str("slug"));
        Reply third = await _admin.PostAsync("/api/v1/admin/tenants", new { name = "Acme  Corp?" });
        Assert.Equal("acme-corp-2", third.Str("slug")); // the slug of "Acme Corp!" is taken

        (await _admin.PatchAsync("/api/v1/admin/tenants/" + Guid.NewGuid().ToString("N"), new { name = "x" })).Problem(HttpStatusCode.NotFound, "not_found");
        (await _admin.PatchAsync("/api/v1/admin/tenants/" + ApiFixture.TenantAId.ToString("N"), new { status = "gone" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _admin.PatchAsync("/api/v1/admin/tenants/" + ApiFixture.TenantAId.ToString("N"), new { name = "Globex" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task Suspending_a_tenant_stops_its_keys_and_users()
    {
        ApiClient key = await _f.KeyClientAsync(ApiFixture.TenantAId);
        ApiClient alice = await _f.SignedInAsync("alice");
        await _admin.PatchAsync("/api/v1/admin/tenants/" + ApiFixture.TenantAId.ToString("N"), new { status = "suspended" });
        (await key.GetAsync("/api/v1/domains")).Problem(HttpStatusCode.Forbidden, "tenant_disabled");
        (await alice.GetAsync("/api/v1/domains")).Problem(HttpStatusCode.Forbidden, "tenant_disabled");
        await _admin.PatchAsync("/api/v1/admin/tenants/" + ApiFixture.TenantAId.ToString("N"), new { status = "active" });
        Assert.Equal(HttpStatusCode.OK, (await key.GetAsync("/api/v1/domains")).Status);
    }

    // Status

    private sealed class FixedPressure : IStoragePressureSource
    {
        public StoragePressure Get() => new(1240, 410, 118.5, true);
    }

    [Fact]
    public async Task Status_reports_queue_storage_certificates_and_switch_state()
    {
        ApiClient key = await _f.KeyClientAsync(ApiFixture.TenantAId);
        await key.PostAsync("/api/v1/messages", new { from = "a@example.com", to = new[] { "x@gmail.test", "y@gmail.test" }, subject = "s", text = "t" });
        await _f.Storage.Config.UpsertCertificateAsync(CertificateMaterial.CreateSelfSigned("mx.egg.test", _f.Protector, _f.Clock.UtcNow), default);
        _f.Clock.Advance(TimeSpan.FromSeconds(125));

        Reply r = await _admin.GetAsync("/api/v1/admin/status");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.False(string.IsNullOrEmpty(r.Str("version")));
        Assert.Equal("memory", r.Str("backend"));
        Assert.Equal("full", r.Str("historyMode"));
        Assert.InRange(r["uptimeSeconds"].GetInt64(), 120, 130);
        Assert.Equal(2, r["queue"].GetProperty("depth").GetInt64());
        Assert.Equal(0, r["queue"].GetProperty("deferred").GetInt64());
        Assert.NotEqual(JsonValueKind.Null, r["queue"].GetProperty("oldestDueAt").ValueKind);
        Assert.True(r["storage"].GetProperty("healthy").GetBoolean());
        Assert.False(string.IsNullOrEmpty(r["storage"].GetProperty("detail").GetString()));
        Assert.Contains(r["storage"].GetProperty("warnings").EnumerateArray(), w => w.GetProperty("code").GetString() == "self_signed_certificate");
        JsonElement cert = Assert.Single(r["certificates"].EnumerateArray());
        Assert.Equal("self_signed", cert.GetProperty("source").GetString());
        Assert.Contains("mx.egg.test", cert.GetProperty("subject").GetString());
        Assert.False(r.Json.TryGetProperty("pressure", out _)); // only backends that can measure it report it
        Assert.Equal("none", r["switch"].GetProperty("state").GetString());
    }

    [Fact]
    public async Task Status_includes_the_pressure_advice_when_the_backend_measures_it()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureServices = s => s.AddSingleton<IStoragePressureSource>(new FixedPressure()) });
        ApiClient admin = await f.SignedInAsync("root");
        JsonElement p = (await admin.GetAsync("/api/v1/admin/status"))["pressure"];
        Assert.Equal(1240, p.GetProperty("writerQueueDepth").GetInt64());
        Assert.Equal(410, p.GetProperty("writerQueueOverThresholdSeconds").GetInt64());
        Assert.Equal(118.5, p.GetProperty("commitP99Ms").GetDouble());
        Assert.True(p.GetProperty("advisory").GetBoolean());
        Assert.False(p.TryGetProperty("queueDepthThreshold", out _)); // optional: a source that does not name its thresholds leaves them out
    }

    [Fact]
    public async Task Status_carries_the_pressure_of_a_real_sqlite_storage()
    {
        string dir = Directory.CreateTempSubdirectory("eggmail-pressure-").FullName;
        try
        {
            await using var sqlite = Mta.Storage.Sqlite.SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = dir, StatsFlushInterval = TimeSpan.Zero } });
            await sqlite.InitializeAsync(default);
            IStoragePressureSource source = Assert.IsType<SqliteStoragePressureSource>(SqliteStoragePressureSource.For(sqlite));
            await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureServices = s => s.AddSingleton(source) });
            ApiClient admin = await f.SignedInAsync("root");
            JsonElement p = (await admin.GetAsync("/api/v1/admin/status"))["pressure"];
            Assert.Equal(0, p.GetProperty("writerQueueDepth").GetInt64());
            Assert.Equal(0, p.GetProperty("writerQueueOverThresholdSeconds").GetInt64());
            Assert.True(p.GetProperty("commitP99Ms").GetDouble() >= 0);
            Assert.False(p.GetProperty("advisory").GetBoolean());
            Assert.Equal(1000, p.GetProperty("queueDepthThreshold").GetInt64()); // the configured thresholds, for the dashboard's labels
            Assert.Equal(300, p.GetProperty("queueThresholdSeconds").GetInt64());
            Assert.Equal(100, p.GetProperty("commitP99ThresholdMs").GetDouble());
            Assert.False(p.TryGetProperty("poolPendingRequests", out _)); // the PostgreSQL figures are left out on SQLite
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task Each_backend_but_memory_has_its_own_pressure_source()
    {
        await using var memory = new Mta.Storage.InMemory.InMemoryStorage(new StorageOptions());
        Assert.Null(SqliteStoragePressureSource.For(memory));
        Assert.Null(PostgresStoragePressureSource.For(memory));
        var pg = new PostgresOptions { RuntimeConnectionString = "Host=127.0.0.1;Port=1;Database=none;Username=none", PressureWindow = TimeSpan.FromMinutes(10), PressureWaitingPercent = 30 };
        await using var postgres = Mta.Storage.Postgres.PostgresStorage.Create(new StorageOptions { Backend = StorageBackend.Postgres, Postgres = pg });
        Assert.Null(SqliteStoragePressureSource.For(postgres));
        IStoragePressureSource source = Assert.IsType<PostgresStoragePressureSource>(PostgresStoragePressureSource.For(postgres));

        // Not initialized (no sampler yet): an empty window with the configured thresholds, never the writer fields of SQLite (decision 109).
        StoragePressure p = source.Get();
        Assert.Null(p.WriterQueueDepth);
        Assert.Null(p.CommitP99Ms);
        Assert.Equal(0, p.PoolSamples);
        Assert.Equal(600, p.PoolWindowSeconds);
        Assert.Equal(30, p.PoolWaitingPercentThreshold);
        Assert.False(p.Advisory);
    }

    private sealed class FixedPoolPressure : IStoragePressureSource
    {
        public StoragePressure Get() => new(null, null, null, true)
        {
            PoolPendingRequests = 6, PoolConnectionsInUse = 32, PoolMaxSize = 32, PoolWaitingPercent = 72.5, PoolSamples = 60, PoolTimeouts = 2, PoolWindowSeconds = 300, PoolWaitingPercentThreshold = 50,
        };
    }

    [Fact]
    public async Task Status_carries_the_pool_figures_of_postgresql_without_the_writer_fields()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureServices = s => s.AddSingleton<IStoragePressureSource>(new FixedPoolPressure()) });
        ApiClient admin = await f.SignedInAsync("root");
        JsonElement p = (await admin.GetAsync("/api/v1/admin/status"))["pressure"];
        Assert.Equal(6, p.GetProperty("poolPendingRequests").GetInt64());
        Assert.Equal(32, p.GetProperty("poolConnectionsInUse").GetInt64());
        Assert.Equal(32, p.GetProperty("poolMaxSize").GetInt64());
        Assert.Equal(72.5, p.GetProperty("poolWaitingPercent").GetDouble());
        Assert.Equal(60, p.GetProperty("poolSamples").GetInt32());
        Assert.Equal(2, p.GetProperty("poolTimeouts").GetInt64());
        Assert.Equal(300, p.GetProperty("poolWindowSeconds").GetInt64());
        Assert.Equal(50, p.GetProperty("poolWaitingPercentThreshold").GetInt32());
        Assert.True(p.GetProperty("advisory").GetBoolean());
        Assert.False(p.TryGetProperty("writerQueueDepth", out _)); // the SQLite figures are left out, not reported as zero
        Assert.False(p.TryGetProperty("commitP99Ms", out _));
    }

    // Global settings

    private static JsonElement Item(Reply r, string key) => r["items"].EnumerateArray().Single(i => i.GetProperty("key").GetString() == key);

    [Fact]
    public async Task Global_settings_show_effective_values_and_lock_what_the_deployment_fixes()
    {
        Reply r = await _admin.GetAsync("/api/v1/admin/settings");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("Full", Item(r, "History:Mode").GetProperty("value").GetString());
        Assert.Equal("enum", Item(r, "History:Mode").GetProperty("type").GetString());
        Assert.Equal(["StatsOnly", "Full"], Item(r, "History:Mode").GetProperty("options").EnumerateArray().Select(o => o.GetString()!));
        Assert.Equal(30, Item(r, "Retention:MetadataDays").GetProperty("value").GetInt32());
        Assert.Equal(5, Item(r, "Queue:MaxLifetimeDays").GetProperty("value").GetInt32());
        Assert.True(Item(r, "Content:RetentionDays").GetProperty("locked").GetBoolean()); // set by the deployment (LockedKeys)
        Assert.True(Item(r, "Sqlite:SyncMode").GetProperty("locked").GetBoolean()); // storage tuning is deployment-only
        Assert.True(Item(r, "Smtp:MaxMessageSize").GetProperty("locked").GetBoolean());
        Assert.False(Item(r, "Retention:MetadataDays").GetProperty("locked").GetBoolean());
        Assert.True(Item(r, "Retention:MetadataDays").GetProperty("requiresRestart").GetBoolean());
    }

    [Fact]
    public async Task Global_settings_can_be_changed_and_are_stored_in_the_config_store()
    {
        Reply put = await _admin.PutAsync("/api/v1/admin/settings", new { values = new Dictionary<string, object> { ["Retention:MetadataDays"] = 0, ["Queue:MaxLifetimeDays"] = 3, ["History:Mode"] = "StatsOnly" } });
        Assert.Equal(HttpStatusCode.OK, put.Status);
        Assert.Equal(0, Item(put, "Retention:MetadataDays").GetProperty("value").GetInt32()); // 0 keeps events forever (decision 28)
        Assert.Equal("StatsOnly", Item(put, "History:Mode").GetProperty("value").GetString());
        var stored = (await _f.Storage.Config.GetSettingsAsync(null, default)).ToDictionary(s => s.Key, s => s.ValueJson);
        Assert.Equal("0", stored["Retention:MetadataDays"]);
        Assert.Equal("3", stored["Queue:MaxLifetimeDays"]);
        Assert.Equal("\"StatsOnly\"", stored["History:Mode"]);
        Assert.Equal(3, Item(await _admin.GetAsync("/api/v1/admin/settings"), "Queue:MaxLifetimeDays").GetProperty("value").GetInt32());
        // Tenant-scoped settings are separate.
        Assert.Empty(await _f.Storage.Config.GetSettingsAsync(ApiFixture.TenantAId, default));
    }

    [Fact]
    public async Task Every_global_setting_is_applied_at_the_next_start_and_none_claims_to_be_live()
    {
        // The API says so for every editable global setting...
        Reply listed = await _admin.GetAsync("/api/v1/admin/settings");
        foreach (JsonElement item in listed["items"].EnumerateArray().Where(i => !i.GetProperty("locked").GetBoolean()))
        {
            Assert.True(item.GetProperty("requiresRestart").GetBoolean(), item.GetProperty("key").GetString() + " would have to be applied live, which no component supports");
        }

        // ...and the stored values really are what the next start reads (the stored-settings layer under the deployment layers).
        var values = new Dictionary<string, object>
        {
            ["History:Mode"] = "StatsOnly",
            ["Retention:MetadataDays"] = 12,
            ["Webhooks:OutboxRetentionDays"] = 4,
            ["Webhooks:AttemptLogDays"] = 5,
            ["Stats:HourlyRetentionDays"] = 6,
            ["Stats:DailyRetentionDays"] = 7,
            ["Content:StoreAttachments"] = true,
            ["Content:AllowAttachmentStorage"] = false,
            ["Queue:MaxLifetimeDays"] = 3,
            ["Sending:GlobalPerHour"] = 11,
            ["Sending:GlobalPerDay"] = 22,
            ["Sending:TenantPerHour"] = 33,
            ["Sending:TenantPerDay"] = 44,
            ["Sending:DomainPerHour"] = 55,
            ["Sending:DomainPerDay"] = 66,
            ["Sending:WarmupEnabled"] = true,
        };
        Assert.Equal(HttpStatusCode.OK, (await _admin.PutAsync("/api/v1/admin/settings", new { values })).Status);

        var stored = await Mta.Host.Configuration.StoredSettings.LoadAsync(_f.Storage.Config, default);
        var loaded = Mta.Host.Configuration.ConfigLoader.Load(Mta.Host.Configuration.ConfigLoader.Build([], dataDirectoryHint: Path.GetTempPath(), storedSettings: stored));
        Assert.True(loaded.IsValid, string.Join("; ", loaded.Errors));
        var c = loaded.Config;
        Assert.Equal(HistoryMode.StatsOnly, c.Storage.History.Mode);
        Assert.Equal((12, 4, 5, 6, 7), (c.Storage.Retention.MetadataDays, c.Storage.Retention.WebhookOutboxDays, c.Storage.Retention.WebhookAttemptLogDays, c.Storage.Retention.StatsHourlyDays, c.Storage.Retention.StatsDailyDays));
        Assert.True(c.Storage.Content.StoreAttachments);
        Assert.False(c.Storage.Content.AllowAttachmentStorage);
        Assert.Equal(TimeSpan.FromDays(3), c.Storage.Queue.MaxLifetime);
        Assert.Equal((11L, 22L, 33L, 44L, 55L, 66L), (c.Sending.GlobalPerHour, c.Sending.GlobalPerDay, c.Sending.TenantPerHour, c.Sending.TenantPerDay, c.Sending.DomainPerHour, c.Sending.DomainPerDay));
        Assert.True(c.Sending.WarmupEnabled);
    }

    [Fact]
    public async Task Invalid_or_locked_global_settings_are_refused_as_a_whole()
    {
        Reply r = await _admin.PutAsync("/api/v1/admin/settings", new { values = new Dictionary<string, object>
        {
            ["Content:RetentionDays"] = 10,
            ["Sqlite:SyncMode"] = "Full",
            ["Retention:MetadataDays"] = -1,
            ["Stats:HourlyRetentionDays"] = "many",
            ["History:Mode"] = "Everything",
            ["Nope"] = true,
        } });
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["Content:RetentionDays", "Sqlite:SyncMode", "Retention:MetadataDays", "Stats:HourlyRetentionDays", "History:Mode", "Nope"], r.ErrorFields);
        Assert.Empty(await _f.Storage.Config.GetSettingsAsync(null, default)); // nothing was applied

        Reply range = await _admin.PutAsync("/api/v1/admin/settings", new { values = new Dictionary<string, object> { ["Queue:MaxLifetimeDays"] = 90 } });
        range.Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task Content_retention_has_no_unlimited_value()
    {
        await using ApiFixture f = await ApiFixture.StartAsync();
        ApiClient admin = await f.SignedInAsync("root");
        foreach (int days in new[] { 0, 5, 31 })
        {
            (await admin.PutAsync("/api/v1/admin/settings", new { values = new Dictionary<string, object> { ["Content:RetentionDays"] = days } })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        }

        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsync("/api/v1/admin/settings", new { values = new Dictionary<string, object> { ["Content:RetentionDays"] = 14 } })).Status);
    }

    // Certificates

    private static (string CertPem, string KeyPem, byte[] Pfx, X509Certificate2 Cert) MakeCertificate(DateTimeOffset notBefore, DateTimeOffset notAfter, string host = "mail.upload.test", bool ec = false)
    {
        AsymmetricAlgorithm key = ec ? ECDsa.Create(ECCurve.NamedCurves.nistP256) : RSA.Create(2048);
        CertificateRequest req = key switch
        {
            RSA rsa => new CertificateRequest("CN=" + host, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ecdsa => new CertificateRequest("CN=" + host, ecdsa, HashAlgorithmName.SHA256),
            _ => throw new InvalidOperationException(),
        };
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(host);
        san.AddDnsName("smtp." + host);
        req.CertificateExtensions.Add(san.Build());
        using X509Certificate2 cert = req.CreateSelfSigned(notBefore, notAfter);
        string certPem = cert.ExportCertificatePem();
        string keyPem = key switch { RSA r => r.ExportPkcs8PrivateKeyPem(), ECDsa e => e.ExportPkcs8PrivateKeyPem(), _ => "" };
        byte[] pfx = cert.Export(X509ContentType.Pfx, "pw");
        var loaded = X509CertificateLoader.LoadPkcs12(pfx, "pw", X509KeyStorageFlags.Exportable);
        key.Dispose();
        return (certPem, keyPem, pfx, loaded);
    }

    [Fact]
    public async Task A_pem_certificate_can_be_uploaded_and_replaces_the_placeholder_self_signed_one()
    {
        await _f.Storage.Config.UpsertCertificateAsync(CertificateMaterial.CreateSelfSigned("mail.upload.test", _f.Protector, _f.Clock.UtcNow), default);
        var (certPem, keyPem, _, cert) = MakeCertificate(_f.Clock.UtcNow.AddDays(-1), _f.Clock.UtcNow.AddDays(90));

        Reply r = await _admin.PostAsync("/api/v1/admin/certificates", new { certificatePem = certPem, privateKeyPem = keyPem });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        Assert.Equal("upload", r.Str("source"));
        Assert.True(r["active"].GetBoolean());
        Assert.Contains("CN=mail.upload.test", r.Str("subject"));
        Assert.Equal(["mail.upload.test", "smtp.mail.upload.test"], r["san"].EnumerateArray().Select(s => s.GetString()!));
        Assert.Equal(cert.Thumbprint, r.Str("thumbprint"));
        Assert.StartsWith("2027-01-10T", r.Str("notAfter"));

        // Stored with its key protected, usable by the TLS provider, and the placeholder no longer serves.
        var records = await _f.Storage.Config.GetCertificatesAsync(default);
        CertificateRecord stored = records.Single(c => c.Source == "upload");
        var (leaf, _) = CertificateMaterial.Load(stored, _f.Protector);
        Assert.True(leaf.HasPrivateKey);
        Assert.Equal(cert.Thumbprint, leaf.Thumbprint);
        Assert.False(records.Single(c => c.Source == "selfsigned").Active);
        Assert.DoesNotContain("PRIVATE KEY", stored.ChainPem);

        Reply list = await _admin.GetAsync("/api/v1/admin/certificates");
        Assert.Equal(["self_signed", "upload"], list.Json.EnumerateArray().Select(c => c.GetProperty("source").GetString()!).Order(StringComparer.Ordinal));
        Assert.DoesNotContain("PRIVATE", list.Body);

        // The same certificate twice is a conflict.
        (await _admin.PostAsync("/api/v1/admin/certificates", new { certificatePem = certPem, privateKeyPem = keyPem })).Problem(HttpStatusCode.Conflict, "conflict");
    }

    [Fact]
    public async Task Ec_pem_and_pfx_uploads_are_supported()
    {
        var (ecCert, ecKey, _, _) = MakeCertificate(_f.Clock.UtcNow.AddDays(-1), _f.Clock.UtcNow.AddDays(90), "ec.upload.test", ec: true);
        Assert.Equal(HttpStatusCode.Created, (await _admin.PostAsync("/api/v1/admin/certificates", new { certificatePem = ecCert, privateKeyPem = ecKey })).Status);

        var (_, _, pfx, cert) = MakeCertificate(_f.Clock.UtcNow.AddDays(-1), _f.Clock.UtcNow.AddDays(90), "pfx.upload.test");
        Reply r = await _admin.PostAsync("/api/v1/admin/certificates", new { pfxBase64 = Convert.ToBase64String(pfx), pfxPassword = "pw" });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        Assert.Equal(cert.Thumbprint, r.Str("thumbprint"));
        Assert.Contains("pfx.upload.test", r["san"].EnumerateArray().Select(s => s.GetString()!));
        foreach (CertificateRecord c in (await _f.Storage.Config.GetCertificatesAsync(default)).Where(c => c.Source == "upload"))
        {
            Assert.True(CertificateMaterial.Load(c, _f.Protector).Leaf.HasPrivateKey);
        }
    }

    [Fact]
    public async Task Bad_certificate_uploads_are_validation_failed()
    {
        var (certPem, keyPem, pfx, _) = MakeCertificate(_f.Clock.UtcNow.AddDays(-1), _f.Clock.UtcNow.AddDays(90));
        var (_, otherKey, _, _) = MakeCertificate(_f.Clock.UtcNow.AddDays(-1), _f.Clock.UtcNow.AddDays(90), "other.test");
        var (expiredPem, expiredKey, _, _) = MakeCertificate(_f.Clock.UtcNow.AddDays(-100), _f.Clock.UtcNow.AddDays(-10), "expired.test");

        (await _admin.PostAsync("/api/v1/admin/certificates", new { })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _admin.PostAsync("/api/v1/admin/certificates", new { certificatePem = certPem })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        Reply mismatch = await _admin.PostAsync("/api/v1/admin/certificates", new { certificatePem = certPem, privateKeyPem = otherKey });
        mismatch.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["privateKeyPem"], mismatch.ErrorFields);
        (await _admin.PostAsync("/api/v1/admin/certificates", new { certificatePem = "not pem", privateKeyPem = keyPem })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _admin.PostAsync("/api/v1/admin/certificates", new { certificatePem = expiredPem, privateKeyPem = expiredKey })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _admin.PostAsync("/api/v1/admin/certificates", new { pfxBase64 = Convert.ToBase64String(pfx), pfxPassword = "wrong" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _admin.PostAsync("/api/v1/admin/certificates", new { pfxBase64 = Convert.ToBase64String(pfx), pfxPassword = "pw", certificatePem = certPem, privateKeyPem = keyPem })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Empty(await _f.Storage.Config.GetCertificatesAsync(default));
    }

    [Fact]
    public async Task Without_acme_configured_a_request_is_not_ready()
    {
        Reply r = await _admin.PostAsync("/api/v1/admin/certificates/acme", new { domains = new[] { "mx.example.com" } });
        r.Problem(HttpStatusCode.ServiceUnavailable, "not_ready");
        Assert.Equal("5", r.Header("Retry-After"));
    }

    [Fact]
    public async Task Acme_domains_are_validated()
    {
        foreach (object domains in new object[] { new string[0], new[] { "not a host" }, new[] { "1.2.3.4" }, new[] { "localhost" }, new[] { "mx.example.com", "*." }, Enumerable.Range(0, 11).Select(i => $"h{i}.example.com").ToArray() })
        {
            Reply r = await _admin.PostAsync("/api/v1/admin/certificates/acme", new { domains });
            r.Problem(HttpStatusCode.BadRequest, "validation_failed");
            Assert.Equal(["domains"], r.ErrorFields.Distinct());
        }

        (await _admin.PostAsync("/api/v1/admin/certificates/acme", new { })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    // Maintenance

    [Fact]
    public async Task Maintenance_runs_in_the_background_and_reports_its_jobs()
    {
        Reply started = await _admin.PostAsync("/api/v1/admin/maintenance/run");
        Assert.Equal(HttpStatusCode.Accepted, started.Status);
        Assert.Contains(started.Str("status"), new[] { "started", "running" });
        await _f.Get<MaintenanceRunner>().Current;

        Reply state = await _admin.GetAsync("/api/v1/admin/maintenance");
        Assert.Equal(HttpStatusCode.OK, state.Status);
        Assert.False(state["running"].GetBoolean());
        Assert.NotEqual(JsonValueKind.Null, state["finishedAt"].ValueKind);
        Assert.Equal(JsonValueKind.Null, state["error"].ValueKind);
        Assert.NotEmpty(state["reports"].EnumerateArray());
        Assert.All(state["reports"].EnumerateArray(), r => Assert.False(string.IsNullOrEmpty(r.GetProperty("job").GetString())));
    }

    // Storage switch

    [Fact]
    public async Task Without_an_engine_the_switch_reports_none_and_every_operation_is_not_ready()
    {
        Reply status = await _admin.GetAsync("/api/v1/admin/storage/switch");
        Assert.Equal(HttpStatusCode.OK, status.Status);
        Assert.Equal("none", status.Str("state"));
        Assert.False(status["available"].GetBoolean());

        object preflight = new { to = "postgres", target = new { host = "db", database = "egg" }, include = new[] { "history" }, mode = "drain" };
        (await _admin.PostAsync("/api/v1/admin/storage/switch/preflight", preflight)).Problem(HttpStatusCode.ServiceUnavailable, "not_ready");
        (await _admin.PostAsync("/api/v1/admin/storage/switch/start", new { to = "postgres", target = new { host = "db", database = "egg" }, include = new[] { "history" }, mode = "drain", exportPassphrase = "a long passphrase", confirmation = "switch to postgres" })).Problem(HttpStatusCode.ServiceUnavailable, "not_ready");
        foreach (string step in new[] { "confirm", "activate", "rollback", "finalize" })
        {
            (await _admin.PostAsync("/api/v1/admin/storage/switch/" + step)).Problem(HttpStatusCode.ServiceUnavailable, "not_ready");
        }
    }

    [Fact]
    public async Task Switch_requests_are_validated_before_they_reach_the_engine()
    {
        Reply sameBackend = await _admin.PostAsync("/api/v1/admin/storage/switch/preflight", new { to = "postgres", target = new { connectionName = "pg" }, include = new[] { "history" }, mode = "drain" });
        // Not yet the engine's business: fields are checked first. The in-memory test backend is neither, so "postgres" is a valid target here.
        sameBackend.Problem(HttpStatusCode.ServiceUnavailable, "not_ready");

        Reply bad = await _admin.PostAsync("/api/v1/admin/storage/switch/preflight", new { to = "oracle", target = new { }, include = new[] { "everything" }, mode = "fast" });
        bad.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["to", "mode", "include"], bad.ErrorFields);
        Reply noTarget = await _admin.PostAsync("/api/v1/admin/storage/switch/preflight", new { to = "postgres", target = new { }, include = new[] { "history" }, mode = "drain" });
        Assert.Equal(["target"], noTarget.ErrorFields);

        Reply drainWithQueue = await _admin.PostAsync("/api/v1/admin/storage/switch/preflight", new { to = "sqlite", target = new { path = "/data2" }, include = new[] { "queue" }, mode = "drain" });
        drainWithQueue.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["include"], drainWithQueue.ErrorFields);

        Reply weakStart = await _admin.PostAsync("/api/v1/admin/storage/switch/start", new { to = "sqlite", target = new { path = "/data2" }, include = new[] { "history" }, mode = "drain", exportPassphrase = "short", confirmation = "yes" });
        weakStart.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["exportPassphrase", "confirmation"], weakStart.ErrorFields);

        (await _admin.PostAsync("/api/v1/admin/storage/switch/preflight", new { to = "postgres", target = new { host = "db" }, include = new string[0], mode = "quiesce" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    private sealed class RecordingSwitchService : IStorageSwitchService
    {
        public List<string> Calls { get; } = [];
        public StorageSwitchException? Throw { get; set; }

        private ValueTask<SwitchStatusReport> Step(string name)
        {
            Calls.Add(name);
            if (Throw is not null)
            {
                throw Throw;
            }

            return ValueTask.FromResult(new SwitchStatusReport(name == "confirm" ? "confirmed" : name, Guid.Parse("c0000000-0000-7000-8000-000000000003"), new SwitchDirection("sqlite", "postgres"), "quiesce", ["queue", "history"],
                new SwitchProgress("done", 100, 10, 10), new SwitchVerifyReport(true, [new SwitchVerifyTable("config.tenants", 2, 2)], true, _now), new SwitchCutoverPatch("environment", "Storage__Backend=Postgres\n"), true, _now, _now));
        }

        private readonly DateTimeOffset _now = new(2026, 10, 12, 12, 30, 0, TimeSpan.Zero);

        public ValueTask<SwitchPreflightReport> PreflightAsync(SwitchRequestModel request, CancellationToken cancellationToken)
        {
            Calls.Add("preflight:" + request.To + ":" + request.Mode + ":" + string.Join('+', request.Include!) + ":" + request.Target!.Host);
            if (Throw is not null)
            {
                throw Throw;
            }

            return ValueTask.FromResult(new SwitchPreflightReport(true, [new PreflightCheckModel("Target reachable", true, "ok", "info")], new PreflightCountsModel(1, 2, 3, 4), new PreflightEstimateModel(60, 1000, true), ["secrets stay"], false));
        }

        public ValueTask<SwitchStatusReport> StartAsync(SwitchStartModel request, CancellationToken cancellationToken)
        {
            Calls.Add("start:" + request.ExportPassphrase);
            return Step("exporting");
        }

        public ValueTask<SwitchStatusReport> GetStatusAsync(CancellationToken cancellationToken) => Step("verified");

        public ValueTask<SwitchStatusReport> ConfirmAsync(CancellationToken cancellationToken) => Step("confirm");

        public ValueTask<SwitchStatusReport> ActivateAsync(CancellationToken cancellationToken) => Step("active");

        public ValueTask<SwitchStatusReport> RollbackAsync(CancellationToken cancellationToken) => Step("rolled_back");

        public ValueTask<SwitchStatusReport> FinalizeAsync(CancellationToken cancellationToken) => Step("finalized");
    }

    [Fact]
    public async Task A_switch_engine_is_driven_through_the_documented_endpoints_and_its_refusals_become_problems()
    {
        var engine = new RecordingSwitchService();
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureServices = s => s.AddSingleton<IStorageSwitchService>(engine) });
        ApiClient admin = await f.SignedInAsync("root");

        Reply pre = await admin.PostAsync("/api/v1/admin/storage/switch/preflight", new { to = "postgres", target = new { host = "db.internal", database = "egg" }, include = new[] { "queue", "history" }, mode = "quiesce" });
        Assert.Equal(HttpStatusCode.OK, pre.Status);
        Assert.True(pre["ok"].GetBoolean());
        Assert.Equal("Target reachable", pre["checks"][0].GetProperty("name").GetString());
        Assert.Equal(1, pre["counts"].GetProperty("queuedMessages").GetInt64());
        Assert.Equal(["secrets stay"], pre["notCarried"].EnumerateArray().Select(x => x.GetString()!));
        Assert.Contains("preflight:postgres:quiesce:queue+history:db.internal", engine.Calls);

        Reply start = await admin.PostAsync("/api/v1/admin/storage/switch/start", new { to = "postgres", target = new { host = "db.internal", database = "egg" }, include = new[] { "queue", "history" }, mode = "quiesce", exportPassphrase = "twelve chars!", confirmation = "switch to postgres" });
        Assert.Equal(HttpStatusCode.Accepted, start.Status);
        Assert.Equal("exporting", start.Str("state"));
        Assert.Equal("postgres", start["direction"].GetProperty("to").GetString());
        Assert.Equal(100, start["progress"].GetProperty("percent").GetInt32());
        Assert.Equal("Storage__Backend=Postgres\n", start["cutoverPatch"].GetProperty("text").GetString());
        Assert.DoesNotContain("twelve chars!", start.Body); // the passphrase is never echoed

        foreach (var (step, state) in new[] { ("confirm", "confirmed"), ("activate", "active"), ("rollback", "rolled_back"), ("finalize", "finalized") })
        {
            Assert.Equal(state, (await admin.PostAsync("/api/v1/admin/storage/switch/" + step)).Str("state"));
        }

        Assert.Equal("verified", (await admin.GetAsync("/api/v1/admin/storage/switch")).Str("state"));

        engine.Throw = new StorageSwitchException(StorageSwitchError.InvalidState, "Cannot activate: the switch is in state \"exporting\".");
        (await admin.PostAsync("/api/v1/admin/storage/switch/activate")).Problem(HttpStatusCode.Conflict, "conflict");
        engine.Throw = new StorageSwitchException(StorageSwitchError.Invalid, "No such connection.", "target.connectionName");
        Reply invalid = await admin.PostAsync("/api/v1/admin/storage/switch/preflight", new { to = "postgres", target = new { host = "db", database = "egg" }, include = new[] { "history" }, mode = "drain" });
        invalid.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["target.connectionName"], invalid.ErrorFields);
        engine.Throw = new StorageSwitchException(StorageSwitchError.NotReady, "Target unreachable.");
        (await admin.GetAsync("/api/v1/admin/storage/switch")).Problem(HttpStatusCode.ServiceUnavailable, "not_ready");
    }

    [Fact]
    public async Task The_admin_status_shows_the_engines_state()
    {
        var engine = new RecordingSwitchService();
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureServices = s => s.AddSingleton<IStorageSwitchService>(engine) });
        ApiClient admin = await f.SignedInAsync("root");
        Assert.Equal("verified", (await admin.GetAsync("/api/v1/admin/status"))["switch"].GetProperty("state").GetString());
    }
}

/// <summary>ACME requests through the real requester and renewal service, with a fake certificate authority.</summary>
[Collection("api")]
public class ApiAcmeTests : IAsyncLifetime
{
    private sealed class FakeAuthority(TestClock clock) : IAcmeOrderRunner
    {
        public List<AcmeOrderRequest> Orders { get; } = [];
        public TaskCompletionSource? Gate { get; set; }

        public async Task<AcmeIssuedCertificate> IssueAsync(AcmeOrderRequest request, IDnsChallengeProvider dns, CancellationToken cancellationToken)
        {
            Orders.Add(request);
            if (Gate is not null)
            {
                await Gate.Task.ConfigureAwait(false);
            }

            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var req = new CertificateRequest("CN=" + request.Domains[0], key, HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();
            foreach (string d in request.Domains)
            {
                san.AddDnsName(d);
            }

            req.CertificateExtensions.Add(san.Build());
            using X509Certificate2 cert = req.CreateSelfSigned(clock.UtcNow.AddMinutes(-5), clock.UtcNow.AddDays(90));
            return new AcmeIssuedCertificate(cert.ExportCertificatePem(), key.ExportPkcs8PrivateKey(), "-----BEGIN PRIVATE KEY-----\nQUNNRQ==\n-----END PRIVATE KEY-----", "https://acme.test/acct/1", cert.NotAfter.ToUniversalTime());
        }
    }

    private sealed class NoDns : IDnsChallengeProvider
    {
        public ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken cancellationToken) => ValueTask.FromResult("h");

        public ValueTask DeleteTxtAsync(string handle, CancellationToken cancellationToken) => ValueTask.CompletedTask;
    }

    private ApiFixture _f = null!;
    private ApiClient _admin = null!;
    private FakeAuthority _authority = null!;

    public async Task InitializeAsync()
    {
        FakeAuthority? authority = null;
        _f = await ApiFixture.StartAsync(new ApiFixtureOptions
        {
            ConfigureServices = s => s.AddSingleton(sp =>
            {
                authority = new FakeAuthority((TestClock)sp.GetRequiredService<IClock>());
                return new AcmeRenewalService(
                    sp.GetRequiredService<IStorage>().Config, sp.GetRequiredService<ISecretProtector>(), authority, new NoDns(),
                    new AcmeSection { Enabled = true, Email = "ops@egg.test", Domains = ["mx.egg.test"], PropagationDelay = TimeSpan.Zero }, sp.GetRequiredService<IClock>());
            }),
        });
        _admin = await _f.SignedInAsync("root");
        _ = _f.Get<AcmeRenewalService>();
        _authority = authority!;
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    [Fact]
    public async Task A_requested_certificate_is_ordered_in_the_background_and_stored()
    {
        Reply r = await _admin.PostAsync("/api/v1/admin/certificates/acme", new { domains = new[] { "Shop.Example.com", "www.shop.example.com" } });
        Assert.Equal(HttpStatusCode.Accepted, r.Status);
        Assert.Equal("pending", r.Str("status"));
        await ((AcmeCertificateRequester)_f.Get<IAcmeCertificateRequester>()).Current;

        AcmeOrderRequest order = Assert.Single(_authority.Orders);
        Assert.Equal(["shop.example.com", "www.shop.example.com"], order.Domains);
        Assert.Equal("ops@egg.test", order.Email);

        Reply list = await _admin.GetAsync("/api/v1/admin/certificates");
        JsonElement cert = Assert.Single(list.Json.EnumerateArray());
        Assert.Equal("acme", cert.GetProperty("source").GetString());
        Assert.StartsWith("acme:shop.example.com+", cert.GetProperty("name").GetString()); // several names: a short hash of the set follows
        Assert.Equal(["shop.example.com", "www.shop.example.com"], cert.GetProperty("san").EnumerateArray().Select(s => s.GetString()!));
        Assert.True(cert.GetProperty("active").GetBoolean());

        Reply renewals = await _admin.GetAsync("/api/v1/admin/certificates/acme");
        Assert.Equal("issued", renewals.Json[0].GetProperty("status").GetString());
        Assert.StartsWith("acme:shop.example.com+", renewals.Json[0].GetProperty("certificateName").GetString());
    }

    [Fact]
    public async Task Only_one_order_runs_at_a_time()
    {
        _authority.Gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Assert.Equal(HttpStatusCode.Accepted, (await _admin.PostAsync("/api/v1/admin/certificates/acme", new { domains = new[] { "a.example.com" } })).Status);
        (await _admin.PostAsync("/api/v1/admin/certificates/acme", new { domains = new[] { "b.example.com" } })).Problem(HttpStatusCode.Conflict, "conflict");
        _authority.Gate.SetResult();
        await ((AcmeCertificateRequester)_f.Get<IAcmeCertificateRequester>()).Current;
        Assert.Equal(HttpStatusCode.Accepted, (await _admin.PostAsync("/api/v1/admin/certificates/acme", new { domains = new[] { "b.example.com" } })).Status);
    }

    [Fact]
    public async Task Requested_certificates_are_renewed_with_the_configured_one()
    {
        await _admin.PostAsync("/api/v1/admin/certificates/acme", new { domains = new[] { "shop.example.com" } });
        await ((AcmeCertificateRequester)_f.Get<IAcmeCertificateRequester>()).Current;
        var service = _f.Get<AcmeRenewalService>();

        Assert.True(await service.CheckOnceAsync(default)); // the configured certificate (mx.egg.test) does not exist yet
        Assert.Equal(["shop.example.com"], _authority.Orders[0].Domains);
        Assert.Equal(["mx.egg.test"], _authority.Orders[1].Domains);
        Assert.False(await service.CheckOnceAsync(default)); // both fresh

        _f.Clock.Advance(TimeSpan.FromDays(65));
        Assert.True(await service.CheckOnceAsync(default));
        Assert.Equal(4, _authority.Orders.Count);
        Assert.Equal(["mx.egg.test", "shop.example.com"], _authority.Orders.Skip(2).Select(o => o.Domains[0]).Order(StringComparer.Ordinal));
        Assert.Equal(2, (await _f.Storage.Config.GetCertificatesAsync(default)).Count(c => c.Active));
    }

    [Fact]
    public async Task Different_sets_of_names_never_replace_each_other()
    {
        var requester = (AcmeCertificateRequester)_f.Get<IAcmeCertificateRequester>();
        await _admin.PostAsync("/api/v1/admin/certificates/acme", new { domains = new[] { "a.example.com", "b.example.com" } });
        await requester.Current;
        await _admin.PostAsync("/api/v1/admin/certificates/acme", new { domains = new[] { "a.example.com", "c.example.com" } });
        await requester.Current;
        var certs = await _f.Storage.Config.GetCertificatesAsync(default);
        Assert.Equal(2, certs.Count(c => c.Active));
        Assert.Equal(2, certs.Select(c => c.Name).Distinct().Count());
    }

    [Fact]
    public async Task Requesting_the_configured_names_renews_the_configured_certificate()
    {
        await _admin.PostAsync("/api/v1/admin/certificates/acme", new { domains = new[] { "mx.egg.test" } });
        await ((AcmeCertificateRequester)_f.Get<IAcmeCertificateRequester>()).Current;
        Assert.Equal(["default"], (await _f.Storage.Config.GetCertificatesAsync(default)).Select(c => c.Name));
    }
}
