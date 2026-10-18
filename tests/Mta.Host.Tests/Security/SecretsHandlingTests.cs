using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Host.Secrets;
using Mta.Host.Tests.Api;
using Mta.Storage;

namespace Mta.Host.Tests.Security;

/// <summary>
/// Security regression tests for secret handling (docs/security-test-map.md, SECRET-*): after the flows that create, use, rotate and fail with every kind
/// of secret the API handles, the log, every API response and the stored database hold none of the secret values. Real Data Protection, a capturing
/// logger, the SQLite files read as bytes. The in-house review, not an independent audit.
/// </summary>
[Collection("api")]
public class SecretsHandlingTests : IAsyncLifetime
{
    private readonly CapturingLoggerProvider _logs = new();
    private ApiFixture _f = null!;
    private ISecretProtector _real = null!;

    // Distinctive values: a hit in a log or a file cannot be a coincidence.
    private const string AdminPassword = "ADMIN-PASSWORD-q7Zk2mV9xW4c";
    private const string TenantPassword = "TENANT-PASSWORD-h3Rt8nB5yL1d";
    private const string WrongPassword = "WRONG-PASSWORD-f6Gj0sP2uA7e";
    private const string NewPassword = "NEW-PASSWORD-z9Xc4vK8mQ3w";
    private const string RelayPassword = "RELAY-PASSWORD-d2Hn7bT1eY6r";
    private const string CertificateKeyMarker = "PRIVATE KEY";

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync(new ApiFixtureOptions
        {
            Sqlite = true,
            ConfigureApi = o => o.PasswordHashIterations = 1000,
            ConfigureServices = s =>
            {
                s.AddSingleton<ILoggerProvider>(_logs);
                // The product's protector (Data Protection with its key ring in the config store) instead of the reversible one of the other API tests.
                s.AddSingleton<ISecretProtector>(sp => SecretsFactory.Create(new SecretsSection(), sp.GetRequiredService<IStorage>().Config));
            },
        });
        _real = _f.Get<ISecretProtector>();
        await Task.CompletedTask;
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    [Fact]
    public async Task No_secret_the_API_creates_uses_or_receives_is_written_to_the_log_returned_again_or_stored_readable()
    {
        var secrets = new List<(string Name, string Value)>();
        ApiClient root = await _f.SignedInAsync("root");
        ApiClient alice = await _f.SignedInAsync("alice");
        string tenantA = ApiFixture.TenantAId.ToString("N");

        // Users: created with a password, reset, changed, failed sign-ins.
        Reply user = await root.PostAsync("/api/v1/admin/users", new { userName = "carol", role = "tenant", tenantId = tenantA, password = TenantPassword });
        Assert.Equal(HttpStatusCode.Created, user.Status);
        secrets.Add(("tenant user password", TenantPassword));
        Assert.Equal(HttpStatusCode.OK, (await root.PostAsync($"/api/v1/admin/users/{user.Str("id")}/reset-password", new { password = NewPassword })).Status);
        secrets.Add(("reset password", NewPassword));
        for (int i = 0; i < 3; i++)
        {
            await _f.NewClient().SignInAsync("carol", WrongPassword + i);
        }

        secrets.Add(("wrong password", WrongPassword));
        await alice.PostAsync("/api/v1/me/password", new { currentPassword = WrongPassword, newPassword = AdminPassword });
        secrets.Add(("password typed as new", AdminPassword));
        Reply generated = await root.PostAsync("/api/v1/admin/users", new { userName = "dave", role = "tenant", tenantId = tenantA });
        secrets.Add(("generated user password", generated.Str("password")));

        // API keys: created, used, used wrongly, revoked.
        Reply key = await alice.PostAsync("/api/v1/api-keys", new { name = "ci", scopes = new[] { "read", "send", "webhooks" } });
        string token = key.Str("key");
        secrets.Add(("api key", token));
        secrets.Add(("api key secret part", token[(token.LastIndexOf('_') + 1)..]));
        ApiClient viaKey = _f.NewClient().WithBearer(token);
        Assert.Equal(HttpStatusCode.OK, (await viaKey.GetAsync("/api/v1/messages")).Status);
        await _f.NewClient().WithBearer(token[..^3] + "AAA").GetAsync("/api/v1/messages");   // a near miss
        await _f.NewClient().WithBearer("egm_AAAAAAAA_" + token[(token.LastIndexOf('_') + 1)..]).GetAsync("/api/v1/messages");   // right secret, wrong id
        await alice.DeleteAsync("/api/v1/api-keys/" + key.Str("id"));
        await viaKey.GetAsync("/api/v1/messages");

        // SMTP credential: a generated password.
        Reply smtp = await alice.PostAsync("/api/v1/smtp-credentials", new { username = "mailer" });
        secrets.Add(("smtp password", smtp.Str("password")));

        // Webhook: a signing secret, rotated, and a test event.
        Reply hook = await alice.PostAsync("/api/v1/webhooks", new { url = "https://hooks.example.com/x", event_types = new[] { "*" } });
        secrets.Add(("webhook secret", hook.Str("secret")));
        Reply rotated = await alice.PostAsync($"/api/v1/webhooks/{hook.Str("id")}/rotate-secret");
        secrets.Add(("rotated webhook secret", rotated.Str("secret")));
        await alice.PostAsync($"/api/v1/webhooks/{hook.Str("id")}/test");

        // A relay with a login, edited, and a failed edit.
        Reply relay = await root.PostAsync("/api/v1/admin/relay-routes", new { name = "smarthost", host = "smtp.relay.example", tlsMode = "starttls", userName = "relay-user", password = RelayPassword, domains = new[] { "a.example" } });
        Assert.Equal(HttpStatusCode.Created, relay.Status);
        secrets.Add(("relay password", RelayPassword));
        await root.PatchAsync("/api/v1/admin/relay-routes/" + relay.Str("id"), new { priority = 5 });
        await root.PatchAsync("/api/v1/admin/relay-routes/" + relay.Str("id"), new { host = "not a host", password = RelayPassword });

        // A certificate and its private key, a domain (a DKIM key pair is made), a rotation.
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=mail.secrets.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 cert = req.CreateSelfSigned(_f.Clock.UtcNow.AddDays(-1), _f.Clock.UtcNow.AddDays(90));
        string keyPem = rsa.ExportPkcs8PrivateKeyPem();
        Assert.Equal(HttpStatusCode.Created, (await root.PostAsync("/api/v1/admin/certificates", new { certificatePem = cert.ExportCertificatePem(), privateKeyPem = keyPem })).Status);
        secrets.Add(("certificate private key", Convert.ToBase64String(rsa.ExportPkcs8PrivateKey())[..64]));
        Reply domain = await alice.PostAsync("/api/v1/domains", new { name = "secrets.example" });
        await alice.PostAsync($"/api/v1/domains/{domain.Str("id")}/dkim/rotate");
        foreach (DkimKeyRecord dkim in await _f.Storage.Config.GetDkimKeysAsync(Guid.Parse(domain.Str("id")), default))
        {
            byte[] pkcs8 = _real.Unprotect(dkim.PrivateKeyProtected, SecretPurposes.DkimKey);
            secrets.Add(("dkim private key", Convert.ToBase64String(pkcs8)[..64]));
        }

        // Every GET route, as the owner of the secrets, must not show them again.
        var bodies = new List<string> { generated.Body[..generated.Body.IndexOf("\"password\"", StringComparison.Ordinal)] };
        foreach (ApiRoute route in ApiRouteTable.Of(_f).Where(r => r.Method == "GET" && !r.Pattern.Contains("{", StringComparison.Ordinal)))
        {
            ApiClient caller = route.Policy == AccessPolicy.Admin ? root : alice;
            Reply reply = await caller.GetAsync(route.Pattern);
            bodies.Add(reply.Body);
        }

        bodies.Add((await alice.GetAsync($"/api/v1/domains/{domain.Str("id")}/records")).Body);
        bodies.Add((await alice.GetAsync($"/api/v1/webhooks/{hook.Str("id")}")).Body);
        bodies.Add((await root.GetAsync("/api/v1/admin/relay-routes/" + relay.Str("id"))).Body);
        string allBodies = string.Join('\n', bodies);
        Assert.DoesNotContain(CertificateKeyMarker, allBodies, StringComparison.Ordinal);
        Assert.DoesNotContain("pbkdf2", allBodies, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("passwordHash", allBodies, StringComparison.Ordinal);

        string log = string.Join('\n', _logs.Lines);
        Assert.Contains("Dashboard user created", log, StringComparison.Ordinal);   // the capture works: these flows do log
        foreach (var (name, value) in secrets)
        {
            Assert.False(log.Contains(value, StringComparison.Ordinal), $"the log contains the {name}");
            Assert.False(allBodies.Contains(value, StringComparison.Ordinal), $"a GET response contains the {name}");
        }

        Assert.DoesNotContain(CertificateKeyMarker, log, StringComparison.Ordinal);
        Assert.DoesNotContain("Bearer ", log, StringComparison.Ordinal);
        Assert.DoesNotContain("egm_", log, StringComparison.Ordinal);       // not even the public prefix of a key presented to the server
        Assert.DoesNotContain("whsec_", log, StringComparison.Ordinal);

        // At rest: the SQLite files, read as bytes, hold none of them in the clear. (Passwords and keys are stored as digests; the others protected.)
        await _f.Storage.DisposeAsync();
        string dir = _f.StorageOptions.Sqlite.DataDirectory!;
        var files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).ToList();
        Assert.NotEmpty(files);
        foreach (string file in files)
        {
            byte[] bytes = await File.ReadAllBytesAsync(file);
            foreach (var (name, value) in secrets)
            {
                Assert.False(bytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes(value)) >= 0, $"{Path.GetFileName(file)} holds the {name} in the clear");
            }

            Assert.False(bytes.AsSpan().IndexOf("-----BEGIN PRIVATE KEY-----"u8) >= 0, $"{Path.GetFileName(file)} holds a PEM private key");
        }
    }

    [Fact]
    public async Task Secrets_are_stored_protected_by_the_real_data_protection_with_one_purpose_per_kind()
    {
        // With the test protector a "protected" value is readable; this one uses the product's protector over the same store.
        ApiClient alice = await _f.SignedInAsync("alice");
        Reply hook = await alice.PostAsync("/api/v1/webhooks", new { url = "https://hooks.example.com/x", event_types = new[] { "*" } });
        string secret = hook.Str("secret");
        WebhookEndpointRecord stored = (await _f.Storage.Config.GetWebhookEndpointsAsync(ApiFixture.TenantAId, default)).Single();

        byte[] protectedByProduct = stored.SecretProtected;
        Assert.DoesNotContain(secret, Encoding.UTF8.GetString(protectedByProduct), StringComparison.Ordinal);
        Assert.DoesNotContain("whsec", Encoding.UTF8.GetString(protectedByProduct), StringComparison.Ordinal);
        Assert.DoesNotContain(secret, Encoding.UTF8.GetString(protectedByProduct), StringComparison.Ordinal);
        Assert.Equal(secret, Encoding.UTF8.GetString(_real.Unprotect(protectedByProduct, SecretPurposes.WebhookSecret)));
        Assert.ThrowsAny<CryptographicException>(() => _real.Unprotect(protectedByProduct, SecretPurposes.DkimKey));          // another kind of secret cannot open it
        Assert.ThrowsAny<CryptographicException>(() => _real.Unprotect(protectedByProduct, SecretPurposes.RelayPassword));
        Assert.ThrowsAny<CryptographicException>(() => _real.Unprotect(protectedByProduct, SecretPurposes.TlsPrivateKey));
        byte[] tampered = (byte[])protectedByProduct.Clone();
        tampered[^1] ^= 0x01;
        Assert.ThrowsAny<CryptographicException>(() => _real.Unprotect(tampered, SecretPurposes.WebhookSecret));
        Assert.NotEmpty(stored.SecretProtected);
    }
}
