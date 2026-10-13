using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Ingest;
using Mta.Host.Security;
using Mta.Host.Submission;
using Mta.Policy;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests;

/// <summary>
/// Whether the raw message with its attachments is kept (design section 5): the per-send flag, then the tenant's setting, then the global default,
/// behind the master switch; SMTP has no per-send flag. A tenant that chose "no" overrides a global "yes".
/// </summary>
public class AttachmentStoragePrecedenceTests : IAsyncLifetime
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    private InMemoryStorage _storage = null!;

    public async Task InitializeAsync()
    {
        _storage = new InMemoryStorage(new StorageOptions());
        await _storage.InitializeAsync(default);
        var now = DateTimeOffset.UtcNow;
        await _storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, now, false), default);
        await _storage.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), TenantId, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
    }

    public async Task DisposeAsync() => await _storage.DisposeAsync();

    internal static byte[] MessageWithAttachment()
    {
        var m = new MimeMessage();
        m.From.Add(MailboxAddress.Parse("news@example.org"));
        m.To.Add(MailboxAddress.Parse("rcpt@dest.example"));
        m.Subject = "With a file";
        var body = new BodyBuilder { TextBody = "see attached" };
        body.Attachments.Add("a.bin", [1, 2, 3, 4], new ContentType("application", "octet-stream"));
        m.Body = body.ToMessageBody();
        using var ms = new MemoryStream();
        m.WriteTo(new FormatOptions { NewLineFormat = NewLineFormat.Dos }, ms);
        return ms.ToArray();
    }

    private async Task SetTenantAsync(bool? choice, bool legacyColumn = false)
    {
        if (choice is { } c)
        {
            await _storage.Config.SetSettingAsync(new SettingRecord(AttachmentStoragePolicy.StoreAttachmentsKey, TenantId, c ? "true" : "false", DateTimeOffset.UtcNow), default);
        }

        if (legacyColumn)
        {
            await _storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, DateTimeOffset.UtcNow, true), default);
        }
    }

    private async Task<bool> IsRawRetainedAsync(MessageSource source, bool? perSendFlag, bool globalDefault, bool masterSwitch)
    {
        var options = new StorageOptions { Content = new ContentOptions { AllowAttachmentStorage = masterSwitch, StoreAttachments = globalDefault } };
        var submission = new SubmissionService(_storage, SystemClock.Instance, new SenderPolicy(), options, new SubmissionOptions { MessageIdDomain = "egg.test" });
        Tenant tenant = (await _storage.Config.GetTenantAsync(TenantId, default))!;
        SubmissionResult result = await submission.SubmitAsync(new SubmissionRequest
        {
            Tenant = tenant,
            Source = source,
            EnvelopeFrom = EmailAddress.Parse("news@example.org"),
            Recipients = [EmailAddress.Parse("rcpt@dest.example")],
            Message = MessageWithAttachment(),
            StoreAttachments = perSendFlag,
        }, default);
        Assert.True(result.IsAccepted, result.Detail);
        foreach (ClaimedDelivery d in await _storage.Deliveries.ClaimAsync("t", 10, DateTimeOffset.UtcNow.AddSeconds(1), TimeSpan.FromMinutes(1), default))
        {
            await _storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = DateTimeOffset.UtcNow, SmtpCode = 250 }, default);
        }

        return (await _storage.History.GetAsync(TenantId, result.MessageId, default))!.RawRetained;
    }

    [Theory]
    // source, per-send flag, tenant choice, global default, master switch -> kept
    [InlineData(MessageSource.Smtp, null, null, false, true, false)]    // nobody asked: not kept
    [InlineData(MessageSource.Smtp, null, null, true, true, true)]      // the tenant never chose: the global default applies
    [InlineData(MessageSource.Smtp, null, true, false, true, true)]     // SMTP uses the tenant's setting
    [InlineData(MessageSource.Smtp, null, false, true, true, false)]    // a tenant that chose "no" overrides a global "yes"
    [InlineData(MessageSource.Api, null, false, true, true, false)]     // the same on the API (this was `tenant || global`)
    [InlineData(MessageSource.Api, null, true, false, true, true)]
    [InlineData(MessageSource.Api, true, false, false, true, true)]     // the per-send flag beats the tenant's setting...
    [InlineData(MessageSource.Api, false, true, true, true, false)]     // ...in both directions
    [InlineData(MessageSource.Api, null, true, true, false, false)]     // the master switch decides first
    [InlineData(MessageSource.Smtp, null, true, true, false, false)]
    public async Task The_precedence_is_per_send_then_tenant_then_global_behind_the_master_switch(MessageSource source, bool? perSend, bool? tenantChoice, bool global, bool master, bool kept)
    {
        await SetTenantAsync(tenantChoice);
        Assert.Equal(kept, await IsRawRetainedAsync(source, perSend, global, master));
    }

    [Fact]
    public async Task A_tenant_that_only_has_the_older_column_set_to_true_counts_as_having_chosen_yes()
    {
        await SetTenantAsync(choice: null, legacyColumn: true);
        Assert.True(await IsRawRetainedAsync(MessageSource.Smtp, null, globalDefault: false, masterSwitch: true));
    }

    [Fact]
    public void TenantSetting_distinguishes_not_chosen_from_chosen_no()
    {
        var tenant = new Tenant(TenantId, "Acme", "acme", true, DateTimeOffset.UtcNow, false);
        Assert.Null(AttachmentStoragePolicy.TenantSetting(tenant, []));
        Assert.False(AttachmentStoragePolicy.TenantSetting(tenant, [new SettingRecord(AttachmentStoragePolicy.StoreAttachmentsKey, TenantId, "false", DateTimeOffset.UtcNow)]));
        Assert.Null(AttachmentStoragePolicy.TenantSetting(tenant, [new SettingRecord(AttachmentStoragePolicy.StoreAttachmentsKey, Guid.NewGuid(), "true", DateTimeOffset.UtcNow)]));   // another tenant's row
        Assert.Null(AttachmentStoragePolicy.TenantSetting(tenant, [new SettingRecord(AttachmentStoragePolicy.StoreAttachmentsKey, TenantId, "\"yes\"", DateTimeOffset.UtcNow)]));   // not a boolean: ignored
    }
}

/// <summary>The tenant setting as the settings API writes it, end to end through the sending API.</summary>
[Collection("api")]
public class AttachmentStorageApiTests
{
    private static JsonElement Item(Mta.Host.Tests.Api.Reply r, string key) => r["items"].EnumerateArray().Single(i => i.GetProperty("key").GetString() == key);

    private static async Task<bool> SendAndCheckRetainedAsync(Mta.Host.Tests.Api.ApiFixture f, Mta.Host.Tests.Api.ApiClient key, bool? perSend, string from = "a@example.com")
    {
        var body = new Dictionary<string, object?>
        {
            ["from"] = from,
            ["to"] = new[] { "x@gmail.test" },
            ["subject"] = "s",
            ["text"] = "t",
            ["attachments"] = new[] { new { filename = "a.bin", content_type = "application/octet-stream", content = Convert.ToBase64String([1, 2, 3]) } },
        };
        if (perSend is { } flag)
        {
            body["store_attachments"] = flag;
        }

        Mta.Host.Tests.Api.Reply sent = await key.PostAsync("/api/v1/messages", body);
        foreach (ClaimedDelivery d in await f.Storage.Deliveries.ClaimAsync("t", 10, f.Clock.UtcNow, TimeSpan.FromMinutes(1), default))
        {
            await f.Storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = f.Clock.UtcNow, SmtpCode = 250 }, default);
        }

        return (await key.GetAsync("/api/v1/messages/" + sent.Str("id")))["rawRetained"].GetBoolean();
    }

    [Fact]
    public async Task A_tenant_that_switched_storing_off_overrides_the_operator_default_and_one_that_never_chose_inherits_it()
    {
        await using var f = await Mta.Host.Tests.Api.ApiFixture.StartAsync(new Mta.Host.Tests.Api.ApiFixtureOptions { StoreAttachmentsByDefault = true });
        var alice = await f.SignedInAsync("alice");      // tenant A
        var keyA = await f.KeyClientAsync(Mta.Host.Tests.Api.ApiFixture.TenantAId);
        var keyB = await f.KeyClientAsync(Mta.Host.Tests.Api.ApiFixture.TenantBId);

        // Nobody chose anything: the operator default (store) applies, and the settings page shows what is in force.
        Assert.True(Item(await alice.GetAsync("/api/v1/settings"), "Content:StoreAttachments").GetProperty("value").GetBoolean());
        Assert.True(await SendAndCheckRetainedAsync(f, keyA, perSend: null));

        // Tenant A turns it off: its sends are no longer kept, tenant B (never chose) still inherits the default.
        var put = await alice.PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { ["Content:StoreAttachments"] = false } });
        Assert.False(Item(put, "Content:StoreAttachments").GetProperty("value").GetBoolean());
        Assert.False(await SendAndCheckRetainedAsync(f, keyA, perSend: null));
        Assert.True(await SendAndCheckRetainedAsync(f, keyB, perSend: null, from: "b@globex.test"));

        // The per-send flag still wins over the tenant's choice.
        Assert.True(await SendAndCheckRetainedAsync(f, keyA, perSend: true));
    }

    [Fact]
    public async Task A_tenant_can_turn_storing_on_while_the_operator_default_is_off()
    {
        await using var f = await Mta.Host.Tests.Api.ApiFixture.StartAsync(new Mta.Host.Tests.Api.ApiFixtureOptions { StoreAttachmentsByDefault = false });
        var alice = await f.SignedInAsync("alice");
        var keyA = await f.KeyClientAsync(Mta.Host.Tests.Api.ApiFixture.TenantAId);
        Assert.False(await SendAndCheckRetainedAsync(f, keyA, perSend: null));

        await alice.PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { ["Content:StoreAttachments"] = true } });

        Assert.True(await SendAndCheckRetainedAsync(f, keyA, perSend: null));
    }
}

/// <summary>SMTP submissions follow the tenant's setting (they have no per-send flag).</summary>
[Collection("CpuHeavy")]
public class AttachmentStorageSmtpTests : IAsyncLifetime
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    private sealed class SelfSigned : IServerCertificateProvider
    {
        private readonly X509Certificate2 _cert;

        public SelfSigned()
        {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var temp = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            _cert = X509CertificateLoader.LoadPkcs12(temp.Export(X509ContentType.Pfx, "x"), "x", X509KeyStorageFlags.Exportable);
        }

        public X509Certificate2? GetCertificate(string? serverName) => _cert;
    }

    private InMemoryStorage _storage = null!;
    private SmtpServer _server = null!;
    private int _port;

    public async Task InitializeAsync()
    {
        _storage = new InMemoryStorage(new StorageOptions());
        await _storage.InitializeAsync(default);
        var now = DateTimeOffset.UtcNow;
        await _storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, now, false), default);
        await _storage.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), TenantId, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        await _storage.Config.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), TenantId, "acme-user", PasswordHasher.Hash("s3cret", 2000), true, now), default);

        // The operator allows attachment storage and defaults it to on.
        var options = new StorageOptions { Content = new ContentOptions { AllowAttachmentStorage = true, StoreAttachments = true } };
        var submission = new SubmissionService(_storage, SystemClock.Instance, new SenderPolicy(), options, new SubmissionOptions { MessageIdDomain = "egg.test" });
        var handler = new IngestHandler(_storage, submission, new AuthThrottle(), new IngestOptions());
        _server = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "egg.test",
            Certificates = new SelfSigned(),
            AuthFailureDelay = TimeSpan.Zero,
            Listeners = [new SmtpListenerOptions { Name = "submission", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.StartTls, AuthRequired = true }],
        }, handler);
        _server.Start();
        _port = _server.LocalEndPoints["submission"].Port;
    }

    public async Task DisposeAsync()
    {
        await _server.DisposeAsync();
        await _storage.DisposeAsync();
    }

    private async Task<bool> SendAndCheckRetainedAsync()
    {
        using var client = new SmtpClient { CheckCertificateRevocation = false, ServerCertificateValidationCallback = (_, _, _, _) => true };
        await client.ConnectAsync("127.0.0.1", _port, SecureSocketOptions.StartTls);
        await client.AuthenticateAsync("acme-user", "s3cret");
        using var ms = new MemoryStream(AttachmentStoragePrecedenceTests.MessageWithAttachment());
        await client.SendAsync(MimeMessage.Load(ms));

        var claimed = await _storage.Deliveries.ClaimAsync("t", 10, DateTimeOffset.UtcNow.AddSeconds(1), TimeSpan.FromMinutes(1), default);
        foreach (ClaimedDelivery d in claimed)
        {
            await _storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = DateTimeOffset.UtcNow, SmtpCode = 250 }, default);
        }

        return (await _storage.History.GetAsync(TenantId, claimed.Single().MessageId, default))!.RawRetained;
    }

    [Fact]
    public async Task An_smtp_submission_follows_the_tenant_setting_and_inherits_the_operator_default_when_the_tenant_never_chose()
    {
        Assert.True(await SendAndCheckRetainedAsync());   // never chose: the operator default (on) applies

        await _storage.Config.SetSettingAsync(new SettingRecord(SettingsService.StoreAttachmentsKey, TenantId, "false", DateTimeOffset.UtcNow), default);
        Assert.False(await SendAndCheckRetainedAsync());  // the tenant chose "no": it overrides the operator default
    }
}
