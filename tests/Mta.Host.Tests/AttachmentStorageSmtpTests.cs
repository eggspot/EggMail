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
        AttachmentStoragePolicy.Bump();   // what the settings service does, so the submission cache does not serve the old choice
        Assert.False(await SendAndCheckRetainedAsync());  // the tenant chose "no": it overrides the operator default
    }
}
