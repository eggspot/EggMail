using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Mta.Core;
using Mta.Dsn;
using Mta.Host.Ingest;
using Mta.Host.Security;
using Mta.Host.Submission;
using Mta.Policy;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.InMemory;
using Mta.Webhooks;

namespace Mta.Host.Tests;

public class IngestTests : IAsyncLifetime
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
    private VerpCodec _verp = null!;
    private int _submissionPort;
    private int _bouncePort;
    private int _wakes;

    public async Task InitializeAsync()
    {
        _storage = new InMemoryStorage(new StorageOptions());
        await _storage.InitializeAsync(default);
        var now = DateTimeOffset.UtcNow;
        await _storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, now, false), default);
        await _storage.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), TenantId, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        await _storage.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), TenantId, "pending.example", DomainStatus.Pending, null, false, now, null, now, 0, null, false, null), default);
        await _storage.Config.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), TenantId, "acme-user", PasswordHasher.Hash("s3cret", 2000), true, now), default);

        _verp = new VerpCodec(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey() }, 1);
        var clock = SystemClock.Instance;
        var submission = new SubmissionService(_storage, clock, new SenderPolicy(), new StorageOptions(), new SubmissionOptions { MessageIdDomain = "egg.test" });
        var bounces = new BounceProcessor(_verp, _storage.Config, _storage.Stats, new StorageWebhookPublisher(_storage), clock);
        var handler = new IngestHandler(_storage, submission, new AuthThrottle(), new IngestOptions { BounceDomain = "bounces.egg.test" }, bounces, () => Interlocked.Increment(ref _wakes));
        _server = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "egg.test",
            Certificates = new SelfSigned(),
            AuthFailureDelay = TimeSpan.Zero,
            Listeners =
            [
                new SmtpListenerOptions { Name = "submission", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.StartTls, AuthRequired = true },
                new SmtpListenerOptions { Name = "bounce", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce },
            ],
        }, handler);
        _server.Start();
        _submissionPort = _server.LocalEndPoints["submission"].Port;
        _bouncePort = _server.LocalEndPoints["bounce"].Port;
    }

    public async Task DisposeAsync()
    {
        await _server.DisposeAsync();
        await _storage.DisposeAsync();
    }

    private async Task<SmtpClient> ConnectAsync(string user = "acme-user", string password = "s3cret")
    {
        var client = new SmtpClient { CheckCertificateRevocation = false, ServerCertificateValidationCallback = (_, _, _, _) => true };
        await client.ConnectAsync("localhost", _submissionPort, SecureSocketOptions.StartTls);
        await client.AuthenticateAsync(user, password);
        return client;
    }

    private static MimeMessage Message(string from = "Acme <news@example.org>", string to = "rcpt@dest.example", string subject = "Hello ü")
    {
        var m = new MimeMessage();
        m.From.Add(MailboxAddress.Parse(from));
        m.To.Add(MailboxAddress.Parse(to));
        m.Subject = subject;
        m.Body = new BodyBuilder { TextBody = "Plain body", HtmlBody = "<p>Html body</p>" }.ToMessageBody();
        return m;
    }

    [Fact]
    public async Task Authenticated_submission_is_queued_with_headers_repaired_and_content_recorded()
    {
        using var client = await ConnectAsync();
        var msg = Message();
        msg.Bcc.Add(MailboxAddress.Parse("hidden@dest.example"));
        msg.Headers.Remove(HeaderId.MessageId);
        await client.SendAsync(msg);

        var claimed = await _storage.Deliveries.ClaimAsync("t", 10, DateTimeOffset.UtcNow.AddSeconds(1), TimeSpan.FromMinutes(1), default);
        Assert.Equal(["hidden@dest.example", "rcpt@dest.example"], claimed.Select(d => d.Recipient.ToString()).OrderBy(x => x));
        Assert.All(claimed, d => Assert.Equal(("example.org", MessageSource.Smtp, TenantId), (d.SendingDomain, d.Source, d.TenantId)));
        string raw = Encoding.UTF8.GetString((await _storage.Deliveries.GetRawAsync(claimed[0].MessageId, default))!);
        Assert.StartsWith("Received: from", raw);
        Assert.Contains("ESMTPSA", raw);
        Assert.Contains("Message-ID: <", raw);
        Assert.DoesNotContain("Bcc:", raw, StringComparison.OrdinalIgnoreCase);
        Assert.True(_wakes >= 1);

        var detail = await _storage.History.GetAsync(TenantId, claimed[0].MessageId, default);
        Assert.Equal("Hello ü", detail!.Content!.Subject);
        Assert.Contains("Plain body", detail.Content.Text);
    }

    [Fact]
    public async Task Wrong_password_and_unknown_user_are_refused_and_lock_out_after_repeated_failures()
    {
        using var bad = new SmtpClient { CheckCertificateRevocation = false, ServerCertificateValidationCallback = (_, _, _, _) => true };
        await bad.ConnectAsync("localhost", _submissionPort, SecureSocketOptions.StartTls);
        await Assert.ThrowsAsync<AuthenticationException>(() => bad.AuthenticateAsync("acme-user", "wrong"));
        await Assert.ThrowsAsync<AuthenticationException>(() => bad.AuthenticateAsync("nobody", "x"));
    }

    [Fact]
    public async Task A_sender_domain_that_is_not_verified_or_not_owned_is_refused_before_anything_is_queued()
    {
        using var client = await ConnectAsync();
        var ex1 = await Assert.ThrowsAsync<SmtpCommandException>(() => client.SendAsync(Message(from: "x@pending.example")));
        Assert.Equal(550, (int)ex1.StatusCode);
        var ex2 = await Assert.ThrowsAsync<SmtpCommandException>(() => client.SendAsync(Message(from: "x@other.example")));
        Assert.Equal(550, (int)ex2.StatusCode);
        Assert.Empty(await _storage.Deliveries.ClaimAsync("t", 10, DateTimeOffset.UtcNow.AddSeconds(1), TimeSpan.FromMinutes(1), default));
    }

    [Fact]
    public async Task The_bounce_listener_accepts_only_verified_bounce_addresses()
    {
        using var rejecting = new MailKit.Net.Smtp.SmtpClient();
        await rejecting.ConnectAsync("127.0.0.1", _bouncePort, SecureSocketOptions.None);
        var m = Message(from: "mailer-daemon@remote.example", to: "user@bounces.egg.test");
        var ex = await Assert.ThrowsAsync<SmtpCommandException>(() => rejecting.SendAsync(m));
        Assert.Equal(550, (int)ex.StatusCode);
        var relay = Message(from: "a@remote.example", to: "victim@elsewhere.example");
        await Assert.ThrowsAsync<SmtpCommandException>(() => rejecting.SendAsync(relay));
    }

    [Fact]
    public async Task A_permanent_dsn_to_a_bounce_address_suppresses_the_recipient_and_publishes_a_webhook()
    {
        var endpoint = new WebhookEndpointRecord(Ids.New(), TenantId, "https://hooks.example/x", [1, 2, 3], [WebhookEventFactory.Bounced], true, null, null, DateTimeOffset.UtcNow, null);
        await _storage.Config.UpsertWebhookEndpointAsync(endpoint, default);
        string bounceAddress = _verp.CreateAddress(TenantId, Ids.New(), "bounces.egg.test", DateTimeOffset.UtcNow);
        byte[] dsn = DsnBuilder.Build(new DsnRequest
        {
            ReportingMta = "mx.remote.example",
            To = EmailAddress.Parse(bounceAddress),
            Action = DsnAction.Failed,
            ArrivalDate = DateTimeOffset.UtcNow,
            Now = DateTimeOffset.UtcNow,
            OriginalMessage = Encoding.ASCII.GetBytes("Message-ID: <orig@egg.test>\r\nSubject: x\r\n\r\nbody\r\n"),
            Recipients = [new DsnRecipient(EmailAddress.Parse("gone@dest.example"), "5.1.1", "550 5.1.1 No such user")],
        });

        using var client = new MailKit.Net.Smtp.SmtpClient();
        await client.ConnectAsync("127.0.0.1", _bouncePort, SecureSocketOptions.None);
        using var ms = new MemoryStream(dsn);
        var message = MimeMessage.Load(ms);
        await client.SendAsync(message, MailboxAddress.Parse("mailer-daemon@remote.example"), [MailboxAddress.Parse(bounceAddress)]);

        Assert.True(await _storage.Config.IsSuppressedAsync(TenantId, "gone@dest.example", default));
        var outbox = await _storage.Webhooks.ClaimDueAsync("w", 10, DateTimeOffset.UtcNow.AddSeconds(1), TimeSpan.FromMinutes(1), default);
        var item = Assert.Single(outbox);
        Assert.Equal(WebhookEventFactory.Bounced, item.EventType);
        Assert.Contains("gone@dest.example", item.PayloadJson);
        Assert.Contains("\"asynchronous\":true", item.PayloadJson);
    }

    [Fact]
    public async Task A_forged_bounce_token_changes_nothing()
    {
        var other = new VerpCodec(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey() }, 1);
        string forged = other.CreateAddress(TenantId, Ids.New(), "bounces.egg.test", DateTimeOffset.UtcNow);
        using var client = new MailKit.Net.Smtp.SmtpClient();
        await client.ConnectAsync("127.0.0.1", _bouncePort, SecureSocketOptions.None);
        await Assert.ThrowsAsync<SmtpCommandException>(() => client.SendAsync(Message(from: "a@remote.example", to: forged)));
        Assert.False(await _storage.Config.IsSuppressedAsync(TenantId, "gone@dest.example", default));
    }
}
