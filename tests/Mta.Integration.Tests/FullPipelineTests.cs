using System.Net;
using System.Security.Cryptography;
using System.Text;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Mta.Core;
using Mta.Delivery;
using Mta.Dkim;
using Mta.Dns;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Security;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.Sqlite;

namespace Mta.Integration.Tests;

/// <summary>A scripted receiving MTA (the "Internet" side).</summary>
internal sealed class FakeInternet : ISmtpServerHandler
{
    public sealed record Mail(string Sender, string[] Recipients, byte[] Body);

    public List<Mail> Received { get; } = [];
    public Func<string, SmtpReply?>? Recipient { get; set; }

    public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken ct) => ValueTask.FromResult<SmtpReply?>(null);

    public ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct) =>
        ValueTask.FromResult(SmtpAuthResult.Failed);

    public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.SenderOk);

    public ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters p, CancellationToken ct) =>
        ValueTask.FromResult(Recipient?.Invoke(recipient.ToString()) ?? SmtpReplies.RecipientOk);

    public ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
    {
        lock (Received)
        {
            Received.Add(new Mail(message.Sender.ToString(), message.Recipients.Select(r => r.ToString()).ToArray(), message.ToArray()));
        }

        return ValueTask.FromResult(SmtpReply.Create(250, "2.0.0", "Accepted"));
    }

    public void OnDisconnected(SmtpSessionContext session)
    {
    }
}

// Same collection as SwitchRuntimeTests: two runtimes generating certificates at once make the STARTTLS handshake of this test flaky under load.
[Collection("Runtime")]
public sealed class FullPipelineTests : IAsyncLifetime
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-it-").FullName;
    private readonly FakeInternet _internet = new();
    private readonly CancellationTokenSource _stop = new();
    private SmtpServer _remote = null!;
    private EggMailRuntime _runtime = null!;
    private StaticDnsResolver _dns = null!;
    private Task _engine = Task.CompletedTask;
    private int _submissionPort;
    private RSA _dkimKey = null!;

    public async Task InitializeAsync()
    {
        _remote = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "mx.dest.example",
            Listeners = [new SmtpListenerOptions { Name = "mx", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce }],
        }, _internet);
        _remote.Start();
        int remotePort = _remote.LocalEndPoints["mx"].Port;

        _dns = new StaticDnsResolver();
        foreach (string domain in new[] { "dest.example", "example.org" })
        {
            _dns.AddMx(domain, 10, "mx." + domain).AddA("mx." + domain, "127.0.0.1");
        }

        var config = new MtaConfig
        {
            Hostname = "egg.test",
            Storage = new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _dir } },
            Smtp = new SmtpSection
            {
                Listeners = new Dictionary<string, ListenerSection>
                {
                    ["submission"] = new() { Port = 0, BindAddress = "127.0.0.1", Mode = ListenerMode.StartTls, AuthRequired = true },
                },
            },
            Webhooks = new Mta.Webhooks.WebhookOptions { AllowHttp = true, PollInterval = TimeSpan.FromMilliseconds(100) },
            Delivery = new DeliverySection { BounceDomain = "bounces.egg.test", RemotePort = remotePort, AllowPrivateMxAddresses = true, PollInterval = TimeSpan.FromMilliseconds(30) },
        };
        var storage = SqliteStorage.Create(config.Storage);
        await storage.InitializeAsync(default);
        _runtime = await EggMailRuntime.CreateAsync(config, storage, SystemClock.Instance, NullMtaLog.Instance, default, _dns);

        var now = DateTimeOffset.UtcNow;
        var domainId = Ids.New();
        _dkimKey = DkimKeyTools.GenerateRsa2048();
        await storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, now, false), default);
        await storage.Config.UpsertDomainAsync(new DomainRecord(domainId, TenantId, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        await storage.Config.AddDkimKeyAsync(new Mta.Storage.DkimKeyRecord(
            Ids.New(), domainId, "egg1", _runtime.Secrets.Protect(_dkimKey.ExportPkcs8PrivateKey(), SecretPurposes.DkimKey), DkimKeyTools.ExportPublicKeyBase64(_dkimKey), now, true, null), default);
        await storage.Config.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), TenantId, "acme-user", PasswordHasher.Hash("s3cret", 2000), true, now), default);
        _dns.AddTxt("egg1._domainkey.example.org", DkimKeyTools.FormatDnsTxtValue(_dkimKey));

        _runtime.SmtpServer.Start();
        _submissionPort = _runtime.SmtpServer.LocalEndPoints["submission"].Port;
        _engine = Task.Run(() => _runtime.Delivery.RunAsync(_stop.Token));
    }

    public async Task DisposeAsync()
    {
        await _stop.CancelAsync();
        try { await _engine; } catch (OperationCanceledException) { }
        await _runtime.SmtpServer.StopAsync(TimeSpan.FromSeconds(2));
        await _remote.DisposeAsync();
        await _runtime.DisposeAsync();
        await _runtime.Storage.DisposeAsync();
        _dkimKey.Dispose();
        Directory.Delete(_dir, recursive: true);
    }

    private async Task SendAsync(string to)
    {
        using var client = new SmtpClient { CheckCertificateRevocation = false, ServerCertificateValidationCallback = (_, _, _, _) => true };
        await client.ConnectAsync("127.0.0.1", _submissionPort, SecureSocketOptions.StartTls);
        await client.AuthenticateAsync("acme-user", "s3cret");
        var m = new MimeMessage();
        m.From.Add(MailboxAddress.Parse("Acme <news@example.org>"));
        m.To.Add(MailboxAddress.Parse(to));
        m.Subject = "Autumn news";
        m.Body = new BodyBuilder { TextBody = "Hello from EggMail", HtmlBody = "<p>Hello from EggMail</p>" }.ToMessageBody();
        await client.SendAsync(m);
        await client.DisconnectAsync(true);
    }

    private static async Task WaitAsync(Func<bool> condition, int timeoutMs = 15_000)
    {
        var until = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (!condition())
        {
            if (DateTime.UtcNow > until)
            {
                throw new TimeoutException();
            }

            await Task.Delay(25);
        }
    }

    [Fact]
    public async Task A_message_submitted_over_smtp_is_signed_delivered_recorded_and_counted()
    {
        await SendAsync("rcpt@dest.example");
        await WaitAsync(() => _internet.Received.Count == 1);

        var mail = Assert.Single(_internet.Received);
        Assert.StartsWith("b+", mail.Sender);
        Assert.EndsWith("@bounces.egg.test", mail.Sender);
        Assert.Equal(["rcpt@dest.example"], mail.Recipients);
        var dkim = Assert.Single(await new DkimVerifier(_dns).VerifyAsync(mail.Body));
        Assert.Equal(DkimStatus.Pass, dkim.Status);
        string text = Encoding.UTF8.GetString(mail.Body);
        Assert.Contains("Subject: Autumn news", text);
        Assert.Contains("Received: from", text);

        var storage = _runtime.Storage;
        MessageEvent? delivered = null;
        await WaitAsync(() =>
        {
            var page = storage.History.SearchAsync(new MessageQuery(TenantId), default).AsTask().Result;
            if (page.Items.Count != 1)
            {
                return false;
            }

            delivered = storage.History.GetEventsAsync(TenantId, page.Items[0].MessageId, default).AsTask().Result.FirstOrDefault(e => e.Type == MessageEventType.Delivered);
            return delivered is not null;
        });
        Assert.Equal("rcpt@dest.example", delivered!.Recipient);

        await storage.Stats.FlushAsync(default);
        var rows = await storage.Stats.QueryAsync(TenantId, DateTimeOffset.UtcNow.AddHours(-2), DateTimeOffset.UtcNow.AddHours(2), daily: false, default);
        Assert.Equal(1, rows.Sum(r => r.Accepted));
        Assert.Equal(1, rows.Sum(r => r.Delivered));
    }

    [Fact]
    public async Task A_rejected_recipient_is_bounced_to_the_sender_suppressed_and_not_retried()
    {
        _internet.Recipient = r => r.StartsWith("gone@", StringComparison.Ordinal) ? SmtpReply.Create(550, "5.1.1", "No such user") : null;
        await SendAsync("gone@dest.example");

        await WaitAsync(() => _internet.Received.Any(m => m.Recipients.Contains("news@example.org")));
        var dsn = _internet.Received.First(m => m.Recipients.Contains("news@example.org"));
        Assert.Equal(string.Empty, dsn.Sender);
        Assert.Contains("Final-Recipient: rfc822; gone@dest.example", Encoding.ASCII.GetString(dsn.Body));
        Assert.True(await _runtime.Storage.Config.IsSuppressedAsync(TenantId, "gone@dest.example", default));

        // A second message to the same address is not even attempted any more.
        int before = _internet.Received.Count;
        await SendAsync("gone@dest.example");
        await Task.Delay(500);
        Assert.Equal(before, _internet.Received.Count);
    }

    [Fact]
    public async Task A_delivered_message_produces_a_signed_webhook_to_the_tenants_endpoint()
    {
        using var listener = new HttpListener();
        int port;
        while (true)
        {
            port = Random.Shared.Next(20000, 40000);
            listener.Prefixes.Clear();
            listener.Prefixes.Add($"http://127.0.0.1:{port}/hook/");
            try { listener.Start(); break; } catch (HttpListenerException) { }
        }

        var received = new TaskCompletionSource<(Dictionary<string, string> Headers, byte[] Body)>(TaskCreationOptions.RunContinuationsAsynchronously);
        _ = Task.Run(async () =>
        {
            var context = await listener.GetContextAsync();
            using var ms = new MemoryStream();
            await context.Request.InputStream.CopyToAsync(ms);
            received.TrySetResult((context.Request.Headers.AllKeys.ToDictionary(k => k!, k => context.Request.Headers[k]!, StringComparer.OrdinalIgnoreCase), ms.ToArray()));
            context.Response.StatusCode = 200;
            context.Response.Close();
        });

        string secret = Mta.Webhooks.StandardWebhooksSigner.GenerateSecret();
        await _runtime.Storage.Config.UpsertWebhookEndpointAsync(new WebhookEndpointRecord(
            Ids.New(), TenantId, $"http://127.0.0.1:{port}/hook/", _runtime.Secrets.Protect(Encoding.UTF8.GetBytes(secret), SecretPurposes.WebhookSecret),
            [Mta.Webhooks.WebhookEventFactory.Delivered], true, null, null, DateTimeOffset.UtcNow, null), default);
        _runtime.Webhooks.AllowlistProvider = _ => [Mta.Webhooks.IpNetwork.Parse("127.0.0.0/8")];
        var dispatcher = Task.Run(() => _runtime.Webhooks.RunAsync(_stop.Token));

        await SendAsync("rcpt@dest.example");

        var (headers, body) = await received.Task.WaitAsync(TimeSpan.FromSeconds(20));
        Assert.True(Mta.Webhooks.StandardWebhooksSigner.Verify(headers["webhook-id"], headers["webhook-timestamp"], headers["webhook-signature"], body, [secret], DateTimeOffset.UtcNow));
        using var json = System.Text.Json.JsonDocument.Parse(body);
        Assert.Equal("message.delivered", json.RootElement.GetProperty("type").GetString());
        Assert.Equal("rcpt@dest.example", json.RootElement.GetProperty("data").GetProperty("recipient").GetString());
        listener.Stop();
    }
}
