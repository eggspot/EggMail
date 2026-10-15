using System.Net;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Mta.Core;
using Mta.Host.Ingest;
using Mta.Host.Security;
using Mta.Host.Submission;
using Mta.Policy;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests;

/// <summary>
/// A full disk is answered <c>452 4.3.1</c> (insufficient system storage) so that the client retries and an operator reading its log knows what to free;
/// any other storage failure stays <c>451 4.3.0</c>. Nothing is queued in either case.
/// </summary>
public class IngestDiskFullTests
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    private sealed class FailingIntake(Func<Exception> failure) : IMessageIntake
    {
        public ValueTask<IntakeResult> AcceptAsync(AcceptedMessage message, CancellationToken cancellationToken) => throw failure();
    }

    private sealed class StorageWithIntake(IStorage inner, IMessageIntake intake) : IStorage
    {
        public StorageBackend Backend => inner.Backend;
        public HistoryMode HistoryMode => inner.HistoryMode;
        public IMessageIntake Intake => intake;
        public IDeliveryStore Deliveries => inner.Deliveries;
        public IConfigStore Config => inner.Config;
        public IStatsStore Stats => inner.Stats;
        public IHistoryStore History => inner.History;
        public IWebhookOutbox Webhooks => inner.Webhooks;
        public IStorageMaintenance Maintenance => inner.Maintenance;
        public Task InitializeAsync(CancellationToken cancellationToken) => inner.InitializeAsync(cancellationToken);
        public ValueTask DisposeAsync() => inner.DisposeAsync();
    }

    private static async Task<int> SendAndGetReplyCodeAsync(Func<Exception> failure)
    {
        await using var real = new InMemoryStorage(new StorageOptions());
        await real.InitializeAsync(default);
        var now = DateTimeOffset.UtcNow;
        await real.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, now, false), default);
        await real.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), TenantId, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        await real.Config.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), TenantId, "acme-user", PasswordHasher.Hash("s3cret", 2000), true, now), default);
        var storage = new StorageWithIntake(real, new FailingIntake(failure));

        var submission = new SubmissionService(storage, SystemClock.Instance, new SenderPolicy(), new StorageOptions(), new SubmissionOptions { MessageIdDomain = "egg.test" });
        var handler = new IngestHandler(storage, submission, new AuthThrottle(), new IngestOptions());
        await using var server = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "egg.test",
            AuthFailureDelay = TimeSpan.Zero,
            Listeners = [new SmtpListenerOptions { Name = "submission", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = true, AllowInsecureAuth = true }],
        }, handler);
        server.Start();

        using var client = new SmtpClient();
        await client.ConnectAsync("127.0.0.1", server.LocalEndPoints["submission"].Port, SecureSocketOptions.None);
        await client.AuthenticateAsync("acme-user", "s3cret");
        var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse("news@example.org"));
        message.To.Add(MailboxAddress.Parse("rcpt@dest.example"));
        message.Subject = "x";
        message.Body = new TextPart("plain") { Text = "body" };
        var ex = await Assert.ThrowsAsync<SmtpCommandException>(() => client.SendAsync(message));
        return (int)ex.StatusCode;
    }

    [Fact]
    public async Task A_full_disk_is_answered_452_so_the_client_retries()
    {
        Assert.Equal(452, await SendAndGetReplyCodeAsync(() => new StorageFullException("disk full")));
    }

    [Fact]
    public async Task Another_storage_failure_stays_451()
    {
        Assert.Equal(451, await SendAndGetReplyCodeAsync(() => new StorageUnavailableException("database down")));
        Assert.Equal(451, await SendAndGetReplyCodeAsync(() => new InvalidOperationException("something else")));
    }
}
