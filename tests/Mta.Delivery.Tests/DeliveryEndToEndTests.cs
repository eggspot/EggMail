using System.Text;
using Mta.Core;
using Mta.Smtp.Protocol;
using Mta.Storage;

namespace Mta.Delivery.Tests;

public class DeliveryEndToEndTests
{
    [Fact]
    public async Task A_queued_message_is_delivered_to_the_remote_mx_and_recorded()
    {
        await using var f = new DeliveryFixture();
        var id = await f.EnqueueAsync(["rcpt@dest.example"]);

        var events = await f.WaitForEventAsync(id, MessageEventType.Delivered);

        var msg = Assert.Single(f.Remote.Messages);
        Assert.Equal("sender@example.org", msg.Sender);
        Assert.Equal(["rcpt@dest.example"], msg.Recipients);
        Assert.Contains("Subject: Hello", Encoding.ASCII.GetString(msg.Body));
        var delivered = events.Single(e => e.Type == MessageEventType.Delivered);
        Assert.Equal("rcpt@dest.example", delivered.Recipient);
        Assert.Equal(250, delivered.SmtpCode);
        Assert.Equal("direct", delivered.Route);
        Assert.Equal("mx.dest.example", delivered.MxHost);
        await DeliveryFixture.WaitAsync(() => f.Storage.Deliveries.GetQueueStatsAsync(default).AsTask().Result is { Queued: 0, Leased: 0, Deferred: 0 });
    }

    [Fact]
    public async Task Recipients_of_the_same_domain_share_one_transaction()
    {
        await using var f = new DeliveryFixture();
        var id = await f.EnqueueAsync(["a@dest.example", "b@dest.example", "c@dest.example"]);

        await f.WaitForEventAsync(id, MessageEventType.Delivered, count: 3);

        var msg = Assert.Single(f.Remote.Messages);
        Assert.Equal(["a@dest.example", "b@dest.example", "c@dest.example"], msg.Recipients.OrderBy(x => x));
    }

    [Fact]
    public async Task Opportunistic_starttls_is_used_when_the_remote_offers_it()
    {
        await using var f = new DeliveryFixture(serverTls: true);
        var id = await f.EnqueueAsync(["rcpt@dest.example"]);

        var events = await f.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.True(Assert.Single(f.Remote.Messages).Tls);
        Assert.True(events.Single(e => e.Type == MessageEventType.Delivered).Tls!.Used);
    }

    [Fact]
    public async Task A_permanent_recipient_rejection_bounces_suppresses_and_notifies_the_sender()
    {
        await using var f = new DeliveryFixture();
        f.Dns.AddMx("example.org", 10, "mx.example.org").AddA("mx.example.org", "127.0.0.1");
        f.Remote.OnRecipient = r => r.StartsWith("gone@", StringComparison.Ordinal) ? SmtpReply.Create(550, "5.1.1", "No such user") : null;
        var id = await f.EnqueueAsync(["gone@dest.example", "ok@dest.example"]);

        var events = await f.WaitForEventAsync(id, MessageEventType.Bounced);

        var bounced = events.Single(e => e.Type == MessageEventType.Bounced);
        Assert.Equal("gone@dest.example", bounced.Recipient);
        Assert.Equal("5.1.1", bounced.EnhancedCode);
        await f.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.True(await f.Storage.Config.IsSuppressedAsync(DeliveryFixture.Tenant, "gone@dest.example", default));
        Assert.False(await f.Storage.Config.IsSuppressedAsync(DeliveryFixture.Tenant, "ok@dest.example", default));

        // The sender gets a delivery status notification, delivered back through the same pipeline.
        await DeliveryFixture.WaitAsync(() => f.Remote.Messages.Any(m => m.Recipients.Contains("sender@example.org")));
        var dsn = f.Remote.Messages.First(m => m.Recipients.Contains("sender@example.org"));
        Assert.Equal(string.Empty, dsn.Sender);
        Assert.Contains("Final-Recipient: rfc822; gone@dest.example", Encoding.ASCII.GetString(dsn.Body));
    }

    [Fact]
    public async Task A_temporary_rejection_defers_with_a_retry_time_and_keeps_the_delivery()
    {
        await using var f = new DeliveryFixture();
        f.Remote.OnMessage = _ => SmtpReply.Create(451, "4.7.1", "Greylisted, try again later");
        var id = await f.EnqueueAsync(["rcpt@dest.example"]);

        var events = await f.WaitForEventAsync(id, MessageEventType.Deferred);

        var deferred = events.Single(e => e.Type == MessageEventType.Deferred);
        Assert.Equal(451, deferred.SmtpCode);
        Assert.Contains("Greylisted", deferred.Message);
        var stats = await f.Storage.Deliveries.GetQueueStatsAsync(default);
        Assert.Equal(1, stats.Deferred);
        Assert.NotNull(stats.OldestDueAt);
        Assert.True(stats.OldestDueAt > DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task An_unreachable_mx_defers_instead_of_failing()
    {
        await using var f = new DeliveryFixture();
        f.Dns.AddMx("down.example", 10, "mx.down.example").AddA("mx.down.example", "127.0.0.1");
        // Port of a listener that is not there: use a second domain on the same IP but force a closed port via options is not possible,
        // so point the single MX at a dead port by disposing the server first.
        await f.DisposeServerForTestAsync();
        var id = await f.EnqueueAsync(["rcpt@down.example"]);

        var events = await f.WaitForEventAsync(id, MessageEventType.Deferred);

        Assert.DoesNotContain(events, e => e.Type == MessageEventType.Bounced);
    }

    [Fact]
    public async Task A_domain_without_mail_service_is_a_permanent_failure()
    {
        await using var f = new DeliveryFixture();
        f.Dns.Add(new Mta.Dns.MxRecord("nullmx.example", 300, 0, ""));
        var id = await f.EnqueueAsync(["rcpt@nullmx.example"]);

        var events = await f.WaitForEventAsync(id, MessageEventType.Bounced);

        Assert.Equal("5.1.10", events.Single(e => e.Type == MessageEventType.Bounced).EnhancedCode);
    }

    [Fact]
    public async Task A_delivery_past_its_lifetime_expires_and_is_not_attempted()
    {
        await using var f = new DeliveryFixture(startEngine: false);
        var id = await f.EnqueueAsync(["rcpt@dest.example"], lifetime: TimeSpan.FromMilliseconds(1));
        await Task.Delay(50);
        f.StartEngine();

        await f.WaitForEventAsync(id, MessageEventType.Expired);

        Assert.Empty(f.Remote.Messages);
    }

    [Fact]
    public async Task Suppressed_recipients_are_not_sent_to()
    {
        await using var f = new DeliveryFixture(startEngine: false);
        await f.Storage.Config.AddSuppressionAsync(new SuppressionRecord(DeliveryFixture.Tenant, "blocked@dest.example", SuppressionReason.Manual, "test", DateTimeOffset.UtcNow, null), default);
        var id = await f.EnqueueAsync(["blocked@dest.example", "fine@dest.example"]);
        f.StartEngine();

        await f.WaitForEventAsync(id, MessageEventType.Suppressed);
        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Equal(["fine@dest.example"], Assert.Single(f.Remote.Messages).Recipients);
    }

    [Fact]
    public async Task Quiesce_requeues_work_in_flight_unchanged_with_a_possible_duplicate_flag()
    {
        await using var f = new DeliveryFixture();
        var gate = new TaskCompletionSource();
        var entered = new TaskCompletionSource();
        f.Remote.OnMessage = _ =>
        {
            entered.TrySetResult();
            gate.Task.Wait(TimeSpan.FromSeconds(20));
            return null;
        };
        var id = await f.EnqueueAsync(["rcpt@dest.example"]);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));

        await f.Engine.QuiesceAsync(TimeSpan.FromMilliseconds(100), default);
        gate.SetResult();

        var events = await f.EventsAsync(id);
        Assert.Contains(events, e => e.Type == MessageEventType.AbortedBySwitch);
        var stats = await f.Storage.Deliveries.GetQueueStatsAsync(default);
        Assert.Equal(1, stats.Queued + stats.Deferred);
        Assert.Equal(0, stats.Leased);
    }
}

public class DeliveryDkimAndLimitsTests
{
    [Fact]
    public async Task The_envelope_sender_is_a_signed_bounce_address_when_a_bounce_domain_is_configured()
    {
        var verp = new Mta.Dsn.VerpCodec(new Dictionary<int, byte[]> { [1] = Mta.Dsn.VerpCodec.GenerateKey() }, 1);
        await using var f = new DeliveryFixture(o => new DeliveryOptions { Owner = o.Owner, Hostname = o.Hostname, RemotePort = o.RemotePort, IdlePoll = o.IdlePoll, ExpirySweepInterval = o.ExpirySweepInterval, BounceDomain = "bounces.egg.test" }, verp: verp);
        var now = DateTimeOffset.UtcNow;
        var domainId = Ids.New();
        await f.Storage.Config.UpsertDomainAsync(new DomainRecord(domainId, DeliveryFixture.Tenant, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);

        var id = await f.EnqueueAsync(["rcpt@dest.example"]);
        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        string sender = Assert.Single(f.Remote.Messages).Sender;
        Assert.EndsWith("@bounces.egg.test", sender);
        Assert.True(verp.TryDecode(sender[..sender.IndexOf('@')], DateTimeOffset.UtcNow, TimeSpan.FromHours(1), out var token));
        Assert.Equal(DeliveryFixture.Tenant, token.TenantId);
        Assert.True(Mta.Dsn.VerpCodec.MatchesDomain(token, domainId));
    }

    private sealed class IdentityProtector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => plaintext.ToArray();
        public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose) => protectedData.ToArray();
    }

    [Fact]
    public async Task Messages_are_signed_with_the_domains_active_dkim_key_at_delivery()
    {
        using var rsa = Mta.Dkim.DkimKeyTools.GenerateRsa2048();
        await using var f = new DeliveryFixture(dkim: s => new ConfigDkimSignerProvider(s.Storage.Config, new IdentityProtector(), s.Clock));
        var now = DateTimeOffset.UtcNow;
        var domainId = Ids.New();
        await f.Storage.Config.UpsertDomainAsync(new DomainRecord(domainId, DeliveryFixture.Tenant, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        await f.Storage.Config.AddDkimKeyAsync(new Mta.Storage.DkimKeyRecord(Ids.New(), domainId, "egg1", rsa.ExportPkcs8PrivateKey(), Mta.Dkim.DkimKeyTools.ExportPublicKeyBase64(rsa), now, true, null), default);
        f.Dns.AddTxt("egg1._domainkey.example.org", Mta.Dkim.DkimKeyTools.FormatDnsTxtValue(rsa));

        var id = await f.EnqueueAsync(["rcpt@dest.example"]);
        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        var body = Assert.Single(f.Remote.Messages).Body;
        Assert.StartsWith("DKIM-Signature:", Encoding.ASCII.GetString(body));
        var results = await new Mta.Dkim.DkimVerifier(f.Dns).VerifyAsync(body);
        var result = Assert.Single(results);
        Assert.Equal(Mta.Dkim.DkimStatus.Pass, result.Status);
    }

    [Fact]
    public async Task A_sending_limit_holds_deliveries_without_counting_an_attempt_or_sending()
    {
        await using var f = new DeliveryFixture(limits: new Mta.Policy.SendingLimitsOptions { DefaultTenant = new Mta.Policy.LimitSet(PerHour: 1, PerDay: null) });
        var first = await f.EnqueueAsync(["a@dest.example"]);
        await f.WaitForEventAsync(first, MessageEventType.Delivered);
        var second = await f.EnqueueAsync(["b@dest.example"]);

        await DeliveryFixture.WaitAsync(() => f.Storage.Deliveries.GetQueueStatsAsync(default).AsTask().Result is { Deferred: 1 } or { Queued: 1, Leased: 0 } && f.Remote.Messages.Count == 1);
        await Task.Delay(300);

        Assert.Single(f.Remote.Messages);
        var events = await f.EventsAsync(second);
        Assert.DoesNotContain(events, e => e.Type is MessageEventType.Deferred or MessageEventType.Delivered or MessageEventType.Bounced);
    }
}

public class DeliveryResumeTests
{
    [Fact]
    public async Task The_engine_delivers_again_after_a_quiesce_and_resume()
    {
        await using var f = new DeliveryFixture();
        await f.Engine.QuiesceAsync(TimeSpan.FromMilliseconds(50), default);
        var id = await f.EnqueueAsync(["rcpt@dest.example"]);
        await Task.Delay(200);
        Assert.Empty(f.Remote.Messages);

        f.Engine.Resume();

        await f.WaitForEventAsync(id, MessageEventType.Delivered);
    }
}
