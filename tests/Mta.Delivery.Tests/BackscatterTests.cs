using System.Text;
using Mta.Core;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Delivery.Tests;

/// <summary>
/// Security regression tests (docs/security-test-map.md, RELAY-4, RELAY-5): a bounce is mail to a third party that somebody caused, so it must go only to
/// the envelope sender of a message that was submitted by an authenticated sender, never for a bounce, a null sender or another source, and never to an
/// address that appears only in the content of the message. The in-house review, not an independent audit.
/// </summary>
public class BackscatterTests : IAsyncLifetime
{
    private static readonly Guid Tenant = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    private InMemoryStorage _storage = null!;

    public async Task InitializeAsync()
    {
        _storage = new InMemoryStorage(new StorageOptions(), SystemClock.Instance);
        await _storage.InitializeAsync(default);
    }

    public async Task DisposeAsync() => await _storage.DisposeAsync();

    private static ClaimedDelivery Delivery(string from, MessageSource source) => new()
    {
        DeliveryId = Ids.New(), MessageId = Ids.New(), TenantId = Tenant,
        EnvelopeFrom = from.Length == 0 ? EmailAddress.Null : EmailAddress.Parse(from),
        Recipient = EmailAddress.Parse("gone@dest.example"), RecipientDomain = "dest.example", Attempt = 1,
        CreatedAt = DateTimeOffset.UtcNow, ExpiresAt = DateTimeOffset.UtcNow.AddDays(5), LeaseUntil = DateTimeOffset.UtcNow.AddMinutes(5),
        Source = source,
    };

    [Theory]
    [InlineData("sender@example.org", MessageSource.Smtp, true, false, true)]
    [InlineData("sender@example.org", MessageSource.Smtp, false, false, false)]
    [InlineData("sender@example.org", MessageSource.Api, false, false, false)]   // the API answers with webhooks; it does not mail the sender unless asked
    [InlineData("sender@example.org", MessageSource.Api, false, true, true)]
    [InlineData("", MessageSource.Smtp, true, true, false)]                      // a null sender never gets a bounce (that would be a bounce loop)
    [InlineData("", MessageSource.Api, true, true, false)]
    [InlineData("sender@example.org", MessageSource.Bounce, true, true, false)]  // a bounce of a bounce
    public void A_bounce_is_made_only_for_a_real_sender_of_a_submitted_message_and_only_where_it_is_switched_on(string from, MessageSource source, bool smtpOn, bool apiOn, bool expected)
    {
        var dsn = new DsnService(_storage, SystemClock.Instance, new DeliveryOptions { GenerateDsnForSmtpSubmissions = smtpOn, GenerateDsnForApiSubmissions = apiOn });

        Assert.Equal(expected, dsn.Applies(Delivery(from, source)));
    }

    [Fact]
    public async Task The_bounce_goes_to_the_envelope_sender_alone_and_with_the_null_return_path_whatever_the_headers_say()
    {
        // A hostile message: its headers name other people (Reply-To, Return-Path, Disposition-Notification-To, Sender, From, Errors-To), as an attacker
        // would to aim the bounce at a victim. The bounce is addressed to the envelope sender only.
        ClaimedDelivery d = Delivery("sender@example.org", MessageSource.Smtp);
        string raw = "From: ceo@victim.test\r\nReply-To: victim1@victim.test\r\nReturn-Path: <victim2@victim.test>\r\nSender: victim3@victim.test\r\n" +
                     "Disposition-Notification-To: victim4@victim.test\r\nErrors-To: victim5@victim.test\r\nTo: gone@dest.example\r\nSubject: s\r\n\r\nbody\r\n";
        await _storage.Intake.AcceptAsync(new AcceptedMessage
        {
            MessageId = d.MessageId,
            TenantId = Tenant,
            Source = MessageSource.Smtp,
            EnvelopeFrom = d.EnvelopeFrom,
            Recipients = [new AcceptedRecipient(d.DeliveryId, d.Recipient)],
            Raw = Encoding.ASCII.GetBytes(raw),
            ReceivedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(5),
        }, default);
        var dsn = new DsnService(_storage, SystemClock.Instance, new DeliveryOptions { Hostname = "mx.egg.test" });

        await dsn.ReportAsync([new BounceItem(d, new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Failed, At = DateTimeOffset.UtcNow, SmtpCode = 550, EnhancedCode = "5.1.1", Message = "no such user" })], default);

        var queued = await _storage.Deliveries.ClaimAsync("t", 100, DateTimeOffset.UtcNow.AddSeconds(5), TimeSpan.FromMinutes(1), default);
        var bounce = Assert.Single(queued, q => q.MessageId != d.MessageId);
        Assert.Equal("sender@example.org", bounce.Recipient.ToString());
        Assert.True(bounce.EnvelopeFrom.IsNull);
        Assert.Equal(MessageSource.Bounce, bounce.Source);
        Assert.Equal(1, queued.Count(q => q.MessageId == bounce.MessageId));   // one recipient
        string bounceRaw = Encoding.ASCII.GetString((await _storage.Deliveries.GetRawAsync(bounce.MessageId, default))!);
        Assert.Matches(@"(?m)^To: .*sender@example\.org", bounceRaw);
        Assert.DoesNotContain("victim", bounceRaw.Split("\r\n\r\n", 2)[0], StringComparison.Ordinal);   // none of the hostile addresses is a recipient or a header of the bounce
    }

    [Fact]
    public async Task A_bounce_that_itself_fails_does_not_produce_another_bounce()
    {
        var dsn = new DsnService(_storage, SystemClock.Instance, new DeliveryOptions { GenerateDsnForApiSubmissions = true });
        ClaimedDelivery bounce = Delivery("", MessageSource.Bounce);

        await dsn.ReportAsync([new BounceItem(bounce, new DeliveryAttempt { DeliveryId = bounce.DeliveryId, Outcome = DeliveryOutcome.Failed, At = DateTimeOffset.UtcNow, SmtpCode = 550 })], default);

        Assert.Empty(await _storage.Deliveries.ClaimAsync("t", 100, DateTimeOffset.UtcNow.AddSeconds(5), TimeSpan.FromMinutes(1), default));
    }
}
