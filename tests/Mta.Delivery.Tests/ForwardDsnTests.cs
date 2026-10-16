using Mta.Core;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Delivery.Tests;

/// <summary>
/// A forward of received mail (decision 95, design section 11.7) never gets a bounce message of any kind: its sender is someone else's, and the
/// tenant learns of a failure from the outbound message and its webhook. This pins <see cref="DsnService.Applies"/> for source Forward whatever the options say.
/// </summary>
public class ForwardDsnTests
{
    private static ClaimedDelivery Delivery(MessageSource source, EmailAddress from) => new()
    {
        DeliveryId = Guid.CreateVersion7(),
        MessageId = Guid.CreateVersion7(),
        TenantId = Guid.CreateVersion7(),
        EnvelopeFrom = from,
        Recipient = EmailAddress.Parse("to@example.org"),
        RecipientDomain = "example.org",
        Attempt = 0,
        CreatedAt = DateTimeOffset.UtcNow,
        ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
        LeaseUntil = DateTimeOffset.UtcNow.AddMinutes(1),
        Source = source,
    };

    [Fact]
    public void A_forward_gets_no_bounce_whatever_the_options_say_while_smtp_and_api_mail_follow_their_options()
    {
        var storage = new InMemoryStorage(new StorageOptions(), SystemClock.Instance);
        var everything = new DsnService(storage, SystemClock.Instance, new DeliveryOptions { GenerateDsnForSmtpSubmissions = true, GenerateDsnForApiSubmissions = true });
        EmailAddress sender = EmailAddress.Parse("srs@example.com");

        Assert.False(everything.Applies(Delivery(MessageSource.Forward, sender)));
        Assert.False(everything.Applies(Delivery(MessageSource.Forward, EmailAddress.Null)));
        Assert.True(everything.Applies(Delivery(MessageSource.Smtp, sender)));
        Assert.True(everything.Applies(Delivery(MessageSource.Api, sender)));
        Assert.False(everything.Applies(Delivery(MessageSource.Smtp, EmailAddress.Null)));
    }
}
