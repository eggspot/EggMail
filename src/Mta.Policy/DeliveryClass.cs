namespace Mta.Policy;

/// <summary>What a remote reply means for the delivery and for the recipient's reputation in our suppression list.</summary>
public enum DeliveryClass : byte
{
    /// <summary>Accepted (2xx). Only an accept at <see cref="SmtpStage.EndOfData"/> means the message was delivered.</summary>
    Delivered = 0,

    /// <summary>Temporary failure: retry on the normal schedule.</summary>
    Transient,

    /// <summary>Temporary failure caused by rate limiting or throttling: retry on a slower schedule and reduce concurrency/rate to this destination.</summary>
    TransientThrottle,

    /// <summary>Greylisting: retry after 5 to 15 minutes.</summary>
    TransientGreylist,

    /// <summary>Hard bounce because the recipient (mailbox or domain) does not exist or cannot receive mail: bounce and suppress the recipient.</summary>
    PermanentRecipient,

    /// <summary>Hard bounce because of the sender address or sender authentication (SPF/DKIM/DMARC, bad sender domain). Bounce; do NOT suppress the recipient.</summary>
    PermanentSender,

    /// <summary>Hard bounce because of a policy decision about us or the connecting IP (blocklist, reputation, relay denied, TLS required). Bounce; do NOT suppress the recipient.</summary>
    PermanentPolicy,

    /// <summary>Hard bounce because the remote side rejected the message content (spam, virus, malformed). Bounce; do NOT suppress the recipient.</summary>
    PermanentContent,

    /// <summary>The recipient mailbox is full (4.2.2 / 5.2.2). Counts as a soft bounce; retry or bounce according to configuration. Never suppresses by itself.</summary>
    SoftBounceMailboxFull,

    /// <summary>A permanent failure that is a configuration problem on our side or the route, for example message too large (5.3.4), SMTP syntax errors, relay authentication failure. Bounce; do NOT suppress.</summary>
    PermanentConfigurationProblem,
}

/// <summary>The result of classifying a remote reply.</summary>
/// <param name="Class">The delivery class.</param>
/// <param name="Reason">A short, constant, human readable reason (which rule matched). Safe to log and show in the dashboard.</param>
public readonly record struct ReplyClassification(DeliveryClass Class, string Reason);

/// <summary>Helpers describing how each <see cref="DeliveryClass"/> should be handled.</summary>
public static class DeliveryClassExtensions
{
    /// <summary>True for any class that ends the delivery as a failure regardless of configuration (hard bounces).</summary>
    public static bool IsPermanentFailure(this DeliveryClass value) =>
        value is DeliveryClass.PermanentRecipient or DeliveryClass.PermanentSender or DeliveryClass.PermanentPolicy
            or DeliveryClass.PermanentContent or DeliveryClass.PermanentConfigurationProblem;

    /// <summary>True when the delivery should be retried later.</summary>
    /// <param name="value">The class.</param>
    /// <param name="retryMailboxFull">Whether a full mailbox is retried (true, the default policy) or bounced (false).</param>
    public static bool ShouldRetry(this DeliveryClass value, bool retryMailboxFull = true) =>
        value is DeliveryClass.Transient or DeliveryClass.TransientThrottle or DeliveryClass.TransientGreylist
        || (value == DeliveryClass.SoftBounceMailboxFull && retryMailboxFull);

    /// <summary>True when the recipient address should be added to the suppression list. Only a recipient-specific hard bounce qualifies.</summary>
    public static bool ShouldSuppressRecipient(this DeliveryClass value) => value == DeliveryClass.PermanentRecipient;

    /// <summary>True when the reply counts toward the recipient's soft-bounce tally.</summary>
    public static bool CountsAsSoftBounce(this DeliveryClass value) => value == DeliveryClass.SoftBounceMailboxFull;

    /// <summary>True when the destination is asking us to slow down (feeds <see cref="DestinationThrottle"/>).</summary>
    public static bool IsThrottleSignal(this DeliveryClass value) => value == DeliveryClass.TransientThrottle;
}
