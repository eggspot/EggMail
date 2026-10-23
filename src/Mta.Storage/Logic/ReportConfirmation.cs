namespace Mta.Storage.Logic;

/// <summary>
/// Which recorded events show that a message was attempted to a recipient, for confirming a bounce or complaint against the hour its bounce address was
/// issued (<see cref="AsyncReport.AttemptedWithin"/>, decision 113). Shared by every backend so they agree exactly: the storage query narrows by type and time,
/// and the recipient is compared here, because the database <c>lower()</c> functions do not fold case the way the stored recipients were folded.
/// </summary>
public static class ReportConfirmation
{
    /// <summary>The event types a delivery attempt writes (<see cref="AttemptPlanner"/>); an attached report has no delivery id and is never one.</summary>
    public static readonly IReadOnlyList<MessageEventType> AttemptTypes = [MessageEventType.Delivered, MessageEventType.Deferred, MessageEventType.Bounced, MessageEventType.AbortedBySwitch];

    /// <summary>The type list for an SQL <c>IN</c> clause.</summary>
    public static readonly string AttemptTypesSql = string.Join(", ", AttemptTypes.Select(t => ((int)t).ToString(System.Globalization.CultureInfo.InvariantCulture)));

    /// <summary>True for an event written by a delivery attempt.</summary>
    public static bool IsAttempt(MessageEventType type, Guid? deliveryId) => deliveryId is not null && AttemptTypes.Contains(type);

    /// <summary>True when <paramref name="at"/> lies in <paramref name="window"/> (start inclusive, end exclusive).</summary>
    public static bool InWindow(DateTimeOffset at, AttemptWindow window) => at >= window.From && at < window.Until;

    /// <summary>
    /// True when an attempt event's recipient (stored as the queue wrote it, case kept) is <paramref name="recipient"/> (already trimmed and lower-cased, as
    /// <c>message_recipient</c> stores it), or when no recipient is named.
    /// </summary>
    public static bool IsRecipient(string? eventRecipient, string? recipient) =>
        recipient is null || (eventRecipient is not null && string.Equals(eventRecipient.Trim().ToLowerInvariant(), recipient, StringComparison.Ordinal));

    public static bool IsSendingDomain(Guid? messageSendingDomainId, ulong? sendingDomainIdPrefix) =>
        sendingDomainIdPrefix is null || messageSendingDomainId is null || Mta.Core.Ids.Prefix64(messageSendingDomainId.Value) == sendingDomainIdPrefix;
}
