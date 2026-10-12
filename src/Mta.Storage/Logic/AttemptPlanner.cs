using System.Globalization;

namespace Mta.Storage.Logic;

/// <summary>What the queue knows about the delivery an attempt belongs to.</summary>
public readonly record struct DeliveryRowInfo(
    Guid DeliveryId,
    Guid MessageId,
    Guid TenantId,
    string Recipient,
    string RecipientDomain,
    string? SendingDomain,
    MessageSource Source,
    int Attempt);

/// <summary>What an attempt does to the queue row.</summary>
public enum QueueRowAction : byte
{
    /// <summary>Delete the row: the delivery is final.</summary>
    Complete = 0,

    /// <summary>Keep the row, increment its attempt counter, set the next due time, release the lease.</summary>
    Reschedule,

    /// <summary>Keep the row unchanged except that the lease is released (<see cref="DeliveryOutcome.AbortedBySwitch"/>).</summary>
    Requeue,
}

public readonly record struct PlannedCounter(StatCounter Counter, long Count);

/// <summary>The consequences of one attempt, identical on every backend. Backends only persist them.</summary>
public sealed class AttemptPlan
{
    public required QueueRowAction Action { get; init; }

    /// <summary>The delivery is final (the row is deleted and counts toward freeing the spool).</summary>
    public required bool IsFinal { get; init; }

    public required bool Delivered { get; init; }
    public required bool Failed { get; init; }

    /// <summary>Whether the sticky <c>possible_duplicate</c> flag is set on the row (Deferred/Aborted outcomes only; final rows are deleted).</summary>
    public required bool SetPossibleDuplicate { get; init; }
    public required IReadOnlyList<MessageEvent> Events { get; init; }
    public required IReadOnlyList<PlannedCounter> Counters { get; init; }
    public required IReadOnlyList<RecentEvent> Ring { get; init; }
    public DateTimeOffset? NextAttemptAt { get; init; }
    public string? LastError { get; init; }
}

/// <summary>Turns a <see cref="DeliveryAttempt"/> into queue, event, statistic, ring and (outside) outbox consequences.</summary>
public static class AttemptPlanner
{
    private static readonly string[] EventTypeNames = BuildEventTypeNames();

    /// <summary>Lower snake_case name of an event type (<c>aborted_by_switch</c>), used by the recent-events ring.</summary>
    public static string EventTypeName(MessageEventType type) => EventTypeNames[(int)type];

    public static AttemptPlan Plan(DeliveryAttempt attempt, DeliveryRowInfo row)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        DateTimeOffset at = StorageTime.Normalize(attempt.At);
        var events = new List<MessageEvent>(3);
        var counters = new List<PlannedCounter>(2);
        var ring = new List<RecentEvent>(3);

        MessageEventType primary;
        QueueRowAction action;
        bool isFinal = false;
        bool delivered = false;
        bool failed = false;
        StatCounter? counter;
        DateTimeOffset? next = null;

        switch (attempt.Outcome)
        {
            case DeliveryOutcome.Delivered:
                primary = MessageEventType.Delivered;
                action = QueueRowAction.Complete;
                isFinal = delivered = true;
                counter = StatCounter.Delivered;
                break;
            case DeliveryOutcome.Deferred:
                primary = MessageEventType.Deferred;
                action = QueueRowAction.Reschedule;
                counter = StatCounter.Deferred;
                next = attempt.NextAttemptAt is { } n
                    ? StorageTime.Normalize(n)
                    : throw new ArgumentException("A Deferred attempt requires NextAttemptAt.", nameof(attempt));
                break;
            case DeliveryOutcome.Failed:
                primary = MessageEventType.Bounced;
                action = QueueRowAction.Complete;
                isFinal = failed = true;
                counter = StatCounter.HardBounce;
                break;
            case DeliveryOutcome.Expired:
                primary = MessageEventType.Expired;
                action = QueueRowAction.Complete;
                isFinal = true;
                counter = StatCounter.Expired;
                break;
            case DeliveryOutcome.Suppressed:
                primary = MessageEventType.Suppressed;
                action = QueueRowAction.Complete;
                isFinal = true;
                counter = StatCounter.Suppressed;
                break;
            case DeliveryOutcome.Cancelled:
                primary = MessageEventType.Cancelled;
                action = QueueRowAction.Complete;
                isFinal = true;
                counter = null;
                break;
            case DeliveryOutcome.AbortedBySwitch:
                primary = MessageEventType.AbortedBySwitch;
                action = QueueRowAction.Requeue;
                counter = null;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(attempt), attempt.Outcome, "Unknown delivery outcome.");
        }

        events.Add(NewEvent(primary));
        ring.Add(NewRing(primary));
        if (counter is { } c)
        {
            counters.Add(new PlannedCounter(c, 1));
        }

        if (attempt.Suppress == SuppressionReason.Complaint)
        {
            events.Add(NewEvent(MessageEventType.Complained));
            ring.Add(NewRing(MessageEventType.Complained));
            counters.Add(new PlannedCounter(StatCounter.Complained, 1));
        }

        if (attempt.PossibleDuplicate)
        {
            events.Add(NewEvent(MessageEventType.PossibleDuplicate));
            ring.Add(NewRing(MessageEventType.PossibleDuplicate));
        }

        return new AttemptPlan
        {
            Action = action,
            IsFinal = isFinal,
            Delivered = delivered,
            Failed = failed,
            SetPossibleDuplicate = attempt.PossibleDuplicate && !isFinal,
            Events = events,
            Counters = counters,
            Ring = ring,
            NextAttemptAt = next,
            LastError = attempt.Outcome == DeliveryOutcome.Deferred ? DescribeError(attempt) : null,
        };

        MessageEvent NewEvent(MessageEventType type) => new(
            EventIds.Next(at),
            row.MessageId,
            row.DeliveryId,
            row.TenantId,
            type,
            at,
            row.Recipient,
            attempt.SmtpCode,
            attempt.EnhancedCode,
            attempt.Message,
            attempt.MxHost,
            attempt.Route,
            attempt.Tls);

        RecentEvent NewRing(MessageEventType type) => new(at, row.TenantId, EventTypeName(type), row.RecipientDomain, RingDetail(attempt));
    }

    /// <summary>"451 4.7.1 greylisted" style one-liner stored with a deferral (<c>last_error</c>).</summary>
    public static string? DescribeError(DeliveryAttempt attempt)
    {
        string? code = attempt.SmtpCode?.ToString(CultureInfo.InvariantCulture);
        string? enhanced = attempt.EnhancedCode;
        string? message = attempt.Message;
        if (code is null && enhanced is null && message is null)
        {
            return null;
        }

        return string.Join(' ', new[] { code, enhanced, message }.Where(x => !string.IsNullOrEmpty(x)));
    }

    /// <summary>Content-free ring detail: status codes only, never message text.</summary>
    private static string? RingDetail(DeliveryAttempt attempt)
    {
        if (attempt.SmtpCode is null && attempt.EnhancedCode is null)
        {
            return null;
        }

        return string.Join(' ', new[] { attempt.SmtpCode?.ToString(CultureInfo.InvariantCulture), attempt.EnhancedCode }.Where(x => !string.IsNullOrEmpty(x)));
    }

    private static string[] BuildEventTypeNames()
    {
        var values = Enum.GetValues<MessageEventType>();
        var names = new string[values.Max(v => (int)v) + 1];
        foreach (var v in values)
        {
            names[(int)v] = Model.StorageModel.SnakeCase(v.ToString());
        }

        return names;
    }
}
