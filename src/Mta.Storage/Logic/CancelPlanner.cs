namespace Mta.Storage.Logic;

/// <summary>Why a waiting delivery cannot be cancelled right now.</summary>
public enum CancelHold : byte
{
    /// <summary>Nothing holds it: it can be cancelled.</summary>
    None = 0,

    /// <summary>A delivery attempt holds the lease (a worker is, or may be, mid-transaction).</summary>
    Leased,

    /// <summary>A backend switch marked the row (exported, or held for activation).</summary>
    TransferHeld,
}

/// <summary>
/// A waiting delivery of the message being cancelled. <see cref="PossibleDuplicate"/> is the effective flag: the row's own flag, or a lease whose holder never
/// reported (the lease ran out with <c>lease_owner</c> still set), so the message may already have been sent.
/// </summary>
public readonly record struct PendingDelivery(Guid DeliveryId, string Recipient, string EnvelopeFrom, int Attempt, bool PossibleDuplicate, CancelHold Hold);

/// <summary>The shared decisions of <see cref="IDeliveryStore.CancelAsync"/>, so every backend answers the same way (decision 85).</summary>
public static class CancelPlanner
{
    /// <summary>The text of the <c>cancelled</c> event when nothing suggests the message was sent.</summary>
    public const string EventMessage = "Cancelled before delivery.";

    /// <summary>The text when an earlier attempt's outcome is unknown, so the message may already have reached the recipient's server.</summary>
    public const string EventMessageOutcomeUnknown = "Cancelled while the outcome of an earlier delivery attempt was unknown; the message may already have been sent.";

    /// <summary>
    /// Whether a delivery with these columns holds an attempt whose outcome may be unknown: flagged, or its lease ran out although its holder never reported
    /// (a reclaimed row). <paramref name="leaseOwnerSet"/> is only meaningful for a lease that is no longer active.
    /// </summary>
    public static bool OutcomeMayBeUnknown(bool possibleDuplicateFlag, bool leaseOwnerSet) => possibleDuplicateFlag || leaseOwnerSet;

    /// <summary>The attempt that finishes a delivery as cancelled; <see cref="AttemptPlanner.Plan"/> turns it into the event, queue and status consequences.</summary>
    public static DeliveryAttempt AttemptFor(PendingDelivery d, Guid messageId, Guid tenantId, DateTimeOffset at, Func<CancelledDeliveryInfo, WebhookEventDraft?>? webhookEvent)
    {
        WebhookEventDraft? draft = webhookEvent?.Invoke(new CancelledDeliveryInfo(d.DeliveryId, messageId, tenantId, d.EnvelopeFrom, d.Recipient, d.Attempt, d.PossibleDuplicate, at));
        return new DeliveryAttempt
        {
            DeliveryId = d.DeliveryId,
            Outcome = DeliveryOutcome.Cancelled,
            At = at,
            Message = d.PossibleDuplicate ? EventMessageOutcomeUnknown : EventMessage,
            PossibleDuplicate = d.PossibleDuplicate,
            WebhookEvents = draft is null ? [] : [draft],
        };
    }

    /// <summary>
    /// Splits the waiting deliveries of a message into those to cancel and those left alone. <paramref name="requested"/> null selects every
    /// waiting delivery; otherwise recipients are matched case-insensitively as whole addresses and a requested address without a waiting delivery is
    /// reported as not waiting. Output order is by recipient (ordinal, case-insensitive), so the answer does not depend on the backend's row order.
    /// </summary>
    public static CancelSelection Select(IReadOnlyCollection<PendingDelivery> waiting, IReadOnlyList<string>? requested)
    {
        var wanted = requested is null ? null : new HashSet<string>(requested.Select(r => r.Trim()), StringComparer.OrdinalIgnoreCase);
        var cancel = new List<PendingDelivery>();
        var inFlight = new List<string>();
        var held = new List<string>();
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (PendingDelivery d in waiting.OrderBy(p => p.Recipient, StringComparer.OrdinalIgnoreCase).ThenBy(p => p.DeliveryId))
        {
            if (wanted is not null && !wanted.Contains(d.Recipient))
            {
                continue;
            }

            found.Add(d.Recipient);
            switch (d.Hold)
            {
                case CancelHold.None:
                    cancel.Add(d);
                    break;
                case CancelHold.TransferHeld:
                    held.Add(d.Recipient);
                    break;
                default:
                    inFlight.Add(d.Recipient);
                    break;
            }
        }

        var notWaiting = wanted is null ? [] : wanted.Where(w => !found.Contains(w)).OrderBy(w => w, StringComparer.OrdinalIgnoreCase).ToList();
        return new CancelSelection(cancel, inFlight, held, notWaiting, waiting.Count);
    }

    /// <summary>The result once <paramref name="selection"/> has been applied.</summary>
    public static CancelResult ResultOf(CancelSelection selection) =>
        new(selection.Cancel.Select(c => c.Recipient).ToList(), selection.InFlight, selection.TransferHeld, selection.NotWaiting, selection.Waiting);
}

/// <summary>The outcome of <see cref="CancelPlanner.Select"/>.</summary>
public sealed record CancelSelection(IReadOnlyList<PendingDelivery> Cancel, IReadOnlyList<string> InFlight, IReadOnlyList<string> TransferHeld, IReadOnlyList<string> NotWaiting, int Waiting);
