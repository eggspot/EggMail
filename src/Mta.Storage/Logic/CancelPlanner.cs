namespace Mta.Storage.Logic;

/// <summary>A pending delivery of the message being cancelled; <see cref="Locked"/> when it is leased (or marked for a backend switch) and so must not be touched.</summary>
public readonly record struct PendingDelivery(Guid DeliveryId, string Recipient, bool Locked);

/// <summary>The shared decisions of <see cref="IDeliveryStore.CancelAsync"/>, so every backend answers the same way (decision 80).</summary>
public static class CancelPlanner
{
    /// <summary>The text recorded with the <c>cancelled</c> event.</summary>
    public const string EventMessage = "Cancelled before delivery.";

    /// <summary>The attempt that finishes a delivery as cancelled; <see cref="AttemptPlanner.Plan"/> turns it into the event, queue and status consequences.</summary>
    public static DeliveryAttempt AttemptFor(Guid deliveryId, DateTimeOffset at) =>
        new() { DeliveryId = deliveryId, Outcome = DeliveryOutcome.Cancelled, At = at, Message = EventMessage };

    /// <summary>
    /// Splits the pending deliveries of a message into those to cancel and those left alone. <paramref name="requested"/> null selects every
    /// pending delivery; otherwise recipients are matched case-insensitively and a requested address without a pending delivery is reported as not pending.
    /// Output order is by recipient (ordinal, case-insensitive), so the answer does not depend on the backend's row order.
    /// </summary>
    public static CancelSelection Select(IReadOnlyCollection<PendingDelivery> pending, IReadOnlyList<string>? requested)
    {
        var wanted = requested is null ? null : new HashSet<string>(requested.Select(r => r.Trim()), StringComparer.OrdinalIgnoreCase);
        var cancel = new List<PendingDelivery>();
        var inFlight = new List<string>();
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (PendingDelivery d in pending.OrderBy(p => p.Recipient, StringComparer.OrdinalIgnoreCase).ThenBy(p => p.DeliveryId))
        {
            if (wanted is not null && !wanted.Contains(d.Recipient))
            {
                continue;
            }

            found.Add(d.Recipient);
            if (d.Locked)
            {
                inFlight.Add(d.Recipient);
            }
            else
            {
                cancel.Add(d);
            }
        }

        var notPending = wanted is null ? [] : wanted.Where(w => !found.Contains(w)).OrderBy(w => w, StringComparer.OrdinalIgnoreCase).ToList();
        return new CancelSelection(cancel, inFlight, notPending);
    }

    /// <summary>The result once <paramref name="selection"/> has been applied.</summary>
    public static CancelResult ResultOf(CancelSelection selection) =>
        new(selection.Cancel.Select(c => c.Recipient).ToList(), selection.InFlight, selection.NotPending);
}

/// <summary>The outcome of <see cref="CancelPlanner.Select"/>.</summary>
public sealed record CancelSelection(IReadOnlyList<PendingDelivery> Cancel, IReadOnlyList<string> InFlight, IReadOnlyList<string> NotPending);
