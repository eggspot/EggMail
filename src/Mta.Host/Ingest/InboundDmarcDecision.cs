using Mta.Auth.Dmarc;
using Mta.Storage;

namespace Mta.Host.Ingest;

/// <summary>What the DMARC verdict does to a transaction as a whole.</summary>
public enum InboundDmarcRefusal : byte
{
    /// <summary>Accept.</summary>
    None = 0,

    /// <summary><c>550 5.7.1</c>: the sender's policy is reject, the message fails it, and every accepted recipient's domain asked for rejection.</summary>
    Reject,

    /// <summary><c>451 4.7.0</c>: every accepted recipient's domain asked for rejection and the verdict could not be settled (a temporary error or the time ran out), so the message is neither accepted unverified nor rejected.</summary>
    TryLater,
}

/// <summary>The outcome of <see cref="InboundDmarcDecision.Decide"/>.</summary>
/// <param name="Refusal">What to answer at the end of DATA.</param>
/// <param name="Flagged">Per accepted recipient (same order as the actions): whether its copy is stored flagged.</param>
public readonly record struct InboundDmarcOutcome(InboundDmarcRefusal Refusal, IReadOnlyList<bool> Flagged);

/// <summary>
/// The DMARC action of design section 11.5 as one pure function, so the receive path and the tests agree. SPF fail and DKIM fail alone never reject: DMARC decides. A transaction can be refused
/// only as a whole, and only when <b>every</b> accepted recipient's domain has the action <c>reject</c>; otherwise it is accepted, and the copies of the domains that asked for <c>flag</c> or
/// <c>reject</c> are stored flagged when the message failed under a quarantine or reject policy. A temporary error never rejects, except under <c>reject</c> where it defers (<c>451</c>).
/// </summary>
public static class InboundDmarcDecision
{
    public static InboundDmarcOutcome Decide(InboundVerification verification, IReadOnlyList<InboundDmarcAction> actionsPerRecipient)
    {
        ArgumentNullException.ThrowIfNull(verification);
        bool allReject = actionsPerRecipient.Count > 0 && actionsPerRecipient.All(a => a == InboundDmarcAction.Reject);
        DmarcEvaluation? dmarc = verification.Dmarc;

        // A trusted sealer's chain turns a failure into a pass for this decision; the recorded verdicts keep the original.
        bool failed = dmarc?.Result == DmarcResult.Fail && !verification.ArcOverridesDmarc && !verification.Unsettled;
        DmarcDisposition policy = dmarc?.Disposition ?? DmarcDisposition.None;

        if (allReject)
        {
            if (verification.Unsettled)
            {
                return new InboundDmarcOutcome(InboundDmarcRefusal.TryLater, new bool[actionsPerRecipient.Count]);
            }

            if (failed && policy == DmarcDisposition.Reject)
            {
                return new InboundDmarcOutcome(InboundDmarcRefusal.Reject, new bool[actionsPerRecipient.Count]);
            }
        }

        var flagged = new bool[actionsPerRecipient.Count];
        if (failed && policy is DmarcDisposition.Quarantine or DmarcDisposition.Reject)
        {
            for (int i = 0; i < flagged.Length; i++)
            {
                flagged[i] = actionsPerRecipient[i] is InboundDmarcAction.Flag or InboundDmarcAction.Reject;
            }
        }

        return new InboundDmarcOutcome(InboundDmarcRefusal.None, flagged);
    }
}
