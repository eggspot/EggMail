using Mta.Core;
using Mta.Dsn;

namespace Mta.Host.Inbound;

/// <summary>What the receive path answers for a recipient that starts with <c>SRS0=</c> or <c>SRS1=</c> (design section 11.4).</summary>
public enum SrsRecipientDecision
{
    /// <summary>A valid, fresh SRS0 address of ours and the null sender: accept the message, then <see cref="SrsBounceHandler.Drop"/> it.</summary>
    Accept,

    /// <summary>Anything else: <c>550 5.1.1</c>.</summary>
    Reject,
}

/// <summary>
/// A DSN for a forwarded message returns to the SRS address on port 25. It is accepted (hash and age verified, only from the null sender), counted, logged <b>without addresses</b> and <b>dropped</b>
/// (DESIGN-DECIDED, design section 11.7): relaying it to the original sender is backscatter to what is usually a forged sender and would make a forged SRS address an open relay. The tenant learns of a failed
/// forward from the outbound side (the forwarded copy is an ordinary outbound message of the tenant).
/// </summary>
public sealed class SrsBounceHandler(SrsCodec srs, IClock clock, IMtaLog log, int maxAgeDays = SrsCodec.DefaultMaxAgeDays)
{
    /// <summary>Decides the RCPT: <paramref name="localPart"/> is the recipient's local part, <paramref name="nullSender"/> whether MAIL FROM was <c>&lt;&gt;</c>.</summary>
    public SrsRecipientDecision Check(string localPart, bool nullSender) =>
        nullSender && srs.TryVerify(localPart, clock.UtcNow, maxAgeDays) ? SrsRecipientDecision.Accept : SrsRecipientDecision.Reject;

    /// <summary>Counts and logs a dropped bounce. Only its size is mentioned: neither the recipient (it names the original sender) nor anything of the message is logged.</summary>
    public void Drop(long size)
    {
        InboundActionMetrics.SrsBouncesDropped.Add(1);
        log.Write(MtaLogLevel.Information, "inbound", $"dropped a bounce to an SRS address of a forwarded message ({size} bytes)");
    }
}
