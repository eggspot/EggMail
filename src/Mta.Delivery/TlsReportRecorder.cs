using Mta.Smtp.Client;
using Mta.Tls;
using Mta.Tls.TlsRpt;

namespace Mta.Delivery;

/// <summary>
/// Feeds the TLS-RPT collector (RFC 8460) from outbound sessions. Only sessions to domains with an MTA-STS or DANE policy are
/// reported, as the RFC asks; connection failures that happen before TLS are not TLS failures and are not counted.
/// </summary>
public static class TlsReportRecorder
{
    /// <summary>A policy-forced refusal to use an MX host (for example a host that MTA-STS does not list).</summary>
    public static void RecordBlocked(TlsRptCollector? collector, TlsPolicyDecision decision, string? sendingIp)
    {
        if (collector is null || decision.PolicyType == TlsPolicyType.NoPolicyFound)
        {
            return;
        }

        collector.RecordFailure(decision.RecipientDomain, decision.TlsRptPolicy, decision.MxHost, decision.BlockedFailure ?? TlsResultType.ValidationFailure, sendingIp, additionalInformation: decision.BlockedReason);
    }

    /// <summary>Records the result of a session that reached the TLS stage: <c>tlsFailure</c> is set when the client could not establish TLS, <c>validation</c> is the certificate validator's verdict when a handshake took place.</summary>
    public static void RecordSession(TlsRptCollector? collector, TlsPolicyDecision decision, string? receivingIp, string? sendingIp, TlsFailure? tlsFailure, CertificateValidationOutcome? validation, bool tlsUsed)
    {
        if (collector is null || decision.PolicyType == TlsPolicyType.NoPolicyFound)
        {
            return;
        }

        var policy = decision.TlsRptPolicy;
        if (tlsFailure is { } failure)
        {
            var type = failure == TlsFailure.NotAdvertised || failure == TlsFailure.Refused
                ? TlsResultType.StarttlsNotSupported
                : validation?.Failure ?? TlsResultType.ValidationFailure;
            collector.RecordFailure(decision.RecipientDomain, policy, decision.MxHost, type, sendingIp, receivingIp);
        }
        else if (validation is { Accepted: false })
        {
            collector.RecordFailure(decision.RecipientDomain, policy, decision.MxHost, validation.Failure ?? TlsResultType.ValidationFailure, sendingIp, receivingIp);
        }
        else if (validation is { Accepted: true, Verified: false, Failure: { } tolerated })
        {
            // MTA-STS testing mode: the certificate failed validation, the policy lets the mail through, and the domain owner asked to hear about it (RFC 8460 section 2).
            collector.RecordFailure(decision.RecipientDomain, policy, decision.MxHost, tolerated, sendingIp, receivingIp);
        }
        else if (decision.ToleratedFailure is { } toleratedByPolicy)
        {
            collector.RecordFailure(decision.RecipientDomain, policy, decision.MxHost, toleratedByPolicy, sendingIp, receivingIp);
        }
        else if (tlsUsed)
        {
            collector.RecordSuccess(decision.RecipientDomain, policy, decision.MxHost, sendingIp, receivingIp);
        }
        else
        {
            collector.RecordFailure(decision.RecipientDomain, policy, decision.MxHost, TlsResultType.StarttlsNotSupported, sendingIp, receivingIp);
        }
    }
}
