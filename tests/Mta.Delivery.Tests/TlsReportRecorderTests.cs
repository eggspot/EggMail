using Mta.Smtp.Client;
using Mta.Tls;
using Mta.Tls.TlsRpt;

namespace Mta.Delivery.Tests;

public class TlsReportRecorderTests
{
    private static TlsPolicyDecision Decision(TlsPolicyType type) => new() { RecipientDomain = "example.net", MxHost = "mx.example.net", PolicyType = type };

    private static TlsRptPolicyAggregate Single(TlsRptCollector c) => Assert.Single(Assert.Single(c.Snapshot()).Policies);

    [Fact]
    public void Domains_without_a_policy_are_not_reported()
    {
        var c = new TlsRptCollector();
        TlsReportRecorder.RecordSession(c, Decision(TlsPolicyType.NoPolicyFound), "192.0.2.1", null, null, null, tlsUsed: true);
        TlsReportRecorder.RecordBlocked(c, Decision(TlsPolicyType.NoPolicyFound), null);
        Assert.Empty(c.Snapshot());
    }

    [Fact]
    public void A_policy_session_that_used_verified_tls_is_a_success()
    {
        var c = new TlsRptCollector();
        TlsReportRecorder.RecordSession(c, Decision(TlsPolicyType.Tlsa), "192.0.2.1", null, null, new CertificateValidationOutcome(true, true, null, System.Net.Security.SslPolicyErrors.None, []), tlsUsed: true);
        var p = Single(c);
        Assert.Equal((1, 0), (p.SuccessCount, p.FailureCount));
    }

    [Theory]
    [InlineData(TlsFailure.NotAdvertised, TlsResultType.StarttlsNotSupported)]
    [InlineData(TlsFailure.Refused, TlsResultType.StarttlsNotSupported)]
    [InlineData(TlsFailure.HandshakeFailed, TlsResultType.ValidationFailure)]
    public void Failed_tls_setup_is_a_failure_of_the_matching_type(TlsFailure failure, TlsResultType expected)
    {
        var c = new TlsRptCollector();
        TlsReportRecorder.RecordSession(c, Decision(TlsPolicyType.Sts), "192.0.2.1", null, failure, null, tlsUsed: false);
        var p = Single(c);
        Assert.Equal(1, p.FailureCount);
        Assert.Equal(expected, Assert.Single(p.FailureDetails).ResultType);
    }

    [Fact]
    public void A_rejected_certificate_reports_the_validators_reason()
    {
        var c = new TlsRptCollector();
        var outcome = new CertificateValidationOutcome(false, false, TlsResultType.CertificateHostMismatch, System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch, []);
        TlsReportRecorder.RecordSession(c, Decision(TlsPolicyType.Sts), "192.0.2.1", null, null, outcome, tlsUsed: true);
        Assert.Equal(TlsResultType.CertificateHostMismatch, Assert.Single(Single(c).FailureDetails).ResultType);
    }

    [Fact]
    public void A_host_the_policy_forbids_is_reported_with_the_policys_failure_type()
    {
        var c = new TlsRptCollector();
        var decision = new TlsPolicyDecision { RecipientDomain = "example.net", MxHost = "evil.example", PolicyType = TlsPolicyType.Sts, IsBlocked = true, BlockedFailure = TlsResultType.ValidationFailure, BlockedReason = "MX not in policy" };
        TlsReportRecorder.RecordBlocked(c, decision, "198.51.100.7");
        var d = Assert.Single(Single(c).FailureDetails);
        Assert.Equal("evil.example", d.ReceivingMxHostname);
        Assert.Equal("MX not in policy", d.AdditionalInformation);
    }
}
