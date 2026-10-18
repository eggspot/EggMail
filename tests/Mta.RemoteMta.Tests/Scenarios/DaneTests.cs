using System.Security.Cryptography.X509Certificates;
using Mta.Dns;
using Mta.RemoteMta.Tests.Harness;
using Mta.Storage;
using Mta.Tls;
using Mta.Tls.TlsRpt;
using static Mta.RemoteMta.Tests.Scenarios.StartTlsPolicyTests;

namespace Mta.RemoteMta.Tests.Scenarios;

/// <summary>
/// DANE for SMTP (RFC 7672) end to end through fake DNS: the AD bit decides whether TLSA records may be believed at all, a secure record set that does not fit is
/// a hard stop rather than a downgrade, and a signed domain that cannot be validated (SERVFAIL) is not mailed in clear.
/// </summary>
public class DaneTests
{
    private sealed class Setup(MtaLab lab, FakeMta mx, MtaPersonality peer, X509Certificate2 certificate) : IAsyncDisposable
    {
        public MtaLab Lab { get; } = lab;
        public FakeMta Mx { get; } = mx;
        public MtaPersonality Peer { get; } = peer;
        public X509Certificate2 Certificate { get; } = certificate;
        public string TlsaName => DnsName.TlsaName("mx.dest.example", Mx.Port);

        public ValueTask DisposeAsync() => Lab.DisposeAsync();

        public void Publish(byte usage, byte selector, byte matching, X509Certificate2? of = null) =>
            Lab.Dns.Tlsa("mx.dest.example", Mx.Port, usage, selector, matching, TestPki.TlsaData(of ?? Certificate, selector, matching));

        public void SignZone() => Lab.Dns.Secure("dest.example", "mx.dest.example", TlsaName);
    }

    private static Setup Start(bool tls = true, bool mtaSts = false, bool requireDane = false)
    {
        var lab = new MtaLab(new LabSettings { Dane = true, MtaSts = mtaSts, RequireDane = requireDane });
        var cert = lab.Cert("mx.dest.example");
        var peer = Personalities.Postfix(tls ? cert : null);
        var mx = lab.AddMta("mx.dest.example", peer);
        lab.Mx("dest.example", 10, "mx.dest.example");
        return new Setup(lab, mx, peer, cert);
    }

    private static TlsRptPolicyAggregate Aggregate(MtaLab lab) => lab.TlsRptFor("dest.example").Single();

    // -------------------------------------------------------------------------------------------- matching

    public static TheoryData<byte, byte> DaneEeParameters => new() { { 1, 1 }, { 1, 2 }, { 0, 1 }, { 0, 0 } };

    [Theory]
    [MemberData(nameof(DaneEeParameters))]
    public async Task A_secure_dane_ee_record_that_matches_the_certificate_authenticates_the_peer(byte selector, byte matching)
    {
        await using var s = Start();
        s.Publish(3, selector, matching);
        s.SignZone();

        var id = await s.Lab.SendAsync(["rcpt@dest.example"]);
        var events = await s.Lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.True(Assert.Single(s.Mx.Messages).Tls);
        var tls = events.Single(e => e.Type == MessageEventType.Delivered).Tls!;
        Assert.True(tls.Verified);
        Assert.Equal("Dane", tls.PolicyApplied);
        var report = Aggregate(s.Lab);
        Assert.Equal(TlsPolicyType.Tlsa, report.Policy.Type);
        Assert.Equal((1L, 0L), (report.SuccessCount, report.FailureCount));
        Assert.Single(report.Policy.PolicyString);
    }

    [Fact]
    public async Task Dane_ee_authenticates_a_self_signed_certificate_that_no_certificate_authority_vouches_for()
    {
        await using var s = Start();
        var selfSigned = TestPki.SelfSigned("whatever.invalid").ForServer();   // wrong name, no chain: DANE-EE does not look at either
        s.Peer.Certificate = _ => selfSigned;
        s.Publish(3, 1, 1, selfSigned);
        s.SignZone();

        var id = await s.Lab.SendAsync(["rcpt@dest.example"]);
        var events = await s.Lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.True(events.Single(e => e.Type == MessageEventType.Delivered).Tls!.Verified);
    }

    [Fact]
    public async Task During_a_certificate_rollover_either_of_two_published_records_is_enough()
    {
        await using var s = Start();
        var next = TestPki.SelfSigned("mx.dest.example").ForServer();
        s.Publish(3, 1, 1, next);   // the record of the certificate that will be installed next
        s.Publish(3, 1, 1);         // and the one in use now
        s.SignZone();

        var id = await s.Lab.SendAsync(["rcpt@dest.example"]);
        await s.Lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(s.Mx.Messages);
    }

    // ------------------------------------------------------------------------------------------ not matching

    [Fact]
    public async Task A_secure_record_set_that_does_not_fit_the_certificate_defers_never_downgrades_and_is_reported_until_dns_is_fixed()
    {
        await using var s = Start();
        s.Publish(3, 1, 1, TestPki.SelfSigned("some.other.example").ForServer());
        s.SignZone();

        var id = await s.Lab.SendAsync(["rcpt@dest.example"]);
        var due = await s.Lab.WaitForRetryScheduleAsync(id);

        Assert.Empty(s.Mx.Messages);
        Assert.Equal("4.7.5", (await s.Lab.EventsAsync(id)).Single(e => e.Type == MessageEventType.Deferred).EnhancedCode);
        var report = Aggregate(s.Lab);
        Assert.Equal((0L, 1L), (report.SuccessCount, report.FailureCount));
        Assert.Equal([TlsResultType.ValidationFailure], report.FailureDetails.Select(d => d.ResultType));

        s.Lab.Dns.Remove(s.TlsaName, DnsRecordType.TLSA);
        s.Publish(3, 1, 1);
        s.Lab.Advance(due - s.Lab.Clock.UtcNow);
        await s.Lab.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.True(Assert.Single(s.Mx.Messages).Tls);
    }

    [Fact]
    public async Task Tlsa_records_that_the_resolver_did_not_validate_are_ignored_even_when_they_are_wrong()
    {
        await using var s = Start();
        s.Publish(3, 1, 1, TestPki.SelfSigned("some.other.example").ForServer());
        s.Lab.Dns.Secure("dest.example", "mx.dest.example");   // the MX is signed, the TLSA answer carries no AD bit

        var id = await s.Lab.SendAsync(["rcpt@dest.example"]);
        var events = await s.Lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(s.Mx.Messages);
        Assert.Equal("Opportunistic", events.Single(e => e.Type == MessageEventType.Delivered).Tls!.PolicyApplied);
        Assert.Empty(s.Lab.TlsRptFor("dest.example"));
    }

    [Fact]
    public async Task Dane_does_not_apply_when_the_mx_record_set_itself_is_not_validated()
    {
        await using var s = Start();
        s.Publish(3, 1, 1, TestPki.SelfSigned("some.other.example").ForServer());
        s.Lab.Dns.Secure("mx.dest.example", s.TlsaName);   // a signed TLSA under an unsigned MX RRset (RFC 7672 section 2.2.1)

        var id = await s.Lab.SendAsync(["rcpt@dest.example"]);
        var events = await s.Lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Equal("Opportunistic", events.Single(e => e.Type == MessageEventType.Delivered).Tls!.PolicyApplied);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 0)]
    public async Task A_secure_set_with_only_unusable_usages_blocks_the_mx_instead_of_downgrading(byte usage, byte matching)
    {
        await using var s = Start();
        s.Publish(usage, 1, matching);   // PKIX-TA and PKIX-EE are not valid for SMTP (RFC 7672 section 3.1.3)
        s.SignZone();

        var id = await s.Lab.SendAsync(["rcpt@dest.example"]);
        await s.Lab.WaitForEventAsync(id, MessageEventType.Deferred);

        Assert.Equal(0, s.Mx.ConnectionCount);
        Assert.Equal([TlsResultType.TlsaInvalid], Aggregate(s.Lab).FailureDetails.Select(d => d.ResultType));
    }

    [Fact]
    public async Task A_servfail_on_the_tlsa_lookup_means_failed_dnssec_validation_and_the_mx_is_not_used()
    {
        await using var s = Start();
        s.Publish(3, 1, 1);
        s.SignZone();
        s.Lab.Dns.Servfail(s.TlsaName, DnsRecordType.TLSA);

        var id = await s.Lab.SendAsync(["rcpt@dest.example"]);
        var due = await s.Lab.WaitForRetryScheduleAsync(id);

        Assert.Equal(0, s.Mx.ConnectionCount);
        Assert.Equal([TlsResultType.DnssecInvalid], Aggregate(s.Lab).FailureDetails.Select(d => d.ResultType));

        s.Lab.Dns.Heal(s.TlsaName, DnsRecordType.TLSA);
        s.Lab.Advance(due - s.Lab.Clock.UtcNow);
        await s.Lab.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.Single(s.Mx.Messages);
    }

    [Fact]
    public async Task A_resolver_that_cannot_be_reached_for_the_tlsa_lookup_defers_instead_of_sending_in_the_clear()
    {
        await using var s = Start();
        s.Publish(3, 1, 1);
        s.SignZone();
        s.Lab.Dns.Unreachable(s.TlsaName, DnsRecordType.TLSA);

        var id = await s.Lab.SendAsync(["rcpt@dest.example"]);
        await s.Lab.WaitForEventAsync(id, MessageEventType.Deferred);

        Assert.Empty(s.Mx.Messages);
        Assert.Equal(0, s.Mx.ConnectionCount);
    }

    [Fact]
    public async Task When_dane_is_required_by_configuration_an_mx_without_tlsa_is_not_used()
    {
        await using var s = Start(requireDane: true);
        s.SignZone();

        var id = await s.Lab.SendAsync(["rcpt@dest.example"]);
        await s.Lab.WaitForEventAsync(id, MessageEventType.Deferred);

        Assert.Equal(0, s.Mx.ConnectionCount);
        Assert.Equal([TlsResultType.DaneRequired], Aggregate(s.Lab).FailureDetails.Select(d => d.ResultType));
    }

    // ------------------------------------------------------------------------------------- STARTTLS under dane

    [Fact]
    public async Task A_dane_protected_mx_that_offers_no_starttls_is_refused_and_reported()
    {
        await using var s = Start(tls: false);
        s.Publish(3, 1, 1);
        s.SignZone();

        var id = await s.Lab.SendAsync(["rcpt@dest.example"]);
        await s.Lab.WaitForEventAsync(id, MessageEventType.Deferred);

        Assert.Empty(s.Mx.Messages);
        Assert.Equal([TlsResultType.StarttlsNotSupported], Aggregate(s.Lab).FailureDetails.Select(d => d.ResultType));
    }

    [Fact]
    public async Task A_dane_protected_mx_that_drops_starttls_after_the_first_contact_cannot_be_downgraded()
    {
        await using var s = Start();
        s.Publish(3, 1, 1);
        s.SignZone();
        s.Peer.OffersStartTls = session => session.Index == 0;

        var first = await s.Lab.SendAsync(["one@dest.example"]);
        await s.Lab.WaitForEventAsync(first, MessageEventType.Delivered);
        s.Mx.DropOpenConnections();
        var second = await s.Lab.SendAsync(["two@dest.example"]);
        await s.Lab.WaitForEventAsync(second, MessageEventType.Deferred);

        Assert.Equal([true], s.Mx.Messages.Select(m => m.Tls));
    }

    [Fact]
    public async Task A_dane_protected_mx_whose_handshake_breaks_is_not_retried_in_plaintext()
    {
        await using var s = Start();
        s.Publish(3, 1, 1);
        s.SignZone();
        s.Peer.StartTls = StartTlsBehaviour.ClosesAfter220;

        var id = await s.Lab.SendAsync(["rcpt@dest.example"]);
        await s.Lab.WaitForEventAsync(id, MessageEventType.Deferred);

        Assert.Empty(s.Mx.Messages);
        Assert.Equal(1, s.Mx.ConnectionCount);
    }

    [Fact]
    public async Task Dane_takes_precedence_over_an_mta_sts_policy_that_would_refuse_the_mx()
    {
        await using var s = Start(mtaSts: true);
        s.Publish(3, 1, 1);
        s.SignZone();
        s.Lab.Dns.MtaStsId("dest.example", "v1");
        s.Lab.StsWeb!.Respond = _ => WebAnswer.Policy("enforce", ["mx.unrelated.example"]);

        var id = await s.Lab.SendAsync(["rcpt@dest.example"]);
        var events = await s.Lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Equal("Dane", events.Single(e => e.Type == MessageEventType.Delivered).Tls!.PolicyApplied);
    }

    [Fact]
    public async Task An_mx_that_is_an_alias_is_authenticated_by_the_tlsa_records_of_its_target()
    {
        var lab = new MtaLab(new LabSettings { Dane = true });
        await using var _l = lab;
        var cert = lab.Cert("real.provider.example");
        var mx = lab.AddMta("real.provider.example", Personalities.Postfix(cert));
        lab.Dns.Cname("mx.dest.example", "real.provider.example");
        lab.MapPort("mx.dest.example", mx.Port);
        lab.Mx("dest.example", 10, "mx.dest.example");
        lab.Dns.Tlsa("real.provider.example", mx.Port, 3, 1, 1, TestPki.TlsaData(cert, 1, 1));   // published under the target's name, as RFC 7672 section 2.2.2 looks first
        lab.Dns.Secure("dest.example", "mx.dest.example", "real.provider.example", DnsName.TlsaName("real.provider.example", mx.Port));

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.True(events.Single(e => e.Type == MessageEventType.Delivered).Tls!.Verified);
        Assert.Equal("Dane", events.Single(e => e.Type == MessageEventType.Delivered).Tls!.PolicyApplied);
    }
}
