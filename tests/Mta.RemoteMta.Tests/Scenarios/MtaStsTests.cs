using Mta.RemoteMta.Tests.Harness;
using System.Text.Json;
using Mta.Storage;
using Mta.Tls;
using Mta.Tls.TlsRpt;
using static Mta.RemoteMta.Tests.Scenarios.StartTlsPolicyTests;

namespace Mta.RemoteMta.Tests.Scenarios;

/// <summary>
/// MTA-STS (RFC 8461) end to end: the TXT id through fake DNS, the policy over HTTPS from a loopback web server (real TLS, real certificate validation against a
/// private root), the policy cache on the fake clock, and the TLS-RPT records that each session leaves behind.
/// </summary>
public class MtaStsTests
{
    private static readonly string[] OwnMx = ["mx.dest.example"];

    private static (MtaLab Lab, FakeMta Mx, MtaPersonality Peer) Start(string mode, string[]? patterns = null, CertKind? certificate = CertKind.Valid, LabSettings? settings = null)
    {
        var lab = new MtaLab(settings ?? new LabSettings { MtaSts = true });
        var peer = Personalities.Postfix();
        if (certificate is { } kind)
        {
            peer.Certificate = _ => Make(lab, kind);
        }

        var mx = lab.AddMta("mx.dest.example", peer);
        lab.Mx("dest.example", 10, "mx.dest.example");
        lab.Dns.MtaStsId("dest.example", "v1");
        lab.StsWeb!.Respond = host => host == "mta-sts.dest.example" ? WebAnswer.Policy(mode, patterns ?? OwnMx) : WebAnswer.NotFound;
        return (lab, mx, peer);
    }

    private static (long Success, long Failure, IReadOnlyList<TlsResultType> Types, TlsPolicyType Policy) Report(MtaLab lab)
    {
        var aggregates = lab.TlsRptFor("dest.example");
        var policy = aggregates.Single();
        return (policy.SuccessCount, policy.FailureCount, policy.FailureDetails.Select(d => d.ResultType).ToArray(), policy.Policy.Type);
    }

    // --------------------------------------------------------------------------------------------- enforce

    [Fact]
    public async Task Enforce_with_a_listed_mx_and_a_valid_certificate_delivers_over_verified_tls_and_reports_one_success()
    {
        var (lab, mx, _) = Start("enforce");
        await using var _l = lab;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.True(Assert.Single(mx.Messages).Tls);
        var tls = events.Single(e => e.Type == MessageEventType.Delivered).Tls!;
        Assert.True(tls.Verified);
        Assert.Equal("MtaStsEnforce", tls.PolicyApplied);
        var report = Report(lab);
        Assert.Equal((1L, 0L, TlsPolicyType.Sts), (report.Success, report.Failure, report.Policy));
        var policy = lab.TlsRptFor("dest.example").Single().Policy;
        Assert.Contains("mode: enforce", policy.PolicyString);
        Assert.Contains("mx.dest.example", policy.MxHosts);
    }

    [Fact]
    public async Task Enforce_never_connects_to_an_mx_the_policy_does_not_list_and_reports_it()
    {
        var (lab, mx, _) = Start("enforce", ["*.mail.other.example"]);
        await using var _l = lab;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Deferred);

        var deferred = (await lab.EventsAsync(id)).Single(e => e.Type == MessageEventType.Deferred);
        Assert.Equal("4.7.5", deferred.EnhancedCode);
        Assert.Contains("MTA-STS", deferred.Message);
        Assert.Equal(0, mx.ConnectionCount);
        Assert.Empty(mx.Messages);
        var report = Report(lab);
        Assert.Equal((0L, 1L), (report.Success, report.Failure));
        Assert.Equal([TlsResultType.ValidationFailure], report.Types);
        Assert.Equal("mx.dest.example", lab.TlsRptFor("dest.example").Single().FailureDetails.Single().ReceivingMxHostname);
    }

    [Theory]
    [InlineData(CertKind.WrongName, TlsResultType.CertificateHostMismatch)]
    [InlineData(CertKind.Expired, TlsResultType.CertificateExpired)]
    [InlineData(CertKind.UntrustedCa, TlsResultType.CertificateNotTrusted)]
    public async Task Enforce_refuses_a_bad_certificate_defers_reports_the_exact_reason_and_delivers_once_the_certificate_is_fixed(CertKind kind, TlsResultType reported)
    {
        var (lab, mx, peer) = Start("enforce", certificate: kind);
        await using var _l = lab;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);

        Assert.Empty(mx.Messages);
        var report = Report(lab);
        Assert.Equal((0L, 1L), (report.Success, report.Failure));
        Assert.Equal([reported], report.Types);

        peer.Certificate = _ => Make(lab, CertKind.Valid);
        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.True(Assert.Single(mx.Messages).Tls);
        Assert.Equal(1, Report(lab).Success);
    }

    [Fact]
    public async Task Enforce_defers_when_the_mx_offers_no_starttls_and_reports_starttls_not_supported()
    {
        var (lab, mx, _) = Start("enforce", certificate: null);
        await using var _l = lab;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Deferred);

        Assert.Empty(mx.Messages);
        Assert.Equal([TlsResultType.StarttlsNotSupported], Report(lab).Types);
    }

    [Fact]
    public async Task Enforce_catches_a_downgrade_that_opportunistic_tls_cannot_the_peer_drops_starttls_on_the_second_contact()
    {
        var (lab, mx, peer) = Start("enforce");
        await using var _l = lab;
        peer.OffersStartTls = s => s.Index == 0;

        var first = await lab.SendAsync(["one@dest.example"]);
        await lab.WaitForEventAsync(first, MessageEventType.Delivered);
        mx.DropOpenConnections();
        var second = await lab.SendAsync(["two@dest.example"]);
        await lab.WaitForEventAsync(second, MessageEventType.Deferred);

        Assert.Equal([true], mx.Messages.Select(m => m.Tls));
        var report = Report(lab);
        Assert.Equal((1L, 1L), (report.Success, report.Failure));
        Assert.Equal([TlsResultType.StarttlsNotSupported], report.Types);
    }

    [Fact]
    public async Task Enforce_skips_an_unlisted_mx_with_a_better_preference_and_never_contacts_it()
    {
        var lab = new MtaLab(new LabSettings { MtaSts = true });
        await using var _l = lab;
        var rogue = lab.AddMta("mx.rogue.example", Personalities.Postfix(lab.Cert("mx.rogue.example")));
        var good = lab.AddMta("mx.dest.example", Personalities.Postfix(lab.Cert("mx.dest.example")));
        lab.Mx("dest.example", 5, "mx.rogue.example").Mx("dest.example", 10, "mx.dest.example");
        lab.Dns.MtaStsId("dest.example", "v1");
        lab.StsWeb!.Respond = _ => WebAnswer.Policy("enforce", OwnMx);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Equal(0, rogue.ConnectionCount);   // a spoofed MX record with a better preference is not even contacted
        Assert.Single(good.Messages);
    }

    [Fact]
    public async Task The_daily_tls_rpt_report_built_from_the_sessions_has_the_rfc_8460_fields_for_a_failure_and_a_success()
    {
        var (lab, mx, peer) = Start("enforce", certificate: CertKind.WrongName);
        await using var _l = lab;
        var failed = await lab.SendAsync(["one@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(failed);
        peer.Certificate = _ => Make(lab, CertKind.Valid);
        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(failed, MessageEventType.Delivered);

        var data = lab.TlsReports.Snapshot().Single(d => d.PolicyDomain == "dest.example");
        var report = new TlsRptReportBuilder(new TlsRptReportOptions { OrganizationName = "EggMail Lab", ContactInfo = "postmaster@example.org", SubmitterDomain = "egg.test", ReportIdFactory = () => "report-1" }).Build(data);
        using var json = JsonDocument.Parse(report.Json);
        var root = json.RootElement;

        Assert.Equal("EggMail Lab", root.GetProperty("organization-name").GetString());
        var policy = Assert.Single(root.GetProperty("policies").EnumerateArray());
        Assert.Equal("sts", policy.GetProperty("policy").GetProperty("policy-type").GetString());
        Assert.Equal("dest.example", policy.GetProperty("policy").GetProperty("policy-domain").GetString());
        Assert.Equal(1, policy.GetProperty("summary").GetProperty("total-successful-session-count").GetInt32());
        Assert.Equal(1, policy.GetProperty("summary").GetProperty("total-failure-session-count").GetInt32());
        var detail = Assert.Single(policy.GetProperty("failure-details").EnumerateArray());
        Assert.Equal("certificate-host-mismatch", detail.GetProperty("result-type").GetString());
        Assert.Equal("mx.dest.example", detail.GetProperty("receiving-mx-hostname").GetString());
        Assert.Equal(1, detail.GetProperty("failed-session-count").GetInt32());
        Assert.EndsWith(".json.gz", report.FileName);
        Assert.Single(mx.Messages);
    }

    // ---------------------------------------------------------------------------------------------- testing

    [Fact]
    public async Task Testing_mode_delivers_despite_a_bad_certificate_and_reports_the_failure_for_the_domain_owner()
    {
        var (lab, mx, _) = Start("testing", certificate: CertKind.WrongName);
        await using var _l = lab;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.True(Assert.Single(mx.Messages).Tls);
        Assert.Equal("MtaStsTesting", events.Single(e => e.Type == MessageEventType.Delivered).Tls!.PolicyApplied);
        var report = Report(lab);
        Assert.Equal((0L, 1L), (report.Success, report.Failure));   // a session that did not satisfy the policy is a failed session even though the mail went out
        Assert.Equal([TlsResultType.CertificateHostMismatch], report.Types);
    }

    [Fact]
    public async Task Testing_mode_delivers_to_an_unlisted_mx_and_reports_the_mismatch()
    {
        var (lab, mx, _) = Start("testing", ["mx.somewhere-else.example"]);
        await using var _l = lab;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(mx.Messages);
        var report = Report(lab);
        Assert.Equal((0L, 1L), (report.Success, report.Failure));
        Assert.Equal([TlsResultType.ValidationFailure], report.Types);
    }

    [Fact]
    public async Task Testing_mode_with_a_good_peer_is_a_plain_success()
    {
        var (lab, _, _) = Start("testing");
        await using var _l = lab;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        var report = Report(lab);
        Assert.Equal((1L, 0L), (report.Success, report.Failure));
    }

    [Fact]
    public async Task Testing_mode_survives_a_broken_starttls_upgrade_by_delivering_in_plaintext_and_reports_it_once()
    {
        var (lab, mx, peer) = Start("testing");
        await using var _l = lab;
        peer.StartTls = StartTlsBehaviour.ClosesAfter220;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.False(Assert.Single(mx.Messages).Tls);
        var report = Report(lab);
        Assert.Equal(1, report.Failure);   // one failed upgrade, not a second failure for the plaintext session that followed
        Assert.Equal(0, report.Success);
    }

    [Fact]
    public async Task A_policy_in_mode_none_withdraws_enforcement()
    {
        var (lab, mx, _) = Start("none", certificate: CertKind.WrongName);
        await using var _l = lab;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(mx.Messages);
        Assert.Empty(lab.TlsRptFor("dest.example"));   // nothing to report against
    }

    // ------------------------------------------------------------------------------------- fetching the policy

    public static TheoryData<string> BrokenPolicyServers => new() { "404", "redirect", "html", "garbage", "oversized", "bad-version", "web-wrong-name", "web-expired", "web-untrusted-ca" };

    [Theory]
    [MemberData(nameof(BrokenPolicyServers))]
    public async Task Without_a_cached_policy_a_failing_fetch_fails_open_to_opportunistic_delivery_and_is_not_retried_for_five_minutes(string failure)
    {
        var (lab, mx, _) = Start("enforce", certificate: CertKind.WrongName);   // a peer that enforce would refuse
        await using var _l = lab;
        var web = lab.StsWeb!;
        switch (failure)
        {
            case "404": web.Respond = _ => WebAnswer.NotFound; break;
            case "redirect": web.Respond = _ => WebAnswer.RedirectTo("https://elsewhere.example/policy"); break;
            case "html": web.Respond = _ => WebAnswer.Raw("<html>version: STSv1</html>", "text/html"); break;
            case "garbage": web.Respond = _ => WebAnswer.Raw("this is not a policy"); break;
            case "oversized": web.Respond = _ => WebAnswer.Raw("version: STSv1\r\nmode: enforce\r\nmx: mx.dest.example\r\nmax_age: 86400\r\n" + new string('#', 70_000)); break;
            case "bad-version": web.Respond = _ => WebAnswer.Raw("version: STSv2\r\nmode: enforce\r\nmx: mx.dest.example\r\nmax_age: 86400\r\n"); break;
            case "web-wrong-name": web.CertificateFor = _ => Make(lab, CertKind.WrongName, "mta-sts.dest.example"); break;
            case "web-expired": web.CertificateFor = _ => Make(lab, CertKind.Expired, "mta-sts.dest.example"); break;
            case "web-untrusted-ca": web.CertificateFor = _ => Make(lab, CertKind.UntrustedCa, "mta-sts.dest.example"); break;
        }

        var first = await lab.SendAsync(["one@dest.example"]);
        var events = await lab.WaitForEventAsync(first, MessageEventType.Delivered);

        Assert.Single(mx.Messages);   // delivered although the peer would fail an enforce policy: no policy was learned
        Assert.Equal("Opportunistic", events.Single(e => e.Type == MessageEventType.Delivered).Tls!.PolicyApplied);
        int fetches = web.Connections;
        Assert.Equal(1, fetches);

        var second = await lab.SendAsync(["two@dest.example"]);
        await lab.WaitForEventAsync(second, MessageEventType.Delivered);
        Assert.Equal(fetches, web.Connections);   // inside the failure back-off the fetch is not repeated

        lab.Advance(TimeSpan.FromMinutes(6));
        var third = await lab.SendAsync(["three@dest.example"]);
        await lab.WaitForEventAsync(third, MessageEventType.Delivered);
        Assert.True(web.Connections > fetches, "after the back-off the policy is fetched again");
    }

    [Fact]
    public async Task A_policy_server_that_never_answers_times_out_and_delivery_proceeds_without_a_policy()
    {
        var (lab, mx, _) = Start("enforce", settings: new LabSettings { MtaSts = true, MtaStsFetchTimeout = TimeSpan.FromSeconds(1) });
        await using var _l = lab;
        lab.StsWeb!.Respond = _ => WebAnswer.Hang;

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(mx.Messages);
        Assert.Equal("Opportunistic", events.Single(e => e.Type == MessageEventType.Delivered).Tls!.PolicyApplied);
    }

    [Fact]
    public async Task A_cached_enforce_policy_keeps_protecting_the_domain_while_the_policy_server_is_down_and_stops_at_max_age()
    {
        var (lab, mx, peer) = Start("enforce", certificate: CertKind.Valid);
        await using var _l = lab;
        var first = await lab.SendAsync(["one@dest.example"]);
        await lab.WaitForEventAsync(first, MessageEventType.Delivered);

        // The domain publishes a new policy id; its web server is down; and the MX presents a certificate that enforce rejects.
        lab.Dns.RemoveAll("_mta-sts.dest.example").MtaStsId("dest.example", "v2");
        lab.StsWeb!.Respond = _ => WebAnswer.NotFound;
        peer.Certificate = _ => Make(lab, CertKind.WrongName);
        mx.DropOpenConnections();
        lab.Advance(TimeSpan.FromHours(2));

        var second = await lab.SendAsync(["two@dest.example"]);
        await lab.WaitForEventAsync(second, MessageEventType.Deferred);
        Assert.Equal([true], mx.Messages.Select(m => m.Tls));   // the stale policy still applies: refused, not sent

        // After max_age (one day, counted from the fetch) the policy is gone and nothing protects the domain any more.
        lab.Advance(TimeSpan.FromHours(30));
        await lab.WaitForEventAsync(second, MessageEventType.Delivered);
        Assert.Equal(2, mx.Messages.Count);
    }

    [Fact]
    public async Task A_changed_policy_id_makes_the_engine_fetch_the_new_policy_and_an_unchanged_one_is_not_refetched_before_the_revalidation_interval()
    {
        var (lab, _, _) = Start("testing");
        await using var _l = lab;

        var a = await lab.SendAsync(["a@dest.example"]);
        await lab.WaitForEventAsync(a, MessageEventType.Delivered);
        Assert.Equal(1, lab.StsWeb!.Requests);

        lab.Advance(TimeSpan.FromHours(3));
        var b = await lab.SendAsync(["b@dest.example"]);
        await lab.WaitForEventAsync(b, MessageEventType.Delivered);
        Assert.Equal(1, lab.StsWeb.Requests);   // same id, fetched three hours ago

        lab.StsWeb.Respond = _ => WebAnswer.Policy("enforce", OwnMx);
        lab.Dns.RemoveAll("_mta-sts.dest.example").MtaStsId("dest.example", "v2");
        var c = await lab.SendAsync(["c@dest.example"]);
        var events = await lab.WaitForEventAsync(c, MessageEventType.Delivered);
        Assert.Equal(2, lab.StsWeb.Requests);
        Assert.Equal("MtaStsEnforce", events.Single(e => e.Type == MessageEventType.Delivered).Tls!.PolicyApplied);

        lab.Advance(TimeSpan.FromHours(25));
        var d = await lab.SendAsync(["d@dest.example"]);
        await lab.WaitForEventAsync(d, MessageEventType.Delivered);
        Assert.Equal(3, lab.StsWeb.Requests);   // revalidated after 24 hours although the id did not change
    }

    [Theory]
    [InlineData("*.dest.example", "mx.dest.example", true)]
    [InlineData("*.dest.example", "a.b.dest.example", false)]
    [InlineData("mx.dest.example", "mx.dest.example", true)]
    [InlineData("MX.DEST.EXAMPLE", "mx.dest.example", true)]
    [InlineData("dest.example", "mx.dest.example", false)]
    public async Task Policy_mx_patterns_follow_the_rfc_matching_rules(string pattern, string mxHost, bool allowed)
    {
        var lab = new MtaLab(new LabSettings { MtaSts = true });
        await using var _l = lab;
        var mx = lab.AddMta(mxHost, Personalities.Postfix(lab.Cert(mxHost)));
        lab.Mx("dest.example", 10, mxHost);
        lab.Dns.MtaStsId("dest.example", "v1");
        lab.StsWeb!.Respond = _ => WebAnswer.Policy("enforce", [pattern]);

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, allowed ? MessageEventType.Delivered : MessageEventType.Deferred);

        Assert.Equal(allowed, mx.Messages.Count == 1);
    }
}
