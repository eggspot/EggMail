using System.Net;
using Mta.Dkim;
using Mta.Dns;
using Mta.Host.Domains;
using Mta.Policy;

namespace Mta.Host.Tests;

/// <summary>
/// The full record set of a domain (SPF, DKIM, DMARC, return-path CNAME, bounce MX, MTA-STS, TLS-RPT, reverse DNS) against a fake DNS: each record type is
/// found as expected, missing, or wrong in the way that type can be wrong, and the result carries the expected and the found value.
/// </summary>
public class DomainRecordCheckTests
{
    private const string Domain = "example.com";
    private const string Server = "mta.mail.test";
    private const string SendingIp = "192.0.2.10";

    private static readonly DomainRecordOptions Full = new()
    {
        BounceDomain = "bounces.mail.test",
        ServerHostname = Server,
        PublicSendingIp = SendingIp,
        MtaStsMode = MtaStsServingMode.Testing,
    };

    private static IReadOnlyList<ExpectedDomainRecord> PlanFor(DomainRecordOptions? options = null)
    {
        using var rsa = DkimKeyTools.GenerateRsa2048();
        return DomainRecordPlanner.Plan(Domain, [new DomainDkimKey("egg202610", DkimKeyTools.ExportPublicKeyBase64(rsa))], options ?? Full);
    }

    private static ExpectedDomainRecord Of(IReadOnlyList<ExpectedDomainRecord> plan, DomainRecordPurpose purpose) => plan.Single(r => r.Purpose == purpose);

    private static async Task<DomainRecordCheck> CheckAsync(StaticDnsResolver dns, IReadOnlyList<ExpectedDomainRecord> plan, DomainRecordPurpose purpose)
    {
        var result = await new DomainChecker(dns).CheckAsync([Of(plan, purpose)], default);
        return Assert.Single(result.Records);
    }

    /// <summary>Publishes a record exactly as planned.</summary>
    private static void Publish(StaticDnsResolver dns, ExpectedDomainRecord r)
    {
        switch (r.Type)
        {
            case "TXT":
                dns.AddTxt(r.Host, r.Value);
                break;
            case "CNAME":
                dns.AddCname(r.Host, r.Value);
                break;
            case "MX":
                dns.AddMx(r.Host, ushort.Parse(r.Value.Split(' ')[0]), r.Value.Split(' ')[1]);
                break;
            case "PTR":
                dns.AddA(Server, SendingIp);
                dns.AddPtr(IPAddress.Parse(SendingIp), r.Value);
                break;
        }
    }

    // The plan

    [Fact]
    public void The_plan_covers_dkim_spf_dmarc_return_path_bounce_mx_mta_sts_tls_rpt_and_reverse_dns()
    {
        var plan = PlanFor();
        Assert.Equal(
            [DomainRecordPurpose.Dkim, DomainRecordPurpose.ReturnPath, DomainRecordPurpose.Spf, DomainRecordPurpose.Dmarc, DomainRecordPurpose.TlsRpt, DomainRecordPurpose.MtaSts, DomainRecordPurpose.MtaStsHost, DomainRecordPurpose.BounceMx, DomainRecordPurpose.Ptr],
            plan.Select(r => r.Purpose));
        Assert.Equal([DomainRecordPurpose.Dkim, DomainRecordPurpose.ReturnPath], plan.Where(r => r.Required).Select(r => r.Purpose));
        Assert.All(plan, r => Assert.False(string.IsNullOrWhiteSpace(r.Note)));

        Assert.Equal("v=spf1 ip4:192.0.2.10 ~all", Of(plan, DomainRecordPurpose.Spf).Value);
        Assert.Equal("v=DMARC1; p=none; rua=mailto:dmarc@example.com", Of(plan, DomainRecordPurpose.Dmarc).Value);
        Assert.Equal(("_smtp._tls.example.com", "v=TLSRPTv1; rua=mailto:tls-rpt@example.com"), (Of(plan, DomainRecordPurpose.TlsRpt).Host, Of(plan, DomainRecordPurpose.TlsRpt).Value));
        Assert.Equal(("CNAME", "bounce.example.com", "bounces.mail.test"), (Of(plan, DomainRecordPurpose.ReturnPath).Type, Of(plan, DomainRecordPurpose.ReturnPath).Host, Of(plan, DomainRecordPurpose.ReturnPath).Value));
        Assert.Equal(("MX", "bounces.mail.test", "10 mta.mail.test"), (Of(plan, DomainRecordPurpose.BounceMx).Type, Of(plan, DomainRecordPurpose.BounceMx).Host, Of(plan, DomainRecordPurpose.BounceMx).Value));
        Assert.Equal(("_mta-sts.example.com", $"v=STSv1; id={MtaStsPolicyDocument.PolicyId(Full)}"), (Of(plan, DomainRecordPurpose.MtaSts).Host, Of(plan, DomainRecordPurpose.MtaSts).Value));
        Assert.Equal(("CNAME", "mta-sts.example.com", "mta.mail.test"), (Of(plan, DomainRecordPurpose.MtaStsHost).Type, Of(plan, DomainRecordPurpose.MtaStsHost).Host, Of(plan, DomainRecordPurpose.MtaStsHost).Value));
        Assert.Equal(("PTR", "10.2.0.192.in-addr.arpa", "mta.mail.test"), (Of(plan, DomainRecordPurpose.Ptr).Type, Of(plan, DomainRecordPurpose.Ptr).Host, Of(plan, DomainRecordPurpose.Ptr).Value));
    }

    [Fact]
    public void Mta_sts_records_appear_only_when_the_policy_is_served()
    {
        var plan = PlanFor(new DomainRecordOptions { BounceDomain = "bounces.mail.test", ServerHostname = Server });
        Assert.DoesNotContain(plan, r => r.Purpose is DomainRecordPurpose.MtaSts or DomainRecordPurpose.MtaStsHost);
        Assert.Contains(plan, r => r.Purpose == DomainRecordPurpose.BounceMx);
    }

    [Fact]
    public void Without_a_fully_qualified_host_name_there_is_no_bounce_mx_mta_sts_or_reverse_dns_advice()
    {
        Assert.Null(DomainRecordOptions.UsableHostname("localhost"));
        Assert.Null(DomainRecordOptions.UsableHostname("192.0.2.1"));
        Assert.Equal("mta.example.net", DomainRecordOptions.UsableHostname(" MTA.Example.NET. "));
        var plan = PlanFor(new DomainRecordOptions { BounceDomain = "bounces.mail.test", MtaStsMode = MtaStsServingMode.Enforce });
        // Nothing to authorize, nothing about mail the domain receives: no SPF (v=spf1 ~all would authorize nothing), no TLS-RPT, no MTA-STS.
        Assert.Equal([DomainRecordPurpose.Dkim, DomainRecordPurpose.ReturnPath, DomainRecordPurpose.Dmarc], plan.Select(r => r.Purpose));
    }

    [Fact]
    public void Spf_authorizes_the_include_and_the_sending_ip_or_otherwise_the_host_name()
    {
        Assert.Equal("v=spf1 include:spf.mail.test ~all", DomainRecordPlanner.SpfValue(new DomainRecordOptions { SpfInclude = "SPF.mail.test." }));
        Assert.Equal("v=spf1 include:spf.mail.test ip4:192.0.2.10 ~all", DomainRecordPlanner.SpfValue(new DomainRecordOptions { SpfInclude = "spf.mail.test", PublicSendingIp = "192.0.2.10" }));
        Assert.Equal("v=spf1 ip6:2001:db8::1 ~all", DomainRecordPlanner.SpfValue(new DomainRecordOptions { PublicSendingIp = "2001:db8::1" }));
        Assert.Equal("v=spf1 a:mta.mail.test ~all", DomainRecordPlanner.SpfValue(new DomainRecordOptions { ServerHostname = Server }));
        Assert.Null(DomainRecordPlanner.SpfValue(new DomainRecordOptions()));   // nothing to authorize: "v=spf1 ~all" would soft-fail every sender
    }

    [Fact]
    public void Dmarc_and_tls_rpt_use_the_configured_policy_and_report_addresses()
    {
        var options = new DomainRecordOptions { DmarcPolicy = "quarantine", DmarcReportAddress = "reports@ops.test", TlsReportAddress = "https://tls.ops.test/{domain}" };
        Assert.Equal("v=DMARC1; p=quarantine; rua=mailto:reports@ops.test", DomainRecordPlanner.DmarcValue("example.com", options));
        Assert.Equal("v=TLSRPTv1; rua=https://tls.ops.test/example.com", DomainRecordPlanner.TlsRptValue("example.com", options));
        Assert.Equal("v=DMARC1; p=none; rua=mailto:dmarc-example.com@ops.test", DomainRecordPlanner.DmarcValue("example.com", new DomainRecordOptions { DmarcReportAddress = "dmarc-{domain}@ops.test" }));
        Assert.Equal("v=TLSRPTv1; rua=mailto:tls@ops.test", DomainRecordPlanner.TlsRptValue("example.com", new DomainRecordOptions { TlsReportAddress = "tls@ops.test" }));
    }

    [Fact]
    public void The_mta_sts_id_changes_exactly_when_the_policy_changes()
    {
        string testing = MtaStsPolicyDocument.PolicyId(Full);
        Assert.Matches("^[0-9a-f]{16}$", testing);
        Assert.Equal(testing, MtaStsPolicyDocument.PolicyId(Full));
        Assert.NotEqual(testing, MtaStsPolicyDocument.PolicyId(new DomainRecordOptions { ServerHostname = Server, MtaStsMode = MtaStsServingMode.Enforce }));
        Assert.NotEqual(testing, MtaStsPolicyDocument.PolicyId(new DomainRecordOptions { ServerHostname = Server, MtaStsMode = MtaStsServingMode.Testing, MtaStsMaxAge = TimeSpan.FromDays(1) }));
        Assert.NotEqual(testing, MtaStsPolicyDocument.PolicyId(new DomainRecordOptions { ServerHostname = "other.mail.test", MtaStsMode = MtaStsServingMode.Testing }));
    }

    [Fact]
    public void The_mta_sts_policy_names_the_mx_hosts_the_mode_and_the_max_age()
    {
        Assert.Equal("version: STSv1\r\nmode: testing\r\nmx: mta.mail.test\r\nmax_age: 604800\r\n", MtaStsPolicyDocument.Render(Full));
        var enforce = new DomainRecordOptions { ServerHostname = Server, MtaStsMode = MtaStsServingMode.Enforce, MtaStsMx = ["mx1.mail.test", "*.mx.mail.test"], MtaStsMaxAge = TimeSpan.FromHours(2) };
        Assert.Equal("version: STSv1\r\nmode: enforce\r\nmx: mx1.mail.test\r\nmx: *.mx.mail.test\r\nmax_age: 7200\r\n", MtaStsPolicyDocument.Render(enforce));
        Assert.Equal("https://mta-sts.example.com/.well-known/mta-sts.txt", MtaStsPolicyDocument.UrlFor("Example.COM."));
    }

    [Fact]
    public void The_zone_file_has_every_record_with_fully_qualified_names_and_long_values_split_in_strings()
    {
        var plan = PlanFor();
        string zone = ZoneFile.Render(Domain, plan);
        Assert.StartsWith("; DNS records for example.com\n", zone);
        Assert.Contains("; DKIM (required):", zone);
        Assert.Contains("; SPF (recommended):", zone);
        Assert.Contains("example.com. 3600 IN TXT \"v=spf1 ip4:192.0.2.10 ~all\"\n", zone);
        Assert.Contains("bounce.example.com. 3600 IN CNAME bounces.mail.test.\n", zone);
        Assert.Contains("; MX bounces.mail.test -> 10 mta.mail.test (published once by whoever runs EggMail, not in this zone)\n", zone);
        Assert.Contains("mta-sts.example.com. 3600 IN CNAME mta.mail.test.\n", zone);
        Assert.Contains("; PTR 10.2.0.192.in-addr.arpa -> mta.mail.test\n", zone);
        string dkim = zone.Split('\n').Single(l => l.StartsWith("egg202610._domainkey.example.com. 3600 IN TXT ", StringComparison.Ordinal));
        string[] strings = dkim["egg202610._domainkey.example.com. 3600 IN TXT ".Length..].Split("\" \"");
        Assert.True(strings.Length >= 2);
        Assert.All(strings, s => Assert.True(s.Trim('"').Length <= 255));
        Assert.Equal(Of(plan, DomainRecordPurpose.Dkim).Value, string.Concat(strings).Trim('"'));
    }

    [Fact]
    public void The_bounce_mx_is_a_zone_line_only_when_the_bounce_domain_is_inside_the_domain()
    {
        var inside = PlanFor(new DomainRecordOptions { BounceDomain = "bounces.example.com", ServerHostname = Server });
        string zone = ZoneFile.Render(Domain, inside);
        Assert.Contains("bounces.example.com. 3600 IN MX 10 mta.mail.test.\n", zone);
        Assert.DoesNotContain("; MX bounces.example.com", zone);

        var outside = ZoneFile.Render(Domain, PlanFor());   // bounces.mail.test belongs to the operator, not to example.com
        Assert.DoesNotContain("IN MX", outside);
        Assert.Contains("; MX bounces.mail.test -> 10 mta.mail.test (published once by whoever runs EggMail, not in this zone)\n", outside);

        // A lookalike suffix is not inside the zone.
        Assert.Contains("; MX notexample.com -> 10 mta.mail.test", ZoneFile.Render(Domain, PlanFor(new DomainRecordOptions { BounceDomain = "notexample.com", ServerHostname = Server })));
    }

    [Fact]
    public void Zone_file_text_escapes_quotes_and_backslashes()
    {
        Assert.Equal("\"a\\\"b\\\\c\"", ZoneFile.QuotedStrings("a\"b\\c"));
        Assert.Equal("\"\"", ZoneFile.QuotedStrings(""));
    }

    // DKIM

    [Fact]
    public async Task Dkim_ok_missing_other_key_and_not_a_key()
    {
        var plan = PlanFor();
        var record = Of(plan, DomainRecordPurpose.Dkim);
        var ok = await CheckAsync(new StaticDnsResolver().AddTxt(record.Host, record.Value), plan, DomainRecordPurpose.Dkim);
        Assert.Equal(DomainRecordStatus.Ok, ok.Status);
        Assert.Equal(record.Value, ok.Found);

        Assert.Equal(DomainRecordStatus.Missing, (await CheckAsync(new StaticDnsResolver(), plan, DomainRecordPurpose.Dkim)).Status);

        using var other = DkimKeyTools.GenerateRsa2048();
        string otherValue = DkimKeyTools.FormatDnsTxtValue(other);
        var mismatch = await CheckAsync(new StaticDnsResolver().AddTxt(record.Host, otherValue), plan, DomainRecordPurpose.Dkim);
        Assert.Equal(DomainRecordStatus.Mismatch, mismatch.Status);
        Assert.Equal(otherValue, mismatch.Found);

        var invalid = await CheckAsync(new StaticDnsResolver().AddTxt(record.Host, "this is not a key"), plan, DomainRecordPurpose.Dkim);
        Assert.Equal(DomainRecordStatus.Invalid, invalid.Status);
        Assert.Equal("this is not a key", invalid.Found);
    }

    // Return-path CNAME

    [Fact]
    public async Task Return_path_cname_ok_missing_and_mismatch()
    {
        var plan = PlanFor();
        var record = Of(plan, DomainRecordPurpose.ReturnPath);
        Assert.Equal(DomainRecordStatus.Ok, (await CheckAsync(new StaticDnsResolver().AddCname(record.Host, "Bounces.Mail.Test."), plan, DomainRecordPurpose.ReturnPath)).Status);
        Assert.Equal(DomainRecordStatus.Missing, (await CheckAsync(new StaticDnsResolver().AddTxt(record.Host, "unrelated"), plan, DomainRecordPurpose.ReturnPath)).Status);
        var wrong = await CheckAsync(new StaticDnsResolver().AddCname(record.Host, "someone-else.test"), plan, DomainRecordPurpose.ReturnPath);
        Assert.Equal(DomainRecordStatus.Mismatch, wrong.Status);
        Assert.Equal("someone-else.test", wrong.Found);
    }

    // SPF

    [Fact]
    public async Task Spf_ok_when_our_mechanism_is_in_the_one_record_even_among_other_senders()
    {
        var plan = PlanFor();
        var exact = await CheckAsync(new StaticDnsResolver().AddTxt(Domain, "v=spf1 ip4:192.0.2.10 ~all"), plan, DomainRecordPurpose.Spf);
        Assert.Equal(DomainRecordStatus.Ok, exact.Status);
        var merged = await CheckAsync(new StaticDnsResolver().AddTxt(Domain, "v=spf1 IP4:192.0.2.10 include:_spf.google.com -all").AddTxt(Domain, "google-site-verification=abc"), plan, DomainRecordPurpose.Spf);
        Assert.Equal(DomainRecordStatus.Ok, merged.Status);
    }

    [Fact]
    public async Task Spf_missing_mismatch_and_invalid_when_there_are_two_records()
    {
        var plan = PlanFor();
        var missing = await CheckAsync(new StaticDnsResolver().AddTxt(Domain, "google-site-verification=abc"), plan, DomainRecordPurpose.Spf);
        Assert.Equal(DomainRecordStatus.Missing, missing.Status);
        Assert.Null(missing.Found);

        var mismatch = await CheckAsync(new StaticDnsResolver().AddTxt(Domain, "v=spf1 include:_spf.google.com ~all"), plan, DomainRecordPurpose.Spf);
        Assert.Equal(DomainRecordStatus.Mismatch, mismatch.Status);
        Assert.Equal("v=spf1 include:_spf.google.com ~all", mismatch.Found);

        var two = await CheckAsync(new StaticDnsResolver().AddTxt(Domain, "v=spf1 ip4:192.0.2.10 ~all").AddTxt(Domain, "v=spf1 include:x.test ~all"), plan, DomainRecordPurpose.Spf);
        Assert.Equal(DomainRecordStatus.Invalid, two.Status);
        Assert.Contains(" | ", two.Found);
    }

    [Fact]
    public async Task A_record_that_only_starts_like_spf_is_not_spf()
    {
        var plan = PlanFor();
        Assert.Equal(DomainRecordStatus.Missing, (await CheckAsync(new StaticDnsResolver().AddTxt(Domain, "v=spf10 ip4:192.0.2.10"), plan, DomainRecordPurpose.Spf)).Status);
    }

    // DMARC

    [Fact]
    public async Task Dmarc_ok_with_any_valid_policy_missing_and_invalid()
    {
        var plan = PlanFor();
        Assert.Equal(DomainRecordStatus.Ok, (await CheckAsync(new StaticDnsResolver().AddTxt("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:dmarc@example.com"), plan, DomainRecordPurpose.Dmarc)).Status);
        Assert.Equal(DomainRecordStatus.Ok, (await CheckAsync(new StaticDnsResolver().AddTxt("_dmarc.example.com", "v=DMARC1;p=REJECT"), plan, DomainRecordPurpose.Dmarc)).Status);   // the customer's own stricter policy is fine
        Assert.Equal(DomainRecordStatus.Missing, (await CheckAsync(new StaticDnsResolver(), plan, DomainRecordPurpose.Dmarc)).Status);
        Assert.Equal(DomainRecordStatus.Invalid, (await CheckAsync(new StaticDnsResolver().AddTxt("_dmarc.example.com", "v=DMARC1; rua=mailto:x@example.com"), plan, DomainRecordPurpose.Dmarc)).Status);
        Assert.Equal(DomainRecordStatus.Invalid, (await CheckAsync(new StaticDnsResolver().AddTxt("_dmarc.example.com", "v=DMARC1; p=none").AddTxt("_dmarc.example.com", "v=DMARC1; p=reject"), plan, DomainRecordPurpose.Dmarc)).Status);
    }

    // TLS-RPT

    [Fact]
    public async Task Tls_rpt_ok_missing_and_invalid()
    {
        var plan = PlanFor();
        var record = Of(plan, DomainRecordPurpose.TlsRpt);
        var ok = await CheckAsync(new StaticDnsResolver().AddTxt(record.Host, record.Value), plan, DomainRecordPurpose.TlsRpt);
        Assert.Equal(DomainRecordStatus.Ok, ok.Status);
        Assert.Equal(record.Value, ok.Found);
        Assert.Equal(DomainRecordStatus.Ok, (await CheckAsync(new StaticDnsResolver().AddTxt(record.Host, "v=TLSRPTv1; rua=https://reports.test/x,mailto:a@b.test"), plan, DomainRecordPurpose.TlsRpt)).Status);
        Assert.Equal(DomainRecordStatus.Missing, (await CheckAsync(new StaticDnsResolver(), plan, DomainRecordPurpose.TlsRpt)).Status);
        Assert.Equal(DomainRecordStatus.Invalid, (await CheckAsync(new StaticDnsResolver().AddTxt(record.Host, "v=TLSRPTv1; rua=ftp://x.test"), plan, DomainRecordPurpose.TlsRpt)).Status);
        Assert.Equal(DomainRecordStatus.Invalid, (await CheckAsync(new StaticDnsResolver().AddTxt(record.Host, "v=TLSRPTv1"), plan, DomainRecordPurpose.TlsRpt)).Status);
    }

    // MTA-STS

    [Fact]
    public async Task Mta_sts_txt_ok_missing_stale_id_and_invalid()
    {
        var plan = PlanFor();
        var record = Of(plan, DomainRecordPurpose.MtaSts);
        Assert.Equal(DomainRecordStatus.Ok, (await CheckAsync(new StaticDnsResolver().AddTxt(record.Host, record.Value), plan, DomainRecordPurpose.MtaSts)).Status);
        Assert.Equal(DomainRecordStatus.Missing, (await CheckAsync(new StaticDnsResolver(), plan, DomainRecordPurpose.MtaSts)).Status);
        var stale = await CheckAsync(new StaticDnsResolver().AddTxt(record.Host, "v=STSv1; id=20200101T000000"), plan, DomainRecordPurpose.MtaSts);
        Assert.Equal(DomainRecordStatus.Mismatch, stale.Status);
        Assert.Equal("v=STSv1; id=20200101T000000", stale.Found);
        Assert.Equal(DomainRecordStatus.Invalid, (await CheckAsync(new StaticDnsResolver().AddTxt(record.Host, "v=STSv1"), plan, DomainRecordPurpose.MtaSts)).Status);
        Assert.Equal(DomainRecordStatus.Invalid, (await CheckAsync(new StaticDnsResolver().AddTxt(record.Host, "v=STSv1; id=bad id!"), plan, DomainRecordPurpose.MtaSts)).Status);
    }

    [Fact]
    public async Task Mta_sts_host_may_be_a_cname_to_the_server_or_addresses_of_the_server()
    {
        var plan = PlanFor();
        var record = Of(plan, DomainRecordPurpose.MtaStsHost);
        Assert.Equal(DomainRecordStatus.Ok, (await CheckAsync(new StaticDnsResolver().AddCname(record.Host, Server), plan, DomainRecordPurpose.MtaStsHost)).Status);

        // An alias of the server (another name with its address) is also fine; so are A records equal to the server's own.
        var alias = new StaticDnsResolver().AddCname(record.Host, "alias.mail.test").AddA("alias.mail.test", SendingIp).AddA(Server, SendingIp);
        Assert.Equal(DomainRecordStatus.Ok, (await CheckAsync(alias, plan, DomainRecordPurpose.MtaStsHost)).Status);
        var direct = new StaticDnsResolver().AddA(record.Host, SendingIp).AddA(Server, SendingIp);
        var okDirect = await CheckAsync(direct, plan, DomainRecordPurpose.MtaStsHost);
        Assert.Equal(DomainRecordStatus.Ok, okDirect.Status);
        Assert.Equal(SendingIp, okDirect.Found);

        Assert.Equal(DomainRecordStatus.Missing, (await CheckAsync(new StaticDnsResolver(), plan, DomainRecordPurpose.MtaStsHost)).Status);
        var elsewhere = await CheckAsync(new StaticDnsResolver().AddCname(record.Host, "elsewhere.test").AddA("elsewhere.test", "198.51.100.7").AddA(Server, SendingIp), plan, DomainRecordPurpose.MtaStsHost);
        Assert.Equal(DomainRecordStatus.Mismatch, elsewhere.Status);
        Assert.Equal("elsewhere.test", elsewhere.Found);
        var wrongAddress = await CheckAsync(new StaticDnsResolver().AddA(record.Host, "198.51.100.7").AddA(Server, SendingIp), plan, DomainRecordPurpose.MtaStsHost);
        Assert.Equal(DomainRecordStatus.Mismatch, wrongAddress.Status);
        Assert.Equal("198.51.100.7", wrongAddress.Found);
    }

    // Bounce MX

    [Fact]
    public async Task Bounce_mx_ok_missing_and_mismatch()
    {
        var plan = PlanFor();
        var record = Of(plan, DomainRecordPurpose.BounceMx);
        var ok = await CheckAsync(new StaticDnsResolver().AddMx(record.Host, 10, Server), plan, DomainRecordPurpose.BounceMx);
        Assert.Equal(DomainRecordStatus.Ok, ok.Status);
        Assert.Equal("10 mta.mail.test", ok.Found);
        Assert.Equal(DomainRecordStatus.Ok, (await CheckAsync(new StaticDnsResolver().AddMx(record.Host, 5, "backup.mail.test").AddMx(record.Host, 20, Server), plan, DomainRecordPurpose.BounceMx)).Status);   // any preference
        Assert.Equal(DomainRecordStatus.Missing, (await CheckAsync(new StaticDnsResolver().AddTxt(record.Host, "x"), plan, DomainRecordPurpose.BounceMx)).Status);
        var wrong = await CheckAsync(new StaticDnsResolver().AddMx(record.Host, 10, "mx.elsewhere.test"), plan, DomainRecordPurpose.BounceMx);
        Assert.Equal(DomainRecordStatus.Mismatch, wrong.Status);
        Assert.Equal("10 mx.elsewhere.test", wrong.Found);
    }

    // Reverse DNS

    [Fact]
    public async Task Reverse_dns_of_the_configured_sending_ip_ok_missing_and_mismatch()
    {
        var plan = PlanFor();
        var ip = IPAddress.Parse(SendingIp);
        var ok = await CheckAsync(new StaticDnsResolver().AddPtr(ip, Server), plan, DomainRecordPurpose.Ptr);
        Assert.Equal(DomainRecordStatus.Ok, ok.Status);
        Assert.Equal(Server, ok.Found);
        Assert.Equal(DomainRecordStatus.Missing, (await CheckAsync(new StaticDnsResolver(), plan, DomainRecordPurpose.Ptr)).Status);
        var wrong = await CheckAsync(new StaticDnsResolver().AddPtr(ip, "static-192-0-2-10.isp.test"), plan, DomainRecordPurpose.Ptr);
        Assert.Equal(DomainRecordStatus.Mismatch, wrong.Status);
        Assert.Equal("static-192-0-2-10.isp.test", wrong.Found);
    }

    [Fact]
    public async Task Reverse_dns_without_a_configured_ip_reverses_the_addresses_of_the_host_name()
    {
        var plan = PlanFor(new DomainRecordOptions { ServerHostname = Server });
        var record = Of(plan, DomainRecordPurpose.Ptr);
        Assert.Equal(Server, record.Host);   // no IP known: the host name is looked up and each of its addresses reversed

        var ok = await CheckAsync(new StaticDnsResolver().AddA(Server, SendingIp).AddPtr(IPAddress.Parse(SendingIp), Server), plan, DomainRecordPurpose.Ptr);
        Assert.Equal(DomainRecordStatus.Ok, ok.Status);
        Assert.Equal($"{SendingIp} -> {Server}", ok.Found);
        Assert.Equal(DomainRecordStatus.Missing, (await CheckAsync(new StaticDnsResolver(), plan, DomainRecordPurpose.Ptr)).Status);   // the host name has no address yet
        var wrong = await CheckAsync(new StaticDnsResolver().AddA(Server, SendingIp).AddPtr(IPAddress.Parse(SendingIp), "other.test"), plan, DomainRecordPurpose.Ptr);
        Assert.Equal(DomainRecordStatus.Mismatch, wrong.Status);
    }

    // The whole set

    [Fact]
    public async Task Everything_published_is_all_ok_and_only_the_required_records_decide_the_result()
    {
        var plan = PlanFor();
        var dns = new StaticDnsResolver();
        foreach (var r in plan)
        {
            Publish(dns, r);
        }

        dns.AddA(Server, SendingIp);
        var result = await new DomainChecker(dns).CheckAsync(plan, default);
        Assert.Equal(VerificationCheckResult.AllRecordsOk, result.Result);
        Assert.All(result.Records, c => Assert.Equal(DomainRecordStatus.Ok, c.Status));

        // Break every recommended record: the domain is still fine; break a required one: it is not.
        var onlyRequired = new StaticDnsResolver();
        foreach (var r in plan.Where(r => r.Required))
        {
            Publish(onlyRequired, r);
        }

        var partial = await new DomainChecker(onlyRequired).CheckAsync(plan, default);
        Assert.Equal(VerificationCheckResult.AllRecordsOk, partial.Result);
        Assert.Equal(7, partial.Records.Count(c => c.Status == DomainRecordStatus.Missing));
    }

    [Fact]
    public async Task A_dns_failure_on_a_recommended_record_is_pending_and_never_fails_the_domain()
    {
        var plan = PlanFor();
        var dns = new StaticDnsResolver();
        foreach (var r in plan.Where(r => r.Required))
        {
            Publish(dns, r);
        }

        dns.Fail("_smtp._tls.example.com", DnsRecordType.TXT).Fail("bounces.mail.test", DnsRecordType.MX).Fail("10.2.0.192.in-addr.arpa", DnsRecordType.PTR);
        var result = await new DomainChecker(dns).CheckAsync(plan, default);
        Assert.Equal(VerificationCheckResult.AllRecordsOk, result.Result);
        Assert.Equal(DomainRecordStatus.Pending, result.Records.Single(c => c.Expected.Purpose == DomainRecordPurpose.TlsRpt).Status);
        Assert.Equal(DomainRecordStatus.Pending, result.Records.Single(c => c.Expected.Purpose == DomainRecordPurpose.BounceMx).Status);
        Assert.Equal(DomainRecordStatus.Pending, result.Records.Single(c => c.Expected.Purpose == DomainRecordPurpose.Ptr).Status);
    }
}
