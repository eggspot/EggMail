using Mta.Dkim;
using Mta.Dns;
using Mta.Host.Domains;
using Mta.Policy;

namespace Mta.Host.Tests;

public class DomainVerificationTests
{
    private static readonly DomainRecordOptions Options = new() { BounceDomain = "bounces.mail.test" };

    private static (IReadOnlyList<ExpectedDomainRecord> Plan, DomainDkimKey Key) PlanFor(string domain)
    {
        using var rsa = DkimKeyTools.GenerateRsa2048();
        var key = new DomainDkimKey("egg202610", DkimKeyTools.ExportPublicKeyBase64(rsa));
        return (DomainRecordPlanner.Plan(domain, [key], Options), key);
    }

    private static StaticDnsResolver Publish(IReadOnlyList<ExpectedDomainRecord> plan, params DomainRecordPurpose[] purposes)
    {
        var dns = new StaticDnsResolver();
        foreach (var r in plan.Where(r => purposes.Contains(r.Purpose)))
        {
            if (r.Type == "CNAME") { dns.AddCname(r.Host, r.Value); } else { dns.AddTxt(r.Host, r.Value); }
        }

        return dns;
    }

    [Fact]
    public void Plan_lists_dkim_return_path_and_advisory_records()
    {
        var (plan, _) = PlanFor("Example.COM.");
        Assert.Equal(5, plan.Count);   // no host name configured: no bounce MX, MTA-STS or reverse-DNS advice
        Assert.Equal("egg202610._domainkey.example.com", plan[0].Host);
        Assert.StartsWith("v=DKIM1; k=rsa; p=", plan[0].Value);
        Assert.Equal(("CNAME", "bounce.example.com", "bounces.mail.test"), (plan[1].Type, plan[1].Host, plan[1].Value));
        Assert.All(plan.Where(p => p.Purpose is DomainRecordPurpose.Spf or DomainRecordPurpose.Dmarc), p => Assert.False(p.Required));
        Assert.Equal("_dmarc.example.com", plan[3].Host);
        Assert.Equal(("_smtp._tls.example.com", DomainRecordPurpose.TlsRpt), (plan[4].Host, plan[4].Purpose));
    }

    [Fact]
    public void Plan_without_bounce_domain_has_no_return_path_record()
    {
        using var rsa = DkimKeyTools.GenerateRsa2048();
        var plan = DomainRecordPlanner.Plan("example.com", [new DomainDkimKey("s1", DkimKeyTools.ExportPublicKeyBase64(rsa))], new DomainRecordOptions());
        Assert.DoesNotContain(plan, p => p.Purpose == DomainRecordPurpose.ReturnPath);
    }

    [Fact]
    public async Task All_required_records_published_verifies_even_without_advisory_ones()
    {
        var (plan, _) = PlanFor("example.com");
        var result = await new DomainChecker(Publish(plan, DomainRecordPurpose.Dkim, DomainRecordPurpose.ReturnPath)).CheckAsync(plan, default);
        Assert.Equal(VerificationCheckResult.AllRecordsOk, result.Result);
        Assert.Equal(DomainRecordStatus.Ok, result.Records[0].Status);
        Assert.Equal(DomainRecordStatus.Missing, result.Records[2].Status);
    }

    [Fact]
    public async Task Missing_dkim_record_is_reported()
    {
        var (plan, _) = PlanFor("example.com");
        var result = await new DomainChecker(Publish(plan, DomainRecordPurpose.ReturnPath)).CheckAsync(plan, default);
        Assert.Equal(VerificationCheckResult.RecordsNotOk, result.Result);
        Assert.Equal(DomainRecordStatus.Missing, result.Records[0].Status);
        Assert.Contains("Dkim", result.Error);
    }

    [Fact]
    public async Task Another_dkim_key_and_a_wrong_cname_target_are_a_mismatch()
    {
        var (plan, _) = PlanFor("example.com");
        using var other = DkimKeyTools.GenerateRsa2048();
        var dns = new StaticDnsResolver()
            .AddTxt(plan[0].Host, DkimKeyTools.FormatDnsTxtValue(other))
            .AddCname(plan[1].Host, "someone-else.test");
        var result = await new DomainChecker(dns).CheckAsync(plan, default);
        Assert.Equal(VerificationCheckResult.RecordsNotOk, result.Result);
        Assert.Equal(DomainRecordStatus.Mismatch, result.Records[0].Status);
        Assert.Equal(DomainRecordStatus.Mismatch, result.Records[1].Status);
        Assert.Equal("someone-else.test", result.Records[1].Found);
    }

    [Fact]
    public async Task Long_dkim_value_split_in_multiple_txt_strings_is_accepted()
    {
        var (plan, _) = PlanFor("example.com");
        // The resolver concatenates the character-strings, so a published 2048-bit key arrives as one text.
        Assert.True(plan[0].Value.Length > 255);
        var result = await new DomainChecker(Publish(plan, DomainRecordPurpose.Dkim, DomainRecordPurpose.ReturnPath)).CheckAsync(plan, default);
        Assert.Equal(VerificationCheckResult.AllRecordsOk, result.Result);
    }

    [Fact]
    public async Task Dns_failure_is_a_temporary_failure_not_a_missing_record()
    {
        var (plan, _) = PlanFor("example.com");
        var dns = Publish(plan, DomainRecordPurpose.ReturnPath).Fail(plan[0].Host, DnsRecordType.TXT);
        var result = await new DomainChecker(dns).CheckAsync(plan, default);
        Assert.Equal(VerificationCheckResult.DnsTemporaryFailure, result.Result);
        Assert.Equal(DomainRecordStatus.Pending, result.Records[0].Status);
    }

    [Fact]
    public async Task Definite_problem_outranks_a_dns_failure_on_another_record()
    {
        var (plan, _) = PlanFor("example.com");
        var dns = new StaticDnsResolver().Fail(plan[0].Host, DnsRecordType.TXT);
        var result = await new DomainChecker(dns).CheckAsync(plan, default);
        Assert.Equal(VerificationCheckResult.RecordsNotOk, result.Result);
    }
}
