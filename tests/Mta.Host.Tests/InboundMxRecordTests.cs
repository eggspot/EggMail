using Mta.Dkim;
using Mta.Dns;
using Mta.Host.Domains;

namespace Mta.Host.Tests;

/// <summary>The MX record that makes senders deliver a domain's mail to this server (design section 11.3): planned only while inbound is enabled for the domain, advice only, checked like the bounce MX.</summary>
public class InboundMxRecordTests
{
    private const string Domain = "example.com";
    private const string Server = "mta.mail.test";

    private static readonly DomainRecordOptions Options = new() { BounceDomain = "bounces.mail.test", ServerHostname = Server, PublicSendingIp = "192.0.2.10", MtaStsMode = MtaStsServingMode.Testing };

    private static IReadOnlyList<ExpectedDomainRecord> Plan(bool inbound, DomainRecordOptions? options = null)
    {
        using var rsa = DkimKeyTools.GenerateRsa2048();
        return DomainRecordPlanner.Plan(Domain, [new DomainDkimKey("egg1", DkimKeyTools.ExportPublicKeyBase64(rsa))], options ?? Options, inbound);
    }

    [Fact]
    public void The_mx_is_planned_only_while_inbound_is_enabled_and_is_never_required()
    {
        Assert.DoesNotContain(Plan(false), r => r.Purpose == DomainRecordPurpose.InboundMx);

        ExpectedDomainRecord mx = Assert.Single(Plan(true), r => r.Purpose == DomainRecordPurpose.InboundMx);
        Assert.Equal(("MX", Domain, "10 " + Server), (mx.Type, mx.Host, mx.Value));
        Assert.False(mx.Required);   // advice: the domain may keep another mail host, and verification never waits for it
        Assert.Contains("A or AAAA", mx.Note, StringComparison.Ordinal);
        Assert.Contains("port 25", mx.Note, StringComparison.Ordinal);
        Assert.Contains("MTA-STS", mx.Note, StringComparison.Ordinal);
        Assert.Equal("inbound_mx", DomainRecordPurposes.ApiWord(DomainRecordPurpose.InboundMx));
    }

    [Fact]
    public void Without_a_fully_qualified_host_name_there_is_no_mx_to_suggest()
    {
        Assert.DoesNotContain(Plan(true, new DomainRecordOptions { BounceDomain = "bounces.mail.test" }), r => r.Purpose == DomainRecordPurpose.InboundMx);
    }

    [Fact]
    public async Task The_mx_is_ok_when_it_names_this_server_missing_without_mx_and_a_mismatch_for_another_host()
    {
        ExpectedDomainRecord record = Plan(true).Single(r => r.Purpose == DomainRecordPurpose.InboundMx);
        async Task<DomainRecordCheck> Check(StaticDnsResolver dns) => Assert.Single((await new DomainChecker(dns).CheckAsync([record], default)).Records);

        Assert.Equal(DomainRecordStatus.Ok, (await Check(new StaticDnsResolver().AddMx(Domain, 10, Server))).Status);
        Assert.Equal(DomainRecordStatus.Ok, (await Check(new StaticDnsResolver().AddMx(Domain, 5, "backup.mail.test").AddMx(Domain, 20, Server))).Status);
        Assert.Equal(DomainRecordStatus.Missing, (await Check(new StaticDnsResolver().AddTxt(Domain, "x"))).Status);
        DomainRecordCheck wrong = await Check(new StaticDnsResolver().AddMx(Domain, 10, "mx.elsewhere.test"));
        Assert.Equal(DomainRecordStatus.Mismatch, wrong.Status);
        Assert.Equal("10 mx.elsewhere.test", wrong.Found);
    }

    [Fact]
    public void The_mx_is_a_line_of_the_zone_file_and_belongs_in_the_domains_zone()
    {
        IReadOnlyList<ExpectedDomainRecord> plan = Plan(true);
        ExpectedDomainRecord mx = plan.Single(r => r.Purpose == DomainRecordPurpose.InboundMx);

        Assert.True(ZoneFile.BelongsInZone(mx, Domain));
        Assert.Contains("example.com. 3600 IN MX 10 mta.mail.test.", ZoneFile.Render(Domain, plan), StringComparison.Ordinal);
        Assert.Contains("; Inbound MX (recommended)", ZoneFile.Render(Domain, plan), StringComparison.Ordinal);
    }
}
