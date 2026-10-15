using Microsoft.Extensions.Configuration;
using Mta.Dkim;
using Mta.Dns;
using Mta.Host.Configuration;
using Mta.Host.Domains;
using Mta.Policy;

namespace Mta.Host.Tests;

/// <summary>
/// What an independent review of the onboarding asked for: records that must not be imported twice, nothing suggested that does harm, SPF by evaluation, DMARC
/// inheritance, CNAME chains, bounded lookups, MTA-STS only where this server receives the mail, and validation of what is written into a DNS record.
/// </summary>
public class DomainRecordReviewTests
{
    private const string Domain = "example.com";
    private const string Server = "mta.mail.test";

    private static readonly DomainRecordOptions Full = new()
    {
        BounceDomain = "bounces.mail.test",
        ServerHostname = Server,
        PublicSendingIp = "192.0.2.10",
        MtaStsMode = MtaStsServingMode.Testing,
    };

    private static IReadOnlyList<ExpectedDomainRecord> PlanFor(DomainRecordOptions options, string domain = Domain)
    {
        using var rsa = DkimKeyTools.GenerateRsa2048();
        return DomainRecordPlanner.Plan(domain, [new DomainDkimKey("egg202610", DkimKeyTools.ExportPublicKeyBase64(rsa))], options);
    }

    private static ExpectedDomainRecord Of(IReadOnlyList<ExpectedDomainRecord> plan, DomainRecordPurpose purpose) => plan.Single(r => r.Purpose == purpose);

    private static async Task<DomainRecordCheck> CheckAsync(IDnsResolver dns, IReadOnlyList<ExpectedDomainRecord> plan, DomainRecordPurpose purpose, TimeSpan? timeout = null) =>
        Assert.Single((await new DomainChecker(dns, timeout).CheckAsync([Of(plan, purpose)], default)).Records);

    // Zone file: nothing that would be imported twice or do harm

    [Fact]
    public void The_zone_file_shows_spf_and_dmarc_as_comments_so_an_import_cannot_create_a_second_record()
    {
        string zone = ZoneFile.Render(Domain, PlanFor(Full));
        string[] lines = zone.Split('\n');
        Assert.DoesNotContain(lines, l => l.StartsWith("example.com. ", StringComparison.Ordinal) && l.Contains("v=spf1", StringComparison.Ordinal));
        Assert.DoesNotContain(lines, l => l.StartsWith("_dmarc.example.com. ", StringComparison.Ordinal));
        Assert.Contains("; example.com. 3600 IN TXT \"v=spf1 ip4:192.0.2.10 ~all\"", lines);
        Assert.Contains("; _dmarc.example.com. 3600 IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc@example.com\"", lines);
        Assert.Contains("two SPF records break SPF", zone);
        // The records that are safe to import are still lines.
        Assert.Contains(lines, l => l.StartsWith("bounce.example.com. 3600 IN CNAME ", StringComparison.Ordinal));
        Assert.Contains(lines, l => l.StartsWith("_smtp._tls.example.com. 3600 IN TXT ", StringComparison.Ordinal));
    }

    [Fact]
    public void Nothing_to_authorize_means_no_spf_record_and_a_comment_that_says_why()
    {
        var plan = PlanFor(new DomainRecordOptions { BounceDomain = "bounces.mail.test" });
        Assert.DoesNotContain(plan, r => r.Purpose == DomainRecordPurpose.Spf);
        string zone = ZoneFile.Render(Domain, plan);
        Assert.Contains("; SPF: nothing to authorize, so no record is suggested.", zone);
        Assert.DoesNotContain("v=spf1 ~all", zone);
    }

    [Fact]
    public void A_dmarc_report_address_given_with_mailto_is_not_prefixed_twice()
    {
        Assert.Equal("v=DMARC1; p=none; rua=mailto:r@ops.test", DomainRecordPlanner.DmarcValue("example.com", new DomainRecordOptions { DmarcReportAddress = "mailto:r@ops.test" }));
    }

    // MTA-STS and TLS-RPT only where this server receives the mail

    [Fact]
    public void Tls_rpt_and_mta_sts_are_suggested_only_with_a_serving_mode_and_the_notes_say_to_publish_them_only_if_this_server_receives_the_mail()
    {
        var off = PlanFor(new DomainRecordOptions { BounceDomain = "bounces.mail.test", ServerHostname = Server });
        Assert.DoesNotContain(off, r => r.Purpose is DomainRecordPurpose.TlsRpt or DomainRecordPurpose.MtaSts or DomainRecordPurpose.MtaStsHost);

        foreach (var mode in new[] { MtaStsServingMode.None, MtaStsServingMode.Testing, MtaStsServingMode.Enforce })
        {
            var plan = PlanFor(new DomainRecordOptions { ServerHostname = Server, MtaStsMode = mode });
            Assert.Contains(plan, r => r.Purpose == DomainRecordPurpose.TlsRpt);
            foreach (var purpose in new[] { DomainRecordPurpose.TlsRpt, DomainRecordPurpose.MtaSts })
            {
                Assert.Contains("only if this server receives the domain's mail", Of(plan, purpose).Note);
            }
        }
    }

    [Fact]
    public void Mode_none_serves_a_policy_that_retires_enforcement()
    {
        var none = new DomainRecordOptions { ServerHostname = Server, MtaStsMode = MtaStsServingMode.None };
        Assert.True(none.MtaStsEnabled);
        Assert.Equal("version: STSv1\r\nmode: none\r\nmx: mta.mail.test\r\nmax_age: 604800\r\n", MtaStsPolicyDocument.Render(none));
        Assert.NotEqual(MtaStsPolicyDocument.PolicyId(none), MtaStsPolicyDocument.PolicyId(new DomainRecordOptions { ServerHostname = Server, MtaStsMode = MtaStsServingMode.Enforce }));
    }

    // Host names

    [Theory]
    [InlineData("mx.example.net", "mx.example.net")]
    [InlineData("MX.Example.NET", "mx.example.net")]
    [InlineData("*.example.net", "*.example.net")]
    [InlineData("*.mx.example.net", "*.mx.example.net")]
    public void Mta_sts_mx_entries_are_normalised(string entry, string expected) => Assert.Equal(expected, DomainRecordOptions.NormalizeMtaStsMx(entry));

    [Theory]
    [InlineData("mx.example.net.")]
    [InlineData("*.*.example.net")]
    [InlineData("*.")]
    [InlineData("*example.net")]
    [InlineData("mx")]
    [InlineData("192.0.2.1")]
    [InlineData("mx..example.net")]
    [InlineData("-mx.example.net")]
    [InlineData("mx_1.example.net")]
    [InlineData("a b.example.net")]
    [InlineData("")]
    public void Mta_sts_mx_entries_that_are_not_fully_qualified_host_names_are_refused(string entry) => Assert.Null(DomainRecordOptions.NormalizeMtaStsMx(entry));

    [Theory]
    [InlineData("a..b.example.com")]
    [InlineData("-x.example.com")]
    [InlineData("*.example.com")]
    [InlineData("x_y.example.com")]
    [InlineData("localhost")]
    public void The_server_host_name_must_be_a_valid_fully_qualified_name(string name) => Assert.Null(DomainRecordOptions.UsableHostname(name));

    // Configuration

    private static string[] Errors(params (string Key, string Value)[] values) =>
        ConfigLoader.Load(new ConfigurationBuilder().AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value))).Build()).Errors.ToArray();

    [Theory]
    [InlineData("mx.example.net.")]
    [InlineData("*.*.example.net")]
    [InlineData("mx")]
    public void A_bad_mta_sts_mx_entry_stops_the_start(string entry) =>
        Assert.Contains(Errors(("Domains:MtaStsMx:0", entry)), e => e.Contains("Domains:MtaStsMx", StringComparison.Ordinal));

    [Theory]
    [InlineData("Domains:DmarcReportAddress", "a@b.test; ruf=mailto:x@y.test")]
    [InlineData("Domains:DmarcReportAddress", "a@b.test c@d.test")]
    [InlineData("Domains:DmarcReportAddress", "a@b.test,c@d.test")]
    [InlineData("Domains:DmarcReportAddress", "no-at-sign")]
    [InlineData("Domains:DmarcReportAddress", "https://reports.test/x")]
    [InlineData("Domains:TlsReportAddress", "a@b.test\r\nv=STSv1")]
    [InlineData("Domains:TlsReportAddress", "a@b.test; x=y")]
    [InlineData("Domains:TlsReportAddress", "https://")]
    public void A_report_address_that_could_alter_the_dns_record_stops_the_start(string key, string value) =>
        Assert.Contains(Errors((key, value)), e => e.Contains(key, StringComparison.Ordinal));

    [Theory]
    [InlineData("Domains:DmarcReportAddress", "dmarc-{domain}@ops.test")]
    [InlineData("Domains:DmarcReportAddress", "mailto:reports@ops.test")]
    [InlineData("Domains:TlsReportAddress", "tls@ops.test")]
    [InlineData("Domains:TlsReportAddress", "https://tls.ops.test/{domain}")]
    public void Report_addresses_in_the_forms_the_documentation_names_are_accepted(string key, string value) => Assert.Empty(Errors((key, value)));

    [Fact]
    public void Mode_none_needs_a_fully_qualified_host_name_like_the_other_serving_modes()
    {
        Assert.Contains(Errors(("Domains:MtaStsMode", "None"), ("Hostname", "localhost")), e => e.Contains("Domains:MtaStsMode", StringComparison.Ordinal));
        Assert.Empty(Errors(("Domains:MtaStsMode", "None"), ("Hostname", "mta.example.net")));
    }

    [Fact]
    public void The_bounce_domain_and_the_spf_include_of_the_api_options_are_copies_of_the_domain_record_options()
    {
        var loaded = ConfigLoader.Load(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Delivery:BounceDomain"] = "bounces.example.net", ["Api:SpfInclude"] = "spf.example.net",
        }).Build());
        var options = Mta.Host.Api.EggMailApiExtensions.ApiOptionsFrom(loaded.Config, loaded.LockedKeys);
        Assert.Equal(options.DomainRecords!.BounceDomain, options.BounceDomain);
        Assert.Equal(options.DomainRecords.SpfInclude, options.SpfInclude);
        Assert.Equal("spf.example.net", options.DomainRecords.SpfInclude);
    }

    // SPF by evaluation

    [Fact]
    public async Task Spf_is_judged_by_what_the_record_authorizes_not_by_its_text()
    {
        var plan = PlanFor(Full);   // asks for ip4:192.0.2.10
        Assert.Equal(DomainRecordStatus.Ok, (await CheckAsync(new StaticDnsResolver().AddTxt(Domain, "v=spf1 ip4:192.0.2.0/24 -all"), plan, DomainRecordPurpose.Spf)).Status);   // a CIDR range covers it
        Assert.Equal(DomainRecordStatus.Ok, (await CheckAsync(new StaticDnsResolver().AddTxt(Domain, "v=spf1 include:_spf.ops.test -all").AddTxt("_spf.ops.test", "v=spf1 ip4:192.0.2.10 -all"), plan, DomainRecordPurpose.Spf)).Status);   // through an include
        Assert.Equal(DomainRecordStatus.Ok, (await CheckAsync(new StaticDnsResolver().AddTxt(Domain, "v=spf1 a:mta.mail.test -all").AddA(Server, "192.0.2.10"), plan, DomainRecordPurpose.Spf)).Status);   // through an a: mechanism
        var elsewhere = await CheckAsync(new StaticDnsResolver().AddTxt(Domain, "v=spf1 ip4:198.51.100.0/24 -all"), plan, DomainRecordPurpose.Spf);   // another range: the sending IP would fail
        Assert.Equal(DomainRecordStatus.Mismatch, elsewhere.Status);
        Assert.Equal("v=spf1 ip4:198.51.100.0/24 -all", elsewhere.Found);
        Assert.Equal(DomainRecordStatus.Mismatch, (await CheckAsync(new StaticDnsResolver().AddTxt(Domain, "v=spf1 -all"), plan, DomainRecordPurpose.Spf)).Status);
    }

    [Fact]
    public async Task An_spf_include_only_expectation_is_checked_by_the_include_in_the_record()
    {
        var plan = PlanFor(new DomainRecordOptions { SpfInclude = "spf.egg.test" });
        Assert.Equal(DomainRecordStatus.Ok, (await CheckAsync(new StaticDnsResolver().AddTxt(Domain, "v=spf1 include:spf.egg.test include:other.test ~all"), plan, DomainRecordPurpose.Spf)).Status);
        Assert.Equal(DomainRecordStatus.Mismatch, (await CheckAsync(new StaticDnsResolver().AddTxt(Domain, "v=spf1 include:other.test ~all"), plan, DomainRecordPurpose.Spf)).Status);
    }

    // DMARC inheritance

    [Fact]
    public async Task A_subdomain_inherits_the_dmarc_record_of_its_organizational_domain()
    {
        var plan = PlanFor(Full, "mail.example.com");
        var inherited = await CheckAsync(new StaticDnsResolver().AddTxt("_dmarc.example.com", "v=DMARC1; p=reject"), plan, DomainRecordPurpose.Dmarc);
        Assert.Equal(DomainRecordStatus.Ok, inherited.Status);
        Assert.Equal("inherited from _dmarc.example.com: v=DMARC1; p=reject", inherited.Found);

        Assert.Equal(DomainRecordStatus.Missing, (await CheckAsync(new StaticDnsResolver(), plan, DomainRecordPurpose.Dmarc)).Status);
        // Its own record wins, also when it is broken.
        var own = await CheckAsync(new StaticDnsResolver().AddTxt("_dmarc.mail.example.com", "v=DMARC1").AddTxt("_dmarc.example.com", "v=DMARC1; p=reject"), plan, DomainRecordPurpose.Dmarc);
        Assert.Equal(DomainRecordStatus.Invalid, own.Status);
    }

    [Fact]
    public async Task Dmarc_inheritance_follows_the_public_suffix_list_and_stops_at_the_organizational_domain()
    {
        var plan = PlanFor(Full, "a.b.example.co.uk");
        var dns = new StaticDnsResolver().AddTxt("_dmarc.example.co.uk", "v=DMARC1; p=none").AddTxt("_dmarc.co.uk", "v=DMARC1; p=reject");
        var found = await CheckAsync(dns, plan, DomainRecordPurpose.Dmarc);
        Assert.Equal("inherited from _dmarc.example.co.uk: v=DMARC1; p=none", found.Found);
        // A domain that is itself an organizational domain has nobody to inherit from.
        Assert.Equal(DomainRecordStatus.Missing, (await CheckAsync(new StaticDnsResolver().AddTxt("_dmarc.co.uk", "v=DMARC1; p=reject"), PlanFor(Full, "example.co.uk"), DomainRecordPurpose.Dmarc)).Status);
    }

    // CNAME chains

    [Fact]
    public async Task The_return_path_may_lead_through_other_names_to_the_bounce_domain()
    {
        var plan = PlanFor(Full);
        var host = Of(plan, DomainRecordPurpose.ReturnPath).Host;
        var chained = await CheckAsync(new StaticDnsResolver().AddCname(host, "hop.dns-provider.test").AddCname("hop.dns-provider.test", "bounces.mail.test"), plan, DomainRecordPurpose.ReturnPath);
        Assert.Equal(DomainRecordStatus.Ok, chained.Status);
        Assert.Equal("hop.dns-provider.test -> bounces.mail.test", chained.Found);

        var wrong = await CheckAsync(new StaticDnsResolver().AddCname(host, "hop.dns-provider.test").AddCname("hop.dns-provider.test", "elsewhere.test"), plan, DomainRecordPurpose.ReturnPath);
        Assert.Equal(DomainRecordStatus.Mismatch, wrong.Status);
        Assert.Equal("hop.dns-provider.test -> elsewhere.test", wrong.Found);
    }

    [Fact]
    public async Task A_cname_loop_does_not_hang_the_check()
    {
        var plan = PlanFor(Full);
        var host = Of(plan, DomainRecordPurpose.ReturnPath).Host;
        var loop = await CheckAsync(new StaticDnsResolver().AddCname(host, "a.test").AddCname("a.test", "b.test").AddCname("b.test", "a.test"), plan, DomainRecordPurpose.ReturnPath, TimeSpan.FromSeconds(30));
        Assert.Equal(DomainRecordStatus.Mismatch, loop.Status);
    }

    [Fact]
    public async Task The_mta_sts_host_may_lead_through_other_names_to_the_server()
    {
        var plan = PlanFor(Full);
        var host = Of(plan, DomainRecordPurpose.MtaStsHost).Host;
        var chained = await CheckAsync(new StaticDnsResolver().AddCname(host, "hop.dns-provider.test").AddCname("hop.dns-provider.test", Server), plan, DomainRecordPurpose.MtaStsHost);
        Assert.Equal(DomainRecordStatus.Ok, chained.Status);
        Assert.Equal("hop.dns-provider.test -> mta.mail.test", chained.Found);
    }

    // Bounded lookups

    private sealed class StallingDns(IDnsResolver inner, string stalledName) : IDnsResolver
    {
        public int InFlight;
        public int MostInFlight;

        public async ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
        {
            int now = Interlocked.Increment(ref InFlight);
            int seen;
            while (now > (seen = Volatile.Read(ref MostInFlight)) && Interlocked.CompareExchange(ref MostInFlight, now, seen) != seen)
            {
            }

            try
            {
                if (name == stalledName)
                {
                    await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);   // never answers
                }

                await Task.Yield();
                return await inner.QueryAsync(name, type, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                Interlocked.Decrement(ref InFlight);
            }
        }
    }

    [Fact]
    public async Task A_record_whose_lookup_never_answers_is_pending_and_the_others_are_still_checked()
    {
        var plan = PlanFor(Full);
        var dkim = Of(plan, DomainRecordPurpose.Dkim);
        var inner = new StaticDnsResolver().AddTxt(dkim.Host, dkim.Value).AddCname(Of(plan, DomainRecordPurpose.ReturnPath).Host, "bounces.mail.test");
        var dns = new StallingDns(inner, Of(plan, DomainRecordPurpose.Dmarc).Host);

        var result = await new DomainChecker(dns, TimeSpan.FromMilliseconds(200)).CheckAsync(plan, default);

        Assert.Equal(DomainRecordStatus.Pending, result.Records.Single(c => c.Expected.Purpose == DomainRecordPurpose.Dmarc).Status);
        Assert.Equal(DomainRecordStatus.Ok, result.Records.Single(c => c.Expected.Purpose == DomainRecordPurpose.Dkim).Status);
        Assert.Equal(DomainRecordStatus.Ok, result.Records.Single(c => c.Expected.Purpose == DomainRecordPurpose.ReturnPath).Status);
        Assert.Equal(VerificationCheckResult.AllRecordsOk, result.Result);   // a stalled recommended record does not hold the domain back
        Assert.Equal(plan.Select(r => r.Purpose), result.Records.Select(c => c.Expected.Purpose));   // the order of the plan is kept
    }

    [Fact]
    public async Task A_stalled_required_record_is_a_temporary_dns_failure_not_a_missing_record()
    {
        var plan = PlanFor(Full);
        var dns = new StallingDns(new StaticDnsResolver(), Of(plan, DomainRecordPurpose.Dkim).Host);
        var result = await new DomainChecker(dns, TimeSpan.FromMilliseconds(200)).CheckAsync(plan, default);
        Assert.Equal(DomainRecordStatus.Pending, result.Records[0].Status);
        Assert.Equal(VerificationCheckResult.RecordsNotOk, result.Result);   // the return path is missing: a definite problem outranks the failure
        var onlyDkim = await new DomainChecker(dns, TimeSpan.FromMilliseconds(200)).CheckAsync([plan[0]], default);
        Assert.Equal(VerificationCheckResult.DnsTemporaryFailure, onlyDkim.Result);
    }

    [Fact]
    public async Task Lookups_run_in_parallel_but_never_more_than_the_limit()
    {
        var plan = PlanFor(Full);
        var dns = new StallingDns(new StaticDnsResolver(), "nothing-stalls.test");
        await new DomainChecker(dns).CheckAsync(plan, default);
        Assert.InRange(dns.MostInFlight, 1, DomainChecker.MaxParallelRecords * 2);   // a record makes up to two lookups at once (A and AAAA)
    }

    [Fact]
    public async Task The_callers_cancellation_still_cancels_the_check()
    {
        var plan = PlanFor(Full);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var dns = new StallingDns(new StaticDnsResolver(), Of(plan, DomainRecordPurpose.Dkim).Host);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new DomainChecker(dns, TimeSpan.FromMinutes(5)).CheckAsync(plan, cts.Token));
    }
}
