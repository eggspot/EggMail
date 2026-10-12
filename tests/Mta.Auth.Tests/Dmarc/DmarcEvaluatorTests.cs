using Mta.Auth.Dmarc;
using Mta.Auth.Domains;
using Mta.Auth.Spf;
using Mta.Dns;
using static Mta.Auth.Tests.TestZone;

namespace Mta.Auth.Tests.Dmarc;

public class DmarcEvaluatorTests
{
    private static readonly IReadOnlyList<DkimAuthResult> NoDkim = [];

    private static DmarcInput Input(string from, SpfResult spf = SpfResult.None, string? spfDomain = null, params DkimAuthResult[] dkim) =>
        new(from, new SpfAuthResult(spf, spfDomain), dkim);

    private static DmarcEvaluator Evaluator(string zone, Random? random = null) =>
        new(Build(zone), new DmarcOptions { Random = random ?? new ScriptedRandom() });

    private sealed class ScriptedRandom(params int[] draws) : Random
    {
        private int _next;

        public int DrawCount => _next;

        public override int Next(int maxValue) => draws.Length == 0 ? throw new InvalidOperationException("unexpected draw") : draws[_next++ % draws.Length] % maxValue;
    }

    // ----- alignment matrix -----

    [Theory]
    // spf result, spf domain, dkim passed, dkim domain, aspf, adkim, expect pass, expect spf aligned, expect dkim aligned
    [InlineData(SpfResult.Pass, "mail.example.com", true, "example.com", "r", "r", true, true, true)]
    [InlineData(SpfResult.Pass, "mail.example.com", true, "example.com", "s", "s", true, false, true)]
    [InlineData(SpfResult.Pass, "mail.example.com", true, "mail.example.com", "s", "s", false, false, false)]
    [InlineData(SpfResult.Pass, "example.com", false, "example.com", "r", "r", true, true, false)]
    [InlineData(SpfResult.Pass, "mail.example.com", false, "x.example.com", "s", "s", false, false, false)]
    [InlineData(SpfResult.Pass, "bounce.example.com", false, "x.example.com", "s", "s", false, false, false)]
    [InlineData(SpfResult.Pass, "bounce.example.com", false, "x.example.com", "r", "r", true, true, false)]
    [InlineData(SpfResult.Pass, "other.net", false, "x.other.net", "r", "r", false, false, false)]
    [InlineData(SpfResult.Pass, "other.net", true, "example.com", "r", "s", true, false, true)]
    [InlineData(SpfResult.Pass, "other.net", true, "mail.example.com", "r", "s", false, false, false)]
    [InlineData(SpfResult.Pass, "other.net", true, "x.mail.example.com", "r", "r", true, false, true)]
    [InlineData(SpfResult.Pass, "other.net", true, "x.mail.example.com", "r", "s", false, false, false)]
    [InlineData(SpfResult.Pass, "other.net", true, "example.com", "r", "r", true, false, true)]
    [InlineData(SpfResult.Fail, "mail.example.com", false, "mail.example.com", "r", "r", false, false, false)]
    [InlineData(SpfResult.SoftFail, "mail.example.com", false, "mail.example.com", "r", "r", false, false, false)]
    [InlineData(SpfResult.Neutral, "mail.example.com", false, "mail.example.com", "r", "r", false, false, false)]
    [InlineData(SpfResult.None, "mail.example.com", false, "mail.example.com", "r", "r", false, false, false)]
    [InlineData(SpfResult.TempError, "mail.example.com", false, "mail.example.com", "r", "r", false, false, false)]
    [InlineData(SpfResult.PermError, "mail.example.com", false, "mail.example.com", "r", "r", false, false, false)]
    [InlineData(SpfResult.Pass, "MAIL.EXAMPLE.COM.", true, "Example.Com", "r", "r", true, true, true)]
    [InlineData(SpfResult.Pass, "evilexample.com", true, "evilexample.com", "r", "r", false, false, false)]
    [InlineData(SpfResult.Pass, "example.com.evil.net", true, "example.com.evil.net", "r", "r", false, false, false)]
    public async Task Alignment_matrix(SpfResult spf, string spfDomain, bool dkimPassed, string dkimDomain, string aspf, string adkim, bool pass, bool spfAligned, bool dkimAligned)
    {
        var evaluator = Evaluator(Z($"_dmarc.example.com TXT v=DMARC1; p=reject; aspf={aspf}; adkim={adkim}"));
        var result = await evaluator.EvaluateAsync(Input("example.com", spf, spfDomain, new DkimAuthResult(dkimDomain, dkimPassed)));
        Assert.Equal(pass ? DmarcResult.Pass : DmarcResult.Fail, result.Result);
        Assert.Equal(spfAligned, result.Spf!.Aligned);
        Assert.Equal(dkimAligned, result.Dkim!.Aligned);
        Assert.Equal(pass ? DmarcDisposition.None : DmarcDisposition.Reject, result.Disposition);
    }

    [Fact]
    public async Task Alignment_details_are_reported()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=none; aspf=s; adkim=r"));
        var result = await evaluator.EvaluateAsync(Input("example.com", SpfResult.Pass, "bounce.example.com", new DkimAuthResult("other.net", true), new DkimAuthResult("mail.example.com", true)));
        Assert.Equal(new DmarcAlignmentResult(true, false, "bounce.example.com", DmarcAlignmentMode.Strict), result.Spf);
        Assert.Equal(new DmarcAlignmentResult(true, true, "mail.example.com", DmarcAlignmentMode.Relaxed), result.Dkim);
        Assert.Equal(DmarcResult.Pass, result.Result);
        Assert.Equal("pass", result.ResultKeyword);
    }

    [Fact]
    public async Task Dkim_with_only_unaligned_passes_reports_the_first_passing_domain()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=none"));
        var result = await evaluator.EvaluateAsync(Input("example.com", SpfResult.None, null, new DkimAuthResult("bad.net", false), new DkimAuthResult("esp.net", true), new DkimAuthResult("esp2.net", true)));
        Assert.Equal(DmarcResult.Fail, result.Result);
        Assert.Equal(new DmarcAlignmentResult(true, false, "esp.net", DmarcAlignmentMode.Relaxed), result.Dkim);
    }

    [Fact]
    public async Task Failed_dkim_signature_never_aligns()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=reject"));
        var result = await evaluator.EvaluateAsync(Input("example.com", SpfResult.None, null, new DkimAuthResult("example.com", false)));
        Assert.Equal(DmarcResult.Fail, result.Result);
        Assert.False(result.Dkim!.Authenticated);
    }

    [Fact]
    public async Task Spf_pass_without_a_domain_cannot_align()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=reject"));
        var result = await evaluator.EvaluateAsync(Input("example.com", SpfResult.Pass, null));
        Assert.Equal(DmarcResult.Fail, result.Result);
        Assert.False(result.Spf!.Authenticated);
    }

    [Fact]
    public async Task Null_dkim_list_is_tolerated()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=reject"));
        var result = await evaluator.EvaluateAsync(new DmarcInput("example.com", new SpfAuthResult(SpfResult.Pass, "example.com"), null!));
        Assert.Equal(DmarcResult.Pass, result.Result);
    }

    // ----- policy discovery -----

    [Fact]
    public async Task Record_at_from_domain_is_used_directly()
    {
        var evaluator = Evaluator(Z("_dmarc.mail.example.com TXT v=DMARC1; p=reject; sp=none", "_dmarc.example.com TXT v=DMARC1; p=none"));
        var result = await evaluator.EvaluateAsync(Input("mail.example.com"));
        Assert.Equal(DmarcPolicy.Reject, result.AppliedPolicy);
        Assert.False(result.UsedOrganizationalDomainRecord);
        Assert.False(result.SubdomainPolicyApplied);
        Assert.Equal("mail.example.com", result.PolicyDomain);
        Assert.Equal(DmarcDisposition.Reject, result.Disposition);
    }

    [Fact]
    public async Task Falls_back_to_the_organizational_domain_and_uses_sp()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=reject; sp=quarantine"));
        var result = await evaluator.EvaluateAsync(Input("a.b.example.com"));
        Assert.Equal(DmarcResult.Fail, result.Result);
        Assert.True(result.UsedOrganizationalDomainRecord);
        Assert.True(result.SubdomainPolicyApplied);
        Assert.Equal(DmarcPolicy.Quarantine, result.AppliedPolicy);
        Assert.Equal(DmarcDisposition.Quarantine, result.Disposition);
        Assert.Equal("example.com", result.PolicyDomain);
        Assert.Equal("example.com", result.OrganizationalDomain);
        Assert.Equal("a.b.example.com", result.FromDomain);
    }

    [Fact]
    public async Task Subdomain_without_sp_uses_p()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=reject"));
        var result = await evaluator.EvaluateAsync(Input("sub.example.com"));
        Assert.Equal(DmarcPolicy.Reject, result.AppliedPolicy);
        Assert.True(result.SubdomainPolicyApplied);
    }

    [Fact]
    public async Task Organizational_domain_itself_uses_p_not_sp()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=reject; sp=none"));
        var result = await evaluator.EvaluateAsync(Input("example.com"));
        Assert.Equal(DmarcPolicy.Reject, result.AppliedPolicy);
        Assert.False(result.SubdomainPolicyApplied);
        Assert.False(result.UsedOrganizationalDomainRecord);
    }

    [Fact]
    public async Task Sp_none_lets_failing_subdomain_mail_through()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=reject; sp=none"));
        var result = await evaluator.EvaluateAsync(Input("news.example.com"));
        Assert.Equal(DmarcResult.Fail, result.Result);
        Assert.Equal(DmarcDisposition.None, result.Disposition);
    }

    [Fact]
    public async Task Public_suffix_list_decides_the_fallback_name()
    {
        var evaluator = Evaluator(Z("_dmarc.example.co.uk TXT v=DMARC1; p=reject", "_dmarc.co.uk TXT v=DMARC1; p=none"));
        var result = await evaluator.EvaluateAsync(Input("mail.eu.example.co.uk"));
        Assert.Equal("example.co.uk", result.PolicyDomain);
        Assert.Equal(DmarcPolicy.Reject, result.AppliedPolicy);
    }

    [Fact]
    public async Task Private_suffix_domains_are_their_own_organizations()
    {
        var evaluator = Evaluator(Z("_dmarc.github.io TXT v=DMARC1; p=reject", "_dmarc.alice.github.io TXT v=DMARC1; p=none"));
        var result = await evaluator.EvaluateAsync(Input("www.alice.github.io"));
        Assert.Equal("alice.github.io", result.PolicyDomain);
        Assert.Equal(DmarcPolicy.None, result.AppliedPolicy);
    }

    [Fact]
    public async Task No_record_anywhere_is_none()
    {
        var result = await Evaluator(Z()).EvaluateAsync(Input("mail.example.com"));
        Assert.Equal(DmarcResult.None, result.Result);
        Assert.Equal(DmarcDisposition.None, result.Disposition);
        Assert.Null(result.Record);
        Assert.Equal("none", result.ResultKeyword);
    }

    [Fact]
    public async Task Nodata_at_from_domain_falls_back()
    {
        var evaluator = Evaluator(Z("_dmarc.mail.example.com TXT hello", "_dmarc.example.com TXT v=DMARC1; p=quarantine"));
        var result = await evaluator.EvaluateAsync(Input("mail.example.com"));
        Assert.Equal("example.com", result.PolicyDomain);
    }

    [Fact]
    public async Task Multiple_records_at_from_domain_mean_no_policy_and_no_fallback()
    {
        var evaluator = Evaluator(Z("_dmarc.mail.example.com TXT v=DMARC1; p=reject", "_dmarc.mail.example.com TXT v=DMARC1; p=none", "_dmarc.example.com TXT v=DMARC1; p=reject"));
        var result = await evaluator.EvaluateAsync(Input("mail.example.com"));
        Assert.Equal(DmarcResult.None, result.Result);
        Assert.Contains("multiple", result.Reason);
    }

    [Fact]
    public async Task Multiple_records_at_organizational_domain_mean_no_policy()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=reject", "_dmarc.example.com TXT v=DMARC1; p=none"));
        var result = await evaluator.EvaluateAsync(Input("mail.example.com"));
        Assert.Equal(DmarcResult.None, result.Result);
    }

    [Fact]
    public async Task Non_dmarc_txt_records_are_ignored_when_counting()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=spf1 -all", "_dmarc.example.com TXT v=DMARC1; p=reject", "_dmarc.example.com TXT hello"));
        var result = await evaluator.EvaluateAsync(Input("example.com"));
        Assert.Equal(DmarcPolicy.Reject, result.AppliedPolicy);
    }

    [Fact]
    public async Task Invalid_record_means_no_policy_and_no_fallback()
    {
        var evaluator = Evaluator(Z("_dmarc.mail.example.com TXT v=DMARC1; p=banana", "_dmarc.example.com TXT v=DMARC1; p=reject"));
        var result = await evaluator.EvaluateAsync(Input("mail.example.com"));
        Assert.Equal(DmarcResult.None, result.Result);
        Assert.Contains("invalid", result.Reason);
    }

    [Fact]
    public async Task Invalid_p_with_rua_is_monitoring_only()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=banana; rua=mailto:r@example.com"));
        var result = await evaluator.EvaluateAsync(Input("example.com"));
        Assert.Equal(DmarcResult.Fail, result.Result);
        Assert.Equal(DmarcDisposition.None, result.Disposition);
        Assert.True(result.Record!.IsMonitoringFallback);
    }

    [Fact]
    public async Task Servfail_at_from_domain_is_temperror_without_fallback()
    {
        var evaluator = Evaluator(Z("_dmarc.mail.example.com SERVFAIL TXT", "_dmarc.example.com TXT v=DMARC1; p=reject"));
        var result = await evaluator.EvaluateAsync(Input("mail.example.com"));
        Assert.Equal(DmarcResult.TempError, result.Result);
        Assert.Equal(DmarcDisposition.None, result.Disposition);
        Assert.Equal("temperror", result.ResultKeyword);
    }

    [Fact]
    public async Task Servfail_at_organizational_domain_is_temperror()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com SERVFAIL TXT"));
        var result = await evaluator.EvaluateAsync(Input("mail.example.com"));
        Assert.Equal(DmarcResult.TempError, result.Result);
    }

    [Fact]
    public async Task Resolver_exception_is_temperror()
    {
        var evaluator = new DmarcEvaluator(new ThrowingResolver());
        var result = await evaluator.EvaluateAsync(Input("example.com"));
        Assert.Equal(DmarcResult.TempError, result.Result);
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData("bad..domain")]
    [InlineData("[192.0.2.1]")]
    [InlineData("exa mple.com")]
    public async Task Unusable_from_domain_is_permerror(string from)
    {
        var result = await Evaluator(Z()).EvaluateAsync(Input(from));
        Assert.Equal(DmarcResult.PermError, result.Result);
        Assert.Equal("permerror", result.ResultKeyword);
    }

    [Fact]
    public async Task Case_and_trailing_dot_of_from_domain_are_normalised()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=reject"));
        var result = await evaluator.EvaluateAsync(Input("MAIL.Example.COM.", SpfResult.Pass, "mail.example.com"));
        Assert.Equal(DmarcResult.Pass, result.Result);
        Assert.Equal("mail.example.com", result.FromDomain);
    }

    [Fact]
    public async Task Lookup_can_be_cached_and_reused()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=quarantine"));
        var lookup = await evaluator.LookupPolicyAsync("example.com");
        Assert.Equal(DmarcLookupStatus.Found, lookup.Status);
        var result = evaluator.Evaluate(Input("example.com"), lookup);
        Assert.Equal(DmarcDisposition.Quarantine, result.Disposition);
    }

    [Fact]
    public async Task Policy_records_over_the_length_limit_are_ignored()
    {
        var resolver = Build(Z("_dmarc.example.com TXT v=DMARC1; p=reject; x=" + new string('a', 200)));
        var evaluator = new DmarcEvaluator(resolver, new DmarcOptions { MaxRecordLength = 100 });
        var result = await evaluator.EvaluateAsync(Input("example.com"));
        Assert.Equal(DmarcResult.None, result.Result);
    }

    // ----- dispositions and pct -----

    [Theory]
    [InlineData("none", DmarcDisposition.None)]
    [InlineData("quarantine", DmarcDisposition.Quarantine)]
    [InlineData("reject", DmarcDisposition.Reject)]
    public async Task Failing_message_gets_the_policy_disposition(string policy, DmarcDisposition expected)
    {
        var result = await Evaluator(Z($"_dmarc.example.com TXT v=DMARC1; p={policy}")).EvaluateAsync(Input("example.com"));
        Assert.Equal(expected, result.Disposition);
        Assert.False(result.SampledOut);
    }

    [Theory]
    [InlineData("reject", 0, DmarcDisposition.Reject, false)]
    [InlineData("reject", 49, DmarcDisposition.Reject, false)]
    [InlineData("reject", 50, DmarcDisposition.Quarantine, true)]
    [InlineData("reject", 99, DmarcDisposition.Quarantine, true)]
    [InlineData("quarantine", 49, DmarcDisposition.Quarantine, false)]
    [InlineData("quarantine", 50, DmarcDisposition.None, true)]
    [InlineData("quarantine", 99, DmarcDisposition.None, true)]
    public async Task Pct_sampling_with_scripted_draws(string policy, int draw, DmarcDisposition expected, bool sampledOut)
    {
        var evaluator = Evaluator(Z($"_dmarc.example.com TXT v=DMARC1; p={policy}; pct=50"), new ScriptedRandom(draw));
        var result = await evaluator.EvaluateAsync(Input("example.com"));
        Assert.Equal(DmarcResult.Fail, result.Result);
        Assert.Equal(expected, result.Disposition);
        Assert.Equal(sampledOut, result.SampledOut);
        Assert.Equal(policy == "reject" ? DmarcPolicy.Reject : DmarcPolicy.Quarantine, result.AppliedPolicy);
    }

    [Fact]
    public async Task Pct_zero_samples_everything_out()
    {
        var random = new ScriptedRandom(0);
        var result = await Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=reject; pct=0"), random).EvaluateAsync(Input("example.com"));
        Assert.Equal(DmarcDisposition.Quarantine, result.Disposition);
        Assert.True(result.SampledOut);
    }

    [Fact]
    public async Task Pct_hundred_never_draws_and_passing_messages_never_draw()
    {
        var random = new ScriptedRandom(0);
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=reject", "_dmarc.other.com TXT v=DMARC1; p=reject; pct=10"), random);
        await evaluator.EvaluateAsync(Input("example.com"));
        await evaluator.EvaluateAsync(Input("other.com", SpfResult.Pass, "other.com"));
        Assert.Equal(0, random.DrawCount);
    }

    [Fact]
    public async Task Pct_with_policy_none_does_not_draw()
    {
        var random = new ScriptedRandom(0);
        var result = await Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=none; pct=10"), random).EvaluateAsync(Input("example.com"));
        Assert.Equal(DmarcDisposition.None, result.Disposition);
        Assert.False(result.SampledOut);
        Assert.Equal(0, random.DrawCount);
    }

    [Fact]
    public async Task Pct_uses_the_subdomain_policy_for_subdomains()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=none; sp=reject; pct=50"), new ScriptedRandom(75));
        var result = await evaluator.EvaluateAsync(Input("sub.example.com"));
        Assert.Equal(DmarcPolicy.Reject, result.AppliedPolicy);
        Assert.Equal(DmarcDisposition.Quarantine, result.Disposition);
    }

    [Fact]
    public async Task Seeded_random_gives_a_stable_split()
    {
        var evaluator = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=reject; pct=30"), new Random(1234));
        int rejected = 0;
        for (int i = 0; i < 1000; i++)
        {
            var r = await evaluator.EvaluateAsync(Input("example.com"));
            if (r.Disposition == DmarcDisposition.Reject)
            {
                rejected++;
            }
        }

        Assert.InRange(rejected, 240, 360);
        var again = Evaluator(Z("_dmarc.example.com TXT v=DMARC1; p=reject; pct=30"), new Random(1234));
        int rejected2 = 0;
        for (int i = 0; i < 1000; i++)
        {
            if ((await again.EvaluateAsync(Input("example.com"))).Disposition == DmarcDisposition.Reject)
            {
                rejected2++;
            }
        }

        Assert.Equal(rejected, rejected2);
    }

    // ----- helpers -----

    [Theory]
    [InlineData("example.com", "example.com", DmarcAlignmentMode.Strict, true)]
    [InlineData("EXAMPLE.com", "example.COM.", DmarcAlignmentMode.Strict, true)]
    [InlineData("a.example.com", "example.com", DmarcAlignmentMode.Strict, false)]
    [InlineData("a.example.com", "b.example.com", DmarcAlignmentMode.Relaxed, true)]
    [InlineData("a.example.co.uk", "b.example.co.uk", DmarcAlignmentMode.Relaxed, true)]
    [InlineData("a.co.uk", "b.co.uk", DmarcAlignmentMode.Relaxed, false)]
    [InlineData("", "example.com", DmarcAlignmentMode.Relaxed, false)]
    public void Is_aligned(string authenticated, string from, DmarcAlignmentMode mode, bool expected) =>
        Assert.Equal(expected, DmarcEvaluator.IsAligned(authenticated, from, mode, PublicSuffixList.Default));

    private sealed class ThrowingResolver : IDnsResolver
    {
        public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default) =>
            throw new DnsException("timeout");
    }
}
