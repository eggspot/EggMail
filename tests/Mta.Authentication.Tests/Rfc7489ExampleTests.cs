using Mta.Auth.Dmarc;
using Mta.Auth.Domains;
using Mta.Auth.Spf;

namespace Mta.Authentication.Tests;

/// <summary>The worked examples in the text of RFC 7489 section 3 (alignment and the Organizational Domain), as stated there.</summary>
public class Rfc7489ExampleTests
{
    private static DmarcEvaluator Evaluator(string aspf = "r", string adkim = "r") =>
        new(ZoneBuilder.Build($"_dmarc.example.com TXT v=DMARC1; p=reject; aspf={aspf}; adkim={adkim}"));

    // Section 3.1.1: "d=example.com" and From alerts@news.example.com are in alignment in relaxed mode, not in strict mode.
    [Theory]
    [InlineData("r", true)]
    [InlineData("s", false)]
    public async Task Section_3_1_1_dkim_example(string mode, bool aligned)
    {
        var result = await Evaluator(adkim: mode).EvaluateAsync(new DmarcInput("news.example.com", new SpfAuthResult(SpfResult.None, null), [new DkimAuthResult("example.com", true)]), default);

        // The policy lookup falls back to the organizational domain's record (_dmarc.example.com).
        Assert.Equal(aligned, result.Dkim!.Aligned);
        Assert.Equal(aligned ? DmarcResult.Pass : DmarcResult.Fail, result.Result);
    }

    // Section 3.1.1: "a DKIM signature bearing a value of d=com would never allow an in alignment result".
    [Fact]
    public async Task Section_3_1_1_a_signature_by_a_top_level_domain_never_aligns()
    {
        foreach (string mode in new[] { "r", "s" })
        {
            var result = await Evaluator(adkim: mode).EvaluateAsync(new DmarcInput("example.com", new SpfAuthResult(SpfResult.None, null), [new DkimAuthResult("com", true)]), default);
            Assert.False(result.Dkim!.Aligned);
        }
    }

    // Section 3.1.1: "it is considered to be a DMARC pass if any DKIM signature is aligned and verifies".
    [Fact]
    public async Task Section_3_1_1_any_aligned_verifying_signature_is_enough_and_a_failing_one_is_not()
    {
        var input = new DmarcInput("example.com", new SpfAuthResult(SpfResult.None, null), [new DkimAuthResult("lists.example.org", true), new DkimAuthResult("example.com", false), new DkimAuthResult("mail.example.com", true)]);

        Assert.Equal(DmarcResult.Pass, (await Evaluator().EvaluateAsync(input, default)).Result);
        Assert.Equal(DmarcResult.Fail, (await Evaluator(adkim: "s").EvaluateAsync(input, default)).Result);   // strict: only an exact "example.com" would do, and that one failed
    }

    // Section 3.1.2: SPF passes for MAIL FROM domain cbg.bounces.example.com, From is payments@example.com: aligned in relaxed mode, not in strict mode.
    [Theory]
    [InlineData("r", true)]
    [InlineData("s", false)]
    public async Task Section_3_1_2_spf_example(string mode, bool aligned)
    {
        var result = await Evaluator(aspf: mode).EvaluateAsync(new DmarcInput("example.com", new SpfAuthResult(SpfResult.Pass, "cbg.bounces.example.com"), []), default);

        Assert.Equal(aligned, result.Spf!.Aligned);
        Assert.Equal(aligned ? DmarcResult.Pass : DmarcResult.Fail, result.Result);
    }

    // Section 3.2: "a.b.c.d.example.com" has the Organizational Domain "example.com" (com is a public suffix).
    [Theory]
    [InlineData("a.b.c.d.example.com", "example.com")]
    [InlineData("example.com", "example.com")]
    [InlineData("www.example.co.uk", "example.co.uk")]
    [InlineData("example.co.uk", "example.co.uk")]
    [InlineData("deep.sub.city.kobe.jp", "city.kobe.jp")]   // the "!city.kobe.jp" exception rule of the public suffix list
    public void Section_3_2_organizational_domain(string domain, string organizational)
    {
        Assert.Equal(organizational, PublicSuffixList.Default.GetOrganizationalDomain(domain));
    }
}
