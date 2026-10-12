namespace Mta.Dkim.Tests;

public class AuthenticationResultsTests
{
    [Fact]
    public async Task Pass_is_formatted_with_header_properties_and_key_comment()
    {
        string signed = Msg.Sign(Msg.Signer(identity: "@mail.example.com"), Msg.Simple());
        var r = await Msg.VerifyOne(Msg.Verifier(Msg.Dns(TestKeys.Rsa2048)), signed);
        string text = DkimAuthenticationResults.Format(r);
        Assert.Equal($"dkim=pass (2048-bit key) header.d=example.com header.i=@mail.example.com header.s=sel header.b={r.HeaderBPrefix}", text);
    }

    [Fact]
    public async Task Weak_and_testing_keys_are_noted_in_the_comment()
    {
        string signed = Msg.Sign(Msg.Signer(key: TestKeys.Rsa1024), Msg.Simple());
        var dns = Msg.Dns(TestKeys.Rsa1024, txt: DkimKeyTools.FormatDnsTxtValue(TestKeys.Rsa1024) + "; t=y");
        var r = await Msg.VerifyOne(Msg.Verifier(dns), signed);
        Assert.Contains("(1024-bit key; weak key; testing mode)", DkimAuthenticationResults.Format(r));
    }

    [Fact]
    public async Task Failures_carry_a_quoted_reason()
    {
        string signed = Msg.Sign(Msg.Signer(), Msg.Simple()).Replace("the body", "evil", StringComparison.Ordinal);
        var r = await Msg.VerifyOne(Msg.Verifier(Msg.Dns(TestKeys.Rsa2048)), signed);
        string text = DkimAuthenticationResults.Format(r);
        Assert.StartsWith("dkim=fail reason=\"body hash did not verify\" header.d=example.com header.s=sel header.b=", text);
    }

    [Theory]
    [InlineData(DkimStatus.Pass, "pass")]
    [InlineData(DkimStatus.Fail, "fail")]
    [InlineData(DkimStatus.Neutral, "neutral")]
    [InlineData(DkimStatus.TempError, "temperror")]
    [InlineData(DkimStatus.PermError, "permerror")]
    [InlineData(DkimStatus.None, "none")]
    public void Result_names_follow_rfc_8601(DkimStatus status, string name) =>
        Assert.Equal(name, DkimAuthenticationResults.ResultName(status));

    [Fact]
    public void None_has_no_properties_or_reason()
    {
        var r = new DkimVerificationResult(DkimStatus.None, "message is not signed", DkimFailure.NoSignature);
        Assert.Equal("dkim=none", DkimAuthenticationResults.Format(r));
        Assert.Equal(["dkim=none"], DkimAuthenticationResults.FormatAll([]));
    }

    [Fact]
    public void Reason_text_is_sanitized_and_identity_quoted_when_needed()
    {
        var r = new DkimVerificationResult(DkimStatus.Fail, "bad \"quote\" \\ and\r\nnewline é")
        {
            Domain = "example.com",
            Identity = "we ird@example.com",
        };
        string text = DkimAuthenticationResults.Format(r);
        Assert.Equal("dkim=fail reason=\"bad \\\"quote\\\" \\\\ and  newline  \" header.d=example.com header.i=\"we ird@example.com\"", text);
        Assert.DoesNotContain('\r', text);
        Assert.DoesNotContain('\n', text);
    }

    [Fact]
    public void Multiple_results_give_one_fragment_each()
    {
        var results = new[]
        {
            new DkimVerificationResult(DkimStatus.Pass, "ok") { Domain = "a.example", Selector = "s1", HeaderBPrefix = "AAAAAAAA" },
            new DkimVerificationResult(DkimStatus.PermError, "no key") { Domain = "b.example", Selector = "s2" },
        };
        var all = DkimAuthenticationResults.FormatAll(results);
        Assert.Equal(["dkim=pass header.d=a.example header.s=s1 header.b=AAAAAAAA", "dkim=permerror reason=\"no key\" header.d=b.example header.s=s2"], all.ToArray());
    }
}
