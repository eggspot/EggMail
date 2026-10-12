using Mta.Auth.AuthenticationResults;
using Mta.Auth.Dmarc;
using Mta.Auth.Spf;

namespace Mta.Auth.Tests.AuthenticationResults;

public class AuthenticationResultsBuilderTests
{
    private const string Id = "mx.example.org";

    [Fact]
    public void Empty_builder_emits_none() =>
        Assert.Equal("mx.example.org; none", new AuthenticationResultsBuilder(Id).BuildFieldBody());

    [Fact]
    public void Header_has_name_and_terminating_crlf()
    {
        string header = new AuthenticationResultsBuilder(Id).BuildHeader();
        Assert.Equal("Authentication-Results: mx.example.org; none\r\n", header);
    }

    [Fact]
    public void Spf_result_with_mailfrom_property()
    {
        var b = new AuthenticationResultsBuilder(Id).AddSpf(new SpfCheckResult(SpfResult.Pass, "example.com"), SpfIdentityKind.MailFrom, "user@example.com");
        Assert.Equal("mx.example.org;\r\n\tspf=pass smtp.mailfrom=user@example.com", b.BuildFieldBody());
    }

    [Fact]
    public void Spf_helo_identity_and_comment()
    {
        var b = new AuthenticationResultsBuilder(Id).AddSpf(new SpfCheckResult(SpfResult.SoftFail, "helo.example.net"), SpfIdentityKind.Helo, "helo.example.net", "best guess record for domain");
        Assert.Equal("mx.example.org;\r\n\tspf=softfail (best guess record for domain) smtp.helo=helo.example.net", b.BuildFieldBody());
    }

    [Theory]
    [InlineData(SpfResult.None, "none")]
    [InlineData(SpfResult.Neutral, "neutral")]
    [InlineData(SpfResult.Pass, "pass")]
    [InlineData(SpfResult.Fail, "fail")]
    [InlineData(SpfResult.SoftFail, "softfail")]
    [InlineData(SpfResult.TempError, "temperror")]
    [InlineData(SpfResult.PermError, "permerror")]
    public void Spf_result_keywords(SpfResult result, string keyword)
    {
        var b = new AuthenticationResultsBuilder(Id).AddSpf(new SpfCheckResult(result, "example.com"), SpfIdentityKind.MailFrom, "example.com");
        Assert.StartsWith("spf=" + keyword + " ", b.Results[0].Method + "=" + b.Results[0].Result + " ");
        Assert.Contains("spf=" + keyword, b.BuildFieldBody());
    }

    [Fact]
    public void Dkim_from_result_and_from_fragment()
    {
        var b = new AuthenticationResultsBuilder(Id)
            .AddDkim(new DkimAuthResult("example.com", true, "sel1"))
            .AddDkim(new DkimAuthResult("other.net", false), "body hash did not verify")
            .AddDkim("dkim=pass header.d=third.org header.s=s3 header.b=AbCdEfGh");
        Assert.Equal(
            "mx.example.org;\r\n\tdkim=pass header.d=example.com header.s=sel1;\r\n\tdkim=fail (body hash did not verify) header.d=other.net;\r\n\tdkim=pass header.d=third.org header.s=s3 header.b=AbCdEfGh",
            b.BuildFieldBody());
    }

    [Fact]
    public void Dmarc_with_policy_comment()
    {
        var evaluation = new DmarcEvaluation(
            DmarcResult.Fail, DmarcDisposition.Reject, DmarcPolicy.Reject, "example.com", "example.com", "example.com", false, false, false,
            ParseRecord("v=DMARC1; p=reject; sp=quarantine"), null, null, null);
        var b = new AuthenticationResultsBuilder(Id).AddDmarc(evaluation);
        Assert.Equal("mx.example.org;\r\n\tdmarc=fail (p=REJECT sp=QUARANTINE dis=REJECT) header.from=example.com", b.BuildFieldBody());
    }

    [Fact]
    public void Dmarc_without_policy_has_no_comment()
    {
        var evaluation = new DmarcEvaluation(DmarcResult.None, DmarcDisposition.None, null, "example.com", null, "example.com", false, false, false, null, null, null, "no DMARC record");
        Assert.Equal("mx.example.org;\r\n\tdmarc=none header.from=example.com", new AuthenticationResultsBuilder(Id).AddDmarc(evaluation).BuildFieldBody());
    }

    [Fact]
    public void Complete_header_with_arc_placeholder()
    {
        var b = new AuthenticationResultsBuilder(Id)
            .AddSpf(new SpfCheckResult(SpfResult.Pass, "example.com"), SpfIdentityKind.MailFrom, "bounce@example.com")
            .AddDkim(new DkimAuthResult("example.com", true, "s1"))
            .AddArc("arc=none")
            .Add("dmarc", "pass", [("header", "from", "example.com")]);
        Assert.Equal(
            "mx.example.org;\r\n\tspf=pass smtp.mailfrom=bounce@example.com;\r\n\tdkim=pass header.d=example.com header.s=s1;\r\n\tarc=none;\r\n\tdmarc=pass header.from=example.com",
            b.BuildFieldBody());
    }

    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("user@example.com", "user@example.com")]
    [InlineData("first.last+tag@example.com", "first.last+tag@example.com")]
    [InlineData("@example.com", "@example.com")]
    [InlineData("abc123", "abc123")]
    [InlineData("a b", "\"a b\"")]
    [InlineData("a\"b", "\"a\\\"b\"")]
    [InlineData("a\\b", "\"a\\\\b\"")]
    [InlineData("a;b", "\"a;b\"")]
    [InlineData("a(b)", "\"a(b)\"")]
    [InlineData("2001:db8::1", "\"2001:db8::1\"")]
    [InlineData("a=b", "\"a=b\"")]
    [InlineData("a/b", "\"a/b\"")]
    [InlineData("", "\"\"")]
    [InlineData("user name@example.com", "\"user name@example.com\"")]
    [InlineData("\"quoted\"@example.com", "\"\\\"quoted\\\"@example.com\"")]
    [InlineData("a@b@example.com", "\"a@b@example.com\"")]
    public void Value_quoting(string value, string expected) =>
        Assert.Equal(expected, AuthenticationResultsBuilder.FormatValue(value));

    [Fact]
    public void Control_characters_cannot_inject_headers()
    {
        var b = new AuthenticationResultsBuilder(Id)
            .Add("dkim", "pass", [("header", "d", "evil.com\r\nX-Injected: yes"), ("header", "s", "a\nb")], comment: "x)\r\nBcc: boss@example.com", reason: "r\r\nr");
        string body = b.BuildFieldBody();
        foreach (string line in body.Split("\r\n").Skip(1))
        {
            Assert.StartsWith("\t", line);
        }

        Assert.DoesNotContain("\n", body.Replace("\r\n\t", string.Empty));
        Assert.DoesNotContain("\r", body.Replace("\r\n\t", string.Empty));
        Assert.True(AuthenticationResultsHeader.TryParse(body, out var parsed));
        Assert.Single(parsed.Results);
        Assert.Equal("evil.com  X-Injected: yes", parsed.Results[0].GetProperty("header", "d"));
    }

    [Fact]
    public void Non_ascii_is_replaced_unless_utf8_is_allowed()
    {
        var plain = new AuthenticationResultsBuilder(Id).Add("dkim", "pass", [("header", "d", "bücher.example")]);
        Assert.Contains("header.d=\"b?cher.example\"", plain.BuildFieldBody());
        var utf8 = new AuthenticationResultsBuilder(Id, allowUtf8: true).Add("dkim", "pass", [("header", "d", "bücher.example")]);
        Assert.Contains("bücher.example", utf8.BuildFieldBody());
    }

    [Fact]
    public void Comment_parentheses_and_backslashes_are_escaped()
    {
        var b = new AuthenticationResultsBuilder(Id).Add("spf", "pass", comment: "a (nested) \\ comment");
        Assert.Equal("mx.example.org;\r\n\tspf=pass (a \\(nested\\) \\\\ comment)", b.BuildFieldBody());
        Assert.True(AuthenticationResultsHeader.TryParse(b.BuildFieldBody(), out var parsed));
        Assert.Equal("a (nested) \\ comment", parsed.Results[0].Comment);
    }

    [Fact]
    public void Reason_is_quoted()
    {
        var b = new AuthenticationResultsBuilder(Id).Add("dkim", "fail", [("header", "d", "example.com")], reason: "bad signature");
        Assert.Equal("mx.example.org;\r\n\tdkim=fail reason=\"bad signature\" header.d=example.com", b.BuildFieldBody());
    }

    [Fact]
    public void Method_version_is_emitted()
    {
        var b = new AuthenticationResultsBuilder(Id).Add("dkim", "pass", methodVersion: 1);
        Assert.Equal("mx.example.org;\r\n\tdkim/1=pass", b.BuildFieldBody());
    }

    [Fact]
    public void Header_version_is_emitted_when_set()
    {
        var b = new AuthenticationResultsBuilder(Id) { Version = 1 };
        Assert.Equal("mx.example.org 1; none", b.BuildFieldBody());
    }

    [Fact]
    public void Authserv_id_is_quoted_when_not_a_token()
    {
        Assert.Equal("\"mx host\"; none", new AuthenticationResultsBuilder("mx host").BuildFieldBody());
    }

    [Fact]
    public void Long_clauses_are_folded_below_78_columns()
    {
        var b = new AuthenticationResultsBuilder(Id).Add(
            "dkim", "pass",
            [("header", "d", "example.com"), ("header", "s", "selector-one"), ("header", "i", "@mail.example.com"), ("header", "a", "rsa-sha256"), ("header", "b", "AbCdEfGhIjKl"), ("policy", "note", "a long note that needs to be quoted")],
            comment: "this is a long comment that explains in some detail why the signature was accepted by this particular verifier");
        string body = b.BuildFieldBody();
        foreach (string line in body.Split("\r\n"))
        {
            Assert.True(line.Length <= 78, $"line too long ({line.Length}): {line}");
        }

        Assert.True(body.Split("\r\n").Length > 2);
        Assert.True(AuthenticationResultsHeader.TryParse(body, out var parsed));
        Assert.Equal(6, parsed.Results[0].Properties.Count);
        Assert.Equal("a long note that needs to be quoted", parsed.Results[0].GetProperty("policy", "note"));
        Assert.StartsWith("this is a long comment", parsed.Results[0].Comment);
    }

    [Fact]
    public void Fragments_are_validated_and_normalised()
    {
        var b = new AuthenticationResultsBuilder(Id);
        Assert.True(b.TryAddFragment("  DKIM=Pass   header.d=Example.com  "));
        Assert.Equal("mx.example.org;\r\n\tdkim=pass header.d=Example.com", b.BuildFieldBody());
        Assert.False(b.TryAddFragment("dkim=pass; spf=pass"));
        Assert.False(b.TryAddFragment("garbage"));
        Assert.False(b.TryAddFragment(null));
        Assert.False(b.TryAddFragment(""));
        Assert.Single(b.Results);
        Assert.Throws<ArgumentException>(() => b.AddFragment("nope"));
    }

    [Fact]
    public void Fragment_with_wrong_method_is_rejected()
    {
        var b = new AuthenticationResultsBuilder(Id);
        Assert.Throws<ArgumentException>(() => b.AddDkim("spf=pass smtp.mailfrom=example.com"));
        Assert.Throws<ArgumentException>(() => b.AddArc("dkim=pass"));
        Assert.Empty(b.Results);
    }

    [Fact]
    public void Fragment_cannot_smuggle_extra_clauses_or_lines()
    {
        var b = new AuthenticationResultsBuilder(Id);
        Assert.False(b.TryAddFragment("dkim=pass\r\nX-Evil: 1"));
        Assert.False(b.TryAddFragment("dkim=pass header.d=x.com;\r\n\tspf=pass"));
    }

    [Theory]
    [InlineData("", "pass")]
    [InlineData("spf", "")]
    [InlineData("sp f", "pass")]
    [InlineData("spf", "pa;ss")]
    [InlineData("-spf", "pass")]
    public void Invalid_keywords_throw(string method, string result) =>
        Assert.Throws<ArgumentException>(() => new AuthenticationResultsBuilder(Id).Add(method, result));

    [Fact]
    public void Invalid_property_keywords_throw()
    {
        Assert.Throws<ArgumentException>(() => new AuthenticationResultsBuilder(Id).Add("spf", "pass", [("smtp", "mail from", "x")]));
        Assert.Throws<ArgumentException>(() => new AuthenticationResultsBuilder(Id).Add("spf", "pass", [("smtp.x", "mailfrom", "x")]));
    }

    [Fact]
    public void Blank_authserv_id_is_rejected() =>
        Assert.Throws<ArgumentException>(() => new AuthenticationResultsBuilder("  "));

    private static DmarcRecord ParseRecord(string text)
    {
        Assert.True(DmarcRecord.TryParse(text, out var record, out _));
        return record;
    }
}
