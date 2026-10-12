using Mta.Auth.AuthenticationResults;

namespace Mta.Auth.Tests.AuthenticationResults;

public class AuthenticationResultsParserTests
{
    private static AuthenticationResultsHeader Parse(string body)
    {
        Assert.True(AuthenticationResultsHeader.TryParse(body, out var header), "failed to parse: " + body);
        return header;
    }

    [Fact]
    public void Rfc8601_none_form()
    {
        var h = Parse("example.org 1; none");
        Assert.Equal("example.org", h.AuthservId);
        Assert.Equal(1, h.Version);
        Assert.True(h.IsNone);
    }

    [Fact]
    public void None_with_comment_and_case()
    {
        Assert.True(Parse("example.org; NONE (no checks)").IsNone);
    }

    [Fact]
    public void Rfc8601_multiple_dkim_results_with_reasons()
    {
        var h = Parse("example.com;\r\n\tdkim=pass reason=\"good signature\"\r\n\t  header.i=@mail-router.example.net;\r\n\tdkim=fail reason=\"bad signature\"\r\n\t  header.i=@newyork.example.com");
        Assert.Equal(2, h.Results.Count);
        Assert.Equal("good signature", h.Results[0].Reason);
        Assert.Equal("@mail-router.example.net", h.Results[0].GetProperty("header", "i"));
        Assert.Equal("fail", h.Results[1].Result);
        Assert.Null(h.Version);
    }

    [Fact]
    public void Rfc8601_auth_and_spf()
    {
        var h = Parse("example.com;\r\n\tauth=pass (cram-md5) smtp.auth=sender@example.com;\r\n\tspf=fail smtp.mailfrom=example.com");
        Assert.Equal("auth", h.Results[0].Method);
        Assert.Equal("cram-md5", h.Results[0].Comment);
        Assert.Equal("sender@example.com", h.Results[0].GetProperty("smtp", "auth"));
        Assert.Equal("fail", h.Results[1].Result);
    }

    [Fact]
    public void Gmail_style_result_with_long_comment()
    {
        var h = Parse("mx.google.com; spf=pass (google.com: domain of sender@example.com designates 192.0.2.1 as permitted sender) smtp.mailfrom=sender@example.com; dkim=pass header.i=@example.com header.s=s1 header.b=abcDEF12; dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=example.com");
        Assert.Equal(3, h.Results.Count);
        Assert.Equal("google.com: domain of sender@example.com designates 192.0.2.1 as permitted sender", h.Results[0].Comment);
        Assert.Equal("sender@example.com", h.Results[0].GetProperty("smtp", "mailfrom"));
        Assert.Equal("abcDEF12", h.Results[1].GetProperty("header", "b"));
        Assert.Equal("p=NONE sp=NONE dis=NONE", h.Results[2].Comment);
    }

    [Fact]
    public void Method_version_and_case_insensitivity()
    {
        var h = Parse("Example.COM; DKIM/1=Pass Header.D=example.com");
        Assert.Equal("dkim", h.Results[0].Method);
        Assert.Equal(1, h.Results[0].MethodVersion);
        Assert.Equal("pass", h.Results[0].Result);
        Assert.Equal("example.com", h.Results[0].GetProperty("HEADER", "D"));
        Assert.Equal("Example.COM", h.AuthservId);
    }

    [Fact]
    public void Quoted_values_with_escapes()
    {
        var h = Parse("example.com; dkim=pass header.d=\"a \\\"quoted\\\" \\\\ value; with semicolon\"");
        Assert.Equal("a \"quoted\" \\ value; with semicolon", h.Results[0].GetProperty("header", "d"));
    }

    [Fact]
    public void Nested_comments_everywhere()
    {
        var h = Parse("(lead) example.com (id) ; (before) spf (m) = (r) pass (outer (inner) text) smtp (p) . (q) mailfrom (e) = (v) example.com (tail)");
        Assert.Equal("example.com", h.AuthservId);
        Assert.Equal("pass", h.Results[0].Result);
        Assert.Equal("outer (inner) text", h.Results[0].Comment);
        Assert.Equal("example.com", h.Results[0].GetProperty("smtp", "mailfrom"));
    }

    [Fact]
    public void Unquoted_ipv6_and_odd_values_are_tolerated()
    {
        var h = Parse("example.com; iprev=pass policy.iprev=2001:db8::1");
        Assert.Equal("2001:db8::1", h.Results[0].GetProperty("policy", "iprev"));
    }

    [Fact]
    public void Result_without_properties()
    {
        var h = Parse("example.com; arc=none");
        Assert.Empty(h.Results[0].Properties);
    }

    [Fact]
    public void Trailing_semicolon_is_tolerated()
    {
        Assert.Single(Parse("example.com; spf=pass;").Results);
    }

    [Fact]
    public void For_method_filters()
    {
        var h = Parse("example.com; dkim=pass header.d=a.com; dkim=fail header.d=b.com; spf=pass");
        Assert.Equal(2, h.ForMethod("DKIM").Count());
        Assert.Single(h.ForMethod("spf"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(";")]
    [InlineData("example.com")]
    [InlineData("example.com;")]
    [InlineData("example.com; spf")]
    [InlineData("example.com; spf=")]
    [InlineData("example.com; =pass")]
    [InlineData("example.com; spf=pass smtp")]
    [InlineData("example.com; spf=pass smtp.mailfrom")]
    [InlineData("example.com; spf=pass smtp.mailfrom=")]
    [InlineData("example.com; spf=pass smtp.=x")]
    [InlineData("example.com; spf=pass (unterminated")]
    [InlineData("example.com; spf=pass x.y=\"unterminated")]
    [InlineData("example.com; spf=pass stray")]
    [InlineData("example.com; spf=pass nonreason=x")]
    [InlineData("example.com; spf=pass )")]
    [InlineData("example.com; spf=pass none")]
    [InlineData("example.com; none extra")]
    [InlineData("example.com 99999; spf=pass")]
    [InlineData("example.com 1 2; spf=pass")]
    [InlineData("\"unterminated; spf=pass")]
    public void Malformed_input_is_rejected(string body)
    {
        Assert.False(AuthenticationResultsHeader.TryParse(body, out var header));
        Assert.Null(header);
    }

    [Fact]
    public void Null_and_oversized_input_is_rejected()
    {
        Assert.False(AuthenticationResultsHeader.TryParse(null, out _));
        Assert.False(AuthenticationResultsHeader.TryParse("example.com; spf=pass " + new string('x', AuthenticationResultsParser.MaxLength), out _));
    }

    [Fact]
    public void Deeply_nested_comments_are_rejected_without_overflow()
    {
        string nested = new string('(', 5000) + "x" + new string(')', 5000);
        Assert.False(AuthenticationResultsHeader.TryParse("example.com; spf=pass " + nested, out _));
    }

    [Fact]
    public void Many_clauses_are_bounded()
    {
        string body = "example.com" + string.Concat(Enumerable.Repeat("; spf=pass", 1000));
        Assert.False(AuthenticationResultsHeader.TryParse(body, out _));
    }

    // ----- builder / parser round trip -----

    public static IEnumerable<object[]> RoundTripValues() =>
    [
        ["example.com"],
        ["user@example.com"],
        ["with space"],
        ["quote\"inside"],
        ["back\\slash"],
        ["semi;colon"],
        ["paren(thesis)"],
        ["2001:db8::1"],
        ["a=b/c?d"],
        [""],
        ["tab\tand\nnewline"],
        ["\u00e9clair.example"],
        ["@example.com"],
        ["trailing space "],
    ];

    [Theory]
    [MemberData(nameof(RoundTripValues))]
    public void Builder_output_parses_back_to_the_same_values(string value)
    {
        string expected = Normalise(value);
        var builder = new AuthenticationResultsBuilder("mx.example.org")
            .Add("dkim", "pass", [("header", "d", value), ("header", "s", "sel")], reason: value, comment: value);
        string body = builder.BuildFieldBody();
        Assert.True(AuthenticationResultsHeader.TryParse(body, out var parsed), body);
        Assert.Equal("mx.example.org", parsed.AuthservId);
        var result = Assert.Single(parsed.Results);
        Assert.Equal("dkim", result.Method);
        Assert.Equal("pass", result.Result);
        Assert.Equal(expected, result.GetProperty("header", "d"));
        Assert.Equal("sel", result.GetProperty("header", "s"));
        Assert.Equal(expected, result.Reason);
        if (expected.Trim().Length > 0)
        {
            Assert.Equal(string.Join(' ', expected.Split(' ', StringSplitOptions.RemoveEmptyEntries)), result.Comment);
        }
    }

    [Fact]
    public void Random_values_round_trip()
    {
        var random = new Random(20261012);
        const string alphabet = "abcXYZ019 .-_@\"\\();:,=/?!#$%&'*+^`{|}~<>[]\t";
        for (int i = 0; i < 500; i++)
        {
            string value = new(Enumerable.Range(0, random.Next(0, 24)).Select(_ => alphabet[random.Next(alphabet.Length)]).ToArray());
            var builder = new AuthenticationResultsBuilder("mx.example.org").Add("spf", "pass", [("smtp", "mailfrom", value), ("policy", "x", "y")]);
            string body = builder.BuildFieldBody();
            Assert.True(AuthenticationResultsHeader.TryParse(body, out var parsed), $"seed value '{value}' produced {body}");
            Assert.Equal(Normalise(value), parsed.Results[0].GetProperty("smtp", "mailfrom"));
            Assert.Equal("y", parsed.Results[0].GetProperty("policy", "x"));
        }
    }

    [Fact]
    public void Multi_method_header_round_trips()
    {
        var builder = new AuthenticationResultsBuilder("mx.example.org") { Version = 1 }
            .Add("spf", "pass", [("smtp", "mailfrom", "user@example.com")], comment: "domain of example.com designates 192.0.2.3 as permitted sender")
            .Add("dkim", "pass", [("header", "d", "example.com"), ("header", "s", "s1")], methodVersion: 1)
            .Add("dmarc", "fail", [("header", "from", "example.com")], comment: "p=REJECT sp=REJECT dis=REJECT")
            .AddArc("arc=none");
        Assert.True(AuthenticationResultsHeader.TryParse(builder.BuildFieldBody(), out var parsed));
        Assert.Equal(1, parsed.Version);
        Assert.Equal(["spf", "dkim", "dmarc", "arc"], parsed.Results.Select(r => r.Method));
        Assert.Equal(1, parsed.Results[1].MethodVersion);
        Assert.Equal("p=REJECT sp=REJECT dis=REJECT", parsed.Results[2].Comment);
        Assert.Equal(builder.BuildFieldBody(), RebuildFrom(parsed).BuildFieldBody());
    }

    private static AuthenticationResultsBuilder RebuildFrom(AuthenticationResultsHeader header)
    {
        var builder = new AuthenticationResultsBuilder(header.AuthservId) { Version = header.Version };
        foreach (var r in header.Results)
        {
            builder.Add(r.Method, r.Result, r.Properties.Select(p => (p.Ptype, p.Property, p.Value)), r.Reason, r.Comment, r.MethodVersion);
        }

        return builder;
    }

    private static string Normalise(string value)
    {
        var chars = value.Select(c => c < ' ' || c == '\x7F' ? ' ' : c > '\x7E' ? '?' : c);
        return new string(chars.ToArray());
    }

    // ----- trust policy -----

    [Theory]
    [InlineData("mx.example.org; spf=pass", true)]
    [InlineData("MX.Example.ORG.; spf=pass", true)]
    [InlineData("\"mx.example.org\"; spf=pass", true)]
    [InlineData("other.net; spf=pass", false)]
    [InlineData("mx.example.org.evil.net; spf=pass", false)]
    [InlineData("garbage", false)]
    [InlineData("", true)]
    public void Ingress_policy_removes_own_and_unparseable_headers(string body, bool remove)
    {
        string[] own = ["mx.example.org", "other-id.example.org"];
        Assert.Equal(remove, AuthenticationResultsPolicy.ShouldRemoveOnIngress(body, own));
    }

    [Fact]
    public void Ingress_policy_matches_any_own_id()
    {
        Assert.True(AuthenticationResultsPolicy.ShouldRemoveOnIngress("other-id.example.org; none", ["mx.example.org", "other-id.example.org"]));
        Assert.True(AuthenticationResultsPolicy.ShouldRemoveOnIngress(null, ["mx.example.org"]));
    }

    [Fact]
    public void Trusted_selection_ignores_foreign_and_broken_headers()
    {
        string[] bodies =
        [
            "mx.example.org; spf=pass smtp.mailfrom=a@example.com",
            "evil.net; dkim=pass header.d=bank.com",
            "mx.example.org; broken",
            "MX.example.org; dkim=pass header.d=example.com",
        ];
        var trusted = AuthenticationResultsPolicy.SelectTrusted(bodies, ["mx.example.org"]);
        Assert.Equal(2, trusted.Count);
        Assert.All(trusted, h => Assert.Equal("mx.example.org", h.AuthservId.ToLowerInvariant()));
        Assert.Empty(AuthenticationResultsPolicy.SelectTrusted(bodies, []));
    }
}
