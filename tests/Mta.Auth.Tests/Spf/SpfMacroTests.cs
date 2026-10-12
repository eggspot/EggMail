using System.Net;
using Mta.Auth.Spf;

namespace Mta.Auth.Tests.Spf;

public class SpfMacroTests
{
    private static SpfMacroContext Rfc(string ip = "192.0.2.3") =>
        new("strong-bad@email.example.com", "email.example.com", IPAddress.Parse(ip), "mx.example.org")
        {
            ReceivingHostName = "mx.receiver.test",
            Timestamp = DateTimeOffset.FromUnixTimeSeconds(1234567890),
        };

    private static string Expand(string text, SpfMacroKind kind, SpfMacroContext ctx)
    {
        Assert.True(SpfMacroString.TryParse(text, kind, out var macro, out string? error), error);
        Assert.True(macro.TryExpand(ctx, 4096, out string? result));
        return result;
    }

    // RFC 7208 section 7.4 examples (sender strong-bad@email.example.com, client 192.0.2.3).
    [Theory]
    [InlineData("%{s}", "strong-bad@email.example.com")]
    [InlineData("%{o}", "email.example.com")]
    [InlineData("%{d}", "email.example.com")]
    [InlineData("%{d4}", "email.example.com")]
    [InlineData("%{d3}", "email.example.com")]
    [InlineData("%{d2}", "example.com")]
    [InlineData("%{d1}", "com")]
    [InlineData("%{dr}", "com.example.email")]
    [InlineData("%{d2r}", "example.email")]
    [InlineData("%{l}", "strong-bad")]
    [InlineData("%{l-}", "strong.bad")]
    [InlineData("%{lr}", "strong-bad")]
    [InlineData("%{lr-}", "bad.strong")]
    [InlineData("%{l1r-}", "strong")]
    public void Rfc_examples(string macro, string expected) =>
        Assert.Equal(expected, Expand(macro, SpfMacroKind.Explanation, Rfc()));

    [Theory]
    [InlineData("%{ir}.%{v}._spf.%{d2}", "3.2.0.192.in-addr._spf.example.com")]
    [InlineData("%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com")]
    [InlineData("%{lr-}.lp.%{ir}.%{v}._spf.%{d2}", "bad.strong.lp.3.2.0.192.in-addr._spf.example.com")]
    [InlineData("%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}", "3.2.0.192.in-addr.strong.lp._spf.example.com")]
    [InlineData("%{d2}.trusted-domains.example.net", "example.com.trusted-domains.example.net")]
    public void Rfc_domain_spec_examples(string spec, string expected) =>
        Assert.Equal(expected, Expand(spec, SpfMacroKind.DomainSpec, Rfc()));

    [Fact]
    public void Ipv6_client_macros()
    {
        var ctx = Rfc("2001:db8::cb01");
        Assert.Equal("1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com",
            Expand("%{ir}.%{v}._spf.%{d2}", SpfMacroKind.DomainSpec, ctx));
        Assert.Equal("2001:db8::cb01", Expand("%{c}", SpfMacroKind.Explanation, ctx));
        Assert.Equal("ip6", Expand("%{v}", SpfMacroKind.Explanation, ctx));
    }

    [Fact]
    public void Ipv4_mapped_client_is_expanded_as_ipv4()
    {
        var ctx = Rfc("::ffff:192.0.2.3");
        Assert.Equal("192.0.2.3", Expand("%{i}", SpfMacroKind.Explanation, ctx));
        Assert.Equal("in-addr", Expand("%{v}", SpfMacroKind.Explanation, ctx));
    }

    [Fact]
    public void Remaining_letters()
    {
        var ctx = Rfc() with { ValidatedDomain = "mail.example.com" };
        Assert.Equal("mx.example.org", Expand("%{h}", SpfMacroKind.Explanation, ctx));
        Assert.Equal("mail.example.com", Expand("%{p}", SpfMacroKind.Explanation, ctx));
        Assert.Equal("mx.receiver.test", Expand("%{r}", SpfMacroKind.Explanation, ctx));
        Assert.Equal("1234567890", Expand("%{t}", SpfMacroKind.Explanation, ctx));
        Assert.Equal("192.0.2.3", Expand("%{c}", SpfMacroKind.Explanation, ctx));
        Assert.Equal("unknown", Expand("%{p}", SpfMacroKind.Explanation, Rfc()));
    }

    [Fact]
    public void Literal_escapes()
    {
        Assert.Equal("a%b c%20d", Expand("a%%b%_c%-d", SpfMacroKind.Explanation, Rfc()));
    }

    [Fact]
    public void Uppercase_letters_url_escape_the_value()
    {
        var ctx = new SpfMacroContext("a b/c@example.com", "example.com", IPAddress.Parse("192.0.2.3"), "h.example");
        Assert.Equal("a%20b%2Fc%40example.com", Expand("%{S}", SpfMacroKind.Explanation, ctx));
        Assert.Equal("a%20b%2Fc", Expand("%{L}", SpfMacroKind.Explanation, ctx));
        Assert.Equal("a b/c@example.com", Expand("%{s}", SpfMacroKind.Explanation, ctx));
    }

    [Fact]
    public void Unreserved_characters_are_not_escaped_and_utf8_is()
    {
        var ctx = new SpfMacroContext("a-b.c_d~eé@example.com", "example.com", IPAddress.Parse("192.0.2.3"), "h");
        Assert.Equal("a-b.c_d~e%C3%A9", Expand("%{L}", SpfMacroKind.Explanation, ctx));
    }

    [Fact]
    public void Empty_local_part_becomes_postmaster()
    {
        var ctx = new SpfMacroContext("@example.com", "example.com", IPAddress.Loopback, "h");
        Assert.Equal("postmaster", ctx.LocalPart);
        Assert.Equal("postmaster@example.com", ctx.Sender);
        var none = new SpfMacroContext("example.com", "example.com", IPAddress.Loopback, "h");
        Assert.Equal("postmaster", none.LocalPart);
        Assert.Equal("example.com", none.SenderDomain);
    }

    [Fact]
    public void Multiple_delimiters_split_on_any_of_them()
    {
        var ctx = new SpfMacroContext("a+b-c.d@example.com", "example.com", IPAddress.Loopback, "h");
        Assert.Equal("a.b.c.d", Expand("%{l+-.}", SpfMacroKind.Explanation, ctx));
        Assert.Equal("d.c.b.a", Expand("%{lr+-.}", SpfMacroKind.Explanation, ctx));
        Assert.Equal("c.d", Expand("%{l2+-.}", SpfMacroKind.Explanation, ctx));
    }

    [Fact]
    public void Digit_count_larger_than_parts_keeps_everything()
    {
        Assert.Equal("email.example.com", Expand("%{d99}", SpfMacroKind.Explanation, Rfc()));
        Assert.Equal("email.example.com", Expand("%{d99999999999}", SpfMacroKind.Explanation, Rfc()));
    }

    [Theory]
    [InlineData("%")]
    [InlineData("%x")]
    [InlineData("%{")]
    [InlineData("%{}")]
    [InlineData("%{d")]
    [InlineData("%{x}")]
    [InlineData("%{d0}")]
    [InlineData("%{d.r}")]
    [InlineData("%{rd}")]
    [InlineData("%{d!}")]
    [InlineData("a b")]
    [InlineData("é")]
    public void Malformed_macro_strings_are_rejected(string text)
    {
        Assert.False(SpfMacroString.TryParse(text, SpfMacroKind.ModifierValue, out var macro, out string? error));
        Assert.Null(macro);
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Theory]
    [InlineData("example.com")]
    [InlineData("example.com.")]
    [InlineData("%{d}")]
    [InlineData("_spf.%{d}")]
    [InlineData("%{d2}.example.com")]
    [InlineData("a.b-c.com")]
    [InlineData("x.1-2")]
    [InlineData("host.%{d}%%")]
    public void Valid_domain_specs(string text) =>
        Assert.True(SpfMacroString.TryParseDomainSpec(text, out _, out _));

    [Theory]
    [InlineData("")]
    [InlineData("com")]
    [InlineData("example.123")]
    [InlineData("example.-com")]
    [InlineData("example.com-")]
    [InlineData("example.c_m")]
    [InlineData("%{c}.example.com")]
    [InlineData("%{r}.example.com")]
    [InlineData("%{t}.example.com")]
    [InlineData("exa mple.com")]
    public void Invalid_domain_specs(string text) =>
        Assert.False(SpfMacroString.TryParseDomainSpec(text, out _, out _));

    [Fact]
    public void Explanation_macros_are_allowed_in_explanations_only()
    {
        Assert.True(SpfMacroString.TryParse("%{c} %{r} %{t}", SpfMacroKind.Explanation, out var macro, out _));
        Assert.True(macro.UsesExplanationOnlyMacros);
        Assert.False(SpfMacroString.TryParse("%{c}", SpfMacroKind.ModifierValue, out _, out _));
    }

    [Fact]
    public void Flags_describe_the_content()
    {
        Assert.True(SpfMacroString.TryParse("%{p}.example.com", SpfMacroKind.DomainSpec, out var withP, out _));
        Assert.True(withP.UsesValidatedDomainName);
        Assert.False(withP.IsLiteral);
        Assert.True(SpfMacroString.TryParse("example.com", SpfMacroKind.DomainSpec, out var literal, out _));
        Assert.True(literal.IsLiteral);
        Assert.False(literal.UsesValidatedDomainName);
        Assert.Equal("example.com", literal.ToString());
    }

    [Fact]
    public void Expansion_larger_than_the_limit_fails()
    {
        Assert.True(SpfMacroString.TryParse(string.Concat(Enumerable.Repeat("%{s}", 100)), SpfMacroKind.Explanation, out var macro, out _));
        Assert.False(macro.TryExpand(Rfc(), 1000, out _));
        Assert.True(macro.TryExpand(Rfc(), 100_000, out _));
    }

    [Fact]
    public void Expanded_domain_is_truncated_from_the_left_to_253_characters()
    {
        string name = string.Join('.', Enumerable.Repeat("abcdefghi", 30)) + ".org";
        Assert.True(SpfDomainName.TryNormalizeExpanded(name, out string? domain));
        Assert.True(domain.Length <= 253);
        Assert.EndsWith(".org", domain);
        Assert.StartsWith("abcdefghi.", domain);
    }

    [Theory]
    [InlineData("a..b.com")]
    [InlineData(".")]
    [InlineData("")]
    [InlineData("a b.com")]
    [InlineData("café.com")]
    public void Expanded_domain_with_bad_labels_is_rejected(string name) =>
        Assert.False(SpfDomainName.TryNormalizeExpanded(name, out _));

    [Fact]
    public void Single_label_longer_than_253_is_rejected()
    {
        Assert.False(SpfDomainName.TryNormalizeExpanded(new string('a', 300), out _));
        Assert.False(SpfDomainName.TryNormalizeExpanded(new string('a', 64) + ".com", out _));
    }

    [Fact]
    public void Expanded_domain_is_lower_cased_and_loses_one_trailing_dot()
    {
        Assert.True(SpfDomainName.TryNormalizeExpanded("Mail.Example.COM.", out string? domain));
        Assert.Equal("mail.example.com", domain);
    }
}
