using System.Text.RegularExpressions;
using Mta.Auth.Domains;

namespace Mta.Auth.Tests.Domains;

public class PublicSuffixListTests
{
    private static readonly PublicSuffixList Psl = PublicSuffixList.Default;

    [Fact]
    public void Embedded_list_loads_and_reports_its_date()
    {
        Assert.NotNull(Psl.Version);
        Assert.Matches(new Regex(@"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_UTC$"), Psl.Version);
        Assert.True(Psl.RuleCount > 8000, "rule count " + Psl.RuleCount);
    }

    [Fact]
    public void Embedded_list_keeps_the_mpl_header_and_both_sections()
    {
        using var stream = typeof(PublicSuffixList).Assembly.GetManifestResourceStream("Mta.Auth.public_suffix_list.dat")!;
        using var reader = new StreamReader(stream);
        string text = reader.ReadToEnd();
        Assert.Contains("Mozilla Public", text);
        Assert.Contains("https://mozilla.org/MPL/2.0/", text);
        Assert.Contains("===BEGIN ICANN DOMAINS===", text);
        Assert.Contains("===END ICANN DOMAINS===", text);
        Assert.Contains("===BEGIN PRIVATE DOMAINS===", text);
        Assert.Contains("===END PRIVATE DOMAINS===", text);
    }

    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("www.example.com", "example.com")]
    [InlineData("a.b.c.example.com", "example.com")]
    [InlineData("EXAMPLE.COM", "example.com")]
    [InlineData("www.Example.Com.", "example.com")]
    [InlineData("example.co.uk", "example.co.uk")]
    [InlineData("www.example.co.uk", "example.co.uk")]
    [InlineData("mail.eu.example.co.uk", "example.co.uk")]
    [InlineData("example.com.cn", "example.com.cn")]
    [InlineData("deep.sub.example.com.cn", "example.com.cn")]
    [InlineData("example.de", "example.de")]
    [InlineData("foo.example.jp", "example.jp")]
    [InlineData("example.invalidtld", "example.invalidtld")]
    [InlineData("a.b.example.invalidtld", "example.invalidtld")]
    public void Organizational_domain_of_ordinary_names(string input, string expected) =>
        Assert.Equal(expected, Psl.GetOrganizationalDomain(input));

    [Theory]
    [InlineData("com", "com")]
    [InlineData("co.uk", "co.uk")]
    [InlineData("com.cn", "com.cn")]
    [InlineData("uk", "uk")]
    public void A_public_suffix_is_its_own_organizational_domain(string input, string expected)
    {
        Assert.Equal(expected, Psl.GetOrganizationalDomain(input));
        Assert.True(Psl.IsPublicSuffix(input));
    }

    [Theory]
    [InlineData("a.b.ck", "a.b.ck")]
    [InlineData("x.a.b.ck", "a.b.ck")]
    [InlineData("b.ck", "b.ck")]
    [InlineData("www.ck", "www.ck")]
    [InlineData("sub.www.ck", "www.ck")]
    [InlineData("a.x.kobe.jp", "a.x.kobe.jp")]
    [InlineData("b.a.x.kobe.jp", "a.x.kobe.jp")]
    [InlineData("city.kobe.jp", "city.kobe.jp")]
    [InlineData("mail.city.kobe.jp", "city.kobe.jp")]
    public void Wildcard_and_exception_rules(string input, string expected) =>
        Assert.Equal(expected, Psl.GetOrganizationalDomain(input));

    [Fact]
    public void Wildcard_suffix_and_exception_suffix_are_reported()
    {
        Assert.Equal("b.ck", Psl.GetPublicSuffix("a.b.ck"));
        Assert.Equal("ck", Psl.GetPublicSuffix("www.ck"));
        Assert.Equal("ck", Psl.GetPublicSuffix("sub.www.ck"));
        Assert.Equal("kobe.jp", Psl.GetPublicSuffix("city.kobe.jp"));
        Assert.True(Psl.IsPublicSuffix("x.kobe.jp"));
        Assert.False(Psl.IsPublicSuffix("www.ck"));
    }

    [Theory]
    [InlineData("foo.github.io", "foo.github.io")]
    [InlineData("bar.foo.github.io", "foo.github.io")]
    [InlineData("github.io", "github.io")]
    [InlineData("mine.blogspot.com", "mine.blogspot.com")]
    [InlineData("x.mine.blogspot.com", "mine.blogspot.com")]
    [InlineData("app.appspot.com", "app.appspot.com")]
    public void Private_section_rules_are_included_by_default(string input, string expected) =>
        Assert.Equal(expected, Psl.GetOrganizationalDomain(input));

    [Fact]
    public void Private_section_can_be_excluded()
    {
        string text = System.Text.Encoding.UTF8.GetString(ReadEmbedded());
        var icannOnly = PublicSuffixList.Parse(text, includePrivateDomains: false);
        Assert.Equal("github.io", icannOnly.GetOrganizationalDomain("foo.github.io"));
        Assert.Equal("co.uk", icannOnly.GetPublicSuffix("a.co.uk"));
        Assert.True(icannOnly.RuleCount < Psl.RuleCount);
    }

    [Theory]
    [InlineData("www.食狮.com.cn", "xn--85x722f.com.cn")]
    [InlineData("bücher.de", "xn--bcher-kva.de")]
    [InlineData("www.xn--85x722f.com.cn", "xn--85x722f.com.cn")]
    public void Internationalized_names_are_compared_in_a_label_form(string input, string expected) =>
        Assert.Equal(expected, Psl.GetOrganizationalDomain(input));

    [Theory]
    [InlineData("", "")]
    [InlineData("   ", "")]
    [InlineData("..", ".")]
    [InlineData("A..B.com", "a..b.com")]
    public void Unusable_input_is_returned_lower_cased_without_throwing(string input, string expected)
    {
        Assert.Equal(expected, Psl.GetOrganizationalDomain(input));
        Assert.Null(Psl.GetPublicSuffix(input));
        Assert.False(Psl.IsPublicSuffix(input));
    }

    [Fact]
    public void Label_longer_than_63_characters_is_unusable()
    {
        string name = new string('a', 64) + ".example.com";
        Assert.Equal(name, Psl.GetOrganizationalDomain(name));
    }

    [Fact]
    public void Same_organizational_domain_comparison()
    {
        Assert.True(Psl.HaveSameOrganizationalDomain("mail.example.com", "www.example.com"));
        Assert.False(Psl.HaveSameOrganizationalDomain("example.com", "example.org"));
        Assert.False(Psl.HaveSameOrganizationalDomain("a.github.io", "b.github.io"));
        Assert.False(Psl.HaveSameOrganizationalDomain("a.co.uk", "b.co.uk"));
    }

    [Fact]
    public void Synthetic_list_semantics()
    {
        var list = PublicSuffixList.Parse("""
            // test list
            // ===BEGIN ICANN DOMAINS===
            test
            *.wild.test
            !keep.wild.test
            sub.example // trailing comment
            // ===END ICANN DOMAINS===
            // ===BEGIN PRIVATE DOMAINS===
            hosted.example
            // ===END PRIVATE DOMAINS===
            """);
        Assert.Equal(5, list.RuleCount);
        Assert.Equal("a.test", list.GetOrganizationalDomain("x.y.a.test"));
        Assert.Equal("a.wild.test", list.GetOrganizationalDomain("a.wild.test"));
        Assert.Equal("b.a.wild.test", list.GetOrganizationalDomain("c.b.a.wild.test"));
        Assert.Equal("keep.wild.test", list.GetOrganizationalDomain("z.keep.wild.test"));
        Assert.Equal("x.sub.example", list.GetOrganizationalDomain("y.x.sub.example"));
        Assert.Equal("me.hosted.example", list.GetOrganizationalDomain("www.me.hosted.example"));
        Assert.Equal("other.example", list.GetOrganizationalDomain("www.other.example")); // implicit * rule
    }

    private static byte[] ReadEmbedded()
    {
        using var stream = typeof(PublicSuffixList).Assembly.GetManifestResourceStream("Mta.Auth.public_suffix_list.dat")!;
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }
}
