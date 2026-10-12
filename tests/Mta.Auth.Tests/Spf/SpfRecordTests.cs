using System.Net;
using Mta.Auth.Spf;

namespace Mta.Auth.Tests.Spf;

public class SpfRecordTests
{
    private static SpfRecord Parse(string text)
    {
        Assert.True(SpfRecord.TryParse(text, 4096, out var record, out string? error), error);
        return record;
    }

    [Fact]
    public void Parses_every_mechanism_kind()
    {
        var r = Parse("v=spf1 all include:a.example a a:b.example mx mx:c.example/24//64 ptr ptr:d.example ip4:192.0.2.0/24 ip6:2001:db8::/32 exists:%{i}.e.example");
        Assert.Equal(
            [SpfMechanismKind.All, SpfMechanismKind.Include, SpfMechanismKind.A, SpfMechanismKind.A, SpfMechanismKind.Mx, SpfMechanismKind.Mx, SpfMechanismKind.Ptr, SpfMechanismKind.Ptr, SpfMechanismKind.Ip4, SpfMechanismKind.Ip6, SpfMechanismKind.Exists],
            r.Directives.Select(d => d.Mechanism.Kind));
        Assert.True(r.HasAllMechanism);
    }

    [Fact]
    public void Qualifiers_map_to_results()
    {
        var r = Parse("v=spf1 +a -a ~a ?a a");
        Assert.Equal([SpfQualifier.Pass, SpfQualifier.Fail, SpfQualifier.SoftFail, SpfQualifier.Neutral, SpfQualifier.Pass], r.Directives.Select(d => d.Qualifier));
        Assert.Equal([SpfResult.Pass, SpfResult.Fail, SpfResult.SoftFail, SpfResult.Neutral, SpfResult.Pass], r.Directives.Select(d => d.MatchResult));
    }

    [Fact]
    public void Dual_cidr_values_are_parsed()
    {
        var m = Parse("v=spf1 mx:c.example/24//64").Directives[0].Mechanism;
        Assert.Equal(24, m.Ip4Prefix);
        Assert.Equal(64, m.Ip6Prefix);
        Assert.Equal("c.example", m.Domain!.Source);
        var onlyV6 = Parse("v=spf1 a//48").Directives[0].Mechanism;
        Assert.Equal(32, onlyV6.Ip4Prefix);
        Assert.Equal(48, onlyV6.Ip6Prefix);
        Assert.Null(onlyV6.Domain);
        var onlyV4 = Parse("v=spf1 a/20").Directives[0].Mechanism;
        Assert.Equal(20, onlyV4.Ip4Prefix);
        Assert.Equal(128, onlyV4.Ip6Prefix);
    }

    [Fact]
    public void Ip_networks_are_parsed()
    {
        var m4 = Parse("v=spf1 ip4:192.0.2.0/24").Directives[0].Mechanism;
        Assert.Equal(IPAddress.Parse("192.0.2.0"), m4.Network);
        Assert.Equal(24, m4.Ip4Prefix);
        var m6 = Parse("v=spf1 ip6:2001:db8::1").Directives[0].Mechanism;
        Assert.Equal(IPAddress.Parse("2001:db8::1"), m6.Network);
        Assert.Equal(128, m6.Ip6Prefix);
    }

    [Fact]
    public void Modifiers_are_collected()
    {
        var r = Parse("v=spf1 a redirect=_spf.example.com exp=why.example.com custom=value other-mod=%{d}");
        Assert.Equal("_spf.example.com", r.Redirect!.Source);
        Assert.Equal("why.example.com", r.Explanation!.Source);
        Assert.Equal(["custom", "other-mod"], r.UnknownModifiers.Select(m => m.Name));
        Assert.Equal("%{d}", r.UnknownModifiers[1].Value);
        Assert.False(r.HasAllMechanism);
    }

    [Theory]
    [InlineData("v=spf1")]
    [InlineData("V=SPF1 -all")]
    [InlineData("v=spf1 ")]
    [InlineData("v=spf1 -all")]
    public void Recognises_spf_records(string text) => Assert.True(SpfRecord.IsSpfRecord(text));

    [Theory]
    [InlineData("")]
    [InlineData("v=spf2.0/pra")]
    [InlineData("v=spf10 -all")]
    [InlineData("v=spf1-all")]
    [InlineData("spf1 -all")]
    [InlineData(" v=spf1 -all")]
    public void Rejects_non_spf_records(string text)
    {
        Assert.False(SpfRecord.IsSpfRecord(text));
        Assert.False(SpfRecord.TryParse(text, 4096, out var record, out string? error));
        Assert.Null(record);
        Assert.NotNull(error);
    }

    [Fact]
    public void Null_text_is_rejected_without_throwing()
    {
        Assert.False(SpfRecord.IsSpfRecord(null));
        Assert.False(SpfRecord.TryParse(null, 4096, out _, out _));
    }

    [Theory]
    [InlineData("v=spf1 foo")]
    [InlineData("v=spf1 ip4")]
    [InlineData("v=spf1 ip4:1.2.3")]
    [InlineData("v=spf1 ip4:1.2.3.4/33")]
    [InlineData("v=spf1 ip4:1.2.3.4/+1")]
    [InlineData("v=spf1 ip4:1.2.3.4/ 24")]
    [InlineData("v=spf1 ip6:::g")]
    [InlineData("v=spf1 ip6:1.2.3.4")]
    [InlineData("v=spf1 a:")]
    [InlineData("v=spf1 a/33")]
    [InlineData("v=spf1 a//129")]
    [InlineData("v=spf1 a/24/64")]
    [InlineData("v=spf1 mx/")]
    [InlineData("v=spf1 ptr/24")]
    [InlineData("v=spf1 ptr:")]
    [InlineData("v=spf1 include")]
    [InlineData("v=spf1 include:")]
    [InlineData("v=spf1 include:nodot")]
    [InlineData("v=spf1 exists")]
    [InlineData("v=spf1 all:x")]
    [InlineData("v=spf1 all/24")]
    [InlineData("v=spf1 redirect=a.example redirect=b.example")]
    [InlineData("v=spf1 exp=a.example exp=b.example")]
    [InlineData("v=spf1 redirect=")]
    [InlineData("v=spf1 exp=%{c}.example.com")]
    [InlineData("v=spf1 foo=%")]
    [InlineData("v=spf1 foo=%{")]
    [InlineData("v=spf1 =bar")]
    [InlineData("v=spf1 -")]
    [InlineData("v=spf1 +")]
    [InlineData("v=spf1 1a")]
    public void Syntax_errors_are_reported(string text)
    {
        Assert.False(SpfRecord.TryParse(text, 4096, out var record, out string? error));
        Assert.Null(record);
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Fact]
    public void Length_limit_is_enforced()
    {
        string text = "v=spf1 " + string.Join(' ', Enumerable.Repeat("ip4:10.0.0.1", 50));
        Assert.True(SpfRecord.TryParse(text, text.Length, out _, out _));
        Assert.False(SpfRecord.TryParse(text, text.Length - 1, out _, out string? error));
        Assert.Contains("too long", error);
    }

    [Fact]
    public void Error_messages_stay_short_for_hostile_mechanism_names()
    {
        Assert.False(SpfRecord.TryParse("v=spf1 " + new string('x', 3000), 4096, out _, out string? error));
        Assert.True(error.Length < 100);
    }
}
