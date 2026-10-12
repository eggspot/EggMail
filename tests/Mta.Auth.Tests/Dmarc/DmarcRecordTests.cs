using Mta.Auth.Dmarc;

namespace Mta.Auth.Tests.Dmarc;

public class DmarcRecordTests
{
    private static DmarcRecord Parse(string text)
    {
        Assert.True(DmarcRecord.TryParse(text, out var record, out string? error), error);
        return record;
    }

    [Fact]
    public void Full_record()
    {
        var r = Parse("v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=s; pct=25; rua=mailto:agg@example.com; ruf=mailto:fail@example.com; fo=1:d; rf=afrf; ri=3600");
        Assert.Equal(DmarcPolicy.Reject, r.Policy);
        Assert.Equal(DmarcPolicy.Quarantine, r.SubdomainPolicy);
        Assert.Equal(DmarcAlignmentMode.Strict, r.DkimAlignment);
        Assert.Equal(DmarcAlignmentMode.Strict, r.SpfAlignment);
        Assert.Equal(25, r.Percentage);
        Assert.Equal("agg@example.com", Assert.Single(r.AggregateReportUris).MailAddress);
        Assert.Equal("fail@example.com", Assert.Single(r.FailureReportUris).MailAddress);
        Assert.Equal("1:d", r.FailureReportingOptions);
        Assert.Equal("afrf", r.FailureReportFormat);
        Assert.Equal(3600, r.AggregateReportIntervalSeconds);
        Assert.False(r.IsMonitoringFallback);
    }

    [Fact]
    public void Defaults()
    {
        var r = Parse("v=DMARC1; p=none");
        Assert.Equal(DmarcPolicy.None, r.Policy);
        Assert.Null(r.SubdomainPolicy);
        Assert.Equal(DmarcAlignmentMode.Relaxed, r.DkimAlignment);
        Assert.Equal(DmarcAlignmentMode.Relaxed, r.SpfAlignment);
        Assert.Equal(100, r.Percentage);
        Assert.Empty(r.AggregateReportUris);
        Assert.Empty(r.FailureReportUris);
        Assert.Equal("0", r.FailureReportingOptions);
        Assert.Equal("afrf", r.FailureReportFormat);
        Assert.Equal(86400, r.AggregateReportIntervalSeconds);
    }

    [Theory]
    [InlineData("v=DMARC1;p=reject")]
    [InlineData("v=DMARC1; p=reject;")]
    [InlineData("v=DMARC1;;; p=reject ;;")]
    [InlineData("  v = DMARC1 ;  p = reject  ")]
    [InlineData("v=DMARC1 ; p=reject")]
    [InlineData("\tv=DMARC1;\tp=reject")]
    [InlineData("V=dmarc1; P=REJECT")]
    [InlineData("v=DMARC1; foo; p=reject")]
    [InlineData("v=DMARC1; unknown=tag; p=reject; x-ext=1")]
    [InlineData("v=DMARC1; p=reject; p=none")]
    public void Tolerant_of_whitespace_case_and_unknown_tags(string text) =>
        Assert.Equal(DmarcPolicy.Reject, Parse(text).Policy);

    [Fact]
    public void P_does_not_have_to_be_the_second_tag()
    {
        Assert.Equal(DmarcPolicy.Quarantine, Parse("v=DMARC1; rua=mailto:a@example.com; p=quarantine").Policy);
    }

    [Theory]
    [InlineData("v=DMARC10; p=none")]
    [InlineData("v=DMARC2; p=none")]
    [InlineData("p=none; v=DMARC1")]
    [InlineData("v=spf1 -all")]
    [InlineData("")]
    [InlineData("DMARC1; p=none")]
    public void Records_without_a_leading_version_tag_are_not_dmarc(string text)
    {
        Assert.False(DmarcRecord.HasVersionTag(text));
        Assert.False(DmarcRecord.TryParse(text, out _, out string? error));
        Assert.NotNull(error);
    }

    [Theory]
    [InlineData("v=DMARC1")]
    [InlineData("v=DMARC1; sp=reject")]
    [InlineData("v=DMARC1; p=banana")]
    [InlineData("v=DMARC1; p=")]
    [InlineData("v=DMARC1; pct=50")]
    [InlineData("v=DMARC1; p=reject; sp=banana")]
    public void Missing_or_invalid_policy_without_a_report_address_is_rejected(string text)
    {
        Assert.False(DmarcRecord.TryParse(text, out var record, out string? error));
        Assert.Null(record);
        Assert.NotNull(error);
    }

    [Theory]
    [InlineData("v=DMARC1; rua=mailto:a@example.com")]
    [InlineData("v=DMARC1; p=banana; rua=mailto:a@example.com")]
    [InlineData("v=DMARC1; p=reject; sp=banana; rua=mailto:a@example.com")]
    public void Missing_or_invalid_policy_with_a_valid_rua_means_monitoring(string text)
    {
        var r = Parse(text);
        Assert.Equal(DmarcPolicy.None, r.Policy);
        Assert.Null(r.SubdomainPolicy);
        Assert.True(r.IsMonitoringFallback);
    }

    [Fact]
    public void Rua_without_any_valid_uri_does_not_rescue()
    {
        Assert.False(DmarcRecord.TryParse("v=DMARC1; rua=not a uri,,mailto:", out _, out _));
    }

    [Theory]
    [InlineData("pct=0", 0)]
    [InlineData("pct=1", 1)]
    [InlineData("pct=100", 100)]
    [InlineData("pct = 50", 50)]
    [InlineData("pct=101", 100)]
    [InlineData("pct=-5", 100)]
    [InlineData("pct=50%", 100)]
    [InlineData("pct=abc", 100)]
    [InlineData("pct=", 100)]
    [InlineData("pct=99999", 100)]
    public void Pct_falls_back_to_100_when_invalid(string tag, int expected) =>
        Assert.Equal(expected, Parse("v=DMARC1; p=reject; " + tag).Percentage);

    [Theory]
    [InlineData("adkim=r", DmarcAlignmentMode.Relaxed)]
    [InlineData("adkim=s", DmarcAlignmentMode.Strict)]
    [InlineData("adkim=S", DmarcAlignmentMode.Strict)]
    [InlineData("adkim=x", DmarcAlignmentMode.Relaxed)]
    [InlineData("adkim=", DmarcAlignmentMode.Relaxed)]
    public void Dkim_alignment_tag(string tag, DmarcAlignmentMode expected) =>
        Assert.Equal(expected, Parse("v=DMARC1; p=none; " + tag).DkimAlignment);

    [Theory]
    [InlineData("aspf=r", DmarcAlignmentMode.Relaxed)]
    [InlineData("aspf=s", DmarcAlignmentMode.Strict)]
    [InlineData("aspf=strict", DmarcAlignmentMode.Relaxed)]
    public void Spf_alignment_tag(string tag, DmarcAlignmentMode expected) =>
        Assert.Equal(expected, Parse("v=DMARC1; p=none; " + tag).SpfAlignment);

    [Theory]
    [InlineData("fo=0", "0")]
    [InlineData("fo=1", "1")]
    [InlineData("fo=0:1:d:s", "0:1:d:s")]
    [InlineData("fo=d:s", "d:s")]
    [InlineData("fo=x", "0")]
    [InlineData("fo=1:x:s:1", "1:s")]
    [InlineData("fo=", "0")]
    public void Failure_options(string tag, string expected) =>
        Assert.Equal(expected, Parse("v=DMARC1; p=none; " + tag).FailureReportingOptions);

    [Theory]
    [InlineData("ri=3600", 3600)]
    [InlineData("ri=0", 86400)]
    [InlineData("ri=-1", 86400)]
    [InlineData("ri=abc", 86400)]
    [InlineData("ri=99999999999", 99999999999)]
    public void Report_interval(string tag, long expected) =>
        Assert.Equal(expected, Parse("v=DMARC1; p=none; " + tag).AggregateReportIntervalSeconds);

    [Fact]
    public void Several_report_uris_with_sizes_and_garbage()
    {
        var r = Parse("v=DMARC1; p=none; rua=mailto:a@example.com!10m, mailto:b@example.net!500k ,garbage, https://example.org/r, mailto:bad@@x, mailto:c@example.org");
        Assert.Equal(4, r.AggregateReportUris.Count);
        Assert.Equal(10L * 1024 * 1024, r.AggregateReportUris[0].MaxSizeBytes);
        Assert.Equal(500L * 1024, r.AggregateReportUris[1].MaxSizeBytes);
        Assert.False(r.AggregateReportUris[2].IsMailTo);
        Assert.Equal("https://example.org/r", r.AggregateReportUris[2].Uri);
        Assert.Equal("c@example.org", r.AggregateReportUris[3].MailAddress);
        Assert.Null(r.AggregateReportUris[3].MaxSizeBytes);
    }

    [Theory]
    [InlineData("mailto:a@example.com", "a@example.com", null)]
    [InlineData("MAILTO:a@example.com", "a@example.com", null)]
    [InlineData("mailto:a@example.com!100", "a@example.com", 100L)]
    [InlineData("mailto:a@example.com!10k", "a@example.com", 10L * 1024)]
    [InlineData("mailto:a@example.com!10K", "a@example.com", 10L * 1024)]
    [InlineData("mailto:a@example.com!2g", "a@example.com", 2L * 1024 * 1024 * 1024)]
    [InlineData("mailto:a@example.com!1t", "a@example.com", 1L << 40)]
    [InlineData("mailto:a@example.com?subject=Reports", "a@example.com", null)]
    [InlineData("mailto:a%2Bb@example.com", "a+b@example.com", null)]
    [InlineData("mailto:a@example.com!999999999999999t", "a@example.com", long.MaxValue)]
    public void Report_uri_parsing(string text, string address, long? max)
    {
        Assert.True(DmarcReportUri.TryParse(text, out var uri));
        Assert.Equal(address, uri.MailAddress);
        Assert.Equal(max, uri.MaxSizeBytes);
        Assert.True(uri.IsMailTo);
        Assert.Equal(address[(address.IndexOf('@') + 1)..], uri.MailDomain);
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData("a@example.com")]
    [InlineData("mailto:")]
    [InlineData("mailto:nodomain")]
    [InlineData("mailto:a@example.com!")]
    [InlineData("mailto:a@example.com!x")]
    [InlineData(":foo")]
    [InlineData("1x:foo")]
    [InlineData("ht tp://x")]
    [InlineData("https:")]
    public void Invalid_report_uris(string text) => Assert.False(DmarcReportUri.TryParse(text, out _));

    [Fact]
    public void Duplicate_known_tags_keep_the_first()
    {
        var r = Parse("v=DMARC1; p=quarantine; p=reject; pct=10; pct=90; adkim=s; adkim=r");
        Assert.Equal(DmarcPolicy.Quarantine, r.Policy);
        Assert.Equal(10, r.Percentage);
        Assert.Equal(DmarcAlignmentMode.Strict, r.DkimAlignment);
    }

    [Fact]
    public void Record_longer_than_limit_is_rejected()
    {
        string text = "v=DMARC1; p=none; rua=mailto:a@example.com; x=" + new string('a', 5000);
        Assert.False(DmarcRecord.TryParse(text, out _, out string? error));
        Assert.Contains("too long", error);
        Assert.True(DmarcRecord.TryParse(text, 10_000, out _, out _));
    }

    [Fact]
    public void Too_many_tags_are_rejected()
    {
        string text = "v=DMARC1; p=none; " + string.Join("; ", Enumerable.Range(0, 100).Select(i => $"x{i}=1"));
        Assert.False(DmarcRecord.TryParse(text, out _, out _));
    }

    [Fact]
    public void Report_uri_list_is_bounded()
    {
        string list = string.Join(',', Enumerable.Range(0, 100).Select(i => $"mailto:u{i}@example.com"));
        Assert.Equal(32, Parse("v=DMARC1; p=none; rua=" + list).AggregateReportUris.Count);
    }

    [Fact]
    public void Text_is_preserved()
    {
        const string text = "v=DMARC1; p=none";
        Assert.Equal(text, Parse(text).Text);
    }
}
