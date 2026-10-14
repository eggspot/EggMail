using System.IO.Compression;
using System.Text;
using Mta.Auth.Dmarc;
using Mta.Auth.Reports;
using Mta.Auth.Spf;
using static Mta.Auth.Tests.Reports.ReportTestSupport;

namespace Mta.Auth.Tests.Reports;

public class DmarcAggregateReportReaderTests
{
    private static void AssertSameReport(DmarcAggregateReport expected, DmarcAggregateReport actual)
    {
        Assert.Equal(expected.Metadata with { Errors = null }, actual.Metadata with { Errors = null });
        Assert.Equal(expected.Metadata.Errors ?? [], actual.Metadata.Errors);
        Assert.Equal(expected.PolicyPublished, actual.PolicyPublished);
        Assert.Equal(expected.Records.Count, actual.Records.Count);
        for (int i = 0; i < expected.Records.Count; i++)
        {
            var e = expected.Records[i];
            var a = actual.Records[i];
            Assert.Equal(e with { Reasons = [], DkimResults = [], SpfResults = [] }, a with { Reasons = [], DkimResults = [], SpfResults = [] });
            Assert.Equal(e.Reasons, a.Reasons);
            Assert.Equal(e.DkimResults, a.DkimResults);
            Assert.Equal(e.SpfResults, a.SpfResults);
        }
    }

    [Fact]
    public void Xml_round_trip()
    {
        var report = SampleReport(4);
        byte[] xml = Encoding.UTF8.GetBytes(DmarcAggregateReportWriter.ToXmlString(report));
        Assert.True(DmarcAggregateReportReader.TryRead(xml, out var parsed));
        AssertSameReport(report, parsed);
    }

    [Fact]
    public void Gzip_round_trip()
    {
        var report = SampleReport(4);
        Assert.True(DmarcAggregateReportReader.TryRead(DmarcAggregateReportWriter.ToGzip(report), out var parsed));
        AssertSameReport(report, parsed);
    }

    [Fact]
    public void Round_trip_of_extra_fields_and_errors()
    {
        var report = SampleReport(1);
        report = report with { Metadata = report.Metadata with { Errors = ["e1", "e2"] } };
        Assert.True(DmarcAggregateReportReader.TryRead(DmarcAggregateReportWriter.ToGzip(report), out var parsed));
        Assert.Equal(["e1", "e2"], parsed.Metadata.Errors);
        Assert.Equal("https://receiver.example/dmarc", parsed.Metadata.ExtraContactInfo);
    }

    [Fact]
    public void Real_world_style_report_with_namespace_and_missing_optionals()
    {
        const string xml = """
            <?xml version="1.0" encoding="UTF-8" ?>
            <feedback xmlns="http://dmarc.org/dmarc-xml/0.1">
              <report_metadata>
                <org_name>google.com</org_name>
                <email>noreply-dmarc-support@google.com</email>
                <report_id>1234567890</report_id>
                <date_range><begin>1700000000</begin><end>1700086399</end></date_range>
              </report_metadata>
              <policy_published>
                <domain>example.com</domain>
                <p>quarantine</p>
                <pct>100</pct>
              </policy_published>
              <record>
                <row>
                  <source_ip>2001:db8::1</source_ip>
                  <count>7</count>
                  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results>
                  <dkim><domain>example.com</domain><result>pass</result><selector>s1</selector></dkim>
                  <spf><domain>example.com</domain><result>fail</result></spf>
                  <unknown>ignored</unknown>
                </auth_results>
              </record>
            </feedback>
            """;
        Assert.True(DmarcAggregateReportReader.TryRead(Encoding.UTF8.GetBytes(xml), out var report));
        Assert.Equal("google.com", report.Metadata.OrganizationName);
        Assert.Equal(DmarcPolicy.Quarantine, report.PolicyPublished.Policy);
        Assert.Equal(DmarcPolicy.Quarantine, report.PolicyPublished.SubdomainPolicy);
        var row = Assert.Single(report.Records);
        Assert.Equal("2001:db8::1", row.SourceIp);
        Assert.Equal(7, row.Count);
        Assert.True(row.DkimAligned);
        Assert.False(row.SpfAligned);
        Assert.Equal("s1", Assert.Single(row.DkimResults).Selector);
        Assert.Equal(SpfResult.Fail, Assert.Single(row.SpfResults).Result);
        Assert.Equal(string.Empty, row.EnvelopeFrom);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not xml")]
    [InlineData("<feedback/>")]
    [InlineData("<other><report_metadata/></other>")]
    [InlineData("<feedback><report_metadata><date_range><begin>x</begin><end>y</end></date_range></report_metadata><policy_published/></feedback>")]
    [InlineData("<feedback><report_metadata><date_range><begin>1</begin><end>2</end></date_range></report_metadata><policy_published/><record/></feedback>")]
    [InlineData("<feedback><report_metadata><date_range><begin>99999999999999</begin><end>2</end></date_range></report_metadata><policy_published/></feedback>")]
    public void Malformed_reports_are_rejected(string xml) =>
        Assert.False(DmarcAggregateReportReader.TryRead(Encoding.UTF8.GetBytes(xml), out _));

    [Fact]
    public void Dtd_and_external_entities_are_refused()
    {
        const string xxe = """
            <?xml version="1.0"?>
            <!DOCTYPE feedback [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <feedback><report_metadata><org_name>&xxe;</org_name></report_metadata></feedback>
            """;
        Assert.False(DmarcAggregateReportReader.TryRead(Encoding.UTF8.GetBytes(xxe), out _));
        const string bomb = """
            <?xml version="1.0"?>
            <!DOCTYPE lolz [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
            <lolz>&b;&b;&b;</lolz>
            """;
        Assert.False(DmarcAggregateReportReader.TryRead(Encoding.UTF8.GetBytes(bomb), out _));
    }

    [Fact]
    public void Truncated_and_corrupt_gzip_is_rejected()
    {
        byte[] gz = DmarcAggregateReportWriter.ToGzip(SampleReport(50));
        Assert.False(DmarcAggregateReportReader.TryRead(gz[..(gz.Length / 2)], out _));
        byte[] corrupt = (byte[])gz.Clone();
        corrupt[corrupt.Length / 2] ^= 0xFF;
        Assert.False(DmarcAggregateReportReader.TryRead(corrupt, out _));
        Assert.False(DmarcAggregateReportReader.TryRead([0x1F, 0x8B], out _));
    }

    [Fact]
    public void Decompression_bomb_is_refused()
    {
        using var ms = new MemoryStream();
        using (var gzip = new GZipStream(ms, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            gzip.Write(Encoding.UTF8.GetBytes("<feedback>"));
            byte[] block = new byte[1024 * 1024];
            Array.Fill(block, (byte)' ');
            for (int i = 0; i < DmarcAggregateReportReader.MaxDocumentBytes / block.Length + 2; i++)
            {
                gzip.Write(block);
            }

            gzip.Write(Encoding.UTF8.GetBytes("</feedback>"));
        }

        Assert.True(ms.Length < 1024 * 1024);
        Assert.False(DmarcAggregateReportReader.TryRead(ms.ToArray(), out _));
    }

    [Fact]
    public void Null_arguments_throw_argument_exceptions()
    {
        Assert.Throws<ArgumentNullException>(() => DmarcAggregateReportReader.TryRead((Stream)null!, out _));
        Assert.Throws<ArgumentNullException>(() => DmarcAggregateReportReader.TryRead((byte[])null!, out _));
    }

    [Fact]
    public async Task Deeply_nested_elements_are_refused_without_parsing_them()
    {
        // Found by the fuzzer: XmlReader has no depth limit and its time grows with the square of the depth (40,000 levels took about two
        // seconds, a document of a few megabytes would have taken hours). No timing is asserted: the depth check answers before the
        // document is loaded, and a hang guard turns a regression into a failure instead of a stuck test run.
        string nested = "<feedback><report_metadata>" + string.Concat(Enumerable.Repeat("<a>", 300_000)) + "x" + string.Concat(Enumerable.Repeat("</a>", 300_000)) + "</report_metadata></feedback>";
        bool parsed = await Task.Run(() => DmarcAggregateReportReader.TryRead(Encoding.UTF8.GetBytes(nested), out _)).WaitAsync(TimeSpan.FromMinutes(2));
        Assert.False(parsed);
    }

    [Fact]
    public void A_nesting_depth_within_the_limit_is_still_parsed()
    {
        string xml = "<feedback><report_metadata><org_name>o</org_name><email>e@x</email><report_id>1</report_id><date_range><begin>1</begin><end>2</end></date_range></report_metadata>"
            + "<policy_published><domain>example.com</domain><p>none</p></policy_published></feedback>";
        Assert.True(DmarcAggregateReportReader.TryRead(Encoding.UTF8.GetBytes(xml), out var report));
        Assert.Equal("example.com", report!.PolicyPublished.Domain);
    }
}
