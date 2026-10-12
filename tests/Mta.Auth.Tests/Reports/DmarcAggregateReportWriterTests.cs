using System.IO.Compression;
using System.Text;
using System.Xml;
using Mta.Auth.Dmarc;
using Mta.Auth.Reports;
using Mta.Auth.Spf;
using static Mta.Auth.Tests.Reports.ReportTestSupport;

namespace Mta.Auth.Tests.Reports;

public class DmarcAggregateReportWriterTests
{
    private static List<string> ElementPath(string xml)
    {
        var names = new List<string>();
        using var reader = XmlReader.Create(new StringReader(xml));
        var stack = new Stack<string>();
        while (reader.Read())
        {
            if (reader.NodeType == XmlNodeType.Element)
            {
                stack.Push(reader.LocalName);
                names.Add(string.Join('/', stack.Reverse()));
                if (reader.IsEmptyElement)
                {
                    stack.Pop();
                }
            }
            else if (reader.NodeType == XmlNodeType.EndElement)
            {
                stack.Pop();
            }
        }

        return names;
    }

    [Fact]
    public void Output_is_valid_against_the_rfc_schema()
    {
        string xml = DmarcAggregateReportWriter.ToXmlString(SampleReport(5));
        Assert.Empty(Validate(xml));
    }

    [Fact]
    public void Compact_output_is_valid_too()
    {
        string xml = DmarcAggregateReportWriter.ToXmlString(SampleReport(3), indent: false);
        Assert.Empty(Validate(xml));
        Assert.DoesNotContain("\n", xml);
    }

    [Fact]
    public void Element_order_matches_the_schema()
    {
        var sample = SampleReport(1);
        var report = sample with
        {
            Metadata = sample.Metadata with { Errors = ["first problem", "second problem"] },
            Records = [sample.Records[0] with { Reasons = [new DmarcPolicyOverrideReason(DmarcPolicyOverride.LocalPolicy, "note")] }],
        };
        string[] path = ElementPath(DmarcAggregateReportWriter.ToXmlString(report)).ToArray();
        string[] expectedPrefix =
        [
            "feedback", "feedback/version",
            "feedback/report_metadata", "feedback/report_metadata/org_name", "feedback/report_metadata/email",
            "feedback/report_metadata/extra_contact_info", "feedback/report_metadata/report_id",
            "feedback/report_metadata/date_range", "feedback/report_metadata/date_range/begin", "feedback/report_metadata/date_range/end",
            "feedback/report_metadata/error", "feedback/report_metadata/error",
            "feedback/policy_published", "feedback/policy_published/domain", "feedback/policy_published/adkim", "feedback/policy_published/aspf",
            "feedback/policy_published/p", "feedback/policy_published/sp", "feedback/policy_published/pct", "feedback/policy_published/fo",
            "feedback/record", "feedback/record/row", "feedback/record/row/source_ip", "feedback/record/row/count",
            "feedback/record/row/policy_evaluated", "feedback/record/row/policy_evaluated/disposition",
            "feedback/record/row/policy_evaluated/dkim", "feedback/record/row/policy_evaluated/spf",
        ];
        Assert.Equal(expectedPrefix, path.Take(expectedPrefix.Length));
        string[] tail = path.Skip(expectedPrefix.Length).ToArray();
        Assert.Equal("feedback/record/row/policy_evaluated/reason", tail[0]);
        Assert.Contains("feedback/record/identifiers/envelope_from", tail);
        Assert.True(Array.IndexOf(tail, "feedback/record/identifiers/envelope_from") < Array.IndexOf(tail, "feedback/record/identifiers/header_from"));
        Assert.True(Array.IndexOf(tail, "feedback/record/identifiers") < Array.IndexOf(tail, "feedback/record/auth_results"));
        Assert.True(Array.LastIndexOf(tail, "feedback/record/auth_results/dkim") < Array.IndexOf(tail, "feedback/record/auth_results/spf"));
    }

    [Fact]
    public void Values_are_serialised_as_the_schema_expects()
    {
        string xml = DmarcAggregateReportWriter.ToXmlString(SampleReport(1));
        var doc = System.Xml.Linq.XDocument.Parse(xml);
        string V(string path) => doc.Root!.XPathValue(path);
        Assert.Equal("1.0", V("version"));
        Assert.Equal("Receiver Inc", V("report_metadata/org_name"));
        Assert.Equal("1700000000", V("report_metadata/date_range/begin"));
        Assert.Equal("1700086399", V("report_metadata/date_range/end"));
        Assert.Equal("example.com", V("policy_published/domain"));
        Assert.Equal("r", V("policy_published/adkim"));
        Assert.Equal("s", V("policy_published/aspf"));
        Assert.Equal("reject", V("policy_published/p"));
        Assert.Equal("quarantine", V("policy_published/sp"));
        Assert.Equal("80", V("policy_published/pct"));
        Assert.Equal("1", V("policy_published/fo"));
        Assert.Equal("192.0.2.1", V("record/row/source_ip"));
        Assert.Equal("1", V("record/row/count"));
        Assert.Equal("none", V("record/row/policy_evaluated/disposition"));
        Assert.Equal("pass", V("record/row/policy_evaluated/dkim"));
        Assert.Equal("fail", V("record/row/policy_evaluated/spf"));
        Assert.Equal("recipient.example", V("record/identifiers/envelope_to"));
        Assert.Equal("softfail", V("record/auth_results/spf/result"));
        Assert.Equal("mfrom", V("record/auth_results/spf/scope"));
    }

    [Fact]
    public void Xml_declaration_is_utf8_without_byte_order_mark()
    {
        using var ms = new MemoryStream();
        DmarcAggregateReportWriter.WriteXml(SampleReport(1), ms);
        byte[] bytes = ms.ToArray();
        Assert.NotEqual(0xEF, bytes[0]);
        Assert.StartsWith("<?xml version=\"1.0\" encoding=\"utf-8\"?>", Encoding.UTF8.GetString(bytes));
    }

    [Fact]
    public void Hostile_text_is_escaped_and_illegal_characters_are_replaced()
    {
        var report = SampleReport(1);
        var row = report.Records[0] with
        {
            HeaderFrom = "exa<mple>&.com",
            EnvelopeFrom = "a\u0001b\ud800c.example",
            DkimResults = [new DkimReportAuthResult("]]></feedback>", "sel\u0000", DkimReportResult.Pass, "line1\r\nline2")],
            Reasons = [new DmarcPolicyOverrideReason(DmarcPolicyOverride.Other, "x & <y>")],
        };
        string xml = DmarcAggregateReportWriter.ToXmlString(report with { Records = [row] });
        Assert.Empty(Validate(xml));
        var doc = System.Xml.Linq.XDocument.Parse(xml);
        Assert.Equal("exa<mple>&.com", doc.Root!.XPathValue("record/identifiers/header_from"));
        Assert.Equal("a?b?c.example", doc.Root!.XPathValue("record/identifiers/envelope_from"));
        Assert.Equal("]]></feedback>", doc.Root!.XPathValue("record/auth_results/dkim/domain"));
    }

    [Fact]
    public void Emoji_surrogate_pairs_survive()
    {
        var report = SampleReport(1);
        var row = report.Records[0] with { HeaderFrom = "xn--ls8h.example😀" };
        string xml = DmarcAggregateReportWriter.ToXmlString(report with { Records = [row] });
        Assert.Contains("😀", xml);
    }

    [Fact]
    public void Record_without_spf_result_still_has_a_schema_valid_spf_element()
    {
        var report = SampleReport(1);
        var row = report.Records[0] with { SpfResults = [], DkimResults = [] };
        string xml = DmarcAggregateReportWriter.ToXmlString(report with { Records = [row] });
        Assert.Empty(Validate(xml));
        Assert.Contains("<result>none</result>", xml.Replace(" ", string.Empty).Replace("\n", string.Empty).Replace("\r", string.Empty));
    }

    [Theory]
    [InlineData(DmarcPolicyOverride.Forwarded, "forwarded")]
    [InlineData(DmarcPolicyOverride.SampledOut, "sampled_out")]
    [InlineData(DmarcPolicyOverride.TrustedForwarder, "trusted_forwarder")]
    [InlineData(DmarcPolicyOverride.MailingList, "mailing_list")]
    [InlineData(DmarcPolicyOverride.LocalPolicy, "local_policy")]
    [InlineData(DmarcPolicyOverride.Other, "other")]
    public void Override_reason_names(DmarcPolicyOverride reason, string expected)
    {
        var report = SampleReport(1);
        var row = report.Records[0] with { Reasons = [new DmarcPolicyOverrideReason(reason)] };
        string xml = DmarcAggregateReportWriter.ToXmlString(report with { Records = [row] });
        Assert.Empty(Validate(xml));
        Assert.Contains($"<type>{expected}</type>", xml);
    }

    [Fact]
    public void All_result_keywords_are_schema_valid()
    {
        var report = SampleReport(1);
        var dkim = Enum.GetValues<DkimReportResult>().Select(r => new DkimReportAuthResult("example.com", null, r)).ToList();
        var spf = Enum.GetValues<SpfResult>().Select(r => new SpfReportAuthResult("example.com", SpfReportScope.Helo, r)).ToList();
        var row = report.Records[0] with { DkimResults = dkim, SpfResults = spf };
        string xml = DmarcAggregateReportWriter.ToXmlString(report with { Records = [row] });
        Assert.Empty(Validate(xml));
    }

    [Fact]
    public void Gzip_output_decompresses_to_the_same_xml()
    {
        var report = SampleReport(3);
        byte[] gz = DmarcAggregateReportWriter.ToGzip(report);
        Assert.Equal(0x1F, gz[0]);
        Assert.Equal(0x8B, gz[1]);
        using var gzip = new GZipStream(new MemoryStream(gz), CompressionMode.Decompress);
        using var reader = new StreamReader(gzip, Encoding.UTF8);
        string xml = reader.ReadToEnd();
        Assert.Empty(Validate(xml));
        Assert.Equal(DmarcAggregateReportWriter.ToXmlString(report, indent: false), xml);
    }

    [Fact]
    public void File_name_follows_the_rfc_convention()
    {
        Assert.Equal(
            "receiver.example!example.com!1700000000!1700086399!report-1.xml.gz",
            DmarcAggregateReportWriter.CreateFileName(SampleReport(1)));
    }

    [Fact]
    public void File_name_parts_are_sanitised()
    {
        var report = SampleReport(1);
        report = report with
        {
            Metadata = report.Metadata with { ReportId = "a!b/c\\d:e\r\nf", ContactEmail = "x@re!ceiver.example" },
            PolicyPublished = report.PolicyPublished with { Domain = "ex ample.com" },
        };
        string name = DmarcAggregateReportWriter.CreateFileName(report);
        Assert.Equal(5, name.Split('!').Length);
        Assert.DoesNotContain("/", name);
        Assert.DoesNotContain("\\", name);
        Assert.DoesNotContain("\r", name);
        Assert.EndsWith(".xml.gz", name);
    }

    [Fact]
    public void Small_report_is_a_single_file_under_the_limit()
    {
        var files = DmarcAggregateReportWriter.CreateFiles(SampleReport(3), 10L * 1024 * 1024);
        var file = Assert.Single(files);
        Assert.Equal("report-1", file.Report.Metadata.ReportId);
        Assert.Equal(DmarcAggregateReportWriter.CreateFileName(file.Report), file.FileName);
    }

    [Fact]
    public void No_limit_means_a_single_file()
    {
        Assert.Single(DmarcAggregateReportWriter.CreateFiles(SampleReport(500), null));
    }

    [Fact]
    public void Oversized_report_is_split_into_parts_that_fit()
    {
        var report = SampleReport(2000);
        long limit = 20_000; // message size limit; the attachment budget is about 12 KB
        var files = DmarcAggregateReportWriter.CreateFiles(report, limit);
        Assert.True(files.Count > 1);
        long budget = (limit - 4096) / 4 * 3;
        Assert.All(files, f =>
        {
            Assert.True(f.Content.Length <= budget || f.Report.Records.Count == 1, $"part of {f.Report.Records.Count} rows is {f.Content.Length} bytes");
            Assert.Empty(Validate(DmarcAggregateReportWriter.ToXmlString(f.Report)));
        });
        Assert.Equal(report.Records.Sum(r => r.Count), files.Sum(f => f.Report.Records.Sum(r => r.Count)));
        Assert.Equal(report.Records.Count, files.Sum(f => f.Report.Records.Count));
        Assert.Equal(files.Count, files.Select(f => f.FileName).Distinct().Count());
        Assert.Equal(files.Count, files.Select(f => f.Report.Metadata.ReportId).Distinct().Count());
        Assert.All(files, f => Assert.Contains(f.Report.Metadata.Errors!, e => e.Contains("split")));
        Assert.Equal(report.Records.Select(r => r.SourceIp + r.Count), files.SelectMany(f => f.Report.Records).Select(r => r.SourceIp + r.Count));
    }

    [Fact]
    public void Tiny_limit_still_terminates_with_one_row_per_part()
    {
        var report = SampleReport(300);
        var files = DmarcAggregateReportWriter.CreateFiles(report, 10);
        Assert.True(files.Count > 1);
        Assert.All(files, f => Assert.True(f.Content.Length <= 1024 || f.Report.Records.Count == 1));
        Assert.Equal(report.Records.Count, files.Sum(f => f.Report.Records.Count));
    }
}

internal static class XmlTestExtensions
{
    /// <summary>Finds the text of a descendant by a slash-separated path of local names, starting below the element.</summary>
    public static string XPathValue(this System.Xml.Linq.XElement root, string path)
    {
        System.Xml.Linq.XElement? current = root;
        foreach (string part in path.Split('/'))
        {
            current = current!.Elements().First(e => e.Name.LocalName == part);
        }

        return current!.Value;
    }
}
