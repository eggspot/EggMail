using System.Net;
using System.Xml;
using System.Xml.Schema;
using Mta.Auth.Dmarc;
using Mta.Auth.Reports;
using Mta.Auth.Spf;
using static Mta.Auth.Tests.TestZone;

namespace Mta.Auth.Tests.Reports;

internal static class ReportTestSupport
{
    /// <summary>The aggregate report schema of RFC 7489 Appendix C, reproduced for validation.</summary>
    public const string Xsd = """
        <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" elementFormDefault="qualified">
          <xs:element name="feedback">
            <xs:complexType>
              <xs:sequence>
                <xs:element name="version" type="xs:decimal" minOccurs="0"/>
                <xs:element name="report_metadata" type="ReportMetadataType"/>
                <xs:element name="policy_published" type="PolicyPublishedType"/>
                <xs:element name="record" type="RecordType" maxOccurs="unbounded"/>
              </xs:sequence>
            </xs:complexType>
          </xs:element>
          <xs:complexType name="ReportMetadataType">
            <xs:sequence>
              <xs:element name="org_name" type="xs:string"/>
              <xs:element name="email" type="xs:string"/>
              <xs:element name="extra_contact_info" type="xs:string" minOccurs="0"/>
              <xs:element name="report_id" type="xs:string"/>
              <xs:element name="date_range" type="DateRangeType"/>
              <xs:element name="error" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
            </xs:sequence>
          </xs:complexType>
          <xs:complexType name="DateRangeType">
            <xs:sequence>
              <xs:element name="begin" type="xs:integer"/>
              <xs:element name="end" type="xs:integer"/>
            </xs:sequence>
          </xs:complexType>
          <xs:complexType name="PolicyPublishedType">
            <xs:sequence>
              <xs:element name="domain" type="xs:string"/>
              <xs:element name="adkim" type="AlignmentType" minOccurs="0"/>
              <xs:element name="aspf" type="AlignmentType" minOccurs="0"/>
              <xs:element name="p" type="DispositionType"/>
              <xs:element name="sp" type="DispositionType"/>
              <xs:element name="pct" type="xs:integer"/>
              <xs:element name="fo" type="xs:string"/>
            </xs:sequence>
          </xs:complexType>
          <xs:complexType name="RecordType">
            <xs:sequence>
              <xs:element name="row" type="RowType"/>
              <xs:element name="identifiers" type="IdentifierType"/>
              <xs:element name="auth_results" type="AuthResultType"/>
            </xs:sequence>
          </xs:complexType>
          <xs:complexType name="RowType">
            <xs:sequence>
              <xs:element name="source_ip" type="xs:string"/>
              <xs:element name="count" type="xs:integer"/>
              <xs:element name="policy_evaluated" type="PolicyEvaluatedType"/>
            </xs:sequence>
          </xs:complexType>
          <xs:complexType name="PolicyEvaluatedType">
            <xs:sequence>
              <xs:element name="disposition" type="DispositionType"/>
              <xs:element name="dkim" type="DMARCResultType"/>
              <xs:element name="spf" type="DMARCResultType"/>
              <xs:element name="reason" type="PolicyOverrideReason" minOccurs="0" maxOccurs="unbounded"/>
            </xs:sequence>
          </xs:complexType>
          <xs:complexType name="PolicyOverrideReason">
            <xs:sequence>
              <xs:element name="type" type="PolicyOverrideType"/>
              <xs:element name="comment" type="xs:string" minOccurs="0"/>
            </xs:sequence>
          </xs:complexType>
          <xs:complexType name="IdentifierType">
            <xs:sequence>
              <xs:element name="envelope_to" type="xs:string" minOccurs="0"/>
              <xs:element name="envelope_from" type="xs:string"/>
              <xs:element name="header_from" type="xs:string"/>
            </xs:sequence>
          </xs:complexType>
          <xs:complexType name="AuthResultType">
            <xs:sequence>
              <xs:element name="dkim" type="DKIMAuthResultType" minOccurs="0" maxOccurs="unbounded"/>
              <xs:element name="spf" type="SPFAuthResultType" maxOccurs="unbounded"/>
            </xs:sequence>
          </xs:complexType>
          <xs:complexType name="DKIMAuthResultType">
            <xs:sequence>
              <xs:element name="domain" type="xs:string"/>
              <xs:element name="selector" type="xs:string" minOccurs="0"/>
              <xs:element name="result" type="DKIMResultType"/>
              <xs:element name="human_result" type="xs:string" minOccurs="0"/>
            </xs:sequence>
          </xs:complexType>
          <xs:complexType name="SPFAuthResultType">
            <xs:sequence>
              <xs:element name="domain" type="xs:string"/>
              <xs:element name="scope" type="SPFDomainScope"/>
              <xs:element name="result" type="SPFResultType"/>
            </xs:sequence>
          </xs:complexType>
          <xs:simpleType name="AlignmentType">
            <xs:restriction base="xs:string"><xs:enumeration value="r"/><xs:enumeration value="s"/></xs:restriction>
          </xs:simpleType>
          <xs:simpleType name="DispositionType">
            <xs:restriction base="xs:string"><xs:enumeration value="none"/><xs:enumeration value="quarantine"/><xs:enumeration value="reject"/></xs:restriction>
          </xs:simpleType>
          <xs:simpleType name="DMARCResultType">
            <xs:restriction base="xs:string"><xs:enumeration value="pass"/><xs:enumeration value="fail"/></xs:restriction>
          </xs:simpleType>
          <xs:simpleType name="PolicyOverrideType">
            <xs:restriction base="xs:string">
              <xs:enumeration value="forwarded"/><xs:enumeration value="sampled_out"/><xs:enumeration value="trusted_forwarder"/>
              <xs:enumeration value="mailing_list"/><xs:enumeration value="local_policy"/><xs:enumeration value="other"/>
            </xs:restriction>
          </xs:simpleType>
          <xs:simpleType name="DKIMResultType">
            <xs:restriction base="xs:string">
              <xs:enumeration value="none"/><xs:enumeration value="pass"/><xs:enumeration value="fail"/><xs:enumeration value="policy"/>
              <xs:enumeration value="neutral"/><xs:enumeration value="temperror"/><xs:enumeration value="permerror"/>
            </xs:restriction>
          </xs:simpleType>
          <xs:simpleType name="SPFDomainScope">
            <xs:restriction base="xs:string"><xs:enumeration value="helo"/><xs:enumeration value="mfrom"/></xs:restriction>
          </xs:simpleType>
          <xs:simpleType name="SPFResultType">
            <xs:restriction base="xs:string">
              <xs:enumeration value="none"/><xs:enumeration value="neutral"/><xs:enumeration value="pass"/><xs:enumeration value="fail"/>
              <xs:enumeration value="softfail"/><xs:enumeration value="temperror"/><xs:enumeration value="permerror"/>
            </xs:restriction>
          </xs:simpleType>
        </xs:schema>
        """;

    /// <summary>Validates XML text against the RFC schema and returns the validation problems (empty when valid).</summary>
    public static List<string> Validate(string xml)
    {
        var schemas = new XmlSchemaSet();
        using (var xsd = XmlReader.Create(new StringReader(Xsd)))
        {
            schemas.Add(null, xsd);
        }

        var problems = new List<string>();
        var settings = new XmlReaderSettings { ValidationType = ValidationType.Schema, Schemas = schemas, DtdProcessing = DtdProcessing.Prohibit };
        settings.ValidationEventHandler += (_, e) => problems.Add(e.Message);
        using var reader = XmlReader.Create(new StringReader(xml), settings);
        while (reader.Read())
        {
        }

        return problems;
    }

    public static DmarcAggregateReport SampleReport(int rows = 2)
    {
        var records = new List<DmarcAggregateRecord>();
        for (int i = 0; i < rows; i++)
        {
            records.Add(new DmarcAggregateRecord(
                $"192.0.2.{i % 250 + 1}",
                i + 1,
                i % 2 == 0 ? DmarcDisposition.None : DmarcDisposition.Reject,
                i % 2 == 0,
                false,
                i % 3 == 0 ? [] : [new DmarcPolicyOverrideReason(DmarcPolicyOverride.LocalPolicy, "trusted by admin")],
                i % 2 == 0 ? "recipient.example" : null,
                "bounce.example.com",
                "example.com",
                [new DkimReportAuthResult("example.com", "sel" + i, DkimReportResult.Pass), new DkimReportAuthResult("esp.net", null, DkimReportResult.Fail, "body hash mismatch")],
                [new SpfReportAuthResult("bounce.example.com", SpfReportScope.MailFrom, SpfResult.SoftFail)]));
        }

        return new DmarcAggregateReport(
            new DmarcReportMetadata("Receiver Inc", "dmarc-reports@receiver.example", "report-1", DateTimeOffset.FromUnixTimeSeconds(1_700_000_000), DateTimeOffset.FromUnixTimeSeconds(1_700_086_399), "https://receiver.example/dmarc"),
            new DmarcPublishedPolicy("example.com", DmarcAlignmentMode.Relaxed, DmarcAlignmentMode.Strict, DmarcPolicy.Reject, DmarcPolicy.Quarantine, 80, "1"),
            records);
    }

    public const string DefaultPolicy = "v=DMARC1; p=reject; sp=quarantine; adkim=s; pct=50; rua=mailto:agg@example.com!5m,mailto:other@example.net";

    /// <summary>Evaluates a message for example.com with the default policy so tests get realistic evaluations.</summary>
    public static async Task<(DmarcInput Input, DmarcEvaluation Evaluation)> EvaluateAsync(
        string from = "example.com",
        SpfResult spf = SpfResult.Pass,
        string spfDomain = "example.com",
        IReadOnlyList<DkimAuthResult>? dkim = null,
        string policy = DefaultPolicy,
        Random? random = null)
    {
        var resolver = Build(Z("_dmarc.example.com TXT " + policy));
        var evaluator = new DmarcEvaluator(resolver, new DmarcOptions { Random = random ?? new Random(1) });
        var input = new DmarcInput(from, new SpfAuthResult(spf, spfDomain), dkim ?? []);
        return (input, await evaluator.EvaluateAsync(input));
    }

    public static async Task<DmarcAggregateObservation> ObservationAsync(
        DateTimeOffset at,
        string ip = "203.0.113.5",
        string from = "example.com",
        SpfResult spf = SpfResult.Pass,
        string spfDomain = "example.com",
        IReadOnlyList<DkimAuthResult>? dkim = null,
        string policy = DefaultPolicy,
        Random? random = null,
        string? envelopeTo = null)
    {
        var (input, evaluation) = await EvaluateAsync(from, spf, spfDomain, dkim, policy, random);
        return new DmarcAggregateObservation(at, IPAddress.Parse(ip), input, evaluation, SpfReportScope.MailFrom, envelopeTo);
    }
}
