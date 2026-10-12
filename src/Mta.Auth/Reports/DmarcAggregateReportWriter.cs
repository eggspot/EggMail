using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Xml;
using Mta.Auth.Dmarc;
using Mta.Auth.Spf;

namespace Mta.Auth.Reports;

/// <summary>A generated report attachment.</summary>
/// <param name="FileName">The file name following RFC 7489 section 7.2.1.1 (<c>receiver!policy-domain!begin!end!unique.xml.gz</c>).</param>
/// <param name="Content">The gzip-compressed XML.</param>
/// <param name="Report">The report that was serialized (one part when a report was split).</param>
public sealed record DmarcAggregateReportFile(string FileName, byte[] Content, DmarcAggregateReport Report);

/// <summary>Serializes <see cref="DmarcAggregateReport"/> to the RFC 7489 Appendix C XML format.</summary>
public static class DmarcAggregateReportWriter
{
    /// <summary>The media type of the compressed attachment.</summary>
    public const string GzipMediaType = "application/gzip";

    /// <summary>Bytes reserved for the report e-mail's headers and MIME structure when fitting a size limit.</summary>
    private const int MessageOverheadBytes = 4096;

    /// <summary>Writes the report as UTF-8 XML (no byte order mark). Element order follows the RFC 7489 schema.</summary>
    /// <param name="report">The report.</param>
    /// <param name="output">The destination stream; it is left open.</param>
    /// <param name="indent">Whether to indent for readability (larger output).</param>
    public static void WriteXml(DmarcAggregateReport report, Stream output, bool indent = true)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(output);
        var settings = new XmlWriterSettings
        {
            Encoding = new UTF8Encoding(false),
            Indent = indent,
            CloseOutput = false,
            CheckCharacters = true,
        };

        using var xml = XmlWriter.Create(output, settings);
        xml.WriteStartDocument();
        xml.WriteStartElement("feedback");
        xml.WriteElementString("version", "1.0");

        DmarcReportMetadata m = report.Metadata;
        xml.WriteStartElement("report_metadata");
        Text(xml, "org_name", m.OrganizationName);
        Text(xml, "email", m.ContactEmail);
        if (!string.IsNullOrEmpty(m.ExtraContactInfo))
        {
            Text(xml, "extra_contact_info", m.ExtraContactInfo);
        }

        Text(xml, "report_id", m.ReportId);
        xml.WriteStartElement("date_range");
        xml.WriteElementString("begin", m.Begin.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
        xml.WriteElementString("end", m.End.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
        xml.WriteEndElement();
        foreach (string error in m.Errors ?? [])
        {
            Text(xml, "error", error);
        }

        xml.WriteEndElement(); // report_metadata

        DmarcPublishedPolicy p = report.PolicyPublished;
        xml.WriteStartElement("policy_published");
        Text(xml, "domain", p.Domain);
        xml.WriteElementString("adkim", Alignment(p.DkimAlignment));
        xml.WriteElementString("aspf", Alignment(p.SpfAlignment));
        xml.WriteElementString("p", PolicyName(p.Policy));
        xml.WriteElementString("sp", PolicyName(p.SubdomainPolicy));
        xml.WriteElementString("pct", p.Percentage.ToString(CultureInfo.InvariantCulture));
        Text(xml, "fo", p.FailureReportingOptions);
        xml.WriteEndElement(); // policy_published

        foreach (DmarcAggregateRecord r in report.Records)
        {
            WriteRecord(xml, r);
        }

        xml.WriteEndElement(); // feedback
        xml.WriteEndDocument();
    }

    /// <summary>Serializes the report to an XML string.</summary>
    /// <param name="report">The report.</param>
    /// <param name="indent">Whether to indent.</param>
    public static string ToXmlString(DmarcAggregateReport report, bool indent = true)
    {
        using var ms = new MemoryStream();
        WriteXml(report, ms, indent);
        return new UTF8Encoding(false).GetString(ms.ToArray());
    }

    /// <summary>Serializes and gzip-compresses the report.</summary>
    /// <param name="report">The report.</param>
    public static byte[] ToGzip(DmarcAggregateReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        using var ms = new MemoryStream();
        using (var gzip = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
        {
            WriteXml(report, gzip, indent: false);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// The attachment name <c>receiver!policy-domain!begin!end!unique.xml.gz</c>: the receiver is the domain of the
    /// report contact address, the timestamps are Unix seconds, the unique part is the report id. Characters that are
    /// unsafe in file names (including the separator) are replaced by underscores.
    /// </summary>
    /// <param name="report">The report.</param>
    public static string CreateFileName(DmarcAggregateReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        DmarcReportMetadata m = report.Metadata;
        int at = m.ContactEmail.LastIndexOf('@');
        string receiver = at >= 0 ? m.ContactEmail[(at + 1)..] : m.ContactEmail;
        return string.Join(
            '!',
            FileNamePart(receiver),
            FileNamePart(report.PolicyPublished.Domain),
            m.Begin.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            m.End.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            FileNamePart(m.ReportId)) + ".xml.gz";
    }

    /// <summary>
    /// Produces the attachment(s) for a report, splitting the rows over several reports when one would exceed the
    /// size limit. The limit is for the whole e-mail; the attachment is sent base64-encoded, so the compressed XML
    /// budget is three quarters of the limit minus 4 KiB for headers. A split part gets the report id suffixed with
    /// <c>.1</c>, <c>.2</c>, ... and an error note. A single row is never split, so a limit smaller than one row yields
    /// one oversized part per row.
    /// </summary>
    /// <param name="report">The report.</param>
    /// <param name="maxMessageBytes">The destination's size limit (<c>!10m</c>), or null for no limit.</param>
    public static IReadOnlyList<DmarcAggregateReportFile> CreateFiles(DmarcAggregateReport report, long? maxMessageBytes)
    {
        ArgumentNullException.ThrowIfNull(report);
        long budget = maxMessageBytes is { } max ? Math.Max(1024, (max - MessageOverheadBytes) / 4 * 3) : long.MaxValue;
        var files = new List<DmarcAggregateReportFile>();
        byte[] whole = ToGzip(report);
        if (whole.Length <= budget || report.Records.Count <= 1)
        {
            files.Add(new DmarcAggregateReportFile(CreateFileName(report), whole, report));
            return files;
        }

        int part = 0;
        Split(report, budget, whole, files, ref part);
        return files;
    }

    private static void Split(DmarcAggregateReport report, long budget, byte[]? compressed, List<DmarcAggregateReportFile> files, ref int part)
    {
        compressed ??= ToGzip(report);
        if (compressed.Length > budget && report.Records.Count > 1)
        {
            int half = report.Records.Count / 2;
            Split(report with { Records = report.Records.Take(half).ToList() }, budget, null, files, ref part);
            Split(report with { Records = report.Records.Skip(half).ToList() }, budget, null, files, ref part);
            return;
        }

        part++;
        string suffix = part.ToString(CultureInfo.InvariantCulture);
        DmarcAggregateReport named = report with
        {
            Metadata = report.Metadata with
            {
                ReportId = report.Metadata.ReportId + "." + suffix,
                Errors = [.. report.Metadata.Errors ?? [], "report split to fit the size limit; this is part " + suffix],
            },
        };
        files.Add(new DmarcAggregateReportFile(CreateFileName(named), ToGzip(named), named));
    }

    private static void WriteRecord(XmlWriter xml, DmarcAggregateRecord r)
    {
        xml.WriteStartElement("record");
        xml.WriteStartElement("row");
        Text(xml, "source_ip", r.SourceIp);
        xml.WriteElementString("count", r.Count.ToString(CultureInfo.InvariantCulture));
        xml.WriteStartElement("policy_evaluated");
        xml.WriteElementString("disposition", DispositionName(r.Disposition));
        xml.WriteElementString("dkim", r.DkimAligned ? "pass" : "fail");
        xml.WriteElementString("spf", r.SpfAligned ? "pass" : "fail");
        foreach (DmarcPolicyOverrideReason reason in r.Reasons)
        {
            xml.WriteStartElement("reason");
            xml.WriteElementString("type", OverrideName(reason.Type));
            if (!string.IsNullOrEmpty(reason.Comment))
            {
                Text(xml, "comment", reason.Comment);
            }

            xml.WriteEndElement();
        }

        xml.WriteEndElement(); // policy_evaluated
        xml.WriteEndElement(); // row

        xml.WriteStartElement("identifiers");
        if (!string.IsNullOrEmpty(r.EnvelopeTo))
        {
            Text(xml, "envelope_to", r.EnvelopeTo);
        }

        Text(xml, "envelope_from", r.EnvelopeFrom);
        Text(xml, "header_from", r.HeaderFrom);
        xml.WriteEndElement(); // identifiers

        xml.WriteStartElement("auth_results");
        foreach (DkimReportAuthResult d in r.DkimResults)
        {
            xml.WriteStartElement("dkim");
            Text(xml, "domain", d.Domain);
            if (!string.IsNullOrEmpty(d.Selector))
            {
                Text(xml, "selector", d.Selector);
            }

            xml.WriteElementString("result", DkimResultName(d.Result));
            if (!string.IsNullOrEmpty(d.HumanResult))
            {
                Text(xml, "human_result", d.HumanResult);
            }

            xml.WriteEndElement();
        }

        IReadOnlyList<SpfReportAuthResult> spf = r.SpfResults.Count > 0
            ? r.SpfResults
            : [new SpfReportAuthResult(r.EnvelopeFrom, SpfReportScope.MailFrom, SpfResult.None)];
        foreach (SpfReportAuthResult s in spf)
        {
            xml.WriteStartElement("spf");
            Text(xml, "domain", s.Domain);
            xml.WriteElementString("scope", s.Scope == SpfReportScope.Helo ? "helo" : "mfrom");
            xml.WriteElementString("result", SpfCheckResult.ToKeyword(s.Result));
            xml.WriteEndElement();
        }

        xml.WriteEndElement(); // auth_results
        xml.WriteEndElement(); // record
    }

    private static void Text(XmlWriter xml, string name, string value) =>
        xml.WriteElementString(name, XmlSafe(value));

    /// <summary>Replaces characters that are illegal in XML 1.0 by '?'; hostile header values must not abort report generation.</summary>
    internal static string XmlSafe(string value)
    {
        StringBuilder? sb = null;
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
            {
                sb?.Append(c).Append(value[i + 1]);
                i++;
                continue;
            }

            if (!XmlConvert.IsXmlChar(c))
            {
                sb ??= new StringBuilder(value, 0, i, value.Length);
                sb.Append('?');
            }
            else
            {
                sb?.Append(c);
            }
        }

        return sb?.ToString() ?? value;
    }

    private static string FileNamePart(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            sb.Append(c is '!' or '/' or '\\' or ':' or '*' or '?' or '"' or '<' or '>' or '|' || c < ' ' || c > '~' ? '_' : c);
        }

        return sb.Length == 0 ? "_" : sb.ToString();
    }

    internal static string Alignment(DmarcAlignmentMode mode) => mode == DmarcAlignmentMode.Strict ? "s" : "r";

    internal static string PolicyName(DmarcPolicy policy) => policy switch
    {
        DmarcPolicy.Quarantine => "quarantine",
        DmarcPolicy.Reject => "reject",
        _ => "none",
    };

    internal static string DispositionName(DmarcDisposition disposition) => disposition switch
    {
        DmarcDisposition.Quarantine => "quarantine",
        DmarcDisposition.Reject => "reject",
        _ => "none",
    };

    internal static string OverrideName(DmarcPolicyOverride value) => value switch
    {
        DmarcPolicyOverride.Forwarded => "forwarded",
        DmarcPolicyOverride.SampledOut => "sampled_out",
        DmarcPolicyOverride.TrustedForwarder => "trusted_forwarder",
        DmarcPolicyOverride.MailingList => "mailing_list",
        DmarcPolicyOverride.LocalPolicy => "local_policy",
        _ => "other",
    };

    internal static string DkimResultName(DkimReportResult value) => value switch
    {
        DkimReportResult.Pass => "pass",
        DkimReportResult.Fail => "fail",
        DkimReportResult.Policy => "policy",
        DkimReportResult.Neutral => "neutral",
        DkimReportResult.TempError => "temperror",
        DkimReportResult.PermError => "permerror",
        _ => "none",
    };
}
