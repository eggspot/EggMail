using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO.Compression;
using System.Xml;
using System.Xml.Linq;
using Mta.Auth.Dmarc;
using Mta.Auth.Spf;

namespace Mta.Auth.Reports;

/// <summary>
/// A bounded reader for received DMARC aggregate reports (XML or gzip-compressed XML). DTDs and external entities are
/// refused, decompression is size-capped, and unknown elements are ignored. ZIP attachments are not handled.
/// </summary>
public static class DmarcAggregateReportReader
{
    /// <summary>The maximum size of the XML document after decompression (64 MiB).</summary>
    public const int MaxDocumentBytes = 64 * 1024 * 1024;

    /// <summary>Reads a report from a stream; gzip is detected from its magic number. Never throws for bad content.</summary>
    /// <param name="stream">The raw attachment.</param>
    /// <param name="report">The parsed report.</param>
    public static bool TryRead(Stream stream, [NotNullWhen(true)] out DmarcAggregateReport? report)
    {
        ArgumentNullException.ThrowIfNull(stream);
        report = null;
        try
        {
            byte[]? xml = ReadBounded(stream);
            if (xml is null)
            {
                return false;
            }

            if (xml.Length >= 2 && xml[0] == 0x1F && xml[1] == 0x8B)
            {
                using var gzip = new GZipStream(new MemoryStream(xml), CompressionMode.Decompress);
                xml = ReadBounded(gzip);
                if (xml is null)
                {
                    return false;
                }
            }

            report = Parse(xml);
            return report is not null;
        }
#pragma warning disable CA1031 // Received reports are hostile; whatever goes wrong, the answer is "not a usable report".
        catch (Exception ex) when (ex is not OutOfMemoryException)
#pragma warning restore CA1031
        {
            report = null;
            return false;
        }
    }

    /// <summary>Reads a report from a byte array.</summary>
    /// <param name="content">The raw attachment (XML or gzip).</param>
    /// <param name="report">The parsed report.</param>
    public static bool TryRead(byte[] content, [NotNullWhen(true)] out DmarcAggregateReport? report)
    {
        ArgumentNullException.ThrowIfNull(content);
        using var ms = new MemoryStream(content);
        return TryRead(ms, out report);
    }

    private static byte[]? ReadBounded(Stream stream)
    {
        using var ms = new MemoryStream();
        var buffer = new byte[81920];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            if (ms.Length + read > MaxDocumentBytes)
            {
                return null;
            }

            ms.Write(buffer, 0, read);
        }

        return ms.ToArray();
    }

    private static DmarcAggregateReport? Parse(byte[] xml)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaxDocumentBytes,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
        };
        using var reader = XmlReader.Create(new MemoryStream(xml), settings);
        XDocument doc = XDocument.Load(reader, LoadOptions.None);
        XElement? root = doc.Root;
        if (root is null || root.Name.LocalName != "feedback")
        {
            return null;
        }

        XElement? metaElement = Child(root, "report_metadata");
        XElement? policyElement = Child(root, "policy_published");
        if (metaElement is null || policyElement is null)
        {
            return null;
        }

        XElement? range = Child(metaElement, "date_range");
        if (!TryEpoch(Text(range, "begin"), out DateTimeOffset begin) || !TryEpoch(Text(range, "end"), out DateTimeOffset end))
        {
            return null;
        }

        var metadata = new DmarcReportMetadata(
            Text(metaElement, "org_name") ?? string.Empty,
            Text(metaElement, "email") ?? string.Empty,
            Text(metaElement, "report_id") ?? string.Empty,
            begin,
            end,
            Text(metaElement, "extra_contact_info"),
            metaElement.Elements().Where(e => e.Name.LocalName == "error").Select(e => e.Value.Trim()).ToList());

        DmarcPolicy p = ParsePolicy(Text(policyElement, "p"));
        var published = new DmarcPublishedPolicy(
            Text(policyElement, "domain") ?? string.Empty,
            ParseAlignment(Text(policyElement, "adkim")),
            ParseAlignment(Text(policyElement, "aspf")),
            p,
            Text(policyElement, "sp") is { } sp ? ParsePolicy(sp) : p,
            int.TryParse(Text(policyElement, "pct"), NumberStyles.None, CultureInfo.InvariantCulture, out int pct) ? pct : 100,
            Text(policyElement, "fo") ?? "0");

        var records = new List<DmarcAggregateRecord>();
        foreach (XElement record in root.Elements().Where(e => e.Name.LocalName == "record"))
        {
            XElement? row = Child(record, "row");
            XElement? evaluated = Child(row, "policy_evaluated");
            XElement? identifiers = Child(record, "identifiers");
            XElement? auth = Child(record, "auth_results");
            if (row is null || evaluated is null)
            {
                return null;
            }

            records.Add(new DmarcAggregateRecord(
                Text(row, "source_ip") ?? string.Empty,
                long.TryParse(Text(row, "count"), NumberStyles.None, CultureInfo.InvariantCulture, out long count) ? count : 0,
                ParseDisposition(Text(evaluated, "disposition")),
                Text(evaluated, "dkim") == "pass",
                Text(evaluated, "spf") == "pass",
                evaluated.Elements().Where(e => e.Name.LocalName == "reason")
                    .Select(r => new DmarcPolicyOverrideReason(ParseOverride(Text(r, "type")), Text(r, "comment")))
                    .ToList(),
                Text(identifiers, "envelope_to"),
                Text(identifiers, "envelope_from") ?? string.Empty,
                Text(identifiers, "header_from") ?? string.Empty,
                auth is null ? [] : auth.Elements().Where(e => e.Name.LocalName == "dkim")
                    .Select(d => new DkimReportAuthResult(Text(d, "domain") ?? string.Empty, Text(d, "selector"), ParseDkimResult(Text(d, "result")), Text(d, "human_result")))
                    .ToList(),
                auth is null ? [] : auth.Elements().Where(e => e.Name.LocalName == "spf")
                    .Select(s => new SpfReportAuthResult(Text(s, "domain") ?? string.Empty, Text(s, "scope") == "helo" ? SpfReportScope.Helo : SpfReportScope.MailFrom, ParseSpfResult(Text(s, "result"))))
                    .ToList()));
        }

        return new DmarcAggregateReport(metadata, published, records);
    }

    private static XElement? Child(XElement? parent, string name) =>
        parent?.Elements().FirstOrDefault(e => e.Name.LocalName == name);

    private static string? Text(XElement? parent, string name)
    {
        string? value = Child(parent, name)?.Value.Trim();
        return string.IsNullOrEmpty(value) ? null : value;
    }

    private static bool TryEpoch(string? text, out DateTimeOffset value)
    {
        value = default;
        if (!long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out long seconds) || seconds > 253402300799)
        {
            return false;
        }

        value = DateTimeOffset.FromUnixTimeSeconds(seconds);
        return true;
    }

    private static DmarcPolicy ParsePolicy(string? text) => text?.ToLowerInvariant() switch
    {
        "reject" => DmarcPolicy.Reject,
        "quarantine" => DmarcPolicy.Quarantine,
        _ => DmarcPolicy.None,
    };

    private static DmarcDisposition ParseDisposition(string? text) => text?.ToLowerInvariant() switch
    {
        "reject" => DmarcDisposition.Reject,
        "quarantine" => DmarcDisposition.Quarantine,
        _ => DmarcDisposition.None,
    };

    private static DmarcAlignmentMode ParseAlignment(string? text) =>
        string.Equals(text, "s", StringComparison.OrdinalIgnoreCase) ? DmarcAlignmentMode.Strict : DmarcAlignmentMode.Relaxed;

    private static DmarcPolicyOverride ParseOverride(string? text) =>
        Enum.GetValues<DmarcPolicyOverride>().FirstOrDefault(v => DmarcAggregateReportWriter.OverrideName(v) == text?.ToLowerInvariant(), DmarcPolicyOverride.Other);

    private static DkimReportResult ParseDkimResult(string? text) =>
        Enum.GetValues<DkimReportResult>().FirstOrDefault(v => DmarcAggregateReportWriter.DkimResultName(v) == text?.ToLowerInvariant(), DkimReportResult.None);

    private static SpfResult ParseSpfResult(string? text) =>
        Enum.GetValues<SpfResult>().FirstOrDefault(v => SpfCheckResult.ToKeyword(v) == text?.ToLowerInvariant(), SpfResult.None);
}
