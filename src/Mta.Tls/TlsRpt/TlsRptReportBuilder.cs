using System.IO.Compression;
using System.Text.Json;
using Mta.Core;

namespace Mta.Tls.TlsRpt;

/// <summary>Options for <see cref="TlsRptReportBuilder"/>.</summary>
public sealed class TlsRptReportOptions
{
    /// <summary>The <c>organization-name</c> field: who generated the report (for example the sending domain's operator).</summary>
    public required string OrganizationName { get; init; }

    /// <summary>The <c>contact-info</c> field: an e-mail address or phone number for questions about the report.</summary>
    public required string ContactInfo { get; init; }

    /// <summary>The domain of the reporting organisation, used as the first component of the report file name (RFC 8460 section 5.1).</summary>
    public required string SubmitterDomain { get; init; }

    /// <summary>Produces a unique <c>report-id</c>. The default is a time-ordered GUID in compact form.</summary>
    public Func<string>? ReportIdFactory { get; init; }
}

/// <summary>A generated TLS-RPT report ready to be delivered.</summary>
/// <param name="ReportId">The unique report id.</param>
/// <param name="PolicyDomain">The domain the report is about.</param>
/// <param name="Begin">Start of the covered period (UTC).</param>
/// <param name="End">End of the covered period (UTC, 23:59:59 of the day).</param>
/// <param name="Json">The uncompressed JSON document.</param>
/// <param name="GzipPayload">The gzip-compressed JSON (the body to POST or attach).</param>
/// <param name="FileName">The attachment file name: <c>submitter!policy-domain!begin!end!report-id.json.gz</c>.</param>
public sealed record TlsRptReport(
    string ReportId,
    string PolicyDomain,
    DateTimeOffset Begin,
    DateTimeOffset End,
    byte[] Json,
    byte[] GzipPayload,
    string FileName)
{
    /// <summary>The media type for the gzip payload (<c>application/tlsrpt+gzip</c>).</summary>
    public const string GzipMediaType = "application/tlsrpt+gzip";

    /// <summary>The media type of the uncompressed JSON report (<c>application/tlsrpt+json</c>).</summary>
    public const string JsonMediaType = "application/tlsrpt+json";
}

/// <summary>Builds RFC 8460 aggregate reports (JSON, gzip) from collected data.</summary>
public sealed class TlsRptReportBuilder
{
    private readonly TlsRptReportOptions _options;

    /// <summary>Creates a builder.</summary>
    public TlsRptReportBuilder(TlsRptReportOptions options) => _options = options ?? throw new ArgumentNullException(nameof(options));

    /// <summary>Builds the report for one domain and day.</summary>
    public TlsRptReport Build(TlsRptDomainReportData data)
    {
        ArgumentNullException.ThrowIfNull(data);
        var begin = new DateTimeOffset(data.Day.Year, data.Day.Month, data.Day.Day, 0, 0, 0, TimeSpan.Zero);
        var end = begin.AddDays(1).AddSeconds(-1);
        string reportId = _options.ReportIdFactory?.Invoke() ?? Ids.ToCompact(Ids.New(begin));

        byte[] json = WriteJson(data, begin, end, reportId);
        string fileName = string.Join(
            "!",
            Sanitize(_options.SubmitterDomain),
            Sanitize(data.PolicyDomain),
            begin.ToUnixTimeSeconds(),
            end.ToUnixTimeSeconds(),
            Sanitize(reportId)) + ".json.gz";
        return new TlsRptReport(reportId, data.PolicyDomain, begin, end, json, Compress(json), fileName);
    }

    /// <summary>Compresses a report with gzip.</summary>
    public static byte[] Compress(ReadOnlySpan<byte> json)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            gzip.Write(json);
        }

        return output.ToArray();
    }

    /// <summary>Decompresses a gzip report, failing with <see cref="InvalidDataException"/> if it would exceed <paramref name="maxBytes"/>.</summary>
    public static byte[] Decompress(ReadOnlySpan<byte> gzipPayload, int maxBytes = 16 * 1024 * 1024)
    {
        using var input = new MemoryStream(gzipPayload.ToArray());
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        int n;
        while ((n = gzip.Read(buffer)) > 0)
        {
            if (output.Length + n > maxBytes)
            {
                throw new InvalidDataException("Decompressed report exceeds the size limit.");
            }

            output.Write(buffer, 0, n);
        }

        return output.ToArray();
    }

    private byte[] WriteJson(TlsRptDomainReportData data, DateTimeOffset begin, DateTimeOffset end, string reportId)
    {
        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream))
        {
            w.WriteStartObject();
            w.WriteString("organization-name", _options.OrganizationName);
            w.WriteStartObject("date-range");
            w.WriteString("start-datetime", FormatTime(begin));
            w.WriteString("end-datetime", FormatTime(end));
            w.WriteEndObject();
            w.WriteString("contact-info", _options.ContactInfo);
            w.WriteString("report-id", reportId);
            w.WriteStartArray("policies");
            foreach (var aggregate in data.Policies)
            {
                WritePolicy(w, data.PolicyDomain, aggregate);
            }

            w.WriteEndArray();
            w.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static void WritePolicy(Utf8JsonWriter w, string policyDomain, TlsRptPolicyAggregate aggregate)
    {
        w.WriteStartObject();
        w.WriteStartObject("policy");
        w.WriteString("policy-type", aggregate.Policy.Type.ToWireString());
        if (aggregate.Policy.PolicyString.Count > 0)
        {
            w.WriteStartArray("policy-string");
            foreach (string line in aggregate.Policy.PolicyString)
            {
                w.WriteStringValue(line);
            }

            w.WriteEndArray();
        }

        w.WriteString("policy-domain", policyDomain);
        if (aggregate.Policy.MxHosts.Count > 0)
        {
            w.WriteStartArray("mx-host");
            foreach (string mx in aggregate.Policy.MxHosts)
            {
                w.WriteStringValue(mx);
            }

            w.WriteEndArray();
        }

        w.WriteEndObject();
        w.WriteStartObject("summary");
        w.WriteNumber("total-successful-session-count", aggregate.SuccessCount);
        w.WriteNumber("total-failure-session-count", aggregate.FailureCount);
        w.WriteEndObject();
        if (aggregate.FailureDetails.Count > 0)
        {
            w.WriteStartArray("failure-details");
            foreach (var d in aggregate.FailureDetails)
            {
                w.WriteStartObject();
                w.WriteString("result-type", d.ResultType.ToWireString());
                WriteOptional(w, "sending-mta-ip", d.SendingMtaIp);
                WriteOptional(w, "receiving-mx-hostname", d.ReceivingMxHostname);
                WriteOptional(w, "receiving-mx-helo", d.ReceivingMxHelo);
                WriteOptional(w, "receiving-ip", d.ReceivingIp);
                w.WriteNumber("failed-session-count", d.FailedSessionCount);
                WriteOptional(w, "additional-information", d.AdditionalInformation);
                WriteOptional(w, "failure-reason-code", d.FailureReasonCode);
                w.WriteEndObject();
            }

            w.WriteEndArray();
        }

        w.WriteEndObject();
    }

    private static void WriteOptional(Utf8JsonWriter w, string name, string? value)
    {
        if (!string.IsNullOrEmpty(value))
        {
            w.WriteString(name, value);
        }
    }

    private static string FormatTime(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);

    private static string Sanitize(string part) => part.Replace('!', '_').Replace('/', '_').Replace('\\', '_');
}
