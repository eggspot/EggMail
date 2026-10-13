using System.Text;
using Mta.Auth.AuthenticationResults;
using Mta.Auth.Arc;
using Mta.Auth.Dmarc;
using Mta.Auth.Reports;
using Mta.Dns;
using Mta.Dsn;

namespace Mta.Fuzz;

/// <summary>Inbound bounces and complaints: the RFC 3464 DSN and RFC 5965 ARF parser (the one unauthenticated surface of the bounce listener).</summary>
internal static class DsnArfTarget
{
    public static FuzzTarget Create() => new("dsn-arf", "Inbound DSN (RFC 3464) and ARF (RFC 5965) report parser", Run, Seeds())
    {
        Tokens = Tokens(),
        MutationIterations = 20000,
        MaxInputLength = 128 * 1024,
    };

    private static void Run(ReadOnlySpan<byte> input)
    {
        var report = InboundReportParser.Parse(input.ToArray());
        Guard.Check(report.Recipients.Count <= 100, "more recipients than the maximum");
        if (report.Kind == InboundReportKind.Unrecognized)
        {
            Guard.Check(report.Recipients.Count == 0, "an unrecognized report must not carry recipients");
        }

        foreach (var recipient in report.Recipients)
        {
            NoControls(recipient.FinalRecipient, "Final-Recipient");
            NoControls(recipient.OriginalRecipient, "Original-Recipient");
            NoControls(recipient.Action, "Action");
            NoControls(recipient.Status, "Status");
            NoControls(recipient.DiagnosticCode, "Diagnostic-Code");
            NoControls(recipient.RemoteMta, "Remote-MTA");
            NoControls(recipient.WillRetryUntil, "Will-Retry-Until");
            Guard.Check(recipient.Action is not null, "recipient without action");
            Guard.Check(recipient.DiagnosticCode is null || recipient.DiagnosticCode.Length <= 1024, "diagnostic code longer than the field limit");
            _ = recipient.IsPermanentFailure;
        }

        NoControls(report.ReportingMta, "Reporting-MTA");
        NoControls(report.OriginalMessageId, "Message-ID");
        NoControls(report.FeedbackType, "Feedback-Type");
        NoControls(report.ArfOriginalRecipient, "Original-Rcpt-To");
        NoControls(report.ArfSourceIp, "Source-IP");
    }

    private static void NoControls(string? value, string field) => Guard.Check(value is null || !value.Any(c => c is < ' ' or '\u007f'), $"control character in the extracted {field}: {value?.Replace('\r', '?')}");

    private static IReadOnlyList<byte[]> Seeds() =>
        new[]
        {
            "From: MAILER-DAEMON@mx.example.org\r\nTo: b+token@bounce.example.com\r\nSubject: Undelivered Mail Returned to Sender\r\nAuto-Submitted: auto-replied\r\nMIME-Version: 1.0\r\nContent-Type: multipart/report; report-type=delivery-status; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nThe message could not be delivered.\r\n--B\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; mx.example.org\r\nArrival-Date: Mon, 12 Oct 2026 12:00:00 +0000\r\n\r\nFinal-Recipient: rfc822; gone@dest.example\r\nOriginal-Recipient: rfc822; gone@dest.example\r\nAction: failed\r\nStatus: 5.1.1\r\nRemote-MTA: dns; mx.dest.example\r\nDiagnostic-Code: smtp; 550 5.1.1 No such user\r\n\r\n--B\r\nContent-Type: text/rfc822-headers\r\n\r\nMessage-ID: <abc@example.com>\r\nFrom: sender@example.com\r\n\r\n--B--\r\n",
            "From: fbl@isp.example\r\nTo: b+token@bounce.example.com\r\nContent-Type: multipart/report; report-type=feedback-report; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nspam complaint\r\n--B\r\nContent-Type: message/feedback-report\r\n\r\nFeedback-Type: abuse\r\nUser-Agent: Example/1.0\r\nVersion: 1\r\nOriginal-Rcpt-To: <victim@example.net>\r\nSource-IP: 192.0.2.55\r\n\r\n--B\r\nContent-Type: message/rfc822\r\n\r\nMessage-ID: <abc@example.com>\r\n\r\nbody\r\n--B--\r\n",
            "Content-Type: multipart/report; report-type=delivery-status; boundary=x\r\n\r\n--x\r\nContent-Type: message/delivery-status\r\n\r\nAction: delayed\r\nStatus: 4.4.1\r\nWill-Retry-Until: Fri, 16 Oct 2026 12:00:00 +0000\r\n\r\nAction: failed\r\nStatus: 5.0.0\r\nFinal-Recipient: rfc822; a@b\r\n--x--\r\n",
            "Subject: Out of office\r\nAuto-Submitted: auto-generated\r\n\r\nI am away.\r\n",
            "Content-Type: multipart/report; report-type=delivery-status\r\n\r\nno boundary",
        }.Select(s => Encoding.Latin1.GetBytes(s)).ToList();

    private static IReadOnlyList<byte[]> Tokens() =>
        new[]
        {
            "Content-Type: multipart/report; report-type=delivery-status; boundary=B\r\n", "report-type=feedback-report", "message/delivery-status", "message/feedback-report", "message/rfc822",
            "Final-Recipient: rfc822; ", "Original-Recipient: ", "Action: failed\r\n", "Action: delayed\r\n", "Status: 5.1.1\r\n", "Diagnostic-Code: smtp; ", "Reporting-MTA: dns; ", "Remote-MTA: ",
            "Feedback-Type: abuse\r\n", "Source-IP: ", "Original-Rcpt-To: ", "Auto-Submitted: ", "\r\n\r\n", "--B\r\n", "--B--", "\r\n ", "\0", "\u001b",
        }.Select(s => Encoding.Latin1.GetBytes(s)).ToList();
}

/// <summary>DMARC record, Authentication-Results header and ARC chain parsers: everything an inbound message's authentication headers go through.</summary>
internal static class AuthHeadersTarget
{
    private const string KeyTxt = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu4uB";

    public static FuzzTarget Create() => new("auth-headers", "DMARC record, Authentication-Results and ARC chain parsers", Run, Seeds())
    {
        Tokens = Tokens(),
        MutationIterations = 20000,
        MaxInputLength = 64 * 1024,
    };

    private static void Run(ReadOnlySpan<byte> input)
    {
        string text = input.Length > 0 && (input[0] & 1) == 1 ? Encoding.Latin1.GetString(input) : Encoding.UTF8.GetString(input);

        if (DmarcRecord.TryParse(text, out var dmarc, out string? error))
        {
            Guard.Check(dmarc is not null, "TryParse succeeded without a record");
        }
        else
        {
            Guard.Check(!string.IsNullOrEmpty(error), "a refused DMARC record needs a reason");
        }

        _ = DmarcReportUri.TryParse(text, out _);

        if (AuthenticationResultsParser.TryParse(text, out var header))
        {
            Guard.Check(header is not null && !string.IsNullOrEmpty(header.AuthservId), "Authentication-Results without an authserv-id");
        }

        _ = AuthenticationResultsParser.TryParseMethodResult(text, out _);
        _ = AuthenticationResultsParser.TryReadAuthservId(text, out _);

        // The same bytes as a whole message for the ARC chain (header index, tag lists, canonicalization, key lookups).
        var validator = new ArcValidator(new AnyKeyResolver(), new ArcValidatorOptions());
        var result = validator.ValidateAsync(input.ToArray()).AsTask().GetAwaiter().GetResult();
        Guard.Check(Enum.IsDefined(result.Status), "undefined ARC chain status");
    }

    private static IReadOnlyList<byte[]> Seeds() =>
        new[]
        {
            "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=r; pct=50; rua=mailto:a@example.com!10m,mailto:b@example.com; ruf=mailto:f@example.com; fo=1:d:s; ri=86400",
            "v=DMARC1;p=none",
            "v=DMARC1; p=bogus; pct=999; rua=http://x; adkim=z",
            "mx.example.com 1; dkim=pass (2048-bit key) header.d=example.com header.s=sel header.b=AbCd; spf=pass smtp.mailfrom=a@example.com; dmarc=pass header.from=example.com",
            "mx.example.com; none",
            "mx.example.com 1; dkim=fail reason=\"signature did not verify\" header.i=@example.com (comment (nested)); arc=pass smtp.remote-ip=192.0.2.1",
            "ARC-Seal: i=1; a=rsa-sha256; t=1791806400; cv=none; d=example.com; s=sel; b=AAAA\r\nARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel; t=1791806400; h=from:to:subject; bh=AAAA; b=AAAA\r\nARC-Authentication-Results: i=1; mx.example.com; spf=pass smtp.mailfrom=a@example.com\r\nFrom: a@example.com\r\nTo: b@example.net\r\nSubject: x\r\n\r\nbody\r\n",
            "ARC-Seal: i=2; a=rsa-sha256; cv=pass; d=a; s=b; b=c\r\nARC-Seal: i=1; cv=none; d=a; s=b; b=c\r\nARC-Seal: i=0; i=99\r\n\r\n",
        }.Select(s => Encoding.Latin1.GetBytes(s)).ToList();

    private static IReadOnlyList<byte[]> Tokens() =>
        new[]
        {
            "v=DMARC1; ", "p=reject", "p=none", "pct=", "rua=mailto:", "!10m", "adkim=s", "aspf=r", "fo=", "ri=", "; ", "dkim=pass", "spf=fail", "dmarc=pass", "arc=none", " header.d=", " smtp.mailfrom=",
            " reason=", "(", ")", "\"", "ARC-Seal: ", "ARC-Message-Signature: ", "ARC-Authentication-Results: ", "i=1; ", "i=50; ", "i=51; ", "cv=pass", "cv=fail", "cv=none", "a=rsa-sha256", "\r\n ", "\r\n",
        }.Select(s => Encoding.Latin1.GetBytes(s)).ToList();

    private sealed class AnyKeyResolver : IDnsResolver
    {
        public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default) =>
            new StaticDnsResolver().AddTxt(name, KeyTxt).QueryAsync(name, type, cancellationToken);
    }
}

/// <summary>DMARC aggregate (rua) reports: the XML and gzip reader. Reports arrive from anyone who knows the address.</summary>
internal static class DmarcAggregateTarget
{
    public static FuzzTarget Create() => new("dmarc-aggregate", "DMARC aggregate report reader (XML, gzip)", Run, Seeds())
    {
        Tokens = Tokens(),
        MutationIterations = 15000,
        MaxInputLength = 128 * 1024,
    };

    private static void Run(ReadOnlySpan<byte> input)
    {
        if (DmarcAggregateReportReader.TryRead(input.ToArray(), out var report))
        {
            Guard.Check(report is not null, "TryRead succeeded without a report");
        }
    }

    private static IReadOnlyList<byte[]> Seeds()
    {
        const string Xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<feedback>\n  <report_metadata><org_name>example.net</org_name><email>noreply@example.net</email><report_id>1</report_id><date_range><begin>1791763200</begin><end>1791849599</end></date_range></report_metadata>\n  <policy_published><domain>example.com</domain><adkim>r</adkim><aspf>r</aspf><p>reject</p><sp>reject</sp><pct>100</pct></policy_published>\n  <record><row><source_ip>192.0.2.1</source_ip><count>3</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers><auth_results><dkim><domain>example.com</domain><result>pass</result><selector>sel</selector></dkim><spf><domain>example.com</domain><result>pass</result></spf></auth_results></record>\n</feedback>\n";
        return
        [
            Encoding.UTF8.GetBytes(Xml),
            Gzip(Encoding.UTF8.GetBytes(Xml)),
            Encoding.UTF8.GetBytes("<!DOCTYPE feedback [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">]><feedback><report_metadata><org_name>&b;</org_name></report_metadata></feedback>"),
            Encoding.UTF8.GetBytes("<feedback><record><row><count>99999999999999999999</count><source_ip>not-an-ip</source_ip></row></record></feedback>"),
            Encoding.UTF8.GetBytes("<feedback>"),
        ];
    }

    /// <summary>
    /// A gzip member made of one stored (uncompressed) deflate block, built by hand so that the seed is byte-identical on every platform
    /// and zlib version (the checked-in corpus is compared against the seeds). A real compressor's output would be a different, equally
    /// valid file; the libFuzzer run adds those.
    /// </summary>
    private static byte[] Gzip(byte[] data)
    {
        var output = new List<byte> { 0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xFF, 0x01 };
        output.Add((byte)data.Length);
        output.Add((byte)(data.Length >> 8));
        output.Add((byte)~data.Length);
        output.Add((byte)(~data.Length >> 8));
        output.AddRange(data);
        uint crc = 0xFFFFFFFF;
        foreach (byte b in data)
        {
            crc ^= b;
            for (int bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
            }
        }

        crc = ~crc;
        for (int i = 0; i < 4; i++)
        {
            output.Add((byte)(crc >> (8 * i)));
        }

        for (int i = 0; i < 4; i++)
        {
            output.Add((byte)((uint)data.Length >> (8 * i)));
        }

        return output.ToArray();
    }

    private static IReadOnlyList<byte[]> Tokens() =>
        new[]
        {
            "<feedback>", "</feedback>", "<record>", "</record>", "<row>", "<count>", "</count>", "<source_ip>", "<policy_evaluated>", "<auth_results>", "<dkim>", "<spf>", "<domain>", "<result>",
            "<!DOCTYPE", "<!ENTITY", "&amp;", "&#x0;", "&#xD800;", "<![CDATA[", "]]>", "<?xml", "xmlns=", "\u001f\u008b",
        }.Select(s => Encoding.UTF8.GetBytes(s)).ToList();
}
