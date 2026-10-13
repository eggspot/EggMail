using System.Text;
using Mta.Tls.MtaSts;
using Mta.Tls.TlsRpt;

namespace Mta.Fuzz;

/// <summary>MTA-STS: the policy file (string and UTF-8 forms) and the <c>_mta-sts</c> TXT record.</summary>
internal static class MtaStsTarget
{
    public static FuzzTarget Create() => new("mta-sts", "MTA-STS policy file and TXT record parsers, MX pattern matching", Run, Seeds())
    {
        Tokens = Tokens(),
        MutationIterations = 40000,
        MaxInputLength = 80 * 1024,
    };

    private static void Run(ReadOnlySpan<byte> input)
    {
        bool bytesOk = MtaStsPolicyParser.TryParse(input, out var fromBytes, out string? bytesError);
        if (bytesOk)
        {
            Check(fromBytes!);
        }
        else
        {
            Guard.Check(!string.IsNullOrEmpty(bytesError), "a refused policy needs a reason");
        }

        string text = Encoding.UTF8.GetString(input);
        if (MtaStsPolicyParser.TryParse(text, out var fromText, out _))
        {
            Check(fromText!);
        }

        _ = MtaStsTxtParser.TryParse(text, out var txt);
        Guard.Check(txt is null || txt.Id.Length is >= 1 and <= 32, "an STS id is 1 to 32 characters");
    }

    private static void Check(MtaStsPolicy policy)
    {
        Guard.Check(policy.MxPatterns.Count <= MtaStsPolicyParser.MaxMxPatterns, "more MX patterns than the maximum");
        Guard.Check(policy.MaxAgeSeconds is >= 0 and <= MtaStsPolicyParser.MaxAgeCeilingSeconds, "max_age outside 0..ceiling");
        _ = policy.IsMxAllowed("mx1.example.com");
        _ = policy.IsMxAllowed(string.Empty);
        foreach (string pattern in policy.MxPatterns)
        {
            _ = policy.IsMxAllowed(pattern.TrimStart('*'));
        }
    }

    private static IReadOnlyList<byte[]> Seeds() =>
        new[]
        {
            "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmax_age: 604800\r\n",
            "version: STSv1\nmode: testing\nmx: a.example.org\nmax_age: 86400\n",
            "version: STSv1\r\nmode: none\r\nmax_age: 0\r\n",
            "version: STSv1\r\nmode: enforce\r\nmx: *.*.example.com\r\nmx: \r\nmx: -bad-.example\r\nmax_age: 99999999999\r\nfoo: bar\r\n",
            "version:STSv1\r\nmode:enforce\r\nmx:mail.example.com\r\nmax_age:1\r\n\r\n",
            "v=STSv1; id=20260101T000000;",
            "v=STSv1; id=a b",
            "version: STSv1\r\nversion: STSv1\r\nmode: enforce\r\nmode: testing\r\n",
        }.Select(s => Encoding.UTF8.GetBytes(s)).ToList();

    private static IReadOnlyList<byte[]> Tokens() =>
        new[]
        {
            "version: STSv1\r\n", "mode: enforce\r\n", "mode: testing\r\n", "mode: none\r\n", "mx: ", "max_age: ", "*.", "\r\n", "\n", ": ", ":", "v=STSv1", "; id=", "\0", "é", "xn--",
        }.Select(s => Encoding.UTF8.GetBytes(s)).ToList();
}

/// <summary>TLS-RPT: the <c>_smtp._tls</c> TXT record and its reporting endpoints.</summary>
internal static class TlsRptTarget
{
    public static FuzzTarget Create() => new("tls-rpt", "TLS-RPT TXT record and endpoint (mailto:/https:) parsers", Run, Seeds())
    {
        Tokens = Tokens(),
        MutationIterations = 50000,
        MaxInputLength = 8 * 1024,
    };

    private static void Run(ReadOnlySpan<byte> input)
    {
        string text = input.Length > 0 && (input[0] & 1) == 1 ? Encoding.Latin1.GetString(input) : Encoding.UTF8.GetString(input);
        if (TlsRptRecordParser.TryParse(text, out var record))
        {
            Guard.Check(record is not null && record.Endpoints.Count is >= 1 and <= TlsRptRecordParser.MaxEndpoints, "a valid record has 1..MaxEndpoints endpoints");
            foreach (var endpoint in record.Endpoints)
            {
                Guard.Check(endpoint.Kind != TlsRptEndpointKind.Mailto || !string.IsNullOrEmpty(endpoint.MailtoAddress), "mailto endpoint without an address");
                Guard.Check(endpoint.Kind != TlsRptEndpointKind.Https || endpoint.Uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase), "https endpoint with another scheme");
            }
        }

        _ = TlsRptRecordParser.TryParseEndpoint(text, out _);
    }

    private static IReadOnlyList<byte[]> Seeds() =>
        new[]
        {
            "v=TLSRPTv1; rua=mailto:reports@example.com",
            "v=TLSRPTv1;rua=mailto:a@example.com,https://reports.example.com/tlsrpt",
            "v=TLSRPTv1; rua=mailto:a@example.com?subject=x&body=y, mailto:b@example.org , https://x.example/y, ftp://nope, https://",
            "v=TLSRPTv1; rua=",
            "v=TLSRPTv1; foo=bar; rua=https://a.example/%zz",
            "v=TLSRPTv2; rua=mailto:a@b",
            "https://reports.example.com/a b",
            "mailto:\"quoted\"@example.com",
        }.Select(s => Encoding.UTF8.GetBytes(s)).ToList();

    private static IReadOnlyList<byte[]> Tokens() =>
        new[]
        {
            "v=TLSRPTv1", ";", "; ", "rua=", "mailto:", "https://", "http://", ",", " ", "?", "&", "%", "@", "\"", "<", ">", "\0", "\r\n",
        }.Select(s => Encoding.UTF8.GetBytes(s)).ToList();
}
