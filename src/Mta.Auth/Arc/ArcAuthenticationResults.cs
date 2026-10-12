using System.Globalization;
using System.Net;
using System.Text;
using Mta.Auth.AuthenticationResults;

namespace Mta.Auth.Arc;

/// <summary>
/// Formats the <c>arc=</c> method result of an RFC 8601 Authentication-Results header (RFC 8617 section 7). The fragment is accepted by
/// <see cref="AuthenticationResultsBuilder.AddArc(string)"/> and by the Authentication-Results parser.
/// </summary>
public static class ArcAuthenticationResults
{
    /// <summary>The RFC 8601 result keyword for a chain status: <c>none</c>, <c>pass</c> or <c>fail</c>.</summary>
    /// <param name="status">The chain status.</param>
    public static string ResultName(ArcChainStatus status) => status switch
    {
        ArcChainStatus.Pass => "pass",
        ArcChainStatus.Fail => "fail",
        _ => "none",
    };

    /// <summary>
    /// Formats the result as a method clause without a leading authserv-id or trailing semicolon, for example
    /// <c>arc=pass header.oldest-pass=1 smtp.remote-ip=192.0.2.1</c>. A failure carries <c>reason="..."</c>.
    /// </summary>
    /// <param name="result">The validation result.</param>
    /// <param name="remoteIp">The IP address of the SMTP client that delivered the message, reported as <c>smtp.remote-ip</c> when given.</param>
    public static string Format(ArcChainResult result, IPAddress? remoteIp = null)
    {
        ArgumentNullException.ThrowIfNull(result);
        var sb = new StringBuilder(64);
        sb.Append("arc=").Append(ResultName(result.Status));

        if (result.Status == ArcChainStatus.Fail && !string.IsNullOrEmpty(result.Reason))
        {
            sb.Append(" reason=").Append(Quote(result.Reason));
        }

        if (result.Status == ArcChainStatus.Pass && result.OldestPassingInstance is int oldest)
        {
            sb.Append(" header.oldest-pass=").Append(oldest.ToString(CultureInfo.InvariantCulture));
        }

        if (remoteIp is not null)
        {
            string ip = remoteIp.IsIPv4MappedToIPv6 ? remoteIp.MapToIPv4().ToString() : remoteIp.ToString();
            int scope = ip.IndexOf('%', StringComparison.Ordinal);
            if (scope >= 0) { ip = ip.Substring(0, scope); }
            sb.Append(" smtp.remote-ip=").Append(ip.Contains(':', StringComparison.Ordinal) ? Quote(ip) : ip);
        }

        return sb.ToString();
    }

    private static string Quote(string text)
    {
        var sb = new StringBuilder(text.Length + 2);
        sb.Append('"');
        foreach (char c in text)
        {
            if (c < 0x20 || c > 0x7E) { sb.Append(' '); }
            else if (c is '"' or '\\') { sb.Append('\\').Append(c); }
            else { sb.Append(c); }
        }

        sb.Append('"');
        return sb.ToString();
    }
}
