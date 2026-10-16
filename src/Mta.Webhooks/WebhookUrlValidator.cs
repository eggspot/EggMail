using System.Net;

namespace Mta.Webhooks;

/// <summary>Validates a webhook endpoint URL when it is registered (delivery re-validates every resolved address).</summary>
public static class WebhookUrlValidator
{
    public static bool TryValidate(string? url, bool allowHttp, IReadOnlyList<IpNetwork> allowlist, out string error)
    {
        error = "";
        if (string.IsNullOrWhiteSpace(url) || url.Length > 2048 || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            error = "The URL is not a valid absolute URL.";
            return false;
        }

        // Uri tolerates (and percent-encodes) line breaks and spaces inside a URL; the stored text would carry them into logs and the dashboard.
        if (url.Trim().Any(c => char.IsControl(c) || char.IsWhiteSpace(c) || c is '\u2028' or '\u2029' or (>= '\u202A' and <= '\u202E') or (>= '\u2066' and <= '\u2069')))
        {
            error = "The URL must not contain spaces or control characters.";
            return false;
        }

        if (uri.Scheme != Uri.UriSchemeHttps && !(allowHttp && uri.Scheme == Uri.UriSchemeHttp))
        {
            error = allowHttp ? "Only http and https URLs are supported." : "Only https URLs are allowed.";
            return false;
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            error = "Credentials in the URL are not allowed.";
            return false;
        }

        // "127.0.0.1." and "localhost." are the same hosts as without the final dot; "x.localhost" is loopback by RFC 6761.
        string host = uri.Host.TrimEnd('.');
        if (host.Length == 0 || (allowlist.Count == 0 && (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))))
        {
            error = "The host is not allowed.";
            return false;
        }

        if (IPAddress.TryParse(host.Trim('[', ']'), out var ip) && !SsrfGuard.IsPubliclyRoutable(ip) && !allowlist.Any(n => n.Contains(ip)))
        {
            error = "The address is in a non-public range.";
            return false;
        }

        return true;
    }
}
