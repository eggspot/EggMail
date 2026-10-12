using System.Globalization;
using System.Text;

namespace Mta.Smtp.Server;

/// <summary>Builds the trace header the server adds to every accepted message (RFC 5321 §4.4).</summary>
internal static class ReceivedHeader
{
    public static byte[] Build(SmtpSessionContext s, string serverHostname, string? singleRecipient, string sessionTag, DateTimeOffset now)
    {
        string with = s.TlsActive
            ? (s.AuthenticatedUser is null ? "ESMTPS" : "ESMTPSA")
            : (s.AuthenticatedUser is null ? "ESMTP" : "ESMTPA");
        string helo = Sanitize(s.HeloName ?? "unknown");
        string ip = s.RemoteEndPoint.Address.IsIPv4MappedToIPv6 ? s.RemoteEndPoint.Address.MapToIPv4().ToString() : s.RemoteEndPoint.Address.ToString();
        string literal = ip.Contains(':') ? $"IPv6:{ip}" : ip;
        var sb = new StringBuilder(256);
        sb.Append("Received: from ").Append(helo).Append(" ([").Append(literal).Append("])\r\n");
        sb.Append("\tby ").Append(Sanitize(serverHostname)).Append(" with ").Append(with).Append(" id ").Append(sessionTag);
        if (s.TlsActive && s.TlsProtocol is not null)
        {
            sb.Append("\r\n\t(").Append(Sanitize(s.TlsProtocol));
            if (s.TlsCipherSuite is not null)
            {
                sb.Append(' ').Append(Sanitize(s.TlsCipherSuite));
            }

            sb.Append(')');
        }

        if (singleRecipient is not null)
        {
            sb.Append("\r\n\tfor <").Append(Sanitize(singleRecipient)).Append('>');
        }

        sb.Append(";\r\n\t").Append(now.ToString("ddd, dd MMM yyyy HH:mm:ss '+0000'", CultureInfo.InvariantCulture)).Append("\r\n");
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    /// <summary>Removes anything that could break the header (CR, LF, NUL, control characters, parentheses).</summary>
    private static string Sanitize(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            if (c < 0x20 || c == 0x7F || c == '(' || c == ')' || c == '<' || c == '>' || c == ';')
            {
                sb.Append('_');
            }
            else
            {
                sb.Append(c);
            }
        }

        return sb.ToString();
    }
}
