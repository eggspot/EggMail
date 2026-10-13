using System.Buffers;
using System.Globalization;
using System.Text;

namespace Mta.Smtp.Server;

/// <summary>
/// Builds the trace header the server adds to every accepted message (RFC 5321 §4.4). One instance per session: the parts that only change
/// with the greeting name, the TLS state or the authenticated user are built once and reused, so a message costs one exactly sized array.
/// </summary>
internal sealed class ReceivedHeaderBuilder
{
    // The inputs of the cached parts; strings are compared by reference (a session replaces them, it never edits them).
    private string? _helo;
    private string? _authenticatedUser;
    private string? _tlsProtocol;
    private string? _tlsCipherSuite;
    private bool _tlsActive;
    private bool _built;

    private byte[] _head = [];      // "Received: from helo ([ip])\r\n\tby host with ESMTP id "
    private byte[] _tlsPart = [];   // "\r\n\t(TLSv1.3 cipher)" or empty

    public byte[] Build(SmtpSessionContext s, string serverHostname, string? singleRecipient, ReadOnlySpan<byte> sessionTag, DateTimeOffset now)
    {
        if (!_built || !ReferenceEquals(_helo, s.HeloName) || !ReferenceEquals(_authenticatedUser, s.AuthenticatedUser)
            || _tlsActive != s.TlsActive || !ReferenceEquals(_tlsProtocol, s.TlsProtocol) || !ReferenceEquals(_tlsCipherSuite, s.TlsCipherSuite))
        {
            Rebuild(s, serverHostname);
        }

        int recipientBytes = singleRecipient is null ? 0 : Encoding.UTF8.GetMaxByteCount(singleRecipient.Length);
        int capacity = _head.Length + sessionTag.Length + _tlsPart.Length + recipientBytes + 64;
        byte[] rented = ArrayPool<byte>.Shared.Rent(capacity);
        try
        {
            Span<byte> buffer = rented;
            int n = 0;
            _head.CopyTo(buffer[n..]);
            n += _head.Length;
            sessionTag.CopyTo(buffer[n..]);
            n += sessionTag.Length;
            _tlsPart.CopyTo(buffer[n..]);
            n += _tlsPart.Length;
            if (singleRecipient is not null)
            {
                ReadOnlySpan<byte> forClause = "\r\n\tfor <"u8;
                forClause.CopyTo(buffer[n..]);
                n += forClause.Length;
                n += WriteSanitized(singleRecipient, buffer[n..]);
                buffer[n++] = (byte)'>';
            }

            buffer[n++] = (byte)';';
            buffer[n++] = (byte)'\r';
            buffer[n++] = (byte)'\n';
            buffer[n++] = (byte)'\t';
            now.TryFormat(buffer[n..], out int dateBytes, "ddd, dd MMM yyyy HH:mm:ss '+0000'", CultureInfo.InvariantCulture);
            n += dateBytes;
            buffer[n++] = (byte)'\r';
            buffer[n++] = (byte)'\n';
            return buffer[..n].ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private void Rebuild(SmtpSessionContext s, string serverHostname)
    {
        string with = s.TlsActive
            ? (s.AuthenticatedUser is null ? "ESMTPS" : "ESMTPSA")
            : (s.AuthenticatedUser is null ? "ESMTP" : "ESMTPA");
        string helo = Sanitize(s.HeloName ?? "unknown");
        string ip = s.RemoteEndPoint.Address.IsIPv4MappedToIPv6 ? s.RemoteEndPoint.Address.MapToIPv4().ToString() : s.RemoteEndPoint.Address.ToString();
        string literal = ip.Contains(':') ? $"IPv6:{ip}" : ip;
        _head = Encoding.UTF8.GetBytes($"Received: from {helo} ([{literal}])\r\n\tby {Sanitize(serverHostname)} with {with} id ");

        var tls = new StringBuilder();
        if (s.TlsActive && s.TlsProtocol is not null)
        {
            tls.Append("\r\n\t(").Append(Sanitize(s.TlsProtocol));
            if (s.TlsCipherSuite is not null)
            {
                tls.Append(' ').Append(Sanitize(s.TlsCipherSuite));
            }

            tls.Append(')');
        }

        _tlsPart = Encoding.UTF8.GetBytes(tls.ToString());
        _helo = s.HeloName;
        _authenticatedUser = s.AuthenticatedUser;
        _tlsActive = s.TlsActive;
        _tlsProtocol = s.TlsProtocol;
        _tlsCipherSuite = s.TlsCipherSuite;
        _built = true;
    }

    /// <summary>Writes <paramref name="value"/> as UTF-8 with the characters that could break the header replaced (see <see cref="Sanitize"/>).</summary>
    private static int WriteSanitized(string value, Span<byte> destination)
    {
        Span<char> chars = value.Length <= 512 ? stackalloc char[value.Length] : new char[value.Length];
        for (int i = 0; i < value.Length; i++)
        {
            chars[i] = IsUnsafe(value[i]) ? '_' : value[i];
        }

        return Encoding.UTF8.GetBytes(chars, destination);
    }

    private static bool IsUnsafe(char c) => c < 0x20 || c == 0x7F || c == '(' || c == ')' || c == '<' || c == '>' || c == ';';

    /// <summary>Removes anything that could break the header (CR, LF, NUL, control characters, parentheses).</summary>
    private static string Sanitize(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            sb.Append(IsUnsafe(c) ? '_' : c);
        }

        return sb.ToString();
    }
}
