namespace Mta.Mime;

/// <summary>
/// Thrown when a header name or value contains CR, LF or NUL (or a name contains characters that are not allowed in
/// a field name). Header injection is always rejected, never sanitized.
/// </summary>
public sealed class HeaderInjectionException : ArgumentException
{
    public HeaderInjectionException(string headerName, string reason)
        : base($"Rejected header '{Printable(headerName)}': {reason}", nameof(headerName))
    {
        HeaderName = headerName;
        Reason = reason;
    }

    /// <summary>The offending header name (as supplied; may itself contain control characters).</summary>
    public string HeaderName { get; }

    /// <summary>Why the header was rejected.</summary>
    public string Reason { get; }

    private static string Printable(string s)
    {
        if (s.Length > 64)
        {
            s = s[..64] + "...";
        }

        return string.Create(s.Length, s, static (span, src) =>
        {
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = src[i] is < ' ' or (>= (char)0x7F and < (char)0xA0) ? '?' : src[i];
            }
        });
    }
}

/// <summary>Thrown by <see cref="MessageBuilder"/> and <see cref="MessageHeaderEditor"/> when the model cannot be turned into a valid message.</summary>
public sealed class MessageBuildException : InvalidOperationException
{
    public MessageBuildException(string message)
        : base(message)
    {
    }
}
