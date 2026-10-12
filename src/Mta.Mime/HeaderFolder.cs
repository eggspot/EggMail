using System.Text;

namespace Mta.Mime;

/// <summary>Validation of header names and values; every header written by this library goes through it.</summary>
public static class HeaderValidator
{
    /// <summary>Longest accepted header field name.</summary>
    public const int MaxNameLength = 128;

    /// <summary>
    /// Checks a field name: 1 to <see cref="MaxNameLength"/> printable ASCII characters other than the colon.
    /// </summary>
    /// <exception cref="HeaderInjectionException">The name is empty, too long or contains CR, LF, NUL, whitespace, colon or non-printable characters.</exception>
    public static void ValidateName(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (name.Length == 0)
        {
            throw new HeaderInjectionException(name, "empty header name");
        }

        if (name.Length > MaxNameLength)
        {
            throw new HeaderInjectionException(name, "header name too long");
        }

        foreach (char c in name)
        {
            if (c is '\r' or '\n' or '\0')
            {
                throw new HeaderInjectionException(name, "header name contains CR, LF or NUL");
            }

            if (c <= ' ' || c >= 127 || c == ':')
            {
                throw new HeaderInjectionException(name, "header name contains a character that is not allowed in a field name");
            }
        }
    }

    /// <summary>
    /// Checks a value that is about to be written. CR, LF, NUL and other control characters (tab excepted) are rejected, as are
    /// the Unicode line separators U+0085, U+2028 and U+2029. Non-ASCII characters are rejected unless <paramref name="allowNonAscii"/>.
    /// </summary>
    /// <exception cref="HeaderInjectionException">The value is not acceptable.</exception>
    public static void ValidateValue(string name, string value, bool allowNonAscii)
    {
        ArgumentNullException.ThrowIfNull(value);
        foreach (char c in value)
        {
            if (c is '\r' or '\n' or '\0')
            {
                throw new HeaderInjectionException(name, "header value contains CR, LF or NUL");
            }

            if ((c < ' ' && c != '\t') || c == 127)
            {
                throw new HeaderInjectionException(name, "header value contains a control character");
            }

            if (c > 127)
            {
                if (!allowNonAscii)
                {
                    throw new HeaderInjectionException(name, "header value contains non-ASCII characters");
                }

                if (c is '\u0085' or '\u2028' or '\u2029')
                {
                    throw new HeaderInjectionException(name, "header value contains a Unicode line separator");
                }
            }
        }
    }
}

/// <summary>
/// Folds header fields (RFC 5322 section 2.2.3): lines are broken at existing whitespace so that they stay within
/// 78 columns where possible. A single token that cannot be broken may exceed 78 columns but never 998 bytes.
/// </summary>
public static class HeaderFolder
{
    /// <summary>The recommended maximum line length (excluding CRLF).</summary>
    public const int PreferredLineLength = 78;

    /// <summary>The hard maximum line length (excluding CRLF).</summary>
    public const int MaxLineLength = 998;

    /// <summary>Returns <c>Name: value</c> folded, ending with CRLF. The inputs are validated.</summary>
    /// <exception cref="HeaderInjectionException">Name or value contains CR, LF, NUL or other control characters.</exception>
    /// <exception cref="MessageBuildException">An unbreakable token would make a line longer than 998 bytes.</exception>
    public static string Fold(string name, string value, bool allowNonAscii = false)
    {
        var sb = new StringBuilder(name.Length + value.Length + 16);
        AppendField(sb, name, value, allowNonAscii);
        return sb.ToString();
    }

    /// <summary>Appends the folded field and CRLF to <paramref name="sb"/>.</summary>
    public static void AppendField(StringBuilder sb, string name, string value, bool allowNonAscii = false)
    {
        HeaderValidator.ValidateName(name);
        HeaderValidator.ValidateValue(name, value, allowNonAscii);

        int lineStart = sb.Length;
        sb.Append(name).Append(':');
        int i = 0;
        // The first token follows ": ".
        while (i < value.Length && value[i] is ' ' or '\t')
        {
            i++;
        }

        bool lineHasToken = false;
        int lineExtraBytes = 0;
        sb.Append(' ');
        int end = value.Length;
        while (end > i && value[end - 1] is ' ' or '\t')
        {
            end--;
        }

        while (i < end)
        {
            int wsStart = i;
            while (i < end && value[i] is ' ' or '\t')
            {
                i++;
            }

            int wsEnd = i;
            int tokenStart = i;
            while (i < end && value[i] is not (' ' or '\t'))
            {
                i++;
            }

            int tokenLength = i - tokenStart;
            if (tokenLength == 0)
            {
                break;
            }

            int column = sb.Length - lineStart;
            if (lineHasToken)
            {
                int wsLength = wsEnd - wsStart;
                if (column + wsLength + tokenLength > PreferredLineLength)
                {
                    // Fold at the whitespace: the line break replaces nothing; the whitespace begins the next line.
                    sb.Append("\r\n");
                    lineStart = sb.Length;
                    lineExtraBytes = 0;
                    if (wsLength == 0)
                    {
                        sb.Append(' ');
                    }
                    else
                    {
                        sb.Append(value, wsStart, wsLength);
                    }
                }
                else
                {
                    sb.Append(value, wsStart, wsEnd - wsStart);
                }
            }

            sb.Append(value, tokenStart, tokenLength);
            lineHasToken = true;
            if (allowNonAscii)
            {
                lineExtraBytes += Encoding.UTF8.GetByteCount(value.AsSpan(tokenStart, tokenLength)) - tokenLength;
            }

            if ((sb.Length - lineStart) + lineExtraBytes > MaxLineLength)
            {
                throw new MessageBuildException($"Header '{name}' contains a token that cannot be folded and makes a line longer than {MaxLineLength} bytes.");
            }
        }

        if (!lineHasToken)
        {
            sb.Length--; // empty value: "Name:" without a trailing space
        }

        sb.Append("\r\n");
    }
}
