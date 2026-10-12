using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;

namespace Mta.Auth.AuthenticationResults;

/// <summary>
/// A tolerant parser for incoming Authentication-Results header field bodies (RFC 8601). It is bounded
/// (input length, comment nesting) and never throws; unparseable input yields false.
/// </summary>
public static class AuthenticationResultsParser
{
    /// <summary>The longest field body that is parsed; longer input is rejected.</summary>
    public const int MaxLength = 65536;

    private const int MaxCommentDepth = 32;

    /// <summary>Parses a complete field body: <c>authserv-id [version] ; (none | resinfo *(; resinfo))</c>.</summary>
    /// <param name="fieldBody">The text after <c>Authentication-Results:</c>.</param>
    /// <param name="header">The parsed header.</param>
    public static bool TryParse(string? fieldBody, [NotNullWhen(true)] out AuthenticationResultsHeader? header)
    {
        header = null;
        if (fieldBody is null || fieldBody.Length > MaxLength)
        {
            return false;
        }

        var r = new Reader(fieldBody);
        if (!r.SkipCfws(out _) || !r.TryReadValue(out string? id) || id.Length == 0)
        {
            return false;
        }

        if (!r.SkipCfws(out _))
        {
            return false;
        }

        int? version = null;
        if (!r.AtEnd && char.IsAsciiDigit(r.Current))
        {
            string digits = r.ReadWhile(char.IsAsciiDigit);
            if (digits.Length > 4 || !r.SkipCfws(out _))
            {
                return false;
            }

            version = int.Parse(digits, NumberStyles.None, CultureInfo.InvariantCulture);
        }

        if (r.AtEnd || r.Current != ';')
        {
            return false;
        }

        r.Advance();
        if (!r.SkipCfws(out _))
        {
            return false;
        }

        var results = new List<AuthenticationMethodResult>();
        if (r.RestStartsWithNone())
        {
            r.Advance(4);
            if (!r.SkipCfws(out _) || !r.AtEnd)
            {
                return false;
            }

            header = new AuthenticationResultsHeader(id, version, results);
            return true;
        }

        while (true)
        {
            if (r.AtEnd)
            {
                break; // tolerate a trailing ';'
            }

            if (!TryReadResInfo(r, out AuthenticationMethodResult? result))
            {
                return false;
            }

            results.Add(result);
            if (r.AtEnd)
            {
                break;
            }

            // TryReadResInfo stops at ';' or the end.
            r.Advance();
            if (!r.SkipCfws(out _))
            {
                return false;
            }

            if (results.Count > 256)
            {
                return false;
            }
        }

        if (results.Count == 0)
        {
            return false;
        }

        header = new AuthenticationResultsHeader(id, version, results);
        return true;
    }

    /// <summary>Parses one preformatted clause such as <c>dkim=pass header.d=example.com header.s=sel</c>.</summary>
    /// <param name="fragment">The clause, without a leading <c>;</c>.</param>
    /// <param name="result">The parsed clause.</param>
    public static bool TryParseMethodResult(string? fragment, [NotNullWhen(true)] out AuthenticationMethodResult? result)
    {
        result = null;
        if (fragment is null || fragment.Length > MaxLength)
        {
            return false;
        }

        var r = new Reader(fragment);
        if (!r.SkipCfws(out _) || !TryReadResInfo(r, out result))
        {
            result = null;
            return false;
        }

        if (!r.AtEnd)
        {
            result = null;
            return false; // a ';' inside means more than one clause
        }

        return true;
    }

    /// <summary>Reads only the authserv-id from a field body (cheap check used when deciding whether to trust a header).</summary>
    /// <param name="fieldBody">The text after <c>Authentication-Results:</c>.</param>
    /// <param name="authservId">The identifier.</param>
    public static bool TryReadAuthservId(string? fieldBody, [NotNullWhen(true)] out string? authservId)
    {
        authservId = null;
        if (fieldBody is null || fieldBody.Length > MaxLength)
        {
            return false;
        }

        var r = new Reader(fieldBody);
        if (!r.SkipCfws(out _) || !r.TryReadValue(out string? id) || id.Length == 0)
        {
            return false;
        }

        authservId = id;
        return true;
    }

    private static bool TryReadResInfo(Reader r, [NotNullWhen(true)] out AuthenticationMethodResult? result)
    {
        result = null;
        string method = r.ReadWhile(IsKeywordChar);
        if (method.Length == 0 || !IsLetDig(method[0]))
        {
            return false;
        }

        if (!r.SkipCfws(out _))
        {
            return false;
        }

        int? methodVersion = null;
        if (!r.AtEnd && r.Current == '/')
        {
            r.Advance();
            if (!r.SkipCfws(out _))
            {
                return false;
            }

            string v = r.ReadWhile(char.IsAsciiDigit);
            if (v.Length is 0 or > 4 || !r.SkipCfws(out _))
            {
                return false;
            }

            methodVersion = int.Parse(v, NumberStyles.None, CultureInfo.InvariantCulture);
        }

        if (r.AtEnd || r.Current != '=')
        {
            return false;
        }

        r.Advance();
        if (!r.SkipCfws(out _))
        {
            return false;
        }

        string resultKeyword = r.ReadWhile(IsKeywordChar);
        if (resultKeyword.Length == 0)
        {
            return false;
        }

        if (!r.SkipCfws(out string? comment))
        {
            return false;
        }

        string? reason = null;
        var properties = new List<AuthenticationResultProperty>();
        while (!r.AtEnd && r.Current != ';')
        {
            string first = r.ReadWhile(IsPropertyChar);
            if (first.Length == 0 || !r.SkipCfws(out _))
            {
                return false;
            }

            if (r.AtEnd)
            {
                return false;
            }

            if (r.Current == '=')
            {
                if (!first.Equals("reason", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                r.Advance();
                if (!r.SkipCfws(out _) || !r.TryReadValue(out string? reasonText))
                {
                    return false;
                }

                reason = reasonText;
            }
            else if (r.Current == '.')
            {
                r.Advance();
                if (!r.SkipCfws(out _))
                {
                    return false;
                }

                string property = r.ReadWhile(IsPropertyChar);
                if (property.Length == 0 || !r.SkipCfws(out _) || r.AtEnd || r.Current != '=')
                {
                    return false;
                }

                r.Advance();
                if (!r.SkipCfws(out _) || !r.TryReadValue(out string? value))
                {
                    return false;
                }

                properties.Add(new AuthenticationResultProperty(first.ToLowerInvariant(), property.ToLowerInvariant(), value));
            }
            else
            {
                return false;
            }

            if (!r.SkipCfws(out string? later))
            {
                return false;
            }

            comment ??= later;
            if (properties.Count > 64)
            {
                return false;
            }
        }

        result = new AuthenticationMethodResult(method.ToLowerInvariant(), methodVersion, resultKeyword.ToLowerInvariant(), reason, comment, properties);
        return true;
    }

    private static bool IsLetDig(char c) => char.IsAsciiLetterOrDigit(c);

    private static bool IsKeywordChar(char c) => char.IsAsciiLetterOrDigit(c) || c == '-';

    private static bool IsPropertyChar(char c) => char.IsAsciiLetterOrDigit(c) || c is '-' or '_';

    private sealed class Reader(string text)
    {
        private int _pos;

        public bool AtEnd => _pos >= text.Length;

        public char Current => text[_pos];

        public void Advance(int count = 1) => _pos += count;

        public bool RestStartsWithNone()
        {
            if (string.Compare(text, _pos, "none", 0, 4, StringComparison.OrdinalIgnoreCase) != 0)
            {
                return false;
            }

            int end = _pos + 4;
            return end >= text.Length || char.IsWhiteSpace(text[end]) || text[end] == '(';
        }

        public string ReadWhile(Func<char, bool> predicate)
        {
            int start = _pos;
            while (_pos < text.Length && predicate(text[_pos]))
            {
                _pos++;
            }

            return text[start.._pos];
        }

        /// <summary>Skips whitespace and comments; returns the text of the comments seen (joined), or null.</summary>
        public bool SkipCfws(out string? comment)
        {
            comment = null;
            StringBuilder? sb = null;
            while (_pos < text.Length)
            {
                char c = text[_pos];
                if (c is ' ' or '\t' or '\r' or '\n')
                {
                    _pos++;
                }
                else if (c == '(')
                {
                    if (!ReadComment(out string body))
                    {
                        return false;
                    }

                    sb ??= new StringBuilder();
                    if (sb.Length > 0)
                    {
                        sb.Append(' ');
                    }

                    sb.Append(body);
                }
                else
                {
                    break;
                }
            }

            comment = sb?.ToString();
            return true;
        }

        private bool ReadComment(out string body)
        {
            body = string.Empty;
            var sb = new StringBuilder();
            int depth = 0;
            while (_pos < text.Length)
            {
                char c = text[_pos++];
                if (c == '\\' && _pos < text.Length)
                {
                    sb.Append(text[_pos++]);
                }
                else if (c == '(')
                {
                    if (++depth > MaxCommentDepth)
                    {
                        return false;
                    }

                    if (depth > 1)
                    {
                        sb.Append(c);
                    }
                }
                else if (c == ')')
                {
                    if (--depth == 0)
                    {
                        body = sb.ToString();
                        return true;
                    }

                    sb.Append(c);
                }
                else
                {
                    sb.Append(c is '\r' or '\n' or '\t' ? ' ' : c);
                }
            }

            return false; // unterminated
        }

        /// <summary>Reads a quoted-string (unescaped) or a bare word that ends at whitespace, ';' or '('.</summary>
        public bool TryReadValue([NotNullWhen(true)] out string? value)
        {
            value = null;
            if (AtEnd)
            {
                return false;
            }

            if (Current == '"')
            {
                _pos++;
                var sb = new StringBuilder();
                while (_pos < text.Length)
                {
                    char c = text[_pos++];
                    if (c == '\\' && _pos < text.Length)
                    {
                        sb.Append(text[_pos++]);
                    }
                    else if (c == '"')
                    {
                        value = sb.ToString();
                        return true;
                    }
                    else
                    {
                        sb.Append(c is '\r' or '\n' or '\t' ? ' ' : c);
                    }
                }

                return false;
            }

            int start = _pos;
            while (_pos < text.Length && text[_pos] is not (' ' or '\t' or '\r' or '\n' or ';' or '('))
            {
                _pos++;
            }

            if (_pos == start)
            {
                return false;
            }

            value = text[start.._pos];
            return true;
        }
    }
}
