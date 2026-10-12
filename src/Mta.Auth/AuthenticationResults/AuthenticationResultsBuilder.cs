using System.Globalization;
using System.Text;
using Mta.Auth.Dmarc;
using Mta.Auth.Spf;

namespace Mta.Auth.AuthenticationResults;

/// <summary>Which SPF identity a result is about (the property <c>smtp.mailfrom</c> or <c>smtp.helo</c>).</summary>
public enum SpfIdentityKind
{
    /// <summary>The MAIL FROM address or domain (<c>smtp.mailfrom</c>).</summary>
    MailFrom,

    /// <summary>The HELO/EHLO domain (<c>smtp.helo</c>).</summary>
    Helo,
}

/// <summary>
/// Builds an Authentication-Results header field (RFC 8601): <c>authserv-id; method=result (comment) ptype.property=value; ...</c>.
/// Values are quoted when they are not a token or <c>[local@]domain</c>, control characters can never reach the output
/// (no header injection), and long fields are folded at 78 columns with CRLF + TAB. Not thread safe.
/// </summary>
public sealed class AuthenticationResultsBuilder
{
    /// <summary>The header field name.</summary>
    public const string HeaderName = "Authentication-Results";

    private const int FoldColumn = 78;

    private readonly List<AuthenticationMethodResult> _results = [];

    /// <summary>Creates a builder.</summary>
    /// <param name="authservId">The authentication server identifier: this MTA's host name or administrative domain.</param>
    /// <param name="allowUtf8">When true, non-ASCII characters in values and comments are kept (RFC 8616); otherwise they become <c>?</c>.</param>
    public AuthenticationResultsBuilder(string authservId, bool allowUtf8 = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authservId);
        AuthservId = authservId.Trim();
        AllowUtf8 = allowUtf8;
    }

    /// <summary>The authentication server identifier.</summary>
    public string AuthservId { get; }

    /// <summary>Whether non-ASCII text is preserved.</summary>
    public bool AllowUtf8 { get; }

    /// <summary>The explicit header version to emit; null (the default) omits it, meaning version 1.</summary>
    public int? Version { get; set; }

    /// <summary>The method results added so far.</summary>
    public IReadOnlyList<AuthenticationMethodResult> Results => _results;

    /// <summary>Adds a generic method result.</summary>
    /// <param name="method">The method keyword (letters, digits, hyphen).</param>
    /// <param name="result">The result keyword.</param>
    /// <param name="properties">Properties as (ptype, property, value) triples.</param>
    /// <param name="reason">Optional human-readable reason (<c>reason="..."</c>).</param>
    /// <param name="comment">Optional comment placed after the result.</param>
    /// <param name="methodVersion">Optional method version.</param>
    /// <exception cref="ArgumentException">A keyword is not a valid RFC 8601 keyword (these are programmer-supplied constants).</exception>
    public AuthenticationResultsBuilder Add(
        string method,
        string result,
        IEnumerable<(string Ptype, string Property, string Value)>? properties = null,
        string? reason = null,
        string? comment = null,
        int? methodVersion = null)
    {
        RequireKeyword(method, nameof(method));
        RequireKeyword(result, nameof(result));
        var props = new List<AuthenticationResultProperty>();
        foreach ((string ptype, string property, string value) in properties ?? [])
        {
            RequireKeyword(ptype, nameof(properties));
            RequireKeyword(property, nameof(properties));
            props.Add(new AuthenticationResultProperty(ptype.ToLowerInvariant(), property.ToLowerInvariant(), Sanitize(value)));
        }

        _results.Add(new AuthenticationMethodResult(
            method.ToLowerInvariant(),
            methodVersion,
            result.ToLowerInvariant(),
            reason is null ? null : Sanitize(reason),
            comment is null ? null : Sanitize(comment),
            props));
        return this;
    }

    /// <summary>Adds a preformatted clause such as <c>dkim=pass header.d=example.com header.s=sel</c>; it is parsed and re-emitted so it cannot break the header.</summary>
    /// <param name="fragment">One clause without a leading semicolon.</param>
    /// <exception cref="ArgumentException">The fragment is not a single valid clause.</exception>
    public AuthenticationResultsBuilder AddFragment(string fragment)
    {
        if (!TryAddFragment(fragment))
        {
            throw new ArgumentException("Not a valid Authentication-Results clause.", nameof(fragment));
        }

        return this;
    }

    /// <summary>Like <see cref="AddFragment"/> but returns false instead of throwing; use it for fragments built from message content.</summary>
    /// <param name="fragment">One clause without a leading semicolon.</param>
    public bool TryAddFragment(string? fragment)
    {
        if (!AuthenticationResultsParser.TryParseMethodResult(fragment, out AuthenticationMethodResult? parsed))
        {
            return false;
        }

        _results.Add(parsed with
        {
            Reason = parsed.Reason is null ? null : Sanitize(parsed.Reason),
            Comment = parsed.Comment is null ? null : Sanitize(parsed.Comment),
            Properties = parsed.Properties.Select(p => p with { Value = Sanitize(p.Value) }).ToList(),
        });
        return true;
    }

    /// <summary>Adds a preformatted <c>dkim=</c> clause (for example from the DKIM verifier). The method must be <c>dkim</c>.</summary>
    /// <param name="fragment">The clause.</param>
    /// <exception cref="ArgumentException">The fragment is invalid or is not a dkim clause.</exception>
    public AuthenticationResultsBuilder AddDkim(string fragment) => AddMethodFragment(fragment, "dkim");

    /// <summary>Adds a preformatted <c>arc=</c> clause (ARC evaluation is provided elsewhere). The method must be <c>arc</c>.</summary>
    /// <param name="fragment">The clause.</param>
    /// <exception cref="ArgumentException">The fragment is invalid or is not an arc clause.</exception>
    public AuthenticationResultsBuilder AddArc(string fragment) => AddMethodFragment(fragment, "arc");

    /// <summary>Adds a <c>dkim=</c> clause for one verified (or failed) signature.</summary>
    /// <param name="signature">The verification result.</param>
    /// <param name="comment">Optional comment, for example the failure detail.</param>
    public AuthenticationResultsBuilder AddDkim(Dmarc.DkimAuthResult signature, string? comment = null)
    {
        ArgumentNullException.ThrowIfNull(signature);
        var props = new List<(string, string, string)> { ("header", "d", signature.Domain) };
        if (!string.IsNullOrEmpty(signature.Selector))
        {
            props.Add(("header", "s", signature.Selector));
        }

        return Add("dkim", signature.Passed ? "pass" : "fail", props, comment: comment);
    }

    /// <summary>Adds an <c>spf=</c> clause.</summary>
    /// <param name="result">The SPF check result.</param>
    /// <param name="kind">Whether the identity is the MAIL FROM or the HELO domain.</param>
    /// <param name="identity">The identity checked: the MAIL FROM address (or domain), or the HELO domain.</param>
    /// <param name="comment">Optional comment, for example <c>domain of example.com designates 192.0.2.1 as permitted sender</c>.</param>
    public AuthenticationResultsBuilder AddSpf(SpfCheckResult result, SpfIdentityKind kind, string identity, string? comment = null)
    {
        ArgumentNullException.ThrowIfNull(result);
        return Add("spf", SpfCheckResult.ToKeyword(result.Result), [("smtp", kind == SpfIdentityKind.Helo ? "helo" : "mailfrom", identity)], comment: comment);
    }

    /// <summary>Adds a <c>dmarc=</c> clause with the published policy in a comment, for example <c>dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=example.com</c>.</summary>
    /// <param name="evaluation">The DMARC evaluation.</param>
    public AuthenticationResultsBuilder AddDmarc(DmarcEvaluation evaluation)
    {
        ArgumentNullException.ThrowIfNull(evaluation);
        string? comment = null;
        if (evaluation.Record is { } record)
        {
            string sp = (record.SubdomainPolicy ?? record.Policy).ToString().ToUpperInvariant();
            comment = $"p={record.Policy.ToString().ToUpperInvariant()} sp={sp} dis={evaluation.Disposition.ToString().ToUpperInvariant()}";
        }

        return Add("dmarc", evaluation.ResultKeyword, [("header", "from", evaluation.FromDomain)], comment: comment);
    }

    /// <summary>The header field body (everything after <c>Authentication-Results: </c>), folded, without a trailing CRLF.</summary>
    public string BuildFieldBody()
    {
        var sb = new StringBuilder();
        sb.Append(FormatValue(AuthservId));
        if (Version is { } version)
        {
            sb.Append(' ').Append(version.ToString(CultureInfo.InvariantCulture));
        }

        if (_results.Count == 0)
        {
            sb.Append("; none");
            return sb.ToString();
        }

        foreach (AuthenticationMethodResult result in _results)
        {
            sb.Append(";\r\n\t");
            AppendResInfo(sb, result);
        }

        return sb.ToString();
    }

    /// <summary>The complete header field including the name and the terminating CRLF.</summary>
    public string BuildHeader() => HeaderName + ": " + BuildFieldBody() + "\r\n";

    /// <inheritdoc />
    public override string ToString() => BuildFieldBody();

    /// <summary>Formats a value as a token, a <c>[local@]domain</c> pvalue, or a quoted-string, whichever is needed.</summary>
    /// <param name="value">The raw value.</param>
    /// <param name="allowUtf8">Keep non-ASCII characters (otherwise they become <c>?</c>).</param>
    public static string FormatValue(string value, bool allowUtf8 = false)
    {
        string clean = SanitizeText(value, allowUtf8);
        if (clean.Length > 0 && (IsToken(clean) || IsAddressOrDomain(clean)))
        {
            return clean;
        }

        var sb = new StringBuilder(clean.Length + 2).Append('"');
        foreach (char c in clean)
        {
            if (c is '"' or '\\')
            {
                sb.Append('\\');
            }

            sb.Append(c);
        }

        return sb.Append('"').ToString();
    }

    private AuthenticationResultsBuilder AddMethodFragment(string fragment, string expectedMethod)
    {
        if (!AuthenticationResultsParser.TryParseMethodResult(fragment, out AuthenticationMethodResult? parsed)
            || !parsed.Method.Equals(expectedMethod, StringComparison.Ordinal))
        {
            throw new ArgumentException($"Not a valid {expectedMethod} clause.", nameof(fragment));
        }

        return AddFragment(fragment);
    }

    private void AppendResInfo(StringBuilder sb, AuthenticationMethodResult r)
    {
        var line = new LineWriter(sb, FoldColumn);
        string head = r.Method + (r.MethodVersion is { } mv ? "/" + mv.ToString(CultureInfo.InvariantCulture) : string.Empty) + "=" + r.Result;
        line.Write(head, noFold: true);
        if (!string.IsNullOrEmpty(r.Comment))
        {
            string[] words = EscapeComment(SanitizeText(r.Comment, AllowUtf8)).Split(' ', StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < words.Length; i++)
            {
                line.Write((i == 0 ? "(" : string.Empty) + words[i] + (i == words.Length - 1 ? ")" : string.Empty));
            }
        }

        if (r.Reason is not null)
        {
            line.Write("reason=" + FormatValue(r.Reason, AllowUtf8));
        }

        foreach (AuthenticationResultProperty p in r.Properties)
        {
            line.Write(p.Ptype + "." + p.Property + "=" + FormatValue(p.Value, AllowUtf8));
        }
    }

    private string Sanitize(string value) => SanitizeText(value, AllowUtf8);

    /// <summary>Replaces control characters (including CR and LF) by spaces and, unless UTF-8 is allowed, non-ASCII characters by '?'.</summary>
    private static string SanitizeText(string value, bool allowUtf8)
    {
        StringBuilder? sb = null;
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            char replacement = c;
            if (c < ' ' || c == '\x7F' || char.IsControl(c))
            {
                replacement = ' ';
            }
            else if (c > '\x7E' && !allowUtf8)
            {
                replacement = '?';
            }

            if (replacement != c)
            {
                sb ??= new StringBuilder(value, 0, i, value.Length);
                sb.Append(replacement);
            }
            else
            {
                sb?.Append(c);
            }
        }

        return sb?.ToString() ?? value;
    }

    private static string EscapeComment(string text)
    {
        var sb = new StringBuilder(text.Length + 2);
        foreach (char c in text)
        {
            if (c is '(' or ')' or '\\')
            {
                sb.Append('\\');
            }

            sb.Append(c);
        }

        return sb.ToString();
    }

    private static void RequireKeyword(string keyword, string parameter)
    {
        if (string.IsNullOrEmpty(keyword) || !char.IsAsciiLetterOrDigit(keyword[0]) || !keyword.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'))
        {
            throw new ArgumentException("Invalid keyword: " + keyword, parameter);
        }
    }

    private static bool IsTokenChar(char c) =>
        c is > ' ' and < '\x7F' && "()<>@,;:\\\"/[]?=".IndexOf(c) < 0;

    private static bool IsToken(string s) => s.All(IsTokenChar);

    /// <summary>pvalue alternative: <c>[[local-part] "@"] domain-name</c> with a dot-atom local part and an LDH domain.</summary>
    private static bool IsAddressOrDomain(string s)
    {
        int at = s.LastIndexOf('@');
        string domain = at < 0 ? s : s[(at + 1)..];
        if (at >= 0)
        {
            string local = s[..at];
            if (local.Length > 0 && !IsDotAtom(local))
            {
                return false;
            }
        }

        return domain.Length > 0 && domain.Split('.').All(l => l.Length > 0 && l.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'));
    }

    private static bool IsDotAtom(string s) =>
        s.Split('.').All(part => part.Length > 0 && part.All(c => char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-/=?^_`{|}~".IndexOf(c) >= 0));

    /// <summary>Appends space-separated words, folding with CRLF + TAB + spaces before a word that would pass the fold column.</summary>
    private sealed class LineWriter(StringBuilder sb, int foldColumn)
    {
        private int _lineStart = LastLineStart(sb);
        private bool _first = true;

        public void Write(string word, bool noFold = false)
        {
            if (!_first)
            {
                if (!noFold && sb.Length - _lineStart + 1 + word.Length > foldColumn)
                {
                    sb.Append("\r\n\t  ");
                    _lineStart = sb.Length - 3;
                }
                else
                {
                    sb.Append(' ');
                }
            }

            sb.Append(word);
            _first = false;
        }

        private static int LastLineStart(StringBuilder b)
        {
            for (int i = b.Length - 1; i >= 0; i--)
            {
                if (b[i] == '\n')
                {
                    return i + 1;
                }
            }

            return 0;
        }
    }
}
