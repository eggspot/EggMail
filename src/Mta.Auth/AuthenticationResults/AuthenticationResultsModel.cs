using System.Diagnostics.CodeAnalysis;

namespace Mta.Auth.AuthenticationResults;

/// <summary>One <c>ptype.property=value</c> item of an Authentication-Results method result (RFC 8601 section 2.2).</summary>
/// <param name="Ptype">The property type: <c>smtp</c>, <c>header</c>, <c>body</c> or <c>policy</c> (lower-case).</param>
/// <param name="Property">The property name, for example <c>mailfrom</c>, <c>d</c> or <c>from</c> (lower-case).</param>
/// <param name="Value">The unquoted value.</param>
public sealed record AuthenticationResultProperty(string Ptype, string Property, string Value)
{
    /// <summary>The dotted name, for example <c>header.d</c>.</summary>
    public string Name => Ptype + "." + Property;
}

/// <summary>One <c>method=result</c> clause (<c>resinfo</c>) of an Authentication-Results header field.</summary>
/// <param name="Method">The method keyword, lower-case (<c>spf</c>, <c>dkim</c>, <c>dmarc</c>, <c>arc</c>, ...).</param>
/// <param name="MethodVersion">The optional method version (<c>dkim/1=pass</c>), otherwise null.</param>
/// <param name="Result">The result keyword, lower-case (<c>pass</c>, <c>fail</c>, ...).</param>
/// <param name="Reason">The optional <c>reason=</c> text.</param>
/// <param name="Comment">The optional parenthesised comment that followed the result, without the parentheses.</param>
/// <param name="Properties">The properties in order.</param>
public sealed record AuthenticationMethodResult(
    string Method,
    int? MethodVersion,
    string Result,
    string? Reason,
    string? Comment,
    IReadOnlyList<AuthenticationResultProperty> Properties)
{
    /// <summary>Returns the value of the first property with the given type and name, or null.</summary>
    /// <param name="ptype">The property type, for example <c>header</c>.</param>
    /// <param name="property">The property name, for example <c>d</c>.</param>
    public string? GetProperty(string ptype, string property) =>
        Properties.FirstOrDefault(p => p.Ptype.Equals(ptype, StringComparison.OrdinalIgnoreCase) && p.Property.Equals(property, StringComparison.OrdinalIgnoreCase))?.Value;
}

/// <summary>A parsed Authentication-Results header field body (RFC 8601 section 2.2).</summary>
/// <param name="AuthservId">The authentication server identifier, usually a domain name.</param>
/// <param name="Version">The explicit header version, or null (meaning 1).</param>
/// <param name="Results">The method results; empty for the <c>none</c> form.</param>
public sealed record AuthenticationResultsHeader(string AuthservId, int? Version, IReadOnlyList<AuthenticationMethodResult> Results)
{
    /// <summary>True for the form <c>authserv-id; none</c>.</summary>
    public bool IsNone => Results.Count == 0;

    /// <summary>Returns the results for a method (case-insensitive).</summary>
    /// <param name="method">The method keyword, for example <c>dkim</c>.</param>
    public IEnumerable<AuthenticationMethodResult> ForMethod(string method) =>
        Results.Where(r => r.Method.Equals(method, StringComparison.OrdinalIgnoreCase));

    /// <summary>Parses a header field body. Never throws.</summary>
    /// <param name="fieldBody">The text after <c>Authentication-Results:</c>; folding is allowed.</param>
    /// <param name="header">The parsed header.</param>
    public static bool TryParse(string? fieldBody, [NotNullWhen(true)] out AuthenticationResultsHeader? header) =>
        AuthenticationResultsParser.TryParse(fieldBody, out header);
}
