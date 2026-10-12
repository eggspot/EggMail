using System.Text;

namespace Mta.Dkim;

/// <summary>
/// Builds the DKIM part of an RFC 8601 Authentication-Results header, for example <c>dkim=pass (2048-bit key) header.d=example.com header.s=sel header.b=Xb4F5k6S</c>.
/// Other components (SPF, DMARC, the header assembler) join these fragments with the authserv-id and their own results.
/// </summary>
public static class DkimAuthenticationResults
{
    /// <summary>The RFC 8601 result keyword for a status: pass, fail, neutral, temperror, permerror or none.</summary>
    public static string ResultName(DkimStatus status) => status switch
    {
        DkimStatus.Pass => "pass",
        DkimStatus.Fail => "fail",
        DkimStatus.Neutral => "neutral",
        DkimStatus.TempError => "temperror",
        DkimStatus.PermError => "permerror",
        _ => "none",
    };

    /// <summary>Formats one result as a <c>dkim=...</c> method result without a leading authserv-id or trailing semicolon.</summary>
    public static string Format(DkimVerificationResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        var sb = new StringBuilder(96);
        sb.Append("dkim=").Append(ResultName(result.Status));

        if (result.Status == DkimStatus.Pass)
        {
            // A comment (not a property): informative only.
            var notes = new List<string>(3);
            if (result.KeyBits > 0) { notes.Add(result.KeyBits + "-bit key"); }
            if (result.WeakKey) { notes.Add("weak key"); }
            if (result.Testing) { notes.Add("testing mode"); }
            if (result.BodyLengthLimited) { notes.Add("l= tag present"); }
            if (notes.Count > 0) { sb.Append(" (").Append(string.Join("; ", notes)).Append(')'); }
        }
        else if (result.Status != DkimStatus.None && !string.IsNullOrEmpty(result.Reason))
        {
            sb.Append(" reason=").Append(Quote(result.Reason));
        }

        if (result.Domain is not null) { sb.Append(" header.d=").Append(result.Domain); }
        if (result.Identity is not null) { sb.Append(" header.i=").Append(IdentityValue(result.Identity)); }
        if (result.Selector is not null) { sb.Append(" header.s=").Append(result.Selector); }
        if (result.HeaderBPrefix is not null) { sb.Append(" header.b=").Append(result.HeaderBPrefix); }
        return sb.ToString();
    }

    /// <summary>Formats all results of a message, one fragment per signature (a single <c>dkim=none</c> for an unsigned message).</summary>
    public static IReadOnlyList<string> FormatAll(IReadOnlyList<DkimVerificationResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);
        if (results.Count == 0) { return ["dkim=none"]; }
        var list = new string[results.Count];
        for (int i = 0; i < list.Length; i++) { list[i] = Format(results[i]); }
        return list;
    }

    private static string IdentityValue(string identity)
    {
        foreach (char c in identity)
        {
            bool simple = c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '-' or '_' or '@' or '+';
            if (!simple) { return Quote(identity); }
        }

        return identity;
    }

    private static string Quote(string text)
    {
        var sb = new StringBuilder(text.Length + 2);
        sb.Append('"');
        foreach (char c in text)
        {
            if (c < 0x20 || c > 0x7E) { sb.Append(' '); }
            else if (c == '"' || c == '\\') { sb.Append('\\').Append(c); }
            else { sb.Append(c); }
        }

        sb.Append('"');
        return sb.ToString();
    }
}
