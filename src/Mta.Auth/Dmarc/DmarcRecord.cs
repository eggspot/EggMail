using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Mta.Core;

namespace Mta.Auth.Dmarc;

/// <summary>The requested handling of messages that fail DMARC (RFC 7489 section 6.3, tag <c>p</c>).</summary>
public enum DmarcPolicy
{
    /// <summary>Monitor only; take no action.</summary>
    None = 0,

    /// <summary>Treat the message as suspicious (spam folder).</summary>
    Quarantine,

    /// <summary>Reject the message.</summary>
    Reject,
}

/// <summary>How strictly an authenticated domain must match the From domain (RFC 7489 section 3.1).</summary>
public enum DmarcAlignmentMode
{
    /// <summary>Relaxed: both domains share the same organizational domain.</summary>
    Relaxed = 0,

    /// <summary>Strict: the domains must be identical.</summary>
    Strict,
}

/// <summary>A reporting address from the <c>rua</c> or <c>ruf</c> tag (RFC 7489 section 6.2).</summary>
/// <param name="Uri">The URI as published, without the size limit (for example <c>mailto:dmarc@example.com</c>).</param>
/// <param name="MailAddress">The mailbox for a <c>mailto:</c> URI (query part removed), otherwise null.</param>
/// <param name="MaxSizeBytes">The maximum report size the receiver of reports accepts (<c>!10m</c>), or null for no limit.</param>
public sealed record DmarcReportUri(string Uri, string? MailAddress, long? MaxSizeBytes)
{
    /// <summary>True for a <c>mailto:</c> URI with a valid mailbox, the only kind this library can deliver to.</summary>
    public bool IsMailTo => MailAddress is not null;

    /// <summary>The domain part of <see cref="MailAddress"/>, lower-case, or null.</summary>
    public string? MailDomain
    {
        get
        {
            if (MailAddress is null)
            {
                return null;
            }

            int at = MailAddress.LastIndexOf('@');
            return at < 0 ? null : MailAddress[(at + 1)..].ToLowerInvariant();
        }
    }

    /// <summary>
    /// Parses one entry of a <c>rua</c>/<c>ruf</c> list: <c>uri[!size]</c> where size is digits with an optional
    /// <c>k</c>, <c>m</c>, <c>g</c> or <c>t</c> unit. Only absolute URIs are accepted.
    /// </summary>
    public static bool TryParse(string? text, [NotNullWhen(true)] out DmarcReportUri? uri)
    {
        uri = null;
        if (text is null)
        {
            return false;
        }

        string t = text.Trim();
        if (t.Length == 0 || t.Length > 1024)
        {
            return false;
        }

        long? max = null;
        int bang = t.LastIndexOf('!');
        if (bang >= 0 && TryParseSize(t.AsSpan(bang + 1), out long size))
        {
            max = size;
            t = t[..bang];
        }

        int colon = t.IndexOf(':');
        if (colon <= 0)
        {
            return false;
        }

        string scheme = t[..colon];
        if (!char.IsAsciiLetter(scheme[0]))
        {
            return false;
        }

        foreach (char c in scheme)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '+' or '-' or '.'))
            {
                return false;
            }
        }

        if (scheme.Equals("mailto", StringComparison.OrdinalIgnoreCase))
        {
            string address = t[(colon + 1)..];
            int query = address.IndexOf('?');
            if (query >= 0)
            {
                address = address[..query];
            }

            try
            {
                address = System.Uri.UnescapeDataString(address);
            }
            catch (UriFormatException)
            {
                return false;
            }

            if (!EmailAddress.TryParse(address, allowUtf8: true, out EmailAddress mailbox))
            {
                return false;
            }

            uri = new DmarcReportUri(t, mailbox.ToString(), max);
            return true;
        }

        if (t.Length == colon + 1 || t.Any(char.IsWhiteSpace))
        {
            return false;
        }

        uri = new DmarcReportUri(t, null, max);
        return true;
    }

    private static bool TryParseSize(ReadOnlySpan<char> text, out long bytes)
    {
        bytes = 0;
        if (text.Length == 0)
        {
            return false;
        }

        long multiplier = 1;
        char last = char.ToLowerInvariant(text[^1]);
        if (last is 'k' or 'm' or 'g' or 't')
        {
            multiplier = last switch
            {
                'k' => 1L << 10,
                'm' => 1L << 20,
                'g' => 1L << 30,
                _ => 1L << 40,
            };
            text = text[..^1];
        }

        if (text.Length is 0 or > 15)
        {
            return false;
        }

        foreach (char c in text)
        {
            if (!char.IsAsciiDigit(c))
            {
                return false;
            }
        }

        long value = long.Parse(text, NumberStyles.None, CultureInfo.InvariantCulture);
        bytes = value > long.MaxValue / multiplier ? long.MaxValue : value * multiplier;
        return true;
    }
}

/// <summary>A parsed DMARC policy record (RFC 7489 section 6.3).</summary>
public sealed class DmarcRecord
{
    /// <summary>The record limits used by <see cref="TryParse(string?, int, out DmarcRecord?, out string?)"/> by default.</summary>
    public const int DefaultMaxLength = 4096;

    private DmarcRecord()
    {
    }

    /// <summary>The record text.</summary>
    public string Text { get; private init; } = string.Empty;

    /// <summary>The domain policy (<c>p</c>).</summary>
    public DmarcPolicy Policy { get; private init; }

    /// <summary>The subdomain policy (<c>sp</c>), or null when absent (then <see cref="Policy"/> applies to subdomains).</summary>
    public DmarcPolicy? SubdomainPolicy { get; private init; }

    /// <summary>DKIM alignment mode (<c>adkim</c>, default relaxed).</summary>
    public DmarcAlignmentMode DkimAlignment { get; private init; }

    /// <summary>SPF alignment mode (<c>aspf</c>, default relaxed).</summary>
    public DmarcAlignmentMode SpfAlignment { get; private init; }

    /// <summary>The percentage of failing messages the policy applies to (<c>pct</c>, 0-100, default 100).</summary>
    public int Percentage { get; private init; } = 100;

    /// <summary>Aggregate report addresses (<c>rua</c>); invalid entries are dropped.</summary>
    public IReadOnlyList<DmarcReportUri> AggregateReportUris { get; private init; } = [];

    /// <summary>Failure (forensic) report addresses (<c>ruf</c>); invalid entries are dropped.</summary>
    public IReadOnlyList<DmarcReportUri> FailureReportUris { get; private init; } = [];

    /// <summary>The failure reporting options (<c>fo</c>, default <c>0</c>), colon-separated.</summary>
    public string FailureReportingOptions { get; private init; } = "0";

    /// <summary>The failure report formats (<c>rf</c>, default <c>afrf</c>).</summary>
    public string FailureReportFormat { get; private init; } = "afrf";

    /// <summary>The requested aggregate report interval in seconds (<c>ri</c>, default 86400).</summary>
    public long AggregateReportIntervalSeconds { get; private init; } = 86400;

    /// <summary>True when <c>p</c> (or <c>sp</c>) was missing or invalid and a valid <c>rua</c> made the record count as <c>p=none</c> (RFC 7489 section 6.6.3 step 6).</summary>
    public bool IsMonitoringFallback { get; private init; }

    /// <summary>True when the text starts with the DMARC version tag (<c>v=DMARC1</c>), so a TXT record is a DMARC candidate.</summary>
    public static bool HasVersionTag([NotNullWhen(true)] string? text)
    {
        if (text is null)
        {
            return false;
        }

        ReadOnlySpan<char> s = text.AsSpan().TrimStart();
        if (s.Length == 0 || (s[0] != 'v' && s[0] != 'V'))
        {
            return false;
        }

        s = s[1..].TrimStart();
        if (s.Length == 0 || s[0] != '=')
        {
            return false;
        }

        s = s[1..].TrimStart();
        if (!s.StartsWith("DMARC1", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        s = s[6..];
        return s.Length == 0 || s[0] == ';' || char.IsWhiteSpace(s[0]);
    }

    /// <summary>Parses a record with the default length limit.</summary>
    public static bool TryParse(string? text, [NotNullWhen(true)] out DmarcRecord? record, [NotNullWhen(false)] out string? error) =>
        TryParse(text, DefaultMaxLength, out record, out error);

    /// <summary>
    /// Parses a DMARC record. Whitespace around tags, values and separators is tolerated and unknown tags are ignored.
    /// A record without a valid <c>p</c> (or with an invalid <c>sp</c>) is rejected unless a valid <c>rua</c> is present,
    /// in which case it is accepted as <c>p=none</c>. Invalid optional tags fall back to their defaults.
    /// </summary>
    /// <param name="text">The (concatenated) TXT text.</param>
    /// <param name="maxLength">Records longer than this are rejected.</param>
    /// <param name="record">The parsed record.</param>
    /// <param name="error">Why the record was rejected.</param>
    public static bool TryParse(string? text, int maxLength, [NotNullWhen(true)] out DmarcRecord? record, [NotNullWhen(false)] out string? error)
    {
        record = null;
        error = null;
        if (!HasVersionTag(text))
        {
            error = "missing v=DMARC1";
            return false;
        }

        if (text.Length > maxLength)
        {
            error = "DMARC record too long";
            return false;
        }

        var tags = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string part in text.Split(';'))
        {
            string item = part.Trim();
            if (item.Length == 0)
            {
                continue;
            }

            int eq = item.IndexOf('=');
            if (eq <= 0)
            {
                continue; // a syntax error in a tag is ignored
            }

            string name = item[..eq].Trim().ToLowerInvariant();
            string value = item[(eq + 1)..].Trim();
            tags.TryAdd(name, value);
            if (tags.Count > 64)
            {
                error = "too many tags";
                return false;
            }
        }

        var aggregate = ParseUriList(tags.GetValueOrDefault("rua"));
        var failure = ParseUriList(tags.GetValueOrDefault("ruf"));

        bool monitoringFallback = false;
        DmarcPolicy policy = DmarcPolicy.None;
        bool pValid = tags.TryGetValue("p", out string? pText) && TryParsePolicy(pText, out policy);
        DmarcPolicy? subdomainPolicy = null;
        bool spValid = true;
        if (tags.TryGetValue("sp", out string? spText))
        {
            spValid = TryParsePolicy(spText, out DmarcPolicy sp);
            if (spValid)
            {
                subdomainPolicy = sp;
            }
        }

        if (!pValid || !spValid)
        {
            if (aggregate.Count == 0)
            {
                error = !pValid ? "missing or invalid p tag" : "invalid sp tag";
                return false;
            }

            policy = DmarcPolicy.None;
            subdomainPolicy = null;
            monitoringFallback = true;
        }

        int pct = 100;
        if (tags.TryGetValue("pct", out string? pctText) && TryParseSmallInt(pctText, out int parsedPct) && parsedPct <= 100)
        {
            pct = parsedPct;
        }

        long interval = 86400;
        if (tags.TryGetValue("ri", out string? riText) && long.TryParse(riText, NumberStyles.None, CultureInfo.InvariantCulture, out long ri) && ri > 0)
        {
            interval = ri;
        }

        record = new DmarcRecord
        {
            Text = text,
            Policy = policy,
            SubdomainPolicy = subdomainPolicy,
            DkimAlignment = ParseAlignment(tags.GetValueOrDefault("adkim")),
            SpfAlignment = ParseAlignment(tags.GetValueOrDefault("aspf")),
            Percentage = pct,
            AggregateReportUris = aggregate,
            FailureReportUris = failure,
            FailureReportingOptions = ParseFailureOptions(tags.GetValueOrDefault("fo")),
            FailureReportFormat = tags.TryGetValue("rf", out string? rf) && rf.Length is > 0 and <= 32 ? rf.ToLowerInvariant() : "afrf",
            AggregateReportIntervalSeconds = interval,
            IsMonitoringFallback = monitoringFallback,
        };
        return true;
    }

    private static bool TryParsePolicy(string value, out DmarcPolicy policy)
    {
        switch (value.ToLowerInvariant())
        {
            case "none":
                policy = DmarcPolicy.None;
                return true;
            case "quarantine":
                policy = DmarcPolicy.Quarantine;
                return true;
            case "reject":
                policy = DmarcPolicy.Reject;
                return true;
            default:
                policy = DmarcPolicy.None;
                return false;
        }
    }

    private static DmarcAlignmentMode ParseAlignment(string? value) =>
        value is not null && value.Equals("s", StringComparison.OrdinalIgnoreCase) ? DmarcAlignmentMode.Strict : DmarcAlignmentMode.Relaxed;

    private static bool TryParseSmallInt(string value, out int result)
    {
        result = 0;
        return value.Length is > 0 and <= 4 && int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out result);
    }

    private static string ParseFailureOptions(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "0";
        }

        var kept = new List<string>();
        foreach (string option in value.Split(':'))
        {
            string o = option.Trim().ToLowerInvariant();
            if (o is "0" or "1" or "d" or "s" && !kept.Contains(o))
            {
                kept.Add(o);
            }
        }

        return kept.Count == 0 ? "0" : string.Join(':', kept);
    }

    private static List<DmarcReportUri> ParseUriList(string? value)
    {
        var list = new List<DmarcReportUri>();
        if (string.IsNullOrWhiteSpace(value))
        {
            return list;
        }

        foreach (string item in value.Split(','))
        {
            if (DmarcReportUri.TryParse(item, out DmarcReportUri? uri))
            {
                list.Add(uri);
                if (list.Count >= 32)
                {
                    break; // bound hostile lists
                }
            }
        }

        return list;
    }
}
