using System.Text;
using Mta.Dns;

namespace Mta.Tls.MtaSts;

/// <summary>A successfully parsed MTA-STS TXT record (<c>v=STSv1; id=...</c>).</summary>
/// <param name="Id">The policy id (1 to 32 alphanumeric characters).</param>
public sealed record MtaStsTxtRecord(string Id);

/// <summary>Parser for the <c>_mta-sts.&lt;domain&gt;</c> TXT record (RFC 8461 section 3.1).</summary>
public static class MtaStsTxtParser
{
    /// <summary>Parses one TXT record value. Returns <see langword="false"/> if it is not a valid MTA-STS record.</summary>
    public static bool TryParse(string? text, out MtaStsTxtRecord? record)
    {
        record = null;
        if (text is null || text.Length > 1024)
        {
            return false;
        }

        string? id = null;
        bool first = true;
        foreach (string rawField in text.Split(';'))
        {
            string field = rawField.Trim(' ', '\t');
            if (field.Length == 0)
            {
                continue;
            }

            int eq = field.IndexOf('=');
            if (eq <= 0)
            {
                return false;
            }

            string key = field[..eq].Trim(' ', '\t');
            string value = field[(eq + 1)..].Trim(' ', '\t');
            if (first)
            {
                if (!string.Equals(key, "v", StringComparison.OrdinalIgnoreCase) || value != "STSv1")
                {
                    return false;
                }

                first = false;
            }
            else if (string.Equals(key, "id", StringComparison.OrdinalIgnoreCase))
            {
                if (id is not null || !IsValidId(value))
                {
                    return false;
                }

                id = value;
            }
        }

        if (first || id is null)
        {
            return false;
        }

        record = new MtaStsTxtRecord(id);
        return true;
    }

    /// <summary>
    /// Selects the MTA-STS record from the TXT RRset: TXT records that do not start with <c>v=STSv1</c> are ignored;
    /// if the number of candidates is not exactly one, or the candidate is invalid, there is no usable record.
    /// </summary>
    public static MtaStsTxtRecord? Select(IEnumerable<TxtRecord> records)
    {
        MtaStsTxtRecord? found = null;
        int candidates = 0;
        foreach (var r in records)
        {
            string t = r.Text.TrimStart(' ', '\t');
            if (!t.StartsWith("v=STSv1", StringComparison.Ordinal))
            {
                continue;
            }

            candidates++;
            if (candidates > 1)
            {
                return null;
            }

            TryParse(r.Text, out found);
        }

        return candidates == 1 ? found : null;
    }

    private static bool IsValidId(string value)
    {
        if (value.Length is < 1 or > 32)
        {
            return false;
        }

        foreach (char c in value)
        {
            if (!(c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9')))
            {
                return false;
            }
        }

        return true;
    }
}

/// <summary>Parser for MTA-STS policy files (RFC 8461 section 3.2). Never throws on malformed input.</summary>
public static class MtaStsPolicyParser
{
    /// <summary>RFC 8461 upper bound for <c>max_age</c> (about one year); larger values are clamped to this.</summary>
    public const int MaxAgeCeilingSeconds = 31557600;

    /// <summary>The maximum accepted policy size in bytes (also enforced by the fetcher).</summary>
    public const int MaxPolicyBytes = 64 * 1024;

    /// <summary>The maximum number of <c>mx</c> lines accepted; more makes the policy invalid.</summary>
    public const int MaxMxPatterns = 100;

    /// <summary>Parses a policy body. LF and CRLF line endings are accepted; unknown keys are ignored.</summary>
    /// <param name="text">The policy text.</param>
    /// <param name="policy">The policy when the method returns <see langword="true"/>.</param>
    /// <param name="error">A short description when the method returns <see langword="false"/>.</param>
    public static bool TryParse(string? text, out MtaStsPolicy? policy, out string? error)
    {
        policy = null;
        error = null;
        if (text is null)
        {
            error = "policy is null";
            return false;
        }

        if (text.Length > MaxPolicyBytes)
        {
            error = "policy too large";
            return false;
        }

        if (text.Length > 0 && text[0] == '﻿')
        {
            text = text[1..];
        }

        bool haveVersion = false;
        MtaStsMode? mode = null;
        long? maxAge = null;
        var mx = new List<string>();
        var lines = new List<string>();

        foreach (string rawLine in text.Split('\n'))
        {
            string line = rawLine.TrimEnd('\r');
            if (line.Trim().Length == 0)
            {
                continue;
            }

            lines.Add(line);
            int colon = line.IndexOf(':');
            if (colon <= 0)
            {
                error = "malformed line";
                return false;
            }

            string key = line[..colon].Trim(' ', '\t').ToLowerInvariant();
            string value = line[(colon + 1)..].Trim(' ', '\t');
            switch (key)
            {
                case "version":
                    if (haveVersion || value != MtaStsPolicy.Version)
                    {
                        error = "unsupported or duplicate version";
                        return false;
                    }

                    haveVersion = true;
                    break;
                case "mode":
                    if (mode is not null || !TryParseMode(value, out var m))
                    {
                        error = "invalid or duplicate mode";
                        return false;
                    }

                    mode = m;
                    break;
                case "max_age":
                    if (maxAge is not null || !TryParseMaxAge(value, out long age))
                    {
                        error = "invalid or duplicate max_age";
                        return false;
                    }

                    maxAge = age;
                    break;
                case "mx":
                    if (mx.Count >= MaxMxPatterns)
                    {
                        error = "too many mx lines";
                        return false;
                    }

                    if (!MtaStsMxMatcher.TryNormalizePattern(value, out string pattern))
                    {
                        error = "invalid mx pattern";
                        return false;
                    }

                    mx.Add(pattern);
                    break;
                default:
                    // Unknown keys are ignored (RFC 8461 section 3.2: extension fields).
                    break;
            }
        }

        if (!haveVersion)
        {
            error = "missing version";
            return false;
        }

        if (mode is null)
        {
            error = "missing mode";
            return false;
        }

        if (maxAge is null)
        {
            error = "missing max_age";
            return false;
        }

        if (mode != MtaStsMode.None && mx.Count == 0)
        {
            error = "missing mx";
            return false;
        }

        policy = new MtaStsPolicy(mode.Value, mx.ToArray(), (int)maxAge.Value, lines.ToArray());
        return true;
    }

    /// <summary>Parses a policy from raw bytes (strict UTF-8, no BOM requirement).</summary>
    public static bool TryParse(ReadOnlySpan<byte> utf8, out MtaStsPolicy? policy, out string? error)
    {
        policy = null;
        if (utf8.Length > MaxPolicyBytes)
        {
            error = "policy too large";
            return false;
        }

        string text;
        try
        {
            text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(utf8);
        }
        catch (ArgumentException)
        {
            error = "policy is not valid UTF-8";
            return false;
        }

        return TryParse(text, out policy, out error);
    }

    private static bool TryParseMode(string value, out MtaStsMode mode)
    {
        switch (value.ToLowerInvariant())
        {
            case "enforce":
                mode = MtaStsMode.Enforce;
                return true;
            case "testing":
                mode = MtaStsMode.Testing;
                return true;
            case "none":
                mode = MtaStsMode.None;
                return true;
            default:
                mode = default;
                return false;
        }
    }

    private static bool TryParseMaxAge(string value, out long seconds)
    {
        seconds = 0;
        if (value.Length == 0 || value.Length > 20)
        {
            return false;
        }

        foreach (char c in value)
        {
            if (c is < '0' or > '9')
            {
                return false;
            }
        }

        // Values with more than 10 digits cannot be below the ceiling; clamp without risking overflow.
        if (value.Length > 10)
        {
            seconds = MaxAgeCeilingSeconds;
            return true;
        }

        seconds = Math.Min(long.Parse(value, System.Globalization.CultureInfo.InvariantCulture), MaxAgeCeilingSeconds);
        return true;
    }
}
