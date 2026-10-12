using System.Globalization;

namespace Mta.Auth.Domains;

/// <summary>
/// The Mozilla Public Suffix List (https://publicsuffix.org, MPL-2.0), used to find the organizational domain of
/// a host name (RFC 7489 section 3.2). The default instance is loaded lazily from the copy embedded in this assembly.
/// Instances are immutable and safe for concurrent use.
/// </summary>
public sealed class PublicSuffixList
{
    private const string ResourceName = "Mta.Auth.public_suffix_list.dat";
    private static readonly Lazy<PublicSuffixList> DefaultInstance = new(LoadEmbedded, LazyThreadSafetyMode.ExecutionAndPublication);

    private readonly HashSet<string> _rules;
    private readonly HashSet<string> _wildcardParents;
    private readonly HashSet<string> _exceptions;

    private PublicSuffixList(HashSet<string> rules, HashSet<string> wildcardParents, HashSet<string> exceptions, string? version, int ruleCount)
    {
        _rules = rules;
        _wildcardParents = wildcardParents;
        _exceptions = exceptions;
        Version = version;
        RuleCount = ruleCount;
    }

    /// <summary>The list embedded in this assembly (ICANN and private sections).</summary>
    public static PublicSuffixList Default => DefaultInstance.Value;

    /// <summary>The <c>VERSION</c> stamp from the list header (for example <c>2026-10-07_07-28-19_UTC</c>), if present.</summary>
    public string? Version { get; }

    /// <summary>The number of rules loaded (normal, wildcard and exception rules).</summary>
    public int RuleCount { get; }

    /// <summary>
    /// Parses a list in the public suffix list file format. Comment lines start with <c>//</c>; text after the first
    /// whitespace on a rule line is ignored; rules in the private section are skipped when
    /// <paramref name="includePrivateDomains"/> is <see langword="false"/>.
    /// </summary>
    public static PublicSuffixList Parse(string text, bool includePrivateDomains = true)
    {
        ArgumentNullException.ThrowIfNull(text);
        var rules = new HashSet<string>(StringComparer.Ordinal);
        var wildcards = new HashSet<string>(StringComparer.Ordinal);
        var exceptions = new HashSet<string>(StringComparer.Ordinal);
        string? version = null;
        bool inPrivate = false;
        int count = 0;
        var idn = new IdnMapping { UseStd3AsciiRules = false, AllowUnassigned = true };

        foreach (var rawLine in text.Split('\n'))
        {
            string line = rawLine.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (line.StartsWith("//", StringComparison.Ordinal))
            {
                if (line.Contains("===BEGIN PRIVATE DOMAINS===", StringComparison.Ordinal))
                {
                    inPrivate = true;
                }
                else if (line.Contains("===END PRIVATE DOMAINS===", StringComparison.Ordinal))
                {
                    inPrivate = false;
                }
                else if (version is null && line.StartsWith("// VERSION:", StringComparison.Ordinal))
                {
                    version = line["// VERSION:".Length..].Trim();
                }

                continue;
            }

            if (inPrivate && !includePrivateDomains)
            {
                continue;
            }

            int ws = line.IndexOfAny([' ', '\t']);
            if (ws >= 0)
            {
                line = line[..ws];
            }

            bool isException = line[0] == '!';
            if (isException)
            {
                line = line[1..];
            }

            string? ascii = ToAscii(line, idn);
            if (ascii is null || ascii.Length == 0)
            {
                continue;
            }

            count++;
            if (isException)
            {
                exceptions.Add(ascii);
            }
            else if (ascii.StartsWith("*.", StringComparison.Ordinal))
            {
                wildcards.Add(ascii[2..]);
            }
            else
            {
                rules.Add(ascii);
            }
        }

        return new PublicSuffixList(rules, wildcards, exceptions, version, count);
    }

    /// <summary>
    /// Returns the public suffix of <paramref name="domain"/> (for example <c>co.uk</c> for <c>www.example.co.uk</c>).
    /// A name with no matching rule uses the implicit <c>*</c> rule, so its last label is the suffix.
    /// </summary>
    /// <returns>The suffix in lower-case A-label form, or <see langword="null"/> when the input is not a usable domain name.</returns>
    public string? GetPublicSuffix(string domain)
    {
        string[]? labels = SplitLabels(domain);
        if (labels is null)
        {
            return null;
        }

        int suffixLabels = CountSuffixLabels(labels);
        return string.Join('.', labels, labels.Length - suffixLabels, suffixLabels);
    }

    /// <summary>
    /// Returns the organizational domain: the public suffix plus one more label (for example <c>example.co.uk</c>
    /// for <c>mail.eu.example.co.uk</c>). When the name is itself a public suffix (or has no more labels than its
    /// suffix) the normalised name itself is returned, so the result is never shorter than the input's registrable part.
    /// Unusable input (empty, bad labels) is returned lower-cased with one trailing dot removed.
    /// </summary>
    public string GetOrganizationalDomain(string domain)
    {
        string[]? labels = SplitLabels(domain);
        if (labels is null)
        {
            string raw = (domain ?? string.Empty).Trim();
            return (raw.EndsWith('.') ? raw[..^1] : raw).ToLowerInvariant();
        }

        int suffixLabels = CountSuffixLabels(labels);
        int take = Math.Min(labels.Length, suffixLabels + 1);
        return string.Join('.', labels, labels.Length - take, take);
    }

    /// <summary>True when <paramref name="domain"/> is exactly a public suffix (for example <c>co.uk</c>).</summary>
    public bool IsPublicSuffix(string domain)
    {
        string[]? labels = SplitLabels(domain);
        return labels is not null && CountSuffixLabels(labels) == labels.Length;
    }

    /// <summary>True when both names share the same organizational domain (relaxed identifier alignment).</summary>
    public bool HaveSameOrganizationalDomain(string first, string second) =>
        string.Equals(GetOrganizationalDomain(first), GetOrganizationalDomain(second), StringComparison.Ordinal);

    private int CountSuffixLabels(string[] labels)
    {
        int n = labels.Length;

        // Exception rules prevail over every other matching rule: the suffix is the exception minus its leftmost label.
        for (int i = 0; i < n; i++)
        {
            if (_exceptions.Count > 0 && _exceptions.Contains(Join(labels, i)))
            {
                return n - i - 1;
            }
        }

        for (int i = 0; i < n; i++)
        {
            string candidate = Join(labels, i);
            if (_rules.Contains(candidate))
            {
                return n - i;
            }

            if (i + 1 < n && _wildcardParents.Contains(Join(labels, i + 1)))
            {
                return n - i;
            }
        }

        return 1; // implicit "*" rule
    }

    private static string Join(string[] labels, int from) => string.Join('.', labels, from, labels.Length - from);

    private static string[]? SplitLabels(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return null;
        }

        string d = domain.Trim();
        if (d.EndsWith('.'))
        {
            d = d[..^1];
        }

        if (d.Length == 0 || d.Length > 253)
        {
            return null;
        }

        string? ascii = ToAscii(d, new IdnMapping { UseStd3AsciiRules = false });
        if (ascii is null)
        {
            return null;
        }

        string[] labels = ascii.Split('.');
        foreach (string label in labels)
        {
            if (label.Length == 0 || label.Length > 63)
            {
                return null;
            }
        }

        return labels;
    }

    private static string? ToAscii(string name, IdnMapping idn)
    {
        bool ascii = true;
        foreach (char c in name)
        {
            if (c > 0x7F)
            {
                ascii = false;
                break;
            }
        }

        if (ascii)
        {
            return name.ToLowerInvariant();
        }

        try
        {
            return idn.GetAscii(name).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static PublicSuffixList LoadEmbedded()
    {
        var assembly = typeof(PublicSuffixList).Assembly;
        using Stream stream = assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException("Embedded resource " + ResourceName + " is missing.");
        using var reader = new StreamReader(stream, System.Text.Encoding.UTF8);
        return Parse(reader.ReadToEnd());
    }
}
