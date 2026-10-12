using System.Diagnostics.CodeAnalysis;
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
    private const int MaxLabels = 128;
    private static readonly Lazy<PublicSuffixList> DefaultInstance = new(LoadEmbedded, LazyThreadSafetyMode.ExecutionAndPublication);
    private static readonly IdnMapping StrictIdn = new() { UseStd3AsciiRules = false };

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
        if (!TryNormalize(domain, out string? name))
        {
            return null;
        }

        Span<int> starts = stackalloc int[MaxLabels];
        int labels = SplitLabels(name, starts);
        int suffixLabels = CountSuffixLabels(name, starts[..labels]);
        return name[starts[labels - suffixLabels]..];
    }

    /// <summary>
    /// Returns the organizational domain: the public suffix plus one more label (for example <c>example.co.uk</c>
    /// for <c>mail.eu.example.co.uk</c>). When the name is itself a public suffix (or has no more labels than its
    /// suffix) the normalised name itself is returned, so the result is never shorter than the input's registrable part.
    /// Unusable input (empty, bad labels) is returned lower-cased with one trailing dot removed.
    /// </summary>
    public string GetOrganizationalDomain(string domain)
    {
        if (!TryNormalize(domain, out string? name))
        {
            string raw = (domain ?? string.Empty).Trim();
            return (raw.EndsWith('.') ? raw[..^1] : raw).ToLowerInvariant();
        }

        Span<int> starts = stackalloc int[MaxLabels];
        int labels = SplitLabels(name, starts);
        int suffixLabels = CountSuffixLabels(name, starts[..labels]);
        int take = Math.Min(labels, suffixLabels + 1);
        return take == labels ? name : name[starts[labels - take]..];
    }

    /// <summary>True when <paramref name="domain"/> is exactly a public suffix (for example <c>co.uk</c>).</summary>
    public bool IsPublicSuffix(string domain)
    {
        if (!TryNormalize(domain, out string? name))
        {
            return false;
        }

        Span<int> starts = stackalloc int[MaxLabels];
        int labels = SplitLabels(name, starts);
        return CountSuffixLabels(name, starts[..labels]) == labels;
    }

    /// <summary>True when both names share the same organizational domain (relaxed identifier alignment).</summary>
    public bool HaveSameOrganizationalDomain(string first, string second) =>
        string.Equals(GetOrganizationalDomain(first), GetOrganizationalDomain(second), StringComparison.Ordinal);

    /// <summary>Counts how many trailing labels of <paramref name="name"/> form its public suffix.</summary>
    private int CountSuffixLabels(string name, ReadOnlySpan<int> starts)
    {
        int n = starts.Length;
        var exceptions = _exceptions.GetAlternateLookup<ReadOnlySpan<char>>();
        var rules = _rules.GetAlternateLookup<ReadOnlySpan<char>>();
        var wildcards = _wildcardParents.GetAlternateLookup<ReadOnlySpan<char>>();

        // Exception rules prevail over every other matching rule: the suffix is the exception minus its leftmost label.
        if (_exceptions.Count > 0)
        {
            for (int i = 0; i < n; i++)
            {
                if (exceptions.Contains(name.AsSpan(starts[i])))
                {
                    return n - i - 1;
                }
            }
        }

        for (int i = 0; i < n; i++)
        {
            if (rules.Contains(name.AsSpan(starts[i])))
            {
                return n - i;
            }

            if (i + 1 < n && wildcards.Contains(name.AsSpan(starts[i + 1])))
            {
                return n - i;
            }
        }

        return 1; // implicit "*" rule
    }

    /// <summary>Writes the start index of every label of an already validated name; returns the label count.</summary>
    private static int SplitLabels(string name, Span<int> starts)
    {
        int count = 0;
        starts[count++] = 0;
        for (int i = 0; i < name.Length; i++)
        {
            if (name[i] == '.')
            {
                starts[count++] = i + 1;
            }
        }

        return count;
    }

    /// <summary>
    /// Validates and normalises a name to lower-case A-label form without a trailing dot: non-empty labels of at most
    /// 63 characters, at most 253 characters in total (and so at most 127 labels).
    /// </summary>
    private static bool TryNormalize(string? domain, [NotNullWhen(true)] out string? name)
    {
        name = null;
        if (string.IsNullOrWhiteSpace(domain))
        {
            return false;
        }

        string d = domain.Trim();
        if (d.EndsWith('.'))
        {
            d = d[..^1];
        }

        if (d.Length == 0 || d.Length > 253)
        {
            return false;
        }

        string? ascii = ToAscii(d, StrictIdn);
        if (ascii is null || ascii.Length > 253)
        {
            return false;
        }

        int labelLength = 0;
        foreach (char c in ascii)
        {
            if (c == '.')
            {
                if (labelLength == 0)
                {
                    return false;
                }

                labelLength = 0;
            }
            else if (++labelLength > 63)
            {
                return false;
            }
        }

        if (labelLength == 0)
        {
            return false;
        }

        name = ascii;
        return true;
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
