using Mta.Core;

namespace Mta.Auth.Spf;

/// <summary>Tunable limits and environment for <see cref="SpfEvaluator"/>. The defaults are the RFC 7208 limits.</summary>
public sealed class SpfOptions
{
    /// <summary>The RFC 7208 default explanation, used for a Fail result that has no usable <c>exp=</c>.</summary>
    public const string RfcDefaultExplanation = "domain of %{o} does not designate %{c} as permitted sender";

    /// <summary>Maximum DNS-querying terms (include, a, mx, ptr, exists, redirect) per check. RFC 7208 section 4.6.4: 10.</summary>
    public int MaxDnsLookups { get; init; } = 10;

    /// <summary>Maximum void lookups (NXDOMAIN or empty answer) per check. RFC 7208 section 4.6.4: 2.</summary>
    public int MaxVoidLookups { get; init; } = 2;

    /// <summary>Maximum MX records an <c>mx</c> mechanism may expand (more is a PermError), and PTR names a <c>ptr</c> mechanism examines (the rest are ignored). RFC 7208: 10.</summary>
    public int MaxMxPtrNames { get; init; } = 10;

    /// <summary>Maximum length in characters of an SPF TXT record; longer records are a PermError. Default 4096.</summary>
    public int MaxRecordLength { get; init; } = 4096;

    /// <summary>Maximum length of one macro expansion before domain truncation; longer results are an error. Default 4096.</summary>
    public int MaxMacroExpansionLength { get; init; } = 4096;

    /// <summary>Maximum length of an explanation string after macro expansion; a longer one is dropped. Default 512.</summary>
    public int MaxExplanationLength { get; init; } = 512;

    /// <summary>Maximum include/redirect nesting depth. Always bounded by <see cref="MaxDnsLookups"/> too. Default 10.</summary>
    public int MaxNestingDepth { get; init; } = 10;

    /// <summary>Overall time limit for one check; exceeding it yields TempError. RFC 7208 recommends at least 20 s.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(20);

    /// <summary>The name of this receiving host for the <c>%{r}</c> macro (explanations only).</summary>
    public string ReceivingHostName { get; init; } = "unknown";

    /// <summary>The explanation used when a Fail result has no usable <c>exp=</c>; macros allowed. Null disables it.</summary>
    public string? DefaultExplanation { get; init; } = RfcDefaultExplanation;

    /// <summary>Whether to fetch <c>exp=</c> explanations (one extra TXT query, not counted against the lookup limit).</summary>
    public bool EvaluateExplanations { get; init; } = true;

    /// <summary>Time source for the <c>%{t}</c> macro.</summary>
    public IClock Clock { get; init; } = SystemClock.Instance;

    /// <summary>The default options (RFC limits).</summary>
    public static SpfOptions Default { get; } = new();
}
