namespace Mta.Auth.Arc;

/// <summary>Policy and resource limits for <see cref="ArcValidator"/>. The defaults are safe for hostile input.</summary>
public sealed class ArcValidatorOptions
{
    /// <summary>Most ARC sets accepted (1 to 50, the RFC 8617 maximum). A chain with a higher instance number fails. Default 50.</summary>
    public int MaxInstances { get; init; } = ArcHeaderNames.MaxInstance;

    /// <summary>Most header fields a message may have; beyond it the chain fails. Default 1024.</summary>
    public int MaxHeaderCount { get; init; } = 1024;

    /// <summary>Longest accepted ARC header field in bytes. Default 16384.</summary>
    public int MaxHeaderLength { get; init; } = ArcHeaderNames.DefaultMaxHeaderLength;

    /// <summary>
    /// Most distinct DKIM key records fetched from DNS for one message. Every seal and message signature names its own domain and selector, so
    /// this bounds the DNS work a hostile chain can cause. Default 25.
    /// </summary>
    public int MaxKeyLookups { get; init; } = 25;

    /// <summary>Keys below this size are rejected (RFC 8301 minimum is 1024). Default 1024.</summary>
    public int MinimumKeyBits { get; init; } = 1024;

    /// <summary>Keys above this size are rejected as a resource-exhaustion guard. Default 4096.</summary>
    public int MaximumKeyBits { get; init; } = 4096;

    /// <summary>
    /// When true (the default), a passing chain also reports <see cref="ArcChainResult.OldestPassingInstance"/>: the ARC-Message-Signatures of
    /// instances 1 up to N-1 are checked in order until one still verifies. This costs up to N-1 more RSA verifications.
    /// </summary>
    public bool ComputeOldestPass { get; init; } = true;
}
