using Mta.Core;

namespace Mta.Dkim;

/// <summary>Policy and resource limits for <see cref="DkimVerifier"/>. The defaults are safe for hostile input.</summary>
public sealed class DkimVerifierOptions
{
    /// <summary>Time source for signature expiry checks. Defaults to the system clock.</summary>
    public IClock Clock { get; init; } = SystemClock.Instance;

    /// <summary>Tolerance applied to <c>x=</c> expiry (a signature is expired only after x= plus this value). Default 5 minutes.</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Most DKIM-Signature headers that are actually verified (each may cost a DNS query and an RSA operation); the rest are reported as neutral. Default 5.</summary>
    public int MaxSignaturesVerified { get; init; } = 5;

    /// <summary>Most header fields a message may have; beyond it every signature is reported as neutral. Default 1024.</summary>
    public int MaxHeaderCount { get; init; } = 1024;

    /// <summary>Longest accepted DKIM-Signature header in bytes. Default 16384.</summary>
    public int MaxSignatureHeaderLength { get; init; } = 16384;

    /// <summary>Keys below this size are rejected (RFC 8301 minimum is 1024). Default 1024.</summary>
    public int MinimumKeyBits { get; init; } = 1024;

    /// <summary>Keys below this size are accepted but flagged <see cref="DkimVerificationResult.WeakKey"/>. Default 2048.</summary>
    public int WeakKeyBelowBits { get; init; } = 2048;

    /// <summary>Keys above this size are rejected as a resource-exhaustion guard. Default 4096.</summary>
    public int MaximumKeyBits { get; init; } = 4096;

    /// <summary>When true, signatures carrying <c>l=</c> fail. Default false (they verify but are flagged, see <see cref="DkimVerificationResult.BodyLengthLimited"/>).</summary>
    public bool RejectBodyLengthLimit { get; init; }
}
