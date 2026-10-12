namespace Mta.Auth.Arc;

/// <summary>
/// An ARC chain validation status (RFC 8617 section 4.4): the <c>cv=</c> value of an ARC-Seal and the outcome of validating a whole chain.
/// The names map one to one onto the <c>arc=</c> result of Authentication-Results.
/// </summary>
public enum ArcChainStatus
{
    /// <summary>No ARC set is present (as a result), or the chain starts here (as the <c>cv</c> of instance 1).</summary>
    None = 0,

    /// <summary>The chain is intact and every seal verified (as a result), or the sealer saw an intact chain (as <c>cv</c>).</summary>
    Pass,

    /// <summary>The chain is broken or failed validation.</summary>
    Fail,
}

/// <summary>Machine readable reason behind an <see cref="ArcChainResult"/>; <see cref="ArcChainResult.Reason"/> carries the human text.</summary>
public enum ArcFailure
{
    /// <summary>No failure.</summary>
    None = 0,

    /// <summary>The message has too many header fields to be processed.</summary>
    TooManyHeaders,

    /// <summary>More ARC sets than <see cref="ArcValidatorOptions.MaxInstances"/>, or an instance number above the limit.</summary>
    TooManyInstances,

    /// <summary>An ARC header exceeds <see cref="ArcValidatorOptions.MaxHeaderLength"/>.</summary>
    HeaderTooLong,

    /// <summary>An ARC header cannot be parsed (missing or invalid tag, bad syntax, bad instance number).</summary>
    MalformedHeader,

    /// <summary>Two headers of the same type carry the same instance number.</summary>
    DuplicateInstance,

    /// <summary>An instance lacks one of its three headers.</summary>
    IncompleteSet,

    /// <summary>The instance numbers are not the contiguous sequence 1..N.</summary>
    InstanceGap,

    /// <summary>The <c>cv=</c> values are inconsistent (instance 1 must be none, later instances must be pass or fail).</summary>
    InvalidChainValidationStatus,

    /// <summary>An ARC-Seal says <c>cv=fail</c>: the chain was already failed upstream.</summary>
    ChainFailedUpstream,

    /// <summary>A signature uses an algorithm other than rsa-sha256 (Ed25519 and rsa-sha1 are not supported).</summary>
    UnsupportedAlgorithm,

    /// <summary>The validator would exceed <see cref="ArcValidatorOptions.MaxKeyLookups"/> DNS key lookups.</summary>
    TooManyKeyLookups,

    /// <summary>No key record exists at <c>selector._domainkey.domain</c>.</summary>
    KeyNotFound,

    /// <summary>The DNS lookup of a key failed (temporary condition).</summary>
    KeyDnsError,

    /// <summary>The key record cannot be parsed or holds no usable RSA key.</summary>
    MalformedKeyRecord,

    /// <summary>The key record has an empty <c>p=</c> (revoked).</summary>
    KeyRevoked,

    /// <summary>The key is smaller than <see cref="ArcValidatorOptions.MinimumKeyBits"/>.</summary>
    KeyTooSmall,

    /// <summary>The key is larger than <see cref="ArcValidatorOptions.MaximumKeyBits"/>.</summary>
    KeyTooLarge,

    /// <summary>The key record is for another key type or does not permit sha256 or email.</summary>
    KeyTypeMismatch,

    /// <summary>The body hash of an ARC-Message-Signature does not match the message body.</summary>
    BodyHashMismatch,

    /// <summary>The signature of an ARC-Message-Signature does not verify.</summary>
    MessageSignatureMismatch,

    /// <summary>The signature of an ARC-Seal does not verify.</summary>
    SealMismatch,

    /// <summary>An unexpected error occurred while validating; reported as a transient failure.</summary>
    InternalError,
}

/// <summary>The outcome of validating the ARC chain of one message (RFC 8617 section 5.2).</summary>
public sealed record ArcChainResult
{
    /// <summary>Creates a result.</summary>
    /// <param name="status">The chain status.</param>
    /// <param name="reason">Short human readable explanation.</param>
    /// <param name="failure">The machine readable reason for a failure.</param>
    public ArcChainResult(ArcChainStatus status, string reason, ArcFailure failure = ArcFailure.None)
    {
        Status = status;
        Reason = reason;
        Failure = failure;
    }

    /// <summary>None, Pass or Fail.</summary>
    public ArcChainStatus Status { get; }

    /// <summary>Short human readable explanation, safe to log and to put in an Authentication-Results comment (it never contains message content).</summary>
    public string Reason { get; }

    /// <summary>The machine readable reason; <see cref="ArcFailure.None"/> unless <see cref="Status"/> is <see cref="ArcChainStatus.Fail"/>.</summary>
    public ArcFailure Failure { get; }

    /// <summary>The number of ARC sets (the highest instance number), 0 when there are none or they could not be counted.</summary>
    public int InstanceCount { get; init; }

    /// <summary>The instance at which validation failed, when it is known.</summary>
    public int? FailedInstance { get; init; }

    /// <summary>
    /// The lowest instance number whose ARC-Message-Signature still verifies against the message (<c>header.oldest-pass</c>), or null when it was
    /// not computed (<see cref="ArcValidatorOptions.ComputeOldestPass"/> off, or the chain did not pass).
    /// </summary>
    public int? OldestPassingInstance { get; init; }

    /// <summary>The signing domains (<c>d=</c>) of the ARC-Seals in instance order, when the chain could be parsed.</summary>
    public IReadOnlyList<string> SealDomains { get; init; } = [];

    /// <summary>True when the failure is a temporary condition (DNS error or internal error): validating again later may give another answer.</summary>
    public bool IsTransient => Failure is ArcFailure.KeyDnsError or ArcFailure.InternalError;

    /// <summary>Convenience: <see cref="Status"/> is <see cref="ArcChainStatus.Pass"/>.</summary>
    public bool IsPass => Status == ArcChainStatus.Pass;
}
