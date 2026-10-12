namespace Mta.Dkim;

/// <summary>DKIM canonicalization algorithm (RFC 6376 section 3.4), used independently for headers and body.</summary>
public enum DkimCanonicalization
{
    /// <summary>Nothing is changed except trailing empty lines of the body (and the final CRLF of the body).</summary>
    Simple = 0,

    /// <summary>Header names are lower-cased and whitespace is normalised; body lines lose trailing whitespace and collapse whitespace runs.</summary>
    Relaxed = 1,
}

/// <summary>Outcome of verifying one signature. The names map one to one onto the RFC 8601 <c>dkim=</c> result values.</summary>
public enum DkimStatus
{
    /// <summary>There is no DKIM-Signature header at all.</summary>
    None = 0,

    /// <summary>The signature is valid for the message.</summary>
    Pass,

    /// <summary>The signature was checked and is not acceptable (body or signature mismatch, expired, revoked key, weak algorithm or key).</summary>
    Fail,

    /// <summary>A signature is present but could not be processed (syntax errors, unsupported algorithm or version, over the per-message limit).</summary>
    Neutral,

    /// <summary>A transient problem (DNS failure) prevented verification; retrying later may help.</summary>
    TempError,

    /// <summary>A permanent problem (missing or malformed key record) prevented verification.</summary>
    PermError,
}

/// <summary>Machine readable reason behind a <see cref="DkimVerificationResult"/>; <see cref="DkimVerificationResult.Reason"/> carries the human text.</summary>
public enum DkimFailure
{
    None = 0,
    NoSignature,
    SignatureLimitExceeded,
    TooManyHeaders,
    MalformedSignature,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    WeakAlgorithm,
    UnsupportedQueryMethod,
    FromNotSigned,
    InvalidIdentity,
    Expired,
    BodyLengthRejected,
    KeyNotFound,
    KeyDnsError,
    MalformedKeyRecord,
    KeyRevoked,
    KeyTooSmall,
    KeyTooLarge,
    KeyTypeMismatch,
    KeyDoesNotPermit,
    BodyHashMismatch,
    SignatureMismatch,
    InternalError,
}

/// <summary>Raised for invalid signer configuration or a message that cannot be signed (for example no From header). Never raised by verification.</summary>
public sealed class DkimException : Exception
{
    public DkimException(string message) : base(message) { }

    public DkimException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>The result for one DKIM-Signature header of a message.</summary>
public sealed record DkimVerificationResult
{
    public DkimVerificationResult(DkimStatus status, string reason, DkimFailure failure = DkimFailure.None)
    {
        Status = status;
        Reason = reason;
        Failure = failure;
    }

    public DkimStatus Status { get; }

    /// <summary>Short human readable explanation, safe to log and to put in an Authentication-Results comment.</summary>
    public string Reason { get; }

    public DkimFailure Failure { get; }

    /// <summary>The signing domain (<c>d=</c>), or null when the signature could not be parsed that far.</summary>
    public string? Domain { get; init; }

    /// <summary>The selector (<c>s=</c>).</summary>
    public string? Selector { get; init; }

    /// <summary>The agent or user identifier (<c>i=</c>) when present.</summary>
    public string? Identity { get; init; }

    /// <summary>The signature algorithm (<c>a=</c>) exactly as written, lower-cased.</summary>
    public string? Algorithm { get; init; }

    /// <summary>Size in bits of the RSA key used (0 when no key was obtained).</summary>
    public int KeyBits { get; init; }

    /// <summary>True when the key is accepted but below 2048 bits (1024 to 2047).</summary>
    public bool WeakKey { get; init; }

    /// <summary>True when the key record has <c>t=y</c> (the domain is testing DKIM); the result is still the real cryptographic result.</summary>
    public bool Testing { get; init; }

    /// <summary>First 8 characters of the <c>b=</c> value, as used for <c>header.b</c> in Authentication-Results (RFC 6008).</summary>
    public string? HeaderBPrefix { get; init; }

    /// <summary>True when the signature carries <c>l=</c>. Such signatures let an attacker append unsigned content; treat with suspicion.</summary>
    public bool BodyLengthLimited { get; init; }

    /// <summary>True when <c>l=</c> is smaller than the canonicalised body, so some body bytes are not covered by the signature.</summary>
    public bool BodyPartiallySigned { get; init; }

    public DkimCanonicalization? HeaderCanonicalization { get; init; }

    public DkimCanonicalization? BodyCanonicalization { get; init; }

    /// <summary>Signature creation time (<c>t=</c>) when present and representable.</summary>
    public DateTimeOffset? SignedAt { get; init; }

    /// <summary>Signature expiration (<c>x=</c>) when present and representable.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>Convenience: <see cref="Status"/> is <see cref="DkimStatus.Pass"/>.</summary>
    public bool IsPass => Status == DkimStatus.Pass;
}
