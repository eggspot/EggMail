using Mta.Core;
using Mta.Dkim;

namespace Mta.Auth.Arc;

/// <summary>Configuration of one <see cref="ArcSealer"/> (one sealing domain and selector).</summary>
public sealed class ArcSealerOptions
{
    private static readonly string[] DefaultHeaders =
    [
        "From", "To", "Cc", "Subject", "Date", "Message-ID", "Reply-To", "In-Reply-To", "References",
        "MIME-Version", "Content-Type", "Content-Transfer-Encoding",
        "List-Id", "List-Help", "List-Unsubscribe", "List-Unsubscribe-Post", "List-Subscribe", "List-Post", "List-Owner", "List-Archive",
        "DKIM-Signature",
    ];

    /// <summary>The header names the ARC-Message-Signature covers by default: the DKIM defaults (<see cref="DkimSignerOptions.DefaultSignedHeaders"/>) plus DKIM-Signature.</summary>
    public static IReadOnlyList<string> DefaultSignedHeaders => DefaultHeaders;

    /// <summary>The sealing domain (<c>d=</c> of the ARC-Message-Signature and the ARC-Seal), an ASCII (A-label) domain name.</summary>
    public required string Domain { get; init; }

    /// <summary>The selector (<c>s=</c>); the public key must be published at <c>selector._domainkey.domain</c>.</summary>
    public required string Selector { get; init; }

    /// <summary>
    /// Header names the ARC-Message-Signature covers (case-insensitive, duplicates ignored). From is always included. Names starting with <c>ARC-</c> are
    /// not allowed. Default <see cref="DefaultSignedHeaders"/>.
    /// </summary>
    public IReadOnlyList<string> SignedHeaders { get; init; } = DefaultHeaders;

    /// <summary>
    /// Oversigning: list every signed header name once more than it occurs, so adding another instance later invalidates the signature. Default
    /// false: RFC 8617 expects later hops to modify messages, and an ARC-Message-Signature only has to survive until the next hop.
    /// </summary>
    public bool OversignHeaders { get; init; }

    /// <summary>Most header fields the message may have. Default 1024.</summary>
    public int MaxHeaderCount { get; init; } = 1024;

    /// <summary>Time source for <c>t=</c>. Defaults to the system clock.</summary>
    public IClock Clock { get; init; } = SystemClock.Instance;
}

/// <summary>The outcome of <see cref="ArcSealer.Seal(ReadOnlySpan{byte}, string, ArcChainResult)"/>.</summary>
public sealed class ArcSealResult
{
    private ArcSealResult(bool isSealed, int instance, ArcChainStatus chainValidationStatus, byte[] headers, string? reason)
    {
        IsSealed = isSealed;
        Instance = instance;
        ChainValidationStatus = chainValidationStatus;
        HeaderBytes = headers;
        NotSealedReason = reason;
    }

    /// <summary>True when a new ARC set was produced.</summary>
    public bool IsSealed { get; }

    /// <summary>The instance number of the new set; 0 when nothing was sealed.</summary>
    public int Instance { get; }

    /// <summary>The <c>cv=</c> value written into the new ARC-Seal; <see cref="ArcChainStatus.None"/> when nothing was sealed.</summary>
    public ArcChainStatus ChainValidationStatus { get; }

    /// <summary>Why no set was added (the chain had already failed, the instance limit is reached, the instance numbers are unreadable); null when sealed.</summary>
    public string? NotSealedReason { get; }

    /// <summary>
    /// The three header lines, ASCII, each CRLF terminated and folded, in the order to prepend them above the existing headers (and above any
    /// older ARC sets): ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results. Empty when nothing was sealed.
    /// </summary>
    public ReadOnlyMemory<byte> HeaderBytes { get; }

    /// <summary>The same as <see cref="HeaderBytes"/> as text.</summary>
    public string Headers => System.Text.Encoding.ASCII.GetString(HeaderBytes.Span);

    internal static ArcSealResult Sealed(int instance, ArcChainStatus cv, byte[] headers) => new(true, instance, cv, headers, null);

    internal static ArcSealResult NotSealed(string reason) => new(false, 0, ArcChainStatus.None, [], reason);
}
