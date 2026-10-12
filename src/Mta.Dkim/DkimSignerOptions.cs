using Mta.Core;

namespace Mta.Dkim;

/// <summary>Configuration of one <see cref="DkimSigner"/> (one signing domain and selector). Use one signer per signing domain.</summary>
public sealed class DkimSignerOptions
{
    private static readonly string[] DefaultHeaders =
    [
        "From", "To", "Cc", "Subject", "Date", "Message-ID", "Reply-To", "In-Reply-To", "References",
        "MIME-Version", "Content-Type", "Content-Transfer-Encoding",
        "List-Id", "List-Help", "List-Unsubscribe", "List-Unsubscribe-Post", "List-Subscribe", "List-Post", "List-Owner", "List-Archive",
    ];

    /// <summary>The header names signed by default: From, To, Cc, Subject, Date, Message-ID, Reply-To, In-Reply-To, References, MIME-Version, Content-Type, Content-Transfer-Encoding and the List-* family.</summary>
    public static IReadOnlyList<string> DefaultSignedHeaders => DefaultHeaders;

    /// <summary>The signing domain (<c>d=</c>), an ASCII (A-label) domain name.</summary>
    public required string Domain { get; init; }

    /// <summary>The selector (<c>s=</c>); the public key must be published at <c>selector._domainkey.domain</c>.</summary>
    public required string Selector { get; init; }

    /// <summary>Header canonicalization. Default relaxed.</summary>
    public DkimCanonicalization HeaderCanonicalization { get; init; } = DkimCanonicalization.Relaxed;

    /// <summary>Body canonicalization. Default relaxed.</summary>
    public DkimCanonicalization BodyCanonicalization { get; init; } = DkimCanonicalization.Relaxed;

    /// <summary>Header names to sign (case-insensitive, duplicates ignored). From is always signed. Default <see cref="DefaultSignedHeaders"/>.</summary>
    public IReadOnlyList<string> SignedHeaders { get; init; } = DefaultHeaders;

    /// <summary>
    /// Oversigning (RFC 6376 section 5.4 and 8.15): list every signed header name once more than it occurs, so that adding another
    /// instance of that header after signing (for example a second From or Subject) invalidates the signature. Default true.
    /// The message must already contain all headers it is meant to carry (Date, Message-ID) when it is signed.
    /// </summary>
    public bool OversignHeaders { get; init; } = true;

    /// <summary>Optional signature lifetime; when set, <c>x=</c> is emitted as the signing time plus this value.</summary>
    public TimeSpan? SignatureLifetime { get; init; }

    /// <summary>Optional agent or user identifier (<c>i=</c>), for example <c>@example.com</c> or <c>news@mail.example.com</c>; its domain must be the signing domain or a subdomain of it.</summary>
    public string? Identity { get; init; }

    /// <summary>Emit the signature creation time <c>t=</c>. Default true.</summary>
    public bool IncludeTimestamp { get; init; } = true;

    /// <summary>Time source for <c>t=</c> and <c>x=</c>. Defaults to the system clock.</summary>
    public IClock Clock { get; init; } = SystemClock.Instance;
}
