namespace Mta.Tls;

/// <summary>
/// The failure classification used by TLS-RPT (RFC 8460 section 4.3) and by the policy and validation code in this
/// assembly. Every failure this library reports maps to exactly one of these values.
/// </summary>
public enum TlsResultType
{
    /// <summary>The receiving MTA did not advertise or complete STARTTLS.</summary>
    StarttlsNotSupported,

    /// <summary>The certificate does not match the expected host name.</summary>
    CertificateHostMismatch,

    /// <summary>The certificate (or a certificate in its chain) is expired or not yet valid.</summary>
    CertificateExpired,

    /// <summary>The certificate chain does not lead to a trusted root (or is otherwise not trusted).</summary>
    CertificateNotTrusted,

    /// <summary>Any other validation failure (also: a DANE record set that does not match the presented chain).</summary>
    ValidationFailure,

    /// <summary>A TLSA record set is secure but unusable or invalid.</summary>
    TlsaInvalid,

    /// <summary>DNSSEC validation failed for the TLSA lookup (the resolver answered SERVFAIL).</summary>
    DnssecInvalid,

    /// <summary>The sender policy required DANE but the receiving MX did not offer a usable TLSA policy.</summary>
    DaneRequired,

    /// <summary>The MTA-STS policy could not be fetched over HTTPS (network, status, content type, size, timeout).</summary>
    StsPolicyFetchError,

    /// <summary>The MTA-STS policy was fetched but is syntactically invalid.</summary>
    StsPolicyInvalid,

    /// <summary>The HTTPS certificate of the MTA-STS policy host failed Web PKI validation.</summary>
    StsWebpkiInvalid,
}

/// <summary>Wire-format helpers for <see cref="TlsResultType"/>.</summary>
public static class TlsResultTypeExtensions
{
    /// <summary>Returns the RFC 8460 <c>result-type</c> string (for example <c>certificate-host-mismatch</c>).</summary>
    public static string ToWireString(this TlsResultType type) => type switch
    {
        TlsResultType.StarttlsNotSupported => "starttls-not-supported",
        TlsResultType.CertificateHostMismatch => "certificate-host-mismatch",
        TlsResultType.CertificateExpired => "certificate-expired",
        TlsResultType.CertificateNotTrusted => "certificate-not-trusted",
        TlsResultType.ValidationFailure => "validation-failure",
        TlsResultType.TlsaInvalid => "tlsa-invalid",
        TlsResultType.DnssecInvalid => "dnssec-invalid",
        TlsResultType.DaneRequired => "dane-required",
        TlsResultType.StsPolicyFetchError => "sts-policy-fetch-error",
        TlsResultType.StsPolicyInvalid => "sts-policy-invalid",
        TlsResultType.StsWebpkiInvalid => "sts-webpki-invalid",
        _ => "validation-failure",
    };

    /// <summary>Parses an RFC 8460 <c>result-type</c> string; returns <see langword="false"/> for unknown values.</summary>
    public static bool TryParseWireString(string? value, out TlsResultType type)
    {
        foreach (var candidate in Enum.GetValues<TlsResultType>())
        {
            if (string.Equals(candidate.ToWireString(), value, StringComparison.Ordinal))
            {
                type = candidate;
                return true;
            }
        }

        type = default;
        return false;
    }
}

/// <summary>The kind of policy a TLS session was subject to, as TLS-RPT reports it (RFC 8460 section 4.4).</summary>
public enum TlsPolicyType
{
    /// <summary>No MTA-STS or DANE policy applied (<c>no-policy-found</c>).</summary>
    NoPolicyFound,

    /// <summary>An MTA-STS policy applied (<c>sts</c>).</summary>
    Sts,

    /// <summary>A DANE TLSA policy applied (<c>tlsa</c>).</summary>
    Tlsa,
}

/// <summary>Wire-format helpers for <see cref="TlsPolicyType"/>.</summary>
public static class TlsPolicyTypeExtensions
{
    /// <summary>Returns the RFC 8460 <c>policy-type</c> string: <c>sts</c>, <c>tlsa</c> or <c>no-policy-found</c>.</summary>
    public static string ToWireString(this TlsPolicyType type) => type switch
    {
        TlsPolicyType.Sts => "sts",
        TlsPolicyType.Tlsa => "tlsa",
        _ => "no-policy-found",
    };
}
