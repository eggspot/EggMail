using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mta.Dns;

namespace Mta.Tls.Dane;

/// <summary>Classification of single TLSA records for SMTP use (RFC 7672 section 3.1).</summary>
public static class TlsaRecordClassifier
{
    /// <summary>
    /// Decides whether a record can be used for SMTP DANE. Usages 2 (DANE-TA) and 3 (DANE-EE) are usable; PKIX-TA(0) and
    /// PKIX-EE(1) are ignored for SMTP; unknown usage, selector or matching type, and association data with a wrong
    /// length for a hash matching type, are unusable.
    /// </summary>
    /// <param name="record">The TLSA record.</param>
    /// <param name="reason">When unusable, why.</param>
    public static bool IsUsable(TlsaRecord record, out string? reason)
    {
        ArgumentNullException.ThrowIfNull(record);
        reason = null;
        switch (record.Usage)
        {
            case 0:
            case 1:
                reason = $"usage {record.Usage} (PKIX-{(record.Usage == 0 ? "TA" : "EE")}) is not used for SMTP (RFC 7672 section 3.1.3); record ignored";
                return false;
            case 2:
            case 3:
                break;
            default:
                reason = $"unknown certificate usage {record.Usage}";
                return false;
        }

        if (record.Selector > 1)
        {
            reason = $"unknown selector {record.Selector}";
            return false;
        }

        int expectedLength = record.MatchingType switch
        {
            0 => -1,
            1 => 32,
            2 => 64,
            _ => -2,
        };
        if (expectedLength == -2)
        {
            reason = $"unknown matching type {record.MatchingType}";
            return false;
        }

        byte[] data = record.Data ?? [];
        if (expectedLength == -1 ? data.Length == 0 : data.Length != expectedLength)
        {
            reason = $"association data has invalid length {data.Length} for matching type {record.MatchingType}";
            return false;
        }

        return true;
    }

    /// <summary>Formats a record in zone-file presentation form for TLS-RPT (<c>name. IN TLSA ( u s m hex )</c>).</summary>
    public static string ToPresentation(TlsaRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return $"{record.Name}. IN TLSA ( {record.Usage} {record.Selector} {record.MatchingType} {Convert.ToHexStringLower(record.Data ?? [])} )";
    }
}

/// <summary>The record that authenticated a DANE session.</summary>
/// <param name="Usage">The certificate usage (2 or 3).</param>
/// <param name="Selector">The selector (0 or 1).</param>
/// <param name="MatchingType">The matching type (0, 1 or 2).</param>
/// <param name="MatchedCertificateSubject">The subject of the certificate the record matched, for logging.</param>
public sealed record DaneMatch(byte Usage, byte Selector, byte MatchingType, string MatchedCertificateSubject);

/// <summary>The outcome of <see cref="DaneVerifier.Verify"/>.</summary>
/// <param name="Success">True when a usable TLSA record authenticated the peer.</param>
/// <param name="Failure">The TLS-RPT classification when <paramref name="Success"/> is false.</param>
/// <param name="Match">The record that matched, on success.</param>
/// <param name="Notes">Human-readable reasons: ignored records, unmatched records, failed checks.</param>
public sealed record DaneVerificationResult(bool Success, TlsResultType? Failure, DaneMatch? Match, IReadOnlyList<string> Notes);

/// <summary>Options for <see cref="DaneVerifier.Verify"/>.</summary>
public sealed class DaneVerifyOptions
{
    /// <summary>Additional acceptable names for DANE-TA name checks (for example the original MX name when the TLSA base domain was reached through a CNAME).</summary>
    public IReadOnlyList<string> AdditionalReferenceNames { get; init; } = [];

    /// <summary>The time used for validity checks of DANE-TA chains. Defaults to now.</summary>
    public DateTimeOffset? Now { get; init; }

    /// <summary>Maximum number of presented chain certificates considered (hostile servers can send many). Default 16.</summary>
    public int MaxChainCertificates { get; init; } = 16;
}

/// <summary>
/// Validates a server certificate chain against TLSA records for SMTP (RFC 7672, RFC 7671, RFC 6698). Only usages
/// DANE-TA(2) and DANE-EE(3) are used. DANE-EE needs no name or expiry check; DANE-TA requires the chain to be
/// anchored at the record, the certificates to be valid in time, and the leaf to carry the MX name.
/// Signature checking is limited to RSA PKCS#1 v1.5 and ECDSA with SHA-256/384/512.
/// </summary>
public static class DaneVerifier
{
    private const int MaxPathDepth = 8;

    /// <summary>Verifies the peer's certificates.</summary>
    /// <param name="records">The secure TLSA record set.</param>
    /// <param name="leaf">The server's end-entity certificate.</param>
    /// <param name="chainCertificates">The other certificates the server presented (the leaf may be included; it is deduplicated).</param>
    /// <param name="mxHostname">The MX host name that DANE-TA certificates must match.</param>
    /// <param name="options">Optional settings.</param>
    public static DaneVerificationResult Verify(
        IReadOnlyList<TlsaRecord> records,
        X509Certificate2 leaf,
        IReadOnlyList<X509Certificate2> chainCertificates,
        string mxHostname,
        DaneVerifyOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(records);
        ArgumentNullException.ThrowIfNull(leaf);
        ArgumentNullException.ThrowIfNull(chainCertificates);
        options ??= new DaneVerifyOptions();
        var notes = new List<string>();

        var usable = new List<TlsaRecord>();
        foreach (var record in records)
        {
            if (TlsaRecordClassifier.IsUsable(record, out string? why))
            {
                usable.Add(record);
            }
            else
            {
                notes.Add(why!);
            }
        }

        if (usable.Count == 0)
        {
            notes.Add("no usable TLSA records");
            return new DaneVerificationResult(false, TlsResultType.TlsaInvalid, null, notes);
        }

        // DANE-EE(3): the leaf must match; no name check, no validity check (RFC 7672 section 3.1.1).
        foreach (var record in usable.Where(r => r.Usage == 3))
        {
            if (Matches(leaf, record))
            {
                notes.Add("DANE-EE matched; name and validity period are not checked (RFC 7672 section 3.1.1)");
                return new DaneVerificationResult(true, null, ToMatch(record, leaf), notes);
            }
        }

        var taRecords = usable.Where(r => r.Usage == 2).ToList();
        if (taRecords.Count == 0)
        {
            notes.Add("no DANE-EE record matched the server certificate");
            return new DaneVerificationResult(false, TlsResultType.ValidationFailure, null, notes);
        }

        var candidates = Dedupe(chainCertificates, leaf, options.MaxChainCertificates);
        var referenceNames = new List<string> { mxHostname };
        referenceNames.AddRange(options.AdditionalReferenceNames);
        DateTimeOffset now = options.Now ?? DateTimeOffset.UtcNow;

        TlsResultType failure = TlsResultType.ValidationFailure;
        bool anchoredAtAll = false;
        foreach (var record in taRecords)
        {
            TaAnchor? anchor = TaAnchor.FromRecord(record);
            var path = new List<X509Certificate2>();
            if (!FindPath(leaf, candidates, record, anchor, path, 0, new[] { 64 }, out X509Certificate2? anchorCertificate))
            {
                notes.Add($"DANE-TA record {record.Usage} {record.Selector} {record.MatchingType} did not anchor the presented chain");
                continue;
            }

            anchoredAtAll = true;
            if (!referenceNames.Any(n => CertificateHelpers.MatchesHost(leaf, n)))
            {
                notes.Add("DANE-TA chain anchored but the certificate does not match the MX name");
                failure = TlsResultType.CertificateHostMismatch;
                continue;
            }

            // Validity applies to the certificates below the trust anchor (and to the leaf even if it is its own anchor).
            bool anchorIsPresentedCertificate = anchorCertificate is not null;
            var checkedCertificates = anchorIsPresentedCertificate && path.Count > 1 ? path.Take(path.Count - 1) : path;
            if (checkedCertificates.Any(c => !CertificateHelpers.IsValidAt(c, now)))
            {
                notes.Add("DANE-TA chain anchored but a certificate is expired or not yet valid");
                failure = TlsResultType.CertificateExpired;
                continue;
            }

            notes.Add("DANE-TA chain verified");
            return new DaneVerificationResult(true, null, ToMatch(record, anchorCertificate ?? leaf), notes);
        }

        if (!anchoredAtAll)
        {
            notes.Add("no TLSA record matched the presented certificate chain");
        }

        return new DaneVerificationResult(false, failure, null, notes);
    }

    private static DaneMatch ToMatch(TlsaRecord record, X509Certificate2 certificate) =>
        new(record.Usage, record.Selector, record.MatchingType, certificate.Subject);

    private static List<X509Certificate2> Dedupe(IReadOnlyList<X509Certificate2> chain, X509Certificate2 leaf, int max)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal) { leaf.Thumbprint };
        var result = new List<X509Certificate2>();
        foreach (var certificate in chain)
        {
            if (result.Count >= max)
            {
                break;
            }

            if (certificate is not null && seen.Add(certificate.Thumbprint))
            {
                result.Add(certificate);
            }
        }

        return result;
    }

    /// <summary>Compares the selected/hashed certificate content with the record's association data.</summary>
    internal static bool Matches(X509Certificate2 certificate, TlsaRecord record)
    {
        byte[]? selected = CertificateHelpers.Select(certificate, record.Selector);
        byte[]? associated = selected is null ? null : CertificateHelpers.ApplyMatchingType(selected, record.MatchingType);
        return associated is not null && CryptographicOperations.FixedTimeEquals(associated, record.Data);
    }

    /// <summary>
    /// Walks from <paramref name="current"/> toward an issuer that the record authorises. On success returns true and
    /// leaves the chain from the leaf up to the anchor in <paramref name="path"/>; <paramref name="presentedAnchor"/> is the
    /// presented certificate that matched the record, or null when the anchor is a certificate or key carried in DNS.
    /// On failure the path is unwound and false is returned.
    /// </summary>
    private static bool FindPath(
        X509Certificate2 current,
        List<X509Certificate2> candidates,
        TlsaRecord record,
        TaAnchor? anchor,
        List<X509Certificate2> path,
        int depth,
        int[] signatureBudget,
        out X509Certificate2? presentedAnchor)
    {
        presentedAnchor = null;
        path.Add(current);
        if (Matches(current, record))
        {
            presentedAnchor = current;
            return true;
        }

        if (anchor is not null && anchor.Authorises(current))
        {
            return true;
        }

        if (depth < MaxPathDepth)
        {
            foreach (var issuer in candidates)
            {
                if (path.Contains(issuer)
                    || !issuer.SubjectName.RawData.AsSpan().SequenceEqual(current.IssuerName.RawData)
                    || !CertificateHelpers.IsCertificateAuthority(issuer))
                {
                    continue;
                }

                // Bound the work a hostile chain of mutually cross-signed certificates can cause.
                if (--signatureBudget[0] < 0)
                {
                    break;
                }

                if (!CertificateHelpers.IsSignedBy(current, CertificateHelpers.GetSubjectPublicKeyInfo(issuer)))
                {
                    continue;
                }

                if (FindPath(issuer, candidates, record, anchor, path, depth + 1, signatureBudget, out presentedAnchor))
                {
                    return true;
                }
            }
        }

        path.RemoveAt(path.Count - 1);
        return false;
    }

    /// <summary>A trust anchor supplied by the TLSA record itself (full certificate or bare public key).</summary>
    private sealed class TaAnchor
    {
        private readonly byte[] _spki;
        private readonly byte[]? _subjectDn;

        private TaAnchor(byte[] spki, byte[]? subjectDn)
        {
            _spki = spki;
            _subjectDn = subjectDn;
        }

        public static TaAnchor? FromRecord(TlsaRecord record)
        {
            if (record.MatchingType != 0)
            {
                return null;
            }

            try
            {
                if (record.Selector == 0)
                {
                    var certificate = X509CertificateLoader.LoadCertificate(record.Data);
                    return CertificateHelpers.IsCertificateAuthority(certificate)
                        ? new TaAnchor(CertificateHelpers.GetSubjectPublicKeyInfo(certificate), certificate.SubjectName.RawData)
                        : null;
                }

                return new TaAnchor(record.Data, null);
            }
            catch (CryptographicException)
            {
                return null;
            }
        }

        public bool Authorises(X509Certificate2 certificate) =>
            (_subjectDn is null || certificate.IssuerName.RawData.AsSpan().SequenceEqual(_subjectDn))
            && CertificateHelpers.IsSignedBy(certificate, _spki);
    }
}
