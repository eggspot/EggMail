using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Mta.Tls;

/// <summary>Certificate inspection helpers built on the BCL only (X.509 name matching, signatures, constraints).</summary>
internal static class CertificateHelpers
{
    private const string SubjectAltNameOid = "2.5.29.17";
    private const int MaxNames = 256;

    /// <summary>Returns the dNSName entries of the subject alternative name extension, lower-cased. Never throws.</summary>
    public static IReadOnlyList<string> GetDnsNames(X509Certificate2 certificate)
    {
        var names = new List<string>();
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension.Oid?.Value != SubjectAltNameOid)
            {
                continue;
            }

            try
            {
                var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
                AsnReader sequence = reader.ReadSequence();
                var dnsTag = new Asn1Tag(TagClass.ContextSpecific, 2);
                while (sequence.HasData && names.Count < MaxNames)
                {
                    if (sequence.PeekTag() == dnsTag)
                    {
                        names.Add(sequence.ReadCharacterString(UniversalTagNumber.IA5String, dnsTag).ToLowerInvariant());
                    }
                    else
                    {
                        sequence.ReadEncodedValue();
                    }
                }
            }
            catch (CryptographicException)
            {
                // Malformed extension: use whatever was read so far.
            }
        }

        return names;
    }

    /// <summary>
    /// RFC 6125 style DNS-ID match against the SAN dNSName entries: exact (case-insensitive), or a wildcard whose
    /// <c>*</c> is the entire left-most label and matches exactly one label under a suffix of at least two labels.
    /// The common name is deliberately not consulted.
    /// </summary>
    public static bool MatchesHost(X509Certificate2 certificate, string host)
    {
        if (!DnsNames.TryNormalizeHost(host, out string h))
        {
            return false;
        }

        foreach (string name in GetDnsNames(certificate))
        {
            if (NameMatches(name.TrimEnd('.'), h))
            {
                return true;
            }
        }

        return false;
    }

    internal static bool NameMatches(string certName, string host)
    {
        if (certName.StartsWith("*.", StringComparison.Ordinal))
        {
            ReadOnlySpan<char> suffix = certName.AsSpan(1);
            if (suffix.Length < 4 || suffix[1..].IndexOf('.') < 0 || suffix.Contains('*'))
            {
                return false;
            }

            if (host.Length <= suffix.Length || !host.AsSpan().EndsWith(suffix, StringComparison.Ordinal))
            {
                return false;
            }

            return host.AsSpan(0, host.Length - suffix.Length).IndexOf('.') < 0;
        }

        return !certName.Contains('*') && string.Equals(certName, host, StringComparison.Ordinal);
    }

    /// <summary>True if the certificate may act as an issuer: basic constraints CA=true (or an X.509 v1 certificate) and, when present, keyCertSign.</summary>
    public static bool IsCertificateAuthority(X509Certificate2 certificate)
    {
        bool sawBasicConstraints = false;
        bool isCa = false;
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension is X509BasicConstraintsExtension bc)
            {
                sawBasicConstraints = true;
                isCa = bc.CertificateAuthority;
            }
            else if (extension is X509KeyUsageExtension ku && (ku.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0)
            {
                return false;
            }
        }

        return sawBasicConstraints ? isCa : certificate.Version == 1;
    }

    public static bool IsValidAt(X509Certificate2 certificate, DateTimeOffset when) =>
        when >= new DateTimeOffset(certificate.NotBefore.ToUniversalTime()) && when <= new DateTimeOffset(certificate.NotAfter.ToUniversalTime());

    public static byte[] GetSubjectPublicKeyInfo(X509Certificate2 certificate) => certificate.PublicKey.ExportSubjectPublicKeyInfo();

    /// <summary>The "selected content" of a certificate for a TLSA selector: 0 = full DER certificate, 1 = SubjectPublicKeyInfo.</summary>
    public static byte[]? Select(X509Certificate2 certificate, byte selector) => selector switch
    {
        0 => certificate.RawData,
        1 => GetSubjectPublicKeyInfo(certificate),
        _ => null,
    };

    /// <summary>Applies a TLSA matching type: 0 = identity, 1 = SHA-256, 2 = SHA-512.</summary>
    public static byte[]? ApplyMatchingType(byte[] selected, byte matchingType) => matchingType switch
    {
        0 => selected,
        1 => SHA256.HashData(selected),
        2 => SHA512.HashData(selected),
        _ => null,
    };

    public static string Sha256Hex(X509Certificate certificate) => Convert.ToHexStringLower(SHA256.HashData(certificate.GetRawCertData()));

    /// <summary>
    /// Verifies that <paramref name="subject"/> carries a valid signature by the key in <paramref name="issuerSpki"/>.
    /// Supports RSA PKCS#1 v1.5 and ECDSA with SHA-256/384/512; anything else (SHA-1, RSA-PSS, EdDSA) returns false.
    /// </summary>
    public static bool IsSignedBy(X509Certificate2 subject, ReadOnlySpan<byte> issuerSpki)
    {
        try
        {
            var outer = new AsnReader(subject.RawData, AsnEncodingRules.DER);
            AsnReader certificate = outer.ReadSequence();
            ReadOnlyMemory<byte> tbs = certificate.ReadEncodedValue();
            AsnReader algorithm = certificate.ReadSequence();
            string oid = algorithm.ReadObjectIdentifier();
            byte[] signature = certificate.ReadBitString(out int unusedBits);
            if (unusedBits != 0)
            {
                return false;
            }

            switch (oid)
            {
                case "1.2.840.113549.1.1.11":
                    return VerifyRsa(issuerSpki, tbs.Span, signature, HashAlgorithmName.SHA256);
                case "1.2.840.113549.1.1.12":
                    return VerifyRsa(issuerSpki, tbs.Span, signature, HashAlgorithmName.SHA384);
                case "1.2.840.113549.1.1.13":
                    return VerifyRsa(issuerSpki, tbs.Span, signature, HashAlgorithmName.SHA512);
                case "1.2.840.10045.4.3.2":
                    return VerifyEcdsa(issuerSpki, tbs.Span, signature, HashAlgorithmName.SHA256);
                case "1.2.840.10045.4.3.3":
                    return VerifyEcdsa(issuerSpki, tbs.Span, signature, HashAlgorithmName.SHA384);
                case "1.2.840.10045.4.3.4":
                    return VerifyEcdsa(issuerSpki, tbs.Span, signature, HashAlgorithmName.SHA512);
                default:
                    return false;
            }
        }
        // NotSupportedException: a key on a curve the platform does not know (PlatformNotSupportedException), for example a bare key in a
        // TLSA record; found by the dane fuzz target. Such a key verifies nothing, and the other records must still be tried.
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException or NotSupportedException)
        {
            return false;
        }
    }

    private static bool VerifyRsa(ReadOnlySpan<byte> spki, ReadOnlySpan<byte> data, byte[] signature, HashAlgorithmName hash)
    {
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(spki, out _);
        return rsa.VerifyData(data, signature, hash, RSASignaturePadding.Pkcs1);
    }

    private static bool VerifyEcdsa(ReadOnlySpan<byte> spki, ReadOnlySpan<byte> data, byte[] signature, HashAlgorithmName hash)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(spki, out _);
        return ecdsa.VerifyData(data, signature, hash, DSASignatureFormat.Rfc3279DerSequence);
    }
}
