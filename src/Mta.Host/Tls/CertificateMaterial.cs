using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Mta.Core;
using Mta.Storage;

namespace Mta.Host.Tls;

/// <summary>Builds usable certificates from stored records and creates the first-run self-signed certificate.</summary>
public static class CertificateMaterial
{
    /// <summary>Converts a stored record (chain PEM plus Data Protection-protected PKCS#8 key) into a leaf and its intermediates.</summary>
    public static (X509Certificate2 Leaf, X509Certificate2Collection Intermediates) Load(CertificateRecord record, ISecretProtector protector)
    {
        byte[] keyDer = protector.Unprotect(record.PrivateKeyProtected, SecretPurposes.TlsPrivateKey);
        try
        {
            var all = new X509Certificate2Collection();
            all.ImportFromPem(record.ChainPem);
            if (all.Count == 0)
            {
                throw new CryptographicException("The stored certificate chain is empty.");
            }

            using var withKey = X509Certificate2.CreateFromPem(all[0].ExportCertificatePem(), PemEncoding.WriteString("PRIVATE KEY", keyDer));
            // Round-trip through PKCS#12 so the private key is usable by SslStream on every platform (including macOS).
            var leaf = X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pfx, "x"), "x", X509KeyStorageFlags.Exportable);
            var intermediates = new X509Certificate2Collection();
            for (int i = 1; i < all.Count; i++)
            {
                intermediates.Add(all[i]);
            }

            return (leaf, intermediates);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyDer);
        }
    }

    /// <summary>Loads a certificate from override files: a PEM chain plus a PEM key, or a PFX.</summary>
    public static (X509Certificate2 Leaf, X509Certificate2Collection Intermediates) LoadFiles(string certificatePath, string? keyPath, string? pfxPassword)
    {
        if (string.IsNullOrEmpty(keyPath))
        {
            var pfx = X509CertificateLoader.LoadPkcs12FromFile(certificatePath, pfxPassword, X509KeyStorageFlags.Exportable);
            return (pfx, new X509Certificate2Collection());
        }

        string chainPem = File.ReadAllText(certificatePath);
        string keyPem = File.ReadAllText(keyPath);
        var all = new X509Certificate2Collection();
        all.ImportFromPem(chainPem);
        if (all.Count == 0)
        {
            throw new CryptographicException("No certificate found in " + certificatePath);
        }

        using var withKey = X509Certificate2.CreateFromPem(all[0].ExportCertificatePem(), keyPem);
        var leaf = X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pfx, "x"), "x", X509KeyStorageFlags.Exportable);
        var intermediates = new X509Certificate2Collection();
        for (int i = 1; i < all.Count; i++)
        {
            intermediates.Add(all[i]);
        }

        return (leaf, intermediates);
    }

    /// <summary>The DNS names a certificate covers (SAN DNS entries, else the subject CN).</summary>
    public static IReadOnlyList<string> SubjectsOf(X509Certificate2 cert)
    {
        var names = new List<string>();
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509SubjectAlternativeNameExtension san)
            {
                names.AddRange(san.EnumerateDnsNames());
            }
        }

        if (names.Count == 0)
        {
            string cn = cert.GetNameInfo(X509NameType.DnsName, false);
            if (!string.IsNullOrEmpty(cn))
            {
                names.Add(cn);
            }
        }

        return names.Select(n => n.ToLowerInvariant()).Distinct().ToList();
    }

    /// <summary>Creates a one-year ECDSA P-256 self-signed certificate (first run; flagged in the dashboard).</summary>
    public static CertificateRecord CreateSelfSigned(string hostname, ISecretProtector protector, DateTimeOffset now)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest($"CN={hostname}", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(hostname);
        if (!hostname.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            san.AddDnsName("localhost");
        }

        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        using var cert = req.CreateSelfSigned(now.AddMinutes(-5), now.AddYears(1));
        byte[] pkcs8 = key.ExportPkcs8PrivateKey();
        try
        {
            return new CertificateRecord(
                Ids.New(), $"selfsigned:{hostname}", [hostname.ToLowerInvariant(), "localhost"], cert.NotBefore.ToUniversalTime(), cert.NotAfter.ToUniversalTime(),
                cert.ExportCertificatePem(), protector.Protect(pkcs8, SecretPurposes.TlsPrivateKey), "selfsigned", cert.Thumbprint, Active: true,
                Version: now.ToUnixTimeMilliseconds(), CreatedAt: now);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    /// <summary>Does <paramref name="pattern"/> (possibly <c>*.example.com</c>) cover <paramref name="host"/>?</summary>
    public static bool Matches(string pattern, string host)
    {
        pattern = pattern.ToLowerInvariant();
        host = host.ToLowerInvariant().TrimEnd('.');
        if (pattern == host)
        {
            return true;
        }

        if (pattern.StartsWith("*.", StringComparison.Ordinal))
        {
            int dot = host.IndexOf('.');
            return dot > 0 && host[(dot + 1)..] == pattern[2..];
        }

        return false;
    }
}
