using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Mta.Core;

namespace Mta.Storage.Portability;

/// <summary>
/// Protects the secrets inside a bundle with ASP.NET Core Data Protection (decision H) without ever writing clear text.
/// <para>
/// Export creates a throwaway RSA certificate and a standalone bundle key ring protected by that certificate
/// (<c>ProtectKeysWithCertificate</c>). The certificate's private key is stored as PKCS#12 encrypted under the operator's
/// export passphrase (PBES2, AES-256, SHA-256, 600,000 iterations). Data Protection has no passphrase mode of its own, so
/// the passphrase travels through the PKCS#12 rather than custom cryptography. Import recovers the certificate with the
/// passphrase, opens the key ring and unprotects each secret in memory, after which the caller re-protects it under the
/// target deployment's own key ring. The source's ring, certificate or KMS key are never needed on the target.
/// </para>
/// </summary>
public static class BundleSecretProtector
{
    public const int MinimumPassphraseLength = 12;
    private const string PurposeRoot = "EggMail.Bundle.v1";
    private const int Iterations = 600_000;

    /// <summary>.NET's default PKCS#12 loader limits (300,000 iterations) are below the 600,000 we write; both sides are ours, so raise them to a bounded value.</summary>
    private static readonly Pkcs12LoaderLimits Limits = new()
    {
        MacIterationLimit = 1_000_000,
        IndividualKdfIterationLimit = 1_000_000,
        TotalKdfIterationLimit = 2_000_000,
    };

    /// <summary>Creates the bundle key ring and certificate under <paramref name="bundle"/> and returns a protector for the export.</summary>
    public static ISecretProtector CreateForExport(BundleWriter bundle, BundleSecrets layout, string passphrase)
    {
        RequirePassphrase(passphrase);
        using var rsa = RSA.Create(3072);
        var req = new CertificateRequest("CN=EggMail bundle", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(10));
        string pfxPath = bundle.ResolvePath(layout.CertificateFile);
        Directory.CreateDirectory(Path.GetDirectoryName(pfxPath)!);
        File.WriteAllBytes(pfxPath, cert.ExportPkcs12(new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, Iterations), passphrase));

        // Re-load so the key ring can be protected with a certificate that carries its private key.
        using var loaded = X509CertificateLoader.LoadPkcs12FromFile(pfxPath, passphrase, X509KeyStorageFlags.Exportable, Limits);
        return Open(bundle.ResolvePath(layout.KeyRingDirectory), loaded, create: true);
    }

    /// <summary>Opens the bundle's key ring with the passphrase. Throws <see cref="BundleException"/> for a wrong passphrase or damaged files.</summary>
    public static ISecretProtector OpenForImport(BundleReader bundle, string passphrase)
    {
        RequirePassphrase(passphrase);
        var layout = bundle.Manifest.Secrets;
        try
        {
            using var cert = X509CertificateLoader.LoadPkcs12FromFile(bundle.PathOf(layout.CertificateFile), passphrase, X509KeyStorageFlags.Exportable, Limits);
            return Open(bundle.PathOf(layout.KeyRingDirectory), cert, create: false);
        }
        catch (Exception ex) when (ex is CryptographicException or Pkcs12LoadLimitExceededException)
        {
            throw new BundleException("The export passphrase is wrong or the bundle's secret files are damaged.", ex);
        }
    }

    private static ISecretProtector Open(string keyRingDirectory, X509Certificate2 cert, bool create)
    {
        Directory.CreateDirectory(keyRingDirectory);
        // The certificate is only needed for the lifetime of the provider; keep a private copy alive with it.
        var owned = X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx, "x"), "x", X509KeyStorageFlags.Exportable);
        var provider = DataProtectionProvider.Create(
            new DirectoryInfo(keyRingDirectory),
            builder =>
            {
                builder.SetApplicationName("EggMail.Bundle");
                builder.ProtectKeysWithCertificate(owned);
                if (!create)
                {
                    builder.DisableAutomaticKeyGeneration();
                }
            },
            owned);
        return new DataProtectionSecretProtector(provider);
    }

    private static void RequirePassphrase(string passphrase)
    {
        if (passphrase.Length < MinimumPassphraseLength)
        {
            throw new ArgumentException($"The export passphrase must be at least {MinimumPassphraseLength} characters.", nameof(passphrase));
        }
    }

    private sealed class DataProtectionSecretProtector(IDataProtectionProvider provider) : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => provider.CreateProtector(PurposeRoot + ":" + purpose).Protect(plaintext.ToArray());

        public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose)
        {
            try
            {
                return provider.CreateProtector(PurposeRoot + ":" + purpose).Unprotect(protectedData.ToArray());
            }
            catch (CryptographicException ex)
            {
                throw new BundleException("A secret in the bundle cannot be unprotected (wrong purpose, tampering or damaged key ring).", ex);
            }
        }
    }
}
