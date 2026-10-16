using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Mta.RemoteMta.Tests.Harness;

/// <summary>A certificate with its private key, ready to be used by a TLS server.</summary>
public sealed class IssuedCertificate(X509Certificate2 withKey)
{
    public X509Certificate2 WithKey { get; } = withKey;

    /// <summary>The certificate without the key: what a client sees and what a trust store holds.</summary>
    public X509Certificate2 Public { get; } = X509CertificateLoader.LoadCertificate(withKey.RawData);

    /// <summary>An exportable copy that SslStream accepts as a server certificate on every platform.</summary>
    public X509Certificate2 ForServer() => X509CertificateLoader.LoadPkcs12(WithKey.Export(X509ContentType.Pfx, "t"), "t");
}

/// <summary>Throwaway certificate authorities and server certificates: nothing touches the disk or the system trust store.</summary>
public static class TestPki
{
    private static long _serial = 5000;

    public static IssuedCertificate CreateRoot(string name = "Fake Root CA")
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var now = DateTimeOffset.UtcNow;
        return new IssuedCertificate(request.CreateSelfSigned(now.AddDays(-400), now.AddYears(10)));
    }

    /// <summary>A leaf for <paramref name="dnsNames"/> issued by <paramref name="issuer"/>; the validity defaults to "valid now".</summary>
    public static IssuedCertificate Leaf(IssuedCertificate issuer, string[] dnsNames, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=" + dnsNames[0], key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var san = new SubjectAlternativeNameBuilder();
        foreach (string name in dnsNames)
        {
            san.AddDnsName(name);
        }

        request.CertificateExtensions.Add(san.Build());
        var now = DateTimeOffset.UtcNow;
        byte[] serial = BitConverter.GetBytes(Interlocked.Increment(ref _serial));
        using var signed = request.Create(issuer.WithKey.SubjectName, X509SignatureGenerator.CreateForECDsa(issuer.WithKey.GetECDsaPrivateKey()!), notBefore ?? now.AddDays(-1), notAfter ?? now.AddDays(90), serial);
        return new IssuedCertificate(signed.CopyWithPrivateKey(key));
    }

    /// <summary>A self-signed server certificate (its own, and only, trust anchor).</summary>
    public static IssuedCertificate SelfSigned(params string[] dnsNames)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=" + dnsNames[0], key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var san = new SubjectAlternativeNameBuilder();
        foreach (string name in dnsNames)
        {
            san.AddDnsName(name);
        }

        request.CertificateExtensions.Add(san.Build());
        var now = DateTimeOffset.UtcNow;
        return new IssuedCertificate(request.CreateSelfSigned(now.AddDays(-1), now.AddDays(90)));
    }

    /// <summary>The TLSA association data for a certificate: <c>selector</c> 0 is the whole certificate, 1 the public key; <c>matchingType</c> 0 exact, 1 SHA-256, 2 SHA-512.</summary>
    public static byte[] TlsaData(X509Certificate2 certificate, byte selector, byte matchingType)
    {
        byte[] selected = selector == 0 ? certificate.RawData : certificate.PublicKey.ExportSubjectPublicKeyInfo();
        return matchingType switch
        {
            0 => selected,
            1 => SHA256.HashData(selected),
            2 => SHA512.HashData(selected),
            _ => throw new ArgumentOutOfRangeException(nameof(matchingType)),
        };
    }
}
