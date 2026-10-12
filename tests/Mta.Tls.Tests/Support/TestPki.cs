using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Mta.Tls.Tests.Support;

/// <summary>A generated certificate together with its private key (disposed with the test process).</summary>
public sealed class IssuedCertificate
{
    public IssuedCertificate(X509Certificate2 withKey)
    {
        WithKey = withKey;
        Public = X509CertificateLoader.LoadCertificate(withKey.RawData);
    }

    /// <summary>The certificate including its private key (needed to issue or to act as a TLS server).</summary>
    public X509Certificate2 WithKey { get; }

    /// <summary>The certificate without a private key (what a TLS client sees).</summary>
    public X509Certificate2 Public { get; }
}

/// <summary>Generates throwaway certificate chains with <see cref="CertificateRequest"/>; nothing touches the disk or system stores.</summary>
public static class TestPki
{
    private static long _serial = 1000;

    public static IssuedCertificate CreateRoot(string commonName = "Test Root CA", bool rsa = false, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)
    {
        var request = NewRequest($"CN={commonName}", rsa);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var cert = request.CreateSelfSigned(notBefore ?? DateTimeOffset.UtcNow.AddDays(-30), notAfter ?? DateTimeOffset.UtcNow.AddYears(10));
        return new IssuedCertificate(cert);
    }

    public static IssuedCertificate CreateIntermediate(IssuedCertificate issuer, string commonName = "Test Intermediate CA", bool rsa = false, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null, bool isCa = true)
    {
        var request = NewRequest($"CN={commonName}", rsa);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCa, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return Issue(request, issuer, notBefore, notAfter);
    }

    public static IssuedCertificate CreateLeaf(IssuedCertificate issuer, string[] dnsNames, string? commonName = null, bool rsa = false, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)
    {
        var request = NewRequest($"CN={commonName ?? (dnsNames.Length > 0 ? dnsNames[0] : "leaf")}", rsa);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        if (dnsNames.Length > 0)
        {
            var san = new SubjectAlternativeNameBuilder();
            foreach (string name in dnsNames)
            {
                san.AddDnsName(name);
            }

            request.CertificateExtensions.Add(san.Build());
        }

        return Issue(request, issuer, notBefore, notAfter);
    }

    /// <summary>A self-signed server certificate (acts as its own trust anchor).</summary>
    public static IssuedCertificate CreateSelfSignedLeaf(string[] dnsNames, bool rsa = false, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)
    {
        var request = NewRequest($"CN={dnsNames[0]}", rsa);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var san = new SubjectAlternativeNameBuilder();
        foreach (string name in dnsNames)
        {
            san.AddDnsName(name);
        }

        request.CertificateExtensions.Add(san.Build());
        return new IssuedCertificate(request.CreateSelfSigned(notBefore ?? DateTimeOffset.UtcNow.AddDays(-1), notAfter ?? DateTimeOffset.UtcNow.AddDays(90)));
    }

    /// <summary>Re-imports a certificate with its key so it can be used by <see cref="System.Net.Security.SslStream"/> as a server certificate.</summary>
    public static X509Certificate2 ForServerUse(IssuedCertificate cert)
    {
        byte[] pfx = cert.WithKey.Export(X509ContentType.Pfx, "test");
        return X509CertificateLoader.LoadPkcs12(pfx, "test");
    }

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<CertificateRequest, AsymmetricAlgorithm> Keys = new();

    private static CertificateRequest NewRequest(string subject, bool rsa)
    {
        CertificateRequest request;
        AsymmetricAlgorithm key;
        if (rsa)
        {
            var k = RSA.Create(2048);
            key = k;
            request = new CertificateRequest(subject, k, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        else
        {
            var k = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            key = k;
            request = new CertificateRequest(subject, k, HashAlgorithmName.SHA256);
        }

        Keys.Add(request, key);
        return request;
    }

    private static IssuedCertificate Issue(CertificateRequest request, IssuedCertificate issuer, DateTimeOffset? notBefore, DateTimeOffset? notAfter)
    {
        byte[] serial = BitConverter.GetBytes(Interlocked.Increment(ref _serial));
        X509Certificate2 signed = request.Create(
            issuer.WithKey,
            notBefore ?? DateTimeOffset.UtcNow.AddDays(-1),
            notAfter ?? DateTimeOffset.UtcNow.AddDays(90),
            serial);

        // Create(...) returns a certificate without a private key; attach the one generated for the request.
        AsymmetricAlgorithm key = Keys.TryGetValue(request, out var k) ? k : throw new InvalidOperationException();
        X509Certificate2 withKey = key is RSA rsa ? signed.CopyWithPrivateKey(rsa) : signed.CopyWithPrivateKey((ECDsa)key);
        return new IssuedCertificate(withKey);
    }
}
