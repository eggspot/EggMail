using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Mta.Integration.Tests.Acme;

/// <summary>The detection of certificates that Pebble cannot look up when they are named in <c>replaces</c>; needs no Pebble.</summary>
public class PebbleSerialTests
{
    private static string ChainWithSerial(byte[] serial)
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest("CN=Serial Root", rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
        using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest("CN=serial.example", leafKey, HashAlgorithmName.SHA256);
        leafRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false));
        using var leaf = leafRequest.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10), serial);
        return leaf.ExportCertificatePem();
    }

    [Theory]
    [InlineData(new byte[] { 0x7f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }, false)]  // top bit clear: the DER integer is the bytes as they are
    [InlineData(new byte[] { 0x0a, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x01, 0x02 }, false)]
    [InlineData(new byte[] { 0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }, true)]    // top bit set: DER adds a 00 byte, which Pebble's index does not have
    [InlineData(new byte[] { 0xcf, 0x11, 0x22 }, true)]
    public void A_serial_with_the_high_bit_set_is_padded_in_the_certificate_id(byte[] serial, bool padded) =>
        Assert.Equal(padded, Pebble.HasPaddedSerial(ChainWithSerial(serial)));
}
