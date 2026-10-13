using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Secrets;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests;

public class SecretsTests
{
    private static async Task<InMemoryStorage> StorageAsync()
    {
        var s = new InMemoryStorage(new StorageOptions());
        await s.InitializeAsync(default);
        return s;
    }

    [Fact]
    public async Task Secrets_survive_a_restart_because_the_key_ring_lives_in_the_config_store()
    {
        await using var storage = await StorageAsync();
        var first = SecretsFactory.Create(new SecretsSection { KeyProtection = KeyProtectionMode.None }, storage.Config);
        byte[] cipher = first.Protect("dkim private key"u8, SecretPurposes.DkimKey);

        var second = SecretsFactory.Create(new SecretsSection { KeyProtection = KeyProtectionMode.None }, storage.Config);

        Assert.Equal("dkim private key"u8.ToArray(), second.Unprotect(cipher, SecretPurposes.DkimKey));
        Assert.Contains((await storage.Config.GetSettingsAsync(null, default)), s => s.Key.StartsWith("dataprotection.key."));
    }

    [Fact]
    public async Task Purposes_are_isolated()
    {
        await using var storage = await StorageAsync();
        var protector = SecretsFactory.Create(new SecretsSection(), storage.Config);
        byte[] cipher = protector.Protect("x"u8, SecretPurposes.DkimKey);
        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(cipher, SecretPurposes.WebhookSecret));
    }

    [Fact]
    public async Task The_key_ring_is_encrypted_when_a_certificate_protects_it()
    {
        await using var storage = await StorageAsync();
        string dir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest("CN=eggmail-keys", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
            string pfx = Path.Combine(dir, "keys.pfx");
            File.WriteAllBytes(pfx, cert.Export(X509ContentType.Pfx, "pw"));
            string pwFile = Path.Combine(dir, "pw.txt");
            File.WriteAllText(pwFile, "pw\n");
            var section = new SecretsSection { KeyProtection = KeyProtectionMode.Certificate, CertificatePath = pfx, CertificatePasswordFile = pwFile };

            var p1 = SecretsFactory.Create(section, storage.Config);
            byte[] cipher = p1.Protect("secret"u8, SecretPurposes.TlsPrivateKey);
            var p2 = SecretsFactory.Create(section, storage.Config);

            Assert.Equal("secret"u8.ToArray(), p2.Unprotect(cipher, SecretPurposes.TlsPrivateKey));
            var ring = (await storage.Config.GetSettingsAsync(null, default)).Where(s => s.Key.StartsWith("dataprotection.key.")).ToList();
            Assert.NotEmpty(ring);
            Assert.All(ring, s => Assert.Contains("EncryptedData", s.ValueJson));
            Assert.All(ring, s => Assert.DoesNotContain("masterKey", s.ValueJson));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
