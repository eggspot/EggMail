using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Secrets;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests;

/// <summary><c>Secrets:KeyProtection=Kms</c>: the key ring in the database holds only keys wrapped by a key that lives outside it.</summary>
public class KeyWrappingTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-kms-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static async Task<InMemoryStorage> StorageAsync()
    {
        var s = new InMemoryStorage(new StorageOptions());
        await s.InitializeAsync(default);
        return s;
    }

    /// <summary>The key-ring elements as stored (the settings hold them as JSON strings of XML).</summary>
    private static async Task<List<(SettingRecord Row, System.Xml.Linq.XElement Xml)>> RingAsync(InMemoryStorage storage) =>
        (await storage.Config.GetSettingsAsync(null, default)).Where(r => r.Key.StartsWith("dataprotection.key.", StringComparison.Ordinal))
            .Select(r => (r, System.Xml.Linq.XElement.Parse(System.Text.Json.JsonSerializer.Deserialize<string>(r.ValueJson)!))).ToList();

    private string WriteKeyFile(byte[]? key = null, string name = "ring.key")
    {
        string path = Path.Combine(_dir, name);
        File.WriteAllText(path, Convert.ToBase64String(key ?? RandomNumberGenerator.GetBytes(32)) + "\n");
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);   // as an operator should: 600
        }

        return path;
    }

    private static SecretsSection Kms(string? keyFile = null, string? key = null, string provider = "LocalKey") =>
        new() { KeyProtection = KeyProtectionMode.Kms, KmsProvider = provider, KmsKeyFile = keyFile, KmsKey = key };

    [Fact]
    public async Task Secrets_survive_a_restart_and_the_stored_ring_holds_only_wrapped_keys()
    {
        await using var storage = await StorageAsync();
        string keyFile = WriteKeyFile();

        var first = SecretsFactory.Create(Kms(keyFile), storage.Config);
        byte[] cipher = first.Protect("dkim private key"u8, SecretPurposes.DkimKey);
        var second = SecretsFactory.Create(Kms(keyFile), storage.Config);   // a new process: it reads the ring back from the store

        Assert.Equal("dkim private key"u8.ToArray(), second.Unprotect(cipher, SecretPurposes.DkimKey));
        var ring = (await storage.Config.GetSettingsAsync(null, default)).Where(s => s.Key.StartsWith("dataprotection.key.", StringComparison.Ordinal)).ToList();
        Assert.NotEmpty(ring);
        Assert.All(ring, s => Assert.Contains("wrappedKey", s.ValueJson, StringComparison.Ordinal));
        Assert.All(ring, s => Assert.DoesNotContain("masterKey", s.ValueJson, StringComparison.Ordinal));   // the unprotected ring (KeyProtection=None) shows it in the clear
    }

    [Fact]
    public async Task The_same_key_given_as_an_environment_value_in_base64_or_hex_opens_the_ring()
    {
        await using var storage = await StorageAsync();
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] cipher = SecretsFactory.Create(Kms(key: Convert.ToBase64String(key)), storage.Config).Protect("x"u8, SecretPurposes.WebhookSecret);

        Assert.Equal("x"u8.ToArray(), SecretsFactory.Create(Kms(key: Convert.ToHexString(key)), storage.Config).Unprotect(cipher, SecretPurposes.WebhookSecret));
        string raw = Path.Combine(_dir, "raw.key");
        File.WriteAllBytes(raw, key);
        Assert.Equal("x"u8.ToArray(), SecretsFactory.Create(Kms(keyFile: raw), storage.Config).Unprotect(cipher, SecretPurposes.WebhookSecret));
    }

    [Fact]
    public async Task A_different_key_cannot_open_the_ring_and_the_error_names_both_key_ids()
    {
        await using var storage = await StorageAsync();
        var original = SecretsFactory.Create(Kms(WriteKeyFile()), storage.Config);
        byte[] cipher = original.Protect("secret"u8, SecretPurposes.TlsPrivateKey);

        // At start, not on the first secret that is read: Data Protection would otherwise treat the unreadable key as missing and may create a new one.
        var ex = Assert.Throws<SecretsConfigurationException>(() => SecretsFactory.Create(Kms(WriteKeyFile(name: "other.key")), storage.Config));

        Assert.Contains("wrapped by provider 'LocalKey' with key", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Configure the original key", ex.Message, StringComparison.Ordinal);
        Assert.Contains(new LocalKeyWrapProvider(Convert.FromBase64String(File.ReadAllText(Path.Combine(_dir, "ring.key")).Trim())).KeyId, ex.Message, StringComparison.Ordinal);   // the id of the key it was wrapped with
        Assert.Single(await RingAsync(storage));   // and no second key was created by the failed start
        Assert.Equal("secret"u8.ToArray(), original.Unprotect(cipher, SecretPurposes.TlsPrivateKey));
    }

    private static string Flatten(Exception ex)
    {
        var parts = new List<string>();
        for (Exception? e = ex; e is not null; e = e.InnerException)
        {
            parts.Add(e.Message);
        }

        return string.Join(" | ", parts);
    }

    [Fact]
    public async Task A_ring_element_that_was_changed_in_the_database_is_rejected()
    {
        await using var storage = await StorageAsync();
        string keyFile = WriteKeyFile();
        byte[] cipher = SecretsFactory.Create(Kms(keyFile), storage.Config).Protect("secret"u8, SecretPurposes.DkimKey);
        var (row, xml) = (await RingAsync(storage)).First();
        System.Xml.Linq.XElement wrapped = xml.Descendants().First(e => e.Name.LocalName == "wrappedKey");
        byte[] bytes = Convert.FromBase64String(wrapped.Value);
        bytes[^1] ^= 1;
        wrapped.Value = Convert.ToBase64String(bytes);
        await storage.Config.SetSettingAsync(row with { ValueJson = System.Text.Json.JsonSerializer.Serialize(xml.ToString(System.Xml.Linq.SaveOptions.DisableFormatting)) }, default);

        var ex = Assert.Throws<SecretsConfigurationException>(() => SecretsFactory.Create(Kms(keyFile), storage.Config));

        Assert.Contains("damaged or was altered", ex.Message, StringComparison.Ordinal);   // AES-GCM refused the altered element
        Assert.NotEmpty(cipher);
    }

    [Theory]
    [InlineData(null, null, "Secrets:KmsKeyFile")]
    [InlineData(null, "dG9vc2hvcnQ=", "exactly 32 bytes")]
    [InlineData(null, "not base64 at all!", "exactly 32 bytes")]
    public async Task A_missing_or_unusable_key_stops_the_start_with_an_actionable_message(string? keyFile, string? key, string expected)
    {
        await using var storage = await StorageAsync();
        var ex = Assert.Throws<InvalidOperationException>(() => SecretsFactory.Create(Kms(keyFile, key), storage.Config));
        Assert.Contains(expected, ex.Message, StringComparison.Ordinal);
        Assert.Contains("openssl rand -base64 32", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unreadable_key_file_is_reported_with_its_path()
    {
        await using var storage = await StorageAsync();
        string missing = Path.Combine(_dir, "missing.key");
        var ex = Assert.Throws<InvalidOperationException>(() => SecretsFactory.Create(Kms(missing), storage.Config));
        Assert.Contains(missing, ex.Message, StringComparison.Ordinal);
    }

    // Configuration

    private static LoadedConfig Load(params (string Key, string? Value)[] values) =>
        ConfigLoader.Load(new ConfigurationBuilder().AddInMemoryCollection(values.ToDictionary(v => v.Key, v => v.Value)).Build());

    [Fact]
    public void The_secrets_keys_are_bound()
    {
        string keyFile = WriteKeyFile();
        LoadedConfig l = Load(("Secrets:KeyProtection", "Kms"), ("Secrets:KmsProvider", "LocalKey"), ("Secrets:KmsKeyFile", keyFile), ("Secrets:KmsKey", "abc"));
        Assert.True(l.IsValid, string.Join("; ", l.Errors));
        Assert.Equal(KeyProtectionMode.Kms, l.Config.Secrets.KeyProtection);
        Assert.Equal(keyFile, l.Config.Secrets.KmsKeyFile);
        Assert.Equal("abc", l.Config.Secrets.KmsKey);
        Assert.Equal("LocalKey", Load().Config.Secrets.KmsProvider);
    }

    [Fact]
    public void An_unknown_key_service_is_a_configuration_error_that_says_what_exists_and_what_to_do()
    {
        LoadedConfig l = Load(("Secrets:KeyProtection", "Kms"), ("Secrets:KmsProvider", "aws-kms"));

        string error = Assert.Single(l.Errors);
        Assert.Contains("'aws-kms'", error, StringComparison.Ordinal);
        Assert.Contains("LocalKey", error, StringComparison.Ordinal);
        Assert.Contains("docs/open-questions.md", error, StringComparison.Ordinal);
        Assert.Contains("Secrets:KeyProtection=Certificate", error, StringComparison.Ordinal);
        Assert.True(Load(("Secrets:KmsProvider", "aws-kms")).IsValid);   // not looked at unless Kms is selected
    }

    [Fact]
    public void Certificate_protection_without_a_certificate_is_a_configuration_error()
    {
        Assert.Contains(Load(("Secrets:KeyProtection", "Certificate")).Errors, e => e.Contains("Secrets:CertificatePath", StringComparison.Ordinal));
    }

    // Plugging in a provider

    private sealed class ReversingProvider(string name) : IKeyWrapProvider
    {
        public string Name => name;

        public string KeyId => "test-key-1";

        public byte[] Wrap(ReadOnlySpan<byte> plaintext) => plaintext.ToArray().Reverse().ToArray();

        public byte[] Unwrap(ReadOnlySpan<byte> wrapped) => wrapped.ToArray().Reverse().ToArray();
    }

    [Fact]
    public async Task A_registered_provider_is_selectable_and_wraps_the_ring()
    {
        string name = "TestKms" + Guid.NewGuid().ToString("N");
        KeyWrapProviders.Register(name, _ => new ReversingProvider(name));
        Assert.Contains(name, KeyWrapProviders.Names);
        Assert.True(Load(("Secrets:KeyProtection", "Kms"), ("Secrets:KmsProvider", name)).IsValid);
        await using var storage = await StorageAsync();

        var protector = SecretsFactory.Create(Kms(provider: name), storage.Config);
        byte[] cipher = protector.Protect("x"u8, SecretPurposes.DkimKey);

        Assert.Equal("x"u8.ToArray(), SecretsFactory.Create(Kms(provider: name), storage.Config).Unprotect(cipher, SecretPurposes.DkimKey));
        var ring = await RingAsync(storage);
        Assert.NotEmpty(ring);
        Assert.All(ring, r => Assert.Equal(name, (string?)r.Xml.Descendants().Single(e => e.Name.LocalName == "wrappedKey").Attribute("provider")));
    }

    [Fact]
    public void The_local_key_provider_authenticates_what_it_unwraps()
    {
        var p = new LocalKeyWrapProvider(RandomNumberGenerator.GetBytes(32));
        byte[] wrapped = p.Wrap("hello"u8);
        Assert.Equal("hello"u8.ToArray(), p.Unwrap(wrapped));
        Assert.NotEqual(p.Wrap("hello"u8), wrapped);   // a fresh nonce each time

        wrapped[^1] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => p.Unwrap(wrapped));
        Assert.Throws<CryptographicException>(() => p.Unwrap([1, 2, 3]));
        Assert.Throws<ArgumentException>(() => new LocalKeyWrapProvider(new byte[16]));
        Assert.NotEqual(p.KeyId, new LocalKeyWrapProvider(RandomNumberGenerator.GetBytes(32)).KeyId);
    }

    // The key is validated with the rest of the configuration

    [Theory]
    [InlineData(null, null)]
    [InlineData(null, "dG9vc2hvcnQ=")]
    public void A_missing_or_unusable_wrapping_key_is_a_configuration_error_at_start(string? keyFile, string? key)
    {
        LoadedConfig l = Load(("Secrets:KeyProtection", "Kms"), ("Secrets:KmsKeyFile", keyFile), ("Secrets:KmsKey", key));
        Assert.Contains(l.Errors, e => e.Contains("32", StringComparison.Ordinal) && e.Contains("openssl rand -base64 32", StringComparison.Ordinal));
        Assert.True(Load(("Secrets:KeyProtection", "Kms"), ("Secrets:KmsKeyFile", WriteKeyFile())).IsValid);
    }

    // The stored ring has to fit the configuration

    private static async Task SetProtectionAsync(InMemoryStorage storage, SecretsSection secrets)
    {
        // Creates the first key under this protection.
        SecretsFactory.Create(secrets, storage.Config).Protect("x"u8, SecretPurposes.DkimKey);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task A_ring_that_was_written_in_the_clear_still_works_under_Kms_but_the_start_warns_and_the_switch_does_not_count_it_as_protected()
    {
        await using var storage = await StorageAsync();
        byte[] cipher = SecretsFactory.Create(new SecretsSection(), storage.Config).Protect("old"u8, SecretPurposes.DkimKey);
        SecretsSection kms = Kms(WriteKeyFile());

        var protector = SecretsFactory.Create(kms, storage.Config);

        Assert.Equal("old"u8.ToArray(), protector.Unprotect(cipher, SecretPurposes.DkimKey));
        Assert.Contains(SecretsFactory.Warnings(kms, storage.Config), w => w.Contains("mta secrets rewrap", StringComparison.Ordinal));
        Assert.False(SecretsFactory.KeysProtectedAtRest(kms, storage.Config));
        Assert.False(SecretsFactory.KeysProtectedAtRest(new SecretsSection(), storage.Config));
    }

    [Fact]
    public async Task A_ring_that_is_all_wrapped_counts_as_protected_and_a_new_one_too()
    {
        await using var storage = await StorageAsync();
        SecretsSection kms = Kms(WriteKeyFile());
        Assert.True(SecretsFactory.KeysProtectedAtRest(kms, storage.Config));   // nothing stored yet: every key made from now on is wrapped
        await SetProtectionAsync(storage, kms);
        Assert.True(SecretsFactory.KeysProtectedAtRest(kms, storage.Config));
        Assert.Empty(SecretsFactory.Warnings(kms, storage.Config));
    }

    [Fact]
    public async Task A_Kms_ring_cannot_be_started_without_Kms_or_under_another_protection()
    {
        await using var storage = await StorageAsync();
        await SetProtectionAsync(storage, Kms(WriteKeyFile()));

        var none = Assert.Throws<SecretsConfigurationException>(() => SecretsFactory.Create(new SecretsSection(), storage.Config));
        Assert.Contains("wrapped by an external key", none.Message, StringComparison.Ordinal);
        Assert.Contains("mta secrets rewrap", none.Message, StringComparison.Ordinal);
        var certificate = Assert.Throws<SecretsConfigurationException>(() => SecretsFactory.Create(new SecretsSection { KeyProtection = KeyProtectionMode.Certificate, CertificatePath = "x.pfx" }, storage.Config));
        Assert.Contains("wrapped by an external key", certificate.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_certificate_ring_cannot_be_started_under_Kms_or_without_a_certificate()
    {
        await using var storage = await StorageAsync();
        using var rsa = RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=ring", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        string pfx = Path.Combine(_dir, "ring.pfx");
        File.WriteAllBytes(pfx, certificate.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, "pw"));
        string pw = Path.Combine(_dir, "pw.txt");
        File.WriteAllText(pw, "pw");
        await SetProtectionAsync(storage, new SecretsSection { KeyProtection = KeyProtectionMode.Certificate, CertificatePath = pfx, CertificatePasswordFile = pw });

        var kms = Assert.Throws<SecretsConfigurationException>(() => SecretsFactory.Create(Kms(WriteKeyFile()), storage.Config));
        Assert.Contains("encrypted with a certificate", kms.Message, StringComparison.Ordinal);
        var none = Assert.Throws<SecretsConfigurationException>(() => SecretsFactory.Create(new SecretsSection(), storage.Config));
        Assert.Contains("encrypted with a certificate", none.Message, StringComparison.Ordinal);
    }

    // mta secrets rewrap

    private static async Task<(int Code, string Out, string Err)> RewrapAsync(InMemoryStorage storage, SecretsSection secrets, bool apply, string? fromKeyFile = null)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        int code = await Mta.Host.Hosting.SecretsCommand.RewrapAsync(storage.Config, secrets, fromKeyFile, null, apply, o, e);
        return (code, o.ToString(), e.ToString());
    }

    [Fact]
    public async Task Rewrap_protects_a_ring_that_was_written_in_the_clear_and_old_secrets_still_open()
    {
        await using var storage = await StorageAsync();
        byte[] cipher = SecretsFactory.Create(new SecretsSection(), storage.Config).Protect("old"u8, SecretPurposes.DkimKey);
        SecretsSection kms = Kms(WriteKeyFile());

        var dry = await RewrapAsync(storage, kms, apply: false);
        Assert.Equal(0, dry.Code);
        Assert.Contains("1 to rewrap", dry.Out, StringComparison.Ordinal);
        Assert.Contains("Nothing was changed", dry.Out, StringComparison.Ordinal);
        Assert.All(await RingAsync(storage), r => Assert.Contains("masterKey", r.Xml.ToString(), StringComparison.Ordinal));

        var applied = await RewrapAsync(storage, kms, apply: true);
        Assert.Equal(0, applied.Code);
        Assert.All(await RingAsync(storage), r => Assert.DoesNotContain("masterKey", r.Xml.ToString(), StringComparison.Ordinal));
        var protector = SecretsFactory.Create(kms, storage.Config);   // starts, with no warning left
        Assert.Equal("old"u8.ToArray(), protector.Unprotect(cipher, SecretPurposes.DkimKey));
        Assert.Empty(SecretsFactory.Warnings(kms, storage.Config));
        Assert.True(SecretsFactory.KeysProtectedAtRest(kms, storage.Config));
        Assert.Contains("0 to rewrap", (await RewrapAsync(storage, kms, apply: true)).Out, StringComparison.Ordinal);   // idempotent
    }

    [Fact]
    public async Task Rewrap_moves_a_ring_from_the_previous_key_to_the_configured_one()
    {
        await using var storage = await StorageAsync();
        string oldKey = WriteKeyFile(name: "old.key");
        byte[] cipher = SecretsFactory.Create(Kms(oldKey), storage.Config).Protect("secret"u8, SecretPurposes.TlsPrivateKey);
        SecretsSection next = Kms(WriteKeyFile(name: "new.key"));

        var withoutOld = await RewrapAsync(storage, next, apply: true);
        Assert.Equal(1, withoutOld.Code);
        Assert.Contains("--from-kms-key-file", withoutOld.Err, StringComparison.Ordinal);

        var done = await RewrapAsync(storage, next, apply: true, fromKeyFile: oldKey);
        Assert.Equal(0, done.Code);
        Assert.Equal("secret"u8.ToArray(), SecretsFactory.Create(next, storage.Config).Unprotect(cipher, SecretPurposes.TlsPrivateKey));
        Assert.Throws<SecretsConfigurationException>(() => SecretsFactory.Create(Kms(oldKey), storage.Config));   // the old key no longer opens it
    }

    [Fact]
    public async Task Rewrap_refuses_a_certificate_ring_it_cannot_convert_and_changes_nothing()
    {
        await using var storage = await StorageAsync();
        using var rsa = RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=ring", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        string pfx = Path.Combine(_dir, "ring.pfx");
        File.WriteAllBytes(pfx, certificate.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, "pw"));
        string pw = Path.Combine(_dir, "pw.txt");
        File.WriteAllText(pw, "pw");
        await SetProtectionAsync(storage, new SecretsSection { KeyProtection = KeyProtectionMode.Certificate, CertificatePath = pfx, CertificatePasswordFile = pw });
        string before = string.Concat((await RingAsync(storage)).Select(r => r.Xml.ToString()));

        var result = await RewrapAsync(storage, Kms(WriteKeyFile()), apply: true);

        Assert.Equal(1, result.Code);
        Assert.Contains("cannot be converted", result.Err, StringComparison.Ordinal);
        Assert.Equal(before, string.Concat((await RingAsync(storage)).Select(r => r.Xml.ToString())));
    }

    [Fact]
    public async Task Rewrap_can_also_protect_a_clear_ring_with_a_certificate()
    {
        await using var storage = await StorageAsync();
        byte[] cipher = SecretsFactory.Create(new SecretsSection(), storage.Config).Protect("old"u8, SecretPurposes.DkimKey);
        using var rsa = RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=ring", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        string pfx = Path.Combine(_dir, "ring.pfx");
        File.WriteAllBytes(pfx, certificate.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, "pw"));
        string pw = Path.Combine(_dir, "pw.txt");
        File.WriteAllText(pw, "pw");
        var section = new SecretsSection { KeyProtection = KeyProtectionMode.Certificate, CertificatePath = pfx, CertificatePasswordFile = pw };

        Assert.Equal(0, (await RewrapAsync(storage, section, apply: true)).Code);

        Assert.All(await RingAsync(storage), r => Assert.Contains("EncryptedData", r.Xml.ToString(), StringComparison.Ordinal));
        Assert.Equal("old"u8.ToArray(), SecretsFactory.Create(section, storage.Config).Unprotect(cipher, SecretPurposes.DkimKey));
    }

    // Pinned names

    [Fact]
    public async Task The_decryptor_type_name_stored_in_every_wrapped_key_is_pinned()
    {
        // Each wrapped element records typeof(KmsXmlDecryptor).AssemblyQualifiedName. Renaming the class, its namespace or the assembly ("mta") makes every existing
        // ring unreadable, so this fails on such a change: add a type-forwarding alias for the old name instead of changing the string below.
        Assert.Equal("Mta.Host.Secrets.KmsXmlDecryptor, mta", KmsXmlDecryptor.StoredTypeName);
        Assert.StartsWith(KmsXmlDecryptor.StoredTypeName, typeof(KmsXmlDecryptor).AssemblyQualifiedName, StringComparison.Ordinal);

        await using var storage = await StorageAsync();
        SecretsFactory.Create(Kms(WriteKeyFile()), storage.Config).Protect("x"u8, SecretPurposes.DkimKey);
        var secret = (await RingAsync(storage)).Single().Xml.Descendants().Single(e => e.Name.LocalName == "encryptedSecret");
        Assert.StartsWith(KmsXmlDecryptor.StoredTypeName, (string?)secret.Attribute("decryptorType"), StringComparison.Ordinal);
        Assert.Equal(RingElementProtection.Kms, KeyRingInspector.Classify((await RingAsync(storage)).Single().Xml));
    }

    [Fact]
    public void The_key_id_is_stable_for_a_key_and_the_wrapped_key_is_bound_to_it()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        var a = new LocalKeyWrapProvider(key);
        var b = new LocalKeyWrapProvider(key);
        Assert.Equal(a.KeyId, b.KeyId);
        Assert.Equal(b.Name, a.Name);
        Assert.Equal("hi"u8.ToArray(), b.Unwrap(a.Wrap("hi"u8)));   // any instance of the same key opens it
    }

    [Fact]
    public void Weak_ways_of_supplying_the_key_are_reported()
    {
        string file = WriteKeyFile();
        Assert.Empty(KeyWrapProviders.Warnings(Kms(file)));
        Assert.Contains(KeyWrapProviders.Warnings(Kms(key: Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)))), w => w.Contains("process environment", StringComparison.Ordinal));
        Assert.Empty(KeyWrapProviders.Warnings(new SecretsSection()));
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
            Assert.Contains(KeyWrapProviders.Warnings(Kms(file)), w => w.Contains("readable by other users", StringComparison.Ordinal));
            File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            Assert.Empty(KeyWrapProviders.Warnings(Kms(file)));
        }
    }
}
