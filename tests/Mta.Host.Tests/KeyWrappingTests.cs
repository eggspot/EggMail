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

        var other = SecretsFactory.Create(Kms(WriteKeyFile(name: "other.key")), storage.Config);
        var ex = Assert.ThrowsAny<Exception>(() => other.Unprotect(cipher, SecretPurposes.TlsPrivateKey));

        string text = Flatten(ex);
        Assert.Contains("wrapped by provider 'LocalKey' with key", text, StringComparison.Ordinal);
        Assert.Contains("Configure the original key", text, StringComparison.Ordinal);
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

        var protector = SecretsFactory.Create(Kms(keyFile), storage.Config);

        var ex = Assert.ThrowsAny<Exception>(() => protector.Unprotect(cipher, SecretPurposes.DkimKey));
        Assert.Contains("authentication tag", Flatten(ex), StringComparison.Ordinal);   // AES-GCM refuses the altered element
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
        LoadedConfig l = Load(("Secrets:KeyProtection", "Kms"), ("Secrets:KmsProvider", "LocalKey"), ("Secrets:KmsKeyFile", "/run/secrets/ring"), ("Secrets:KmsKey", "abc"));
        Assert.True(l.IsValid, string.Join("; ", l.Errors));
        Assert.Equal(KeyProtectionMode.Kms, l.Config.Secrets.KeyProtection);
        Assert.Equal("/run/secrets/ring", l.Config.Secrets.KmsKeyFile);
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
}
