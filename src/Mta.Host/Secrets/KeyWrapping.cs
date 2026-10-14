using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
using Mta.Host.Configuration;

namespace Mta.Host.Secrets;

/// <summary>
/// An external key service that wraps and unwraps the Data Protection key ring (<c>Secrets:KeyProtection=Kms</c>, design section 9.1): the ring in the config store holds
/// only wrapped keys, and the key that wraps them lives outside the database. A cloud key management service (AWS KMS, Azure Key Vault, Google Cloud KMS) is one
/// implementation: <c>Wrap</c> and <c>Unwrap</c> are calls to the service, authorized by credentials from the environment. The built-in implementation is
/// <see cref="LocalKeyWrapProvider"/> (a key from a file or the environment); no cloud SDK is referenced by this repository.
/// <para>Implementations must be thread-safe, must authenticate (<see cref="Unwrap"/> throws <see cref="CryptographicException"/> for a wrong key or tampered data) and must
/// never return the key material they hold. Register one with <see cref="KeyWrapProviders.Register"/> and select it with <c>Secrets:KmsProvider</c>.</para>
/// </summary>
public interface IKeyWrapProvider
{
    /// <summary>The name <c>Secrets:KmsProvider</c> selects (recorded in every wrapped key so a wrong provider is diagnosed, not guessed).</summary>
    string Name { get; }

    /// <summary>Identifies the wrapping key without revealing it (a fingerprint or the key service's key id); recorded with every wrapped key.</summary>
    string KeyId { get; }

    byte[] Wrap(ReadOnlySpan<byte> plaintext);

    byte[] Unwrap(ReadOnlySpan<byte> wrapped);
}

/// <summary>The providers that can be selected with <c>Secrets:KmsProvider</c>.</summary>
public static class KeyWrapProviders
{
    public const string LocalKey = "LocalKey";

    private static readonly object Gate = new();
    private static readonly Dictionary<string, Func<SecretsSection, IKeyWrapProvider>> Factories = new(StringComparer.OrdinalIgnoreCase)
    {
        [LocalKey] = LocalKeyWrapProvider.FromConfiguration,
    };

    public static IReadOnlyList<string> Names
    {
        get
        {
            lock (Gate)
            {
                return [.. Factories.Keys.Order(StringComparer.OrdinalIgnoreCase)];
            }
        }
    }

    public static bool IsRegistered(string? name)
    {
        lock (Gate)
        {
            return name is not null && Factories.ContainsKey(name);
        }
    }

    /// <summary>Adds (or replaces) a provider; the factory reads its settings from <see cref="SecretsSection"/> and the environment and throws <see cref="InvalidOperationException"/> with an actionable message when they are missing.</summary>
    public static void Register(string name, Func<SecretsSection, IKeyWrapProvider> factory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(factory);
        lock (Gate)
        {
            Factories[name] = factory;
        }
    }

    public static IKeyWrapProvider Create(SecretsSection secrets)
    {
        Func<SecretsSection, IKeyWrapProvider> factory;
        lock (Gate)
        {
            if (!Factories.TryGetValue(secrets.KmsProvider, out factory!))
            {
                throw new InvalidOperationException(UnknownProviderMessage(secrets.KmsProvider, [.. Factories.Keys.Order(StringComparer.OrdinalIgnoreCase)]));
            }
        }

        return factory(secrets);
    }

    /// <summary>Weaknesses of how the wrapping key is supplied; logged at start (the start itself is not refused).</summary>
    public static IReadOnlyList<string> Warnings(SecretsSection secrets)
    {
        var warnings = new List<string>();
        if (secrets.KeyProtection != KeyProtectionMode.Kms || !string.Equals(secrets.KmsProvider, LocalKey, StringComparison.OrdinalIgnoreCase))
        {
            return warnings;
        }

        if (!string.IsNullOrWhiteSpace(secrets.KmsKey) && string.IsNullOrWhiteSpace(secrets.KmsKeyFile))
        {
            warnings.Add("Secrets:KmsKey carries the key ring's wrapping key in the process environment, where anyone who can read it (docker inspect, /proc, crash dumps) has it. Prefer Secrets:KmsKeyFile with a mounted secret.");
        }

        if (!string.IsNullOrWhiteSpace(secrets.KmsKeyFile) && !OperatingSystem.IsWindows())
        {
            try
            {
                UnixFileMode mode = File.GetUnixFileMode(secrets.KmsKeyFile);
                if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.OtherRead | UnixFileMode.OtherWrite)) != 0)
                {
                    warnings.Add($"Secrets:KmsKeyFile '{secrets.KmsKeyFile}' is readable by other users ({mode}). Make it readable by the EggMail user only (chmod 600).");
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // the key could not be read either; the factory reports that
            }
        }

        return warnings;
    }

    public static string UnknownProviderMessage(string? name, IReadOnlyList<string> available) =>
        $"Secrets:KmsProvider '{name}' is not available. Built in: {string.Join(", ", available)}. " +
        "Cloud key services (AWS KMS, Azure Key Vault, Google Cloud KMS) are not part of this build: each needs an SDK and an account to be written and verified against (docs/open-questions.md). " +
        "Use Secrets:KmsProvider=LocalKey with a key held outside the database, or Secrets:KeyProtection=Certificate.";
}

/// <summary>
/// Wraps with AES-256-GCM under a 32-byte key that the operator keeps outside the database (a mounted secret file, or an environment variable): a key-encryption key
/// without a remote service. It protects the key ring from anyone who can read only the database or its backups; whoever can read the key file as well can open the ring.
/// </summary>
public sealed class LocalKeyWrapProvider : IKeyWrapProvider
{
    private const byte Version = 1;
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly byte[] _key;
    private readonly byte[] _associatedData;

    public LocalKeyWrapProvider(ReadOnlySpan<byte> key)
    {
        if (key.Length != 32)
        {
            throw new ArgumentException($"The key must be exactly 32 bytes (256 bits), not {key.Length}.", nameof(key));
        }

        _key = key.ToArray();
        // A keyed hash of a constant: identifies the key without revealing anything about it that the key itself would not.
        KeyId = Convert.ToHexString(HMACSHA256.HashData(_key, "EggMail.KeyRing.KeyId"u8).AsSpan(0, 8)).ToLowerInvariant();
        // The provider name and key id are authenticated with every wrapped key, so a wrapped key cannot be relabelled as another key's.
        _associatedData = Encoding.ASCII.GetBytes("EggMail.KeyRing.v1|" + KeyWrapProviders.LocalKey + "|" + KeyId);
    }

    public string Name => KeyWrapProviders.LocalKey;

    public string KeyId { get; }

    public byte[] Wrap(ReadOnlySpan<byte> plaintext)
    {
        byte[] result = new byte[1 + NonceSize + TagSize + plaintext.Length];
        result[0] = Version;
        Span<byte> nonce = result.AsSpan(1, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plaintext, result.AsSpan(1 + NonceSize + TagSize), result.AsSpan(1 + NonceSize, TagSize), _associatedData);
        return result;
    }

    public byte[] Unwrap(ReadOnlySpan<byte> wrapped)
    {
        if (wrapped.Length < 1 + NonceSize + TagSize || wrapped[0] != Version)
        {
            throw new CryptographicException("The wrapped key is not in the LocalKey format (version 1).");
        }

        byte[] plaintext = new byte[wrapped.Length - 1 - NonceSize - TagSize];
        using var aes = new AesGcm(_key, TagSize);
        aes.Decrypt(wrapped.Slice(1, NonceSize), wrapped[(1 + NonceSize + TagSize)..], wrapped.Slice(1 + NonceSize, TagSize), plaintext, _associatedData);
        return plaintext;
    }

    /// <summary>Reads <c>Secrets:KmsKeyFile</c> (preferred: a mounted secret) or <c>Secrets:KmsKey</c>; base64 (44 characters), hex (64) or the 32 raw bytes of a file.</summary>
    public static IKeyWrapProvider FromConfiguration(SecretsSection secrets)
    {
        byte[]? key;
        string source;
        if (!string.IsNullOrWhiteSpace(secrets.KmsKeyFile))
        {
            source = "Secrets:KmsKeyFile";
            byte[] content;
            try
            {
                content = File.ReadAllBytes(secrets.KmsKeyFile);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new InvalidOperationException($"Secrets:KmsKeyFile '{secrets.KmsKeyFile}' cannot be read: {ex.Message}", ex);
            }

            key = content.Length == 32 ? content : Decode(Encoding.ASCII.GetString(content).Trim());
            if (!ReferenceEquals(key, content))
            {
                CryptographicOperations.ZeroMemory(content);
            }
        }
        else if (!string.IsNullOrWhiteSpace(secrets.KmsKey))
        {
            source = "Secrets:KmsKey";
            key = Decode(secrets.KmsKey.Trim());
        }
        else
        {
            throw new InvalidOperationException(
                "Secrets:KeyProtection=Kms with KmsProvider=LocalKey needs a 32-byte key held outside the database: set Secrets:KmsKeyFile (a mounted secret file) or Secrets:KmsKey. " +
                "Create one with: openssl rand -base64 32 > eggmail-keyring.key");
        }

        if (key is not { Length: 32 })
        {
            throw new InvalidOperationException($"{source} must hold exactly 32 bytes as base64 (44 characters), hex (64 characters) or raw bytes. Create one with: openssl rand -base64 32");
        }

        try
        {
            return new LocalKeyWrapProvider(key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static byte[]? Decode(string text)
    {
        if (text.Length == 64)
        {
            try
            {
                return Convert.FromHexString(text);
            }
            catch (FormatException)
            {
                // not hex: fall through to base64
            }
        }

        try
        {
            return Convert.FromBase64String(text);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}

/// <summary>Data Protection hook: wraps every key-ring element with the selected <see cref="IKeyWrapProvider"/> before it reaches the config store.</summary>
public sealed class KmsXmlEncryptor(IKeyWrapProvider provider) : IXmlEncryptor
{
    public static readonly XNamespace Ns = "urn:eggmail:keywrap:v1";

    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(plaintextElement.ToString(SaveOptions.DisableFormatting));
        byte[] wrapped = provider.Wrap(plaintext);
        CryptographicOperations.ZeroMemory(plaintext);
        var element = new XElement(Ns + "wrappedKey", new XAttribute("provider", provider.Name), new XAttribute("keyId", provider.KeyId), Convert.ToBase64String(wrapped));
        return new EncryptedXmlInfo(element, typeof(KmsXmlDecryptor));
    }
}

/// <summary>
/// Unwraps a key-ring element; created by Data Protection with the provider from the service container.
/// <para><b>The type name is stored in every wrapped element</b> (<c>decryptorType</c>, the assembly-qualified name; the version is ignored on load). Renaming this
/// class, its namespace or the assembly (<c>mta</c>) makes every existing ring unreadable. <c>KeyWrappingTests</c> pins <see cref="StoredTypeName"/>.</para>
/// </summary>
public sealed class KmsXmlDecryptor(IServiceProvider services) : IXmlDecryptor
{
    /// <summary>Namespace-qualified type name and assembly name, as stored (without version).</summary>
    public const string StoredTypeName = "Mta.Host.Secrets.KmsXmlDecryptor, mta";

    public XElement Decrypt(XElement encryptedElement)
    {
        IKeyWrapProvider provider = services.GetRequiredService<IKeyWrapProvider>();
        byte[] plaintext = UnwrapElement(encryptedElement, provider);
        try
        {
            return XElement.Parse(Encoding.UTF8.GetString(plaintext));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Unwraps one <c>wrappedKey</c> element. The provider decides whether the key fits; only when it cannot unwrap is the recorded provider and key id compared with
    /// the configured ones, to say which key to bring back (a key service may well accept a key under another id or alias, so the ids alone never refuse).
    /// </summary>
    public static byte[] UnwrapElement(XElement wrappedKey, IKeyWrapProvider provider)
    {
        string? usedProvider = (string?)wrappedKey.Attribute("provider");
        string? usedKeyId = (string?)wrappedKey.Attribute("keyId");
        try
        {
            return provider.Unwrap(Convert.FromBase64String(wrappedKey.Value));
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            bool same = string.Equals(usedProvider, provider.Name, StringComparison.OrdinalIgnoreCase) && string.Equals(usedKeyId, provider.KeyId, StringComparison.Ordinal);
            throw new CryptographicException(same
                ? $"A key of the Data Protection key ring (wrapped with {usedProvider} key '{usedKeyId}') cannot be unwrapped: it is damaged or was altered in the database."
                : $"The Data Protection key ring was wrapped by provider '{usedProvider}' with key '{usedKeyId}', but Secrets:KmsProvider '{provider.Name}' offers key '{provider.KeyId}'. " +
                  "Configure the original key (a rotated key cannot open the old ring), or restore the database from before the change.", ex);
        }
    }
}

/// <summary>Start-up validation of <c>Secrets:*</c>, so a missing certificate or an unknown key service stops the start with the key's name instead of failing later.</summary>
public static class SecretsConfigurationCheck
{
    public static void Validate(SecretsSection secrets, List<string> errors)
    {
        if (secrets.KeyProtection == KeyProtectionMode.Certificate && string.IsNullOrWhiteSpace(secrets.CertificatePath))
        {
            errors.Add("Secrets:CertificatePath is required when Secrets:KeyProtection is Certificate.");
        }

        if (secrets.KeyProtection == KeyProtectionMode.Kms && !KeyWrapProviders.IsRegistered(secrets.KmsProvider))
        {
            errors.Add(KeyWrapProviders.UnknownProviderMessage(secrets.KmsProvider, KeyWrapProviders.Names));
        }
        else if (secrets.KeyProtection == KeyProtectionMode.Kms && string.Equals(secrets.KmsProvider, KeyWrapProviders.LocalKey, StringComparison.OrdinalIgnoreCase))
        {
            // Reading the key has no side effect, so a missing or unusable one is a configuration error (exit 2) like any other, not a crash later.
            try
            {
                KeyWrapProviders.Create(secrets);
            }
            catch (InvalidOperationException ex)
            {
                errors.Add(ex.Message);
            }
        }
    }
}
