using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography.X509Certificates;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Storage;

namespace Mta.Host.Secrets;

/// <summary><see cref="ISecretProtector"/> over ASP.NET Core Data Protection; each purpose string gets its own protector.</summary>
public sealed class DataProtectionSecretProtector(IDataProtectionProvider provider) : ISecretProtector
{
    public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => provider.CreateProtector(purpose).Protect(plaintext.ToArray());

    public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose) => provider.CreateProtector(purpose).Unprotect(protectedData.ToArray());
}

/// <summary>
/// Persists the Data Protection key ring in the configuration store (settings table), so every replica and every backend shares one ring
/// and the ring travels with the data. Keys are never deleted. The ring itself is protected by <see cref="SecretsSection"/>.
/// </summary>
public sealed class ConfigStoreXmlRepository(IConfigStore config) : IXmlRepository
{
    private const string Prefix = "dataprotection.key.";

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        var settings = config.GetSettingsAsync(null, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        return settings.Where(s => s.Key.StartsWith(Prefix, StringComparison.Ordinal))
            .OrderBy(s => s.Key, StringComparer.Ordinal)
            .Select(s => XElement.Parse(System.Text.Json.JsonSerializer.Deserialize<string>(s.ValueJson)!))
            .ToList();
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        string key = Prefix + (string.IsNullOrWhiteSpace(friendlyName) ? Guid.NewGuid().ToString("N") : friendlyName);
        string json = System.Text.Json.JsonSerializer.Serialize(element.ToString(SaveOptions.DisableFormatting));
        config.SetSettingAsync(new SettingRecord(key, null, json, DateTimeOffset.UtcNow), CancellationToken.None).AsTask().GetAwaiter().GetResult();
    }
}

/// <summary>The key ring does not fit <c>Secrets:*</c>, or the key that protects it is not the right one. The message says what to do.</summary>
public sealed class SecretsConfigurationException(string message, Exception? inner = null) : InvalidOperationException(message, inner);

public static class SecretsFactory
{
    /// <summary>
    /// True when the keys at rest in the config store are all protected: a mode other than <c>None</c> <b>and</b> no key still stored in the clear from before it was set.
    /// This is what the backend switch asks before it accepts an unprotected target.
    /// </summary>
    public static bool KeysProtectedAtRest(SecretsSection secrets, IConfigStore config) =>
        secrets.KeyProtection != KeyProtectionMode.None && KeyRingInspector.Inspect(config).NoPlaintext;

    /// <summary>Start-up warnings about the protection (a ring with unprotected keys, a key given in the environment, a key file others can read).</summary>
    public static IReadOnlyList<string> Warnings(SecretsSection secrets, IConfigStore config) =>
        [.. KeyRingInspector.Warnings(KeyRingInspector.Inspect(config), secrets), .. KeyWrapProviders.Warnings(secrets)];

    /// <summary>
    /// Creates the process-wide secret protector. <see cref="KeyProtectionMode.Certificate"/> encrypts the key ring with the configured
    /// certificate; <see cref="KeyProtectionMode.Kms"/> wraps it with an external key (<see cref="IKeyWrapProvider"/>); <see cref="KeyProtectionMode.None"/> leaves it readable by anyone who can read the database (development only, logged as a warning by the caller).
    /// </summary>
    public static ISecretProtector Create(SecretsSection secrets, IConfigStore config)
    {
        // Look at the stored ring first, and open the Kms keys with the configured key: Data Protection would treat a key it cannot read as missing and may create a
        // new one, which strands the secrets protected by the old ring. A ring that does not fit the configuration stops the start here, with the reason.
        IKeyWrapProvider? wrap = secrets.KeyProtection == KeyProtectionMode.Kms ? KeyWrapProviders.Create(secrets) : null;
        IReadOnlyList<string> problems = KeyRingInspector.Problems(KeyRingInspector.Inspect(config), secrets, wrap);
        if (problems.Count > 0)
        {
            throw new SecretsConfigurationException(string.Join(" ", problems));
        }

        var services = new ServiceCollection();
        var builder = services.AddDataProtection().SetApplicationName("EggMail");
        builder.Services.Configure<KeyManagementOptions>(o => o.XmlRepository = new ConfigStoreXmlRepository(config));
        switch (secrets.KeyProtection)
        {
            case KeyProtectionMode.Certificate:
                if (string.IsNullOrWhiteSpace(secrets.CertificatePath))
                {
                    throw new InvalidOperationException("Secrets:CertificatePath is required when Secrets:KeyProtection is Certificate.");
                }

                string? password = string.IsNullOrWhiteSpace(secrets.CertificatePasswordFile) ? null : File.ReadAllText(secrets.CertificatePasswordFile).Trim();
                var cert = X509CertificateLoader.LoadPkcs12FromFile(secrets.CertificatePath, password);
                builder.ProtectKeysWithCertificate(cert);
                break;
            case KeyProtectionMode.Kms:
                // The ring in the config store holds only keys wrapped by an external key; the decryptor finds the provider in the container.
                builder.Services.AddSingleton(wrap!);
                builder.Services.Configure<KeyManagementOptions>(o => o.XmlEncryptor = new KmsXmlEncryptor(wrap!));
                break;
        }

        var provider = services.BuildServiceProvider().GetRequiredService<IDataProtectionProvider>();
        return new DataProtectionSecretProtector(provider);
    }
}
