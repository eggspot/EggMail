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

public static class SecretsFactory
{
    /// <summary>
    /// Creates the process-wide secret protector. <see cref="KeyProtectionMode.Certificate"/> encrypts the key ring with the configured
    /// certificate; <see cref="KeyProtectionMode.None"/> leaves it readable by anyone who can read the database (development only, logged as a warning by the caller).
    /// </summary>
    public static ISecretProtector Create(SecretsSection secrets, IConfigStore config)
    {
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
                throw new NotSupportedException("Secrets:KeyProtection=Kms is not implemented in this version.");
        }

        var provider = services.BuildServiceProvider().GetRequiredService<IDataProtectionProvider>();
        return new DataProtectionSecretProtector(provider);
    }
}
