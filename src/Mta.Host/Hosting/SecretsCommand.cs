using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Secrets;
using Mta.Host.Switching;
using Mta.Storage;

namespace Mta.Host.Hosting;

/// <summary>
/// <c>mta secrets rewrap [--apply] [--from-kms-key-file FILE | --from-kms-key VALUE]</c>: brings the stored Data Protection key ring in line with
/// <c>Secrets:KeyProtection</c>. It protects keys that were stored in the clear (before protection was switched on) and, with <c>--from-kms-key*</c>, re-wraps keys wrapped
/// by a previous <c>LocalKey</c> key under the configured one. Without <c>--apply</c> it only reports what it would change. Keys encrypted to a certificate are not
/// converted (restore the old configuration, or keep using the certificate). Run it with the server stopped, after a backup of the database: a ring that is rewrapped
/// wrongly cannot be read again.
/// </summary>
public static class SecretsCommand
{
    private const string Usage = "Usage: mta secrets rewrap [--apply] [--from-kms-key-file FILE | --from-kms-key VALUE] (plus any configuration option, for example --Sqlite:DataDirectory=/data)";
    private static readonly string[] OwnOptions = ["--from-kms-key-file", "--from-kms-key"];

    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error)
    {
        if (args.FirstOrDefault() != "rewrap")
        {
            error.WriteLine(Usage);
            return 64;
        }

        string[] rest = args.Skip(1).ToArray();
        bool apply = rest.Contains("--apply");
        var own = new ConfigurationBuilder().AddCommandLine(rest.Where(a => a != "--apply").ToArray()).Build();
        string? fromFile = own["from-kms-key-file"];
        string? fromKey = own["from-kms-key"];

        LoadedConfig loaded = ConfigLoader.Load(ConfigLoader.Build(ConfigurationArguments(rest)));
        if (!loaded.IsValid)
        {
            foreach (string e in loaded.Errors)
            {
                error.WriteLine("configuration error: " + e);
            }

            return 2;
        }

        SecretsSection secrets = loaded.Config.Secrets;
        if (secrets.KeyProtection == KeyProtectionMode.None)
        {
            error.WriteLine("Secrets:KeyProtection is None: there is nothing to protect the ring with. Set Secrets:KeyProtection=Kms (or Certificate) first.");
            return 64;
        }

        DataDirectoryLock? directoryLock = null;
        try
        {
            directoryLock = loaded.Config.Storage.Backend == StorageBackend.Sqlite ? DataDirectoryLock.Acquire(loaded.Config.Storage.Sqlite.DataDirectory) : null;
        }
        catch (IOException ex)
        {
            error.WriteLine(ex.Message + " Stop the server first.");
            return 3;
        }

        using (directoryLock)
        {
            await using var storage = StorageFactory.Create(loaded.Config.Storage, SystemClock.Instance, NullMtaLog.Instance);
            await storage.InitializeAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                return await RewrapAsync(storage.Config, secrets, fromFile, fromKey, apply, output, error).ConfigureAwait(false);
            }
            catch (InvalidOperationException ex)
            {
                error.WriteLine(ex.Message);
                return 64;
            }
        }
    }

    /// <summary>The rewrap itself, over an open config store (also what the tests call).</summary>
    public static async Task<int> RewrapAsync(IConfigStore config, SecretsSection secrets, string? fromKmsKeyFile, string? fromKmsKey, bool apply, TextWriter output, TextWriter error)
    {
        IXmlEncryptor target;
        IKeyWrapProvider? current = null;
        if (secrets.KeyProtection == KeyProtectionMode.Kms)
        {
            current = KeyWrapProviders.Create(secrets);
            target = new KmsXmlEncryptor(current);
        }
        else
        {
            string? password = string.IsNullOrWhiteSpace(secrets.CertificatePasswordFile) ? null : File.ReadAllText(secrets.CertificatePasswordFile).Trim();
            target = new CertificateXmlEncryptor(X509CertificateLoader.LoadPkcs12FromFile(secrets.CertificatePath ?? throw new InvalidOperationException("Secrets:CertificatePath is required."), password), NullLoggerFactory.Instance);
        }

        IKeyWrapProvider? previous = null;
        if (!string.IsNullOrWhiteSpace(fromKmsKeyFile) || !string.IsNullOrWhiteSpace(fromKmsKey))
        {
            previous = LocalKeyWrapProvider.FromConfiguration(new SecretsSection { KeyProtection = KeyProtectionMode.Kms, KmsKeyFile = fromKmsKeyFile, KmsKey = fromKmsKey });
        }

        KeyRingReport ring = KeyRingInspector.Inspect(config);
        var settings = (await config.GetSettingsAsync(null, CancellationToken.None).ConfigureAwait(false)).ToDictionary(s => s.Key, StringComparer.Ordinal);
        int changed = 0, unchanged = 0;
        var changes = new List<SettingRecord>();
        foreach (var (setting, xml, protection) in ring.Elements)
        {
            XElement? masterKey = null;
            switch (protection)
            {
                case RingElementProtection.Plaintext:
                    masterKey = xml.Descendants().First(e => e.Name.LocalName == "masterKey");
                    break;
                case RingElementProtection.Kms when current is not null:
                    XElement wrapped = xml.Descendants().First(e => e.Name.LocalName == "wrappedKey");
                    try
                    {
                        byte[] plain = KmsXmlDecryptor.UnwrapElement(wrapped, current);   // already under the configured key
                        CryptographicOperations.ZeroMemory(plain);
                        unchanged++;
                        continue;
                    }
                    catch (CryptographicException) when (previous is not null)
                    {
                        byte[] plain = KmsXmlDecryptor.UnwrapElement(wrapped, previous);
                        try
                        {
                            masterKey = XElement.Parse(Encoding.UTF8.GetString(plain));
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(plain);
                        }
                    }
                    catch (CryptographicException ex)
                    {
                        error.WriteLine($"{setting}: not under the configured key ({ex.Message}). Give the key it was wrapped with: --from-kms-key-file FILE.");
                        return 1;
                    }

                    break;
                case RingElementProtection.Certificate when secrets.KeyProtection == KeyProtectionMode.Certificate:
                    unchanged++;
                    continue;
                default:
                    error.WriteLine($"{setting}: a key protected as {protection} cannot be converted to {secrets.KeyProtection}. Restore the configuration it was written under, or keep it.");
                    return 1;
            }

            EncryptedXmlInfo info = target.Encrypt(masterKey!);
            var replacement = new XElement(XName.Get("encryptedSecret", "http://schemas.asp.net/2015/03/dataProtection"),
                new XAttribute("decryptorType", info.DecryptorType.AssemblyQualifiedName!), info.EncryptedElement);
            XElement updated = new(xml);
            XElement slot = updated.Descendants().First(e => e.Name.LocalName is "masterKey" or "encryptedSecret");
            slot.ReplaceWith(replacement);
            changes.Add(settings[setting] with { ValueJson = System.Text.Json.JsonSerializer.Serialize(updated.ToString(SaveOptions.DisableFormatting)), UpdatedAt = DateTimeOffset.UtcNow });
            changed++;
        }

        output.WriteLine($"{ring.Elements.Count} key(s) in the ring: {unchanged} already protected as configured, {changed} to rewrap.");
        if (changed == 0)
        {
            return 0;
        }

        if (!apply)
        {
            output.WriteLine("Nothing was changed. Back up the database, stop the server, and run again with --apply.");
            return 0;
        }

        foreach (SettingRecord change in changes)
        {
            await config.SetSettingAsync(change, CancellationToken.None).ConfigureAwait(false);
        }

        output.WriteLine($"Rewrapped {changed} key(s) under Secrets:KeyProtection={secrets.KeyProtection}.");
        return 0;
    }

    private static string[] ConfigurationArguments(IEnumerable<string> args)
    {
        var result = new List<string>();
        var list = args.ToList();
        for (int i = 0; i < list.Count; i++)
        {
            string a = list[i];
            bool isOwn = a == "--apply" || OwnOptions.Any(o => a == o || a.StartsWith(o + "=", StringComparison.Ordinal));
            if (!isOwn)
            {
                result.Add(a);
            }
            else if (a != "--apply" && !a.Contains('='))
            {
                i++;
            }
        }

        return result.ToArray();
    }
}
