using System.Security.Cryptography;
using System.Xml.Linq;
using Mta.Host.Configuration;
using Mta.Storage;

namespace Mta.Host.Secrets;

/// <summary>How one element of the Data Protection key ring in the config store is protected.</summary>
public enum RingElementProtection : byte
{
    /// <summary>The master key is stored in the clear (<c>Secrets:KeyProtection=None</c>, or an element written before protection was switched on).</summary>
    Plaintext,

    /// <summary>Encrypted to a certificate (<c>Secrets:KeyProtection=Certificate</c>).</summary>
    Certificate,

    /// <summary>Wrapped by an <see cref="IKeyWrapProvider"/> (<c>Secrets:KeyProtection=Kms</c>).</summary>
    Kms,
}

/// <summary>What the stored key ring looks like and what is wrong with it for the configured protection.</summary>
public sealed record KeyRingReport(IReadOnlyList<(string Setting, XElement Xml, RingElementProtection Protection)> Elements)
{
    public int Count(RingElementProtection protection) => Elements.Count(e => e.Protection == protection);

    /// <summary>True when every element is protected (an empty ring counts: the keys created later are protected by the configured mode).</summary>
    public bool NoPlaintext => Count(RingElementProtection.Plaintext) == 0;
}

/// <summary>
/// Looks at the key ring before Data Protection does. Data Protection treats a key it cannot decrypt as a missing key and may then create a new one under the current
/// configuration, which silently strands everything protected by the old ring; so a ring that does not match <c>Secrets:*</c> has to stop the start, with the reason.
/// Switching <c>Secrets:KeyProtection</c> on a ring that already holds keys is only supported through <c>mta secrets rewrap</c>.
/// </summary>
public static class KeyRingInspector
{
    private const string Prefix = "dataprotection.key.";

    public static KeyRingReport Inspect(IConfigStore config)
    {
        var settings = config.GetSettingsAsync(null, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        var elements = new List<(string, XElement, RingElementProtection)>();
        foreach (SettingRecord row in settings.Where(s => s.Key.StartsWith(Prefix, StringComparison.Ordinal)).OrderBy(s => s.Key, StringComparer.Ordinal))
        {
            XElement xml = XElement.Parse(System.Text.Json.JsonSerializer.Deserialize<string>(row.ValueJson)!);
            elements.Add((row.Key, xml, Classify(xml)));
        }

        return new KeyRingReport(elements);
    }

    public static RingElementProtection Classify(XElement key)
    {
        XElement? secret = key.Descendants().FirstOrDefault(e => e.Name.LocalName == "encryptedSecret");
        if (secret is null)
        {
            return RingElementProtection.Plaintext;
        }

        string decryptor = (string?)secret.Attribute("decryptorType") ?? "";
        return decryptor.StartsWith(KmsXmlDecryptor.StoredTypeName, StringComparison.Ordinal) ? RingElementProtection.Kms : RingElementProtection.Certificate;
    }

    /// <summary>Errors that must stop the start. <paramref name="provider"/> is the configured key service when the mode is Kms.</summary>
    public static IReadOnlyList<string> Problems(KeyRingReport ring, SecretsSection secrets, IKeyWrapProvider? provider)
    {
        var problems = new List<string>();
        int certificate = ring.Count(RingElementProtection.Certificate);
        int kms = ring.Count(RingElementProtection.Kms);
        const string Rewrap = " Changing Secrets:KeyProtection on a ring that already holds keys is not supported unless the ring is re-wrapped (mta secrets rewrap), or restore the previous configuration.";

        if (certificate > 0 && secrets.KeyProtection != KeyProtectionMode.Certificate)
        {
            problems.Add($"The Data Protection key ring holds {certificate} key(s) encrypted with a certificate, but Secrets:KeyProtection is {secrets.KeyProtection}: they cannot be read, and the secrets they protect (DKIM keys, TLS keys, webhook secrets) would be lost." + Rewrap);
        }

        if (kms > 0 && secrets.KeyProtection != KeyProtectionMode.Kms)
        {
            problems.Add($"The Data Protection key ring holds {kms} key(s) wrapped by an external key (Secrets:KeyProtection=Kms), but Secrets:KeyProtection is {secrets.KeyProtection}: they cannot be read." + Rewrap);
        }

        if (provider is not null)
        {
            foreach (var (setting, xml, protection) in ring.Elements)
            {
                if (protection != RingElementProtection.Kms)
                {
                    continue;
                }

                try
                {
                    CryptographicOperations.ZeroMemory(KmsXmlDecryptor.UnwrapElement(xml.Descendants().First(e => e.Name.LocalName == "wrappedKey"), provider));
                }
                catch (CryptographicException ex)
                {
                    problems.Add($"{setting}: {ex.Message}");
                    break;   // one is enough: the same key opens all of them
                }
            }
        }

        return problems;
    }

    /// <summary>Things that work but weaken the protection; logged at start.</summary>
    public static IReadOnlyList<string> Warnings(KeyRingReport ring, SecretsSection secrets)
    {
        var warnings = new List<string>();
        int plaintext = ring.Count(RingElementProtection.Plaintext);
        if (plaintext > 0 && secrets.KeyProtection != KeyProtectionMode.None)
        {
            warnings.Add($"The Data Protection key ring still holds {plaintext} unprotected key(s) from before Secrets:KeyProtection={secrets.KeyProtection} was set. Secrets protected by them are only as safe as the database, and one of them may still be the active key. Run 'mta secrets rewrap' to protect them.");
        }

        return warnings;
    }
}
