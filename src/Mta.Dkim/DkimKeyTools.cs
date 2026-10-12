using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Mta.Dkim.Internal;

namespace Mta.Dkim;

/// <summary>
/// Key generation, import/export and DNS record formatting for DKIM.
/// </summary>
/// <remarks>
/// Key rotation (documentation only, see docs/components/dkim.md): publish the new key under a new selector N+1, verify the TXT record resolves,
/// switch signing to N+1, keep the old record N published for at least 7 days (mail signed with N may still be in flight or in retry queues),
/// then remove it. Never reuse a selector name.
/// </remarks>
public static class DkimKeyTools
{
    /// <summary>Longest character-string in a DNS TXT record (RFC 1035).</summary>
    public const int MaxTxtStringLength = 255;

    /// <summary>Generates a new RSA-2048 key pair. The caller disposes the returned key.</summary>
    public static RSA GenerateRsa2048() => RSA.Create(2048);

    /// <summary>Generates a new RSA key pair of 1024 to 4096 bits (2048 is the supported default; 1024 exists for tests and legacy interop).</summary>
    public static RSA GenerateRsa(int bits)
    {
        if (bits is < 1024 or > 4096) { throw new ArgumentOutOfRangeException(nameof(bits), "Key size must be between 1024 and 4096 bits."); }
        return RSA.Create(bits);
    }

    /// <summary>Exports the private key as an unencrypted PKCS#8 PEM (<c>-----BEGIN PRIVATE KEY-----</c>). Protect the result at rest.</summary>
    public static string ExportPrivateKeyPem(RSA key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return key.ExportPkcs8PrivateKeyPem();
    }

    /// <summary>Exports the private key as DER PKCS#8.</summary>
    public static byte[] ExportPrivateKeyDer(RSA key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return key.ExportPkcs8PrivateKey();
    }

    /// <summary>Exports the public key as base64 of the DER SubjectPublicKeyInfo (the <c>p=</c> value).</summary>
    public static string ExportPublicKeyBase64(RSA key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
    }

    /// <summary>Returns the TXT value to publish: <c>v=DKIM1; k=rsa; p=...</c>.</summary>
    public static string FormatDnsTxtValue(RSA publicKey) => FormatDnsTxtValue(ExportPublicKeyBase64(publicKey));

    /// <summary>Returns the TXT value to publish for an already base64 encoded SubjectPublicKeyInfo.</summary>
    public static string FormatDnsTxtValue(string publicKeyBase64)
    {
        ArgumentNullException.ThrowIfNull(publicKeyBase64);
        return "v=DKIM1; k=rsa; p=" + publicKeyBase64;
    }

    /// <summary>Splits a TXT value into character-strings of at most <paramref name="maxLength"/> characters (255 by default), as many DNS panels require.</summary>
    public static IReadOnlyList<string> SplitTxtValue(string txtValue, int maxLength = MaxTxtStringLength)
    {
        ArgumentNullException.ThrowIfNull(txtValue);
        if (maxLength is < 1 or > MaxTxtStringLength) { throw new ArgumentOutOfRangeException(nameof(maxLength)); }
        if (txtValue.Length == 0) { return [string.Empty]; }
        var parts = new List<string>((txtValue.Length / maxLength) + 1);
        for (int i = 0; i < txtValue.Length; i += maxLength)
        {
            parts.Add(txtValue.Substring(i, Math.Min(maxLength, txtValue.Length - i)));
        }

        return parts;
    }

    /// <summary>Formats the TXT value as quoted strings of at most 255 characters separated by spaces, for example <c>"v=DKIM1; k=rsa; p=MIIB..." "...AQAB"</c>.</summary>
    public static string FormatDnsTxtQuoted(string txtValue, int maxLength = MaxTxtStringLength)
    {
        var parts = SplitTxtValue(txtValue, maxLength);
        var sb = new StringBuilder(txtValue.Length + (parts.Count * 3));
        for (int i = 0; i < parts.Count; i++)
        {
            if (i > 0) { sb.Append(' '); }
            sb.Append('"');
            foreach (char c in parts[i])
            {
                if (c == '"' || c == '\\') { sb.Append('\\'); }
                sb.Append(c);
            }

            sb.Append('"');
        }

        return sb.ToString();
    }

    /// <summary>Joins DNS panel style quoted strings (<c>"abc" "def"</c>) into one value; text without quotes is returned trimmed. Never throws.</summary>
    public static string JoinQuotedStrings(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (text.IndexOf('"') < 0) { return text.Trim(); }
        var sb = new StringBuilder(text.Length);
        bool inQuote = false;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (inQuote)
            {
                if (c == '\\' && i + 1 < text.Length) { sb.Append(text[++i]); }
                else if (c == '"') { inQuote = false; }
                else { sb.Append(c); }
            }
            else if (c == '"')
            {
                inQuote = true;
            }
        }

        return sb.ToString();
    }

    /// <summary>Parses a key record as shown by a DNS panel or <c>dig</c> (plain or quoted and split). Never throws.</summary>
    public static bool TryParseDnsTxtValue(string text, out DkimKeyRecord? record, out string? error)
    {
        if (text is null)
        {
            record = null;
            error = "no text";
            return false;
        }

        return DkimKeyRecord.TryParse(JoinQuotedStrings(text), out record, out error);
    }

    /// <summary>The DNS name that holds the key: <c>selector._domainkey.domain</c>.</summary>
    public static string GetDnsName(string domain, string selector)
    {
        ArgumentNullException.ThrowIfNull(domain);
        ArgumentNullException.ThrowIfNull(selector);
        return selector + "._domainkey." + domain.Trim().TrimEnd('.');
    }

    /// <summary>Suggests a selector for a key created at <paramref name="now"/>: the prefix plus year and month, for example <c>egg202610</c>. Create a different one if you rotate twice in a month.</summary>
    public static string SuggestSelector(DateTimeOffset now, string prefix = "egg")
    {
        ArgumentNullException.ThrowIfNull(prefix);
        if (!DkimNames.IsValidSelector(prefix) || prefix.Contains('.')) { throw new ArgumentException("Prefix must be a single DNS label.", nameof(prefix)); }
        var utc = now.UtcDateTime;
        return prefix + utc.ToString("yyyyMM", CultureInfo.InvariantCulture);
    }

    /// <summary>Loads an RSA private key from a PEM (PKCS#8 <c>PRIVATE KEY</c> or PKCS#1 <c>RSA PRIVATE KEY</c>). The caller disposes the key.</summary>
    /// <exception cref="DkimException">The text is not a usable RSA private key.</exception>
    public static RSA LoadPrivateKeyPem(string pem)
    {
        ArgumentNullException.ThrowIfNull(pem);
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(pem);
            return rsa;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            rsa.Dispose();
            throw new DkimException("The PEM is not a valid RSA private key.", ex);
        }
    }

    /// <summary>Loads an RSA private key from DER PKCS#8 (falling back to PKCS#1). The caller disposes the key.</summary>
    /// <exception cref="DkimException">The data is not a usable RSA private key.</exception>
    public static RSA LoadPrivateKeyDer(ReadOnlySpan<byte> der)
    {
        var rsa = RSA.Create();
        try
        {
            try
            {
                rsa.ImportPkcs8PrivateKey(der, out _);
            }
            catch (CryptographicException)
            {
                rsa.ImportRSAPrivateKey(der, out _);
            }

            return rsa;
        }
        catch (CryptographicException ex)
        {
            rsa.Dispose();
            throw new DkimException("The data is not a valid RSA private key.", ex);
        }
    }
}
