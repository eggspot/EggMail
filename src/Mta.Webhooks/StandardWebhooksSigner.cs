using System.Security.Cryptography;
using System.Text;

namespace Mta.Webhooks;

/// <summary>
/// Standard Webhooks signing (https://github.com/standard-webhooks/standard-webhooks): headers <c>webhook-id</c>,
/// <c>webhook-timestamp</c>, <c>webhook-signature</c>; HMAC-SHA256 over <c>id.timestamp.payload</c>, signature <c>v1,&lt;base64&gt;</c>,
/// secrets <c>whsec_&lt;base64&gt;</c>; key rotation by signing with several secrets (space-delimited).
/// </summary>
public static class StandardWebhooksSigner
{
    public const string SecretPrefix = "whsec_";
    public const string IdHeader = "webhook-id";
    public const string TimestampHeader = "webhook-timestamp";
    public const string SignatureHeader = "webhook-signature";

    /// <summary>Default replay tolerance (Stripe's library convention; the spec only says "some allowable tolerance").</summary>
    public static readonly TimeSpan DefaultTolerance = TimeSpan.FromMinutes(5);

    public static string GenerateSecret()
    {
        byte[] key = RandomNumberGenerator.GetBytes(24);
        return SecretPrefix + Convert.ToBase64String(key);
    }

    public static byte[] ParseSecret(string secret)
    {
        string b64 = secret.StartsWith(SecretPrefix, StringComparison.Ordinal) ? secret[SecretPrefix.Length..] : secret;
        return Convert.FromBase64String(b64);
    }

    /// <summary>Computes the <c>webhook-signature</c> header value for one or more secrets.</summary>
    public static string Sign(string messageId, long unixSeconds, ReadOnlySpan<byte> payload, IEnumerable<string> secrets)
    {
        var parts = new List<string>(2);
        foreach (string secret in secrets)
        {
            parts.Add("v1," + Convert.ToBase64String(ComputeMac(ParseSecret(secret), messageId, unixSeconds, payload)));
        }

        return string.Join(' ', parts);
    }

    public static string Sign(string messageId, long unixSeconds, ReadOnlySpan<byte> payload, string secret) =>
        Sign(messageId, unixSeconds, payload, [secret]);

    private static byte[] ComputeMac(byte[] key, string id, long ts, ReadOnlySpan<byte> payload)
    {
        using var h = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
        h.AppendData(Encoding.UTF8.GetBytes(id));
        h.AppendData("."u8);
        h.AppendData(Encoding.ASCII.GetBytes(ts.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        h.AppendData("."u8);
        h.AppendData(payload);
        return h.GetHashAndReset();
    }

    /// <summary>Receiver-side verification (also used by tests and documentation examples). Constant-time comparison.</summary>
    public static bool Verify(string messageId, string timestampHeader, string signatureHeader, ReadOnlySpan<byte> payload, IEnumerable<string> secrets, DateTimeOffset now, TimeSpan? tolerance = null)
    {
        if (!long.TryParse(timestampHeader, out long ts))
        {
            return false;
        }

        var age = now - DateTimeOffset.FromUnixTimeSeconds(ts);
        var tol = tolerance ?? DefaultTolerance;
        if (age > tol || age < -tol)
        {
            return false;
        }

        foreach (string secret in secrets)
        {
            byte[] expected = ComputeMac(ParseSecret(secret), messageId, ts, payload);
            foreach (string candidate in signatureHeader.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (!candidate.StartsWith("v1,", StringComparison.Ordinal)) { continue; }
                byte[] got;
                try { got = Convert.FromBase64String(candidate[3..]); }
                catch (FormatException) { continue; }
                if (CryptographicOperations.FixedTimeEquals(expected, got)) { return true; }
            }
        }

        return false;
    }
}
