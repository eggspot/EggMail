using System.Security.Cryptography;
using System.Text;

namespace Mta.Host.Security;

/// <summary>API keys: <c>egm_&lt;id&gt;_&lt;secret&gt;</c>, shown once, stored as a SHA-256 digest (decision 21; high-entropy keys do not need a slow hash).</summary>
public static class ApiKeys
{
    public const string Prefix = "egm_";

    /// <summary>Creates a key. Returns the full token (show once), its display prefix and the digest to store.</summary>
    public static (string Token, string DisplayPrefix, byte[] Digest) Generate()
    {
        string id = ToBase64Url(RandomNumberGenerator.GetBytes(6));
        string secret = ToBase64Url(RandomNumberGenerator.GetBytes(32));
        string token = $"{Prefix}{id}_{secret}";
        return (token, $"{Prefix}{id}", Digest(token));
    }

    public static byte[] Digest(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token));

    /// <summary>Cheap syntax check before touching the database.</summary>
    public static bool LooksLikeKey(string? token) =>
        token is { Length: >= 40 and <= 80 } && token.StartsWith(Prefix, StringComparison.Ordinal) && token.Count(c => c == '_') == 2;

    private static string ToBase64Url(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
