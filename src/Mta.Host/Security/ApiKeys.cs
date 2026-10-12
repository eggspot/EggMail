using System.Security.Cryptography;
using System.Text;

namespace Mta.Host.Security;

/// <summary>API keys: <c>egm_&lt;id&gt;_&lt;secret&gt;</c>, shown once, stored as a SHA-256 digest (decision 21; high-entropy keys do not need a slow hash).</summary>
public static class ApiKeys
{
    public const string Prefix = "egm_";

    // 6 id bytes and 32 secret bytes in unpadded base64url (8 and 43 characters). Base64url may itself contain '_', so the layout is positional.
    private const int IdLength = 8;
    private const int SecretLength = 43;
    private const int TokenLength = 4 + IdLength + 1 + SecretLength;

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
        token is { Length: TokenLength } && token.StartsWith(Prefix, StringComparison.Ordinal) && token[Prefix.Length + IdLength] == '_'
        && token.AsSpan(Prefix.Length).ToString().All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    private static string ToBase64Url(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
