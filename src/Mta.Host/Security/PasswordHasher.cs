using System.Security.Cryptography;

namespace Mta.Host.Security;

/// <summary>
/// PBKDF2-HMAC-SHA256 password hashing for SMTP credentials and dashboard users (BCL only). Format:
/// <c>pbkdf2-sha256$iterations$base64(salt)$base64(hash)</c>. The default iteration count follows OWASP's 2023 guidance (600,000);
/// <see cref="NeedsRehash"/> lets the caller upgrade hashes at the next successful login. A hash can carry a fifth part, <c>$change</c>
/// (<see cref="MarkMustChange"/>): the password is a temporary one (the one the server generated for the first administrator and printed once), and the
/// dashboard user has to choose another before anything else. Setting a new password stores a new hash without the part, which is how the mark ends.
/// </summary>
public static class PasswordHasher
{
    public const int DefaultIterations = 600_000;
    private const int SaltBytes = 16;
    private const int HashBytes = 32;
    private const string Scheme = "pbkdf2-sha256";
    private const string ChangeMark = "change";

    /// <summary>The same hash, marked as that of a temporary password.</summary>
    public static string MarkMustChange(string stored) => MustChange(stored) ? stored : stored + "$" + ChangeMark;

    /// <summary>Is the password this hash belongs to a temporary one that has to be changed?</summary>
    public static bool MustChange(string stored) => stored.EndsWith("$" + ChangeMark, StringComparison.Ordinal);

    public static string Hash(string password, int iterations = DefaultIterations)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltBytes);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, HashBytes);
        return $"{Scheme}${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string password, string stored)
    {
        if (!TryParse(stored, out int iterations, out byte[] salt, out byte[] expected))
        {
            return false;
        }

        byte[] actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    public static bool NeedsRehash(string stored, int iterations = DefaultIterations) =>
        !TryParse(stored, out int it, out _, out _) || it < iterations;

    /// <summary>
    /// Burns the same CPU as a real verification. Call it when the user does not exist so response times do not reveal valid
    /// user names.
    /// </summary>
    public static void VerifyDummy(string password) => Verify(password, DummyHash.Value);

    private static class DummyHash
    {
        public static readonly string Value = Hash("dummy-password-for-timing", 600_000);
    }

    private static bool TryParse(string stored, out int iterations, out byte[] salt, out byte[] hash)
    {
        iterations = 0;
        salt = hash = [];
        string[] parts = stored.Split('$');
        if (parts.Length is not (4 or 5) || (parts.Length == 5 && parts[4] != ChangeMark) || parts[0] != Scheme || !int.TryParse(parts[1], out iterations) || iterations is < 1000 or > 10_000_000)
        {
            return false;
        }

        try
        {
            salt = Convert.FromBase64String(parts[2]);
            hash = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        return salt.Length >= 8 && hash.Length >= 16;
    }
}
