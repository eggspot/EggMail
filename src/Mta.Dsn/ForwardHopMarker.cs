using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Mta.Dsn;

/// <summary>
/// The signed hop marker of a forwarded message (design section 11.7): the header <c>X-EggMail-Hops: &lt;n&gt;; &lt;signature&gt;</c>, where <c>signature</c> is the first 16 hex digits of
/// <c>HMAC-SHA-256(key, "EggMail.Hops.v1\n" + n + "\n" + hex(SHA-256(body)))</c>. <c>body</c> is the message after the first empty line exactly as stored; no header is in the input, because
/// headers are what senders, lists and the next hop rewrite, while a forward delivers the body byte for byte. The key is derived from the bounce-token key with the purpose <see cref="Purpose"/>;
/// signing uses the active key of the ring, verification tries every key.
/// </summary>
public sealed class ForwardHopMarker
{
    public const string Purpose = "EggMail.Hops.v1";
    public const string HeaderName = "X-EggMail-Hops";
    private const int SignatureLength = 16;
    private const int MaxHops = 1000;

    private readonly VerpCodec _verp;
    private readonly Dictionary<int, byte[]> _derived = [];

    public ForwardHopMarker(VerpCodec verp)
    {
        ArgumentNullException.ThrowIfNull(verp);
        _verp = verp;
        foreach (int id in verp.KeyIds)
        {
            _derived[id] = verp.DeriveKey(id, Purpose);
        }
    }

    /// <summary>The SHA-256 of the body as lower-case hex: compute it once per message, it is the part of the check that costs.</summary>
    public static string BodyHash(ReadOnlySpan<byte> body) => Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();

    /// <summary>The field value for a message with the body hash <paramref name="bodyHash"/> that has been forwarded <paramref name="hops"/> times (this hop included): <c>3; 0123456789abcdef</c>.</summary>
    public string CreateValue(int hops, string bodyHash) =>
        hops.ToString(CultureInfo.InvariantCulture) + "; " + Sign(_derived[_verp.ActiveKeyId], hops, bodyHash);

    /// <summary>
    /// Checks the value of an <c>X-EggMail-Hops</c> field against the body hash: <see langword="true"/> with the count when the shape is right and the signature verifies under a key of the ring.
    /// A forged marker, one whose body changed on the way, and one with a count that is not a plain non-negative number all give <see langword="false"/>.
    /// </summary>
    public bool TryVerify(string fieldValue, string bodyHash, out int hops)
    {
        hops = 0;
        string value = fieldValue.Trim();
        int semicolon = value.IndexOf(';', StringComparison.Ordinal);
        if (semicolon < 1)
        {
            return false;
        }

        string count = value[..semicolon].Trim();
        string signature = value[(semicolon + 1)..].Trim().ToLowerInvariant();
        if (count.Length is 0 or > 4 || !count.All(char.IsAsciiDigit) || signature.Length != SignatureLength
            || !int.TryParse(count, NumberStyles.None, CultureInfo.InvariantCulture, out int n) || n > MaxHops)
        {
            return false;
        }

        byte[] given = Encoding.ASCII.GetBytes(signature);
        bool verified = false;
        foreach (byte[] key in _derived.Values)
        {
            verified |= CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Sign(key, n, bodyHash)), given);
        }

        if (verified)
        {
            hops = n;
        }

        return verified;
    }

    private static string Sign(byte[] key, int hops, string bodyHash)
    {
        byte[] input = Encoding.ASCII.GetBytes("EggMail.Hops.v1\n" + hops.ToString(CultureInfo.InvariantCulture) + "\n" + bodyHash);
        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(key, input, mac);
        return Convert.ToHexString(mac[..(SignatureLength / 2)]).ToLowerInvariant();
    }
}
