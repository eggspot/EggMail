using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Mta.Mime;

namespace Mta.Dsn;

/// <summary>
/// The signed hop marker of a forwarded message (design section 11.7): the header <c>X-EggMail-Hops: &lt;n&gt;; &lt;signature&gt;</c>, where <c>signature</c> is the first 16 hex digits of
/// <c>HMAC-SHA-256(key, "EggMail.Hops.v1\n" + n + "\n" + hex(SHA-256(body)))</c>. <c>body</c> is the message after the first empty line exactly as stored; no header is in the input, because
/// headers are what senders, lists and the next hop rewrite, while a forward delivers the body byte for byte. The key is derived from the bounce-token key with the purpose <see cref="Purpose"/>;
/// signing uses the active key of the ring, verification tries every key. The one implementation of both sides: the receive path keeps or removes markers on arrival, the forward runner counts and writes them.
/// <para>Rules: a marker whose signature does not verify (forged, or the body changed on the way) counts for nothing; among the valid ones the highest <c>n</c> counts; a forward removes every marker and writes exactly one
/// with <c>n + 1</c>; a message that arrives with <c>n</c> at <see cref="MaxHops"/> is not forwarded. The count is 1 to 999 (a plain number of at most three digits).</para>
/// </summary>
public sealed class ForwardHopMarker
{
    public const string Purpose = "EggMail.Hops.v1";
    public const string HeaderName = "X-EggMail-Hops";

    /// <summary>A message that arrives having been forwarded this many times by this server is not forwarded again.</summary>
    public const int MaxHops = 3;

    private const int SignatureLength = 16;
    private const int MaxCountDigits = 3;

    private readonly Dictionary<int, byte[]> _keys = [];
    private readonly int _activeKeyId;

    public ForwardHopMarker(VerpCodec ring)
    {
        ArgumentNullException.ThrowIfNull(ring);
        _activeKeyId = ring.ActiveKeyId;
        foreach (int id in ring.KeyIds)
        {
            _keys[id] = ring.DeriveKey(id, Purpose);
        }
    }

    /// <summary>The SHA-256 of the body as lower-case hex: compute it once per message, it is the part of the check that costs.</summary>
    public static string BodyHash(ReadOnlySpan<byte> body) => Convert.ToHexStringLower(SHA256.HashData(body));

    /// <summary>The field value for a message with the body hash <paramref name="bodyHash"/> that has been forwarded <paramref name="hops"/> times (this hop included): <c>3; 0123456789abcdef</c>.</summary>
    public string CreateValue(int hops, string bodyHash) =>
        hops.ToString(CultureInfo.InvariantCulture) + "; " + Sign(_keys[_activeKeyId], hops, bodyHash);

    /// <summary>The value of the header for <paramref name="hops"/> hops on a message whose body is <paramref name="body"/>.</summary>
    public string CreateValue(int hops, ReadOnlySpan<byte> body) => CreateValue(hops, BodyHash(body));

    /// <summary>
    /// Checks the value of an <c>X-EggMail-Hops</c> field against the body hash: <see langword="true"/> with the count when the shape is right (one to three digits, at least 1) and the signature verifies under a
    /// key of the ring. A forged marker, one whose body changed on the way, and one with any other count all give <see langword="false"/>.
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
        if (count.Length is 0 or > MaxCountDigits || !count.All(char.IsAsciiDigit) || signature.Length != SignatureLength
            || !int.TryParse(count, NumberStyles.None, CultureInfo.InvariantCulture, out int n) || n < 1)
        {
            return false;
        }

        byte[] given = Encoding.ASCII.GetBytes(signature);
        bool verified = false;
        foreach (byte[] key in _keys.Values)
        {
            verified |= CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Sign(key, n, bodyHash)), given);
        }

        if (verified)
        {
            hops = n;
        }

        return verified;
    }

    /// <summary>The number of hops the message proves: the highest <c>n</c> among the markers with a valid signature for this message body, 0 when there is none valid.</summary>
    public int ReadValidHops(ReadOnlyMemory<byte> message)
    {
        HeaderList headers = HeaderList.Parse(message);
        int highest = 0;
        string? bodyHash = null;
        foreach (MimeHeader header in headers)
        {
            if (header.IsMalformed || !NameIs(header))
            {
                continue;
            }

            bodyHash ??= BodyHash(headers.Body.Span);
            if (TryVerify(header.GetValue(), bodyHash, out int hops) && hops > highest)
            {
                highest = hops;
            }
        }

        return highest;
    }

    /// <summary>The message with every marker removed and exactly one, for <paramref name="hops"/>, at the top. Nothing else about the message changes.</summary>
    public byte[] Apply(ReadOnlyMemory<byte> message, int hops)
    {
        HeaderList headers = HeaderList.Parse(message);
        string value = CreateValue(hops, headers.Body.Span);
        return new MessageHeaderEditor(message).Remove(HeaderName).Prepend(HeaderName, value).ToArray();
    }

    /// <summary>Whether the header is a marker: the name as written, without the white space some senders put before the colon.</summary>
    internal static bool NameIs(MimeHeader header)
    {
        ReadOnlySpan<byte> name = header.NameBytes;
        while (name.Length > 0 && name[^1] is (byte)' ' or (byte)'\t')
        {
            name = name[..^1];
        }

        return Ascii.EqualsIgnoreCase(name, "X-EggMail-Hops"u8);
    }

    private static string Sign(byte[] key, int hops, string bodyHash)
    {
        byte[] input = Encoding.ASCII.GetBytes(Purpose + "\n" + hops.ToString(CultureInfo.InvariantCulture) + "\n" + bodyHash);
        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(key, input, mac);
        return Convert.ToHexStringLower(mac[..(SignatureLength / 2)]);
    }
}
