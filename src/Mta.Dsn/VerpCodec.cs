using System.Security.Cryptography;
using Mta.Core;

namespace Mta.Dsn;

/// <summary>
/// What a bounce address proves about the original message (stateless, decision 13). A version 2 token is also bound to the destination
/// domain the message was sent to (<see cref="BoundToDestination"/>); a version 1 token (issued before that existed) is not.
/// </summary>
public readonly record struct VerpToken(Guid TenantId, ulong DomainIdPrefix, DateTimeOffset IssuedAt, int KeyId, bool BoundToDestination = false, uint DestinationTag = 0);

/// <summary>How a recipient address compares with the destination domain a bounce address was issued for.</summary>
public enum VerpDestinationCheck
{
    /// <summary>The token carries no destination (version 1): nothing can be said.</summary>
    Unbound,

    /// <summary>The address is in the destination domain the token was issued for.</summary>
    Match,

    /// <summary>The address is in another domain: a report that names it is not about mail this address was issued for.</summary>
    Mismatch,
}

/// <summary>
/// Stateless signed VERP bounce addresses: <c>b+&lt;token&gt;@bounce-domain</c>. The token carries the tenant id, an 8-byte prefix
/// of the sending domain's id (unique within a tenant), an hour-resolution timestamp, a key id and a truncated HMAC-SHA-256,
/// encoded as lower-case base32 so that mail systems that fold case cannot corrupt it. No per-message state is needed to correlate a bounce
/// (the recipient to suppress comes from the DSN's Final-Recipient).
/// <para>Version 2 (what is issued when the destination domain is known) adds a 4-byte keyed tag of the domain the message was sent to and
/// shortens the MAC to 6 bytes: 38 bytes become 61 characters, which with <c>b+</c> is 63 and fits the 64-octet local-part limit. The tag is
/// what stops a stranger who merely <em>received</em> one message (the address is in its Return-Path) from sending a forged report that
/// names somebody else's address and gets it suppressed: a report is acted on only for addresses in the domain the token was issued for.
/// A message group has one envelope sender and all its recipients share a destination domain, so the tag is per domain, not per address.
/// Version 1 (36 bytes, 58 characters, 8-byte MAC) is still accepted for tokens that were already in flight (at most the 14 days of the maximum age).</para>
/// </summary>
public sealed class VerpCodec
{
    public const string Prefix = "b+";
    private const int PayloadLengthV1 = 28;   // version/key (1) + tenant (16) + domain prefix (8) + timestamp (3)
    private const int MacLengthV1 = 8;
    private const int PayloadLengthV2 = 32;   // the same + destination tag (4)
    private const int MacLengthV2 = 6;
    private const int CharsV1 = ((PayloadLengthV1 + MacLengthV1) * 8 + 4) / 5;   // 58
    private const int CharsV2 = ((PayloadLengthV2 + MacLengthV2) * 8 + 4) / 5;   // 61
    private static readonly DateTimeOffset Epoch = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private const string Alphabet = "abcdefghijklmnopqrstuvwxyz234567";

    private readonly IReadOnlyDictionary<int, byte[]> _keys;
    private readonly int _activeKeyId;

    /// <param name="keys">Signing keys by id (0..15). Keep retired keys here while their tokens may still be in flight.</param>
    public VerpCodec(IReadOnlyDictionary<int, byte[]> keys, int activeKeyId)
    {
        if (!keys.TryGetValue(activeKeyId, out var k) || k.Length < 16 || activeKeyId is < 0 or > 15)
        {
            throw new ArgumentException("The active key must exist, be at least 16 bytes and have an id in 0..15.");
        }

        _keys = keys;
        _activeKeyId = activeKeyId;
    }

    /// <summary>The id of the key new tokens are signed with.</summary>
    public int ActiveKeyId => _activeKeyId;

    public static byte[] GenerateKey() => RandomNumberGenerator.GetBytes(32);

    /// <summary>The ids of every key in the ring (the active key and the retired ones whose tokens may still be in flight): what a verifier of a derived secret (<see cref="DeriveKey"/>) tries in turn.</summary>
    public IReadOnlyCollection<int> KeyIds => _keys.Keys.ToArray();

    /// <summary>
    /// A key for another purpose, derived from the ring key <paramref name="keyId"/> with HKDF-SHA-256 and <paramref name="purpose"/> as the context (for example <c>EggMail.Srs.v1</c>): the
    /// bounce key is the only secret the deployment holds, so SRS addresses and the forward hop marker do not add a new one to deploy or back up, and rotating the ring rotates them too.
    /// </summary>
    public byte[] DeriveKey(int keyId, string purpose) =>
        System.Security.Cryptography.HKDF.DeriveKey(HashAlgorithmName.SHA256, _keys[keyId], 32, salt: [], info: System.Text.Encoding.UTF8.GetBytes(purpose));

    /// <summary>
    /// The hour (counted from the codec's epoch) a token made at <paramref name="now"/> carries. Everything else in an address is fixed for a tenant, sending domain, return-path host and destination domain, so
    /// the address is the same for every message of the same hour: a caller may keep it per (tenant, domain, host, destination, hour stamp) instead of signing again for every message.
    /// </summary>
    public static long HourStamp(DateTimeOffset now) => (long)(now - Epoch).TotalHours;

    /// <summary>
    /// Returns the local part, for example <c>b+abc...</c>. With <paramref name="destinationDomain"/> (the domain the message is sent to) the token is
    /// version 2 and bound to it; without, version 1.
    /// </summary>
    public string CreateLocalPart(Guid tenantId, Guid domainId, DateTimeOffset now, string? destinationDomain = null)
    {
        bool bound = !string.IsNullOrWhiteSpace(destinationDomain);
        int payloadLength = bound ? PayloadLengthV2 : PayloadLengthV1;
        int macLength = bound ? MacLengthV2 : MacLengthV1;
        Span<byte> data = stackalloc byte[payloadLength + macLength];
        data[0] = (byte)(((bound ? 2 : 1) << 4) | _activeKeyId);   // version in the high nibble
        tenantId.TryWriteBytes(data[1..17], bigEndian: true, out _);
        Span<byte> dom = stackalloc byte[16];
        domainId.TryWriteBytes(dom, bigEndian: true, out _);
        dom[..8].CopyTo(data[17..25]);
        long hours = HourStamp(now);
        data[25] = (byte)(hours >> 16);
        data[26] = (byte)(hours >> 8);
        data[27] = (byte)hours;
        if (bound)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(data[28..32], DestinationTag(_keys[_activeKeyId], destinationDomain!));
        }

        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(_keys[_activeKeyId], data[..payloadLength], mac);
        mac[..macLength].CopyTo(data[payloadLength..]);
        return Prefix + Base32Encode(data);
    }

    /// <summary>Length of the longest bounce address this codec issues at <paramref name="host"/>: <c>b+</c>, a 61 character token, <c>@</c> and the host.</summary>
    public static int AddressLengthAt(string host) => Prefix.Length + CharsV2 + 1 + host.Length;

    /// <summary>The full bounce address for a domain: <c>b+token@domain</c>.</summary>
    public string CreateAddress(Guid tenantId, Guid domainId, string bounceDomain, DateTimeOffset now, string? destinationDomain = null) =>
        CreateLocalPart(tenantId, domainId, now, destinationDomain) + "@" + bounceDomain;

    /// <summary>
    /// Verifies and decodes a local part. Tokens older than <paramref name="maxAge"/> or issued more than an hour in the future
    /// are rejected.
    /// </summary>
    public bool TryDecode(string localPart, DateTimeOffset now, TimeSpan maxAge, out VerpToken token)
    {
        token = default;
        if (!localPart.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        ReadOnlySpan<char> text = localPart.AsSpan(Prefix.Length);
        int version = text.Length switch { CharsV1 => 1, CharsV2 => 2, _ => 0 };
        if (version == 0)
        {
            return false;
        }

        int payloadLength = version == 2 ? PayloadLengthV2 : PayloadLengthV1;
        int macLength = version == 2 ? MacLengthV2 : MacLengthV1;
        Span<byte> data = stackalloc byte[payloadLength + macLength];
        if (!Base32Decode(text, data))
        {
            return false;
        }

        if ((data[0] >> 4) != version)
        {
            return false;
        }

        int keyId = data[0] & 0xF;
        if (!_keys.TryGetValue(keyId, out var key))
        {
            return false;
        }

        Span<byte> expected = stackalloc byte[32];
        HMACSHA256.HashData(key, data[..payloadLength], expected);
        if (!CryptographicOperations.FixedTimeEquals(expected[..macLength], data[payloadLength..]))
        {
            return false;
        }

        long hours = (data[25] << 16) | (data[26] << 8) | data[27];
        var issued = Epoch.AddHours(hours);
        if (issued > now.AddHours(1) || now - issued > maxAge)
        {
            return false;
        }

        var tenant = new Guid(data[1..17], bigEndian: true);
        ulong prefix = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(data[17..25]);
        token = version == 2
            ? new VerpToken(tenant, prefix, issued, keyId, BoundToDestination: true, System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(data[28..32]))
            : new VerpToken(tenant, prefix, issued, keyId);
        return true;
    }

    /// <summary>
    /// Compares the domain of an address a report names with the destination domain the token was issued for. Fails safe: a name that cannot be
    /// normalised does not match.
    /// </summary>
    public VerpDestinationCheck CheckDestination(in VerpToken token, string recipientDomain)
    {
        if (!token.BoundToDestination)
        {
            return VerpDestinationCheck.Unbound;
        }

        return _keys.TryGetValue(token.KeyId, out var key) && DestinationTag(key, recipientDomain) == token.DestinationTag
            ? VerpDestinationCheck.Match
            : VerpDestinationCheck.Mismatch;
    }

    /// <summary>The first four bytes of HMAC-SHA-256(key, "dst" + NUL + normalised domain): keyed, so the tag of a domain cannot be computed from a token of another.</summary>
    private static uint DestinationTag(byte[] key, string domain)
    {
        byte[] name = System.Text.Encoding.ASCII.GetBytes("dst\0" + NormalizeDomain(domain));
        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(key, name, mac);
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(mac);
    }

    /// <summary>Lower case, no trailing dot, A-label form (an invalid internationalised name stays as it is and so matches nothing real).</summary>
    private static string NormalizeDomain(string domain)
    {
        string d = domain.Trim().TrimEnd('.').ToLowerInvariant();
        if (d.All(char.IsAscii))
        {
            return d;
        }

        try
        {
            return new System.Globalization.IdnMapping().GetAscii(d).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return d;
        }
    }

    /// <summary>True if <paramref name="domainId"/> is the domain the token was issued for.</summary>
    public static bool MatchesDomain(in VerpToken token, Guid domainId)
    {
        Span<byte> b = stackalloc byte[16];
        domainId.TryWriteBytes(b, bigEndian: true, out _);
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(b) == token.DomainIdPrefix;
    }

    private static string Base32Encode(ReadOnlySpan<byte> data)
    {
        var chars = new char[(data.Length * 8 + 4) / 5];
        int buffer = 0, bits = 0, n = 0;
        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                chars[n++] = Alphabet[(buffer >> (bits - 5)) & 31];
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            chars[n++] = Alphabet[(buffer << (5 - bits)) & 31];
        }

        return new string(chars, 0, n);
    }

    private static bool Base32Decode(ReadOnlySpan<char> text, Span<byte> output)
    {
        int expected = (output.Length * 8 + 4) / 5;
        if (text.Length != expected)
        {
            return false;
        }

        int buffer = 0, bits = 0, n = 0;
        foreach (char raw in text)
        {
            // ASCII-only case folding: char.ToLowerInvariant maps the Kelvin sign (U+212A) to 'k', a second spelling of the token.
            char c = raw is >= 'A' and <= 'Z' ? (char)(raw | 0x20) : raw;
            int v = c switch
            {
                >= 'a' and <= 'z' => c - 'a',
                >= '2' and <= '7' => c - '2' + 26,
                _ => -1,
            };
            if (v < 0)
            {
                return false;
            }

            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8)
            {
                if (n >= output.Length)
                {
                    return false;
                }

                output[n++] = (byte)(buffer >> (bits - 8));
                bits -= 8;
            }
        }

        // Canonical form only: the unused trailing bits must be zero, otherwise several strings would decode to the same token.
        return n == output.Length && (buffer & ((1 << bits) - 1)) == 0;
    }
}
