using System.Security.Cryptography;
using Mta.Core;

namespace Mta.Dsn;

/// <summary>What a bounce address proves about the original message (stateless, decision 13).</summary>
public readonly record struct VerpToken(Guid TenantId, ulong DomainIdPrefix, DateTimeOffset IssuedAt, int KeyId);

/// <summary>
/// Stateless signed VERP bounce addresses: <c>b+&lt;token&gt;@bounce-domain</c>. The token carries the tenant id, an 8-byte prefix
/// of the sending domain's id (unique within a tenant), an hour-resolution timestamp, a key id and a truncated HMAC-SHA-256,
/// encoded as lower-case base32 so that mail systems that fold case cannot corrupt it. 36 bytes become 58 characters, which
/// together with <c>b+</c> fits the 64-octet local-part limit. No per-message state is needed to correlate a bounce
/// (the recipient to suppress comes from the DSN's Final-Recipient).
/// </summary>
public sealed class VerpCodec
{
    public const string Prefix = "b+";
    private const int PayloadLength = 28;   // version/key (1) + tenant (16) + domain prefix (8) + timestamp (3)
    private const int MacLength = 8;
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

    public static byte[] GenerateKey() => RandomNumberGenerator.GetBytes(32);

    /// <summary>Returns the local part, for example <c>b+abc…</c>.</summary>
    public string CreateLocalPart(Guid tenantId, Guid domainId, DateTimeOffset now)
    {
        Span<byte> data = stackalloc byte[PayloadLength + MacLength];
        data[0] = (byte)((1 << 4) | _activeKeyId);   // version 1 in the high nibble
        tenantId.TryWriteBytes(data[1..17], bigEndian: true, out _);
        Span<byte> dom = stackalloc byte[16];
        domainId.TryWriteBytes(dom, bigEndian: true, out _);
        dom[..8].CopyTo(data[17..25]);
        long hours = (long)(now - Epoch).TotalHours;
        data[25] = (byte)(hours >> 16);
        data[26] = (byte)(hours >> 8);
        data[27] = (byte)hours;
        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(_keys[_activeKeyId], data[..PayloadLength], mac);
        mac[..MacLength].CopyTo(data[PayloadLength..]);
        return Prefix + Base32Encode(data);
    }

    /// <summary>The full bounce address for a domain: <c>b+token@domain</c>.</summary>
    public string CreateAddress(Guid tenantId, Guid domainId, string bounceDomain, DateTimeOffset now) =>
        CreateLocalPart(tenantId, domainId, now) + "@" + bounceDomain;

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

        Span<byte> data = stackalloc byte[PayloadLength + MacLength];
        if (!Base32Decode(localPart.AsSpan(Prefix.Length), data))
        {
            return false;
        }

        if ((data[0] >> 4) != 1)
        {
            return false;
        }

        int keyId = data[0] & 0xF;
        if (!_keys.TryGetValue(keyId, out var key))
        {
            return false;
        }

        Span<byte> expected = stackalloc byte[32];
        HMACSHA256.HashData(key, data[..PayloadLength], expected);
        if (!CryptographicOperations.FixedTimeEquals(expected[..MacLength], data[PayloadLength..]))
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
        token = new VerpToken(tenant, prefix, issued, keyId);
        return true;
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
            char c = char.ToLowerInvariant(raw);
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
