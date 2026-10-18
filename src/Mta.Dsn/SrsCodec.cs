using System.Security.Cryptography;
using System.Text;

namespace Mta.Dsn;

/// <summary>
/// Sender Rewriting Scheme addresses for forwarded mail (design section 11.7): the envelope sender of a forward is
/// <c>SRS0=&lt;hash&gt;=&lt;tt&gt;=&lt;original domain&gt;=&lt;original local part&gt;</c> at the forwarding domain. The final receiver checks SPF against that address, which is at a domain whose record authorizes this server.
/// The one implementation of both sides: the forward runner creates the address, the receive path verifies the bounces that return to it.
/// <para><b>Hash:</b> the first 8 characters (40 bits) of the Base32 of HMAC-SHA-256 over the lower-case text <c>tt "=" domain field "=" local part field</c> (the fields as they appear in the address; the separators make the boundaries unambiguous), with a key derived
/// from the bounce-token ring by HKDF (<see cref="Purpose"/>). Signing uses the active key; verification tries every key of the ring and runs every comparison in constant time, so rotating the ring does not invalidate
/// addresses in flight. <b>Timestamp <c>tt</c>:</b> the day number since 1970-01-01 modulo 1024 in two Base32 characters. <b>Age:</b> the current day and the days before it, <c>maxAgeDays</c> in all (the default 21 is
/// the design's "current and previous 20 days"); an address dated in the future is invalid.</para>
/// <para><b>Long and unusual addresses:</b> the SMTP local part is limited to 64 <em>octets</em>. When the long form does not fit, or the original domain or local part is not plain (lower-case ASCII letters, digits and
/// <c>. _ + -</c>, with no empty or dotted-out label: anything that would need quoting or is not ASCII), both are replaced by one token: <c>SRS0=&lt;hash&gt;=&lt;tt&gt;=x=&lt;first 32 hex digits of SHA-256(UTF-8 of
/// lower-case(domain "=" local))&gt;</c> (51 octets). The hash covers the digest, which covers the original, so the short form is as hard to forge as the long one. This is safe because an SRS address is never reversed: a
/// bounce to it is verified and dropped (design section 11.7). An address that carries anything but ASCII, or is longer than 64 octets, never verifies.</para>
/// </summary>
public sealed class SrsCodec
{
    /// <summary>The HKDF purpose of the key.</summary>
    public const string Purpose = "EggMail.Srs.v1";

    public const string Prefix = "SRS0=";

    /// <summary>The longest local part an SMTP server must accept, in octets (RFC 5321 section 4.5.3.1.1).</summary>
    public const int MaxLocalPartLength = 64;

    /// <summary>The current day and the 20 before it.</summary>
    public const int DefaultMaxAgeDays = 21;

    public const int HashLength = 8;
    private const string Alphabet = "abcdefghijklmnopqrstuvwxyz234567";

    private readonly VerpCodec _ring;
    private readonly int _maxAgeDays;
    private readonly Dictionary<int, byte[]> _keys = [];

    /// <param name="ring">The bounce-token key ring the SRS key is derived from.</param>
    /// <param name="maxAgeDays">How many days an address stays valid for <see cref="TryVerify(string, DateTimeOffset)"/> (<c>Inbound:Srs:MaxAgeDays</c>).</param>
    public SrsCodec(VerpCodec ring, int maxAgeDays = DefaultMaxAgeDays)
    {
        ArgumentNullException.ThrowIfNull(ring);
        if (maxAgeDays is < 1 or > 500)
        {
            throw new ArgumentOutOfRangeException(nameof(maxAgeDays), "The age must be between 1 and 500 days.");
        }

        _ring = ring;
        _maxAgeDays = maxAgeDays;
        foreach (int id in ring.KeyIds)
        {
            _keys[id] = ring.DeriveKey(id, Purpose);
        }
    }

    /// <summary>True when the local part starts with <c>SRS0=</c> or <c>SRS1=</c> (any case): the receive path treats such a recipient as an SRS recipient (design section 11.4).</summary>
    public static bool HasSrsPrefix(string localPart) =>
        localPart.StartsWith("SRS0=", StringComparison.OrdinalIgnoreCase) || localPart.StartsWith("SRS1=", StringComparison.OrdinalIgnoreCase);

    /// <summary>The local part (without the domain) for a message whose reverse-path was <c>originalLocalPart@originalDomain</c>, dated <paramref name="now"/>. Never longer than <see cref="MaxLocalPartLength"/> octets.</summary>
    public string CreateLocalPart(string originalDomain, string originalLocalPart, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrEmpty(originalDomain);
        ArgumentException.ThrowIfNullOrEmpty(originalLocalPart);
        string domain = originalDomain.Trim().TrimEnd('.').ToLowerInvariant();
        string local = originalLocalPart.ToLowerInvariant();
        string tt = EncodeDay(now);
        if (IsPlain(domain, local))
        {
            string longForm = Prefix + Hash(_ring.ActiveKeyId, tt, domain, local) + "=" + tt + "=" + domain + "=" + local;
            if (longForm.Length <= MaxLocalPartLength)   // plain means ASCII: characters are octets
            {
                return longForm;
            }
        }

        string digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(domain + "=" + local)))[..32];
        return Prefix + Hash(_ring.ActiveKeyId, tt, "x", digest) + "=" + tt + "=x=" + digest;
    }

    /// <summary>The full address at the forwarding domain.</summary>
    public string CreateAddress(string originalDomain, string originalLocalPart, string forwardingDomain, DateTimeOffset now) =>
        CreateLocalPart(originalDomain, originalLocalPart, now) + "@" + forwardingDomain;

    /// <summary>True when <paramref name="localPart"/> is an SRS0 address this server made with a key of the ring, not older than the configured age and not dated in the future. An <c>SRS1=</c> address is never valid: this server issues none.</summary>
    public bool TryVerify(string localPart, DateTimeOffset now) => TryVerify(localPart, now, _maxAgeDays);

    /// <summary><see cref="TryVerify(string, DateTimeOffset)"/> with an explicit age in days.</summary>
    public bool TryVerify(string localPart, DateTimeOffset now, int maxAgeDays)
    {
        // Only what we issue can verify: ASCII, at most 64 octets, SRS0 and the fixed shape SRS0=<hash>=<tt>=<domain>=<local>.
        if (localPart.Length > MaxLocalPartLength || !Ascii.IsValid(localPart) || !localPart.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase) || maxAgeDays < 1 || maxAgeDays > 1000)
        {
            return false;
        }

        string[] parts = localPart.Split('=', 5);
        if (parts.Length != 5 || parts[1].Length != HashLength || parts[2].Length != 2 || parts[3].Length == 0 || parts[4].Length == 0 || !TryDecodeDay(parts[2], out int day))
        {
            return false;
        }

        int today = (int)(now.ToUnixTimeSeconds() / 86400 % 1024);
        int age = (today - day + 1024) % 1024;
        if (age >= maxAgeDays || !TryDecodeHash(parts[1], out byte[] presented))
        {
            return false;
        }

        bool valid = false;
        string text = parts[2].ToLowerInvariant() + "=" + parts[3].ToLowerInvariant() + "=" + parts[4].ToLowerInvariant();
        foreach (byte[] key in _keys.Values)
        {
            // Every key is tried and every comparison runs: the time does not tell which key (or whether any) matched.
            valid |= CryptographicOperations.FixedTimeEquals(Mac(key, text).AsSpan(0, 5), presented);
        }

        return valid;
    }

    private string Hash(int keyId, string tt, string field3, string field4) => EncodeHash(Mac(_keys[keyId], tt + "=" + field3 + "=" + field4)[..5]);

    private static byte[] Mac(byte[] key, string text) => HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(text));

    private static bool IsPlain(string domain, string local)
    {
        if (local.Length == 0 || domain.Length == 0 || local.Contains("..", StringComparison.Ordinal) || local[0] == '.' || local[^1] == '.' || domain.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        foreach (char c in local)
        {
            if (!(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '+' or '-'))
            {
                return false;
            }
        }

        foreach (char c in domain)
        {
            if (!(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-'))
            {
                return false;
            }
        }

        return true;
    }

    private static string EncodeDay(DateTimeOffset now)
    {
        int day = (int)(now.ToUnixTimeSeconds() / 86400 % 1024);
        return new string([Alphabet[day >> 5], Alphabet[day & 31]]);
    }

    private static bool TryDecodeDay(string tt, out int day)
    {
        int high = Alphabet.IndexOf(char.ToLowerInvariant(tt[0]), StringComparison.Ordinal);
        int low = Alphabet.IndexOf(char.ToLowerInvariant(tt[1]), StringComparison.Ordinal);
        day = (high << 5) | low;
        return high >= 0 && low >= 0;
    }

    private static string EncodeHash(ReadOnlySpan<byte> five)
    {
        var chars = new char[HashLength];
        int buffer = 0, bits = 0, n = 0;
        foreach (byte b in five)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                chars[n++] = Alphabet[(buffer >> (bits - 5)) & 31];
                bits -= 5;
            }
        }

        return new string(chars, 0, n);
    }

    private static bool TryDecodeHash(string text, out byte[] bytes)
    {
        bytes = new byte[5];
        int buffer = 0, bits = 0, n = 0;
        foreach (char raw in text)
        {
            int v = Alphabet.IndexOf(char.ToLowerInvariant(raw), StringComparison.Ordinal);
            if (v < 0)
            {
                return false;
            }

            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8)
            {
                bytes[n++] = (byte)(buffer >> (bits - 8));
                bits -= 8;
            }
        }

        return n == 5;
    }
}
