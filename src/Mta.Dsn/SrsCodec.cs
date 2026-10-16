using System.Security.Cryptography;
using System.Text;

namespace Mta.Dsn;

/// <summary>What <see cref="SrsCodec.Verify"/> concluded about the local part of an address at one of our domains.</summary>
public enum SrsCheck
{
    /// <summary>Not an SRS0 address, or its shape is wrong, or the hash does not verify under any key of the ring.</summary>
    Invalid,

    /// <summary>The hash verifies but the address is older than the allowed age (or from the future).</summary>
    Expired,

    /// <summary>The hash verifies and the address is recent enough.</summary>
    Valid,
}

/// <summary>
/// Sender Rewriting Scheme addresses for forwarded mail (design section 11.7): <c>SRS0=&lt;hash&gt;=&lt;tt&gt;=&lt;original domain&gt;=&lt;original local part&gt;@forwarding-domain</c>. The receiver of a
/// forward checks SPF against the envelope sender, and with SRS that is our domain, which the tenant verified. Stateless: <c>tt</c> is the day number modulo 1024 in two Base32 characters and <c>hash</c> is
/// the first 8 Base32 characters (40 bits) of HMAC-SHA-256 over the lower-cased <c>tt + original domain + original local part</c>, keyed by HKDF from the bounce-token key with the purpose
/// <see cref="Purpose"/>. Signing uses the active key of the ring; verification tries every key of the ring, each comparison in constant time, so rotating the bounce key does not invalidate addresses in flight.
/// <para>The SMTP local part is limited to 64 octets. When the long form is longer, domain and local part are both replaced by one token, <c>SRS0=hash=tt=x=&lt;first 32 hex digits of SHA-256(lower(domain "=" local))&gt;</c>
/// (at most 51 octets), and the hash is computed over <c>tt + "x" + digest</c>, which covers the original through the digest. That is safe because an SRS address is never reversed: a bounce to it is verified and dropped.</para>
/// </summary>
public sealed class SrsCodec
{
    /// <summary>The HKDF context of the SRS key.</summary>
    public const string Purpose = "EggMail.Srs.v1";

    public const string Prefix = "SRS0=";
    public const int MaxLocalPartLength = 64;
    public const int HashLength = 8;
    private const string Alphabet = "abcdefghijklmnopqrstuvwxyz234567";

    private readonly VerpCodec _verp;
    private readonly int _maxAgeDays;
    private readonly Dictionary<int, byte[]> _derived = [];

    /// <param name="verp">The bounce-token key ring the SRS key is derived from.</param>
    /// <param name="maxAgeDays">How many days an address stays valid (<c>Inbound:Srs:MaxAgeDays</c>, 21 by default).</param>
    public SrsCodec(VerpCodec verp, int maxAgeDays = 21)
    {
        ArgumentNullException.ThrowIfNull(verp);
        if (maxAgeDays is < 1 or > 500)
        {
            throw new ArgumentOutOfRangeException(nameof(maxAgeDays), "The age must be between 1 and 500 days.");
        }

        _verp = verp;
        _maxAgeDays = maxAgeDays;
        foreach (int id in verp.KeyIds)
        {
            _derived[id] = verp.DeriveKey(id, Purpose);
        }
    }

    /// <summary>The local part for a message whose envelope sender was <c>originalLocalPart@originalDomain</c>, at <paramref name="now"/>. Never longer than <see cref="MaxLocalPartLength"/>.</summary>
    public string CreateLocalPart(string originalDomain, string originalLocalPart, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrEmpty(originalDomain);
        ArgumentException.ThrowIfNullOrEmpty(originalLocalPart);
        string tt = Timestamp(now);
        string domain = originalDomain.ToLowerInvariant();
        string local = originalLocalPart;
        string full = Prefix + new string('h', HashLength) + "=" + tt + "=" + domain + "=" + local;
        if (full.Length > MaxLocalPartLength)
        {
            domain = "x";
            local = ShortDigest(originalDomain, originalLocalPart);
        }

        return Prefix + Hash(_derived[_verp.ActiveKeyId], tt, domain, local) + "=" + tt + "=" + domain + "=" + local;
    }

    /// <summary>The full address at the forwarding domain.</summary>
    public string CreateAddress(string originalDomain, string originalLocalPart, string forwardingDomain, DateTimeOffset now) =>
        CreateLocalPart(originalDomain, originalLocalPart, now) + "@" + forwardingDomain;

    /// <summary>Checks the local part of a recipient: a recent SRS0 address with a hash that verifies under a key of the ring.</summary>
    public SrsCheck Verify(string localPart, DateTimeOffset now)
    {
        if (!localPart.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase) || localPart.Length > MaxLocalPartLength)
        {
            return SrsCheck.Invalid;
        }

        // SRS0=<hash>=<tt>=<domain>=<local>: the hash has a fixed length, tt two characters, the domain has no '=', the local part may have any.
        ReadOnlySpan<char> rest = localPart.AsSpan(Prefix.Length);
        if (rest.Length < HashLength + 1 + 2 + 1 + 1 + 1 + 1 || rest[HashLength] != '=' || rest[HashLength + 3] != '=')
        {
            return SrsCheck.Invalid;
        }

        string hash = rest[..HashLength].ToString().ToLowerInvariant();
        string tt = rest.Slice(HashLength + 1, 2).ToString().ToLowerInvariant();
        ReadOnlySpan<char> tail = rest[(HashLength + 4)..];
        int equals = tail.IndexOf('=');
        if (equals < 1 || equals == tail.Length - 1)
        {
            return SrsCheck.Invalid;
        }

        string domain = tail[..equals].ToString();
        string local = tail[(equals + 1)..].ToString();
        if (TimestampValue(tt) is not { } day)
        {
            return SrsCheck.Invalid;
        }

        byte[] given = Encoding.ASCII.GetBytes(hash);
        bool verified = false;
        foreach (byte[] key in _derived.Values)
        {
            // Every key is tried and none short-circuits the others' comparisons, so the time does not say which key matched.
            verified |= CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Hash(key, tt, domain, local)), given);
        }

        if (!verified)
        {
            return SrsCheck.Invalid;
        }

        int age = ((CurrentDay(now) - day) % 1024 + 1024) % 1024;
        return age <= _maxAgeDays || age == 1023 /* a day ahead: clocks and time zones */ ? SrsCheck.Valid : SrsCheck.Expired;
    }

    private static long DaysSinceEpoch(DateTimeOffset now) => (long)Math.Floor((now.ToUniversalTime() - DateTimeOffset.UnixEpoch).TotalDays);

    private static int CurrentDay(DateTimeOffset now) => (int)(DaysSinceEpoch(now) % 1024);

    private static string Timestamp(DateTimeOffset now)
    {
        int day = CurrentDay(now);
        return new string([Alphabet[(day >> 5) & 31], Alphabet[day & 31]]);
    }

    private static int? TimestampValue(string tt)
    {
        int a = Alphabet.IndexOf(tt[0], StringComparison.Ordinal);
        int b = Alphabet.IndexOf(tt[1], StringComparison.Ordinal);
        return a < 0 || b < 0 ? null : (a << 5) | b;
    }

    private static string ShortDigest(string domain, string local)
    {
        byte[] data = Encoding.UTF8.GetBytes((domain + "=" + local).ToLowerInvariant());
        return Convert.ToHexString(SHA256.HashData(data))[..32].ToLowerInvariant();
    }

    private static string Hash(byte[] key, string tt, string domain, string local)
    {
        byte[] input = Encoding.UTF8.GetBytes((tt + domain + local).ToLowerInvariant());
        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(key, input, mac);
        var chars = new char[HashLength];
        int buffer = 0, bits = 0, n = 0;
        foreach (byte b in mac[..5])
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5 && n < HashLength)
            {
                chars[n++] = Alphabet[(buffer >> (bits - 5)) & 31];
                bits -= 5;
            }
        }

        return new string(chars);
    }
}
