using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Mta.Dsn;
using Mta.Mime;

namespace Mta.Host.Inbound;

/// <summary>The hop marker of a forward at the level of a whole message: read the count a message proves, and write the copy's marker (design section 11.7).</summary>
public interface IForwardHops
{
    /// <summary>The highest count among the markers that verify for this message's body; 0 when none does.</summary>
    int ReadValidHops(ReadOnlySpan<byte> message);

    /// <summary>The message with every marker removed and exactly one, for <paramref name="hops"/>, at the top.</summary>
    byte[] Apply(ReadOnlyMemory<byte> message, int hops);
}


/// <summary>
/// The signed hop marker of a forwarded message (design section 11.7): the header <c>X-EggMail-Hops: &lt;n&gt;; &lt;signature&gt;</c> where <c>signature</c> is the first 16 hex digits of
/// <c>HMAC-SHA-256(key, "EggMail.Hops.v1\n" + n + "\n" + hex(SHA-256(body)))</c>, <c>body</c> being the bytes after the first empty line exactly as stored, and the key derived from the bounce-token ring with the purpose
/// <see cref="Purpose"/> (signed with the active key, verified against every key of the ring). <b>No header is in the signature</b>: headers are what senders, lists and the next hop rewrite, while the forward delivers the body byte
/// for byte, so the body hash is the one thing that survives an honest forward and that a forger would have to know to produce a valid marker.
/// <para>Rules: a marker whose signature does not verify (forged, or the body changed on the way) counts for nothing; among the valid ones the highest <c>n</c> counts; a forward removes every marker and writes exactly one
/// with <c>n + 1</c>; a message that arrives with <c>n</c> at <see cref="MaxHops"/> is not forwarded. A sender can therefore neither lower the count (it would have to forge the signature) nor raise it to block a victim's forwarding
/// (a forged high count is invalid and ignored).</para>
/// </summary>
public sealed class ForwardHops : IForwardHops
{
    public const string HeaderName = "X-EggMail-Hops";

    /// <summary>The HKDF purpose of the key.</summary>
    public const string Purpose = "EggMail.Hops.v1";

    /// <summary>A message that arrives having been forwarded this many times by this server is not forwarded again.</summary>
    public const int MaxHops = 3;

    private const int SignatureHexChars = 16;
    private readonly Dictionary<int, byte[]> _keys = [];
    private readonly int _activeKeyId;

    public ForwardHops(VerpCodec ring)
    {
        ArgumentNullException.ThrowIfNull(ring);
        _activeKeyId = ring.ActiveKeyId;
        foreach (int id in ring.KeyIds)
        {
            _keys[id] = ring.DeriveKey(id, Purpose);
        }
    }

    /// <summary>The SHA-256 of the body as lower-case hex: compute it once per message.</summary>
    public static string BodyHash(ReadOnlySpan<byte> body) => Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();

    /// <summary>The field value for a body with the hash <paramref name="bodyHash"/> that has been forwarded <paramref name="hops"/> times (this hop included): <c>3; 0123456789abcdef</c>.</summary>
    public string CreateValue(int hops, string bodyHash) =>
        hops.ToString(CultureInfo.InvariantCulture) + "; " + Signature(_keys[_activeKeyId], hops, bodyHash);

    /// <summary>Checks the value of one <c>X-EggMail-Hops</c> field against the body hash: true with the count when the shape is right and the signature verifies under a key of the ring.</summary>
    public bool TryVerify(string fieldValue, string bodyHash, out int hops)
    {
        hops = 0;
        if (!TryParse(fieldValue, out int n, out string signature) || !IsValid(n, signature, bodyHash))
        {
            return false;
        }

        hops = n;
        return true;
    }

    /// <summary>
    /// The number of hops the message proves: the highest <c>n</c> among the markers with a valid signature for this message body, 0 when there is none valid. Markers with an invalid signature are ignored.
    /// </summary>
    public int ReadValidHops(ReadOnlySpan<byte> message)
    {
        int highest = 0;
        string? bodyHash = null;
        foreach (string value in MarkerValues(message, out int bodyStart))
        {
            bodyHash ??= BodyHash(message[bodyStart..]);
            if (TryVerify(value, bodyHash, out int hops) && hops > highest)
            {
                highest = hops;
            }
        }

        return highest;
    }

    /// <summary>The message with every marker removed and exactly one, for <paramref name="hops"/>, at the top. Nothing else about the message changes.</summary>
    public byte[] Apply(ReadOnlyMemory<byte> message, int hops)
    {
        int bodyStart = BodyStart(message.Span);
        string value = CreateValue(hops, BodyHash(message.Span[bodyStart..]));
        return new MessageHeaderEditor(message).Remove(HeaderName).Prepend(HeaderName, value).ToArray();
    }

    private bool IsValid(int hops, string signature, string bodyHash)
    {
        if (signature.Length != SignatureHexChars)
        {
            return false;
        }

        bool valid = false;
        foreach (byte[] key in _keys.Values)
        {
            valid |= CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Signature(key, hops, bodyHash)), Encoding.ASCII.GetBytes(signature.ToLowerInvariant()));
        }

        return valid;
    }

    private static string Signature(byte[] key, int hops, string bodyHash) =>
        Convert.ToHexStringLower(HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(Purpose + "\n" + hops.ToString(CultureInfo.InvariantCulture) + "\n" + bodyHash)))[..SignatureHexChars];


    private static bool TryParse(string value, out int hops, out string signature)
    {
        hops = 0;
        signature = string.Empty;
        int semicolon = value.IndexOf(';', StringComparison.Ordinal);
        if (semicolon <= 0)
        {
            return false;
        }

        string count = value[..semicolon].Trim();
        signature = value[(semicolon + 1)..].Trim();
        return count.Length is > 0 and <= 3 && count.All(char.IsAsciiDigit) && int.TryParse(count, NumberStyles.None, CultureInfo.InvariantCulture, out hops) && hops > 0;
    }

    /// <summary>Index of the first byte after the empty line that ends the header section (the message length when there is none).</summary>
    internal static int BodyStart(ReadOnlySpan<byte> message)
    {
        if (message.Length >= 2 && message[0] == '\r' && message[1] == '\n')
        {
            return 2;
        }

        int at = message.IndexOf("\r\n\r\n"u8);
        return at < 0 ? message.Length : at + 4;
    }

    /// <summary>The unfolded values of the marker headers of the message, in order.</summary>
    private static List<string> MarkerValues(ReadOnlySpan<byte> message, out int bodyStart)
    {
        bodyStart = BodyStart(message);
        var values = new List<string>();
        int headerEnd = Math.Max(0, bodyStart - 2);   // the header lines end at the CRLF that precedes the empty line
        ReadOnlySpan<byte> headers = message[..Math.Min(headerEnd, message.Length)];
        int pos = 0;
        while (pos < headers.Length)
        {
            int end = headers[pos..].IndexOf("\r\n"u8);
            int lineEnd = end < 0 ? headers.Length : pos + end;
            // A field continues on the following lines that start with a space or a tab.
            int fieldEnd = lineEnd;
            while (fieldEnd + 2 < headers.Length && (headers[fieldEnd + 2] == ' ' || headers[fieldEnd + 2] == '\t'))
            {
                int next = headers[(fieldEnd + 2)..].IndexOf("\r\n"u8);
                fieldEnd = next < 0 ? headers.Length : fieldEnd + 2 + next;
            }

            ReadOnlySpan<byte> field = headers[pos..fieldEnd];
            int colon = field.IndexOf((byte)':');
            if (colon == HeaderName.Length && Encoding.ASCII.GetString(field[..colon]).Equals(HeaderName, StringComparison.OrdinalIgnoreCase))
            {
                string raw = Encoding.ASCII.GetString(field[(colon + 1)..]).Replace("\r\n", string.Empty, StringComparison.Ordinal);
                values.Add(raw.Trim());
            }

            pos = fieldEnd + 2;
        }

        return values;
    }
}
