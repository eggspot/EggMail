using System.Security.Cryptography;
using System.Text;

namespace Mta.Storage.Portability;

/// <summary>
/// A 256-bit sum (modulo 2^256) of hashes. Adding is commutative, so two stores that hold the same rows get the same sum
/// whatever order their database returns them in (collations and uuid ordering differ between SQLite and PostgreSQL).
/// </summary>
public struct HashSum
{
    private byte[]? _bytes;

    public static HashSum Parse(string hex)
    {
        byte[] b = Convert.FromHexString(hex);
        if (b.Length != 32)
        {
            throw new FormatException("A hash sum is 32 bytes.");
        }

        return new HashSum { _bytes = b };
    }

    public void Add(ReadOnlySpan<byte> hash32)
    {
        _bytes ??= new byte[32];
        int carry = 0;
        for (int i = 31; i >= 0; i--)
        {
            int sum = _bytes[i] + hash32[i] + carry;
            _bytes[i] = (byte)sum;
            carry = sum >> 8;
        }
    }

    public readonly string Hex => Convert.ToHexString(_bytes ?? new byte[32]).ToLowerInvariant();
}

/// <summary>Row count and checksums of one table, accumulated while rows stream by (export, or recomputation on the target).</summary>
public sealed class TableChecksum
{
    private HashSum _rows;
    private HashSum _secrets;
    private bool _hasSecrets;

    public long Rows { get; private set; }

    /// <summary>The rows of the table that a switch holds (all of them unless the table's hold names a condition).</summary>
    public long HeldRows { get; set; }

    public string Checksum => _rows.Hex;

    public string? SecretDigest => _hasSecrets ? _secrets.Hex : null;

    public static TableChecksum Resume(long rows, string checksum, string? secretDigest, long? heldRows = null)
    {
        var t = new TableChecksum { Rows = rows, HeldRows = heldRows ?? rows, _rows = HashSum.Parse(checksum) };
        if (secretDigest is not null)
        {
            t._secrets = HashSum.Parse(secretDigest);
            t._hasSecrets = true;
        }

        return t;
    }

    public void AddRow(string canonical)
    {
        Rows++;
        _rows.Add(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    /// <summary>Adds the keyed hash of one plain secret, bound to its row (the canonical text) and column.</summary>
    public void AddSecret(byte[] digestKey, string canonical, string column, ReadOnlySpan<byte> plain)
    {
        using var hmac = new HMACSHA256(digestKey);
        hmac.TransformBlock(Encoding.UTF8.GetBytes(canonical), 0, Encoding.UTF8.GetByteCount(canonical), null, 0);
        byte[] separator = [0];
        hmac.TransformBlock(separator, 0, 1, null, 0);
        hmac.TransformBlock(Encoding.UTF8.GetBytes(column), 0, Encoding.UTF8.GetByteCount(column), null, 0);
        hmac.TransformBlock(separator, 0, 1, null, 0);
        hmac.TransformFinalBlock(plain.ToArray(), 0, plain.Length);
        _secrets.Add(hmac.Hash!);
        _hasSecrets = true;
    }

    public BundleTable ToManifest(string name, string part) => new() { Name = name, Part = part, Rows = Rows, HeldRows = HeldRows, Checksum = Checksum, SecretDigest = SecretDigest };
}
