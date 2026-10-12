using System.Buffers;
using System.Text;
using Mta.Dkim.Internal;

namespace Mta.Dkim;

/// <summary>A parsed DKIM public key record (the TXT record at <c>selector._domainkey.domain</c>, RFC 6376 section 3.6.1).</summary>
public sealed class DkimKeyRecord
{
    /// <summary>Longest record text accepted; a 4096-bit RSA key needs about 800 characters.</summary>
    public const int MaxRecordLength = 8192;

    /// <summary>Largest accepted decoded <c>p=</c> value in bytes (a 4096-bit SubjectPublicKeyInfo is about 550).</summary>
    public const int MaxPublicKeyBytes = 1024;

    private const int MaxTags = 24;

    private DkimKeyRecord(string? version, string keyType, byte[] publicKey, string[]? hashAlgorithms, string[]? serviceTypes, string[] flags, string? notes)
    {
        Version = version;
        KeyType = keyType;
        PublicKeySubjectPublicKeyInfo = publicKey;
        HashAlgorithms = hashAlgorithms;
        ServiceTypes = serviceTypes;
        Flags = flags;
        Notes = notes;
    }

    /// <summary><c>v=</c> when present (always <c>DKIM1</c> for an accepted record).</summary>
    public string? Version { get; }

    /// <summary><c>k=</c>, lower-cased; <c>rsa</c> when absent.</summary>
    public string KeyType { get; }

    /// <summary>The DER SubjectPublicKeyInfo from <c>p=</c>; empty when the key was revoked.</summary>
    public byte[] PublicKeySubjectPublicKeyInfo { get; }

    /// <summary><c>h=</c> acceptable hash algorithms (lower-cased), or null when unrestricted.</summary>
    public string[]? HashAlgorithms { get; }

    /// <summary><c>s=</c> service types (lower-cased), or null when unrestricted.</summary>
    public string[]? ServiceTypes { get; }

    /// <summary><c>t=</c> flags (lower-cased), for example <c>y</c> and <c>s</c>.</summary>
    public string[] Flags { get; }

    /// <summary><c>n=</c> human readable notes, if any.</summary>
    public string? Notes { get; }

    /// <summary>An empty <c>p=</c> means the key has been revoked.</summary>
    public bool IsRevoked => PublicKeySubjectPublicKeyInfo.Length == 0;

    /// <summary><c>t=y</c>: the domain is testing DKIM.</summary>
    public bool IsTesting => Array.IndexOf(Flags, "y") >= 0;

    /// <summary><c>t=s</c>: <c>i=</c> must have exactly the <c>d=</c> domain, no subdomains.</summary>
    public bool IsStrictIdentity => Array.IndexOf(Flags, "s") >= 0;

    /// <summary>True when the record allows the SHA-256 hash (no <c>h=</c> restriction, or it lists sha256).</summary>
    public bool AllowsSha256 => HashAlgorithms is null || Array.IndexOf(HashAlgorithms, "sha256") >= 0;

    /// <summary>True when the record is usable for e-mail (no <c>s=</c> restriction, or it lists <c>*</c> or <c>email</c>).</summary>
    public bool AllowsEmail => ServiceTypes is null || Array.IndexOf(ServiceTypes, "*") >= 0 || Array.IndexOf(ServiceTypes, "email") >= 0;

    /// <summary>Parses the TXT text (all character-strings already concatenated). Never throws.</summary>
    public static bool TryParse(string? text, out DkimKeyRecord? record, out string? error)
    {
        record = null;
        error = null;
        if (text is null) { error = "no record text"; return false; }
        if (text.Length > MaxRecordLength) { error = "key record too long"; return false; }

        byte[]? rented = null;
        Span<byte> bytes = text.Length <= 1024 ? stackalloc byte[text.Length] : (rented = ArrayPool<byte>.Shared.Rent(text.Length)).AsSpan(0, text.Length);
        try
        {
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (c > 0x7E) { error = "non-ASCII character in key record"; return false; }
                bytes[i] = (byte)c;
            }

            return TryParse(bytes, out record, out error);
        }
        finally
        {
            if (rented is not null) { ArrayPool<byte>.Shared.Return(rented); }
        }
    }

    internal static bool TryParse(ReadOnlySpan<byte> input, out DkimKeyRecord? record, out string? error)
    {
        record = null;
        Span<TagEntry> tags = stackalloc TagEntry[MaxTags];
        if (!TagListParser.TryParse(input, 0, tags, out int count, out error)) { return false; }
        tags = tags.Slice(0, count);

        string? version = null;
        if (TagListParser.TryFind(input, tags, "v"u8, out var v))
        {
            var vv = TagListParser.Value(input, v);
            if (!vv.SequenceEqual("DKIM1"u8)) { error = "unsupported key record version"; return false; }
            version = "DKIM1";
        }

        string keyType = "rsa";
        if (TagListParser.TryFind(input, tags, "k"u8, out var k))
        {
            var kv = TagListParser.Value(input, k);
            if (kv.IsEmpty || kv.Length > 32) { error = "invalid k= tag"; return false; }
            keyType = TagListParser.CompactAscii(kv).ToLowerInvariant();
        }

        if (!TagListParser.TryFind(input, tags, "p"u8, out var p)) { error = "missing p= tag"; return false; }
        if (!TagListParser.TryDecodeBase64(TagListParser.Value(input, p), MaxPublicKeyBytes, out var key))
        {
            error = "invalid p= tag (bad base64 or key too large)";
            return false;
        }

        string[]? hashes = null;
        if (TagListParser.TryFind(input, tags, "h"u8, out var h)) { hashes = SplitColonList(TagListParser.Value(input, h)); }
        string[]? services = null;
        if (TagListParser.TryFind(input, tags, "s"u8, out var s)) { services = SplitColonList(TagListParser.Value(input, s)); }
        string[] flags = [];
        if (TagListParser.TryFind(input, tags, "t"u8, out var t)) { flags = SplitColonList(TagListParser.Value(input, t)) ?? []; }
        string? notes = null;
        if (TagListParser.TryFind(input, tags, "n"u8, out var n))
        {
            var nv = TagListParser.Value(input, n);
            notes = nv.Length > 256 ? null : Encoding.ASCII.GetString(nv);
        }

        record = new DkimKeyRecord(version, keyType, key, hashes, services, flags, notes);
        error = null;
        return true;
    }

    private static string[]? SplitColonList(ReadOnlySpan<byte> value)
    {
        if (value.Length > 256) { return ["?"]; }
        var list = new List<string>(4);
        while (true)
        {
            int idx = value.IndexOf((byte)':');
            var part = idx < 0 ? value : value.Slice(0, idx);
            string s = TagListParser.CompactAscii(part).ToLowerInvariant();
            if (s.Length > 0) { list.Add(s); }
            if (idx < 0) { break; }
            value = value.Slice(idx + 1);
        }

        return list.Count == 0 ? null : list.ToArray();
    }
}
