namespace Mta.Dkim.Internal;

/// <summary>A parsed and syntactically validated DKIM-Signature header field. Parsing never throws; problems are reported through the Error* members.</summary>
internal sealed class DkimSignatureHeader
{
    public const int MaxTags = 32;
    public const int MaxSignedHeaderNames = 512;
    public const int MaxSignatureBytes = 512;

    public string? Domain { get; private set; }

    public string? Selector { get; private set; }

    public string? Identity { get; private set; }

    public string? Algorithm { get; private set; }

    public string? BPrefix { get; private set; }

    public byte[] Signature { get; private set; } = [];

    public byte[] BodyHash { get; private set; } = [];

    /// <summary>Lower-cased header field names from <c>h=</c> in order.</summary>
    public string[] SignedHeaderNames { get; private set; } = [];

    public bool HeaderRelaxed { get; private set; }

    public bool BodyRelaxed { get; private set; }

    public long? BodyLength { get; private set; }

    public long? Timestamp { get; private set; }

    public long? Expiration { get; private set; }

    /// <summary>Start of the <c>b=</c> value including surrounding whitespace, relative to the field without its trailing CRLF.</summary>
    public int BValueStart { get; private set; }

    public int BValueEnd { get; private set; }

    public DkimStatus ErrorStatus { get; private set; }

    public DkimFailure ErrorFailure { get; private set; }

    public string? ErrorReason { get; private set; }

    public bool HasError => ErrorReason is not null;

    /// <summary>
    /// Parses a DKIM-Signature field. <paramref name="field"/> is the whole field (name, colon, folded value) without the trailing CRLF;
    /// <paramref name="colonOffset"/> is the offset of the colon.
    /// </summary>
    public static DkimSignatureHeader Parse(ReadOnlySpan<byte> field, int colonOffset, int maxLength)
    {
        var sig = new DkimSignatureHeader();
        if (field.Length > maxLength)
        {
            return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "DKIM-Signature header too large");
        }

        Span<TagEntry> tags = stackalloc TagEntry[MaxTags];
        if (!TagListParser.TryParse(field, colonOffset + 1, tags, out int count, out string? error))
        {
            return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "malformed signature: " + error);
        }

        tags = tags.Slice(0, count);

        // d= and s= first so that they are reported even when a later tag is bad.
        // Single-token tags may not contain folding or other whitespace.
        foreach (var tag in tags)
        {
            var name = field.Slice(tag.NameStart, tag.NameLength);
            if ((name.SequenceEqual("d"u8) || name.SequenceEqual("s"u8) || name.SequenceEqual("v"u8) || name.SequenceEqual("a"u8) || name.SequenceEqual("c"u8)
                    || name.SequenceEqual("q"u8) || name.SequenceEqual("l"u8) || name.SequenceEqual("t"u8) || name.SequenceEqual("x"u8))
                && HasWhitespace(field.Slice(tag.ValueStart, tag.ValueLength)))
            {
                return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "whitespace inside a single-token tag value");
            }
        }

        if (!TagListParser.TryFind(field, tags, "d"u8, out var d) || d.ValueLength == 0) { return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "missing d= tag"); }
        string domain = TagListParser.CompactAscii(TagListParser.Value(field, d)).ToLowerInvariant();
        if (!DkimNames.IsValidDomain(domain)) { return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "invalid d= domain"); }
        sig.Domain = domain;

        if (!TagListParser.TryFind(field, tags, "s"u8, out var s) || s.ValueLength == 0) { return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "missing s= tag"); }
        string selector = TagListParser.CompactAscii(TagListParser.Value(field, s));
        if (!DkimNames.IsValidSelector(selector)) { return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "invalid s= selector"); }
        sig.Selector = selector;

        if (!TagListParser.TryFind(field, tags, "v"u8, out var v)) { return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "missing v= tag"); }
        if (!TagListParser.Value(field, v).SequenceEqual("1"u8)) { return sig.Fail(DkimStatus.Neutral, DkimFailure.UnsupportedVersion, "unsupported signature version"); }

        if (!TagListParser.TryFind(field, tags, "a"u8, out var a) || a.ValueLength == 0) { return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "missing a= tag"); }
        string algorithm = TagListParser.CompactAscii(TagListParser.Value(field, a)).ToLowerInvariant();
        if (algorithm.Length > 32) { return sig.Fail(DkimStatus.Neutral, DkimFailure.UnsupportedAlgorithm, "unsupported algorithm"); }
        sig.Algorithm = algorithm;

        if (!TagListParser.TryFind(field, tags, "b"u8, out var b) || b.ValueLength == 0) { return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "missing b= tag"); }
        sig.BValueStart = b.RawValueStart;
        sig.BValueEnd = b.RawValueEnd;
        if (!TagListParser.TryDecodeBase64(TagListParser.Value(field, b), MaxSignatureBytes, out var signature) || signature.Length == 0)
        {
            return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "invalid b= value");
        }

        sig.Signature = signature;
        string bCompact = TagListParser.CompactAscii(TagListParser.Value(field, b));
        sig.BPrefix = bCompact.Length > 8 ? bCompact.Substring(0, 8) : bCompact;

        if (algorithm == "rsa-sha1")
        {
            return sig.Fail(DkimStatus.Fail, DkimFailure.WeakAlgorithm, "rsa-sha1 signatures are not accepted (RFC 8301)");
        }

        if (algorithm != "rsa-sha256")
        {
            return sig.Fail(DkimStatus.Neutral, DkimFailure.UnsupportedAlgorithm, algorithm == "ed25519-sha256" ? "unsupported algorithm ed25519-sha256" : "unsupported algorithm");
        }

        if (!TagListParser.TryFind(field, tags, "bh"u8, out var bh) || bh.ValueLength == 0) { return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "missing bh= tag"); }
        if (!TagListParser.TryDecodeBase64(TagListParser.Value(field, bh), 32, out var bodyHash) || bodyHash.Length != 32)
        {
            return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "invalid bh= value");
        }

        sig.BodyHash = bodyHash;

        if (!TagListParser.TryFind(field, tags, "h"u8, out var h) || h.ValueLength == 0) { return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "missing h= tag"); }
        if (!TryParseHeaderNames(TagListParser.Value(field, h), out var names, out string? hError)) { return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, hError!); }
        sig.SignedHeaderNames = names;
        if (Array.IndexOf(names, "from") < 0) { return sig.Fail(DkimStatus.Neutral, DkimFailure.FromNotSigned, "From header is not covered by h="); }

        if (TagListParser.TryFind(field, tags, "c"u8, out var c))
        {
            string canon = TagListParser.CompactAscii(TagListParser.Value(field, c)).ToLowerInvariant();
            int slash = canon.IndexOf('/');
            string hc = slash < 0 ? canon : canon.Substring(0, slash);
            string bc = slash < 0 ? "simple" : canon.Substring(slash + 1);
            if (!TryCanon(hc, out bool hr) || !TryCanon(bc, out bool br)) { return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "invalid c= value"); }
            sig.HeaderRelaxed = hr;
            sig.BodyRelaxed = br;
        }

        if (TagListParser.TryFind(field, tags, "q"u8, out var q))
        {
            string method = TagListParser.CompactAscii(TagListParser.Value(field, q)).ToLowerInvariant();
            if (method != "dns/txt") { return sig.Fail(DkimStatus.Neutral, DkimFailure.UnsupportedQueryMethod, "unsupported query method"); }
        }

        if (TagListParser.TryFind(field, tags, "l"u8, out var l))
        {
            if (!TagListParser.TryParseDecimal(TagListParser.Value(field, l), 15, out long len)) { return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "invalid l= value"); }
            sig.BodyLength = len;
        }

        if (TagListParser.TryFind(field, tags, "t"u8, out var t))
        {
            if (!TagListParser.TryParseDecimal(TagListParser.Value(field, t), 15, out long ts)) { return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "invalid t= value"); }
            sig.Timestamp = ts;
        }

        if (TagListParser.TryFind(field, tags, "x"u8, out var x))
        {
            if (!TagListParser.TryParseDecimal(TagListParser.Value(field, x), 15, out long exp)) { return sig.Fail(DkimStatus.Neutral, DkimFailure.MalformedSignature, "invalid x= value"); }
            sig.Expiration = exp;
        }

        if (TagListParser.TryFind(field, tags, "i"u8, out var i))
        {
            var iv = TagListParser.Value(field, i);
            if (iv.Length > 512 || !TagListParser.TryDecodeQuotedPrintable(iv, out string identity) || !DkimNames.IsIdentityWithin(identity, domain))
            {
                return sig.Fail(DkimStatus.Neutral, DkimFailure.InvalidIdentity, "i= is not within the d= domain");
            }

            sig.Identity = identity;
        }

        return sig;
    }

    private static bool HasWhitespace(ReadOnlySpan<byte> value)
    {
        foreach (byte b in value)
        {
            if (TagListParser.IsWhitespace(b)) { return true; }
        }

        return false;
    }

    private static bool TryCanon(string value, out bool relaxed)
    {
        relaxed = false;
        switch (value)
        {
            case "simple": return true;
            case "relaxed": relaxed = true; return true;
            default: return false;
        }
    }

    private static bool TryParseHeaderNames(ReadOnlySpan<byte> value, out string[] names, out string? error)
    {
        names = [];
        error = null;
        var list = new List<string>(24);
        while (true)
        {
            int idx = value.IndexOf((byte)':');
            var part = idx < 0 ? value : value.Slice(0, idx);
            int s = 0;
            int e = part.Length;
            while (s < e && TagListParser.IsWhitespace(part[s])) { s++; }
            while (e > s && TagListParser.IsWhitespace(part[e - 1])) { e--; }
            if (e > s)
            {
                var name = part.Slice(s, e - s);
                foreach (byte ch in name)
                {
                    if (ch <= 0x20 || ch >= 0x7F) { error = "invalid header name in h="; return false; }
                }

                if (list.Count >= MaxSignedHeaderNames) { error = "too many header names in h="; return false; }
                list.Add(TagListParser.CompactAscii(name).ToLowerInvariant());
            }

            if (idx < 0) { break; }
            value = value.Slice(idx + 1);
        }

        if (list.Count == 0) { error = "empty h= list"; return false; }
        names = list.ToArray();
        return true;
    }

    private DkimSignatureHeader Fail(DkimStatus status, DkimFailure failure, string reason)
    {
        ErrorStatus = status;
        ErrorFailure = failure;
        ErrorReason = reason;
        return this;
    }
}

/// <summary>Syntax checks for the names that become DNS labels and identities.</summary>
internal static class DkimNames
{
    public static bool IsValidDomain(string domain)
    {
        if (domain.Length is 0 or > 253) { return false; }
        int labelLength = 0;
        foreach (char ch in domain)
        {
            if (ch == '.')
            {
                if (labelLength == 0) { return false; }
                labelLength = 0;
                continue;
            }

            if (!IsLabelChar(ch)) { return false; }
            if (++labelLength > 63) { return false; }
        }

        return labelLength > 0 && domain.Contains('.');
    }

    public static bool IsValidSelector(string selector)
    {
        if (selector.Length is 0 or > 100) { return false; }
        int labelLength = 0;
        foreach (char ch in selector)
        {
            if (ch == '.')
            {
                if (labelLength == 0) { return false; }
                labelLength = 0;
                continue;
            }

            if (!IsLabelChar(ch)) { return false; }
            if (++labelLength > 63) { return false; }
        }

        return labelLength > 0;
    }

    private static bool IsLabelChar(char ch) => ch is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_';

    /// <summary>True when the domain part of the identity (after the last '@') equals <paramref name="domain"/> or is a subdomain of it.</summary>
    public static bool IsIdentityWithin(string identity, string domain)
    {
        int at = identity.LastIndexOf('@');
        if (at < 0) { return false; }
        var idDomain = identity.AsSpan(at + 1);
        if (idDomain.Equals(domain, StringComparison.OrdinalIgnoreCase)) { return true; }
        return idDomain.Length > domain.Length
            && idDomain[idDomain.Length - domain.Length - 1] == '.'
            && idDomain.Slice(idDomain.Length - domain.Length).Equals(domain, StringComparison.OrdinalIgnoreCase);
    }
}
