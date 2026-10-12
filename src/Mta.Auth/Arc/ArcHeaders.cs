using System.Diagnostics.CodeAnalysis;
using System.Text;
using Mta.Auth.AuthenticationResults;
using Mta.Dkim;

namespace Mta.Auth.Arc;

/// <summary>Names, limits and syntax rules shared by the three ARC header types (RFC 8617 section 4).</summary>
public static class ArcHeaderNames
{
    /// <summary>The ARC-Seal header field name.</summary>
    public const string Seal = "ARC-Seal";

    /// <summary>The ARC-Message-Signature header field name.</summary>
    public const string MessageSignature = "ARC-Message-Signature";

    /// <summary>The ARC-Authentication-Results header field name.</summary>
    public const string AuthenticationResults = "ARC-Authentication-Results";

    /// <summary>The highest instance number RFC 8617 allows (section 4.2.1).</summary>
    public const int MaxInstance = 50;

    /// <summary>The only signature algorithm this implementation produces and accepts.</summary>
    public const string RsaSha256 = "rsa-sha256";

    /// <summary>Default for the longest accepted ARC header field in bytes.</summary>
    public const int DefaultMaxHeaderLength = 16384;
}

/// <summary>Syntax checks for the domain and selector names that end up in DNS queries.</summary>
internal static class ArcNames
{
    public static bool IsValidDomain(string name) => IsDnsName(name, allowUnderscore: false, requireDot: true);

    public static bool IsValidSelector(string name) => IsDnsName(name, allowUnderscore: true, requireDot: false);

    private static bool IsDnsName(string name, bool allowUnderscore, bool requireDot)
    {
        if (name.Length is 0 or > 253) { return false; }
        int labelLength = 0;
        bool sawDot = false;
        for (int i = 0; i < name.Length; i++)
        {
            char c = name[i];
            if (c == '.')
            {
                if (labelLength == 0 || name[i - 1] == '-') { return false; }
                labelLength = 0;
                sawDot = true;
                continue;
            }

            bool ok = char.IsAsciiLetterOrDigit(c) || c == '-' || (allowUnderscore && c == '_');
            if (!ok || (labelLength == 0 && c == '-') || ++labelLength > 63) { return false; }
        }

        return labelLength > 0 && name[^1] != '-' && (sawDot || !requireDot);
    }
}

/// <summary>Shared parsing of the fields all three ARC headers have in common.</summary>
internal static class ArcHeaderParsing
{
    public static bool TryInstance(ReadOnlySpan<byte> value, out int instance, out ArcFailure failure, out string error)
    {
        instance = 0;
        failure = ArcFailure.MalformedHeader;
        error = "invalid instance number (i=)";
        if (!ArcTagList.TryParseNumber(value, out long n) || n < 1) { return false; }
        if (n > ArcHeaderNames.MaxInstance)
        {
            failure = ArcFailure.TooManyInstances;
            error = "instance number above " + ArcHeaderNames.MaxInstance;
            return false;
        }

        instance = (int)n;
        failure = ArcFailure.None;
        error = string.Empty;
        return true;
    }

    public static bool TryTimestamp(ReadOnlySpan<byte> input, ReadOnlySpan<ArcTag> tags, out DateTimeOffset? time, out string? error)
    {
        time = null;
        error = null;
        if (!ArcTagList.TryFind(input, tags, "t"u8, out var t)) { return true; }
        if (!ArcTagList.TryParseNumber(ArcTagList.Value(input, t), out long seconds)) { error = "invalid timestamp (t=)"; return false; }
        if (seconds <= 253402300799L) { time = DateTimeOffset.FromUnixTimeSeconds(seconds); }
        return true;
    }

    public static bool TryRequiredText(ReadOnlySpan<byte> input, ReadOnlySpan<ArcTag> tags, ReadOnlySpan<byte> name, out string text, out string? error)
    {
        text = string.Empty;
        error = null;
        if (!ArcTagList.TryFind(input, tags, name, out var tag) || tag.ValueLength == 0)
        {
            error = "missing " + Encoding.ASCII.GetString(name) + "= tag";
            return false;
        }

        text = ArcTagList.CompactAscii(ArcTagList.Value(input, tag));
        return true;
    }

    public static bool TryDomainAndSelector(ReadOnlySpan<byte> input, ReadOnlySpan<ArcTag> tags, out string domain, out string selector, out string? error)
    {
        selector = string.Empty;
        if (!TryRequiredText(input, tags, "d"u8, out domain, out error)) { return false; }
        if (!TryRequiredText(input, tags, "s"u8, out selector, out error)) { return false; }
        domain = domain.TrimEnd('.').ToLowerInvariant();
        if (!ArcNames.IsValidDomain(domain)) { error = "invalid signing domain (d=)"; return false; }
        if (!ArcNames.IsValidSelector(selector)) { error = "invalid selector (s=)"; return false; }
        return true;
    }

    public static bool TrySignature(ReadOnlySpan<byte> input, ReadOnlySpan<ArcTag> tags, out ArcTag tag, out byte[] signature, out string? error)
    {
        signature = [];
        error = null;
        if (!ArcTagList.TryFind(input, tags, "b"u8, out tag)) { error = "missing b= tag"; return false; }
        if (!ArcTagList.TryDecodeBase64(ArcTagList.Value(input, tag), 1024, out signature)) { error = "invalid signature (b=)"; return false; }
        return true;
    }

    public static bool CheckLength(ReadOnlySpan<byte> field, int maxLength, out ArcFailure failure, out string? error)
    {
        failure = ArcFailure.None;
        error = null;
        if (field.Length > maxLength)
        {
            failure = ArcFailure.HeaderTooLong;
            error = "header too long";
            return false;
        }

        return true;
    }

    public static bool TryAsciiString(string? text, [NotNullWhen(true)] out byte[]? bytes)
    {
        bytes = null;
        if (text is null) { return false; }
        var result = new byte[text.Length];
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] > 0x7E) { return false; }
            result[i] = (byte)text[i];
        }

        bytes = result;
        return true;
    }
}

/// <summary>
/// A parsed ARC-Seal header field (RFC 8617 section 4.1.3): <c>i</c>, <c>a</c>, <c>cv</c>, <c>d</c>, <c>s</c>, <c>b</c> and optionally <c>t</c>.
/// <c>h=</c> is not allowed in a seal. Unknown tags are ignored.
/// </summary>
public sealed class ArcSealHeader
{
    private ArcSealHeader(int instance, string algorithm, ArcChainStatus chainValidationStatus, string domain, string selector, DateTimeOffset? timestamp, byte[] signature, int bStart, int bEnd)
    {
        Instance = instance;
        Algorithm = algorithm;
        ChainValidationStatus = chainValidationStatus;
        Domain = domain;
        Selector = selector;
        Timestamp = timestamp;
        Signature = signature;
        SignatureValueStart = bStart;
        SignatureValueEnd = bEnd;
    }

    /// <summary>The instance number (<c>i=</c>), 1 to 50.</summary>
    public int Instance { get; }

    /// <summary>The signature algorithm (<c>a=</c>), lower-cased as written.</summary>
    public string Algorithm { get; }

    /// <summary>The chain validation status the sealer recorded (<c>cv=</c>).</summary>
    public ArcChainStatus ChainValidationStatus { get; }

    /// <summary>The signing domain (<c>d=</c>), lower-cased.</summary>
    public string Domain { get; }

    /// <summary>The selector (<c>s=</c>).</summary>
    public string Selector { get; }

    /// <summary>The signing time (<c>t=</c>) when present.</summary>
    public DateTimeOffset? Timestamp { get; }

    /// <summary>The decoded signature (<c>b=</c>).</summary>
    public ReadOnlyMemory<byte> Signature { get; }

    /// <summary>Offsets of the <c>b=</c> value within the field text that was parsed.</summary>
    internal int SignatureValueStart { get; }

    internal int SignatureValueEnd { get; }

    /// <summary>Parses the field value (the text after <c>ARC-Seal:</c>, folding allowed). Never throws.</summary>
    /// <param name="fieldValue">The header field value as ASCII bytes.</param>
    /// <param name="header">The parsed header.</param>
    /// <param name="error">A short description of the problem.</param>
    /// <param name="maxLength">The longest accepted value in bytes.</param>
    public static bool TryParse(ReadOnlySpan<byte> fieldValue, [NotNullWhen(true)] out ArcSealHeader? header, out string? error, int maxLength = ArcHeaderNames.DefaultMaxHeaderLength) =>
        TryParseField(fieldValue, 0, maxLength, out header, out _, out error);

    /// <summary>Parses the field value given as text. Never throws.</summary>
    /// <param name="fieldValue">The header field value.</param>
    /// <param name="header">The parsed header.</param>
    /// <param name="error">A short description of the problem.</param>
    public static bool TryParse(string? fieldValue, [NotNullWhen(true)] out ArcSealHeader? header, out string? error)
    {
        if (!ArcHeaderParsing.TryAsciiString(fieldValue, out byte[]? bytes))
        {
            header = null;
            error = "header is not ASCII";
            return false;
        }

        return TryParse(bytes, out header, out error);
    }

    internal static bool TryParseField(ReadOnlySpan<byte> field, int valueOffset, int maxLength, [NotNullWhen(true)] out ArcSealHeader? header, out ArcFailure failure, out string? error)
    {
        header = null;
        if (!ArcHeaderParsing.CheckLength(field, maxLength, out failure, out error)) { return false; }
        failure = ArcFailure.MalformedHeader;
        Span<ArcTag> tags = stackalloc ArcTag[ArcTagList.MaxTags];
        if (!ArcTagList.TryParse(field, valueOffset, tags, out int count, out error)) { return false; }
        tags = tags.Slice(0, count);

        if (ArcTagList.TryFind(field, tags, "h"u8, out _)) { error = "h= is not allowed in an ARC-Seal"; return false; }
        if (!ArcTagList.TryFind(field, tags, "i"u8, out var i)) { error = "missing i= tag"; return false; }
        if (!ArcHeaderParsing.TryInstance(ArcTagList.Value(field, i), out int instance, out failure, out string instanceError)) { error = instanceError; return false; }
        failure = ArcFailure.MalformedHeader;

        if (!ArcHeaderParsing.TryRequiredText(field, tags, "a"u8, out string algorithm, out error)) { return false; }
        if (!ArcHeaderParsing.TryRequiredText(field, tags, "cv"u8, out string cvText, out error)) { return false; }
        ArcChainStatus cv;
        if (cvText.Equals("none", StringComparison.OrdinalIgnoreCase)) { cv = ArcChainStatus.None; }
        else if (cvText.Equals("pass", StringComparison.OrdinalIgnoreCase)) { cv = ArcChainStatus.Pass; }
        else if (cvText.Equals("fail", StringComparison.OrdinalIgnoreCase)) { cv = ArcChainStatus.Fail; }
        else { error = "invalid chain validation status (cv=)"; return false; }

        if (!ArcHeaderParsing.TryDomainAndSelector(field, tags, out string domain, out string selector, out error)) { return false; }
        if (!ArcHeaderParsing.TryTimestamp(field, tags, out var time, out error)) { return false; }
        if (!ArcHeaderParsing.TrySignature(field, tags, out var b, out byte[] signature, out error)) { return false; }

        header = new ArcSealHeader(instance, algorithm.ToLowerInvariant(), cv, domain, selector, time, signature, b.RawValueStart, b.RawValueEnd);
        failure = ArcFailure.None;
        error = null;
        return true;
    }
}

/// <summary>
/// A parsed ARC-Message-Signature header field (RFC 8617 section 4.1.2): a DKIM-Signature style signature over the message in which
/// <c>i=</c> is the instance number. Required: <c>i</c>, <c>a</c>, <c>b</c>, <c>bh</c>, <c>d</c>, <c>h</c>, <c>s</c>; optional <c>c</c> (default simple/simple)
/// and <c>t</c>. <c>l=</c> is rejected, and <c>h=</c> may not list ARC-Seal or ARC-Message-Signature. Unknown tags (including <c>x</c>, <c>z</c>) are ignored.
/// </summary>
public sealed class ArcMessageSignatureHeader
{
    /// <summary>The most header names an <c>h=</c> tag may list.</summary>
    public const int MaxSignedHeaderNames = 200;

    private ArcMessageSignatureHeader(int instance, string algorithm, string domain, string selector, DkimCanonicalization headerCanonicalization, DkimCanonicalization bodyCanonicalization, string[] signedHeaders, byte[] bodyHash, byte[] signature, DateTimeOffset? timestamp, int bStart, int bEnd)
    {
        Instance = instance;
        Algorithm = algorithm;
        Domain = domain;
        Selector = selector;
        HeaderCanonicalization = headerCanonicalization;
        BodyCanonicalization = bodyCanonicalization;
        SignedHeaderNames = signedHeaders;
        BodyHash = bodyHash;
        Signature = signature;
        Timestamp = timestamp;
        SignatureValueStart = bStart;
        SignatureValueEnd = bEnd;
    }

    /// <summary>The instance number (<c>i=</c>), 1 to 50.</summary>
    public int Instance { get; }

    /// <summary>The signature algorithm (<c>a=</c>), lower-cased as written.</summary>
    public string Algorithm { get; }

    /// <summary>The signing domain (<c>d=</c>), lower-cased.</summary>
    public string Domain { get; }

    /// <summary>The selector (<c>s=</c>).</summary>
    public string Selector { get; }

    /// <summary>Header canonicalization (<c>c=</c>, first half).</summary>
    public DkimCanonicalization HeaderCanonicalization { get; }

    /// <summary>Body canonicalization (<c>c=</c>, second half).</summary>
    public DkimCanonicalization BodyCanonicalization { get; }

    /// <summary>The signed header names (<c>h=</c>), lower-cased, in signing order (a repeated name selects successive instances from the bottom up).</summary>
    public IReadOnlyList<string> SignedHeaderNames { get; }

    /// <summary>The decoded body hash (<c>bh=</c>).</summary>
    public ReadOnlyMemory<byte> BodyHash { get; }

    /// <summary>The decoded signature (<c>b=</c>).</summary>
    public ReadOnlyMemory<byte> Signature { get; }

    /// <summary>The signing time (<c>t=</c>) when present.</summary>
    public DateTimeOffset? Timestamp { get; }

    internal int SignatureValueStart { get; }

    internal int SignatureValueEnd { get; }

    /// <summary>Parses the field value (the text after <c>ARC-Message-Signature:</c>, folding allowed). Never throws.</summary>
    /// <param name="fieldValue">The header field value as ASCII bytes.</param>
    /// <param name="header">The parsed header.</param>
    /// <param name="error">A short description of the problem.</param>
    /// <param name="maxLength">The longest accepted value in bytes.</param>
    public static bool TryParse(ReadOnlySpan<byte> fieldValue, [NotNullWhen(true)] out ArcMessageSignatureHeader? header, out string? error, int maxLength = ArcHeaderNames.DefaultMaxHeaderLength) =>
        TryParseField(fieldValue, 0, maxLength, out header, out _, out error);

    /// <summary>Parses the field value given as text. Never throws.</summary>
    /// <param name="fieldValue">The header field value.</param>
    /// <param name="header">The parsed header.</param>
    /// <param name="error">A short description of the problem.</param>
    public static bool TryParse(string? fieldValue, [NotNullWhen(true)] out ArcMessageSignatureHeader? header, out string? error)
    {
        if (!ArcHeaderParsing.TryAsciiString(fieldValue, out byte[]? bytes))
        {
            header = null;
            error = "header is not ASCII";
            return false;
        }

        return TryParse(bytes, out header, out error);
    }

    internal static bool TryParseField(ReadOnlySpan<byte> field, int valueOffset, int maxLength, [NotNullWhen(true)] out ArcMessageSignatureHeader? header, out ArcFailure failure, out string? error)
    {
        header = null;
        if (!ArcHeaderParsing.CheckLength(field, maxLength, out failure, out error)) { return false; }
        failure = ArcFailure.MalformedHeader;
        Span<ArcTag> tags = stackalloc ArcTag[ArcTagList.MaxTags];
        if (!ArcTagList.TryParse(field, valueOffset, tags, out int count, out error)) { return false; }
        tags = tags.Slice(0, count);

        if (ArcTagList.TryFind(field, tags, "l"u8, out _)) { error = "l= is not supported in an ARC-Message-Signature"; return false; }
        if (!ArcTagList.TryFind(field, tags, "i"u8, out var i)) { error = "missing i= tag"; return false; }
        if (!ArcHeaderParsing.TryInstance(ArcTagList.Value(field, i), out int instance, out failure, out string instanceError)) { error = instanceError; return false; }
        failure = ArcFailure.MalformedHeader;

        if (!ArcHeaderParsing.TryRequiredText(field, tags, "a"u8, out string algorithm, out error)) { return false; }
        if (!ArcHeaderParsing.TryDomainAndSelector(field, tags, out string domain, out string selector, out error)) { return false; }
        if (!ArcHeaderParsing.TryTimestamp(field, tags, out var time, out error)) { return false; }
        if (!ArcHeaderParsing.TrySignature(field, tags, out var b, out byte[] signature, out error)) { return false; }

        if (!ArcTagList.TryFind(field, tags, "bh"u8, out var bh)) { error = "missing bh= tag"; return false; }
        if (!ArcTagList.TryDecodeBase64(ArcTagList.Value(field, bh), 64, out byte[] bodyHash)) { error = "invalid body hash (bh=)"; return false; }

        var headerCanon = DkimCanonicalization.Simple;
        var bodyCanon = DkimCanonicalization.Simple;
        if (ArcTagList.TryFind(field, tags, "c"u8, out var c))
        {
            string text = ArcTagList.CompactAscii(ArcTagList.Value(field, c));
            int slash = text.IndexOf('/');
            string head = slash < 0 ? text : text.Substring(0, slash);
            string? body = slash < 0 ? null : text.Substring(slash + 1);
            if (!TryCanonicalization(head, out headerCanon) || (body is not null && !TryCanonicalization(body, out bodyCanon)))
            {
                error = "invalid canonicalization (c=)";
                return false;
            }
        }

        if (!ArcTagList.TryFind(field, tags, "h"u8, out var h)) { error = "missing h= tag"; return false; }
        if (!TrySignedHeaders(ArcTagList.Value(field, h), out string[] names, out error)) { return false; }

        header = new ArcMessageSignatureHeader(instance, algorithm.ToLowerInvariant(), domain, selector, headerCanon, bodyCanon, names, bodyHash, signature, time, b.RawValueStart, b.RawValueEnd);
        failure = ArcFailure.None;
        error = null;
        return true;
    }

    private static bool TryCanonicalization(string text, out DkimCanonicalization value)
    {
        value = DkimCanonicalization.Simple;
        if (text.Equals("simple", StringComparison.OrdinalIgnoreCase)) { return true; }
        if (text.Equals("relaxed", StringComparison.OrdinalIgnoreCase)) { value = DkimCanonicalization.Relaxed; return true; }
        return false;
    }

    private static bool TrySignedHeaders(ReadOnlySpan<byte> value, out string[] names, out string? error)
    {
        names = [];
        error = null;
        var list = new List<string>(16);
        while (true)
        {
            int colon = value.IndexOf((byte)':');
            var part = colon < 0 ? value : value.Slice(0, colon);
            string name = ArcTagList.CompactAscii(part).ToLowerInvariant();
            if (name.Length == 0) { error = "empty header name in h="; return false; }
            foreach (char ch in name)
            {
                if (ch <= 0x20 || ch >= 0x7F) { error = "invalid header name in h="; return false; }
            }

            if (name is "arc-seal" or "arc-message-signature") { error = "h= must not list ARC-Seal or ARC-Message-Signature"; return false; }
            if (list.Count >= MaxSignedHeaderNames) { error = "too many header names in h="; return false; }
            list.Add(name);
            if (colon < 0) { break; }
            value = value.Slice(colon + 1);
        }

        names = list.ToArray();
        return true;
    }
}

/// <summary>
/// A parsed ARC-Authentication-Results header field (RFC 8617 section 4.1.1): <c>i=N;</c> followed by an Authentication-Results body
/// (<c>authserv-id; method=result ...</c>).
/// </summary>
public sealed class ArcAuthenticationResultsHeader
{
    private ArcAuthenticationResultsHeader(int instance, string body, AuthenticationResultsHeader? results)
    {
        Instance = instance;
        Body = body;
        Results = results;
    }

    /// <summary>The instance number (<c>i=</c>), 1 to 50.</summary>
    public int Instance { get; }

    /// <summary>The text after <c>i=N;</c>, unfolded and trimmed.</summary>
    public string Body { get; }

    /// <summary>The body parsed as an RFC 8601 Authentication-Results value, or null when it does not parse. A body that does not parse is not an ARC error.</summary>
    public AuthenticationResultsHeader? Results { get; }

    /// <summary>The authserv-id of the hop that recorded these results, or null when the body does not parse.</summary>
    public string? AuthservId => Results?.AuthservId;

    /// <summary>Parses the field value (the text after <c>ARC-Authentication-Results:</c>, folding allowed). Never throws.</summary>
    /// <param name="fieldValue">The header field value as bytes (ASCII, or UTF-8 when the sender uses SMTPUTF8).</param>
    /// <param name="header">The parsed header.</param>
    /// <param name="error">A short description of the problem.</param>
    /// <param name="maxLength">The longest accepted value in bytes.</param>
    public static bool TryParse(ReadOnlySpan<byte> fieldValue, [NotNullWhen(true)] out ArcAuthenticationResultsHeader? header, out string? error, int maxLength = ArcHeaderNames.DefaultMaxHeaderLength) =>
        TryParseField(fieldValue, 0, maxLength, out header, out _, out error);

    /// <summary>Parses the field value given as text. Never throws.</summary>
    /// <param name="fieldValue">The header field value.</param>
    /// <param name="header">The parsed header.</param>
    /// <param name="error">A short description of the problem.</param>
    public static bool TryParse(string? fieldValue, [NotNullWhen(true)] out ArcAuthenticationResultsHeader? header, out string? error)
    {
        if (fieldValue is null)
        {
            header = null;
            error = "no value";
            return false;
        }

        return TryParse(Encoding.UTF8.GetBytes(fieldValue), out header, out error);
    }

    internal static bool TryParseField(ReadOnlySpan<byte> field, int valueOffset, int maxLength, [NotNullWhen(true)] out ArcAuthenticationResultsHeader? header, out ArcFailure failure, out string? error)
    {
        header = null;
        if (!ArcHeaderParsing.CheckLength(field, maxLength, out failure, out error)) { return false; }
        failure = ArcFailure.MalformedHeader;
        error = "malformed ARC-Authentication-Results";

        int pos = ArcTagList.SkipWhitespace(field, valueOffset);
        if (pos >= field.Length || field[pos] != (byte)'i') { error = "missing i= tag"; return false; }
        pos = ArcTagList.SkipWhitespace(field, pos + 1);
        if (pos >= field.Length || field[pos] != (byte)'=') { error = "missing i= tag"; return false; }
        pos = ArcTagList.SkipWhitespace(field, pos + 1);
        int digitsStart = pos;
        while (pos < field.Length && field[pos] is >= (byte)'0' and <= (byte)'9') { pos++; }
        if (!ArcHeaderParsing.TryInstance(field.Slice(digitsStart, pos - digitsStart), out int instance, out failure, out string instanceError)) { error = instanceError; return false; }
        failure = ArcFailure.MalformedHeader;
        pos = ArcTagList.SkipWhitespace(field, pos);
        if (pos >= field.Length || field[pos] != (byte)';') { error = "i= must be followed by ';'"; return false; }
        pos++;

        var rest = field.Slice(pos);
        foreach (byte b in rest)
        {
            if ((b < 0x20 && b is not ((byte)'\t' or (byte)'\r' or (byte)'\n')) || b == 0x7F) { error = "control character in header"; return false; }
        }

        string text;
        try
        {
            text = new UTF8Encoding(false, true).GetString(rest);
        }
        catch (ArgumentException)
        {
            error = "invalid UTF-8 in header";
            return false;
        }

        string body = Unfold(text);
        if (body.Length == 0) { error = "empty ARC-Authentication-Results body"; return false; }

        AuthenticationResultsHeader.TryParse(body, out var results);
        header = new ArcAuthenticationResultsHeader(instance, body, results);
        failure = ArcFailure.None;
        error = null;
        return true;
    }

    private static string Unfold(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (char c in text)
        {
            if (c is '\r' or '\n') { continue; }
            sb.Append(c);
        }

        return sb.ToString().Trim(' ', '\t');
    }
}
