using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Unicode;

namespace Mta.Mime;

/// <summary>
/// Charset name resolution and decoding of 8-bit text. Resolves RFC 2045/2047 charset names through
/// <see cref="Encoding.GetEncoding(string)"/> after registering the code-pages provider, refuses dangerous or absurd
/// names (UTF-7, over-long names, names with unusual characters) and provides the safe fallback used for unknown charsets.
/// </summary>
public static class MimeCharsets
{
    private const int MaxCharsetNameLength = 64;
    private const int MaxCacheEntries = 512;

    // Keys are the lower-case names; the comparer ignores case so that a name as written in a message is found without building its lower-case form first.
    private static readonly ConcurrentDictionary<string, Encoding?> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, Encoding?>.AlternateLookup<ReadOnlySpan<char>> CacheLookup = Cache.GetAlternateLookup<ReadOnlySpan<char>>();
    private static readonly Encoding? Windows1252;

    static MimeCharsets()
    {
        RegisterCodePages();
        try
        {
            Windows1252 = Encoding.GetEncoding(1252);
        }
        catch (ArgumentException)
        {
            Windows1252 = null;
        }
        catch (NotSupportedException)
        {
            Windows1252 = null;
        }
    }

    /// <summary>
    /// Registers <see cref="CodePagesEncodingProvider"/> so legacy code pages (windows-1252, iso-8859-x, gb2312, shift_jis ...)
    /// resolve. Idempotent and thread-safe; also invoked automatically the first time this library resolves a charset.
    /// </summary>
    public static void RegisterCodePages() => Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

    /// <summary>The fallback for 8-bit text of unknown charset: windows-1252 (a superset of ISO-8859-1), or Latin-1 if unavailable.</summary>
    public static Encoding FallbackEncoding => Windows1252 ?? Encoding.Latin1;

    /// <summary>
    /// Resolves a charset name (an optional RFC 2231 <c>*language</c> suffix is ignored). Returns false for unknown,
    /// refused (UTF-7) or malformed names. Never throws.
    /// </summary>
    public static bool TryGetEncoding(ReadOnlySpan<char> charset, [NotNullWhen(true)] out Encoding? encoding)
    {
        encoding = null;
        int star = charset.IndexOf('*');
        if (star >= 0)
        {
            charset = charset[..star];
        }

        charset = charset.Trim();
        if (charset.Length == 0 || charset.Length > MaxCharsetNameLength)
        {
            return false;
        }

        foreach (char c in charset)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or ':' or '+'))
            {
                return false;
            }
        }

        if (IsRefused(charset))
        {
            return false;
        }

        if (CacheLookup.TryGetValue(charset, out var cached))
        {
            encoding = cached;
            return cached is not null;
        }

        string key = string.Create(charset.Length, charset, static (dst, src) => src.ToLowerInvariant(dst));

        Encoding? resolved;
        try
        {
            resolved = Encoding.GetEncoding(key);
        }
        catch (ArgumentException)
        {
            resolved = null;
        }
        catch (NotSupportedException)
        {
            resolved = null;
        }

        if (resolved is not null && resolved.CodePage == 65000)
        {
            resolved = null;
        }

        if (Cache.Count < MaxCacheEntries)
        {
            Cache.TryAdd(key, resolved);
        }

        encoding = resolved;
        return resolved is not null;
    }

    /// <summary>Resolves a charset name, or returns null (see <see cref="TryGetEncoding"/>).</summary>
    public static Encoding? GetEncodingOrNull(string? charset) =>
        charset is not null && TryGetEncoding(charset, out var e) ? e : null;

    private static bool IsRefused(ReadOnlySpan<char> name) =>
        name.Equals("utf-7", StringComparison.OrdinalIgnoreCase) || name.Equals("utf7", StringComparison.OrdinalIgnoreCase)
        || name.Equals("unicode-1-1-utf-7", StringComparison.OrdinalIgnoreCase) || name.Equals("unicode-2-0-utf-7", StringComparison.OrdinalIgnoreCase)
        || name.Equals("x-unicode-1-1-utf-7", StringComparison.OrdinalIgnoreCase) || name.Equals("x-unicode-2-0-utf-7", StringComparison.OrdinalIgnoreCase)
        || name.Equals("csunicode11utf7", StringComparison.OrdinalIgnoreCase) || name.Equals("cp65000", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Decodes bytes of the given charset to a string. Malformed sequences become U+FFFD. When <paramref name="charset"/>
    /// is missing, unknown, refused or <c>us-ascii</c> and the data is not plain ASCII, the data is decoded as UTF-8 when valid
    /// and as windows-1252 otherwise (the behaviour of mail clients for unlabeled 8-bit text).
    /// </summary>
    public static string Decode(ReadOnlySpan<byte> bytes, string? charset, ref MimeAnomaly anomalies)
    {
        if (bytes.IsEmpty)
        {
            return string.Empty;
        }

        Encoding? encoding = null;
        bool known = charset is not null && TryGetEncoding(charset, out encoding);
        if (charset is not null && !known)
        {
            anomalies |= MimeAnomaly.UnknownCharset;
        }

        if (known && encoding!.CodePage != 20127)
        {
            return encoding.GetString(bytes);
        }

        return DecodeUnlabeled(bytes);
    }

    /// <summary>Decodes data without (usable) charset: ASCII, else UTF-8 when valid, else windows-1252.</summary>
    public static string DecodeUnlabeled(ReadOnlySpan<byte> bytes)
    {
        if (System.Text.Ascii.IsValid(bytes))
        {
            return Encoding.ASCII.GetString(bytes);
        }

        return Utf8.IsValid(bytes) ? Encoding.UTF8.GetString(bytes) : FallbackEncoding.GetString(bytes);
    }
}
