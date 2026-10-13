using System.Buffers;
using System.Text;
using System.Text.Unicode;

namespace Mta.Mime;

/// <summary>Header field names that this library recognizes without allocating a string.</summary>
public enum HeaderId
{
    Unknown = 0,
    From,
    Sender,
    ReplyTo,
    To,
    Cc,
    Bcc,
    Subject,
    Date,
    MessageId,
    InReplyTo,
    References,
    Received,
    ReturnPath,
    MimeVersion,
    ContentType,
    ContentTransferEncoding,
    ContentDisposition,
    ContentId,
    ContentDescription,
    DkimSignature,
    AuthenticationResults,
    ResentDate,
    ResentFrom,
    ResentSender,
    ResentTo,
    ResentCc,
    ResentBcc,
    ResentMessageId,
}

/// <summary>Canonical spellings of common header field names.</summary>
public static class HeaderNames
{
    public const string From = "From";
    public const string Sender = "Sender";
    public const string ReplyTo = "Reply-To";
    public const string To = "To";
    public const string Cc = "Cc";
    public const string Bcc = "Bcc";
    public const string Subject = "Subject";
    public const string Date = "Date";
    public const string MessageId = "Message-ID";
    public const string InReplyTo = "In-Reply-To";
    public const string References = "References";
    public const string Received = "Received";
    public const string ReturnPath = "Return-Path";
    public const string MimeVersion = "MIME-Version";
    public const string ContentType = "Content-Type";
    public const string ContentTransferEncoding = "Content-Transfer-Encoding";
    public const string ContentDisposition = "Content-Disposition";
    public const string ContentId = "Content-ID";
    public const string ContentDescription = "Content-Description";
    public const string DkimSignature = "DKIM-Signature";
    public const string AuthenticationResults = "Authentication-Results";

    /// <summary>Maps a field name to its <see cref="HeaderId"/> (case-insensitive, ASCII).</summary>
    public static HeaderId Identify(ReadOnlySpan<byte> name)
    {
        switch (name.Length)
        {
            case 2: return Is(name, "to"u8) ? HeaderId.To : Is(name, "cc"u8) ? HeaderId.Cc : HeaderId.Unknown;
            case 3: return Is(name, "bcc"u8) ? HeaderId.Bcc : HeaderId.Unknown;
            case 4: return Is(name, "from"u8) ? HeaderId.From : Is(name, "date"u8) ? HeaderId.Date : HeaderId.Unknown;
            case 6: return Is(name, "sender"u8) ? HeaderId.Sender : HeaderId.Unknown;
            case 7: return Is(name, "subject"u8) ? HeaderId.Subject : HeaderId.Unknown;
            case 8:
                return Is(name, "reply-to"u8) ? HeaderId.ReplyTo
                    : Is(name, "received"u8) ? HeaderId.Received : HeaderId.Unknown;
            case 9:
                return Is(name, "resent-to"u8) ? HeaderId.ResentTo
                    : Is(name, "resent-cc"u8) ? HeaderId.ResentCc : HeaderId.Unknown;
            case 10:
                return Is(name, "message-id"u8) ? HeaderId.MessageId
                    : Is(name, "references"u8) ? HeaderId.References
                    : Is(name, "content-id"u8) ? HeaderId.ContentId
                    : Is(name, "resent-bcc"u8) ? HeaderId.ResentBcc : HeaderId.Unknown;
            case 11:
                return Is(name, "in-reply-to"u8) ? HeaderId.InReplyTo
                    : Is(name, "return-path"u8) ? HeaderId.ReturnPath
                    : Is(name, "resent-from"u8) ? HeaderId.ResentFrom
                    : Is(name, "resent-date"u8) ? HeaderId.ResentDate : HeaderId.Unknown;
            case 12:
                return Is(name, "mime-version"u8) ? HeaderId.MimeVersion
                    : Is(name, "content-type"u8) ? HeaderId.ContentType : HeaderId.Unknown;
            case 13:
                return Is(name, "resent-sender"u8) ? HeaderId.ResentSender : HeaderId.Unknown;
            case 14:
                return Is(name, "dkim-signature"u8) ? HeaderId.DkimSignature : HeaderId.Unknown;
            case 17:
                return Is(name, "resent-message-id"u8) ? HeaderId.ResentMessageId : HeaderId.Unknown;
            case 19:
                return Is(name, "content-disposition"u8) ? HeaderId.ContentDisposition
                    : Is(name, "content-description"u8) ? HeaderId.ContentDescription : HeaderId.Unknown;
            case 22:
                return Is(name, "authentication-results"u8) ? HeaderId.AuthenticationResults : HeaderId.Unknown;
            case 25:
                return Is(name, "content-transfer-encoding"u8) ? HeaderId.ContentTransferEncoding : HeaderId.Unknown;
            default:
                return HeaderId.Unknown;
        }
    }

    /// <summary>Maps a field name to its <see cref="HeaderId"/>.</summary>
    public static HeaderId Identify(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (name.Length > 32 || !Ascii.IsValid(name))
        {
            return HeaderId.Unknown;
        }

        Span<byte> buffer = stackalloc byte[32];
        int n = Encoding.ASCII.GetBytes(name, buffer);
        return Identify(buffer[..n]);
    }

    private static bool Is(ReadOnlySpan<byte> name, ReadOnlySpan<byte> lower) => Ascii.EqualsIgnoreCase(name, lower);
}

/// <summary>
/// One header field of a message, backed by the original bytes. Nothing is copied: <see cref="Raw"/> is a slice of the
/// message buffer, which is exactly what DKIM canonicalization needs.
/// </summary>
public readonly struct MimeHeader
{
    private readonly ReadOnlyMemory<byte> _raw;
    private readonly int _offset;
    private readonly int _nameLength;
    private readonly int _valueStart;
    private readonly byte _eolLength;
    private readonly HeaderId _id;

    internal MimeHeader(ReadOnlyMemory<byte> raw, int offset, int nameLength, int valueStart, int eolLength, HeaderId id)
    {
        _raw = raw;
        _offset = offset;
        _nameLength = nameLength;
        _valueStart = valueStart;
        _eolLength = (byte)eolLength;
        _id = id;
    }

    /// <summary>Offset of the first byte of the field within the buffer that was parsed.</summary>
    public int Offset => _offset;

    /// <summary>The whole field exactly as received: name, colon, value and any folding line breaks, without the final line ending.</summary>
    public ReadOnlyMemory<byte> Raw => _raw;

    /// <summary>Length of the field including its final line ending (0 to 2 bytes; 0 only at the end of unterminated data).</summary>
    public int LengthWithLineEnding => _raw.Length + _eolLength;

    /// <summary>True when the line has no colon or an invalid field name. <see cref="Raw"/> still holds the bytes.</summary>
    public bool IsMalformed => _valueStart < 0;

    /// <summary>The recognized well-known name, or <see cref="HeaderId.Unknown"/>.</summary>
    public HeaderId Id => _id;

    /// <summary>The field name bytes as written (without the colon and without whitespace before it). Empty for malformed lines.</summary>
    public ReadOnlySpan<byte> NameBytes => _raw.Span[.._nameLength];

    /// <summary>The field name as written (allocates; prefer <see cref="Id"/> or <see cref="NameEquals(string)"/>).</summary>
    public string Name => Encoding.Latin1.GetString(NameBytes);

    /// <summary>The raw value: everything after the colon, including leading whitespace and fold line breaks.</summary>
    public ReadOnlyMemory<byte> RawValue => _valueStart < 0 ? _raw : _raw[_valueStart..];

    /// <summary>Case-insensitive field-name comparison without allocating.</summary>
    public bool NameEquals(ReadOnlySpan<byte> name) => Ascii.EqualsIgnoreCase(NameBytes, name);

    /// <summary>Case-insensitive field-name comparison without allocating.</summary>
    public bool NameEquals(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return Ascii.EqualsIgnoreCase(NameBytes, name);
    }

    /// <summary>
    /// The value with fold line breaks removed (RFC 5322 section 2.2.3) as bytes, otherwise unchanged: leading and
    /// trailing whitespace are kept, which is what DKIM "simple" and "relaxed" canonicalization start from.
    /// </summary>
    public byte[] GetUnfoldedValueBytes()
    {
        var raw = RawValue.Span;
        var result = new byte[Unfold(raw, default, countOnly: true)];
        Unfold(raw, result, countOnly: false);
        return result;
    }

    /// <summary>Length in bytes of <see cref="GetUnfoldedValueBytes"/>.</summary>
    public int GetUnfoldedValueLength() => Unfold(RawValue.Span, default, countOnly: true);

    /// <summary>Copies the unfolded value into <paramref name="destination"/>; returns the length written. Throws if too small.</summary>
    public int CopyUnfoldedValueTo(Span<byte> destination) => Unfold(RawValue.Span, destination, countOnly: false);

    /// <summary>The unfolded value, trimmed, as text (UTF-8 when valid per RFC 6532, else windows-1252). Truncated at <paramref name="maxBytes"/> bytes.</summary>
    public string GetValue(int maxBytes = 64 * 1024) => HeaderText.GetValue(RawValue.Span, maxBytes);

    /// <summary>The unfolded value, trimmed.</summary>
    public string Value => GetValue();

    /// <summary>The value with RFC 2047 encoded words decoded (for unstructured fields such as Subject).</summary>
    public string GetDecodedValue(int maxBytes = 64 * 1024)
    {
        var an = MimeAnomaly.None;
        return Rfc2047.DecodeCore(GetValue(maxBytes), ref an);
    }

    /// <summary>The value with RFC 2047 encoded words decoded.</summary>
    public string DecodedValue => GetDecodedValue();

    /// <inheritdoc />
    public override string ToString() => HeaderText.DecodeBytes(_raw.Span);

    private static int Unfold(ReadOnlySpan<byte> raw, Span<byte> destination, bool countOnly)
    {
        int n = 0;
        int i = 0;
        while (i < raw.Length)
        {
            int nl = raw[i..].IndexOf((byte)'\n');
            int chunkEnd = nl < 0 ? raw.Length : i + nl;
            int copyEnd = chunkEnd;
            if (nl >= 0 && copyEnd > i && raw[copyEnd - 1] == (byte)'\r')
            {
                copyEnd--;
            }

            int count = copyEnd - i;
            if (!countOnly)
            {
                raw.Slice(i, count).CopyTo(destination[n..]);
            }

            n += count;
            i = nl < 0 ? raw.Length : chunkEnd + 1;
        }

        return n;
    }
}

/// <summary>Conversion of header bytes to text.</summary>
internal static class HeaderText
{
    /// <summary>Strict UTF-8 when valid (RFC 6532), otherwise windows-1252.</summary>
    public static string DecodeBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            return string.Empty;
        }

        if (Ascii.IsValid(bytes))
        {
            return Encoding.ASCII.GetString(bytes);
        }

        return Utf8.IsValid(bytes) ? Encoding.UTF8.GetString(bytes) : MimeCharsets.FallbackEncoding.GetString(bytes);
    }

    /// <summary>Unfolds, trims and decodes a raw header value.</summary>
    public static string GetValue(ReadOnlySpan<byte> rawValue, int maxBytes)
    {
        if (rawValue.Length > maxBytes)
        {
            rawValue = rawValue[..maxBytes];
        }

        if (rawValue.IndexOf((byte)'\n') < 0)
        {
            return DecodeBytes(TrimWsp(rawValue));
        }

        byte[]? rented = null;
        Span<byte> buffer = rawValue.Length <= 512 ? stackalloc byte[512] : (rented = ArrayPool<byte>.Shared.Rent(rawValue.Length));
        try
        {
            int n = 0;
            int i = 0;
            while (i < rawValue.Length)
            {
                int nl = rawValue[i..].IndexOf((byte)'\n');
                int end = nl < 0 ? rawValue.Length : i + nl;
                int copyEnd = end;
                if (nl >= 0 && copyEnd > i && rawValue[copyEnd - 1] == (byte)'\r')
                {
                    copyEnd--;
                }

                rawValue[i..copyEnd].CopyTo(buffer[n..]);
                n += copyEnd - i;
                i = nl < 0 ? rawValue.Length : end + 1;
            }

            return DecodeBytes(TrimWsp(buffer[..n]));
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    /// <summary>
    /// The same text as <see cref="GetValue"/> for a pure-ASCII value, written into <paramref name="destination"/> instead of a new string
    /// (fold line breaks removed, white space trimmed). Returns false, writing nothing useful, when the value has a non-ASCII byte or is longer
    /// than the destination; the caller then falls back to <see cref="GetValue"/>.
    /// </summary>
    public static bool TryGetAsciiValue(ReadOnlySpan<byte> rawValue, Span<char> destination, out int length)
    {
        length = 0;
        if (rawValue.Length > destination.Length || !System.Text.Ascii.IsValid(rawValue))
        {
            return false;
        }

        int n = 0;
        for (int i = 0; i < rawValue.Length; i++)
        {
            byte b = rawValue[i];
            if (b == (byte)'\n' || (b == (byte)'\r' && i + 1 < rawValue.Length && rawValue[i + 1] == (byte)'\n'))
            {
                continue;
            }

            destination[n++] = (char)b;
        }

        int start = 0;
        int end = n;
        while (start < end && destination[start] is ' ' or '\t')
        {
            start++;
        }

        while (end > start && destination[end - 1] is ' ' or '\t')
        {
            end--;
        }

        if (start > 0)
        {
            destination[start..end].CopyTo(destination);
        }

        length = end - start;
        return true;
    }

    public static ReadOnlySpan<byte> TrimWsp(ReadOnlySpan<byte> s)
    {
        int start = 0;
        int end = s.Length;
        while (start < end && s[start] is (byte)' ' or (byte)'\t')
        {
            start++;
        }

        while (end > start && s[end - 1] is (byte)' ' or (byte)'\t')
        {
            end--;
        }

        return s[start..end];
    }
}
