namespace Mta.Mime;

/// <summary>
/// Deviations from the RFCs and limit hits noticed while parsing. Parsers are tolerant and report instead of failing;
/// callers (the SMTP server policy, the validator) decide what to do with them.
/// </summary>
[Flags]
public enum MimeAnomaly : ulong
{
    None = 0,

    /// <summary>A line ended with a bare LF (not CRLF).</summary>
    BareLf = 1UL << 0,

    /// <summary>A bare CR (not followed by LF) occurs inside a header line. It is never treated as a line break.</summary>
    BareCr = 1UL << 1,

    /// <summary>A NUL byte occurs in the headers.</summary>
    NulInHeaders = 1UL << 2,

    /// <summary>A header line has no colon or an invalid field name (kept as a malformed header).</summary>
    MissingColon = 1UL << 3,

    /// <summary>Header bytes outside US-ASCII (8-bit or RFC 6532 UTF-8 headers).</summary>
    NonAsciiHeaders = 1UL << 4,

    /// <summary>A header line is longer than <see cref="MimeLimits.MaxLineLength"/>.</summary>
    HeaderLineTooLong = 1UL << 5,

    /// <summary>More header fields than <see cref="MimeLimits.MaxHeaderCount"/>; the rest are not recorded.</summary>
    TooManyHeaders = 1UL << 6,

    /// <summary>The header block is larger than <see cref="MimeLimits.MaxHeaderBytes"/>; the rest is not recorded.</summary>
    HeaderBlockTooLarge = 1UL << 7,

    /// <summary>No empty line separates headers from body (the data ended inside the header block).</summary>
    NoHeaderBodySeparator = 1UL << 8,

    /// <summary>Whitespace between a field name and its colon (obsolete syntax).</summary>
    SpaceBeforeColon = 1UL << 9,

    /// <summary>A header value was longer than <see cref="MimeLimits.MaxHeaderValueBytes"/> and was truncated.</summary>
    HeaderValueTooLong = 1UL << 10,

    /// <summary>A multipart entity has no usable boundary parameter; it is kept as an opaque leaf.</summary>
    MissingBoundary = 1UL << 11,

    /// <summary>A multipart entity has no closing delimiter.</summary>
    MissingCloseDelimiter = 1UL << 12,

    /// <summary>Nesting is deeper than <see cref="MimeLimits.MaxDepth"/>; the entity is kept as an opaque leaf.</summary>
    MaxDepthExceeded = 1UL << 13,

    /// <summary>More parts than <see cref="MimeLimits.MaxParts"/>; the rest are dropped.</summary>
    TooManyParts = 1UL << 14,

    /// <summary>An unknown Content-Transfer-Encoding value (treated as identity).</summary>
    UnknownTransferEncoding = 1UL << 15,

    /// <summary>Invalid base64 data (skipped characters, bad padding or truncated final quantum).</summary>
    MalformedBase64 = 1UL << 16,

    /// <summary>Invalid quoted-printable data (stray or malformed escapes).</summary>
    MalformedQuotedPrintable = 1UL << 17,

    /// <summary>Decoded output hit <see cref="MimeLimits.MaxDecodedBytes"/> (or a caller-provided maximum) and was truncated.</summary>
    DecodedSizeLimit = 1UL << 18,

    /// <summary>An unknown or refused charset name; a UTF-8 / Latin-1 fallback was used.</summary>
    UnknownCharset = 1UL << 19,

    /// <summary>An unparsable Content-Type (treated as application/octet-stream).</summary>
    InvalidContentType = 1UL << 20,

    /// <summary>A body line is longer than <see cref="MimeLimits.MaxLineLength"/>.</summary>
    BodyLineTooLong = 1UL << 21,

    /// <summary>A NUL byte occurs in the body.</summary>
    NulInBody = 1UL << 22,

    /// <summary>A nested multipart reuses the boundary of one of its ancestors; it is kept as an opaque leaf.</summary>
    DuplicateBoundary = 1UL << 23,

    /// <summary>More than <see cref="MimeLimits.MaxParameters"/> parameters; the rest are dropped.</summary>
    TooManyParameters = 1UL << 24,

    /// <summary>More than <see cref="MimeLimits.MaxAddresses"/> addresses; the rest are dropped.</summary>
    TooManyAddresses = 1UL << 25,

    /// <summary>A malformed RFC 2047 encoded word (kept literally).</summary>
    InvalidEncodedWord = 1UL << 26,

    /// <summary>An address header could not be parsed completely.</summary>
    InvalidAddress = 1UL << 27,

    /// <summary>An unparsable date.</summary>
    InvalidDate = 1UL << 28,

    /// <summary>A malformed RFC 2231 parameter continuation.</summary>
    InvalidParameterContinuation = 1UL << 29,

    /// <summary>Body bytes outside US-ASCII.</summary>
    NonAsciiBody = 1UL << 30,

    /// <summary>A bare LF in the body.</summary>
    BareLfInBody = 1UL << 31,

    /// <summary>A bare CR in the body.</summary>
    BareCrInBody = 1UL << 32,
}

/// <summary>Helpers for <see cref="MimeAnomaly"/>.</summary>
public static class MimeAnomalyExtensions
{
    /// <summary>True when <paramref name="value"/> contains any of the <paramref name="flags"/>.</summary>
    public static bool HasAny(this MimeAnomaly value, MimeAnomaly flags) => (value & flags) != 0;
}
