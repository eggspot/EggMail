using System.Buffers;
using System.Buffers.Text;
using System.Text;
using System.Text.Unicode;

namespace Mta.Mime;

/// <summary>Result of one pass over a raw message; see <see cref="MessageInspector.Inspect"/>.</summary>
/// <param name="HasBareLf">A line ends with LF not preceded by CR (header or body).</param>
/// <param name="HasBareCr">A CR that is not part of a CRLF pair (header or body).</param>
/// <param name="HasNul">A NUL byte anywhere.</param>
/// <param name="HasNonAsciiHeaders">Bytes above 0x7F in the header block (RFC 6532 headers need SMTPUTF8).</param>
/// <param name="HasNonAsciiBody">Bytes above 0x7F in the body (8BITMIME needed unless transfer-encoded).</param>
/// <param name="LongestHeaderLine">Longest header line excluding the line ending.</param>
/// <param name="LongestBodyLine">Longest body line excluding the line ending.</param>
/// <param name="HeaderLength">Offset of the first body byte (the data length when there is no separator).</param>
/// <param name="HasHeaderBodySeparator">True when an empty line separates headers and body.</param>
public readonly record struct MessageInspection(
    bool HasBareLf,
    bool HasBareCr,
    bool HasNul,
    bool HasNonAsciiHeaders,
    bool HasNonAsciiBody,
    int LongestHeaderLine,
    int LongestBodyLine,
    int HeaderLength,
    bool HasHeaderBodySeparator);

/// <summary>Fast read-only checks on raw message bytes (no allocation, linear time).</summary>
public static class MessageInspector
{
    private static readonly SearchValues<byte> Unusual = SearchValues.Create(BuildUnusual());

    private static byte[] BuildUnusual()
    {
        var list = new List<byte> { 0, (byte)'\r' };
        for (int i = 0x80; i <= 0xFF; i++)
        {
            list.Add((byte)i);
        }

        return list.ToArray();
    }

    /// <summary>Scans the whole message once.</summary>
    public static MessageInspection Inspect(ReadOnlySpan<byte> message)
    {
        bool bareLf = false;
        bool bareCr = false;
        bool nul = false;
        bool nonAsciiHeaders = false;
        bool nonAsciiBody = false;
        int longestHeader = 0;
        int longestBody = 0;
        int headerLength = message.Length;
        bool separator = false;
        bool inHeaders = true;
        int pos = 0;
        while (pos < message.Length)
        {
            int nl = message[pos..].IndexOf((byte)'\n');
            int contentEnd;
            int next;
            if (nl < 0)
            {
                contentEnd = message.Length;
                next = message.Length;
            }
            else
            {
                contentEnd = pos + nl;
                next = contentEnd + 1;
                if (contentEnd > pos && message[contentEnd - 1] == (byte)'\r')
                {
                    contentEnd--;
                }
                else
                {
                    bareLf = true;
                }
            }

            if (inHeaders && nl >= 0 && contentEnd == pos)
            {
                headerLength = next;
                separator = true;
                inHeaders = false;
                pos = next;
                continue;
            }

            var line = message[pos..contentEnd];
            int len = line.Length;
            if (inHeaders)
            {
                longestHeader = Math.Max(longestHeader, len);
            }
            else
            {
                longestBody = Math.Max(longestBody, len);
            }

            int offset = 0;
            while (true)
            {
                int idx = line[offset..].IndexOfAny(Unusual);
                if (idx < 0)
                {
                    break;
                }

                byte b = line[offset + idx];
                if (b == 0)
                {
                    nul = true;
                }
                else if (b == (byte)'\r')
                {
                    bareCr = true;
                }
                else if (inHeaders)
                {
                    nonAsciiHeaders = true;
                }
                else
                {
                    nonAsciiBody = true;
                }

                if (b >= 0x80)
                {
                    // Skip the rest of the high-byte run quickly: all remaining high bytes give the same answer.
                    int rest = line[(offset + idx + 1)..].IndexOfAny(NonHighUnusual);
                    if (rest < 0)
                    {
                        break;
                    }

                    offset += idx + 1 + rest;
                    continue;
                }

                offset += idx + 1;
            }

            pos = next;
        }

        return new MessageInspection(bareLf, bareCr, nul, nonAsciiHeaders, nonAsciiBody, longestHeader, longestBody, headerLength, separator);
    }

    private static readonly SearchValues<byte> NonHighUnusual = SearchValues.Create([(byte)0, (byte)'\r']);

    /// <summary>True when the header block contains bytes above 0x7F, i.e. the message needs SMTPUTF8 (RFC 6532) or is 8-bit in its headers.</summary>
    public static bool HasUtf8Headers(ReadOnlySpan<byte> message)
    {
        int end = HeaderList.FindBodyOffset(message);
        return !Ascii.IsValid(message[..end]);
    }

    /// <summary>True when the header block has non-ASCII bytes and all of them form valid UTF-8.</summary>
    public static bool HasValidUtf8Headers(ReadOnlySpan<byte> message)
    {
        int end = HeaderList.FindBodyOffset(message);
        var headers = message[..end];
        return !Ascii.IsValid(headers) && Utf8.IsValid(headers);
    }

    /// <summary>True when the body (everything after the header block) contains bytes above 0x7F (8BITMIME decision).</summary>
    public static bool HasEightBitBody(ReadOnlySpan<byte> message)
    {
        int end = HeaderList.FindBodyOffset(message);
        return !Ascii.IsValid(message[end..]);
    }

    /// <summary>True when any LF is not preceded by CR.</summary>
    public static bool ContainsBareLf(ReadOnlySpan<byte> data)
    {
        int pos = 0;
        while (pos < data.Length)
        {
            int nl = data[pos..].IndexOf((byte)'\n');
            if (nl < 0)
            {
                return false;
            }

            int at = pos + nl;
            if (at == 0 || data[at - 1] != (byte)'\r')
            {
                return true;
            }

            pos = at + 1;
        }

        return false;
    }

    /// <summary>True when any CR is not immediately followed by LF.</summary>
    public static bool ContainsBareCr(ReadOnlySpan<byte> data)
    {
        int pos = 0;
        while (pos < data.Length)
        {
            int cr = data[pos..].IndexOf((byte)'\r');
            if (cr < 0)
            {
                return false;
            }

            int at = pos + cr;
            if (at + 1 >= data.Length || data[at + 1] != (byte)'\n')
            {
                return true;
            }

            pos = at + 2;
        }

        return false;
    }
}

/// <summary>What <see cref="LineEndings"/> does with a CR that is not followed by LF.</summary>
public enum BareCrHandling
{
    /// <summary>Treat it as a line break and write CRLF (default; makes the line structure unambiguous for every receiver).</summary>
    ConvertToCrlf,

    /// <summary>Drop it.</summary>
    Remove,

    /// <summary>Leave it untouched.</summary>
    Keep,
}

/// <summary>Line-ending normalization.</summary>
public static class LineEndings
{
    /// <summary>Returns <paramref name="data"/> with every bare LF (and, per <paramref name="bareCr"/>, bare CR) turned into CRLF. Returns a copy only when something changes.</summary>
    public static byte[] ToCrlf(ReadOnlySpan<byte> data, BareCrHandling bareCr = BareCrHandling.ConvertToCrlf)
    {
        if (!NeedsNormalization(data, bareCr))
        {
            return data.ToArray();
        }

        var writer = new ArrayBufferWriter<byte>(data.Length + (data.Length >> 4) + 16);
        ToCrlf(data, writer, bareCr);
        return writer.WrittenSpan.ToArray();
    }

    /// <summary>True when <see cref="ToCrlf(ReadOnlySpan{byte}, BareCrHandling)"/> would change the data.</summary>
    public static bool NeedsNormalization(ReadOnlySpan<byte> data, BareCrHandling bareCr = BareCrHandling.ConvertToCrlf) =>
        MessageInspector.ContainsBareLf(data) || (bareCr != BareCrHandling.Keep && MessageInspector.ContainsBareCr(data));

    /// <summary>Writes the normalized data to <paramref name="writer"/>; the output is at most twice the input length.</summary>
    public static void ToCrlf(ReadOnlySpan<byte> data, IBufferWriter<byte> writer, BareCrHandling bareCr = BareCrHandling.ConvertToCrlf)
    {
        ArgumentNullException.ThrowIfNull(writer);
        int i = 0;
        int runStart = 0;
        while (i < data.Length)
        {
            byte b = data[i];
            if (b == (byte)'\n')
            {
                bool precededByCr = i > 0 && data[i - 1] == (byte)'\r';
                if (precededByCr)
                {
                    i++;
                    continue;
                }

                Flush(data[runStart..i], writer);
                Write(writer, "\r\n"u8);
                i++;
                runStart = i;
            }
            else if (b == (byte)'\r' && (i + 1 >= data.Length || data[i + 1] != (byte)'\n'))
            {
                if (bareCr == BareCrHandling.Keep)
                {
                    i++;
                    continue;
                }

                Flush(data[runStart..i], writer);
                if (bareCr == BareCrHandling.ConvertToCrlf)
                {
                    Write(writer, "\r\n"u8);
                }

                i++;
                runStart = i;
            }
            else
            {
                i++;
            }
        }

        Flush(data[runStart..], writer);
    }

    private static void Flush(ReadOnlySpan<byte> run, IBufferWriter<byte> writer)
    {
        if (!run.IsEmpty)
        {
            Write(writer, run);
        }
    }

    internal static void Write(IBufferWriter<byte> writer, ReadOnlySpan<byte> data)
    {
        var span = writer.GetSpan(data.Length);
        data.CopyTo(span);
        writer.Advance(data.Length);
    }
}

/// <summary>Content-Transfer-Encoding encoders used when composing messages.</summary>
public static class TransferEncoder
{
    /// <summary>Longest encoded line for base64 and quoted-printable (RFC 2045).</summary>
    public const int MaxEncodedLineLength = 76;

    private const int Base64BytesPerLine = 57; // 57 bytes -> 76 base64 characters
    private const int QuotedPrintableChunk = 16 * 1024;

    /// <summary>Writes <paramref name="data"/> as base64 in lines of 76 characters separated by CRLF (no trailing CRLF).</summary>
    public static void WriteBase64(ReadOnlySpan<byte> data, IBufferWriter<byte> writer)
    {
        ArgumentNullException.ThrowIfNull(writer);
        int pos = 0;
        while (pos < data.Length)
        {
            int n = Math.Min(Base64BytesPerLine, data.Length - pos);
            var dst = writer.GetSpan(80);
            if (pos > 0)
            {
                dst[0] = (byte)'\r';
                dst[1] = (byte)'\n';
                Base64.EncodeToUtf8(data.Slice(pos, n), dst[2..], out _, out int written);
                writer.Advance(written + 2);
            }
            else
            {
                Base64.EncodeToUtf8(data.Slice(pos, n), dst, out _, out int written);
                writer.Advance(written);
            }

            pos += n;
        }
    }

    /// <summary>
    /// Writes <paramref name="data"/> (text with CRLF or LF line breaks) as quoted-printable with soft line breaks so
    /// that no line exceeds 76 characters; trailing white space is encoded; hard line breaks are written as CRLF. A '-' that a soft
    /// break would place at the start of a line is encoded (=2D), so a soft break can never create a line that looks like a MIME delimiter.
    /// </summary>
    public static void WriteQuotedPrintable(ReadOnlySpan<byte> data, IBufferWriter<byte> writer)
    {
        ArgumentNullException.ThrowIfNull(writer);
        int pos = 0;
        while (pos < data.Length)
        {
            int nl = data[pos..].IndexOf((byte)'\n');
            int lineEnd = nl < 0 ? data.Length : pos + nl;
            int contentEnd = lineEnd;
            if (nl >= 0 && contentEnd > pos && data[contentEnd - 1] == (byte)'\r')
            {
                contentEnd--;
            }

            int column = 0;
            for (int c0 = pos; c0 < contentEnd; c0 += QuotedPrintableChunk)
            {
                int c1 = Math.Min(contentEnd, c0 + QuotedPrintableChunk);
                int n = c1 - c0;
                var dst = writer.GetSpan((n * 3) + (((n * 3) / 70) + 2) * 3 + 8);
                int w = 0;
                for (int i = c0; i < c1; i++)
                {
                    byte b = data[i];
                    bool last = i == contentEnd - 1;
                    bool literal = (b >= 33 && b <= 126 && b != (byte)'=') || ((b == (byte)' ' || b == (byte)'\t') && !last);
                    int need = literal ? 1 : 3;
                    if (column + need > (last ? MaxEncodedLineLength : MaxEncodedLineLength - 1))
                    {
                        dst[w++] = (byte)'=';
                        dst[w++] = (byte)'\r';
                        dst[w++] = (byte)'\n';
                        column = 0;
                        if (b == (byte)'-')
                        {
                            // A soft break must not bring "--" to the start of a line: after decoding it is not there, but a MIME parser reading the
                            // encoded text sees a delimiter line ("--boundary") that the content never had (boundary forgery).
                            literal = false;
                            need = 3;
                        }
                    }

                    if (literal)
                    {
                        dst[w++] = b;
                    }
                    else
                    {
                        dst[w++] = (byte)'=';
                        dst[w++] = (byte)"0123456789ABCDEF"[b >> 4];
                        dst[w++] = (byte)"0123456789ABCDEF"[b & 0xF];
                    }

                    column += need;
                }

                writer.Advance(w);
            }

            if (nl >= 0)
            {
                LineEndings.Write(writer, "\r\n"u8);
                pos = lineEnd + 1;
            }
            else
            {
                pos = data.Length;
            }
        }
    }

    /// <summary>
    /// Chooses the transfer encoding for UTF-8 text: 7bit for plain short ASCII lines, 8bit when allowed and safe, otherwise
    /// quoted-printable (mostly ASCII) or base64 (mostly non-ASCII or containing control characters).
    /// </summary>
    public static ContentTransferEncoding ChooseForText(ReadOnlySpan<byte> utf8Text, bool allow8Bit, int maxLineLength = 998)
    {
        int nonAscii = 0;
        bool controls = false;
        int longest = 0;
        int current = 0;
        foreach (byte b in utf8Text)
        {
            if (b == (byte)'\n')
            {
                longest = Math.Max(longest, current);
                current = 0;
                continue;
            }

            if (b >= 0x80)
            {
                nonAscii++;
            }
            else if ((b < 32 && b != (byte)'\t' && b != (byte)'\r') || b == 127)
            {
                controls = true;
            }

            current++;
        }

        longest = Math.Max(longest, current);
        if (controls)
        {
            return ContentTransferEncoding.Base64;
        }

        if (nonAscii == 0)
        {
            return longest <= maxLineLength ? ContentTransferEncoding.SevenBit : ContentTransferEncoding.QuotedPrintable;
        }

        if (allow8Bit && longest <= maxLineLength)
        {
            return ContentTransferEncoding.EightBit;
        }

        return nonAscii * 3 > utf8Text.Length ? ContentTransferEncoding.Base64 : ContentTransferEncoding.QuotedPrintable;
    }
}
