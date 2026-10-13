using System.Buffers;

namespace Mta.Mime;

/// <summary>A Content-Transfer-Encoding mechanism (RFC 2045 section 6).</summary>
public enum ContentTransferEncoding
{
    SevenBit = 0,
    EightBit,
    Binary,
    Base64,
    QuotedPrintable,

    /// <summary>An unrecognized mechanism; the data is treated as identity.</summary>
    Unknown,
}

/// <summary>Parsing and formatting of <see cref="ContentTransferEncoding"/> values.</summary>
public static class ContentTransferEncodings
{
    /// <summary>Parses the value of a Content-Transfer-Encoding header (case-insensitive, comments ignored).</summary>
    public static ContentTransferEncoding Parse(ReadOnlySpan<char> value)
    {
        int paren = value.IndexOf('(');
        if (paren >= 0)
        {
            value = value[..paren];
        }

        value = value.Trim();
        if (value.IsEmpty)
        {
            return ContentTransferEncoding.SevenBit;
        }

        if (value.Equals("7bit", StringComparison.OrdinalIgnoreCase)) { return ContentTransferEncoding.SevenBit; }
        if (value.Equals("8bit", StringComparison.OrdinalIgnoreCase)) { return ContentTransferEncoding.EightBit; }
        if (value.Equals("binary", StringComparison.OrdinalIgnoreCase)) { return ContentTransferEncoding.Binary; }
        if (value.Equals("base64", StringComparison.OrdinalIgnoreCase)) { return ContentTransferEncoding.Base64; }
        if (value.Equals("quoted-printable", StringComparison.OrdinalIgnoreCase)) { return ContentTransferEncoding.QuotedPrintable; }
        if (value.Equals("x-quoted-printable", StringComparison.OrdinalIgnoreCase)) { return ContentTransferEncoding.QuotedPrintable; }
        return ContentTransferEncoding.Unknown;
    }

    /// <summary>Parses a Content-Transfer-Encoding header field (the value is cut at 256 bytes); no string is built for the usual short ASCII value.</summary>
    internal static ContentTransferEncoding ParseHeader(in MimeHeader header)
    {
        Span<char> value = stackalloc char[256];
        return HeaderText.TryGetAsciiValue(header.RawValue.Span, value, out int length)
            ? Parse(value[..length])
            : Parse(header.GetValue(256));
    }

    /// <summary>The canonical header token ("7bit", "base64" ...).</summary>
    public static string ToToken(this ContentTransferEncoding encoding) => encoding switch
    {
        ContentTransferEncoding.SevenBit => "7bit",
        ContentTransferEncoding.EightBit => "8bit",
        ContentTransferEncoding.Binary => "binary",
        ContentTransferEncoding.Base64 => "base64",
        ContentTransferEncoding.QuotedPrintable => "quoted-printable",
        _ => "7bit",
    };
}

/// <summary>Outcome of a body decode.</summary>
/// <param name="BytesWritten">Decoded bytes delivered to the sink.</param>
/// <param name="Truncated">True when output stopped at the size limit; <paramref name="BytesWritten"/> equals the limit.</param>
/// <param name="Anomalies">Problems found in the encoded data.</param>
public readonly record struct DecodeResult(long BytesWritten, bool Truncated, MimeAnomaly Anomalies);

/// <summary>
/// Streaming, lenient base64 decoder. Whitespace is skipped; other invalid characters are skipped and reported;
/// a truncated final quantum yields its complete bytes. Output never exceeds three bytes per four input characters,
/// so it cannot amplify its input. The struct is mutable: keep it in a local and pass it by reference.
/// </summary>
public struct Base64Decoder
{
    private const byte Invalid = 0xFF;
    private const byte Skip = 0xFE;
    private const byte Pad = 0xFD;

    private static readonly byte[] Table = BuildTable();

    private uint _accumulator;
    private int _count;
    private MimeAnomaly _anomalies;

    /// <summary>Anomalies seen so far.</summary>
    public readonly MimeAnomaly Anomalies => _anomalies;

    /// <summary>The upper bound of bytes <see cref="Decode"/> writes for <paramref name="inputLength"/> input bytes.</summary>
    public static int GetMaxDecodedLength(int inputLength) => ((inputLength >> 2) * 3) + 8;

    private static byte[] BuildTable()
    {
        var t = new byte[256];
        Array.Fill(t, Invalid);
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < alphabet.Length; i++)
        {
            t[alphabet[i]] = (byte)i;
        }

        t['-'] = 62; // URL-safe variants, tolerated
        t['_'] = 63;
        t[' '] = Skip;
        t['\t'] = Skip;
        t['\r'] = Skip;
        t['\n'] = Skip;
        t['='] = Pad;
        return t;
    }

    /// <summary>Decodes a chunk. <paramref name="destination"/> must be at least <see cref="GetMaxDecodedLength"/> bytes. Returns the bytes written.</summary>
    public int Decode(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int written = 0;
        uint acc = _accumulator;
        int count = _count;
        byte[] table = Table;
        for (int i = 0; i < source.Length; i++)
        {
            byte v = table[source[i]];
            if (v < 64)
            {
                acc = (acc << 6) | v;
                if (++count == 4)
                {
                    destination[written++] = (byte)(acc >> 16);
                    destination[written++] = (byte)(acc >> 8);
                    destination[written++] = (byte)acc;
                    acc = 0;
                    count = 0;
                }
            }
            else if (v == Skip)
            {
                continue;
            }
            else if (v == Pad)
            {
                if (count >= 2)
                {
                    if (count == 2)
                    {
                        destination[written++] = (byte)(acc >> 4);
                    }
                    else
                    {
                        destination[written++] = (byte)(acc >> 10);
                        destination[written++] = (byte)(acc >> 2);
                    }

                    acc = 0;
                    count = 0;
                }
                else if (count == 1)
                {
                    _anomalies |= MimeAnomaly.MalformedBase64;
                    acc = 0;
                    count = 0;
                }

                // Further '=' after padding are ignored (padding may be "==" or have stray extras).
            }
            else
            {
                _anomalies |= MimeAnomaly.MalformedBase64;
            }
        }

        _accumulator = acc;
        _count = count;
        return written;
    }

    /// <summary>Ends the stream: emits the complete bytes of an unpadded final quantum. <paramref name="destination"/> needs 2 bytes.</summary>
    public int Finish(Span<byte> destination)
    {
        int written = 0;
        if (_count == 2)
        {
            destination[written++] = (byte)(_accumulator >> 4);
            _anomalies |= MimeAnomaly.MalformedBase64;
        }
        else if (_count == 3)
        {
            destination[written++] = (byte)(_accumulator >> 10);
            destination[written++] = (byte)(_accumulator >> 2);
            _anomalies |= MimeAnomaly.MalformedBase64;
        }
        else if (_count == 1)
        {
            _anomalies |= MimeAnomaly.MalformedBase64;
        }

        _accumulator = 0;
        _count = 0;
        return written;
    }
}

/// <summary>
/// Streaming, lenient quoted-printable decoder (RFC 2045 section 6.7). Soft line breaks are removed, whitespace
/// preceding a hard line break is dropped, malformed escapes are kept literally and reported. Hard line breaks are
/// passed through as they appear in the input (CRLF or LF). Mutable struct: keep it in a local and pass it by reference.
/// </summary>
public struct QuotedPrintableDecoder
{
    private const int MaxPendingWhitespace = 64;

    private enum State : byte { Normal, Equals, EqualsHex, EqualsCr }

    private State _state;
    private byte _hexFirst;
    private int _pendingCount;
    private ulong _pendingIsTab; // bit i set: pending whitespace i is a tab, else a space
    private MimeAnomaly _anomalies;

    /// <summary>Anomalies seen so far.</summary>
    public readonly MimeAnomaly Anomalies => _anomalies;

    /// <summary>The upper bound of bytes <see cref="Decode"/> writes for <paramref name="inputLength"/> input bytes.</summary>
    public static int GetMaxDecodedLength(int inputLength) => inputLength + MaxPendingWhitespace + 8;

    private static int HexValue(byte b) => b switch
    {
        >= (byte)'0' and <= (byte)'9' => b - '0',
        >= (byte)'A' and <= (byte)'F' => b - 'A' + 10,
        >= (byte)'a' and <= (byte)'f' => b - 'a' + 10,
        _ => -1,
    };

    private int FlushPending(Span<byte> destination, int written)
    {
        for (int k = 0; k < _pendingCount; k++)
        {
            destination[written++] = (byte)(((_pendingIsTab >> k) & 1) != 0 ? '\t' : ' ');
        }

        _pendingCount = 0;
        _pendingIsTab = 0;
        return written;
    }

    /// <summary>Decodes a chunk. <paramref name="destination"/> must be at least <see cref="GetMaxDecodedLength"/> bytes. Returns the bytes written.</summary>
    public int Decode(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int written = 0;
        for (int i = 0; i < source.Length; i++)
        {
            byte b = source[i];
        reprocess:
            switch (_state)
            {
                case State.Normal:
                    if (b == '=')
                    {
                        written = FlushPending(destination, written);
                        _state = State.Equals;
                    }
                    else if (b is (byte)' ' or (byte)'\t')
                    {
                        if (_pendingCount == MaxPendingWhitespace)
                        {
                            written = FlushPending(destination, written);
                        }

                        if (b == '\t')
                        {
                            _pendingIsTab |= 1UL << _pendingCount;
                        }

                        _pendingCount++;
                    }
                    else if (b is (byte)'\r' or (byte)'\n')
                    {
                        _pendingCount = 0;
                        _pendingIsTab = 0;
                        destination[written++] = b;
                    }
                    else
                    {
                        written = FlushPending(destination, written);
                        destination[written++] = b;
                    }

                    break;

                case State.Equals:
                    if (HexValue(b) >= 0)
                    {
                        _hexFirst = b;
                        _state = State.EqualsHex;
                    }
                    else if (b == '\r')
                    {
                        _state = State.EqualsCr;
                    }
                    else if (b == '\n')
                    {
                        _state = State.Normal;
                    }
                    else
                    {
                        _anomalies |= MimeAnomaly.MalformedQuotedPrintable;
                        destination[written++] = (byte)'=';
                        _state = State.Normal;
                        goto reprocess;
                    }

                    break;

                case State.EqualsHex:
                    {
                        int hi = HexValue(_hexFirst);
                        int lo = HexValue(b);
                        if (lo >= 0)
                        {
                            destination[written++] = (byte)((hi << 4) | lo);
                            _state = State.Normal;
                        }
                        else
                        {
                            _anomalies |= MimeAnomaly.MalformedQuotedPrintable;
                            destination[written++] = (byte)'=';
                            destination[written++] = _hexFirst;
                            _state = State.Normal;
                            goto reprocess;
                        }

                        break;
                    }

                case State.EqualsCr:
                    _state = State.Normal;
                    if (b != '\n')
                    {
                        _anomalies |= MimeAnomaly.MalformedQuotedPrintable;
                        goto reprocess;
                    }

                    break;
            }
        }

        return written;
    }

    /// <summary>Ends the stream. <paramref name="destination"/> needs 4 bytes.</summary>
    public int Finish(Span<byte> destination)
    {
        int written = 0;
        switch (_state)
        {
            case State.Equals:
                destination[written++] = (byte)'=';
                _anomalies |= MimeAnomaly.MalformedQuotedPrintable;
                break;
            case State.EqualsHex:
                destination[written++] = (byte)'=';
                destination[written++] = _hexFirst;
                _anomalies |= MimeAnomaly.MalformedQuotedPrintable;
                break;
        }

        _state = State.Normal;
        _pendingCount = 0; // trailing whitespace at end of data is dropped, like before a hard line break
        _pendingIsTab = 0;
        return written;
    }
}

/// <summary>Decodes a Content-Transfer-Encoded body into a sink, bounded by a byte limit.</summary>
public static class BodyDecoder
{
    private const int ChunkSize = 8192;

    /// <summary>
    /// Decodes <paramref name="body"/> into <paramref name="writer"/>, writing at most <paramref name="maxBytes"/> bytes.
    /// Never throws for malformed data; problems are returned as anomalies.
    /// </summary>
    public static DecodeResult Decode(ReadOnlySpan<byte> body, ContentTransferEncoding encoding, IBufferWriter<byte> writer, long maxBytes)
    {
        ArgumentNullException.ThrowIfNull(writer);
        long total = 0;
        MimeAnomaly anomalies = MimeAnomaly.None;
        bool truncated = false;

        switch (encoding)
        {
            case ContentTransferEncoding.Base64:
                {
                    var decoder = new Base64Decoder();
                    for (int pos = 0; pos < body.Length && !truncated; pos += ChunkSize)
                    {
                        var chunk = body.Slice(pos, Math.Min(ChunkSize, body.Length - pos));
                        var dst = writer.GetSpan(Base64Decoder.GetMaxDecodedLength(chunk.Length));
                        int n = decoder.Decode(chunk, dst);
                        Commit(writer, n, maxBytes, ref total, ref truncated);
                    }

                    if (!truncated)
                    {
                        var dst = writer.GetSpan(4);
                        int n = decoder.Finish(dst);
                        Commit(writer, n, maxBytes, ref total, ref truncated);
                    }

                    anomalies |= decoder.Anomalies;
                    break;
                }

            case ContentTransferEncoding.QuotedPrintable:
                {
                    var decoder = new QuotedPrintableDecoder();
                    for (int pos = 0; pos < body.Length && !truncated; pos += ChunkSize)
                    {
                        var chunk = body.Slice(pos, Math.Min(ChunkSize, body.Length - pos));
                        var dst = writer.GetSpan(QuotedPrintableDecoder.GetMaxDecodedLength(chunk.Length));
                        int n = decoder.Decode(chunk, dst);
                        Commit(writer, n, maxBytes, ref total, ref truncated);
                    }

                    if (!truncated)
                    {
                        var dst = writer.GetSpan(8);
                        int n = decoder.Finish(dst);
                        Commit(writer, n, maxBytes, ref total, ref truncated);
                    }

                    anomalies |= decoder.Anomalies;
                    break;
                }

            default:
                {
                    for (int pos = 0; pos < body.Length && !truncated; pos += ChunkSize)
                    {
                        var chunk = body.Slice(pos, Math.Min(ChunkSize, body.Length - pos));
                        var dst = writer.GetSpan(chunk.Length);
                        chunk.CopyTo(dst);
                        Commit(writer, chunk.Length, maxBytes, ref total, ref truncated);
                    }

                    if (encoding == ContentTransferEncoding.Unknown)
                    {
                        anomalies |= MimeAnomaly.UnknownTransferEncoding;
                    }

                    break;
                }
        }

        if (truncated)
        {
            anomalies |= MimeAnomaly.DecodedSizeLimit;
        }

        return new DecodeResult(total, truncated, anomalies);
    }

    /// <summary>Counts the decoded size of <paramref name="body"/> without keeping the output (bounded by <paramref name="maxBytes"/>).</summary>
    public static DecodeResult Measure(ReadOnlySpan<byte> body, ContentTransferEncoding encoding, long maxBytes = long.MaxValue)
    {
        var sink = new CountingWriter();
        try
        {
            return Decode(body, encoding, sink, maxBytes);
        }
        finally
        {
            sink.Dispose();
        }
    }

    private static void Commit(IBufferWriter<byte> writer, int produced, long maxBytes, ref long total, ref bool truncated)
    {
        long room = maxBytes - total;
        if (produced > room)
        {
            produced = (int)Math.Max(0, room);
            truncated = true;
        }

        if (produced > 0)
        {
            writer.Advance(produced);
            total += produced;
        }
    }

    private sealed class CountingWriter : IBufferWriter<byte>, IDisposable
    {
        private byte[]? _buffer = ArrayPool<byte>.Shared.Rent(ChunkSize + 128);

        public void Advance(int count)
        {
        }

        public Memory<byte> GetMemory(int sizeHint = 0) => EnsureBuffer(sizeHint);

        public Span<byte> GetSpan(int sizeHint = 0) => EnsureBuffer(sizeHint).Span;

        public void Dispose()
        {
            var b = _buffer;
            _buffer = null;
            if (b is not null)
            {
                ArrayPool<byte>.Shared.Return(b);
            }
        }

        private Memory<byte> EnsureBuffer(int sizeHint)
        {
            var b = _buffer ?? throw new ObjectDisposedException(nameof(CountingWriter));
            if (sizeHint > b.Length)
            {
                ArrayPool<byte>.Shared.Return(b);
                b = _buffer = ArrayPool<byte>.Shared.Rent(sizeHint);
            }

            return b;
        }
    }
}
