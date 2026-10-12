using System.Buffers;
using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Mta.Mime;

/// <summary>
/// The ordered header fields of a message (or MIME part) plus the offset where the body starts. Parsing never copies
/// message bytes and never fails: hostile or malformed input produces anomaly flags and, at the limits, a truncated list.
/// Handles CRLF and bare-LF line endings, obsolete folding, RFC 6532 UTF-8 and 8-bit field bodies. A bare CR is never a line
/// break (it is reported), so a header cannot be split by CR smuggling.
/// </summary>
public sealed class HeaderList : IReadOnlyList<MimeHeader>
{
    private static readonly SearchValues<byte> Unusual = SearchValues.Create(BuildUnusual());

    private readonly MimeHeader[] _headers;
    private readonly int _count;

    private HeaderList(ReadOnlyMemory<byte> data, MimeHeader[] headers, int count, int bodyOffset, bool hasSeparator, MimeAnomaly anomalies)
    {
        Data = data;
        _headers = headers;
        _count = count;
        BodyOffset = bodyOffset;
        HasSeparator = hasSeparator;
        Anomalies = anomalies;
    }

    /// <summary>The buffer that was parsed (whole message or part).</summary>
    public ReadOnlyMemory<byte> Data { get; }

    /// <summary>Offset of the first body byte (just after the empty line), or the data length when there is no body.</summary>
    public int BodyOffset { get; }

    /// <summary>True when an empty line terminated the header block.</summary>
    public bool HasSeparator { get; }

    /// <summary>Anomalies found in the header block.</summary>
    public MimeAnomaly Anomalies { get; }

    /// <summary>The body bytes (everything after the separator), not copied.</summary>
    public ReadOnlyMemory<byte> Body => Data[BodyOffset..];

    /// <summary>The header block including the line ending of the last field, excluding the separator line.</summary>
    public ReadOnlyMemory<byte> HeaderBlock
    {
        get
        {
            if (_count == 0)
            {
                return ReadOnlyMemory<byte>.Empty;
            }

            var last = _headers[_count - 1];
            return Data[..(last.Offset + last.LengthWithLineEnding)];
        }
    }

    /// <summary>True when the data contains bytes outside US-ASCII in the header block (RFC 6532 / 8-bit headers).</summary>
    public bool HasNonAsciiHeaders => (Anomalies & MimeAnomaly.NonAsciiHeaders) != 0;

    /// <inheritdoc />
    public int Count => _count;

    /// <inheritdoc />
    public MimeHeader this[int index] => (uint)index < (uint)_count ? _headers[index] : throw new ArgumentOutOfRangeException(nameof(index));

    /// <summary>Parses the header block at the start of <paramref name="data"/>.</summary>
    public static HeaderList Parse(ReadOnlyMemory<byte> data, MimeLimits? limits = null) => ParseCore(data, limits ?? MimeLimits.Default);

    /// <summary>
    /// Finds where the headers end without recording any field: returns the offset of the first body byte
    /// (data length if there is no separator). Cheap enough for the SMTP receive path.
    /// </summary>
    public static int FindBodyOffset(ReadOnlySpan<byte> data)
    {
        int pos = 0;
        while (pos < data.Length)
        {
            int nl = data[pos..].IndexOf((byte)'\n');
            if (nl < 0)
            {
                return data.Length;
            }

            int end = pos + nl;
            int lineLength = end - pos;
            if (lineLength == 0 || (lineLength == 1 && data[pos] == (byte)'\r'))
            {
                return end + 1;
            }

            pos = end + 1;
        }

        return data.Length;
    }

    /// <summary>
    /// Reads the field (or the separator line) at <paramref name="pos"/> without recording anything: used by the header editor
    /// to stream over arbitrarily many fields. <paramref name="fieldEnd"/> excludes the final line ending, <paramref name="next"/>
    /// is the start of the next field; <paramref name="nameLength"/> is 0 for malformed lines.
    /// </summary>
    internal static bool TryReadField(ReadOnlySpan<byte> data, int pos, out int fieldEnd, out int next, out int nameLength, out bool blank, out int afterBlank)
    {
        fieldEnd = next = nameLength = afterBlank = 0;
        blank = false;
        if (pos >= data.Length)
        {
            return false;
        }

        var an = MimeAnomaly.None;
        ReadLine(data, pos, out int lineEnd, out int eol, out int nxt, ref an);
        if (lineEnd == pos && eol > 0)
        {
            blank = true;
            afterBlank = nxt;
            return true;
        }

        int firstLineEnd = lineEnd;
        fieldEnd = lineEnd;
        next = nxt;
        while (next < data.Length && data[next] is (byte)' ' or (byte)'\t')
        {
            ReadLine(data, next, out lineEnd, out eol, out nxt, ref an);
            fieldEnd = lineEnd;
            next = nxt;
        }

        Classify(data, pos, firstLineEnd, out nameLength, out _, ref an);
        return true;
    }

    private static byte[] BuildUnusual()
    {
        var list = new List<byte> { 0, (byte)'\r' };
        for (int i = 0x80; i <= 0xFF; i++)
        {
            list.Add((byte)i);
        }

        return list.ToArray();
    }

    private static HeaderList ParseCore(ReadOnlyMemory<byte> data, MimeLimits limits)
    {
        var span = data.Span;
        int length = span.Length;
        var anomalies = MimeAnomaly.None;
        var headers = new MimeHeader[length == 0 ? 0 : 16];
        int count = 0;
        int pos = 0;
        int bodyOffset = length;
        bool separator = false;
        int maxLine = limits.MaxLineLength;

        while (pos < length)
        {
            ReadLine(span, pos, out int lineEnd, out int eol, out int next, ref anomalies);
            if (lineEnd == pos && eol > 0)
            {
                bodyOffset = next;
                separator = true;
                break;
            }

            int fieldStart = pos;
            int firstLineEnd = lineEnd;
            int fieldEnd = lineEnd;
            int fieldEol = eol;
            CheckLine(span[pos..lineEnd], maxLine, ref anomalies);
            pos = next;
            while (pos < length && span[pos] is (byte)' ' or (byte)'\t')
            {
                ReadLine(span, pos, out lineEnd, out eol, out next, ref anomalies);
                CheckLine(span[pos..lineEnd], maxLine, ref anomalies);
                fieldEnd = lineEnd;
                fieldEol = eol;
                pos = next;
            }

            if (count >= limits.MaxHeaderCount)
            {
                anomalies |= MimeAnomaly.TooManyHeaders;
                continue;
            }

            if (fieldStart >= limits.MaxHeaderBytes)
            {
                anomalies |= MimeAnomaly.HeaderBlockTooLarge;
                continue;
            }

            Classify(span, fieldStart, firstLineEnd, out int nameLength, out int valueStart, ref anomalies);
            var id = nameLength > 0 ? HeaderNames.Identify(span.Slice(fieldStart, nameLength)) : HeaderId.Unknown;
            if (count == headers.Length)
            {
                Array.Resize(ref headers, Math.Min(Math.Max(16, count * 2), limits.MaxHeaderCount));
            }

            headers[count++] = new MimeHeader(data[fieldStart..fieldEnd], fieldStart, nameLength, valueStart, fieldEol, id);
        }

        if (!separator)
        {
            anomalies |= MimeAnomaly.NoHeaderBodySeparator;
        }

        return new HeaderList(data, headers, count, bodyOffset, separator, anomalies);
    }

    /// <summary>Finds the extent of the line at <paramref name="pos"/>: content end (before CR LF), line-ending length and next position.</summary>
    private static void ReadLine(ReadOnlySpan<byte> span, int pos, out int lineEnd, out int eol, out int next, ref MimeAnomaly anomalies)
    {
        int nl = span[pos..].IndexOf((byte)'\n');
        if (nl < 0)
        {
            lineEnd = span.Length;
            eol = 0;
            next = span.Length;
            return;
        }

        int nlAbs = pos + nl;
        next = nlAbs + 1;
        if (nlAbs > pos && span[nlAbs - 1] == (byte)'\r')
        {
            lineEnd = nlAbs - 1;
            eol = 2;
        }
        else
        {
            lineEnd = nlAbs;
            eol = 1;
            anomalies |= MimeAnomaly.BareLf;
        }
    }

    private static void CheckLine(ReadOnlySpan<byte> line, int maxLine, ref MimeAnomaly anomalies)
    {
        if (line.Length > maxLine)
        {
            anomalies |= MimeAnomaly.HeaderLineTooLong;
        }

        const MimeAnomaly All = MimeAnomaly.NulInHeaders | MimeAnomaly.BareCr | MimeAnomaly.NonAsciiHeaders;
        int offset = 0;
        while ((anomalies & All) != All)
        {
            int idx = line[offset..].IndexOfAny(Unusual);
            if (idx < 0)
            {
                return;
            }

            byte b = line[offset + idx];
            anomalies |= b == 0 ? MimeAnomaly.NulInHeaders : b == (byte)'\r' ? MimeAnomaly.BareCr : MimeAnomaly.NonAsciiHeaders;
            offset += idx + 1;
        }
    }

    private static void Classify(ReadOnlySpan<byte> span, int start, int firstLineEnd, out int nameLength, out int valueStart, ref MimeAnomaly anomalies)
    {
        nameLength = 0;
        valueStart = -1;
        var line = span[start..firstLineEnd];
        int colon = line.IndexOf((byte)':');
        if (colon <= 0)
        {
            anomalies |= MimeAnomaly.MissingColon;
            return;
        }

        int nameEnd = colon;
        while (nameEnd > 0 && line[nameEnd - 1] is (byte)' ' or (byte)'\t')
        {
            nameEnd--;
        }

        if (nameEnd == 0)
        {
            anomalies |= MimeAnomaly.MissingColon;
            return;
        }

        for (int i = 0; i < nameEnd; i++)
        {
            byte b = line[i];
            if (b <= 32 || b >= 127)
            {
                anomalies |= MimeAnomaly.MissingColon;
                return;
            }
        }

        if (nameEnd != colon)
        {
            anomalies |= MimeAnomaly.SpaceBeforeColon;
        }

        nameLength = nameEnd;
        valueStart = colon + 1;
    }

    // ---------------------------------------------------------------- queries

    /// <summary>Index of the first field with the given id, or -1.</summary>
    public int IndexOf(HeaderId id)
    {
        if (id == HeaderId.Unknown)
        {
            return -1;
        }

        for (int i = 0; i < _count; i++)
        {
            if (_headers[i].Id == id)
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>Index of the first field with the given name (case-insensitive), or -1.</summary>
    public int IndexOf(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        var id = HeaderNames.Identify(name);
        for (int i = 0; i < _count; i++)
        {
            var h = _headers[i];
            if (id != HeaderId.Unknown ? h.Id == id : h.NameEquals(name))
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>The first field with the given id.</summary>
    public bool TryGetFirst(HeaderId id, out MimeHeader header)
    {
        int i = IndexOf(id);
        header = i >= 0 ? _headers[i] : default;
        return i >= 0;
    }

    /// <summary>The first field with the given name (case-insensitive).</summary>
    public bool TryGetFirst(string name, out MimeHeader header)
    {
        int i = IndexOf(name);
        header = i >= 0 ? _headers[i] : default;
        return i >= 0;
    }

    /// <summary>The unfolded, trimmed value of the first field with the given id, or null.</summary>
    public string? GetFirstValue(HeaderId id) => TryGetFirst(id, out var h) ? h.Value : null;

    /// <summary>The unfolded, trimmed value of the first field with the given name, or null.</summary>
    public string? GetFirstValue(string name) => TryGetFirst(name, out var h) ? h.Value : null;

    /// <summary>Number of fields with the given id.</summary>
    public int CountOf(HeaderId id)
    {
        if (id == HeaderId.Unknown)
        {
            return 0;
        }

        int n = 0;
        for (int i = 0; i < _count; i++)
        {
            if (_headers[i].Id == id)
            {
                n++;
            }
        }

        return n;
    }

    /// <summary>Number of fields with the given name (case-insensitive).</summary>
    public int CountOf(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        var id = HeaderNames.Identify(name);
        if (id != HeaderId.Unknown)
        {
            return CountOf(id);
        }

        int n = 0;
        for (int i = 0; i < _count; i++)
        {
            if (_headers[i].NameEquals(name))
            {
                n++;
            }
        }

        return n;
    }

    /// <summary>True when any field is malformed (no colon or invalid name).</summary>
    public bool HasMalformedHeaders => (Anomalies & MimeAnomaly.MissingColon) != 0;

    /// <summary>A struct enumerator (no allocation).</summary>
    public Enumerator GetEnumerator() => new(this);

    IEnumerator<MimeHeader> IEnumerable<MimeHeader>.GetEnumerator() => GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    /// <summary>Allocation-free enumerator over the fields.</summary>
    public struct Enumerator : IEnumerator<MimeHeader>
    {
        private readonly HeaderList _list;
        private int _index;

        internal Enumerator(HeaderList list)
        {
            _list = list;
            _index = -1;
        }

        public readonly MimeHeader Current => _list._headers[_index];

        readonly object IEnumerator.Current => Current;

        public bool MoveNext() => ++_index < _list._count;

        public void Reset() => _index = -1;

        public readonly void Dispose()
        {
        }
    }
}
