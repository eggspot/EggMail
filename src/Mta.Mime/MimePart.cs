using System.Buffers;
using System.Text;

namespace Mta.Mime;

/// <summary>
/// One MIME entity (RFC 2045/2046): the message itself, a multipart child, or an embedded message/rfc822. All byte
/// ranges (<see cref="Raw"/>, <see cref="Body"/>, <see cref="Preamble"/> ...) are slices of the original buffer; the
/// transfer-decoded content is produced lazily by <see cref="DecodeBodyTo"/> and friends.
/// </summary>
public sealed class MimePart
{
    private readonly MimeLimits _limits;
    private MimePart[] _children = [];
    private ContentDisposition? _disposition;
    private bool _dispositionRead;

    internal MimePart(
        MimeLimits limits,
        MimePart? parent,
        int depth,
        HeaderList headers,
        ContentType contentType,
        ContentTransferEncoding transferEncoding,
        MimeAnomaly anomalies)
    {
        _limits = limits;
        Parent = parent;
        Depth = depth;
        Headers = headers;
        ContentType = contentType;
        TransferEncoding = transferEncoding;
        Anomalies = anomalies;
    }

    /// <summary>The containing entity, or null for the root.</summary>
    public MimePart? Parent { get; }

    /// <summary>Nesting depth; the root is 0.</summary>
    public int Depth { get; }

    /// <summary>The entity's own header fields.</summary>
    public HeaderList Headers { get; }

    /// <summary>The effective content type (the default for the context when the header is absent).</summary>
    public ContentType ContentType { get; }

    /// <summary>The Content-Transfer-Encoding of this entity's body.</summary>
    public ContentTransferEncoding TransferEncoding { get; }

    /// <summary>Anomalies found in this entity itself (its headers and its multipart structure), not in its children.</summary>
    public MimeAnomaly Anomalies { get; internal set; }

    /// <summary>The whole entity including its headers.</summary>
    public ReadOnlyMemory<byte> Raw => Headers.Data;

    /// <summary>The body bytes as transferred (not decoded). For a multipart this is everything after the headers.</summary>
    public ReadOnlyMemory<byte> Body => Headers.Body;

    /// <summary>Text before the first delimiter of a multipart, or empty.</summary>
    public ReadOnlyMemory<byte> Preamble { get; internal set; }

    /// <summary>Text after the closing delimiter of a multipart, or empty.</summary>
    public ReadOnlyMemory<byte> Epilogue { get; internal set; }

    /// <summary>Child entities of a multipart; the single embedded message of a message/rfc822; otherwise empty.</summary>
    public IReadOnlyList<MimePart> Children => _children;

    internal void SetChildren(MimePart[] children) => _children = children;

    /// <summary>The limits this entity was parsed with (reused by consumers that continue working on an already parsed message).</summary>
    internal MimeLimits Limits => _limits;

    /// <summary>True for <c>multipart/*</c> that was split into children (or has none because the structure is broken).</summary>
    public bool IsMultipart => ContentType.IsMultipart;

    /// <summary>True when this entity is a message/rfc822 whose content was parsed as <see cref="Children"/>[0].</summary>
    public bool IsEmbeddedMessage => ContentType.IsEmbeddedMessage && _children.Length == 1;

    /// <summary>The Content-Disposition, or null.</summary>
    public ContentDisposition? Disposition
    {
        get
        {
            if (!_dispositionRead)
            {
                _dispositionRead = true;
                _disposition = Headers.TryGetFirst(HeaderId.ContentDisposition, out var h)
                    ? ContentDisposition.Parse(h.GetValue(_limits.MaxHeaderValueBytes), _limits)
                    : null;
            }

            return _disposition;
        }
    }

    /// <summary>The Content-ID without angle brackets, or null.</summary>
    public string? ContentId
    {
        get
        {
            if (!Headers.TryGetFirst(HeaderId.ContentId, out var h))
            {
                return null;
            }

            string v = h.GetValue(1024).Trim();
            if (v.Length >= 2 && v[0] == '<' && v[^1] == '>')
            {
                v = v[1..^1].Trim();
            }

            return v.Length == 0 ? null : v;
        }
    }

    /// <summary>The file name from Content-Disposition <c>filename</c> or Content-Type <c>name</c>, or null.</summary>
    public string? FileName => Disposition?.FileName ?? ContentType.Name;

    /// <summary>True when the entity is marked as an attachment, or is a non-text, non-multipart leaf with a file name.</summary>
    public bool IsAttachment =>
        Disposition is { IsAttachment: true }
        || (!ContentType.IsMultipart && !ContentType.IsText && FileName is not null && Disposition is not { IsInline: true });

    /// <summary>Enumerates this entity and all descendants depth-first, parents before children (iterative; no recursion).</summary>
    public IEnumerable<MimePart> EnumerateParts()
    {
        var stack = new Stack<MimePart>();
        stack.Push(this);
        while (stack.Count > 0)
        {
            var p = stack.Pop();
            yield return p;
            for (int i = p._children.Length - 1; i >= 0; i--)
            {
                stack.Push(p._children[i]);
            }
        }
    }

    /// <summary>
    /// Decodes the body per Content-Transfer-Encoding into <paramref name="writer"/>, writing at most
    /// <paramref name="maxBytes"/> bytes (default: <see cref="MimeLimits.MaxDecodedBytes"/>). Never throws for malformed data.
    /// </summary>
    public DecodeResult DecodeBodyTo(IBufferWriter<byte> writer, long? maxBytes = null) =>
        BodyDecoder.Decode(Body.Span, EffectiveEncoding, writer, Math.Min(maxBytes ?? _limits.MaxDecodedBytes, _limits.MaxDecodedBytes));

    /// <summary>The decoded body bytes (bounded by <paramref name="maxBytes"/> / the limit).</summary>
    public byte[] GetDecodedBytes(long? maxBytes = null)
    {
        var writer = new ArrayBufferWriter<byte>(Math.Clamp(Body.Length, 256, 64 * 1024));
        DecodeBodyTo(writer, maxBytes);
        return writer.WrittenSpan.ToArray();
    }

    /// <summary>The decoded size of the body in bytes, computed without keeping the content.</summary>
    public long GetDecodedLength() => BodyDecoder.Measure(Body.Span, EffectiveEncoding, _limits.MaxDecodedBytes).BytesWritten;

    /// <summary>
    /// The decoded body as text in the part's charset (UTF-16 string). At most <paramref name="maxBytes"/> decoded bytes
    /// are used; <paramref name="truncated"/> tells whether the content was longer. Unknown charsets fall back to UTF-8 / windows-1252.
    /// </summary>
    public string GetText(long maxBytes, out bool truncated)
    {
        var an = MimeAnomaly.None;
        return GetText(maxBytes, out truncated, ref an);
    }

    /// <summary>Like <see cref="GetText(long, out bool)"/> and additionally accumulates charset/transfer anomalies.</summary>
    public string GetText(long maxBytes, out bool truncated, ref MimeAnomaly anomalies)
    {
        long cap = Math.Min(maxBytes, _limits.MaxDecodedBytes);
        var enc = EffectiveEncoding;
        string text;
        if (enc is ContentTransferEncoding.SevenBit or ContentTransferEncoding.EightBit or ContentTransferEncoding.Binary or ContentTransferEncoding.Unknown)
        {
            var span = Body.Span;
            truncated = span.Length > cap;
            if (truncated)
            {
                span = span[..(int)cap];
            }

            if (enc == ContentTransferEncoding.Unknown)
            {
                anomalies |= MimeAnomaly.UnknownTransferEncoding;
            }

            text = MimeCharsets.Decode(span, ContentType.Charset, ref anomalies);
        }
        else
        {
            var writer = new ArrayBufferWriter<byte>(Math.Clamp(Body.Length, 256, 64 * 1024));
            var result = BodyDecoder.Decode(Body.Span, enc, writer, cap);
            truncated = result.Truncated;
            anomalies |= result.Anomalies;
            text = MimeCharsets.Decode(writer.WrittenSpan, ContentType.Charset, ref anomalies);
        }

        if (truncated)
        {
            anomalies |= MimeAnomaly.DecodedSizeLimit;
            if (text.Length > 0 && text[^1] == '�')
            {
                text = text[..^1];
            }
        }

        return text;
    }

    private ContentTransferEncoding EffectiveEncoding =>
        ContentType.IsMultipart || ContentType.MediaType == "message" ? ContentTransferEncoding.Binary : TransferEncoding;

    /// <inheritdoc />
    public override string ToString() => $"{ContentType.MimeType} ({Raw.Length} bytes)";
}

/// <summary>
/// A parsed message: the root <see cref="MimePart"/> and everything found while parsing. Parsing is bounded by
/// <see cref="MimeLimits"/>, linear in the input (times the nesting depth) and never throws for content problems.
/// </summary>
public sealed class MimeMessage
{
    private MimeMessage(MimePart root, int partCount, MimeAnomaly anomalies)
    {
        Root = root;
        PartCount = partCount;
        Anomalies = anomalies;
    }

    /// <summary>The top-level entity (its <see cref="MimePart.Headers"/> are the message headers).</summary>
    public MimePart Root { get; }

    /// <summary>The message header fields.</summary>
    public HeaderList Headers => Root.Headers;

    /// <summary>The limits this message was parsed with.</summary>
    internal MimeLimits Limits => Root.Limits;

    /// <summary>The raw message bytes that were parsed.</summary>
    public ReadOnlyMemory<byte> Raw => Root.Raw;

    /// <summary>Number of entities that were created.</summary>
    public int PartCount { get; }

    /// <summary>Union of the anomalies of all entities.</summary>
    public MimeAnomaly Anomalies { get; }

    /// <summary>Enumerates all entities depth-first.</summary>
    public IEnumerable<MimePart> EnumerateParts() => Root.EnumerateParts();

    /// <summary>Parses a message (or any RFC 5322 entity).</summary>
    public static MimeMessage Parse(ReadOnlyMemory<byte> raw, MimeLimits? limits = null)
    {
        var builder = new TreeBuilder(limits ?? MimeLimits.Default);
        var root = builder.ParsePart(raw, null, 0, ContentType.Default);
        return new MimeMessage(root, builder.PartCount, builder.Anomalies);
    }

    private sealed class TreeBuilder
    {
        private readonly MimeLimits _limits;

        public TreeBuilder(MimeLimits limits) => _limits = limits;

        public int PartCount { get; private set; }

        public MimeAnomaly Anomalies { get; private set; }

        public MimePart ParsePart(ReadOnlyMemory<byte> region, MimePart? parent, int depth, ContentType defaultType)
        {
            PartCount++;
            var headers = HeaderList.Parse(region, _limits);
            var an = headers.Anomalies;

            var contentType = defaultType;
            if (headers.TryGetFirst(HeaderId.ContentType, out var ctHeader))
            {
                contentType = ContentType.Parse(ctHeader.GetValue(_limits.MaxHeaderValueBytes), _limits);
                an |= contentType.Anomalies;
            }

            var cte = ContentTransferEncoding.SevenBit;
            if (headers.TryGetFirst(HeaderId.ContentTransferEncoding, out var cteHeader))
            {
                cte = ContentTransferEncodings.Parse(cteHeader.GetValue(256));
                if (cte == ContentTransferEncoding.Unknown)
                {
                    an |= MimeAnomaly.UnknownTransferEncoding;
                }
            }

            var part = new MimePart(_limits, parent, depth, headers, contentType, cte, an);
            if (contentType.IsMultipart)
            {
                SplitMultipart(part);
            }
            else if (contentType.IsEmbeddedMessage
                     && cte is ContentTransferEncoding.SevenBit or ContentTransferEncoding.EightBit or ContentTransferEncoding.Binary)
            {
                if (depth >= _limits.MaxDepth)
                {
                    part.Anomalies |= MimeAnomaly.MaxDepthExceeded;
                }
                else if (PartCount >= _limits.MaxParts)
                {
                    part.Anomalies |= MimeAnomaly.TooManyParts;
                }
                else
                {
                    var inner = ParsePart(part.Body, part, depth + 1, ContentType.Default);
                    part.SetChildren([inner]);
                }
            }

            Anomalies |= part.Anomalies;
            return part;
        }

        private void SplitMultipart(MimePart part)
        {
            var ct = part.ContentType;
            string? boundary = ct.Boundary;
            if (part.Depth >= _limits.MaxDepth)
            {
                part.Anomalies |= MimeAnomaly.MaxDepthExceeded;
                return;
            }

            if (string.IsNullOrEmpty(boundary) || boundary.Length > _limits.MaxBoundaryLength || HasLineBreak(boundary))
            {
                part.Anomalies |= MimeAnomaly.MissingBoundary;
                return;
            }

            for (var anc = part.Parent; anc is not null; anc = anc.Parent)
            {
                if (anc.ContentType.IsMultipart && string.Equals(anc.ContentType.Boundary, boundary, StringComparison.Ordinal))
                {
                    part.Anomalies |= MimeAnomaly.DuplicateBoundary;
                    return;
                }
            }

            var delimiter = Encoding.UTF8.GetBytes("--" + boundary);
            var body = part.Body;
            var span = body.Span;
            if (!FindDelimiter(span, 0, delimiter, out int lineStart, out int afterLine, out bool isClose))
            {
                part.Anomalies |= MimeAnomaly.MissingCloseDelimiter;
                part.Preamble = body;
                return;
            }

            part.Preamble = body[..TrimEol(span, 0, lineStart)];
            var children = new List<MimePart>();
            while (true)
            {
                if (isClose)
                {
                    part.Epilogue = body[afterLine..];
                    break;
                }

                if (PartCount >= _limits.MaxParts)
                {
                    part.Anomalies |= MimeAnomaly.TooManyParts;
                    break;
                }

                int childStart = afterLine;
                bool found = FindDelimiter(span, childStart, delimiter, out int nextLineStart, out int nextAfterLine, out bool nextClose);
                int childEnd = found ? TrimEol(span, childStart, nextLineStart) : span.Length;
                children.Add(ParsePart(body[childStart..childEnd], part, part.Depth + 1, DefaultChildType(ct)));
                if (!found)
                {
                    part.Anomalies |= MimeAnomaly.MissingCloseDelimiter;
                    break;
                }

                lineStart = nextLineStart;
                afterLine = nextAfterLine;
                isClose = nextClose;
            }

            part.SetChildren(children.ToArray());
        }

        private static ContentType DefaultChildType(ContentType parent) =>
            parent.MediaSubtype == "digest" ? ContentType.DigestDefault : ContentType.Default;

        private static bool HasLineBreak(string s) => s.AsSpan().IndexOfAny('\r', '\n') >= 0;

        /// <summary>End index of the content before a delimiter line starting at <paramref name="delimiterStart"/>: the line ending that belongs to the delimiter is excluded.</summary>
        private static int TrimEol(ReadOnlySpan<byte> span, int contentStart, int delimiterStart)
        {
            int end = delimiterStart;
            if (end > contentStart && span[end - 1] == (byte)'\n')
            {
                end--;
                if (end > contentStart && span[end - 1] == (byte)'\r')
                {
                    end--;
                }
            }

            return end;
        }

        /// <summary>
        /// Finds the next delimiter line (<c>--boundary</c> or <c>--boundary--</c> followed by optional whitespace and a
        /// line end) at or after <paramref name="from"/>, which must be the start of a line. Linear: candidate lines are located
        /// by searching for the 3-byte sequence LF "--".
        /// </summary>
        private static bool FindDelimiter(ReadOnlySpan<byte> span, int from, ReadOnlySpan<byte> delimiter, out int lineStart, out int afterLine, out bool isClose)
        {
            lineStart = afterLine = 0;
            isClose = false;
            int i = from;
            while (i <= span.Length)
            {
                if (span.Length - i >= delimiter.Length && span.Slice(i, delimiter.Length).SequenceEqual(delimiter))
                {
                    int j = i + delimiter.Length;
                    bool close = false;
                    if (j + 1 < span.Length && span[j] == (byte)'-' && span[j + 1] == (byte)'-')
                    {
                        close = true;
                        j += 2;
                    }

                    int k = j;
                    while (k < span.Length && span[k] is (byte)' ' or (byte)'\t')
                    {
                        k++;
                    }

                    if (k == span.Length)
                    {
                        lineStart = i;
                        afterLine = k;
                        isClose = close;
                        return true;
                    }

                    if (span[k] == (byte)'\n')
                    {
                        lineStart = i;
                        afterLine = k + 1;
                        isClose = close;
                        return true;
                    }

                    if (span[k] == (byte)'\r' && k + 1 < span.Length && span[k + 1] == (byte)'\n')
                    {
                        lineStart = i;
                        afterLine = k + 2;
                        isClose = close;
                        return true;
                    }
                }

                if (i >= span.Length)
                {
                    break;
                }

                int rel = span[i..].IndexOf("\n--"u8);
                if (rel < 0)
                {
                    return false;
                }

                i += rel + 1;
            }

            return false;
        }
    }
}
