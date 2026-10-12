using System.Buffers;
using System.Text;
using Mta.Core;

namespace Mta.Mime;

/// <summary>
/// Allow and deny lists for caller-supplied (custom) headers. Names are compared case-insensitively. A name must pass
/// the deny list and, when the allow list is not empty, appear on the allow list. Entries ending in <c>*</c> are prefixes
/// (<c>X-Mta-*</c>).
/// </summary>
public sealed class HeaderPolicy
{
    private static readonly string[] DefaultDenied =
    [
        "From", "Sender", "To", "Cc", "Bcc", "Reply-To", "Subject", "Date", "Message-ID", "MIME-Version",
        "Content-Type", "Content-Transfer-Encoding", "Content-Disposition", "Content-ID", "Content-Description", "Content-Length",
        "Return-Path", "Received", "DKIM-Signature", "Authentication-Results", "ARC-Seal", "ARC-Message-Signature",
        "ARC-Authentication-Results", "Resent-*", "In-Reply-To", "References", "X-Mta-*",
    ];

    private readonly List<string> _allowed = [];
    private readonly List<string> _denied = [];

    /// <summary>The default policy: everything except headers the builder owns and trace/authentication headers.</summary>
    public static HeaderPolicy Default => new();

    /// <summary>Creates a policy with the default deny list.</summary>
    public HeaderPolicy() => _denied.AddRange(DefaultDenied);

    /// <summary>A policy that denies nothing (use with care: callers could then inject trace headers).</summary>
    public static HeaderPolicy AllowAll()
    {
        var policy = new HeaderPolicy();
        policy._denied.Clear();
        return policy;
    }

    /// <summary>Names (or <c>prefix*</c>) that are allowed; empty means "anything not denied".</summary>
    public IList<string> Allowed => _allowed;

    /// <summary>Names (or <c>prefix*</c>) that are refused.</summary>
    public IList<string> Denied => _denied;

    /// <summary>True when a custom header with this name may be added.</summary>
    public bool IsAllowed(string name)
    {
        foreach (string d in _denied)
        {
            if (Matches(d, name))
            {
                return false;
            }
        }

        if (_allowed.Count == 0)
        {
            return true;
        }

        foreach (string a in _allowed)
        {
            if (Matches(a, name))
            {
                return true;
            }
        }

        return false;
    }

    private static bool Matches(string pattern, string name) =>
        pattern.EndsWith('*')
            ? name.StartsWith(pattern.AsSpan(0, pattern.Length - 1), StringComparison.OrdinalIgnoreCase)
            : string.Equals(pattern, name, StringComparison.OrdinalIgnoreCase);
}

/// <summary>Settings for <see cref="MessageBuilder"/>.</summary>
public sealed class MessageBuilderOptions
{
    /// <summary>Domain used for generated Message-ID and Content-ID values (a valid host name; typically the sending domain).</summary>
    public string MessageIdDomain { get; init; } = "localhost";

    /// <summary>Time source for the Date header and Message-ID timestamps.</summary>
    public IClock Clock { get; init; } = SystemClock.Instance;

    /// <summary>Which custom headers callers may add.</summary>
    public HeaderPolicy HeaderPolicy { get; init; } = HeaderPolicy.Default;

    /// <summary>Write non-ASCII header text as raw UTF-8 (RFC 6532, needs SMTPUTF8) instead of RFC 2047 encoded words.</summary>
    public bool AllowUtf8Headers { get; init; }

    /// <summary>Write non-ASCII text bodies as 8bit (needs 8BITMIME) instead of quoted-printable or base64.</summary>
    public bool Allow8BitBody { get; init; }
}

/// <summary>A file attached to, or an inline resource embedded in, a built message.</summary>
public sealed class BuilderAttachment
{
    /// <summary>Creates an attachment. Directory parts of <paramref name="fileName"/> are removed.</summary>
    /// <exception cref="HeaderInjectionException">The file name or content type contains CR, LF or NUL.</exception>
    /// <exception cref="ArgumentException">The content type is not a valid non-multipart type.</exception>
    public BuilderAttachment(string fileName, string contentType, ReadOnlyMemory<byte> content)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        ArgumentNullException.ThrowIfNull(contentType);
        HeaderValidator.ValidateValue("filename", fileName, allowNonAscii: true);
        HeaderValidator.ValidateValue("Content-Type", contentType, allowNonAscii: false);
        int slash = fileName.AsSpan().LastIndexOfAny('/', '\\');
        string name = slash >= 0 ? fileName[(slash + 1)..] : fileName;
        FileName = name.Length == 0 ? "attachment" : name;
        var parsed = ContentType.Parse(contentType);
        if ((parsed.Anomalies & MimeAnomaly.InvalidContentType) != 0 || parsed.IsMultipart)
        {
            throw new ArgumentException("Attachment content type must be a valid, non-multipart type/subtype: " + contentType, nameof(contentType));
        }

        ContentType = parsed;
        Content = content;
    }

    /// <summary>The file name without directory.</summary>
    public string FileName { get; }

    /// <summary>The attachment's media type (parameters other than charset/name are dropped when written).</summary>
    public ContentType ContentType { get; }

    /// <summary>The bytes.</summary>
    public ReadOnlyMemory<byte> Content { get; }

    /// <summary>Content-ID without angle brackets; generated for inline resources when null.</summary>
    public string? ContentId { get; init; }

    /// <summary>True to embed the resource next to the HTML body (multipart/related) and reference it by Content-ID.</summary>
    public bool IsInline { get; init; }
}

/// <summary>The identity of a message that was just composed.</summary>
/// <param name="MessageId">The Message-ID header value including angle brackets.</param>
/// <param name="Date">The value written to the Date header.</param>
/// <param name="Length">Bytes written.</param>
public readonly record struct BuiltMessage(string MessageId, DateTimeOffset Date, long Length);

/// <summary>
/// Composes RFC 5322 / MIME messages from a model: addresses, subject (RFC 2047), text and/or HTML (multipart/alternative),
/// attachments (multipart/mixed), inline resources (multipart/related), custom headers under a <see cref="HeaderPolicy"/>.
/// Output uses CRLF line endings, folds headers at 78 columns, never emits a line over 998 bytes (bodies are quoted-printable
/// or base64 encoded when needed) and rejects header injection with <see cref="HeaderInjectionException"/>.
/// Bcc recipients are an envelope concern: they are not written unless <see cref="IncludeBccHeader"/> is set.
/// </summary>
public sealed class MessageBuilder
{
    private readonly MessageBuilderOptions _options;
    private readonly List<(string Name, string Value)> _customHeaders = [];
    private bool _endsWithCrlf = true;

    /// <summary>Creates a builder.</summary>
    public MessageBuilder(MessageBuilderOptions? options = null) => _options = options ?? new MessageBuilderOptions();

    /// <summary>The From mailbox (required).</summary>
    public Mailbox? From { get; set; }

    /// <summary>Optional Sender mailbox.</summary>
    public Mailbox? Sender { get; set; }

    /// <summary>To recipients.</summary>
    public IList<Mailbox> To { get; } = new List<Mailbox>();

    /// <summary>Cc recipients.</summary>
    public IList<Mailbox> Cc { get; } = new List<Mailbox>();

    /// <summary>Bcc recipients; only written when <see cref="IncludeBccHeader"/> is true.</summary>
    public IList<Mailbox> Bcc { get; } = new List<Mailbox>();

    /// <summary>Reply-To mailboxes.</summary>
    public IList<Mailbox> ReplyTo { get; } = new List<Mailbox>();

    /// <summary>Write a Bcc header (for drafts); default false.</summary>
    public bool IncludeBccHeader { get; set; }

    /// <summary>The subject (unstructured text; encoded as needed).</summary>
    public string? Subject { get; set; }

    /// <summary>The plain-text body.</summary>
    public string? TextBody { get; set; }

    /// <summary>The HTML body.</summary>
    public string? HtmlBody { get; set; }

    /// <summary>Message-ID to use (with or without angle brackets); generated when null.</summary>
    public string? MessageId { get; set; }

    /// <summary>Date to use; the options' clock when null.</summary>
    public DateTimeOffset? Date { get; set; }

    /// <summary>In-Reply-To message id (with or without angle brackets).</summary>
    public string? InReplyTo { get; set; }

    /// <summary>References message ids (with or without angle brackets).</summary>
    public IList<string> References { get; } = new List<string>();

    /// <summary>Attachments and inline resources.</summary>
    public IList<BuilderAttachment> Attachments { get; } = new List<BuilderAttachment>();

    /// <summary>The custom headers added so far.</summary>
    public IReadOnlyList<(string Name, string Value)> CustomHeaders => _customHeaders;

    /// <summary>Generates a Message-ID of the form <c>&lt;uuidv7@domain&gt;</c> with the project's time-ordered id.</summary>
    public static string GenerateMessageId(string domain, IClock? clock = null)
    {
        ArgumentNullException.ThrowIfNull(domain);
        if (!EmailAddress.IsValidHostName(domain))
        {
            throw new MessageBuildException("Invalid Message-ID domain: " + domain);
        }

        var id = Ids.New((clock ?? SystemClock.Instance).UtcNow);
        return $"<{Ids.ToCompact(id)}@{domain}>";
    }

    /// <summary>Adds a custom header after checking it against the policy.</summary>
    /// <exception cref="HeaderInjectionException">The name or value contains CR, LF, NUL or other forbidden characters.</exception>
    /// <exception cref="MessageBuildException">The header is not allowed by the policy.</exception>
    public void AddHeader(string name, string value)
    {
        HeaderValidator.ValidateName(name);
        HeaderValidator.ValidateValue(name, value, allowNonAscii: true);
        if (!_options.HeaderPolicy.IsAllowed(name))
        {
            throw new MessageBuildException($"Header '{name}' is not allowed by the header policy.");
        }

        _customHeaders.Add((name, value));
    }

    /// <summary>Builds the message into memory.</summary>
    public (byte[] Content, BuiltMessage Info) Build()
    {
        var writer = new ArrayBufferWriter<byte>(8192);
        var info = WriteTo(writer);
        return (writer.WrittenSpan.ToArray(), info);
    }

    /// <summary>Builds the message into <paramref name="writer"/>.</summary>
    /// <exception cref="MessageBuildException">The model is incomplete or cannot be represented (no From, bad domain, unfoldable token ...).</exception>
    /// <exception cref="HeaderInjectionException">Any header text contains CR, LF, NUL or other control characters.</exception>
    public BuiltMessage WriteTo(IBufferWriter<byte> writer)
    {
        ArgumentNullException.ThrowIfNull(writer);
        if (From is null)
        {
            throw new MessageBuildException("A message needs a From mailbox.");
        }

        bool utf8 = _options.AllowUtf8Headers;
        var now = _options.Clock.UtcNow;
        var date = Date ?? now;
        string messageId = MessageId is null ? GenerateMessageId(_options.MessageIdDomain, _options.Clock) : NormalizeMessageId(MessageId);

        var h = new StringBuilder(512);
        HeaderFolder.AppendField(h, HeaderNames.Date, MimeDate.Format(date));
        HeaderFolder.AppendField(h, HeaderNames.From, From.ToHeaderValue(utf8), utf8);
        if (Sender is not null)
        {
            HeaderFolder.AppendField(h, HeaderNames.Sender, Sender.ToHeaderValue(utf8), utf8);
        }

        AppendMailboxes(h, HeaderNames.ReplyTo, ReplyTo, utf8);
        AppendMailboxes(h, HeaderNames.To, To, utf8);
        AppendMailboxes(h, HeaderNames.Cc, Cc, utf8);
        if (IncludeBccHeader)
        {
            AppendMailboxes(h, HeaderNames.Bcc, Bcc, utf8);
        }

        if (Subject is not null)
        {
            HeaderValidator.ValidateValue(HeaderNames.Subject, Subject, allowNonAscii: true);
            string subject = utf8 ? Subject : Rfc2047.Encode(Subject);
            HeaderFolder.AppendField(h, HeaderNames.Subject, subject, utf8);
        }

        HeaderFolder.AppendField(h, HeaderNames.MessageId, messageId);
        if (InReplyTo is not null)
        {
            HeaderFolder.AppendField(h, HeaderNames.InReplyTo, NormalizeMessageId(InReplyTo));
        }

        if (References.Count > 0)
        {
            var refs = new StringBuilder();
            foreach (string r in References)
            {
                if (refs.Length > 0)
                {
                    refs.Append(' ');
                }

                refs.Append(NormalizeMessageId(r));
            }

            HeaderFolder.AppendField(h, HeaderNames.References, refs.ToString());
        }

        foreach (var (name, value) in _customHeaders)
        {
            string v = utf8 ? value : Rfc2047.Encode(value);
            HeaderFolder.AppendField(h, name, v, utf8);
        }

        HeaderFolder.AppendField(h, HeaderNames.MimeVersion, "1.0");
        long total = Emit(writer, h.ToString());

        _endsWithCrlf = true;
        var root = BuildStructure();
        total += WriteEntity(writer, root);
        if (!_endsWithCrlf)
        {
            total += Emit(writer, "\r\n");
        }

        return new BuiltMessage(messageId, date, total);
    }

    // ---------------------------------------------------------------- structure

    private abstract class Node
    {
    }

    private sealed class TextNode(string subtype, string text) : Node
    {
        public string Subtype { get; } = subtype;

        public string Text { get; } = text;
    }

    private sealed class BinaryNode(BuilderAttachment attachment, string? contentId) : Node
    {
        public BuilderAttachment Attachment { get; } = attachment;

        public string? ContentId { get; } = contentId;
    }

    private sealed class MultipartNode(string subtype, List<Node> children) : Node
    {
        public string Subtype { get; } = subtype;

        public List<Node> Children { get; } = children;
    }

    private Node BuildStructure()
    {
        var inlines = new List<BinaryNode>();
        var regular = new List<BinaryNode>();
        foreach (var a in Attachments)
        {
            string? id = a.ContentId;
            if (id is not null)
            {
                id = NormalizeContentId(id);
            }

            if (a.IsInline && HtmlBody is not null)
            {
                inlines.Add(new BinaryNode(a, id ?? NormalizeContentId(GenerateContentId())));
            }
            else
            {
                regular.Add(new BinaryNode(a, id));
            }
        }

        Node? body = null;
        Node? html = HtmlBody is null ? null : new TextNode("html", HtmlBody);
        if (html is not null && inlines.Count > 0)
        {
            var related = new List<Node> { html };
            related.AddRange(inlines);
            html = new MultipartNode("related", related);
        }

        if (TextBody is not null && html is not null)
        {
            body = new MultipartNode("alternative", [new TextNode("plain", TextBody), html]);
        }
        else if (html is not null)
        {
            body = html;
        }
        else if (TextBody is not null)
        {
            body = new TextNode("plain", TextBody);
        }
        else if (regular.Count == 0)
        {
            body = new TextNode("plain", string.Empty);
        }

        if (regular.Count == 0)
        {
            return body!;
        }

        var mixed = new List<Node>();
        if (body is not null)
        {
            mixed.Add(body);
        }

        mixed.AddRange(regular);
        return new MultipartNode("mixed", mixed);
    }

    private string GenerateContentId() => $"{Ids.ToCompact(Ids.New(_options.Clock.UtcNow))}@{_options.MessageIdDomain}";

    private static string NormalizeContentId(string id)
    {
        id = id.Trim();
        if (id.Length >= 2 && id[0] == '<' && id[^1] == '>')
        {
            id = id[1..^1];
        }

        ValidateIdToken("Content-ID", id);
        return id;
    }

    private static string NormalizeMessageId(string id)
    {
        id = id.Trim();
        if (id.Length >= 2 && id[0] == '<' && id[^1] == '>')
        {
            id = id[1..^1];
        }

        ValidateIdToken("Message-ID", id);
        return "<" + id + ">";
    }

    private static void ValidateIdToken(string header, string id)
    {
        if (id.Length == 0 || id.Length > 255)
        {
            throw new MessageBuildException($"{header} must be 1 to 255 characters.");
        }

        HeaderValidator.ValidateValue(header, id, allowNonAscii: false);
        foreach (char c in id)
        {
            if (c is ' ' or '\t' or '<' or '>' or '(' or ')' or '"' or '\\' or ',' or ';' or ':')
            {
                throw new MessageBuildException($"{header} contains a character that is not allowed: '{c}'.");
            }
        }
    }

    private static void AppendMailboxes(StringBuilder h, string name, IList<Mailbox> mailboxes, bool utf8)
    {
        if (mailboxes.Count == 0)
        {
            return;
        }

        var value = new StringBuilder();
        foreach (var m in mailboxes)
        {
            if (value.Length > 0)
            {
                value.Append(", ");
            }

            value.Append(m.ToHeaderValue(utf8));
        }

        HeaderFolder.AppendField(h, name, value.ToString(), utf8);
    }

    // ---------------------------------------------------------------- serialization

    private long Emit(IBufferWriter<byte> writer, string text)
    {
        int count = Encoding.UTF8.GetByteCount(text);
        var span = writer.GetSpan(count);
        int n = Encoding.UTF8.GetBytes(text, span);
        writer.Advance(n);
        if (n > 0)
        {
            _endsWithCrlf = text.EndsWith("\r\n", StringComparison.Ordinal);
        }

        return n;
    }

    private long Emit(IBufferWriter<byte> writer, ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > 0)
        {
            LineEndings.Write(writer, bytes);
            _endsWithCrlf = bytes.Length >= 2 && bytes[^2] == (byte)'\r' && bytes[^1] == (byte)'\n';
        }

        return bytes.Length;
    }

    /// <summary>Writes the entity's own headers, a blank line and the body. The caller has already written any preceding headers.</summary>
    private long WriteEntity(IBufferWriter<byte> writer, Node node)
    {
        switch (node)
        {
            case TextNode t:
                return WriteText(writer, t);
            case BinaryNode b:
                return WriteBinary(writer, b);
            case MultipartNode m:
                return WriteMultipart(writer, m);
            default:
                throw new InvalidOperationException();
        }
    }

    private long WriteText(IBufferWriter<byte> writer, TextNode node)
    {
        byte[] bytes = LineEndings.ToCrlf(Encoding.UTF8.GetBytes(node.Text));
        var cte = TransferEncoder.ChooseForText(bytes, _options.Allow8BitBody);
        bool ascii = System.Text.Ascii.IsValid(bytes);
        var h = new StringBuilder();
        HeaderFolder.AppendField(h, HeaderNames.ContentType, $"text/{node.Subtype}; charset={(ascii && cte == ContentTransferEncoding.SevenBit ? "us-ascii" : "utf-8")}");
        HeaderFolder.AppendField(h, HeaderNames.ContentTransferEncoding, cte.ToToken());
        h.Append("\r\n");
        long n = Emit(writer, h.ToString());
        switch (cte)
        {
            case ContentTransferEncoding.QuotedPrintable:
                {
                    var tmp = new ArrayBufferWriter<byte>(bytes.Length + 64);
                    TransferEncoder.WriteQuotedPrintable(bytes, tmp);
                    n += Emit(writer, tmp.WrittenSpan);
                    break;
                }

            case ContentTransferEncoding.Base64:
                {
                    var tmp = new ArrayBufferWriter<byte>((bytes.Length * 4 / 3) + 64);
                    TransferEncoder.WriteBase64(bytes, tmp);
                    n += Emit(writer, tmp.WrittenSpan);
                    break;
                }

            default:
                n += Emit(writer, bytes);
                break;
        }

        return n;
    }

    private long WriteBinary(IBufferWriter<byte> writer, BinaryNode node)
    {
        var a = node.Attachment;
        var h = new StringBuilder();
        var ct = new StringBuilder(a.ContentType.MimeType);
        ParameterFormatter.Append(ct, "name", a.FileName);
        HeaderFolder.AppendField(h, HeaderNames.ContentType, ct.ToString(), allowNonAscii: false);
        HeaderFolder.AppendField(h, HeaderNames.ContentTransferEncoding, "base64");
        var disp = new StringBuilder(a.IsInline && node.ContentId is not null ? "inline" : "attachment");
        ParameterFormatter.Append(disp, "filename", a.FileName);
        HeaderFolder.AppendField(h, HeaderNames.ContentDisposition, disp.ToString(), allowNonAscii: false);
        if (node.ContentId is not null)
        {
            HeaderFolder.AppendField(h, HeaderNames.ContentId, "<" + node.ContentId + ">");
        }

        h.Append("\r\n");
        long n = Emit(writer, h.ToString());
        var tmp = new ArrayBufferWriter<byte>((a.Content.Length * 4 / 3) + 128);
        TransferEncoder.WriteBase64(a.Content.Span, tmp);
        n += Emit(writer, tmp.WrittenSpan);
        return n;
    }

    private long WriteMultipart(IBufferWriter<byte> writer, MultipartNode node)
    {
        string boundary = NewBoundary();
        var h = new StringBuilder();
        var ct = new StringBuilder("multipart/" + node.Subtype);
        ParameterFormatter.Append(ct, "boundary", boundary);
        HeaderFolder.AppendField(h, HeaderNames.ContentType, ct.ToString());
        h.Append("\r\n");
        long n = Emit(writer, h.ToString());
        bool first = true;
        foreach (var child in node.Children)
        {
            n += Emit(writer, first ? "--" + boundary + "\r\n" : "\r\n--" + boundary + "\r\n");
            first = false;
            n += WriteEntity(writer, child);
        }

        n += Emit(writer, "\r\n--" + boundary + "--\r\n");
        return n;
    }

    private static string NewBoundary() => "=_EggMail_" + Guid.NewGuid().ToString("N");
}
