using System.Buffers;
using System.Text;

namespace Mta.Smtp.Protocol;

/// <summary>
/// An SMTP reply (RFC 5321 §4.2): a three-digit code, an optional enhanced status code (RFC 2034) and one or more
/// text lines. Instances are immutable; constant replies are pre-rendered once and reused without allocation.
/// </summary>
public sealed class SmtpReply
{
    private readonly byte[]? _wire;

    // A reply is held as a list of lines, or, for the common single-line reply, as just its text, or its fixed text and an id: the list (and the text of
    // an id reply) is only made when somebody asks for it. The reply of every accepted message is one of these, and is created per message.
    private IReadOnlyList<string>? _lines;
    private readonly string? _text;
    private readonly Guid _id;

    public int Code { get; }

    /// <summary>Enhanced status such as <c>2.1.0</c>, or null.</summary>
    public string? EnhancedCode { get; }

    public IReadOnlyList<string> Lines => _lines ??= [_text is { } text ? text : string.Concat(_prefix, _id.ToString("N"))];

    private readonly string? _prefix;

    /// <summary>True for 4yz replies (transient failure).</summary>
    public bool IsTransient => Code is >= 400 and < 500;

    /// <summary>True for 5yz replies (permanent failure).</summary>
    public bool IsPermanent => Code is >= 500 and < 600;

    public bool IsPositive => Code is >= 200 and < 400;

    public bool IsPositiveCompletion => Code is >= 200 and < 300;

    public bool IsIntermediate => Code is >= 300 and < 400;

    public SmtpReply(int code, string? enhancedCode, IReadOnlyList<string> lines)
    {
        if (code is < 200 or > 599)
        {
            throw new ArgumentOutOfRangeException(nameof(code));
        }

        if (lines.Count == 0)
        {
            throw new ArgumentException("A reply needs at least one line.", nameof(lines));
        }

        for (int i = 0; i < lines.Count; i++)   // by index: enumerating an IReadOnlyList allocates its enumerator
        {
            if (lines[i].AsSpan().IndexOfAny('\r', '\n', '\0') >= 0)
            {
                throw new ArgumentException("Reply text must not contain CR, LF or NUL.", nameof(lines));
            }
        }

        Code = code;
        EnhancedCode = enhancedCode;
        _lines = lines;
    }

    private SmtpReply(int code, string? enhancedCode, string text, string? prefix, Guid id)
    {
        if (code is < 200 or > 599)
        {
            throw new ArgumentOutOfRangeException(nameof(code));
        }

        if (text.AsSpan().IndexOfAny('\r', '\n', '\0') >= 0 || (prefix is not null && prefix.AsSpan().IndexOfAny('\r', '\n', '\0') >= 0))
        {
            throw new ArgumentException("Reply text must not contain CR, LF or NUL.", nameof(text));
        }

        Code = code;
        EnhancedCode = enhancedCode;
        _text = prefix is null ? text : null;
        _prefix = prefix;
        _id = id;
    }

    private SmtpReply(int code, string? enhanced, string line, bool prerender) : this(code, enhanced, [line])
    {
        if (prerender)
        {
            var ms = new ArrayBufferWriter<byte>(line.Length + 16);
            WriteTo(ms);
            _wire = ms.WrittenSpan.ToArray();
        }
    }

    /// <summary>Creates a single-line reply. Pass <paramref name="enhanced"/> as null when ENHANCEDSTATUSCODES is not in use.</summary>
    public static SmtpReply Create(int code, string? enhanced, string text) => new(code, enhanced, text, null, default);

    /// <summary>
    /// Creates the single-line reply <c>prefix</c> + the id as 32 hex digits (<c>"Queued as "</c> + the message id), without building that text: it is written straight to
    /// the wire, and made only if a caller reads <see cref="Lines"/>.
    /// </summary>
    public static SmtpReply CreateWithId(int code, string? enhanced, string prefix, Guid id) => new(code, enhanced, "", prefix, id);

    /// <summary>Creates a constant reply whose wire form is rendered once.</summary>
    public static SmtpReply Constant(int code, string? enhanced, string text) => new(code, enhanced, text, prerender: true);

    /// <summary>Writes the reply in wire format (<c>250-text\r\n250 text\r\n</c>).</summary>
    public void WriteTo(IBufferWriter<byte> writer, bool includeEnhanced = true)
    {
        if (_wire is not null && includeEnhanced)
        {
            writer.Write(_wire);
            return;
        }

        string? enhanced = includeEnhanced ? EnhancedCode : null;
        if (_lines is null)
        {
            WriteSingleLine(writer, enhanced);
            return;
        }

        var lines = _lines;
        for (int i = 0; i < lines.Count; i++)
        {
            bool last = i == lines.Count - 1;
            string text = lines[i];
            int max = 3 + 1 + (enhanced?.Length + 1 ?? 0) + Encoding.UTF8.GetMaxByteCount(text.Length) + 2;
            var span = writer.GetSpan(max);
            int p = WriteStart(span, last, enhanced);
            p += Encoding.UTF8.GetBytes(text, span[p..]);
            span[p++] = (byte)'\r';
            span[p++] = (byte)'\n';
            writer.Advance(p);
        }
    }

    private void WriteSingleLine(IBufferWriter<byte> writer, string? enhanced)
    {
        if (_text is { } text)
        {
            int max = 3 + 1 + (enhanced?.Length + 1 ?? 0) + Encoding.UTF8.GetMaxByteCount(text.Length) + 2;
            var span = writer.GetSpan(max);
            int p = WriteStart(span, last: true, enhanced);
            p += Encoding.UTF8.GetBytes(text, span[p..]);
            span[p++] = (byte)'\r';
            span[p++] = (byte)'\n';
            writer.Advance(p);
            return;
        }

        string prefix = _prefix!;
        int length = 3 + 1 + (enhanced?.Length + 1 ?? 0) + Encoding.UTF8.GetMaxByteCount(prefix.Length) + 32 + 2;
        var buffer = writer.GetSpan(length);
        int n = WriteStart(buffer, last: true, enhanced);
        n += Encoding.UTF8.GetBytes(prefix, buffer[n..]);
        _id.TryFormat(buffer[n..], out int idBytes, "N");
        n += idBytes;
        buffer[n++] = (byte)'\r';
        buffer[n++] = (byte)'\n';
        writer.Advance(n);
    }

    private int WriteStart(Span<byte> span, bool last, string? enhanced)
    {
        int p = 0;
        span[p++] = (byte)('0' + Code / 100);
        span[p++] = (byte)('0' + Code / 10 % 10);
        span[p++] = (byte)('0' + Code % 10);
        span[p++] = last ? (byte)' ' : (byte)'-';
        if (enhanced is not null)
        {
            p += Encoding.ASCII.GetBytes(enhanced, span[p..]);
            span[p++] = (byte)' ';
        }

        return p;
    }

    public override string ToString() => $"{Code}{(EnhancedCode is null ? "" : " " + EnhancedCode)} {string.Join(" | ", Lines)}";
}

/// <summary>Pre-built replies used by the server. Text follows common practice (Postfix/Exim style).</summary>
public static class SmtpReplies
{
    public static readonly SmtpReply Ok = SmtpReply.Constant(250, "2.0.0", "OK");
    public static readonly SmtpReply SenderOk = SmtpReply.Constant(250, "2.1.0", "Sender OK");
    public static readonly SmtpReply RecipientOk = SmtpReply.Constant(250, "2.1.5", "Recipient OK");
    public static readonly SmtpReply ResetOk = SmtpReply.Constant(250, "2.0.0", "Reset OK");
    public static readonly SmtpReply StartData = SmtpReply.Constant(354, null, "End data with <CR><LF>.<CR><LF>");
    public static readonly SmtpReply Bye = SmtpReply.Constant(221, "2.0.0", "Bye");
    public static readonly SmtpReply ReadyForTls = SmtpReply.Constant(220, "2.0.0", "Ready to start TLS");
    public static readonly SmtpReply AuthOk = SmtpReply.Constant(235, "2.7.0", "Authentication successful");

    public static readonly SmtpReply SyntaxError = SmtpReply.Constant(500, "5.5.2", "Syntax error, command unrecognized");
    public static readonly SmtpReply ArgumentSyntaxError = SmtpReply.Constant(501, "5.5.4", "Syntax error in parameters or arguments");
    public static readonly SmtpReply NotImplemented = SmtpReply.Constant(502, "5.5.1", "Command not implemented");
    public static readonly SmtpReply BadSequence = SmtpReply.Constant(503, "5.5.1", "Bad sequence of commands");
    public static readonly SmtpReply ParameterNotImplemented = SmtpReply.Constant(504, "5.5.4", "Command parameter not implemented");
    public static readonly SmtpReply LineTooLong = SmtpReply.Constant(500, "5.5.2", "Line too long");
    public static readonly SmtpReply BareLineEnding = SmtpReply.Constant(500, "5.5.2", "Bare CR or LF not allowed, closing connection");
    public static readonly SmtpReply TooManyErrors = SmtpReply.Constant(421, "4.7.0", "Too many errors, closing connection");
    public static readonly SmtpReply Timeout = SmtpReply.Constant(421, "4.4.2", "Timeout, closing connection");
    public static readonly SmtpReply ShuttingDown = SmtpReply.Constant(421, "4.3.2", "Service shutting down, closing connection");
    public static readonly SmtpReply TlsRequired = SmtpReply.Constant(530, "5.7.0", "Must issue a STARTTLS command first");
    public static readonly SmtpReply AuthRequired = SmtpReply.Constant(530, "5.7.0", "Authentication required");
    public static readonly SmtpReply AuthFailed = SmtpReply.Constant(535, "5.7.8", "Authentication credentials invalid");
    public static readonly SmtpReply AuthNeedsTls = SmtpReply.Constant(538, "5.7.11", "Encryption required for requested authentication mechanism");
    public static readonly SmtpReply TlsNotAvailable = SmtpReply.Constant(454, "4.7.0", "TLS not available due to temporary reason");
    public static readonly SmtpReply TooManyRecipients = SmtpReply.Constant(452, "4.5.3", "Too many recipients");
    public static readonly SmtpReply MessageTooLarge = SmtpReply.Constant(552, "5.3.4", "Message size exceeds fixed limit");
    public static readonly SmtpReply InsufficientStorage = SmtpReply.Constant(452, "4.3.1", "Insufficient system storage");
    public static readonly SmtpReply LocalError = SmtpReply.Constant(451, "4.3.0", "Requested action aborted: local error in processing");
    public static readonly SmtpReply NoValidRecipients = SmtpReply.Constant(554, "5.5.1", "No valid recipients");
    public static readonly SmtpReply VrfyDisabled = SmtpReply.Constant(252, "2.5.2", "Cannot VRFY user, but will accept message and attempt delivery");

    public static SmtpReply Greeting(string hostname, string product = "EggMail") =>
        SmtpReply.Create(220, null, $"{hostname} ESMTP {product}");
}
