namespace Mta.Mime;

/// <summary>How serious a <see cref="MessageIssue"/> is; the SMTP policy decides what to reject.</summary>
public enum IssueSeverity
{
    /// <summary>Worth knowing (for example: the message needs 8BITMIME).</summary>
    Info = 0,

    /// <summary>Violates a SHOULD or is unusual; most receivers cope.</summary>
    Warning,

    /// <summary>Violates a MUST or is dangerous; many receivers reject or misinterpret it.</summary>
    Error,
}

/// <summary>Kinds of problems <see cref="MessageValidator"/> reports.</summary>
public enum MessageIssueCode
{
    /// <summary>There is no From header.</summary>
    MissingFrom,
    /// <summary>A header that may occur only once (From, Subject, Date, Content-Type ...) occurs several times.</summary>
    DuplicateSingletonHeader,
    /// <summary>The From header contains no valid mailbox.</summary>
    InvalidFrom,
    /// <summary>Several From mailboxes and no Sender header (RFC 5322 section 3.6.2).</summary>
    MultipleFromWithoutSender,
    /// <summary>There is no Date header.</summary>
    MissingDate,
    /// <summary>The Date header cannot be parsed.</summary>
    InvalidDate,
    /// <summary>There is no Message-ID header.</summary>
    MissingMessageId,
    /// <summary>A header line has no colon or an invalid field name.</summary>
    MalformedHeader,
    /// <summary>A header line is longer than the line limit.</summary>
    HeaderLineTooLong,
    /// <summary>A body line is longer than the line limit.</summary>
    BodyLineTooLong,
    /// <summary>A line ends with LF instead of CRLF.</summary>
    BareLineFeed,
    /// <summary>A CR that is not part of CRLF.</summary>
    BareCarriageReturn,
    /// <summary>A NUL byte in the headers.</summary>
    NulInHeaders,
    /// <summary>A NUL byte in the body.</summary>
    NulInBody,
    /// <summary>More header fields than the limit.</summary>
    TooManyHeaders,
    /// <summary>The header block is larger than the limit.</summary>
    HeaderBlockTooLarge,
    /// <summary>No empty line between headers and body.</summary>
    NoHeaderBodySeparator,
    /// <summary>Non-ASCII header bytes (needs SMTPUTF8 to be relayed unchanged).</summary>
    Utf8Headers,
    /// <summary>8-bit body bytes (needs 8BITMIME to be relayed unchanged).</summary>
    EightBitBody,
    /// <summary>Many Received headers: probable mail loop.</summary>
    TooManyReceivedHeaders,
    /// <summary>A MIME structure problem (missing boundary, no closing delimiter, nesting or part limits, duplicate boundary).</summary>
    MimeStructure,
}

/// <summary>One problem found in a message.</summary>
/// <param name="Code">What kind of problem.</param>
/// <param name="Severity">How serious it is.</param>
/// <param name="Message">Human-readable description (English, safe to log).</param>
/// <param name="HeaderName">The header concerned, if any.</param>
public sealed record MessageIssue(MessageIssueCode Code, IssueSeverity Severity, string Message, string? HeaderName = null);

/// <summary>Options for <see cref="MessageValidator"/>.</summary>
public sealed class MessageValidationOptions
{
    /// <summary>Parse the MIME tree and report structural problems (default true).</summary>
    public bool CheckMimeStructure { get; init; } = true;

    /// <summary>More Received headers than this is reported as a probable mail loop (default 100).</summary>
    public int MaxReceivedHeaders { get; init; } = 100;
}

/// <summary>The outcome of <see cref="MessageValidator.Validate"/>.</summary>
public sealed class MessageValidationResult
{
    internal MessageValidationResult(IReadOnlyList<MessageIssue> issues, MimeAnomaly anomalies, int headerCount, int receivedCount, MessageInspection inspection)
    {
        Issues = issues;
        Anomalies = anomalies;
        HeaderCount = headerCount;
        ReceivedCount = receivedCount;
        Inspection = inspection;
    }

    /// <summary>All issues in the order found.</summary>
    public IReadOnlyList<MessageIssue> Issues { get; }

    /// <summary>The union of parser anomalies (headers and, when checked, MIME structure).</summary>
    public MimeAnomaly Anomalies { get; }

    /// <summary>Number of header fields recorded.</summary>
    public int HeaderCount { get; }

    /// <summary>Number of Received headers (hop count).</summary>
    public int ReceivedCount { get; }

    /// <summary>Byte-level facts about the message.</summary>
    public MessageInspection Inspection { get; }

    /// <summary>True when any issue has <see cref="IssueSeverity.Error"/>.</summary>
    public bool HasErrors
    {
        get
        {
            foreach (var issue in Issues)
            {
                if (issue.Severity == IssueSeverity.Error)
                {
                    return true;
                }
            }

            return false;
        }
    }

    /// <summary>True when there is an issue with this code.</summary>
    public bool Has(MessageIssueCode code)
    {
        foreach (var issue in Issues)
        {
            if (issue.Code == code)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>The highest severity found, or null when the message is clean.</summary>
    public IssueSeverity? WorstSeverity
    {
        get
        {
            IssueSeverity? worst = null;
            foreach (var issue in Issues)
            {
                if (worst is null || issue.Severity > worst)
                {
                    worst = issue.Severity;
                }
            }

            return worst;
        }
    }
}

/// <summary>
/// Receive-side checks on a raw message: duplicate singleton headers, missing From, over-long lines, bare CR/LF, NUL,
/// malformed headers, header limits, mail loops and MIME structure problems. It reports; the caller (SMTP policy) decides
/// what to reject. Never throws for message content.
/// </summary>
public static class MessageValidator
{
    private static readonly (HeaderId Id, string Name)[] Singletons =
    [
        (HeaderId.From, HeaderNames.From),
        (HeaderId.Sender, HeaderNames.Sender),
        (HeaderId.ReplyTo, HeaderNames.ReplyTo),
        (HeaderId.To, HeaderNames.To),
        (HeaderId.Cc, HeaderNames.Cc),
        (HeaderId.Bcc, HeaderNames.Bcc),
        (HeaderId.Subject, HeaderNames.Subject),
        (HeaderId.Date, HeaderNames.Date),
        (HeaderId.MessageId, HeaderNames.MessageId),
        (HeaderId.InReplyTo, HeaderNames.InReplyTo),
        (HeaderId.References, HeaderNames.References),
        (HeaderId.MimeVersion, HeaderNames.MimeVersion),
        (HeaderId.ContentType, HeaderNames.ContentType),
        (HeaderId.ContentTransferEncoding, HeaderNames.ContentTransferEncoding),
    ];

    /// <summary>Validates <paramref name="raw"/>.</summary>
    public static MessageValidationResult Validate(ReadOnlyMemory<byte> raw, MimeLimits? limits = null, MessageValidationOptions? options = null)
    {
        limits ??= MimeLimits.Default;
        options ??= new MessageValidationOptions();
        var issues = new List<MessageIssue>();
        var inspection = MessageInspector.Inspect(raw.Span);
        var headers = HeaderList.Parse(raw, limits);
        var an = headers.Anomalies;

        if (inspection.HasNul)
        {
            // Locate NUL as header or body issue.
            if ((an & MimeAnomaly.NulInHeaders) != 0)
            {
                issues.Add(new(MessageIssueCode.NulInHeaders, IssueSeverity.Error, "A NUL byte occurs in the headers."));
            }

            if (raw.Span[headers.BodyOffset..].IndexOf((byte)0) >= 0)
            {
                an |= MimeAnomaly.NulInBody;
                issues.Add(new(MessageIssueCode.NulInBody, IssueSeverity.Warning, "A NUL byte occurs in the body."));
            }
        }

        if (inspection.HasBareCr)
        {
            issues.Add(new(MessageIssueCode.BareCarriageReturn, IssueSeverity.Error, "A bare CR (not part of CRLF) occurs; receivers disagree on whether it is a line break."));
        }

        if (inspection.HasBareLf)
        {
            issues.Add(new(MessageIssueCode.BareLineFeed, IssueSeverity.Warning, "A line ends with a bare LF instead of CRLF."));
        }

        if ((an & MimeAnomaly.HeaderLineTooLong) != 0)
        {
            issues.Add(new(MessageIssueCode.HeaderLineTooLong, IssueSeverity.Error, $"A header line is longer than {limits.MaxLineLength} bytes."));
        }

        if (inspection.LongestBodyLine > limits.MaxLineLength)
        {
            an |= MimeAnomaly.BodyLineTooLong;
            issues.Add(new(MessageIssueCode.BodyLineTooLong, IssueSeverity.Warning, $"A body line is longer than {limits.MaxLineLength} bytes."));
        }

        if ((an & MimeAnomaly.MissingColon) != 0)
        {
            issues.Add(new(MessageIssueCode.MalformedHeader, IssueSeverity.Error, "A header line has no colon or an invalid field name."));
        }

        if ((an & MimeAnomaly.TooManyHeaders) != 0)
        {
            issues.Add(new(MessageIssueCode.TooManyHeaders, IssueSeverity.Error, $"More than {limits.MaxHeaderCount} header fields."));
        }

        if ((an & MimeAnomaly.HeaderBlockTooLarge) != 0)
        {
            issues.Add(new(MessageIssueCode.HeaderBlockTooLarge, IssueSeverity.Error, $"The header block is larger than {limits.MaxHeaderBytes} bytes."));
        }

        if ((an & MimeAnomaly.NoHeaderBodySeparator) != 0)
        {
            issues.Add(new(MessageIssueCode.NoHeaderBodySeparator, IssueSeverity.Warning, "There is no empty line between the headers and the body."));
        }

        if (inspection.HasNonAsciiHeaders)
        {
            issues.Add(new(MessageIssueCode.Utf8Headers, IssueSeverity.Info, "The headers contain non-ASCII bytes (SMTPUTF8 / RFC 6532)."));
        }

        if (inspection.HasNonAsciiBody)
        {
            an |= MimeAnomaly.NonAsciiBody;
            issues.Add(new(MessageIssueCode.EightBitBody, IssueSeverity.Info, "The body contains 8-bit data (8BITMIME)."));
        }

        foreach (var (id, name) in Singletons)
        {
            if (headers.CountOf(id) > 1)
            {
                issues.Add(new(MessageIssueCode.DuplicateSingletonHeader, IssueSeverity.Error, $"The {name} header occurs more than once.", name));
            }
        }

        CheckFrom(headers, limits, issues);

        if (!headers.TryGetFirst(HeaderId.Date, out var date))
        {
            issues.Add(new(MessageIssueCode.MissingDate, IssueSeverity.Info, "There is no Date header.", HeaderNames.Date));
        }
        else if (!MimeDate.TryParse(date.GetValue(256), out _))
        {
            an |= MimeAnomaly.InvalidDate;
            issues.Add(new(MessageIssueCode.InvalidDate, IssueSeverity.Warning, "The Date header cannot be parsed.", HeaderNames.Date));
        }

        if (headers.IndexOf(HeaderId.MessageId) < 0)
        {
            issues.Add(new(MessageIssueCode.MissingMessageId, IssueSeverity.Info, "There is no Message-ID header.", HeaderNames.MessageId));
        }

        int received = headers.CountOf(HeaderId.Received);
        if (received > options.MaxReceivedHeaders)
        {
            issues.Add(new(MessageIssueCode.TooManyReceivedHeaders, IssueSeverity.Warning, $"{received} Received headers: probable mail loop.", HeaderNames.Received));
        }

        if (options.CheckMimeStructure)
        {
            var message = MimeMessage.Parse(raw, limits);
            var mime = message.Anomalies;
            an |= mime;
            AddMime(issues, mime, MimeAnomaly.MissingBoundary, IssueSeverity.Warning, "A multipart entity has no usable boundary.");
            AddMime(issues, mime, MimeAnomaly.MissingCloseDelimiter, IssueSeverity.Warning, "A multipart entity has no closing delimiter.");
            AddMime(issues, mime, MimeAnomaly.MaxDepthExceeded, IssueSeverity.Error, $"MIME nesting is deeper than {limits.MaxDepth}.");
            AddMime(issues, mime, MimeAnomaly.TooManyParts, IssueSeverity.Error, $"More than {limits.MaxParts} MIME parts.");
            AddMime(issues, mime, MimeAnomaly.DuplicateBoundary, IssueSeverity.Error, "A nested multipart reuses an ancestor's boundary.");
            AddMime(issues, mime, MimeAnomaly.UnknownTransferEncoding, IssueSeverity.Warning, "An unknown Content-Transfer-Encoding.");
            AddMime(issues, mime, MimeAnomaly.InvalidContentType, IssueSeverity.Warning, "An unparsable Content-Type.");
        }

        return new MessageValidationResult(issues, an, headers.Count, received, inspection);
    }

    private static void AddMime(List<MessageIssue> issues, MimeAnomaly found, MimeAnomaly flag, IssueSeverity severity, string text)
    {
        if ((found & flag) != 0)
        {
            issues.Add(new(MessageIssueCode.MimeStructure, severity, text));
        }
    }

    private static void CheckFrom(HeaderList headers, MimeLimits limits, List<MessageIssue> issues)
    {
        if (!headers.TryGetFirst(HeaderId.From, out var from))
        {
            issues.Add(new(MessageIssueCode.MissingFrom, IssueSeverity.Error, "There is no From header.", HeaderNames.From));
            return;
        }

        var list = AddressList.Parse(from, limits);
        int valid = 0;
        int total = 0;
        foreach (var m in list.Mailboxes)
        {
            total++;
            if (m.IsValid)
            {
                valid++;
            }
        }

        if (valid == 0)
        {
            issues.Add(new(MessageIssueCode.InvalidFrom, IssueSeverity.Error, "The From header contains no valid mailbox.", HeaderNames.From));
        }
        else if (total > 1 && headers.IndexOf(HeaderId.Sender) < 0)
        {
            issues.Add(new(MessageIssueCode.MultipleFromWithoutSender, IssueSeverity.Warning, "The From header has several mailboxes but there is no Sender header.", HeaderNames.From));
        }
    }
}
