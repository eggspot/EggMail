using Mta.Core;

namespace Mta.Storage;

/// <summary>Where a message entered the system.</summary>
public enum MessageSource : byte
{
    Smtp = 0,
    Api,
    Bounce,
    System,
}

public sealed record AcceptedRecipient(Guid DeliveryId, EmailAddress Address);

/// <summary>
/// Content extracted at accept time for history (only recorded when <see cref="HistoryMode.Full"/>). A body is either a string or, for the intake path, the UTF-8 bytes
/// it already is in the message (<see cref="TextUtf8"/>, <see cref="HtmlUtf8"/>): a storage that writes UTF-8 binds those bytes and never builds the string, and
/// <see cref="Text"/> / <see cref="Html"/> still give the string (made on first use) for every other reader. Equal contents compare equal whichever way they are held.
/// </summary>
public sealed class MessageContent : IEquatable<MessageContent>
{
    private string? _text;
    private string? _html;

    public MessageContent(string? subject, string? text, string? html, IReadOnlyList<AttachmentInfo> attachments, bool truncated)
    {
        Subject = subject;
        _text = text;
        _html = html;
        Attachments = attachments;
        Truncated = truncated;
    }

    /// <summary>A content whose text and/or HTML body is held as UTF-8 bytes (a body given as bytes must be null as a string).</summary>
    public MessageContent(string? subject, string? text, string? html, ReadOnlyMemory<byte>? textUtf8, ReadOnlyMemory<byte>? htmlUtf8, IReadOnlyList<AttachmentInfo> attachments, bool truncated)
        : this(subject, text, html, attachments, truncated)
    {
        if ((text is not null && textUtf8 is not null) || (html is not null && htmlUtf8 is not null))
        {
            throw new ArgumentException("A body is held either as a string or as UTF-8 bytes, not both.");
        }

        TextUtf8 = textUtf8;
        HtmlUtf8 = htmlUtf8;
    }

    public string? Subject { get; }

    /// <summary>The text body as a string (made from <see cref="TextUtf8"/> on first use when it is held as bytes).</summary>
    public string? Text => _text ?? (TextUtf8 is { } bytes ? _text = System.Text.Encoding.UTF8.GetString(bytes.Span) : null);

    /// <summary>The HTML body as a string (made from <see cref="HtmlUtf8"/> on first use when it is held as bytes).</summary>
    public string? Html => _html ?? (HtmlUtf8 is { } bytes ? _html = System.Text.Encoding.UTF8.GetString(bytes.Span) : null);

    /// <summary>The text body as UTF-8 when it is held that way (and only then). The memory is stable: it belongs to the stored message.</summary>
    public ReadOnlyMemory<byte>? TextUtf8 { get; }

    /// <summary>The HTML body as UTF-8 when it is held that way (and only then).</summary>
    public ReadOnlyMemory<byte>? HtmlUtf8 { get; }

    public IReadOnlyList<AttachmentInfo> Attachments { get; }

    public bool Truncated { get; }

    public bool Equals(MessageContent? other) =>
        other is not null && Subject == other.Subject && Text == other.Text && Html == other.Html && ReferenceEquals(Attachments, other.Attachments) && Truncated == other.Truncated;

    public override bool Equals(object? obj) => Equals(obj as MessageContent);

    public override int GetHashCode() => HashCode.Combine(Subject, Text, Html, Truncated);

    public override string ToString() => $"MessageContent {{ Subject = {Subject}, Text = {Text}, Html = {Html}, Attachments = {Attachments}, Truncated = {Truncated} }}";
}

public sealed record AttachmentInfo(string? FileName, string? ContentType, long Size, string? ContentId);

/// <summary>
/// Everything the intake path hands to storage: the verbatim message, the envelope and the recipients to deliver to. The properties can be set again
/// because the submission service reuses these objects: <see cref="IMessageIntake.AcceptAsync"/> must be completely done with a message (nothing queued
/// that still reads it) when its task completes, and must not keep the object itself, only values taken from it.
/// </summary>
public sealed class AcceptedMessage
{
    public required Guid MessageId { get; set; }
    public required Guid TenantId { get; set; }
    public required MessageSource Source { get; set; }
    public required EmailAddress EnvelopeFrom { get; set; }
    public required IReadOnlyList<AcceptedRecipient> Recipients { get; set; }

    /// <summary>The raw message exactly as it will be delivered (including server-added headers), CRLF lines.</summary>
    public required ReadOnlyMemory<byte> Raw { get; set; }

    public required DateTimeOffset ReceivedAt { get; set; }

    /// <summary>When undelivered recipients expire (ReceivedAt + Queue:MaxLifetime unless overridden).</summary>
    public required DateTimeOffset ExpiresAt { get; set; }

    /// <summary>API idempotency key, if any (unique per tenant).</summary>
    public string? IdempotencyKey { get; set; }

    /// <summary>
    /// Digest of the request that carries <see cref="IdempotencyKey"/> (the API hashes the body). Stored with the key and returned in
    /// <see cref="IntakeResult.IdempotencyFingerprint"/> on a duplicate, so the caller can tell a safe retry from key reuse with another body.
    /// </summary>
    public string? IdempotencyFingerprint { get; set; }

    public string? RemoteAddress { get; set; }
    public string? Authenticated { get; set; }

    /// <summary>
    /// The header section of <see cref="Raw"/> is internationalized (RFC 6532: UTF-8 in header fields), so delivering it needs the SMTPUTF8
    /// extension on every outbound transaction, or fails. Whether an envelope address needs SMTPUTF8 is a per-transaction question that
    /// delivery answers from the addresses themselves. Persisted with each delivery row and returned as <see cref="ClaimedDelivery.HeadersUtf8"/>.
    /// </summary>
    public bool HeadersUtf8 { get; set; }

    /// <summary>Extracted content, or null when not recorded (StatsOnly, Content:Mode=None, or extraction skipped).</summary>
    public MessageContent? Content { get; set; }

    /// <summary>Move the raw message to long-term retention when delivery completes (attachment storage enabled).</summary>
    public bool RetainRaw { get; set; }

    /// <summary>Recipient-domain buckets and sending domain for statistics.</summary>
    public string? SendingDomain { get; set; }

    /// <summary>
    /// The message's <c>Message-ID</c> header, so an asynchronous bounce or complaint that returns the headers can be attached to the message's history
    /// (<see cref="IHistoryStore.AttachReportAsync"/>). Recorded only with <see cref="HistoryMode.Full"/>.
    /// </summary>
    public string? MessageIdHeader { get; set; }

    /// <summary>Tags the API caller gave the message. Recorded with the message's history (<see cref="HistoryMode.Full"/> only).</summary>
    public IReadOnlyList<string>? Tags { get; set; }
}

public enum IntakeStatus : byte
{
    Accepted = 0,

    /// <summary>The idempotency key was seen before: no new message was created.</summary>
    DuplicateIdempotencyKey,
}

/// <param name="Status">Whether a message was created.</param>
/// <param name="MessageId">The new message, or the original message for a duplicate idempotency key.</param>
/// <param name="IdempotencyFingerprint">For <see cref="IntakeStatus.DuplicateIdempotencyKey"/>: the fingerprint stored with the original request (null when it had none).</param>
public readonly record struct IntakeResult(IntakeStatus Status, Guid MessageId, string? IdempotencyFingerprint = null);

/// <summary>A delivery handed to a worker by <see cref="IDeliveryStore.ClaimAsync"/>.</summary>
public sealed class ClaimedDelivery
{
    public required Guid DeliveryId { get; init; }
    public required Guid MessageId { get; init; }
    public required Guid TenantId { get; init; }
    public required EmailAddress EnvelopeFrom { get; init; }
    public required EmailAddress Recipient { get; init; }
    public required string RecipientDomain { get; init; }

    /// <summary>Number of attempts made before this one.</summary>
    public required int Attempt { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public required DateTimeOffset LeaseUntil { get; init; }
    public string? LastError { get; init; }

    /// <summary>A previous attempt was aborted after the end of message data was sent (quiesce requeue, decision R).</summary>
    public bool PossibleDuplicate { get; init; }

    public string? SendingDomain { get; init; }
    public MessageSource Source { get; init; }

    /// <summary>The message's headers are internationalized: sending it needs SMTPUTF8 (see <see cref="AcceptedMessage.HeadersUtf8"/>).</summary>
    public bool HeadersUtf8 { get; init; }
}

public enum DeliveryOutcome : byte
{
    Delivered = 0,

    /// <summary>Temporary failure: reschedule at <see cref="DeliveryAttempt.NextAttemptAt"/>.</summary>
    Deferred,

    /// <summary>Permanent failure (5xx): bounce.</summary>
    Failed,

    /// <summary>Lifetime exceeded while deferred.</summary>
    Expired,

    /// <summary>Recipient suppressed: not attempted.</summary>
    Suppressed,

    Cancelled,

    /// <summary>The attempt was aborted by a backend switch; the delivery is requeued unchanged (decision R).</summary>
    AbortedBySwitch,
}

public sealed record TlsInfo(
    bool Used,
    string? Version,
    string? CipherSuite,
    string? PeerSubject,
    string? PeerIssuer,
    string? PeerSha256,
    string? PolicyErrors,
    bool Verified,
    string? PolicyApplied,
    string? PolicyId,
    bool StartTlsAdvertised,
    bool PlaintextFallback);

/// <summary>An event to publish to webhook endpoints, composed by the delivery layer; storage fans it out into the outbox in the same commit.</summary>
public sealed record WebhookEventDraft(Guid EventId, string EventType, string PayloadJson);

/// <summary>The result of one delivery attempt, recorded atomically with its consequences (decision 13 ordering rules).</summary>
public sealed class DeliveryAttempt
{
    public required Guid DeliveryId { get; init; }
    public required DeliveryOutcome Outcome { get; init; }
    public required DateTimeOffset At { get; init; }
    public int? SmtpCode { get; init; }
    public string? EnhancedCode { get; init; }
    public string? Message { get; init; }
    public string? MxHost { get; init; }
    public string? Route { get; init; }
    public TlsInfo? Tls { get; init; }
    public TimeSpan Duration { get; init; }

    /// <summary>For <see cref="DeliveryOutcome.Deferred"/>: when to retry.</summary>
    public DateTimeOffset? NextAttemptAt { get; init; }

    /// <summary>Mark the delivery as possibly sent twice (aborted after end-of-data).</summary>
    public bool PossibleDuplicate { get; init; }

    /// <summary>
    /// For <see cref="DeliveryOutcome.Deferred"/>: <c>false</c> for a hold where nothing was sent (a local sending limit or a
    /// destination throttle). The row is only rescheduled to <see cref="NextAttemptAt"/> and its lease released: the attempt
    /// counter is not incremented, no "deferred" history event or statistic is written and no webhook events are fanned out.
    /// </summary>
    public bool CountAttempt { get; init; } = true;

    /// <summary>For <see cref="DeliveryOutcome.Failed"/> hard bounces or complaints: suppress the recipient (written before completing the row).</summary>
    public SuppressionReason? Suppress { get; init; }

    public IReadOnlyList<WebhookEventDraft> WebhookEvents { get; init; } = [];
}
