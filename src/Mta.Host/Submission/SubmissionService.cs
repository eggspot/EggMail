using Mta.Core;
using Mta.Mime;
using Mta.Policy;
using Mta.Storage;
using StoredAttachment = Mta.Storage.AttachmentInfo;

namespace Mta.Host.Submission;

public enum SubmissionStatus
{
    Accepted,

    /// <summary>The idempotency key was used before: nothing new was queued.</summary>
    Duplicate,

    /// <summary>The sender policy refused the message (see <see cref="SubmissionResult.Rejection"/>).</summary>
    Rejected,

    /// <summary>The message cannot be queued as it is (no From, too many recipients, ...).</summary>
    Invalid,

    TooLarge,
}

/// <summary>One message handed in by SMTP submission or the HTTP API.</summary>
public sealed class SubmissionRequest
{
    public required Tenant Tenant { get; init; }
    public required MessageSource Source { get; init; }
    public required EmailAddress EnvelopeFrom { get; init; }
    public required IReadOnlyList<EmailAddress> Recipients { get; init; }

    /// <summary>The RFC 5322 message as submitted, CRLF line endings.</summary>
    public required ReadOnlyMemory<byte> Message { get; init; }

    /// <summary>The <c>Received</c> field to put in front of an SMTP-submitted message; empty for API messages.</summary>
    public ReadOnlyMemory<byte> ReceivedHeader { get; init; }

    public string? RemoteAddress { get; init; }
    public string? Authenticated { get; init; }
    public bool SmtpUtf8 { get; init; }
    public string? IdempotencyKey { get; init; }

    /// <summary>The caller asks to keep the raw message with its attachments after delivery (needs the global switch too).</summary>
    public bool StoreAttachments { get; init; }
}

public sealed record SubmissionResult(SubmissionStatus Status, Guid MessageId, SenderRejection? Rejection = null, string? Detail = null)
{
    public bool IsAccepted => Status is SubmissionStatus.Accepted or SubmissionStatus.Duplicate;
}

public sealed class SubmissionOptions
{
    /// <summary>Domain used when a message needs a generated Message-ID.</summary>
    public string MessageIdDomain { get; init; } = "localhost";

    public long MaxMessageBytes { get; init; } = 25 * 1024 * 1024;

    public int MaxRecipients { get; init; } = 100;
}

/// <summary>
/// The one path every submitted message takes into the queue (SMTP and HTTP API): sender policy, header repair, content extraction for
/// history, and durable intake. Behaviour is identical on every storage backend.
/// </summary>
public sealed class SubmissionService
{
    private readonly IStorage _storage;
    private readonly IClock _clock;
    private readonly SenderPolicy _policy;
    private readonly StorageOptions _storageOptions;
    private readonly SubmissionOptions _options;

    public SubmissionService(IStorage storage, IClock clock, SenderPolicy policy, StorageOptions storageOptions, SubmissionOptions? options = null)
    {
        _storage = storage;
        _clock = clock;
        _policy = policy;
        _storageOptions = storageOptions;
        _options = options ?? new SubmissionOptions();
    }

    public async ValueTask<SubmissionResult> SubmitAsync(SubmissionRequest request, CancellationToken ct)
    {
        if (request.Message.Length + request.ReceivedHeader.Length > _options.MaxMessageBytes)
        {
            return new SubmissionResult(SubmissionStatus.TooLarge, Guid.Empty, Detail: "message exceeds the size limit");
        }

        var recipients = request.Recipients.Distinct().ToList();
        if (recipients.Count == 0)
        {
            return new SubmissionResult(SubmissionStatus.Invalid, Guid.Empty, Detail: "no recipients");
        }

        if (recipients.Count > _options.MaxRecipients || _policy.CheckRecipientCount(recipients.Count) is { } tooMany)
        {
            return new SubmissionResult(SubmissionStatus.Invalid, Guid.Empty, _policy.CheckRecipientCount(recipients.Count), "too many recipients");
        }

        var parsed = MimeMessage.Parse(request.Message);
        string? fromDomain = HeaderFromDomain(parsed, out string? fromProblem);
        if (fromDomain is null)
        {
            return new SubmissionResult(SubmissionStatus.Invalid, Guid.Empty, Detail: fromProblem);
        }

        var domains = await _storage.Config.GetDomainsAsync(request.Tenant.Id, ct).ConfigureAwait(false);
        var decision = _policy.Evaluate(request.Tenant, request.EnvelopeFrom, fromDomain, domains);
        if (!decision.IsAllowed)
        {
            return new SubmissionResult(SubmissionStatus.Rejected, Guid.Empty, decision.Rejection, decision.Rejection!.Message);
        }

        var now = _clock.UtcNow;
        var editor = new MessageHeaderEditor(request.Message);
        editor.Remove(HeaderNames.Bcc);
        if (!parsed.Headers.TryGetFirst(HeaderId.MessageId, out _))
        {
            editor.Prepend(HeaderNames.MessageId, MessageBuilder.GenerateMessageId(_options.MessageIdDomain, _clock));
        }

        if (!parsed.Headers.TryGetFirst(HeaderId.Date, out _))
        {
            editor.Prepend(HeaderNames.Date, MimeDate.Format(now));
        }

        byte[] edited = editor.ToArray();
        byte[] raw;
        if (request.ReceivedHeader.IsEmpty)
        {
            raw = edited;
        }
        else
        {
            raw = new byte[request.ReceivedHeader.Length + edited.Length];
            request.ReceivedHeader.CopyTo(raw);
            edited.CopyTo(raw.AsSpan(request.ReceivedHeader.Length));
        }

        var content = ExtractContent(raw);
        var messageId = Ids.New(now);
        var accepted = new AcceptedMessage
        {
            MessageId = messageId,
            TenantId = request.Tenant.Id,
            Source = request.Source,
            EnvelopeFrom = request.EnvelopeFrom,
            Recipients = recipients.Select(r => new AcceptedRecipient(Ids.New(now), r)).ToList(),
            Raw = raw,
            ReceivedAt = now,
            ExpiresAt = now + _storageOptions.Queue.MaxLifetime,
            IdempotencyKey = request.IdempotencyKey,
            RemoteAddress = request.RemoteAddress,
            Authenticated = request.Authenticated,
            SmtpUtf8 = request.SmtpUtf8,
            Content = content,
            RetainRaw = request.StoreAttachments && _storageOptions.Content.AllowAttachmentStorage && content is { Attachments.Count: > 0 },
            SendingDomain = decision.SendingDomain?.Name ?? fromDomain,
        };

        var result = await _storage.Intake.AcceptAsync(accepted, ct).ConfigureAwait(false);
        return new SubmissionResult(result.Status == IntakeStatus.Accepted ? SubmissionStatus.Accepted : SubmissionStatus.Duplicate, result.MessageId);
    }

    private MessageContent? ExtractContent(byte[] raw)
    {
        if (_storage.HistoryMode != HistoryMode.Full || !_storageOptions.Content.Retain)
        {
            return null;
        }

        var extracted = MessageContentExtractor.Extract(raw, _storageOptions.Content.MaxStoredBodyBytes);
        return new MessageContent(
            _storageOptions.Content.StoreSubject ? extracted.Subject : null,
            extracted.TextBody,
            extracted.HtmlBody,
            extracted.Attachments.Select(a => new StoredAttachment(a.FileName, a.ContentType, a.Size, a.ContentId)).ToList(),
            extracted.IsTruncated);
    }

    private static string? HeaderFromDomain(MimeMessage message, out string? problem)
    {
        problem = null;
        if (!message.Headers.TryGetFirst(HeaderId.From, out var from))
        {
            problem = "message has no From header";
            return null;
        }

        var mailboxes = AddressList.Parse(from).Mailboxes.Where(m => m.IsValid).ToList();
        if (mailboxes.Count == 0)
        {
            problem = "the From header has no valid address";
            return null;
        }

        string domain = mailboxes[0].Address.Domain.ToLowerInvariant();
        if (mailboxes.Any(m => !string.Equals(m.Address.Domain, domain, StringComparison.OrdinalIgnoreCase)))
        {
            problem = "the From header must use a single domain";
            return null;
        }

        return domain;
    }
}
