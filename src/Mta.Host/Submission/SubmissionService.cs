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
    public string? IdempotencyKey { get; init; }

    /// <summary>Digest of the request that carries <see cref="IdempotencyKey"/>; storage returns the stored one on a duplicate so the caller can detect key reuse with another body.</summary>
    public string? IdempotencyFingerprint { get; init; }

    /// <summary>The caller asks to keep the raw message with its attachments after delivery (needs the global switch too).</summary>
    public bool StoreAttachments { get; init; }

    /// <summary>Tags the API caller gave the message; stored with the message's history (<c>History:Mode=Full</c>) and returned by the messages API.</summary>
    public IReadOnlyList<string>? Tags { get; init; }
}

public sealed record SubmissionResult(SubmissionStatus Status, Guid MessageId, SenderRejection? Rejection = null, string? Detail = null, string? IdempotencyFingerprint = null)
{
    public bool IsAccepted => Status is SubmissionStatus.Accepted or SubmissionStatus.Duplicate;
}

public sealed class SubmissionOptions
{
    /// <summary>Domain used when a message needs a generated Message-ID.</summary>
    public string MessageIdDomain { get; init; } = "localhost";

    public long MaxMessageBytes { get; init; } = 25 * 1024 * 1024;

    public int MaxRecipients { get; init; } = 100;

    /// <summary>How long a tenant's domain list is reused for the sender check.</summary>
    public TimeSpan DomainCacheTtl { get; init; } = TimeSpan.FromSeconds(5);
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
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, (IReadOnlyList<DomainRecord> Domains, long ExpiresAt, long Version)> _domainCache = new();

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

        var domains = await GetDomainsAsync(request.Tenant.Id, ct).ConfigureAwait(false);
        var decision = _policy.Evaluate(request.Tenant, request.EnvelopeFrom, fromDomain, domains);
        if (!decision.IsAllowed)
        {
            return new SubmissionResult(SubmissionStatus.Rejected, Guid.Empty, decision.Rejection, decision.Rejection!.Message);
        }

        var now = _clock.UtcNow;
        var editor = new MessageHeaderEditor(request.Message);
        editor.Remove(HeaderNames.Bcc);
        string messageIdHeader;
        if (parsed.Headers.TryGetFirst(HeaderId.MessageId, out var existingMessageId))
        {
            messageIdHeader = existingMessageId.Value;
        }
        else
        {
            messageIdHeader = MessageBuilder.GenerateMessageId(_options.MessageIdDomain, _clock);
            editor.Prepend(HeaderNames.MessageId, messageIdHeader);
        }

        if (!parsed.Headers.TryGetFirst(HeaderId.Date, out _))
        {
            editor.Prepend(HeaderNames.Date, MimeDate.Format(now));
        }

        if (!request.ReceivedHeader.IsEmpty)
        {
            editor.PrependRaw(request.ReceivedHeader.Span);   // last: each prepended field goes above the earlier ones, and Received belongs at the very top
        }

        byte[] raw = editor.ToArray();
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
            IdempotencyFingerprint = request.IdempotencyFingerprint,
            RemoteAddress = request.RemoteAddress,
            Authenticated = request.Authenticated,
            // What the message itself needs (UTF-8 in its header fields), decided from its bytes rather than from the submitter's MAIL FROM
            // parameter: a client that declares SMTPUTF8 only for an internationalized address must not make every transaction of this
            // message demand SMTPUTF8, and one that sends UTF-8 headers without declaring it still gets them delivered as such.
            HeadersUtf8 = MessageInspector.HasValidUtf8Headers(raw),
            Content = content,
            RetainRaw = request.StoreAttachments && _storageOptions.Content.AllowAttachmentStorage && content is { Attachments.Count: > 0 },
            SendingDomain = decision.SendingDomain?.Name ?? fromDomain,
            MessageIdHeader = messageIdHeader,
            Tags = request.Tags is { Count: > 0 } tags ? tags.Distinct(StringComparer.Ordinal).ToList() : null,
        };

        var result = await _storage.Intake.AcceptAsync(accepted, ct).ConfigureAwait(false);
        return new SubmissionResult(result.Status == IntakeStatus.Accepted ? SubmissionStatus.Accepted : SubmissionStatus.Duplicate, result.MessageId, IdempotencyFingerprint: result.IdempotencyFingerprint);
    }

    /// <summary>
    /// The tenant's domains, cached briefly: the sender check runs for every message and the list changes rarely. A change made through this process (API, verification service) takes effect at once
    /// (<see cref="DomainChangeSignal"/>); a change made by another replica within <see cref="SubmissionOptions.DomainCacheTtl"/>.
    /// </summary>
    private async ValueTask<IReadOnlyList<DomainRecord>> GetDomainsAsync(Guid tenantId, CancellationToken ct)
    {
        long now = _clock.Timestamp;
        long version = DomainChangeSignal.Version;
        if (_domainCache.TryGetValue(tenantId, out var cached) && now < cached.ExpiresAt && cached.Version == version)
        {
            return cached.Domains;
        }

        var domains = await _storage.Config.GetDomainsAsync(tenantId, ct).ConfigureAwait(false);
        _domainCache[tenantId] = (domains, now + (long)(_options.DomainCacheTtl.TotalSeconds * System.Diagnostics.Stopwatch.Frequency), version);
        return domains;
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

/// <summary>
/// Raised by every code path that changes a domain record, so cached copies of a tenant's domain list (the sender check on the hot
/// path) are dropped at once instead of waiting for their time to live.
/// </summary>
public static class DomainChangeSignal
{
    private static long _version;

    public static long Version => Interlocked.Read(ref _version);

    public static void Bump() => Interlocked.Increment(ref _version);
}
