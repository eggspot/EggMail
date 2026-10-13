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

    /// <summary>Digest of the request that carries <see cref="IdempotencyKey"/>; storage returns the stored one on a duplicate so the caller can detect key reuse with another body.</summary>
    public string? IdempotencyFingerprint { get; init; }

    /// <summary>The caller asks to keep the raw message with its attachments after delivery (needs the global switch too).</summary>
    public bool StoreAttachments { get; init; }
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

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<SubmissionResult> SubmitAsync(SubmissionRequest request, CancellationToken ct)
    {
        if (request.Message.Length + request.ReceivedHeader.Length > _options.MaxMessageBytes)
        {
            return new SubmissionResult(SubmissionStatus.TooLarge, Guid.Empty, Detail: "message exceeds the size limit");
        }

        var recipients = DistinctRecipients(request.Recipients);
        if (recipients.Count == 0)
        {
            return new SubmissionResult(SubmissionStatus.Invalid, Guid.Empty, Detail: "no recipients");
        }

        if (recipients.Count > _options.MaxRecipients || _policy.CheckRecipientCount(recipients.Count) is { } tooMany)
        {
            return new SubmissionResult(SubmissionStatus.Invalid, Guid.Empty, _policy.CheckRecipientCount(recipients.Count), "too many recipients");
        }

        // The message is parsed once here; the sender check, the header repair and the history extraction all work from this one parse.
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
        var headers = parsed.Headers;
        var editor = new MessageHeaderEditor(request.Message);

        // Bcc must never reach the stored copy. The parsed list is authoritative only when it is complete: past the header count or
        // size limits it stops recording fields, while the editor (which has no such limit) still sees them, so then the rule stays.
        bool headerListComplete = (headers.Anomalies & (MimeAnomaly.TooManyHeaders | MimeAnomaly.HeaderBlockTooLarge)) == 0;
        if (!headerListComplete || headers.IndexOf(HeaderId.Bcc) >= 0)
        {
            editor.Remove(HeaderNames.Bcc);
        }

        if (!headers.TryGetFirst(HeaderId.MessageId, out _))
        {
            editor.Prepend(HeaderNames.MessageId, MessageBuilder.GenerateMessageId(_options.MessageIdDomain, _clock));
        }

        if (!headers.TryGetFirst(HeaderId.Date, out _))
        {
            editor.Prepend(HeaderNames.Date, MimeDate.Format(now));
        }

        if (!request.ReceivedHeader.IsEmpty)
        {
            editor.PrependRawWithoutCopy(request.ReceivedHeader);   // last: each prepended field goes above the earlier ones, and Received belongs at the very top
        }

        byte[] raw = editor.ToArray();

        // Only headers are added or removed, so subject, bodies and attachments of the original parse are those of the stored message.
        var content = ExtractContent(parsed);
        var messageId = Ids.New(now);
        var accepted = new AcceptedMessage
        {
            MessageId = messageId,
            TenantId = request.Tenant.Id,
            Source = request.Source,
            EnvelopeFrom = request.EnvelopeFrom,
            Recipients = ToAcceptedRecipients(recipients, now),
            Raw = raw,
            ReceivedAt = now,
            ExpiresAt = now + _storageOptions.Queue.MaxLifetime,
            IdempotencyKey = request.IdempotencyKey,
            IdempotencyFingerprint = request.IdempotencyFingerprint,
            RemoteAddress = request.RemoteAddress,
            Authenticated = request.Authenticated,
            SmtpUtf8 = request.SmtpUtf8,
            Content = content,
            RetainRaw = request.StoreAttachments && _storageOptions.Content.AllowAttachmentStorage && content is { Attachments.Count: > 0 },
            SendingDomain = decision.SendingDomain?.Name ?? fromDomain,
        };

        var result = await _storage.Intake.AcceptAsync(accepted, ct).ConfigureAwait(false);
        return new SubmissionResult(result.Status == IntakeStatus.Accepted ? SubmissionStatus.Accepted : SubmissionStatus.Duplicate, result.MessageId, IdempotencyFingerprint: result.IdempotencyFingerprint);
    }

    /// <summary>The recipients without duplicates, in first-seen order. Returns the caller's list itself when it has none (the usual case).</summary>
    private static IReadOnlyList<EmailAddress> DistinctRecipients(IReadOnlyList<EmailAddress> recipients)
    {
        int count = recipients.Count;
        if (count < 2)
        {
            return recipients;
        }

        if (count <= 16)
        {
            // Quadratic but allocation free; the common message has one to three recipients.
            for (int i = 1; i < count; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    if (recipients[i].Equals(recipients[j]))
                    {
                        return FirstOccurrences(recipients);
                    }
                }
            }

            return recipients;
        }

        return FirstOccurrences(recipients);
    }

    private static List<EmailAddress> FirstOccurrences(IReadOnlyList<EmailAddress> recipients)
    {
        var seen = new HashSet<EmailAddress>(recipients.Count);
        var distinct = new List<EmailAddress>(recipients.Count);
        for (int i = 0; i < recipients.Count; i++)
        {
            if (seen.Add(recipients[i]))
            {
                distinct.Add(recipients[i]);
            }
        }

        return distinct;
    }

    private static AcceptedRecipient[] ToAcceptedRecipients(IReadOnlyList<EmailAddress> recipients, DateTimeOffset now)
    {
        var accepted = new AcceptedRecipient[recipients.Count];
        for (int i = 0; i < accepted.Length; i++)
        {
            accepted[i] = new AcceptedRecipient(Ids.New(now), recipients[i]);
        }

        return accepted;
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

    private MessageContent? ExtractContent(MimeMessage parsed)
    {
        if (_storage.HistoryMode != HistoryMode.Full || !_storageOptions.Content.Retain)
        {
            return null;
        }

        var extracted = MessageContentExtractor.Extract(parsed, _storageOptions.Content.MaxStoredBodyBytes);
        return new MessageContent(
            _storageOptions.Content.StoreSubject ? extracted.Subject : null,
            extracted.TextBody,
            extracted.HtmlBody,
            ToStoredAttachments(extracted.Attachments),
            extracted.IsTruncated);
    }

    private static IReadOnlyList<StoredAttachment> ToStoredAttachments(IReadOnlyList<Mta.Mime.AttachmentInfo> attachments)
    {
        if (attachments.Count == 0)
        {
            return [];
        }

        var stored = new StoredAttachment[attachments.Count];
        for (int i = 0; i < stored.Length; i++)
        {
            var a = attachments[i];
            stored[i] = new StoredAttachment(a.FileName, a.ContentType, a.Size, a.ContentId);
        }

        return stored;
    }

    private static string? HeaderFromDomain(MimeMessage message, out string? problem)
    {
        problem = null;
        if (!message.Headers.TryGetFirst(HeaderId.From, out var from))
        {
            problem = "message has no From header";
            return null;
        }

        switch (AddressList.Parse(from).GetCommonDomain(out string? domain))
        {
            case CommonDomainResult.Single:
                return domain;
            case CommonDomainResult.MultipleDomains:
                problem = "the From header must use a single domain";
                return null;
            default:
                problem = "the From header has no valid address";
                return null;
        }
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
