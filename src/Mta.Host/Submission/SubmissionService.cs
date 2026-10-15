using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
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

/// <summary>
/// One message handed in by SMTP submission or the HTTP API. The properties can be set again so that one instance can serve the messages of an SMTP
/// session in turn (the submission service reads the request only until <see cref="SubmissionService.SubmitAsync"/> has returned, and keeps no reference to it).
/// </summary>
public sealed class SubmissionRequest
{
    public required Tenant Tenant { get; set; }
    public required MessageSource Source { get; set; }
    public required EmailAddress EnvelopeFrom { get; set; }
    public required IReadOnlyList<EmailAddress> Recipients { get; set; }

    /// <summary>The RFC 5322 message as submitted, CRLF line endings.</summary>
    public required ReadOnlyMemory<byte> Message { get; set; }

    /// <summary>The <c>Received</c> field to put in front of an SMTP-submitted message; empty for API messages.</summary>
    public ReadOnlyMemory<byte> ReceivedHeader { get; set; }

    public string? RemoteAddress { get; set; }
    public string? Authenticated { get; set; }
    public string? IdempotencyKey { get; set; }

    /// <summary>Digest of the request that carries <see cref="IdempotencyKey"/>; storage returns the stored one on a duplicate so the caller can detect key reuse with another body.</summary>
    public string? IdempotencyFingerprint { get; set; }

    /// <summary>
    /// The per-send request to keep (true) or not keep (false) the raw message with its attachments after delivery; null when the submitter has no such flag (SMTP, or an API
    /// request that did not set one), in which case the tenant's setting and then the global default decide (<see cref="AttachmentStoragePolicy"/>). Needs the master switch either way.
    /// </summary>
    public bool? StoreAttachments { get; set; }

    /// <summary>Tags the API caller gave the message; stored with the message's history (<c>History:Mode=Full</c>) and returned by the messages API.</summary>
    public IReadOnlyList<string>? Tags { get; set; }
}

public readonly record struct SubmissionResult(SubmissionStatus Status, Guid MessageId, SenderRejection? Rejection = null, string? Detail = null, string? IdempotencyFingerprint = null)
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

/// <summary>What <see cref="SubmissionService.Prepare"/> needs from storage before it can finish.</summary>
public enum SubmissionLoad : byte
{
    None = 0,

    /// <summary>The tenant's domain list (for the sender check).</summary>
    Domains,

    /// <summary>The tenant's attachment-storage setting.</summary>
    AttachmentSetting,
}

/// <summary>Settings a caller of <see cref="SubmissionService.Prepare"/> loaded because it asked for them; pass the same instance to the next call.</summary>
public struct LoadedSettings
{
    public IReadOnlyList<DomainRecord>? Domains;
    public bool HasAttachmentRow;
    public bool? AttachmentRow;
}

/// <summary>
/// A submission between <see cref="SubmissionService.Prepare"/> and the end of the storage call: the message to store (the answer of a submission that was
/// refused is returned by <see cref="SubmissionService.Prepare"/> itself). The message object belongs to the service (it is reused): finish every prepared
/// submission with <see cref="SubmissionService.Complete"/> or <see cref="SubmissionService.Abandon"/>.
/// </summary>
public readonly struct PreparedSubmission
{
    internal PreparedSubmission(AcceptedMessage message, Activity? span)
    {
        Message = message;
        Span = span;
    }

    internal AcceptedMessage? Message { get; }

    internal Activity? Span { get; }

    /// <summary>True when there is nothing to store (the submission was refused or invalid, or settings must be loaded first).</summary>
    public bool IsFinal => Message is null;
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
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, (bool? Row, long ExpiresAt, long Version)> _attachmentRowCache = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, (IReadOnlyList<DomainRecord> Domains, long ExpiresAt, long Version)> _domainCache = new();

    public SubmissionService(IStorage storage, IClock clock, SenderPolicy policy, StorageOptions storageOptions, SubmissionOptions? options = null)
    {
        _storage = storage;
        _clock = clock;
        _policy = policy;
        _storageOptions = storageOptions;
        _options = options ?? new SubmissionOptions();
    }

    /// <summary>Submits one message: checks, header repair, content extraction and durable intake.</summary>
    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<SubmissionResult> SubmitAsync(SubmissionRequest request, CancellationToken ct)
    {
        // Everything but the storage calls happens in Prepare, which cannot wait: when it needs the tenant's domain list or attachment setting and has no
        // current copy, it says so, the answer is loaded here and Prepare runs again with it (from the top; it is a pure function of its inputs).
        var loaded = new LoadedSettings();
        PreparedSubmission prepared = Prepare(request, ref loaded, out SubmissionLoad load, out SubmissionResult refused);
        while (load != SubmissionLoad.None)
        {
            if (load == SubmissionLoad.Domains)
            {
                loaded.Domains = await GetDomainsAsync(request.Tenant.Id, ct).ConfigureAwait(false);
            }
            else
            {
                loaded.AttachmentRow = await GetAttachmentRowAsync(request.Tenant.Id, ct).ConfigureAwait(false);
                loaded.HasAttachmentRow = true;
            }

            prepared = Prepare(request, ref loaded, out load, out refused);
        }

        if (prepared.IsFinal)
        {
            return refused;
        }

        IntakeResult intake;
        try
        {
            intake = await StoreAsync(prepared, ct).ConfigureAwait(false);
        }
        catch
        {
            Abandon(ref prepared);
            throw;
        }

        return Complete(ref prepared, intake);
    }

    /// <summary>
    /// The synchronous part of <see cref="SubmitAsync"/>: everything up to the storage call. Returns either the final answer (a refusal, nothing to store)
    /// or a message ready for <see cref="StoreAsync"/>; the caller then reports the storage result with <see cref="Complete"/>, or
    /// <see cref="Abandon"/> when the storage call failed. When <paramref name="load"/> comes back as something other than <see cref="SubmissionLoad.None"/>
    /// nothing was prepared: load that setting (<see cref="GetDomainsAsync"/> / <see cref="GetAttachmentRowAsync"/>), put it into <paramref name="loaded"/> and
    /// call again. The SMTP handler uses these steps directly so that a message waiting for storage holds one asynchronous frame fewer.
    /// </summary>
    public PreparedSubmission Prepare(SubmissionRequest request, ref LoadedSettings loaded, out SubmissionLoad load, out SubmissionResult refused)
    {
        load = SubmissionLoad.None;
        refused = default;
        if (request.Message.Length + request.ReceivedHeader.Length > _options.MaxMessageBytes)
        {
            refused = new SubmissionResult(SubmissionStatus.TooLarge, Guid.Empty, Detail: "message exceeds the size limit");
            return default;
        }

        var recipients = DistinctRecipients(request.Recipients);
        if (recipients.Count == 0)
        {
            refused = new SubmissionResult(SubmissionStatus.Invalid, Guid.Empty, Detail: "no recipients");
            return default;
        }

        if (recipients.Count > _options.MaxRecipients || _policy.CheckRecipientCount(recipients.Count) is { } tooMany)
        {
            refused = new SubmissionResult(SubmissionStatus.Invalid, Guid.Empty, _policy.CheckRecipientCount(recipients.Count), "too many recipients");
            return default;
        }

        // The message is parsed once here; the sender check, the header repair and the history extraction all work from this one parse. The parse
        // objects live in the thread's lent buffers and are finished with when this method returns (everything kept is a copy).
        MimeParseBuffers buffers = t_parseBuffers ?? new MimeParseBuffers();
        t_parseBuffers = null;
        try
        {
            var parsed = MimeMessage.Parse(request.Message, null, buffers);
            string? fromDomain = HeaderFromDomain(parsed, out string? fromProblem);
            if (fromDomain is null)
            {
                refused = new SubmissionResult(SubmissionStatus.Invalid, Guid.Empty, Detail: fromProblem);
                return default;
            }

            IReadOnlyList<DomainRecord>? domains = loaded.Domains ?? CachedDomains(request.Tenant.Id);
            if (domains is null)
            {
                load = SubmissionLoad.Domains;
                return default;
            }

            var decision = _policy.Evaluate(request.Tenant, request.EnvelopeFrom, fromDomain, domains);
            if (!decision.IsAllowed)
            {
                refused = new SubmissionResult(SubmissionStatus.Rejected, Guid.Empty, decision.Rejection, decision.Rejection!.Message);
                return default;
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

            string messageIdHeader;
            if (headers.TryGetFirst(HeaderId.MessageId, out var existingMessageId))
            {
                messageIdHeader = existingMessageId.Value;
            }
            else
            {
                messageIdHeader = MessageBuilder.GenerateMessageId(_options.MessageIdDomain, _clock);
                editor.Prepend(HeaderNames.MessageId, messageIdHeader);
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
            var content = ExtractContent(parsed, request.Message, raw);

            // The tenant's setting is only looked up when it can matter: the operator allows attachment storage, the message has attachments to keep
            // and the request does not say.
            bool retainRaw = false;
            if (_storageOptions.Content.AllowAttachmentStorage && content is { Attachments.Count: > 0 })
            {
                if (request.StoreAttachments is { } requested)
                {
                    retainRaw = requested;
                }
                else
                {
                    bool? row;
                    if (loaded.HasAttachmentRow)
                    {
                        row = loaded.AttachmentRow;
                    }
                    else if (!TryCachedAttachmentRow(request.Tenant.Id, out row))
                    {
                        load = SubmissionLoad.AttachmentSetting;
                        return default;
                    }

                    retainRaw = AttachmentStoragePolicy.Combine(request.Tenant, row) ?? _storageOptions.Content.StoreAttachments;
                }
            }

            var messageId = Ids.New(now);
            var accepted = RentMessage();
            accepted.MessageId = messageId;
            accepted.TenantId = request.Tenant.Id;
            accepted.Source = request.Source;
            accepted.EnvelopeFrom = request.EnvelopeFrom;
            accepted.Recipients = ToAcceptedRecipients(recipients, now);
            accepted.Raw = raw;
            accepted.ReceivedAt = now;
            accepted.ExpiresAt = now + _storageOptions.Queue.MaxLifetime;
            accepted.IdempotencyKey = request.IdempotencyKey;
            accepted.IdempotencyFingerprint = request.IdempotencyFingerprint;
            accepted.RemoteAddress = request.RemoteAddress;
            accepted.Authenticated = request.Authenticated;
            // What the message itself needs (UTF-8 in its header fields), decided from its bytes rather than from the submitter's MAIL FROM
            // parameter: a client that declares SMTPUTF8 only for an internationalized address must not make every transaction of this
            // message demand SMTPUTF8, and one that sends UTF-8 headers without declaring it still gets them delivered as such.
            accepted.HeadersUtf8 = MessageInspector.HasValidUtf8Headers(raw);
            accepted.Content = content;
            accepted.RetainRaw = retainRaw;
            accepted.SendingDomain = decision.SendingDomain?.Name ?? fromDomain;
            accepted.MessageIdHeader = messageIdHeader;
            accepted.Tags = request.Tags is { Count: > 0 } tags ? tags.Distinct(StringComparer.Ordinal).ToList() : null;

            Activity? span = MessageTrace.Start(MessageTrace.SubmitSpan, messageId);
            if (span is not null)
            {
                span.SetTag("mta.tenant.id", Ids.ToCompact(request.Tenant.Id));
                span.SetTag("mta.message.source", request.Source.ToString());
                span.SetTag("mta.message.recipients", recipients.Count);
                span.SetTag("mta.message.size", raw.Length);
            }

            return new PreparedSubmission(accepted, span);
        }
        finally
        {
            buffers.Release();
            t_parseBuffers = buffers;
        }
    }

    /// <summary>The storage call for a prepared message. Not an asynchronous method: it is the task of the storage itself.</summary>
    public ValueTask<IntakeResult> StoreAsync(in PreparedSubmission prepared, CancellationToken ct) => _storage.Intake.AcceptAsync(prepared.Message!, ct);

    /// <summary>Ends a prepared submission whose storage call returned: hands the message object back, ends the trace span and returns the answer.</summary>
    public SubmissionResult Complete(ref PreparedSubmission prepared, in IntakeResult result)
    {
        Activity? span = prepared.Span;
        ReturnMessage(prepared.Message!);
        prepared = default;
        if (span is not null)
        {
            span.SetTag("mta.submit.outcome", result.Status == IntakeStatus.Accepted ? "accepted" : "duplicate");
            if (result.Status != IntakeStatus.Accepted)
            {
                span.SetTag("mta.submit.original_message_id", Ids.ToCompact(result.MessageId));   // an idempotent repeat: the message that counts is the first one
            }

            span.Dispose();
        }

        return new SubmissionResult(result.Status == IntakeStatus.Accepted ? SubmissionStatus.Accepted : SubmissionStatus.Duplicate, result.MessageId, IdempotencyFingerprint: result.IdempotencyFingerprint);
    }

    /// <summary>Ends a prepared submission whose storage call failed (threw or was cancelled): nothing is reported, the resources are released.</summary>
    public void Abandon(ref PreparedSubmission prepared)
    {
        Activity? span = prepared.Span;
        if (prepared.Message is { } message)
        {
            ReturnMessage(message);
        }

        prepared = default;
        span?.Dispose();
    }

    [ThreadStatic]
    private static MimeParseBuffers? t_parseBuffers;

    // The stored-message objects are reused: one is filled per submission and handed back as soon as storage has finished with it
    // (IMessageIntake.AcceptAsync completes only then and does not keep the object).
    private readonly System.Collections.Concurrent.ConcurrentQueue<AcceptedMessage> _messagePool = new();
    private int _pooledMessages;

    private AcceptedMessage RentMessage()
    {
        if (_messagePool.TryDequeue(out AcceptedMessage? message))
        {
            Interlocked.Decrement(ref _pooledMessages);
            return message;
        }

        return new AcceptedMessage { MessageId = default, TenantId = default, Source = default, EnvelopeFrom = default, Recipients = [], Raw = default, ReceivedAt = default, ExpiresAt = default };
    }

    private void ReturnMessage(AcceptedMessage message)
    {
        // Every reference is dropped: a pooled object must not keep the message, its recipients or its extracted content alive.
        message.EnvelopeFrom = default;
        message.Recipients = [];
        message.Raw = default;
        message.IdempotencyKey = null;
        message.IdempotencyFingerprint = null;
        message.RemoteAddress = null;
        message.Authenticated = null;
        message.Content = null;
        message.SendingDomain = null;
        message.MessageIdHeader = null;
        message.Tags = null;
        if (Interlocked.Increment(ref _pooledMessages) <= 256)
        {
            _messagePool.Enqueue(message);
        }
        else
        {
            Interlocked.Decrement(ref _pooledMessages);
        }
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
    public async ValueTask<IReadOnlyList<DomainRecord>> GetDomainsAsync(Guid tenantId, CancellationToken ct)
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

    /// <summary>The cached domain list of the tenant, or null when there is no current one.</summary>
    private IReadOnlyList<DomainRecord>? CachedDomains(Guid tenantId) =>
        _domainCache.TryGetValue(tenantId, out var cached) && _clock.Timestamp < cached.ExpiresAt && cached.Version == DomainChangeSignal.Version ? cached.Domains : null;

    private bool TryCachedAttachmentRow(Guid tenantId, out bool? row)
    {
        if (_attachmentRowCache.TryGetValue(tenantId, out var cached) && _clock.Timestamp < cached.ExpiresAt && cached.Version == AttachmentStoragePolicy.Version)
        {
            row = cached.Row;
            return true;
        }

        row = null;
        return false;
    }

    /// <summary>The tenant's attachment-storage row, cached briefly like the domain list (a change made through this process shows at once: <see cref="AttachmentStoragePolicy.Bump"/>).</summary>
    public async ValueTask<bool?> GetAttachmentRowAsync(Guid tenantId, CancellationToken ct)
    {
        long now = _clock.Timestamp;
        long version = AttachmentStoragePolicy.Version;
        if (_attachmentRowCache.TryGetValue(tenantId, out var cached) && now < cached.ExpiresAt && cached.Version == version)
        {
            return cached.Row;
        }

        bool? row = AttachmentStoragePolicy.RowSetting(tenantId, await _storage.Config.GetSettingsAsync(tenantId, ct).ConfigureAwait(false));
        _attachmentRowCache[tenantId] = (row, now + (long)(_options.DomainCacheTtl.TotalSeconds * System.Diagnostics.Stopwatch.Frequency), version);
        return row;
    }

    /// <summary>
    /// The content for history. A text or HTML body that is already valid UTF-8 in the message (the usual one) is kept as the bytes of the stored copy
    /// <paramref name="raw"/>, not as a string of twice the size: the storage binds those bytes as they are.
    /// </summary>
    private MessageContent? ExtractContent(MimeMessage parsed, ReadOnlyMemory<byte> original, byte[] raw)
    {
        if (_storage.HistoryMode != HistoryMode.Full || !_storageOptions.Content.Retain)
        {
            return null;
        }

        var extracted = MessageContentExtractor.Extract(parsed, _storageOptions.Content.MaxStoredBodyBytes, bodiesAsUtf8: true);
        string? text = extracted.TextBody;
        string? html = extracted.HtmlBody;
        ReadOnlyMemory<byte>? textBytes = null;
        ReadOnlyMemory<byte>? htmlBytes = null;
        if (extracted.TextBodyUtf8 is { } textBody && !TryFindInStoredCopy(textBody, original, raw, out textBytes))
        {
            text = Encoding.UTF8.GetString(textBody.Span);   // the same string the extraction without the shortcut gives
        }

        if (extracted.HtmlBodyUtf8 is { } htmlBody && !TryFindInStoredCopy(htmlBody, original, raw, out htmlBytes))
        {
            html = Encoding.UTF8.GetString(htmlBody.Span);
        }

        return new MessageContent(
            _storageOptions.Content.StoreSubject ? extracted.Subject : null,
            text,
            html,
            textBytes,
            htmlBytes,
            ToStoredAttachments(extracted.Attachments),
            extracted.IsTruncated);
    }

    /// <summary>
    /// Finds <paramref name="body"/> (a slice of <paramref name="original"/>) in the stored copy: only headers are added or removed, so the stored message ends with the
    /// same bytes as the original. False when it does not (line endings were repaired inside the body, the memory is not an array); the bytes are compared, never assumed.
    /// </summary>
    internal static bool TryFindInStoredCopy(ReadOnlyMemory<byte> body, ReadOnlyMemory<byte> original, byte[] raw, out ReadOnlyMemory<byte>? stored)
    {
        stored = null;
        if (!MemoryMarshal.TryGetArray(body, out ArraySegment<byte> bodySegment) || !MemoryMarshal.TryGetArray(original, out ArraySegment<byte> originalSegment)
            || !ReferenceEquals(bodySegment.Array, originalSegment.Array))
        {
            return false;
        }

        int offsetInOriginal = bodySegment.Offset - originalSegment.Offset;
        if (offsetInOriginal < 0 || offsetInOriginal + body.Length > original.Length)
        {
            return false;
        }

        int start = raw.Length - (original.Length - offsetInOriginal);
        if (start < 0 || start + body.Length > raw.Length || !raw.AsSpan(start, body.Length).SequenceEqual(body.Span))
        {
            return false;
        }

        stored = raw.AsMemory(start, body.Length);
        return true;
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

        switch (AddressList.GetCommonDomain(from, null, out string? domain))
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
