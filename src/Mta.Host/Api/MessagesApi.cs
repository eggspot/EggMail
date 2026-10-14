using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Mta.Core;
using Mta.Host.Submission;
using Mta.Mime;
using Mta.Storage;
using Mta.Webhooks;

namespace Mta.Host.Api;

public sealed record MessageSummaryResponse(Guid Id, DateTimeOffset ReceivedAt, string Subject, string From, IReadOnlyList<string> Recipients, int RecipientCount, string Status, long Size, IReadOnlyList<string> Tags);

public sealed record AttachmentResponse(string Filename, [property: JsonPropertyName("content_type")] string? ContentType, long Size, [property: JsonPropertyName("content_id")] string? ContentId);

public sealed record MessageContentResponse(
    string State,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Text,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Html,
    IReadOnlyList<AttachmentResponse> Attachments,
    bool Truncated);

public sealed record MessageDetailResponse(
    Guid Id,
    Guid TenantId,
    DateTimeOffset ReceivedAt,
    string Subject,
    string From,
    IReadOnlyList<string> Recipients,
    int RecipientCount,
    string Status,
    long Size,
    MessageContentResponse Content,
    bool RawRetained,
    IReadOnlyList<string> Tags);

public sealed record TlsResponse(
    bool Used,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Version,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Cipher,
    bool Verified,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Policy,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PeerSubject,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PeerIssuer,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PeerSha256,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PolicyErrors,
    bool StartTlsAdvertised,
    bool PlaintextFallback);

public sealed record MessageEventResponse(Guid Id, string Type, DateTimeOffset At, string? Recipient, int? SmtpCode, string? EnhancedCode, string? Message, string? MxHost, string? Route, TlsResponse? Tls);

public sealed record ResendResponse(Guid Id, bool Recomposed);

/// <summary>Optional body of <c>POST /messages/{id}/cancel</c>: omit it (or the member) to cancel every recipient still waiting for delivery.</summary>
public sealed class CancelMessageRequest
{
    [JsonPropertyName("recipients")]
    public List<string>? Recipients { get; set; }
}

/// <summary>What a cancel did, per recipient (docs/api.md). <c>Status</c> is the message status afterwards and is left out when history is not recorded.</summary>
public sealed record CancelMessageResponse(
    Guid Id,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Status,
    IReadOnlyList<string> Cancelled,
    IReadOnlyList<string> InFlight,
    IReadOnlyList<string> TransferHeld,
    IReadOnlyList<string> NotWaiting);

/// <summary>Per-message history (<c>History:Mode=Full</c>): list, detail, events, content, resend. With <c>StatsOnly</c> all of it answers 410 (cancelling does not need history and works in both modes).</summary>
public sealed class MessagesApi(ApiAuthenticator auth, IStorage storage, SubmissionService submission, ApiOptions options, StorageOptions storageOptions, IClock clock)
{
    public void Map(RouteGroupBuilder api)
    {
        api.GetRoute("/messages", ListAsync);
        api.GetRoute("/messages/{id}", DetailAsync);
        api.GetRoute("/messages/{id}/events", EventsAsync);
        api.GetRoute("/messages/{id}/content", ContentAsync);
        api.PostRoute("/messages/{id}/resend", ResendAsync);
        api.PostRoute("/messages/{id}/cancel", CancelAsync);
    }

    private void RequireHistory()
    {
        if (storage.HistoryMode != HistoryMode.Full)
        {
            throw new ApiException(
                StatusCodes.Status410Gone,
                ApiCodes.HistoryNotRecorded,
                "History:Mode is StatsOnly; per-message data is not stored.",
                extensions: new Dictionary<string, object?> { ["history_mode"] = "StatsOnly" });
        }
    }

    private static Guid ParseMessageId(string id) =>
        ApiJson.TryParseId(id, out Guid guid) ? guid : throw new ApiException(StatusCodes.Status404NotFound, ApiCodes.MessageNotFound, "No message with that id (unknown, or older than the event retention).");

    private static ApiException NotFound() =>
        new(StatusCodes.Status404NotFound, ApiCodes.MessageNotFound, "No message with that id (unknown, or older than the event retention).");

    private async Task<IResult> ListAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Read).ConfigureAwait(false);
        RequireHistory();
        var errors = new ValidationErrors();
        var q = new QueryReader(context.Request, errors);
        var query = new MessageQuery(
            TenantId: caller.TenantId,
            Recipient: q.String("recipient", 320),
            Sender: q.String("sender", 320),
            SubjectContains: q.String("subject", 200),
            Status: q.String("status", 32),
            Tag: q.String("tag", 64),
            From: q.Timestamp("from"),
            To: q.Timestamp("to"),
            Limit: q.Int("limit", 50, 1, 200),
            Cursor: q.String("cursor", 512));
        errors.ThrowIfAny();

        Page<MessageSummary> page;
        try
        {
            page = await storage.History.SearchAsync(query, context.RequestAborted).ConfigureAwait(false);
        }
        catch (ArgumentException)
        {
            throw ApiException.Validation("cursor", "Not a valid cursor.");
        }

        IReadOnlyDictionary<Guid, IReadOnlyList<string>> recipients = new Dictionary<Guid, IReadOnlyList<string>>();
        if (storage.History is IMessageRecipientLookup lookup && page.Items.Count > 0)
        {
            recipients = await lookup.GetRecipientsAsync(caller.TenantId, page.Items.Select(i => i.MessageId).ToList(), 5, context.RequestAborted).ConfigureAwait(false);
        }

        var items = page.Items.Select(i => new MessageSummaryResponse(
            i.MessageId, i.ReceivedAt, i.Subject ?? "", i.EnvelopeFrom, recipients.TryGetValue(i.MessageId, out var r) ? r : [], i.RecipientCount, i.Status ?? "queued", i.Size, i.Tags ?? [])).ToList();
        return ApiResults.Ok(new ListResponse<MessageSummaryResponse>(items, page.NextCursor));
    }

    private async Task<IResult> DetailAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Read).ConfigureAwait(false);
        RequireHistory();
        MessageDetail detail = await storage.History.GetAsync(caller.TenantId, ParseMessageId(id), context.RequestAborted).ConfigureAwait(false) ?? throw NotFound();
        MessageSummary s = detail.Summary;
        return ApiResults.Ok(new MessageDetailResponse(
            s.MessageId, s.TenantId, s.ReceivedAt, s.Subject ?? detail.Content?.Subject ?? "", s.EnvelopeFrom, detail.Recipients, s.RecipientCount, s.Status ?? "queued", s.Size, ContentOf(detail), detail.RawRetained, s.Tags ?? []));
    }

    private static MessageContentResponse ContentOf(MessageDetail detail) => detail.ContentState switch
    {
        ContentState.Available when detail.Content is { } c =>
            new MessageContentResponse("available", c.Text, c.Html, c.Attachments.Select(a => new AttachmentResponse(a.FileName ?? "attachment", a.ContentType, a.Size, a.ContentId)).ToList(), c.Truncated),
        ContentState.Expired => new MessageContentResponse("body_expired", null, null, [], false),
        _ => new MessageContentResponse("not_recorded", null, null, [], false),
    };

    private async Task<IResult> EventsAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Read).ConfigureAwait(false);
        RequireHistory();
        Guid messageId = ParseMessageId(id);
        // History returns an empty list for an unknown id, so existence (and tenant ownership) is decided by the detail lookup.
        _ = await storage.History.GetAsync(caller.TenantId, messageId, context.RequestAborted).ConfigureAwait(false) ?? throw NotFound();
        IReadOnlyList<MessageEvent> events = await storage.History.GetEventsAsync(caller.TenantId, messageId, context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(events.Select(e => new MessageEventResponse(
            e.EventId, ApiMap.EventType(e.Type), e.At, e.Recipient, e.SmtpCode, e.EnhancedCode, e.Message, e.MxHost, e.Route, e.Tls is null ? null : TlsOf(e.Tls))).ToList());
    }

    private static TlsResponse TlsOf(TlsInfo t) =>
        new(t.Used, t.Version, t.CipherSuite, t.Verified, t.PolicyApplied, t.PeerSubject, t.PeerIssuer, t.PeerSha256, t.PolicyErrors, t.StartTlsAdvertised, t.PlaintextFallback);

    private ApiException BodyExpired(DateTimeOffset receivedAt) => new(
        StatusCodes.Status410Gone,
        ApiCodes.BodyExpired,
        "The message content has expired and was removed.",
        extensions: new Dictionary<string, object?> { ["expired_at"] = receivedAt.AddDays(storageOptions.Content.RetentionDays), ["retention_days"] = storageOptions.Content.RetentionDays });

    private static ApiException NotRecorded() => new(
        StatusCodes.Status410Gone,
        ApiCodes.ContentNotRecorded,
        "The content of this message was not recorded (Content:Mode=None).");

    private async Task<IResult> ContentAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Read).ConfigureAwait(false);
        RequireHistory();
        MessageDetail detail = await storage.History.GetAsync(caller.TenantId, ParseMessageId(id), context.RequestAborted).ConfigureAwait(false) ?? throw NotFound();
        return detail.ContentState switch
        {
            ContentState.Expired => throw BodyExpired(detail.Summary.ReceivedAt),
            ContentState.NotRecorded => throw NotRecorded(),
            _ => ApiResults.Ok(ContentOf(detail)),
        };
    }

    private async Task<IResult> ResendAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Send).ConfigureAwait(false);
        RequireHistory();
        CancellationToken ct = context.RequestAborted;
        MessageDetail detail = await storage.History.GetAsync(caller.TenantId, ParseMessageId(id), ct).ConfigureAwait(false) ?? throw NotFound();
        if (detail.Summary.EnvelopeFrom.Length == 0 || !EmailAddress.TryParse(detail.Summary.EnvelopeFrom, allowUtf8: true, out EmailAddress from))
        {
            throw ApiException.Conflict("A message without a sender (a bounce) cannot be resent.");
        }

        var recipients = new List<EmailAddress>();
        foreach (string r in detail.Recipients)
        {
            if (EmailAddress.TryParse(r, allowUtf8: true, out EmailAddress address))
            {
                recipients.Add(address);
            }
        }

        if (recipients.Count == 0)
        {
            throw ApiException.Conflict("The message has no recipients left to resend to.");
        }

        byte[]? raw = detail.RawRetained ? await storage.History.GetRetainedRawAsync(caller.TenantId, detail.Summary.MessageId, ct).ConfigureAwait(false) : null;
        bool recomposed = raw is null;
        if (raw is null)
        {
            raw = Recompose(detail, from, recipients, caller.Tenant!);
        }

        SubmissionResult result = await submission.SubmitAsync(new SubmissionRequest
        {
            Tenant = caller.Tenant!,
            Source = MessageSource.Api,
            EnvelopeFrom = from,
            Recipients = recipients,
            Message = raw,
            RemoteAddress = context.Connection.RemoteIpAddress?.ToString(),
            Authenticated = caller.Name,
            StoreAttachments = null,   // the tenant's choice (then the operator default) decides, as for any send: a resend must not override an opt-out
        }, ct).ConfigureAwait(false);
        if (!result.IsAccepted)
        {
            throw SubmissionErrors.ToException(result);
        }

        return ApiResults.Accepted(new ResendResponse(result.MessageId, recomposed));
    }

    /// <summary>The most recipients one cancel request may name (a message has at most <c>Smtp:MaxRecipients</c>, 50 by default).</summary>
    private const int MaxCancelRecipients = 200;

    private async Task<IResult> CancelAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Send).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        Guid messageId = ParseMessageId(id);

        // The body is optional: no body, or no recipients member, cancels every recipient still waiting. An empty list is an error, never "all".
        IReadOnlyList<string>? recipients = null;
        HttpRequest request = context.Request;
        bool hasBody = request.ContentLength is > 0 || (request.ContentLength is null && !string.IsNullOrEmpty(request.ContentType));
        if (hasBody)
        {
            CancelMessageRequest body = await ApiJson.ReadBodyAsync<CancelMessageRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
            if (body.Recipients is { } named)
            {
                var errors = new ValidationErrors();
                var parsed = new List<string>(named.Count);
                if (named.Count == 0 || named.Count > MaxCancelRecipients)
                {
                    errors.Add("recipients", $"Name 1 to {MaxCancelRecipients} recipients, or leave the member out to cancel every recipient that is still waiting.");
                }
                else
                {
                    for (int i = 0; i < named.Count; i++)
                    {
                        if (string.IsNullOrWhiteSpace(named[i]) || named[i].Length > 320 || !EmailAddress.TryParse(named[i].Trim(), allowUtf8: true, out EmailAddress address))
                        {
                            errors.Add($"recipients[{i}]", "Enter a valid email address.");
                        }
                        else
                        {
                            parsed.Add(address.ToString());
                        }
                    }
                }

                errors.ThrowIfAny();
                recipients = parsed;
            }
        }

        // The queue is keyed by tenant as well as message id, so another tenant's message looks exactly like an unknown one: nothing is waiting. Cancelling needs
        // no history: it acts on the queue and records history only when history is recorded.
        CancelResult result = await storage.Deliveries.CancelAsync(
            caller.TenantId, messageId, recipients, clock.UtcNow, info => storage.Webhooks.MayHaveSubscribers(info.TenantId, WebhookEventFactory.Cancelled) ? WebhookEventFactory.ForCancelled(info) : null, ct).ConfigureAwait(false);

        if (result.Cancelled.Count > 0)
        {
            string? status = storage.HistoryMode == HistoryMode.Full ? (await storage.History.GetAsync(caller.TenantId, messageId, ct).ConfigureAwait(false))?.Summary.Status : null;
            return ApiResults.Ok(new CancelMessageResponse(messageId, status, result.Cancelled, result.InFlight, result.TransferHeld, result.NotWaiting));
        }

        if (result.InFlight.Count > 0 || result.TransferHeld.Count > 0)
        {
            throw NothingCancelled(result, result.InFlight.Count > 0
                ? "Every recipient that is still waiting is being delivered right now. Try again when the attempt has ended (a recipient that is deferred can be cancelled between attempts)."
                : "A storage backend switch holds the waiting recipients, so they cannot be cancelled until the switch is finished or rolled back.");
        }

        if (storage.HistoryMode != HistoryMode.Full)
        {
            // Without history the queue is all there is: a message with no waiting recipient cannot be told from one that never existed.
            throw result.Waiting == 0
                ? NotFound()
                : NothingCancelled(result, "None of the named recipients is waiting for delivery.");
        }

        MessageDetail detail = await storage.History.GetAsync(caller.TenantId, messageId, ct).ConfigureAwait(false) ?? throw NotFound();
        if (await AlreadyCancelledAsync(caller.TenantId, messageId, detail.Summary.Status, recipients, result, ct).ConfigureAwait(false))
        {
            // A repeated request whose work is already done: success, nothing more to cancel.
            return ApiResults.Ok(new CancelMessageResponse(messageId, detail.Summary.Status, [], [], [], []));
        }

        throw NothingCancelled(result, result.Waiting == 0
            ? "No recipient of this message is waiting for delivery: each is delivered, failed, expired, suppressed or already cancelled."
            : "None of the named recipients is waiting for delivery.");
    }

    private ApiException NothingCancelled(CancelResult result, string detail) => new(
        StatusCodes.Status409Conflict,
        ApiCodes.Conflict,
        detail,
        extensions: new Dictionary<string, object?> { ["inFlight"] = result.InFlight, ["transferHeld"] = result.TransferHeld, ["notWaiting"] = result.NotWaiting });

    /// <summary>Whether the request asks for what already happened: every named recipient has a <c>cancelled</c> event, or (without names) the whole message is cancelled.</summary>
    private async Task<bool> AlreadyCancelledAsync(Guid tenantId, Guid messageId, string? status, IReadOnlyList<string>? requested, CancelResult result, CancellationToken ct)
    {
        if (requested is null)
        {
            return result.Waiting == 0 && string.Equals(status, "cancelled", StringComparison.Ordinal);
        }

        IReadOnlyList<MessageEvent> events = await storage.History.GetEventsAsync(tenantId, messageId, ct).ConfigureAwait(false);
        var cancelled = new HashSet<string>(events.Where(e => e.Type == MessageEventType.Cancelled && e.Recipient is not null).Select(e => e.Recipient!), StringComparer.OrdinalIgnoreCase);
        return requested.All(cancelled.Contains);
    }

    /// <summary>Rebuilds an attachment-free message from its stored content (labelled <c>recomposed</c>; headers are not byte-identical).</summary>
    private byte[] Recompose(MessageDetail detail, EmailAddress from, IReadOnlyList<EmailAddress> recipients, Tenant tenant)
    {
        switch (detail.ContentState)
        {
            case ContentState.Expired:
                throw BodyExpired(detail.Summary.ReceivedAt);
            case ContentState.NotRecorded:
                throw NotRecorded();
        }

        MessageContent content = detail.Content ?? throw NotRecorded();
        if (content.Attachments.Count > 0)
        {
            throw new ApiException(StatusCodes.Status409Conflict, ApiCodes.AttachmentsNotStored, "The message had attachments that were not stored, so it cannot be resent.");
        }

        if (content.Truncated)
        {
            throw ApiException.Conflict("The stored content was truncated, so it cannot be re-composed. Send the message again from the original.");
        }

        bool international = from.IsInternational || recipients.Any(r => r.IsInternational);
        var builder = new MessageBuilder(new MessageBuilderOptions
        {
            MessageIdDomain = EmailAddress.IsValidHostName(from.Domain) ? from.Domain : options.MessageIdDomain,
            Clock = clock,
            AllowUtf8Headers = international,
        });
        builder.From = new Mailbox(null, from);

        // The stored envelope recipients mix To, Cc and Bcc, so only a single recipient can safely appear in the To header.
        if (recipients.Count == 1)
        {
            builder.To.Add(new Mailbox(null, recipients[0]));
        }

        builder.Subject = content.Subject ?? detail.Summary.Subject ?? "";
        builder.TextBody = string.IsNullOrEmpty(content.Text) ? null : content.Text;
        builder.HtmlBody = string.IsNullOrEmpty(content.Html) ? null : content.Html;
        if (builder.TextBody is null && builder.HtmlBody is null)
        {
            builder.TextBody = "";
        }

        try
        {
            return builder.Build().Content;
        }
        catch (Exception ex) when (ex is MessageBuildException or ArgumentException)
        {
            throw ApiException.Conflict("The message cannot be re-composed: " + ex.Message);
        }
    }
}
