using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Mta.Core;
using Mta.Host.Submission;
using Mta.Mime;
using Mta.Storage;

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

/// <summary>Per-message history (<c>History:Mode=Full</c>): list, detail, events, content, resend. With <c>StatsOnly</c> all of it answers 410.</summary>
public sealed class MessagesApi(ApiAuthenticator auth, IStorage storage, SubmissionService submission, ApiOptions options, StorageOptions storageOptions, IClock clock)
{
    public void Map(RouteGroupBuilder api)
    {
        api.GetRoute("/messages", ListAsync);
        api.GetRoute("/messages/{id}", DetailAsync);
        api.GetRoute("/messages/{id}/events", EventsAsync);
        api.GetRoute("/messages/{id}/content", ContentAsync);
        api.PostRoute("/messages/{id}/resend", ResendAsync);
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
            StoreAttachments = !recomposed,
        }, ct).ConfigureAwait(false);
        if (!result.IsAccepted)
        {
            throw SubmissionErrors.ToException(result);
        }

        return ApiResults.Accepted(new ResendResponse(result.MessageId, recomposed));
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
