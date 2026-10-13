using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Mta.Core;
using Mta.Host.Submission;
using Mta.Mime;
using Mta.Storage;

namespace Mta.Host.Api;

public sealed class AttachmentRequest
{
    [JsonPropertyName("filename")]
    public string? Filename { get; set; }

    [JsonPropertyName("content_type")]
    public string? ContentType { get; set; }

    /// <summary>Base64 on the wire; the JSON reader decodes it straight into bytes.</summary>
    [JsonPropertyName("content")]
    public byte[]? Content { get; set; }

    [JsonPropertyName("content_id")]
    public string? ContentId { get; set; }
}

/// <summary><c>POST /messages</c> (docs/api.md, "Sending").</summary>
public sealed class SendRequest
{
    [JsonPropertyName("from")]
    public string? From { get; set; }

    [JsonPropertyName("to")]
    public List<string>? To { get; set; }

    [JsonPropertyName("cc")]
    public List<string>? Cc { get; set; }

    [JsonPropertyName("bcc")]
    public List<string>? Bcc { get; set; }

    [JsonPropertyName("reply_to")]
    public string? ReplyTo { get; set; }

    [JsonPropertyName("subject")]
    public string? Subject { get; set; }

    [JsonPropertyName("text")]
    public string? Text { get; set; }

    [JsonPropertyName("html")]
    public string? Html { get; set; }

    [JsonPropertyName("headers")]
    public Dictionary<string, string>? Headers { get; set; }

    [JsonPropertyName("attachments")]
    public List<AttachmentRequest>? Attachments { get; set; }

    [JsonPropertyName("store_attachments")]
    public bool? StoreAttachments { get; set; }

    [JsonPropertyName("tags")]
    public List<string>? Tags { get; set; }
}

/// <summary><c>POST /messages/raw</c>: a pre-built RFC 5322 message (for example already DKIM-signed by the sender).</summary>
public sealed class SendRawRequest
{
    [JsonPropertyName("from")]
    public string? From { get; set; }

    [JsonPropertyName("to")]
    public List<string>? To { get; set; }

    [JsonPropertyName("raw")]
    public byte[]? Raw { get; set; }

    [JsonPropertyName("store_attachments")]
    public bool? StoreAttachments { get; set; }
}

public sealed record SendResponse(Guid Id, string Status, int Recipients);

/// <summary>A composed message ready for <see cref="SubmissionService"/>.</summary>
public sealed record ComposedMessage(byte[] Raw, EmailAddress EnvelopeFrom, IReadOnlyList<EmailAddress> Recipients, bool SmtpUtf8, IReadOnlyList<string>? Tags = null);

/// <summary>Validates a <see cref="SendRequest"/> and composes it into an RFC 5322 message with <see cref="MessageBuilder"/>.</summary>
public static class MessageComposer
{
    private static readonly char[] ContentIdForbidden = ['<', '>', ' ', '\t', '\r', '\n', '\0'];

    public static ComposedMessage Compose(SendRequest request, ApiOptions options, IClock clock)
    {
        var errors = new ValidationErrors();
        Mailbox? from = ParseMailbox(request.From, "from", errors, required: true);
        var to = ParseList(request.To, "to", errors, required: true);
        var cc = ParseList(request.Cc, "cc", errors, required: false);
        var bcc = ParseList(request.Bcc, "bcc", errors, required: false);
        Mailbox? replyTo = ParseMailbox(request.ReplyTo, "reply_to", errors, required: false);

        int total = to.Count + cc.Count + bcc.Count;
        if (total > options.MaxRecipients)
        {
            errors.Add("to", $"At most {options.MaxRecipients} recipients are allowed in total (got {total}).");
        }

        if (string.IsNullOrWhiteSpace(request.Subject))
        {
            errors.Add("subject", "A subject is required.");
        }
        else if (request.Subject.AsSpan().IndexOfAny('\r', '\n', '\0') >= 0)
        {
            errors.Add("subject", "The subject must not contain line breaks.");
        }
        else if (request.Subject.Length > 998)
        {
            errors.Add("subject", "At most 998 characters.");
        }

        if (string.IsNullOrEmpty(request.Text) && string.IsNullOrEmpty(request.Html))
        {
            errors.Add("text", "Provide a text or an html body.");
        }

        if (request.Tags is { } tags)
        {
            if (tags.Count > options.MaxTags)
            {
                errors.Add("tags", $"At most {options.MaxTags} tags.");
            }

            for (int i = 0; i < tags.Count; i++)
            {
                if (string.IsNullOrWhiteSpace(tags[i]) || tags[i].Length > 64 || tags[i].Any(char.IsControl))
                {
                    errors.Add($"tags[{i}]", "A tag is 1 to 64 characters without control characters.");
                }
            }
        }

        bool international = new[] { from }.Concat(to).Concat(cc).Concat(bcc).Concat([replyTo]).Any(m => m is { IsValid: true, Address.IsInternational: true });
        string idDomain = from?.Domain is { } d && EmailAddress.IsValidHostName(d) ? d : options.MessageIdDomain;
        var builder = new MessageBuilder(new MessageBuilderOptions { MessageIdDomain = idDomain, Clock = clock, AllowUtf8Headers = international });
        builder.From = from;
        foreach (Mailbox m in to) { builder.To.Add(m); }
        foreach (Mailbox m in cc) { builder.Cc.Add(m); }
        foreach (Mailbox m in bcc) { builder.Bcc.Add(m); }
        if (replyTo is not null) { builder.ReplyTo.Add(replyTo); }
        builder.Subject = request.Subject;
        builder.TextBody = string.IsNullOrEmpty(request.Text) ? null : request.Text;
        builder.HtmlBody = string.IsNullOrEmpty(request.Html) ? null : request.Html;

        if (request.Headers is { } headers)
        {
            if (headers.Count > options.MaxCustomHeaders)
            {
                errors.Add("headers", $"At most {options.MaxCustomHeaders} custom headers.");
            }
            else
            {
                foreach (var (name, value) in headers)
                {
                    if (value is null)
                    {
                        errors.Add("headers", $"Header '{Printable(name)}' needs a text value.");
                        continue;
                    }

                    try
                    {
                        builder.AddHeader(name, value);
                    }
                    catch (Exception ex) when (ex is ArgumentException or MessageBuildException)
                    {
                        errors.Add("headers", ex is HeaderInjectionException ? $"Header '{Printable(name)}' contains characters that are not allowed (CR, LF or NUL)." : ex.Message);
                    }
                }
            }
        }

        long attachmentBytes = 0;
        if (request.Attachments is { } attachments)
        {
            if (attachments.Count > options.MaxAttachments)
            {
                errors.Add("attachments", $"At most {options.MaxAttachments} attachments.");
            }
            else
            {
                for (int i = 0; i < attachments.Count; i++)
                {
                    AttachmentRequest? a = attachments[i];
                    string at = $"attachments[{i}]";
                    if (a is null)
                    {
                        errors.Add(at, "An attachment object is required.");
                        continue;
                    }

                    if (string.IsNullOrWhiteSpace(a.Filename) || a.Filename.Length > 255)
                    {
                        errors.Add(at + ".filename", "A file name of 1 to 255 characters is required.");
                    }

                    if (a.Content is null || a.Content.Length == 0)
                    {
                        errors.Add(at + ".content", "Base64 content is required.");
                    }

                    if (a.ContentId is { } cid && (cid.Length is 0 or > 255 || cid.IndexOfAny(ContentIdForbidden) >= 0))
                    {
                        errors.Add(at + ".content_id", "A Content-ID without spaces or angle brackets.");
                    }

                    if (string.IsNullOrWhiteSpace(a.Filename) || a.Content is null || a.Content.Length == 0 || a.Filename.Length > 255)
                    {
                        continue;
                    }

                    attachmentBytes += a.Content.Length;
                    try
                    {
                        builder.Attachments.Add(new BuilderAttachment(a.Filename, string.IsNullOrWhiteSpace(a.ContentType) ? "application/octet-stream" : a.ContentType, a.Content)
                        {
                            ContentId = a.ContentId,
                            IsInline = a.ContentId is not null,
                        });
                    }
                    catch (ArgumentException)
                    {
                        errors.Add(at + ".content_type", "Not a valid media type (for example application/pdf).");
                    }
                }
            }
        }

        errors.ThrowIfAny();

        long approximate = attachmentBytes + (request.Text?.Length ?? 0) + (request.Html?.Length ?? 0);
        if (approximate > options.MaxMessageBytes)
        {
            throw new ApiException(StatusCodes.Status413PayloadTooLarge, ApiCodes.PayloadTooLarge, $"The message is larger than the allowed {options.MaxMessageBytes} bytes.");
        }

        byte[] raw;
        try
        {
            raw = builder.Build().Content;
        }
        catch (MessageBuildException ex)
        {
            throw ApiException.Validation("$", ex.Message);
        }
        catch (HeaderInjectionException ex)
        {
            throw ApiException.Validation("$", ex.Message);
        }

        if (raw.Length > options.MaxMessageBytes)
        {
            throw new ApiException(StatusCodes.Status413PayloadTooLarge, ApiCodes.PayloadTooLarge, $"The message is larger than the allowed {options.MaxMessageBytes} bytes.");
        }

        var recipients = to.Concat(cc).Concat(bcc).Select(m => m.Address).ToList();
        return new ComposedMessage(raw, from!.Address, recipients, international, request.Tags);
    }

    /// <summary>Parses the From and recipient addresses of a raw submission.</summary>
    public static (EmailAddress From, IReadOnlyList<EmailAddress> Recipients, bool SmtpUtf8) ParseEnvelope(string? from, List<string>? to, ApiOptions options, ValidationErrors errors)
    {
        Mailbox? sender = ParseMailbox(from, "from", errors, required: true);
        var recipients = ParseList(to, "to", errors, required: true);
        if (recipients.Count > options.MaxRecipients)
        {
            errors.Add("to", $"At most {options.MaxRecipients} recipients are allowed (got {recipients.Count}).");
        }

        errors.ThrowIfAny();
        bool utf8 = sender!.Address.IsInternational || recipients.Any(r => r.Address.IsInternational);
        return (sender.Address, recipients.Select(r => r.Address).ToList(), utf8);
    }

    private static Mailbox? ParseMailbox(string? text, string field, ValidationErrors errors, bool required)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            if (required)
            {
                errors.Add(field, "A valid email address is required.");
            }

            return null;
        }

        if (text.Length > 998 || !Mailbox.TryParse(text, out Mailbox mailbox))
        {
            errors.Add(field, "Not a valid email address (Name <user@example.com> or user@example.com).");
            return null;
        }

        return mailbox;
    }

    private static List<Mailbox> ParseList(List<string>? values, string field, ValidationErrors errors, bool required)
    {
        var result = new List<Mailbox>();
        if (values is null || values.Count == 0)
        {
            if (required)
            {
                errors.Add(field, "At least one recipient is required.");
            }

            return result;
        }

        for (int i = 0; i < values.Count; i++)
        {
            Mailbox? m = ParseMailbox(values[i], $"{field}[{i}]", errors, required: true);
            if (m is not null)
            {
                result.Add(m);
            }
        }

        return result;
    }

    private static string Printable(string name) => new(name.Take(64).Select(c => char.IsControl(c) ? '?' : c).ToArray());
}

/// <summary>Turns a refused <see cref="SubmissionResult"/> into the API error of docs/api.md.</summary>
public static class SubmissionErrors
{
    public static ApiException ToException(SubmissionResult result)
    {
        switch (result.Status)
        {
            case SubmissionStatus.TooLarge:
                return new ApiException(StatusCodes.Status413PayloadTooLarge, ApiCodes.PayloadTooLarge, result.Detail ?? "The message exceeds the size limit.");
            case SubmissionStatus.Rejected:
                {
                    var rejection = result.Rejection!;
                    return rejection.ApiErrorCode switch
                    {
                        "tenant_disabled" => new ApiException(StatusCodes.Status403Forbidden, ApiCodes.TenantDisabled, rejection.Message),
                        "sender_domain_not_registered" or "sender_domain_not_verified" or "sender_domain_verification_failed" or "sending_paused" =>
                            new ApiException(StatusCodes.Status403Forbidden, ApiCodes.DomainNotVerified, rejection.Message, extensions: new Dictionary<string, object?> { ["reason"] = rejection.ApiErrorCode }),
                        "null_sender_not_allowed" or "sender_required" => ApiException.Validation("from", rejection.Message),
                        _ => new ApiException(StatusCodes.Status403Forbidden, ApiCodes.Forbidden, rejection.Message),
                    };
                }

            default:
                return result.Rejection is { ApiErrorCode: "too_many_recipients" } many
                    ? ApiException.Validation("to", many.Message)
                    : ApiException.Validation("$", result.Detail ?? "The message cannot be queued.");
        }
    }
}

/// <summary>Bounds the memory held by send requests in flight: each reserves its declared body size (or the maximum when it is not declared) for its duration.</summary>
public sealed class SendBudget(ApiOptions options)
{
    private long _inFlight;

    public long InFlightBytes => Interlocked.Read(ref _inFlight);

    /// <summary>Reserves memory for a request, or throws 429. Dispose the lease when the request is done.</summary>
    public Lease Reserve(HttpContext context)
    {
        long wanted = Math.Min(context.Request.ContentLength ?? options.MaxSendBodyBytes, options.MaxSendBodyBytes);
        // A single request larger than the whole budget is still allowed on an idle server (the budget is configurable below the body limit).
        long now = Interlocked.Add(ref _inFlight, wanted);
        if (now > options.MaxInFlightSendBytes && now != wanted)
        {
            Interlocked.Add(ref _inFlight, -wanted);
            throw ApiException.RateLimited("The server is busy accepting other messages. Retry shortly.", TimeSpan.FromSeconds(1));
        }

        return new Lease(this, wanted);
    }

    public readonly struct Lease(SendBudget budget, long bytes) : IDisposable
    {
        public void Dispose() => Interlocked.Add(ref budget._inFlight, -bytes);
    }
}

/// <summary>The sending endpoints; both go through <see cref="SubmissionService"/>, the one path into the queue.</summary>
public sealed class SendingApi(ApiAuthenticator auth, SubmissionService submission, ApiOptions options, IClock clock, SendBudget budget)
{
    public void Map(RouteGroupBuilder api)
    {
        api.PostRoute("/messages", SendAsync);
        api.PostRoute("/messages/raw", SendRawAsync);
    }

    private async Task<IResult> SendAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Send).ConfigureAwait(false);
        string? key = IdempotencyKeyOf(context);
        using SendBudget.Lease lease = budget.Reserve(context);
        (SendRequest body, string digest) = await ApiJson.ReadBodyWithDigestAsync<SendRequest>(context, options.MaxSendBodyBytes).ConfigureAwait(false);
        ComposedMessage composed = MessageComposer.Compose(body, options, clock);
        return await SubmitAsync(context, caller, composed, key, "messages\n" + digest, body.StoreAttachments).ConfigureAwait(false);
    }

    private async Task<IResult> SendRawAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Send).ConfigureAwait(false);
        string? key = IdempotencyKeyOf(context);
        using SendBudget.Lease lease = budget.Reserve(context);
        (SendRawRequest body, string digest) = await ApiJson.ReadBodyWithDigestAsync<SendRawRequest>(context, options.MaxSendBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        if (body.Raw is null || body.Raw.Length == 0)
        {
            errors.Add("raw", "A base64 encoded RFC 5322 message is required.");
        }
        else if (body.Raw.Length > options.MaxMessageBytes)
        {
            throw new ApiException(StatusCodes.Status413PayloadTooLarge, ApiCodes.PayloadTooLarge, $"The message is larger than the allowed {options.MaxMessageBytes} bytes.");
        }

        var (from, recipients, utf8) = MessageComposer.ParseEnvelope(body.From, body.To, options, errors);
        byte[] raw = LineEndings.ToCrlf(body.Raw!);
        return await SubmitAsync(context, caller, new ComposedMessage(raw, from, recipients, utf8), key, "raw\n" + digest, body.StoreAttachments).ConfigureAwait(false);
    }

    private async Task<IResult> SubmitAsync(HttpContext context, ApiCaller caller, ComposedMessage message, string? idempotencyKey, string fingerprint, bool? storeAttachmentsFlag)
    {
        Tenant tenant = caller.Tenant!;
        SubmissionResult result = await submission.SubmitAsync(new SubmissionRequest
        {
            Tenant = tenant,
            Source = MessageSource.Api,
            EnvelopeFrom = message.EnvelopeFrom,
            Recipients = message.Recipients,
            Message = message.Raw,
            RemoteAddress = context.Connection.RemoteIpAddress?.ToString(),
            Authenticated = caller.Name,
            SmtpUtf8 = message.SmtpUtf8,
            IdempotencyKey = idempotencyKey,
            IdempotencyFingerprint = idempotencyKey is null ? null : fingerprint,
            StoreAttachments = storeAttachmentsFlag,   // null: the submission service applies the tenant's setting, then the global default (design section 5)
            Tags = message.Tags,
        }, context.RequestAborted).ConfigureAwait(false);

        if (!result.IsAccepted)
        {
            throw SubmissionErrors.ToException(result);
        }

        if (result.Status == SubmissionStatus.Duplicate)
        {
            if (result.IdempotencyFingerprint is { } stored && !string.Equals(stored, fingerprint, StringComparison.Ordinal))
            {
                throw new ApiException(StatusCodes.Status409Conflict, ApiCodes.IdempotencyConflict, "This Idempotency-Key was already used with a different request body.");
            }

            context.Response.Headers["Idempotent-Replayed"] = "true";
        }

        return ApiResults.Accepted(new SendResponse(result.MessageId, "queued", message.Recipients.Distinct().Count()));
    }

    private static string? IdempotencyKeyOf(HttpContext context)
    {
        string key = context.Request.Headers["Idempotency-Key"].ToString();
        if (key.Length == 0)
        {
            return null;
        }

        if (key.Length > 255 || key.Any(c => c < 0x21 || c > 0x7E))
        {
            throw ApiException.Validation("Idempotency-Key", "1 to 255 printable ASCII characters without spaces.");
        }

        return key;
    }
}
