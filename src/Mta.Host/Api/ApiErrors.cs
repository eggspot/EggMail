using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;

namespace Mta.Host.Api;

/// <summary>Stable machine-readable error codes (docs/api.md, "Errors").</summary>
public static class ApiCodes
{
    public const string Unauthorized = "unauthorized";
    public const string Forbidden = "forbidden";
    public const string NotFound = "not_found";
    public const string ValidationFailed = "validation_failed";
    public const string RateLimited = "rate_limited";
    public const string DomainNotVerified = "domain_not_verified";
    public const string RecipientSuppressed = "recipient_suppressed";
    public const string PayloadTooLarge = "payload_too_large";
    public const string IdempotencyConflict = "idempotency_conflict";
    public const string HistoryNotRecorded = "history_not_recorded";
    public const string BodyExpired = "body_expired";
    public const string ContentNotRecorded = "content_not_recorded";
    public const string MessageNotFound = "message_not_found";
    public const string AttachmentsNotStored = "attachments_not_stored";
    public const string NotReady = "not_ready";
    public const string QueryTooSlow = "query_too_slow";
    public const string Conflict = "conflict";
    public const string UnsupportedMediaType = "unsupported_media_type";
    public const string ServerError = "server_error";
    public const string TenantDisabled = "tenant_disabled";
    public const string InboundBodyGone = "inbound_body_gone";
    public const string PasswordChangeRequired = "password_change_required";

    /// <summary>Short human title per code (RFC 9457 <c>title</c>).</summary>
    public static string TitleOf(string code, int status) => code switch
    {
        Unauthorized => "Unauthorized",
        Forbidden => "Forbidden",
        NotFound => "Not found",
        ValidationFailed => "Validation failed",
        RateLimited => "Too many requests",
        DomainNotVerified => "Domain not verified",
        RecipientSuppressed => "Recipient suppressed",
        PayloadTooLarge => "Payload too large",
        IdempotencyConflict => "Idempotency conflict",
        HistoryNotRecorded => "Per-message history is not recorded",
        BodyExpired => "Message body expired",
        ContentNotRecorded => "Message content was not recorded",
        MessageNotFound => "Message not found",
        AttachmentsNotStored => "Attachments were not stored",
        NotReady => "Not ready",
        QueryTooSlow => "Query too slow",
        Conflict => "Conflict",
        UnsupportedMediaType => "Unsupported media type",
        TenantDisabled => "Account disabled",
        InboundBodyGone => "Message body is gone",
        PasswordChangeRequired => "Password change required",
        _ => status >= 500 ? "Internal server error" : "Request failed",
    };
}

/// <summary>One entry of the <c>errors</c> array of a <c>validation_failed</c> problem.</summary>
public sealed record FieldError(string Field, string Message);

/// <summary>
/// An error that becomes an RFC 9457 <c>application/problem+json</c> response with a stable <c>code</c>. Thrown from endpoint code and
/// turned into the response by the API's endpoint filter, so every handler can simply <c>throw</c>.
/// </summary>
public sealed class ApiException : Exception
{
    public ApiException(int status, string code, string detail, IReadOnlyList<FieldError>? errors = null, IReadOnlyDictionary<string, object?>? extensions = null, IReadOnlyDictionary<string, string>? headers = null)
        : base(detail)
    {
        Status = status;
        Code = code;
        Detail = detail;
        Errors = errors;
        Extensions = extensions;
        Headers = headers;
    }

    public int Status { get; }
    public string Code { get; }
    public string Detail { get; }
    public IReadOnlyList<FieldError>? Errors { get; }
    public IReadOnlyDictionary<string, object?>? Extensions { get; }
    public IReadOnlyDictionary<string, string>? Headers { get; }

    public static ApiException Unauthorized(string detail = "Authentication is required.") =>
        new(StatusCodes.Status401Unauthorized, ApiCodes.Unauthorized, detail, headers: new Dictionary<string, string> { ["WWW-Authenticate"] = "Bearer" });

    public static ApiException Forbidden(string detail) => new(StatusCodes.Status403Forbidden, ApiCodes.Forbidden, detail);

    /// <summary>The signed-in user has a temporary password and may do nothing but change it (and sign out).</summary>
    public static ApiException PasswordChangeRequired() =>
        new(StatusCodes.Status403Forbidden, ApiCodes.PasswordChangeRequired, "This account has a temporary password. Change it first (POST /me/password); until then only GET /me, POST /me/password and DELETE /session are allowed.");

    public static ApiException NotFound(string detail = "The resource was not found.") => new(StatusCodes.Status404NotFound, ApiCodes.NotFound, detail);

    public static ApiException Conflict(string detail) => new(StatusCodes.Status409Conflict, ApiCodes.Conflict, detail);

    public static ApiException Validation(string field, string message) => new(StatusCodes.Status400BadRequest, ApiCodes.ValidationFailed, "One or more fields are invalid.", [new FieldError(field, message)]);

    public static ApiException Validation(IReadOnlyList<FieldError> errors) => new(StatusCodes.Status400BadRequest, ApiCodes.ValidationFailed, "One or more fields are invalid.", errors);

    public static ApiException RateLimited(string detail, TimeSpan retryAfter) =>
        new(StatusCodes.Status429TooManyRequests, ApiCodes.RateLimited, detail, headers: new Dictionary<string, string> { ["Retry-After"] = RetryAfterSeconds(retryAfter) });

    /// <summary>The database refused to run the query for longer (read-only role <c>statement_timeout</c>); the client should narrow it. 503, but not "try again".</summary>
    public static ApiException QueryTooSlow(string detail) => new(StatusCodes.Status503ServiceUnavailable, ApiCodes.QueryTooSlow, detail);

    public static ApiException NotReady(string detail) =>
        new(StatusCodes.Status503ServiceUnavailable, ApiCodes.NotReady, detail, headers: new Dictionary<string, string> { ["Retry-After"] = "5" });

    public static string RetryAfterSeconds(TimeSpan span) => Math.Max(1, (int)Math.Ceiling(span.TotalSeconds)).ToString(System.Globalization.CultureInfo.InvariantCulture);
}

/// <summary>Collects field errors and throws <c>validation_failed</c> if there are any.</summary>
public sealed class ValidationErrors
{
    private readonly List<FieldError> _errors = [];

    public bool Any => _errors.Count > 0;

    public void Add(string field, string message) => _errors.Add(new FieldError(field, message));

    public void ThrowIfAny()
    {
        if (_errors.Count > 0)
        {
            throw ApiException.Validation(_errors);
        }
    }
}

/// <summary>Writes problem+json bodies.</summary>
public static class ProblemWriter
{
    public static async Task WriteAsync(HttpContext context, ApiException error)
    {
        HttpResponse response = context.Response;
        if (response.HasStarted)
        {
            return;
        }

        response.StatusCode = error.Status;
        response.ContentType = "application/problem+json";
        response.Headers.CacheControl = "no-store";
        response.Headers["X-Request-Id"] = RequestIds.Of(context);
        if (error.Headers is not null)
        {
            foreach (var (name, value) in error.Headers)
            {
                response.Headers[name] = value;
            }
        }

        using var buffer = new MemoryStream();
        await using (var w = new Utf8JsonWriter(buffer))
        {
            w.WriteStartObject();
            w.WriteString("type", "https://eggmail.example/problems/" + error.Code);
            w.WriteString("title", ApiCodes.TitleOf(error.Code, error.Status));
            w.WriteNumber("status", error.Status);
            w.WriteString("detail", error.Detail);
            w.WriteString("code", error.Code);
            w.WriteString("request_id", RequestIds.Of(context));
            if (error.Errors is { Count: > 0 } errors)
            {
                w.WriteStartArray("errors");
                foreach (FieldError e in errors)
                {
                    w.WriteStartObject();
                    w.WriteString("field", e.Field);
                    w.WriteString("message", e.Message);
                    w.WriteEndObject();
                }

                w.WriteEndArray();
            }

            if (error.Extensions is not null)
            {
                foreach (var (name, value) in error.Extensions)
                {
                    w.WritePropertyName(name);
                    JsonSerializer.Serialize(w, value, ApiJson.Write);
                }
            }

            w.WriteEndObject();
        }

        await response.Body.WriteAsync(buffer.GetBuffer().AsMemory(0, (int)buffer.Length), context.RequestAborted).ConfigureAwait(false);
    }
}

/// <summary>The id echoed in every problem as <c>request_id</c> and in the <c>X-Request-Id</c> response header.</summary>
public static class RequestIds
{
    private const string ItemKey = "eggmail.request_id";

    public static string Of(HttpContext context)
    {
        if (context.Items.TryGetValue(ItemKey, out object? existing) && existing is string s)
        {
            return s;
        }

        string id = "req_" + Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8));
        context.Items[ItemKey] = id;
        return id;
    }
}
