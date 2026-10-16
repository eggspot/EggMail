using System.Globalization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Mta.Storage;

namespace Mta.Host.Api;

/// <summary>Result helpers that produce the wire formats of docs/api.md.</summary>
public static class ApiResults
{
    public static IResult Ok<T>(T value) => Results.Json(value, ApiJson.Write, statusCode: StatusCodes.Status200OK);

    public static IResult Created<T>(string location, T value) => new CreatedResult<T>(location, value);

    public static IResult Accepted<T>(T value) => Results.Json(value, ApiJson.Write, statusCode: StatusCodes.Status202Accepted);

    public static IResult NoContent() => Results.NoContent();

    private sealed class CreatedResult<T>(string location, T value) : IResult
    {
        public Task ExecuteAsync(HttpContext httpContext)
        {
            httpContext.Response.Headers.Location = location;
            return Results.Json(value, ApiJson.Write, statusCode: StatusCodes.Status201Created).ExecuteAsync(httpContext);
        }
    }
}

/// <summary>
/// Route registration for handlers written as <c>Task&lt;IResult&gt; Handler(HttpContext, ...)</c>. Passing such a method group straight to <c>MapGet</c>
/// would bind it as a plain <c>RequestDelegate</c> and discard the <see cref="IResult"/>; taking a <see cref="Delegate"/> binds it as a route handler.
/// </summary>
internal static class ApiRouteExtensions
{
    public static RouteHandlerBuilder GetRoute(this IEndpointRouteBuilder builder, string pattern, Delegate handler) => builder.MapGet(pattern, handler);

    public static RouteHandlerBuilder PostRoute(this IEndpointRouteBuilder builder, string pattern, Delegate handler) => builder.MapPost(pattern, handler);

    public static RouteHandlerBuilder PutRoute(this IEndpointRouteBuilder builder, string pattern, Delegate handler) => builder.MapPut(pattern, handler);

    public static RouteHandlerBuilder PatchRoute(this IEndpointRouteBuilder builder, string pattern, Delegate handler) => builder.MapPatch(pattern, handler);

    public static RouteHandlerBuilder DeleteRoute(this IEndpointRouteBuilder builder, string pattern, Delegate handler) => builder.MapDelete(pattern, handler);
}

/// <summary>A list response: <c>{ items, next_cursor }</c>.</summary>
public sealed record ListResponse<T>(IReadOnlyList<T> Items, [property: System.Text.Json.Serialization.JsonPropertyName("next_cursor")] string? NextCursor);

/// <summary>
/// Wraps every API endpoint: stamps <c>X-Request-Id</c>, forbids caching, and turns <see cref="ApiException"/> and unexpected failures into
/// problem+json (unexpected errors are logged and answered with a generic 500 that never carries internals).
/// </summary>
public sealed class ApiEndpointFilter(ILogger<ApiEndpointFilter> logger) : IEndpointFilter
{
    /// <summary>The request path for log lines: the decoded path may carry CR/LF, which would forge log entries in plain-text sinks.</summary>
    private static string SafePath(HttpContext context) => string.Concat((context.Request.Path.Value ?? "").Select(c => char.IsControl(c) ? '?' : c));

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext invocation, EndpointFilterDelegate next)
    {
        HttpContext context = invocation.HttpContext;
        context.Response.Headers["X-Request-Id"] = RequestIds.Of(context);
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.XContentTypeOptions = "nosniff";
        try
        {
            return await next(invocation).ConfigureAwait(false);
        }
        catch (ApiException ex)
        {
            return new ProblemResult(ex);
        }
        catch (StorageConflictException)
        {
            return new ProblemResult(ApiException.Conflict("The change conflicts with existing data."));
        }
        catch (Mta.Storage.Transfer.StorageFencedException ex)
        {
            // A backend switch closed this instance: senders retry (Retry-After) against the new backend or after a rollback.
            return new ProblemResult(ApiException.NotReady(ex.Message));
        }
        catch (StorageQueryTimeoutException ex)
        {
            logger.LogWarning("Read query timed out in {Method} {Path} ({RequestId}): {Message}", context.Request.Method, SafePath(context), RequestIds.Of(context), ex.Message);
            return new ProblemResult(ApiException.QueryTooSlow("The query took too long and was stopped. Narrow it (a shorter time range, more filters) and try again."));
        }
        catch (StorageUnavailableException ex)
        {
            logger.LogWarning("Storage unavailable in {Method} {Path} ({RequestId}): {Message}", context.Request.Method, SafePath(context), RequestIds.Of(context), ex.Message);
            return new ProblemResult(ApiException.NotReady("The storage backend is not available."));
        }
        catch (BadHttpRequestException ex)
        {
            // An aborted or malformed request body or header block: the client's problem, not a server error.
            return new ProblemResult(ex.StatusCode == StatusCodes.Status413PayloadTooLarge
                ? new ApiException(StatusCodes.Status413PayloadTooLarge, ApiCodes.PayloadTooLarge, "The request body is too large.")
                : ApiException.Validation("$", "The request could not be read."));
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            return Results.Empty;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unhandled error in {Method} {Path} ({RequestId})", context.Request.Method, SafePath(context), RequestIds.Of(context));
            return new ProblemResult(new ApiException(StatusCodes.Status500InternalServerError, ApiCodes.ServerError, "An internal error occurred. Quote the request_id when reporting it."));
        }
    }
}

internal sealed class ProblemResult(ApiException error) : IResult
{
    public Task ExecuteAsync(HttpContext httpContext) => ProblemWriter.WriteAsync(httpContext, error);
}

/// <summary>Parsing of common query parameters; problems are collected as field errors.</summary>
public sealed class QueryReader(HttpRequest request, ValidationErrors errors)
{
    public string? String(string name, int maxLength = 256)
    {
        string? value = request.Query[name].ToString();
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        if (value.Length > maxLength)
        {
            errors.Add(name, $"At most {maxLength} characters.");
            return null;
        }

        if (value.Any(char.IsControl) || !StorageText.IsStorable(value))
        {
            // A NUL or an unpaired surrogate is no filter anybody means, and PostgreSQL could not even be asked about it.
            errors.Add(name, "Must not contain control characters.");
            return null;
        }

        return value;
    }

    public int Int(string name, int defaultValue, int min, int max)
    {
        string? text = request.Query[name].ToString();
        if (string.IsNullOrEmpty(text))
        {
            return defaultValue;
        }

        if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out int value) || value < min || value > max)
        {
            errors.Add(name, $"Must be a whole number from {min} to {max}.");
            return defaultValue;
        }

        return value;
    }

    public DateTimeOffset? Timestamp(string name)
    {
        string? text = request.Query[name].ToString();
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        if (!DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset value)
            || value.Year is < 2000 or > 2100)
        {
            errors.Add(name, "Not a valid ISO 8601 timestamp between the years 2000 and 2100.");
            return null;
        }

        return value;
    }

    public string? OneOf(string name, params string[] allowed)
    {
        string? text = request.Query[name].ToString();
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        if (!allowed.Contains(text, StringComparer.Ordinal))
        {
            errors.Add(name, "Must be one of: " + string.Join(", ", allowed) + ".");
            return null;
        }

        return text;
    }
}

/// <summary>Shared mappings between storage values and API values.</summary>
public static class ApiMap
{
    public static string DomainStatus(DomainStatus status) => status switch
    {
        Storage.DomainStatus.Pending => "pending",
        Storage.DomainStatus.Verifying => "verifying",
        Storage.DomainStatus.Verified => "verified",
        Storage.DomainStatus.TemporaryFailure => "temporary_failure",
        _ => "failed",
    };

    public static string SuppressionReason(SuppressionReason reason) => reason switch
    {
        Storage.SuppressionReason.HardBounce => "bounce",
        Storage.SuppressionReason.Complaint => "complaint",
        Storage.SuppressionReason.Unsubscribe => "unsubscribe",
        _ => "manual",
    };

    public static bool TryParseSuppressionReason(string? text, out SuppressionReason reason)
    {
        switch (text)
        {
            case null or "" or "manual": reason = Storage.SuppressionReason.Manual; return true;
            case "bounce": reason = Storage.SuppressionReason.HardBounce; return true;
            case "complaint": reason = Storage.SuppressionReason.Complaint; return true;
            case "unsubscribe": reason = Storage.SuppressionReason.Unsubscribe; return true;
            default: reason = default; return false;
        }
    }

    public static string EventType(MessageEventType type) => type switch
    {
        MessageEventType.Queued => "queued",
        MessageEventType.Delivered => "delivered",
        MessageEventType.Deferred => "deferred",
        MessageEventType.Bounced => "bounced",
        MessageEventType.Expired => "expired",
        MessageEventType.Suppressed => "suppressed",
        MessageEventType.Cancelled => "cancelled",
        MessageEventType.Complained => "complained",
        MessageEventType.AbortedBySwitch => "aborted_by_switch",
        MessageEventType.PossibleDuplicate => "possible_duplicate",
        _ => "opened",
    };

    public static string Backend(StorageBackend backend) => backend switch
    {
        StorageBackend.Sqlite => "sqlite",
        StorageBackend.Postgres => "postgres",
        _ => "memory",
    };

    public static string HistoryMode(HistoryMode mode) => mode == Storage.HistoryMode.Full ? "full" : "statsonly";
}
