using System.Globalization;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Mta.Core;
using Mta.Storage;
using Mta.Webhooks;

namespace Mta.Host.Api;

public sealed class CreateWebhookRequest
{
    [JsonPropertyName("url")]
    public string? Url { get; set; }

    [JsonPropertyName("event_types")]
    public List<string>? EventTypes { get; set; }
}

public sealed class UpdateWebhookRequest
{
    [JsonPropertyName("url")]
    public string? Url { get; set; }

    [JsonPropertyName("event_types")]
    public List<string>? EventTypes { get; set; }

    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }
}

public sealed record WebhookResponse(
    Guid Id,
    string Url,
    [property: JsonPropertyName("event_types")] IReadOnlyList<string> EventTypes,
    bool Enabled,
    string? DisabledReason,
    DateTimeOffset? DisabledAt,
    DateTimeOffset CreatedAt,
    bool SecretRotationPending,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Secret = null);

public sealed record WebhookAttemptResponse(string Id, Guid OutboxId, string? EventType, DateTimeOffset At, int? Status, long DurationMs, string? ErrorClass, string? Snippet);

public sealed record OutboxResponse(Guid OutboxId, string? Status = null);

/// <summary>
/// Webhook endpoints (Standard Webhooks, decision 16). The signing secret is shown once as <c>whsec_...</c>; rotation keeps the previous
/// secret signing next to the new one until it is removed. Every call is keyed by the caller's tenant.
/// </summary>
public sealed class WebhooksApi(ApiAuthenticator auth, IStorage storage, ISecretProtector protector, SettingsService settings, ApiOptions options, IClock clock)
{
    public const string TestEventType = "webhook.test";

    private static readonly HashSet<string> KnownEventTypes = new(WebhookEventFactory.AllEventTypes.Concat([WebhookEventFactory.EndpointDisabled, TestEventType, "*"]), StringComparer.Ordinal);

    public void Map(RouteGroupBuilder api)
    {
        api.GetRoute("/webhooks", ListAsync);
        api.PostRoute("/webhooks", CreateAsync);
        api.GetRoute("/webhooks/{id}", GetAsync);
        api.PatchRoute("/webhooks/{id}", UpdateAsync);
        api.DeleteRoute("/webhooks/{id}", DeleteAsync);
        api.PostRoute("/webhooks/{id}/rotate-secret", RotateAsync);
        api.DeleteRoute("/webhooks/{id}/previous-secret", RemovePreviousSecretAsync);
        api.PostRoute("/webhooks/{id}/test", TestAsync);
        api.GetRoute("/webhooks/{id}/attempts", AttemptsAsync);
        api.PostRoute("/webhook-events/{outboxId}/replay", ReplayAsync);
    }

    private IConfigStore Config => storage.Config;

    private async Task<WebhookEndpointRecord> FindOwnAsync(ApiCaller caller, string id, CancellationToken ct)
    {
        WebhookEndpointRecord? endpoint = ApiJson.TryParseId(id, out Guid guid) ? await Config.GetWebhookEndpointAsync(guid, ct).ConfigureAwait(false) : null;
        return endpoint is not null && endpoint.TenantId == caller.TenantId ? endpoint : throw ApiException.NotFound("Webhook endpoint not found.");
    }

    private static WebhookResponse ToResponse(WebhookEndpointRecord w, int secretCount, string? secret = null) =>
        new(w.Id, w.Url, w.EventTypes, w.Enabled, w.DisabledReason, w.DisabledAt, w.CreatedAt, secretCount > 1, secret);

    private int SecretCountOf(WebhookEndpointRecord w)
    {
        try
        {
            return Encoding.UTF8.GetString(protector.Unprotect(w.SecretProtected, SecretPurposes.WebhookSecret)).Split(' ', StringSplitOptions.RemoveEmptyEntries).Length;
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or FormatException)
        {
            return 1;
        }
    }

    private async Task<IResult> ListAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Webhooks).ConfigureAwait(false);
        var endpoints = await Config.GetWebhookEndpointsAsync(caller.TenantId, context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(endpoints.Select(w => ToResponse(w, SecretCountOf(w))).ToList());
    }

    private async Task<IResult> GetAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Webhooks).ConfigureAwait(false);
        WebhookEndpointRecord w = await FindOwnAsync(caller, id, context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(ToResponse(w, SecretCountOf(w)));
    }

    private async Task<IResult> CreateAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Webhooks).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        CreateWebhookRequest body = await ApiJson.ReadBodyAsync<CreateWebhookRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        await ValidateUrlAsync(caller.TenantId, body.Url, errors, ct).ConfigureAwait(false);
        ValidateEventTypes(body.EventTypes, errors, required: true);
        errors.ThrowIfAny();

        if ((await Config.GetWebhookEndpointsAsync(caller.TenantId, ct).ConfigureAwait(false)).Count >= options.MaxWebhooksPerTenant)
        {
            throw ApiException.Validation("url", $"At most {options.MaxWebhooksPerTenant} webhook endpoints per tenant.");
        }

        string secret = StandardWebhooksSigner.GenerateSecret();
        DateTimeOffset now = clock.UtcNow;
        var endpoint = new WebhookEndpointRecord(
            Ids.New(now), caller.TenantId, body.Url!.Trim(), ProtectSecrets(secret), body.EventTypes!.Distinct().ToList(), true, null, null, now, null);
        await Config.UpsertWebhookEndpointAsync(endpoint, ct).ConfigureAwait(false);
        return ApiResults.Created("/api/v1/webhooks/" + ApiJson.Id(endpoint.Id), ToResponse(endpoint, 1, secret));
    }

    private async Task<IResult> UpdateAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Webhooks).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        WebhookEndpointRecord current = await FindOwnAsync(caller, id, ct).ConfigureAwait(false);
        UpdateWebhookRequest body = await ApiJson.ReadBodyAsync<UpdateWebhookRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        if (body.Url is not null)
        {
            await ValidateUrlAsync(caller.TenantId, body.Url, errors, ct).ConfigureAwait(false);
        }

        if (body.EventTypes is not null)
        {
            ValidateEventTypes(body.EventTypes, errors, required: true);
        }

        errors.ThrowIfAny();

        WebhookEndpointRecord updated = current with
        {
            Url = body.Url?.Trim() ?? current.Url,
            EventTypes = body.EventTypes?.Distinct().ToList() ?? current.EventTypes,
        };
        if (body.Enabled is { } enabled && enabled != current.Enabled)
        {
            updated = enabled
                ? updated with { Enabled = true, DisabledReason = null, DisabledAt = null, FailingSince = null }
                : updated with { Enabled = false, DisabledReason = "Disabled by the account owner.", DisabledAt = clock.UtcNow };
        }

        await Config.UpsertWebhookEndpointAsync(updated, ct).ConfigureAwait(false);
        return ApiResults.Ok(ToResponse(updated, SecretCountOf(updated)));
    }

    private async Task<IResult> DeleteAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Webhooks).ConfigureAwait(false);
        WebhookEndpointRecord endpoint = await FindOwnAsync(caller, id, context.RequestAborted).ConfigureAwait(false);
        await Config.DeleteWebhookEndpointAsync(caller.TenantId, endpoint.Id, context.RequestAborted).ConfigureAwait(false);
        return ApiResults.NoContent();
    }

    private async Task<IResult> RotateAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Webhooks).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        WebhookEndpointRecord endpoint = await FindOwnAsync(caller, id, ct).ConfigureAwait(false);
        string[] current = UnprotectSecrets(endpoint);
        string fresh = StandardWebhooksSigner.GenerateSecret();
        // The newest secret first, then the one that was current: at most two sign at any time.
        string[] all = current.Length == 0 ? [fresh] : [fresh, current[0]];
        WebhookEndpointRecord updated = endpoint with { SecretProtected = ProtectSecrets(all) };
        await Config.UpsertWebhookEndpointAsync(updated, ct).ConfigureAwait(false);
        return ApiResults.Ok(ToResponse(updated, all.Length, fresh));
    }

    private async Task<IResult> RemovePreviousSecretAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Webhooks).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        WebhookEndpointRecord endpoint = await FindOwnAsync(caller, id, ct).ConfigureAwait(false);
        string[] secrets = UnprotectSecrets(endpoint);
        if (secrets.Length < 2)
        {
            throw ApiException.NotFound("There is no previous secret: no rotation is in progress.");
        }

        await Config.UpsertWebhookEndpointAsync(endpoint with { SecretProtected = ProtectSecrets(secrets[0]) }, ct).ConfigureAwait(false);
        return ApiResults.NoContent();
    }

    private async Task<IResult> TestAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Webhooks).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        WebhookEndpointRecord endpoint = await FindOwnAsync(caller, id, ct).ConfigureAwait(false);
        if (!endpoint.Enabled)
        {
            throw ApiException.Conflict("The endpoint is disabled; enable it before sending a test event.");
        }

        DateTimeOffset now = clock.UtcNow;
        Guid eventId = Ids.New(now);
        string payload = System.Text.Json.JsonSerializer.Serialize(new
        {
            id = "evt_" + Ids.ToCompact(eventId),
            type = TestEventType,
            timestamp = now.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture),
            data = new { endpoint_id = Ids.ToCompact(endpoint.Id), message = "This is a test event from EggMail." },
        });
        Guid? outboxId;
        try
        {
            outboxId = await storage.Webhooks.EnqueueForEndpointAsync(caller.TenantId, endpoint.Id, new WebhookEventDraft(eventId, TestEventType, payload), now, ct).ConfigureAwait(false);
        }
        catch (NotSupportedException)
        {
            throw ApiException.NotReady("This storage provider cannot queue test events yet.");
        }

        return outboxId is { } queued
            ? ApiResults.Accepted(new OutboxResponse(queued, "queued"))
            : throw ApiException.Conflict("The endpoint is not active; try again in a moment.");
    }

    private async Task<IResult> AttemptsAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Webhooks).ConfigureAwait(false);
        WebhookEndpointRecord endpoint = await FindOwnAsync(caller, id, context.RequestAborted).ConfigureAwait(false);
        var errors = new ValidationErrors();
        int limit = new QueryReader(context.Request, errors).Int("limit", 50, 1, 200);
        errors.ThrowIfAny();
        var attempts = await storage.Webhooks.GetAttemptsAsync(caller.TenantId, endpoint.Id, limit, context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(attempts.Select(a => new WebhookAttemptResponse(
            ApiJson.Id(a.OutboxId) + "-" + a.At.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture),
            a.OutboxId, null, a.At, a.StatusCode, (long)a.Duration.TotalMilliseconds, a.ErrorClass, a.ResponseSnippet)).ToList());
    }

    private async Task<IResult> ReplayAsync(HttpContext context, string outboxId)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Webhooks).ConfigureAwait(false);
        if (!ApiJson.TryParseId(outboxId, out Guid guid)
            || !await storage.Webhooks.ReplayAsync(caller.TenantId, guid, clock.UtcNow, context.RequestAborted).ConfigureAwait(false))
        {
            throw ApiException.NotFound("No finished or failed webhook event with that id.");
        }

        return ApiResults.Accepted(new OutboxResponse(guid, "queued"));
    }

    // Validation and secrets

    private async Task ValidateUrlAsync(Guid tenantId, string? url, ValidationErrors errors, CancellationToken ct)
    {
        IReadOnlyList<IpNetwork> allowlist = await settings.GetWebhookAllowlistAsync(tenantId, ct).ConfigureAwait(false);
        if (!WebhookUrlValidator.TryValidate(url, options.Webhooks.AllowHttp, allowlist, out string error))
        {
            errors.Add("url", error + (options.Webhooks.AllowHttp ? "" : " Enter a full https:// URL such as https://example.com/hooks/eggmail."));
        }
    }

    private static void ValidateEventTypes(List<string>? types, ValidationErrors errors, bool required)
    {
        if (types is null || types.Count == 0)
        {
            if (required)
            {
                errors.Add("event_types", "Select at least one event type.");
            }

            return;
        }

        if (types.Count > 32 || types.Any(t => !KnownEventTypes.Contains(t)))
        {
            errors.Add("event_types", "Unknown event type. Known: " + string.Join(", ", KnownEventTypes.Order(StringComparer.Ordinal)) + ".");
        }
    }

    private byte[] ProtectSecrets(params string[] secrets) => protector.Protect(Encoding.UTF8.GetBytes(string.Join(' ', secrets)), SecretPurposes.WebhookSecret);

    private string[] UnprotectSecrets(WebhookEndpointRecord endpoint)
    {
        try
        {
            return Encoding.UTF8.GetString(protector.Unprotect(endpoint.SecretProtected, SecretPurposes.WebhookSecret)).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or FormatException)
        {
            return [];
        }
    }
}
