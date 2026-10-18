using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Mta.Core;
using Mta.Host.Domains;
using Mta.Host.Inbound;
using Mta.Storage;
using Mta.Storage.Logic;
using Mta.Storage.Model;

namespace Mta.Host.Api;

/// <summary>The server-wide inbound defaults the API reports as "effective" values (the receive path applies the same ones).</summary>
public sealed class InboundApiDefaults
{
    public long MaxMessageBytes { get; set; } = 25L * 1024 * 1024;

    public int MaxMessagesPerMinute { get; set; } = 600;

    public int MaxMessagesPerMinutePerRemote { get; set; } = 60;

    /// <summary>0 is unlimited.</summary>
    public long MaxStoredBytesPerDomain { get; set; } = 2L * 1024 * 1024 * 1024;

    /// <summary>0 keeps forever.</summary>
    public int RetentionDays { get; set; } = 7;

    /// <summary>The longest retention a domain may choose; 0: none.</summary>
    public int MaxRetentionDays { get; set; }

    /// <summary>Stored bytes for all domains of one tenant together; 0 unlimited.</summary>
    public long MaxStoredBytesPerTenant { get; set; } = 10L * 1024 * 1024 * 1024;

    /// <summary>The operator's limits as the contract states them: what a domain's own settings may be at most.</summary>
    public InboundCeilings Ceilings() => new(MaxMessageBytes, MaxMessagesPerMinute, MaxMessagesPerMinutePerRemote, MaxStoredBytesPerDomain, MaxStoredBytesPerTenant, MaxRetentionDays);
}

public sealed record InboundWarningResponse(string Code, string Message);

public sealed record InboundEffectiveResponse(long MaxMessageBytes, int MaxMessagesPerMinute, int MaxMessagesPerMinutePerRemote, long MaxStoredBytes, int RetentionDays);

public sealed record InboundMxAdviceResponse(string? Host, int Priority);

public sealed record InboundSettingsResponse(
    Guid DomainId,
    bool Enabled,
    string DmarcAction,
    long? MaxMessageBytes,
    int? MaxMessagesPerMinute,
    int? MaxMessagesPerMinutePerRemote,
    long? MaxStoredBytes,
    int? RetentionDays,
    DateTimeOffset? UpdatedAt,
    InboundEffectiveResponse Effective,
    InboundMxAdviceResponse Mx,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<InboundWarningResponse>? Warnings = null);

public sealed record InboundMatchResponse(string Kind, string? LocalPart, bool PlusAddressing);

public sealed record InboundRouteActionResponse(string Kind, Guid? WebhookEndpointId, string? WebhookFormat, IReadOnlyList<string> ForwardTo);

public sealed record InboundRouteResponse(
    Guid Id,
    Guid DomainId,
    string Name,
    int Order,
    bool Enabled,
    InboundMatchResponse Match,
    InboundRouteActionResponse Action,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<InboundWarningResponse>? Warnings = null);

public sealed record InboundRouteMatchResponse(string Address, bool DomainEnabled, InboundRouteResponse? Route, string Reply);

public sealed record InboundVerdictResponse(string Result, [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Domain = null, [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Policy = null);

public sealed record InboundAuthResponse(InboundVerdictResponse Spf, InboundVerdictResponse SpfHelo, InboundVerdictResponse Dkim, InboundVerdictResponse Dmarc, InboundVerdictResponse Arc);

/// <summary>
/// <c>Kind</c> is the action the message was given when it was received. The action that runs is the route's current one (design section 11.7), so on the detail endpoint <c>CurrentKind</c> says
/// what the route does now (null: no route, it was deleted, or this is a list entry); <c>Note</c> is set when the action finished but something happened the tenant should know.
/// </summary>
public sealed record InboundActionResponse(
    string Kind, string State, int Attempts, int RetryGeneration, DateTimeOffset? NextAttemptAt, DateTimeOffset? FinishedAt, string? LastError, Guid? ForwardMessageId,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Note = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? CurrentKind = null);

public sealed record InboundHeaderResponse(string Name, string Value);

public sealed record InboundAttachmentResponse(int Index, string? Filename, [property: JsonPropertyName("content_type")] string ContentType, long Size, [property: JsonPropertyName("content_id")] string? ContentId, string Disposition);

public sealed record InboundContentResponse(
    string State,
    IReadOnlyList<InboundHeaderResponse> Headers,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Text,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Html,
    bool Truncated,
    IReadOnlyList<InboundAttachmentResponse> Attachments);

public sealed record InboundMessageResponse(
    Guid Id,
    Guid DomainId,
    string Domain,
    DateTimeOffset ReceivedAt,
    string RemoteIp,
    string? Helo,
    bool Tls,
    string From,
    string To,
    string? Subject,
    long Size,
    InboundAuthResponse Auth,
    bool DmarcFlagged,
    Guid? RouteId,
    InboundActionResponse Action,
    bool HasRaw,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] InboundContentResponse? Content = null);

public sealed record InboundUsageResponse(long Messages, long BodyBytes, long Pending, long Failed, DateTimeOffset? OldestPendingAt);

public sealed record InboundErasedResponse(long Deleted);

public sealed record InboundRetryResponse(Guid Id, InboundActionResponse Action);

/// <summary>Update of the inbound settings of a domain. A member that is absent is unchanged; <c>null</c> resets a limit to the server default (design section 11.6).</summary>
public sealed class UpdateInboundSettingsRequest
{
    public bool? Enabled { get; set; }

    public string? DmarcAction { get; set; }

    public JsonElement MaxMessageBytes { get; set; }

    public JsonElement MaxMessagesPerMinute { get; set; }

    public JsonElement MaxMessagesPerMinutePerRemote { get; set; }

    public JsonElement MaxStoredBytes { get; set; }

    public JsonElement RetentionDays { get; set; }
}

public sealed class InboundMatchRequest
{
    public string? Kind { get; set; }

    public string? LocalPart { get; set; }

    public bool? PlusAddressing { get; set; }
}

public sealed class InboundRouteActionRequest
{
    public string? Kind { get; set; }

    public Guid? WebhookEndpointId { get; set; }

    public string? WebhookFormat { get; set; }

    public List<string>? ForwardTo { get; set; }
}

public sealed class CreateInboundRouteRequest
{
    public string? Name { get; set; }

    public int? Order { get; set; }

    public bool? Enabled { get; set; }

    public InboundMatchRequest? Match { get; set; }

    public InboundRouteActionRequest? Action { get; set; }
}

public sealed class UpdateInboundRouteRequest
{
    public string? Name { get; set; }

    public int? Order { get; set; }

    public bool? Enabled { get; set; }

    public InboundMatchRequest? Match { get; set; }

    public InboundRouteActionRequest? Action { get; set; }
}

/// <summary>
/// Inbound mail over the HTTP API (docs/api.md, "Inbound mail"): the settings and routes of a domain and the received messages. Every call is keyed by the
/// caller's tenant (another tenant's domain, route or message is a 404) and needs <c>inbound:read</c> (reads) or <c>inbound:write</c> (changes); a forward route also needs <c>send</c>.
/// </summary>
public sealed class InboundApi(ApiAuthenticator auth, IStorage storage, DomainVerificationService verification, ApiOptions options, IClock clock)
{
    private const int MaxBodyChars = 256 * 1024;
    private const int MatchProbeLimit = 320;

    public void Map(RouteGroupBuilder api)
    {
        api.GetRoute("/domains/{id}/inbound", GetSettingsAsync);
        api.PatchRoute("/domains/{id}/inbound", UpdateSettingsAsync);
        api.GetRoute("/domains/{id}/inbound/routes", ListRoutesAsync);
        api.PostRoute("/domains/{id}/inbound/routes", CreateRouteAsync);
        api.GetRoute("/domains/{id}/inbound/routes/match", MatchRouteAsync);
        api.GetRoute("/domains/{id}/inbound/routes/{routeId}", GetRouteAsync);
        api.PatchRoute("/domains/{id}/inbound/routes/{routeId}", UpdateRouteAsync);
        api.DeleteRoute("/domains/{id}/inbound/routes/{routeId}", DeleteRouteAsync);

        api.GetRoute("/inbound/messages", ListMessagesAsync);
        api.GetRoute("/inbound/usage", UsageAsync);
        api.GetRoute("/inbound/messages/{id}", GetMessageAsync);
        api.GetRoute("/inbound/messages/{id}/raw", RawAsync);
        api.GetRoute("/inbound/messages/{id}/attachments/{index}", AttachmentAsync);
        api.DeleteRoute("/inbound/messages/{id}", DeleteMessageAsync);
        api.DeleteRoute("/inbound/messages", EraseMessagesAsync);
        api.PostRoute("/inbound/messages/{id}/retry", RetryAsync);
    }

    private IInboundStore Inbound => storage.Inbound;

    private IConfigStore Config => storage.Config;

    private async Task<DomainRecord> FindOwnDomainAsync(ApiCaller caller, string id, CancellationToken ct)
    {
        DomainRecord? domain = ApiJson.TryParseId(id, out Guid guid) ? await Config.GetDomainAsync(guid, ct).ConfigureAwait(false) : null;
        // A domain of another tenant is indistinguishable from one that does not exist.
        return domain is not null && domain.TenantId == caller.TenantId ? domain : throw ApiException.NotFound("Domain not found.");
    }

    private static Guid ParseId(string id, string what) => ApiJson.TryParseId(id, out Guid guid) ? guid : throw ApiException.NotFound(what + " not found.");

    // Settings

    private InboundEffectiveResponse EffectiveOf(InboundDomainSettings s)
    {
        InboundEffectiveLimits e = InboundRules.Effective(s, options.Inbound.Ceilings(), options.Inbound.RetentionDays);
        return new InboundEffectiveResponse(e.MaxMessageBytes, e.MaxMessagesPerMinute, e.MaxMessagesPerMinutePerRemote, e.MaxStoredBytes, e.RetentionDays);
    }

    private InboundSettingsResponse ToResponse(InboundDomainSettings s, bool stored, IReadOnlyList<InboundWarningResponse>? warnings = null)
    {
        InboundEffectiveResponse effective = EffectiveOf(s);
        var all = new List<InboundWarningResponse>(warnings ?? []);
        if (effective.RetentionDays == 0)
        {
            all.Add(new InboundWarningResponse("retention_unlimited", "Received mail is kept forever: nothing is deleted automatically, so the database grows without bound (design section 5.1)."));
        }

        return new InboundSettingsResponse(
            s.DomainId, s.Enabled, InboundNames.Of(s.DmarcAction), s.MaxMessageBytes, s.MaxMessagesPerMinute, s.MaxMessagesPerMinutePerRemote, s.MaxStoredBytes, s.RetentionDays,
            stored ? s.UpdatedAt : null, effective, new InboundMxAdviceResponse(options.DomainRecords?.ServerHostname, 10), all.Count == 0 ? null : all);
    }

    private async Task<IResult> GetSettingsAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.InboundRead).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        DomainRecord domain = await FindOwnDomainAsync(caller, id, ct).ConfigureAwait(false);
        InboundDomainSettings? stored = await Inbound.GetSettingsAsync(domain.Id, ct).ConfigureAwait(false);
        return ApiResults.Ok(ToResponse(stored ?? InboundDomainSettings.Disabled(domain.Id, domain.TenantId, clock.UtcNow), stored is not null));
    }

    private async Task<IResult> UpdateSettingsAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.InboundWrite).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        DomainRecord domain = await FindOwnDomainAsync(caller, id, ct).ConfigureAwait(false);
        UpdateInboundSettingsRequest body = await ApiJson.ReadBodyAsync<UpdateInboundSettingsRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        InboundDomainSettings current = await Inbound.GetSettingsAsync(domain.Id, ct).ConfigureAwait(false) ?? InboundDomainSettings.Disabled(domain.Id, domain.TenantId, clock.UtcNow);

        var errors = new ValidationErrors();
        InboundDmarcAction action = current.DmarcAction;
        if (body.DmarcAction is not null && !InboundNames.TryParse(body.DmarcAction, out action))
        {
            errors.Add("dmarcAction", "Must be one of: " + string.Join(", ", Enum.GetValues<InboundDmarcAction>().Select(InboundNames.Of)) + ".");
        }

        InboundDomainSettings updated = current with
        {
            Enabled = body.Enabled ?? current.Enabled,
            DmarcAction = action,
            MaxMessageBytes = Number(body.MaxMessageBytes, "maxMessageBytes", current.MaxMessageBytes, errors),
            MaxMessagesPerMinute = ToInt(Number(body.MaxMessagesPerMinute, "maxMessagesPerMinute", current.MaxMessagesPerMinute, errors), "maxMessagesPerMinute", errors),
            MaxMessagesPerMinutePerRemote = ToInt(Number(body.MaxMessagesPerMinutePerRemote, "maxMessagesPerMinutePerRemote", current.MaxMessagesPerMinutePerRemote, errors), "maxMessagesPerMinutePerRemote", errors),
            MaxStoredBytes = Number(body.MaxStoredBytes, "maxStoredBytes", current.MaxStoredBytes, errors),
            RetentionDays = ToInt(Number(body.RetentionDays, "retentionDays", current.RetentionDays, errors), "retentionDays", errors),
            UpdatedAt = clock.UtcNow,
        };
        errors.ThrowIfAny();
        foreach (InboundValidationError e in InboundRules.ValidateSettings(updated, options.Inbound.Ceilings(), ChangedMembers(body)))
        {
            errors.Add(e.Field, e.Message);
        }

        errors.ThrowIfAny();

        // An MX record proves nothing about who owns a domain; the verification of the domain does (design section 11.3).
        if (updated.Enabled && !current.Enabled && domain.Status is not (DomainStatus.Verified or DomainStatus.TemporaryFailure))
        {
            throw new ApiException(
                StatusCodes.Status403Forbidden, ApiCodes.DomainNotVerified, "The domain must be verified before it can receive mail.",
                extensions: new Dictionary<string, object?> { ["reason"] = "inbound_domain_not_verified" });
        }

        if (updated.Enabled && !current.Enabled && await IsBounceNameAsync(domain.Name, ct).ConfigureAwait(false))
        {
            throw ApiException.Validation("enabled", "This name only receives signed bounces (the bounce domain or a return-path host); it cannot receive other mail.");
        }

        try
        {
            await Inbound.UpsertSettingsAsync(updated, ct).ConfigureAwait(false);
            Mta.Host.Ingest.InboundConfigChangeSignal.Bump();
        }
        catch (StorageConflictException)
        {
            throw ApiException.NotFound("Domain not found.");   // deleted while the request ran
        }

        return ApiResults.Ok(ToResponse(updated, stored: true));
    }

    // The members the request names: only these are held to the operator's ceilings, so a stored value that a lowered ceiling now exceeds never blocks an unrelated change (such as turning the domain off).
    private static List<string> ChangedMembers(UpdateInboundSettingsRequest body)
    {
        var changed = new List<string>();
        if (body.MaxMessageBytes.ValueKind != JsonValueKind.Undefined)
        {
            changed.Add("maxMessageBytes");
        }

        if (body.MaxMessagesPerMinute.ValueKind != JsonValueKind.Undefined)
        {
            changed.Add("maxMessagesPerMinute");
        }

        if (body.MaxMessagesPerMinutePerRemote.ValueKind != JsonValueKind.Undefined)
        {
            changed.Add("maxMessagesPerMinutePerRemote");
        }

        if (body.MaxStoredBytes.ValueKind != JsonValueKind.Undefined)
        {
            changed.Add("maxStoredBytes");
        }

        if (body.RetentionDays.ValueKind != JsonValueKind.Undefined)
        {
            changed.Add("retentionDays");
        }

        return changed;
    }

    // Mail for these names has one meaning, signed bounces; the receive path classifies it before any inbound domain (design section 11.4).
    private async Task<bool> IsBounceNameAsync(string name, CancellationToken ct)
    {
        if (options.BounceDomain is { Length: > 0 } bounce && string.Equals(bounce.TrimEnd('.'), name, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var all = await Config.GetDomainsAsync(null, ct).ConfigureAwait(false);
        return all.Any(d => d.ReturnPathHost is { Length: > 0 } host && string.Equals(host.TrimEnd('.'), name, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>A PATCH number: absent keeps <paramref name="current"/>, <c>null</c> resets to the server default, a whole number replaces.</summary>
    private static long? Number(JsonElement element, string field, long? current, ValidationErrors errors)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Undefined:
                return current;
            case JsonValueKind.Null:
                return null;
            case JsonValueKind.Number when element.TryGetInt64(out long value):
                return value;
            default:
                errors.Add(field, "Must be a whole number or null.");
                return current;
        }
    }

    private static int? ToInt(long? value, string field, ValidationErrors errors)
    {
        if (value is null)
        {
            return null;
        }

        if (value is < int.MinValue or > int.MaxValue)
        {
            errors.Add(field, "Out of range.");
            return null;
        }

        return (int)value;
    }

    // Routes

    private static InboundRouteResponse ToResponse(InboundRouteRecord r, IReadOnlyList<InboundWarningResponse>? warnings = null) => new(
        r.Id, r.DomainId, r.Name, r.Order, r.Enabled,
        new InboundMatchResponse(InboundNames.Of(r.MatchKind), r.LocalPart, r.PlusAddressing),
        new InboundRouteActionResponse(InboundNames.Of(r.ActionKind), r.WebhookEndpointId, r.ActionKind == InboundActionKind.Webhook ? InboundNames.Of(r.WebhookFormat) : null, r.ForwardTo),
        r.CreatedAt, r.UpdatedAt, warnings is { Count: > 0 } ? warnings : null);

    private async Task<IResult> ListRoutesAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.InboundRead).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        DomainRecord domain = await FindOwnDomainAsync(caller, id, ct).ConfigureAwait(false);
        var routes = await Inbound.GetRoutesAsync(domain.Id, ct).ConfigureAwait(false);
        return ApiResults.Ok(routes.Select(r => ToResponse(r)).ToList());
    }

    private async Task<IResult> GetRouteAsync(HttpContext context, string id, string routeId)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.InboundRead).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        DomainRecord domain = await FindOwnDomainAsync(caller, id, ct).ConfigureAwait(false);
        return ApiResults.Ok(ToResponse(await FindRouteAsync(caller, domain, routeId, ct).ConfigureAwait(false)));
    }

    private async Task<InboundRouteRecord> FindRouteAsync(ApiCaller caller, DomainRecord domain, string routeId, CancellationToken ct)
    {
        InboundRouteRecord? route = ApiJson.TryParseId(routeId, out Guid guid) ? await Inbound.GetRouteAsync(caller.TenantId, guid, ct).ConfigureAwait(false) : null;
        return route is not null && route.DomainId == domain.Id ? route : throw ApiException.NotFound("Route not found.");
    }

    private async Task<IResult> CreateRouteAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.InboundWrite).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        DomainRecord domain = await FindOwnDomainAsync(caller, id, ct).ConfigureAwait(false);
        CreateInboundRouteRequest body = await ApiJson.ReadBodyAsync<CreateInboundRouteRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        if (body.Match is null)
        {
            errors.Add("match", "Required.");
        }

        if (body.Action is null)
        {
            errors.Add("action", "Required.");
        }

        errors.ThrowIfAny();

        int routeLimit = Math.Min(options.MaxInboundRoutesPerDomain, InboundRules.MaxRoutesPerDomain);
        if ((await Inbound.GetRoutesAsync(domain.Id, ct).ConfigureAwait(false)).Count >= routeLimit)
        {
            throw new ApiException(StatusCodes.Status409Conflict, ApiCodes.Conflict, $"At most {routeLimit} routes per domain.", extensions: new Dictionary<string, object?> { ["reason"] = "route_limit", ["limit"] = routeLimit });
        }

        DateTimeOffset now = clock.UtcNow;
        InboundRouteRecord route = await BuildAsync(
            caller, domain, Ids.New(now), body.Name ?? "", body.Order ?? 100, body.Enabled ?? true, body.Match!, body.Action!, now, now, errors, ct).ConfigureAwait(false);
        errors.ThrowIfAny();
        await SaveRouteAsync(route, ct).ConfigureAwait(false);
        return ApiResults.Created($"/api/v1/domains/{ApiJson.Id(domain.Id)}/inbound/routes/{ApiJson.Id(route.Id)}", ToResponse(route, await WarningsAsync(domain, route, ct).ConfigureAwait(false)));
    }

    private async Task<IResult> UpdateRouteAsync(HttpContext context, string id, string routeId)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.InboundWrite).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        DomainRecord domain = await FindOwnDomainAsync(caller, id, ct).ConfigureAwait(false);
        InboundRouteRecord current = await FindRouteAsync(caller, domain, routeId, ct).ConfigureAwait(false);
        UpdateInboundRouteRequest body = await ApiJson.ReadBodyAsync<UpdateInboundRouteRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        InboundMatchRequest match = body.Match ?? new InboundMatchRequest { Kind = InboundNames.Of(current.MatchKind), LocalPart = current.LocalPart, PlusAddressing = current.PlusAddressing };
        InboundRouteActionRequest action = body.Action ?? new InboundRouteActionRequest
        {
            Kind = InboundNames.Of(current.ActionKind), WebhookEndpointId = current.WebhookEndpointId, WebhookFormat = InboundNames.Of(current.WebhookFormat), ForwardTo = [.. current.ForwardTo],
        };

        InboundRouteRecord updated = await BuildAsync(
            caller, domain, current.Id, body.Name ?? current.Name, body.Order ?? current.Order, body.Enabled ?? current.Enabled, match, action, current.CreatedAt, clock.UtcNow, errors, ct,
            actionChanged: body.Action is not null).ConfigureAwait(false);
        errors.ThrowIfAny();
        await SaveRouteAsync(updated, ct).ConfigureAwait(false);
        return ApiResults.Ok(ToResponse(updated, await WarningsAsync(domain, updated, ct).ConfigureAwait(false)));
    }

    private async Task SaveRouteAsync(InboundRouteRecord route, CancellationToken ct)
    {
        try
        {
            await Inbound.UpsertRouteAsync(route, ct).ConfigureAwait(false);
            Mta.Host.Ingest.InboundConfigChangeSignal.Bump();
        }
        catch (StorageConflictException ex) when (ex.Reason == StorageConflictReasons.WebhookEndpointMissing)
        {
            throw ApiException.Validation("action.webhookEndpointId", "No such webhook endpoint.");   // deleted while the request ran
        }
        catch (StorageConflictException)
        {
            throw ApiException.NotFound("Domain not found.");   // deleted while the request ran
        }
    }

    /// <summary>Builds and validates a route from the request members; validation problems are added to <paramref name="errors"/> under the request's member names.</summary>
    private async Task<InboundRouteRecord> BuildAsync(
        ApiCaller caller, DomainRecord domain, Guid id, string name, int order, bool enabled, InboundMatchRequest match, InboundRouteActionRequest action, DateTimeOffset created, DateTimeOffset updated,
        ValidationErrors errors, CancellationToken ct, bool actionChanged = true)
    {
        InboundMatchKind matchKind = InboundMatchKind.CatchAll;
        if (match.Kind is null)
        {
            errors.Add("match.kind", "Required.");
        }
        else if (!InboundNames.TryParse(match.Kind, out matchKind))
        {
            errors.Add("match.kind", "Must be one of: catch_all, address, wildcard.");
        }

        InboundActionKind actionKind = InboundActionKind.Store;
        if (action.Kind is null)
        {
            errors.Add("action.kind", "Required.");
        }
        else if (!InboundNames.TryParse(action.Kind, out actionKind))
        {
            errors.Add("action.kind", "Must be one of: webhook, forward, store, discard.");
        }

        InboundWebhookFormat format = InboundWebhookFormat.Json;
        if (action.WebhookFormat is not null && !InboundNames.TryParse(action.WebhookFormat, out format))
        {
            errors.Add("action.webhookFormat", "Must be one of: json, raw_mime.");
        }

        if (order is < 0 or > 1_000_000)
        {
            errors.Add("order", "Must be between 0 and 1000000.");
        }

        var route = new InboundRouteRecord(
            id, domain.TenantId, domain.Id, name.Trim(), order, enabled, matchKind, match.LocalPart, match.PlusAddressing ?? false, actionKind, action.WebhookEndpointId, format,
            action.ForwardTo is null ? [] : [.. action.ForwardTo], created, updated);
        if (!errors.Any && actionKind == InboundActionKind.Forward && actionChanged && !caller.HasScope(ApiScopes.Send))
        {
            // A forward route sends every matching message, from now on, to an address of the caller's choosing: that is sending mail, so it takes the send scope as well (design section 11.9).
            // This comes before the lookup of the target domains below, so a key without `send` learns nothing about which domains this server receives for.
            throw ApiException.Forbidden($"A forward route also needs the '{ApiScopes.Send}' scope: it sends the mail it receives to the addresses it names.");
        }

        if (!errors.Any)
        {
            // The loop check has one implementation, the validator; the API only supplies the fact it cannot read: which target domains this server receives mail for (design section 11.6).
            HashSet<string> localInbound = [];
            if (actionKind == InboundActionKind.Forward)
            {
                foreach (string target in InboundRules.ForwardTargetDomains(route))
                {
                    if (await Config.FindDomainByNameAsync(target, ct).ConfigureAwait(false) is { } local && await Inbound.GetSettingsAsync(local.Id, ct).ConfigureAwait(false) is { Enabled: true })
                    {
                        localInbound.Add(target);
                    }
                }
            }

            foreach (InboundValidationError e in InboundRules.ValidateRoute(route, domain.Name, localInbound))
            {
                errors.Add(FieldOf(e.Field), e.Message);
            }
        }

        if (!errors.Any && actionChanged && actionKind == InboundActionKind.Webhook)
        {
            WebhookEndpointRecord? endpoint = await Config.GetWebhookEndpointAsync(route.WebhookEndpointId!.Value, ct).ConfigureAwait(false);
            if (endpoint is null || endpoint.TenantId != caller.TenantId)
            {
                errors.Add("action.webhookEndpointId", "No such webhook endpoint.");
            }
        }

        return route;
    }

    // The validator names members of the record; the request nests them under match and action.
    private static string FieldOf(string field) => field switch
    {
        "localPart" or "plusAddressing" => "match." + field,
        "matchKind" => "match.kind",
        "action" => "action.kind",
        "webhookEndpointId" or "webhookFormat" => "action." + field,
        _ when field.StartsWith("forwardTo", StringComparison.Ordinal) => "action." + field,
        _ => field,
    };

    /// <summary>A forward puts this domain in the envelope of the forwarded copy, so its SPF record decides whether the next receiver trusts it (design section 11.7).</summary>
    private async Task<IReadOnlyList<InboundWarningResponse>> WarningsAsync(DomainRecord domain, InboundRouteRecord route, CancellationToken ct)
    {
        if (route.ActionKind != InboundActionKind.Forward)
        {
            return [];
        }

        var keys = await Config.GetDkimKeysAsync(domain.Id, ct).ConfigureAwait(false);
        ExpectedDomainRecord? spf = verification.PlanRecords(domain, keys, clock.UtcNow).FirstOrDefault(r => r.Purpose == DomainRecordPurpose.Spf);
        if (spf is null)
        {
            return [];
        }

        DomainCheckSnapshot? snapshot = await verification.GetSnapshotAsync(domain.Id, ct).ConfigureAwait(false);
        bool ok = snapshot is not null && snapshot.Records.TryGetValue(DomainCheckSnapshot.KeyOf(spf.Type, spf.Host), out RecordCheckSnapshot? seen) && DomainVerificationService.StatusWord(seen.Status) == "ok";
        return ok ? [] : [new InboundWarningResponse("spf_not_ok", "The SPF record of this domain is not as expected. A forwarded message has this domain in its envelope, so the next receiver's SPF check will not pass without it.")];
    }

    private async Task<IResult> DeleteRouteAsync(HttpContext context, string id, string routeId)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.InboundWrite).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        DomainRecord domain = await FindOwnDomainAsync(caller, id, ct).ConfigureAwait(false);
        InboundRouteRecord route = await FindRouteAsync(caller, domain, routeId, ct).ConfigureAwait(false);
        if (!await Inbound.DeleteRouteAsync(caller.TenantId, route.Id, ct).ConfigureAwait(false))
        {
            throw ApiException.NotFound("Route not found.");
        }

        Mta.Host.Ingest.InboundConfigChangeSignal.Bump();
        return ApiResults.NoContent();
    }

    private async Task<IResult> MatchRouteAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.InboundRead).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        DomainRecord domain = await FindOwnDomainAsync(caller, id, ct).ConfigureAwait(false);
        string? text = context.Request.Query["address"].ToString();
        if (string.IsNullOrWhiteSpace(text) || text.Length > MatchProbeLimit || !EmailAddress.TryParse(text.Trim(), allowUtf8: true, out EmailAddress address) || address.IsNull
            || !string.Equals(address.Domain, domain.Name, StringComparison.OrdinalIgnoreCase))
        {
            throw ApiException.Validation("address", "Must be an address at this domain.");
        }

        InboundDomainSettings? settings = await Inbound.GetSettingsAsync(domain.Id, ct).ConfigureAwait(false);
        bool enabled = settings is { Enabled: true };
        InboundRouteRecord? route = null;
        string reply = "550 5.7.1";
        if (enabled)
        {
            // What the receive path answers for a domain that stopped being verified or a suspended tenant: keep the mail waiting (design sections 11.3 and 11.4).
            Tenant? tenant = await Config.GetTenantAsync(domain.TenantId, ct).ConfigureAwait(false);
            if (domain.Status is not (DomainStatus.Verified or DomainStatus.TemporaryFailure) || tenant is not { Enabled: true })
            {
                reply = "450 4.2.1";
            }
            else
            {
                route = InboundRules.MatchRoute(await Inbound.GetRoutesAsync(domain.Id, ct).ConfigureAwait(false), address.LocalPart);
                // postmaster is accepted without a route (RFC 5321 section 4.5.1) and stored with the action store: the receive path says 250 for it, and so must this.
                reply = route is null && !InboundRules.IsPostmaster(address.LocalPart) ? "550 5.1.1" : "250";
            }
        }

        return ApiResults.Ok(new InboundRouteMatchResponse((address.LocalPart + "@" + address.Domain).ToLowerInvariant(), enabled, route is null ? null : ToResponse(route), reply));
    }

    // Messages

    private static InboundVerdictResponse Verdict(InboundVerdict v, string? domain = null, string? policy = null) => new(InboundNames.Of(v), domain, policy);

    private static InboundActionResponse ActionOf(InboundMessage m, string? currentKind = null) =>
        new(InboundNames.Of(m.ActionKind), InboundNames.Of(m.ActionState), m.ActionAttempts, m.RetryGeneration, m.ActionNextAttemptAt, m.ActionFinishedAt, m.ActionLastError, m.ForwardMessageId, m.ActionNote, currentKind);

    private static InboundMessageResponse ToResponse(InboundMessage m, InboundContentResponse? content = null, string? currentKind = null) => new(
        m.Id, m.DomainId, m.Domain, m.ReceivedAt, m.RemoteAddress, m.Helo, m.TlsUsed, m.EnvelopeFrom, m.EnvelopeTo, m.Subject, m.Size,
        new InboundAuthResponse(Verdict(m.Auth.Spf, m.Auth.SpfDomain), Verdict(m.Auth.SpfHelo), Verdict(m.Auth.Dkim, m.Auth.DkimDomain), Verdict(m.Auth.Dmarc, policy: m.Auth.DmarcPolicy), Verdict(m.Auth.Arc)),
        m.Disposition == InboundDmarcDisposition.Flagged, m.RouteId, ActionOf(m, currentKind), m.HasRaw, content);

    private async Task<InboundMessage> FindMessageAsync(ApiCaller caller, string id, CancellationToken ct)
    {
        InboundMessage? message = ApiJson.TryParseId(id, out Guid guid) ? await Inbound.GetAsync(caller.TenantId, guid, ct).ConfigureAwait(false) : null;
        return message ?? throw ApiException.NotFound("Message not found.");
    }

    /// <summary>The filters of the message list and of the erasure, read from the query string (the same names and rules).</summary>
    private static InboundMessageQuery ReadQuery(HttpContext context, Guid tenantId, bool paging)
    {
        var errors = new ValidationErrors();
        var q = new QueryReader(context.Request, errors);
        Guid? domain = Id(q.String("domainId", 64), "domainId", errors);
        Guid? route = Id(q.String("route", 64), "route", errors);
        InboundActionKind? kind = null;
        if (q.String("action", 16) is { } kindText)
        {
            if (InboundNames.TryParse(kindText, out InboundActionKind k)) { kind = k; } else { errors.Add("action", "Must be one of: webhook, forward, store, discard."); }
        }

        InboundActionState? state = null;
        if (q.String("state", 16) is { } stateText)
        {
            if (InboundNames.TryParse(stateText, out InboundActionState s)) { state = s; } else { errors.Add("state", "Must be one of: pending, done, failed."); }
        }

        InboundVerdict? dmarc = null;
        if (q.String("dmarc", 16) is { } dmarcText)
        {
            if (InboundNames.TryParse(dmarcText, out InboundVerdict v)) { dmarc = v; } else { errors.Add("dmarc", "Must be a verdict: none, pass, fail, softfail, neutral, temperror, permerror, policy."); }
        }

        bool? flagged = null;
        if (q.OneOf("dmarcFlagged", "true", "false") is { } flaggedText)
        {
            flagged = flaggedText == "true";
        }

        var query = new InboundMessageQuery(
            TenantId: tenantId,
            DomainId: domain,
            Recipient: q.String("recipient", 320),
            Sender: q.String("sender", 320),
            SubjectContains: q.String("subject", 200),
            RouteId: route,
            ActionKind: kind,
            ActionState: state,
            Dmarc: dmarc,
            DmarcFlagged: flagged,
            From: q.Timestamp("from"),
            To: q.Timestamp("to"),
            Limit: paging ? q.Int("limit", 50, 1, 200) : 50,
            Cursor: paging ? q.String("cursor", 512) : null);
        errors.ThrowIfAny();
        return query;
    }

    private async Task<IResult> ListMessagesAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.InboundRead).ConfigureAwait(false);
        InboundMessageQuery query = ReadQuery(context, caller.TenantId, paging: true);
        Page<InboundMessage> page = await Inbound.SearchAsync(query, context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(new ListResponse<InboundMessageResponse>(page.Items.Select(m => ToResponse(m)).ToList(), page.NextCursor));
    }

    /// <summary>Erasure: everything of the tenant that matches the filters. At least one filter is required so the call can never empty a tenant by accident.</summary>
    private async Task<IResult> EraseMessagesAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.InboundWrite).ConfigureAwait(false);
        InboundMessageQuery query = ReadQuery(context, caller.TenantId, paging: false);
        if (!InboundRules.HasFilter(query))
        {
            throw ApiException.Validation("filter", "Name at least one filter (domainId, recipient, sender, subject, route, action, state, dmarc, dmarcFlagged, from, to): the call never deletes everything.");
        }

        long deleted = await Inbound.DeleteMatchingAsync(query, context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(new InboundErasedResponse(deleted));
    }

    private static Guid? Id(string? text, string field, ValidationErrors errors)
    {
        if (text is null)
        {
            return null;
        }

        if (ApiJson.TryParseId(text, out Guid id))
        {
            return id;
        }

        errors.Add(field, "Not a valid id.");
        return null;
    }

    private async Task<IResult> UsageAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.InboundRead).ConfigureAwait(false);
        var errors = new ValidationErrors();
        Guid? domain = Id(new QueryReader(context.Request, errors).String("domainId", 64), "domainId", errors);
        errors.ThrowIfAny();
        InboundUsage usage = await Inbound.GetUsageAsync(caller.TenantId, domain, context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(new InboundUsageResponse(usage.Messages, usage.BodyBytes, usage.Pending, usage.Failed, usage.OldestPendingAt));
    }

    private async Task<IResult> GetMessageAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.InboundRead).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        InboundMessage message = await FindMessageAsync(caller, id, ct).ConfigureAwait(false);
        byte[]? raw = message.HasRaw ? await Inbound.GetRawAsync(caller.TenantId, message.Id, ct).ConfigureAwait(false) : null;
        InboundContentResponse content;
        if (raw is null)
        {
            content = new InboundContentResponse("no_body", [], null, null, false, []);
        }
        else
        {
            InboundMessageContent read = InboundContentReader.Read(raw, MaxBodyChars);
            content = new InboundContentResponse(
                "available", read.Headers.Select(h => new InboundHeaderResponse(h.Name, h.Value)).ToList(), read.Text, read.Html, read.Truncated,
                read.Attachments.Select(a => new InboundAttachmentResponse(a.Index, a.FileName, a.ContentType, a.Size, a.ContentId, a.Disposition)).ToList());
        }

        InboundRouteRecord? route = message.RouteId is { } routeId ? await Inbound.GetRouteAsync(caller.TenantId, routeId, ct).ConfigureAwait(false) : null;
        return ApiResults.Ok(ToResponse(message, content, route is null ? null : InboundNames.Of(route.ActionKind)));
    }

    private static ApiException BodyGone() =>
        new(StatusCodes.Status410Gone, ApiCodes.InboundBodyGone, "The message has no stored body any more (discarded, forwarded, or past its retention).");

    private async Task<IResult> RawAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.InboundRead).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        InboundMessage message = await FindMessageAsync(caller, id, ct).ConfigureAwait(false);
        byte[] raw = (message.HasRaw ? await Inbound.GetRawAsync(caller.TenantId, message.Id, ct).ConfigureAwait(false) : null) ?? throw BodyGone();
        return new DownloadResult(raw, "message/rfc822", $"{ApiJson.Id(message.Id)}.eml");
    }

    private async Task<IResult> AttachmentAsync(HttpContext context, string id, string index)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.InboundRead).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        InboundMessage message = await FindMessageAsync(caller, id, ct).ConfigureAwait(false);
        byte[] raw = (message.HasRaw ? await Inbound.GetRawAsync(caller.TenantId, message.Id, ct).ConfigureAwait(false) : null) ?? throw BodyGone();
        InboundMessageContent read = InboundContentReader.Read(raw, 1);
        if (!int.TryParse(index, NumberStyles.None, CultureInfo.InvariantCulture, out int i) || i >= read.Attachments.Count)
        {
            throw ApiException.NotFound("Attachment not found.");
        }

        InboundAttachment attachment = read.Attachments[i];
        string name = InboundContentReader.SafeDownloadName(attachment.FileName, $"attachment-{i}");
        return new DownloadResult(attachment.Part.GetDecodedBytes(), "application/octet-stream", name, attachment.ContentType);
    }

    private async Task<IResult> DeleteMessageAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.InboundWrite).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        InboundMessage message = await FindMessageAsync(caller, id, ct).ConfigureAwait(false);
        if (!await Inbound.DeleteAsync(caller.TenantId, message.Id, ct).ConfigureAwait(false))
        {
            throw ApiException.NotFound("Message not found.");
        }

        return ApiResults.NoContent();
    }

    private async Task<IResult> RetryAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.InboundWrite).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        InboundMessage message = await FindMessageAsync(caller, id, ct).ConfigureAwait(false);
        InboundRetryResult result = await Inbound.RetryActionAsync(caller.TenantId, message.Id, clock.UtcNow, ct).ConfigureAwait(false);
        switch (result)
        {
            case InboundRetryResult.NotFound:
                throw ApiException.NotFound("Message not found.");
            case InboundRetryResult.NotRetryable:
                throw new ApiException(StatusCodes.Status409Conflict, ApiCodes.Conflict, "Only a webhook or forward action whose message body is still stored can be repeated.", extensions: new Dictionary<string, object?> { ["reason"] = "not_retryable" });
            case InboundRetryResult.AlreadyPending:
                throw new ApiException(StatusCodes.Status409Conflict, ApiCodes.Conflict, "The action is pending already.", extensions: new Dictionary<string, object?> { ["reason"] = "already_pending" });
        }

        InboundMessage again = await FindMessageAsync(caller, id, ct).ConfigureAwait(false);
        return ApiResults.Accepted(new InboundRetryResponse(again.Id, ActionOf(again)));
    }

    // The type is the sender's claim, put in a response header: only token characters, exactly one slash, a bounded length.
    private static bool IsMediaType(string value)
    {
        if (value.Length is 0 or > 127 || value.Count(c => c == '/') != 1)
        {
            return false;
        }

        foreach (char c in value)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '/' or '.' or '+' or '-' or '_'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>A body offered for download: never rendered by a browser (<c>attachment</c>, <c>nosniff</c>, no caching), whatever the sender claimed it to be.</summary>
    private sealed class DownloadResult(byte[] bytes, string contentType, string fileName, string? originalContentType = null) : IResult
    {
        public async Task ExecuteAsync(HttpContext httpContext)
        {
            HttpResponse response = httpContext.Response;
            response.StatusCode = StatusCodes.Status200OK;
            response.ContentType = contentType;
            response.ContentLength = bytes.Length;
            response.Headers.CacheControl = "no-store";
            response.Headers["X-Content-Type-Options"] = "nosniff";
            // Should a browser render it anyway (a saved link opened by hand), nothing in it may run, load or reach out.
            response.Headers["Content-Security-Policy"] = "default-src 'none'; sandbox";
            response.Headers.ContentDisposition = $"attachment; filename=\"{fileName}\"";
            if (originalContentType is not null)
            {
                response.Headers["X-Original-Content-Type"] = IsMediaType(originalContentType) ? originalContentType : "application/octet-stream";
            }

            await response.Body.WriteAsync(bytes, httpContext.RequestAborted).ConfigureAwait(false);
        }
    }
}
