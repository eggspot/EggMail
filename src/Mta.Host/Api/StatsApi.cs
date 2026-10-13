using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Mta.Core;
using Mta.Storage;

namespace Mta.Host.Api;

public sealed record StatsRowResponse(
    DateTimeOffset Period,
    string SendingDomain,
    string RecipientDomain,
    long Accepted,
    long Delivered,
    long Deferred,
    long HardBounce,
    long SoftBounce,
    long Expired,
    long Complained,
    long Rejected,
    long Suppressed);

public sealed record StatsResponse(string Granularity, IReadOnlyList<StatsRowResponse> Rows);

public sealed record RecentEventResponse(DateTimeOffset At, string Type, string RecipientDomain, [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? SendingDomain, Guid TenantId, string? Code);

/// <summary>Statistics and the content-free recent-events ring (scope <c>read</c>; available on every backend and in both history modes).</summary>
public sealed class StatsApi(ApiAuthenticator auth, IStorage storage, ApiOptions options, IClock clock)
{
    private static readonly TimeSpan MaxHourlyRange = TimeSpan.FromDays(35);
    private static readonly TimeSpan MaxDailyRange = TimeSpan.FromDays(800);

    public void Map(RouteGroupBuilder api)
    {
        api.GetRoute("/stats", StatsAsync);
        api.GetRoute("/stats/recent-events", RecentEventsAsync);
    }

    private async Task<IResult> StatsAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Read).ConfigureAwait(false);
        var errors = new ValidationErrors();
        var q = new QueryReader(context.Request, errors);
        string granularity = q.OneOf("granularity", "hour", "day") ?? "hour";
        bool daily = granularity == "day";
        DateTimeOffset to = q.Timestamp("to") ?? clock.UtcNow;
        DateTimeOffset from = q.Timestamp("from") ?? (daily ? to.AddDays(-30) : to.AddHours(-24));
        string? domain = q.String("domain", 253)?.ToLowerInvariant();
        errors.ThrowIfAny();
        if (from > to)
        {
            throw ApiException.Validation("from", "Must not be after 'to'.");
        }

        if (to - from > (daily ? MaxDailyRange : MaxHourlyRange))
        {
            throw ApiException.Validation("from", $"At most {(daily ? MaxDailyRange : MaxHourlyRange).TotalDays:0} days per query at {granularity} granularity.");
        }

        IReadOnlyList<StatRow> rows = await storage.Stats.QueryAsync(caller.TenantId, from, to, daily, context.RequestAborted).ConfigureAwait(false);
        var selected = rows.Where(r => domain is null || string.Equals(r.SendingDomain, domain, StringComparison.OrdinalIgnoreCase)).ToList();
        if (selected.Count > options.MaxStatsRows)
        {
            throw ApiException.Validation("from", $"The range holds more than {options.MaxStatsRows} rows; narrow the range or filter by domain.");
        }

        return ApiResults.Ok(new StatsResponse(granularity, selected.Select(r => new StatsRowResponse(
            r.PeriodStart, r.SendingDomain, r.RecipientDomain, r.Accepted, r.Delivered, r.Deferred, r.HardBounce, r.SoftBounce, r.Expired, r.Complained, r.Rejected, r.Suppressed)).ToList()));
    }

    private async Task<IResult> RecentEventsAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Read).ConfigureAwait(false);
        var errors = new ValidationErrors();
        int limit = new QueryReader(context.Request, errors).Int("limit", 50, 1, 1000);
        errors.ThrowIfAny();
        IReadOnlyList<RecentEvent> events = await storage.Stats.GetRecentEventsAsync(caller.TenantId, limit, context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(events.Select(e => new RecentEventResponse(e.At, e.EventType, e.RecipientDomain, null, e.TenantId, e.Detail)).ToList());
    }
}

/// <summary>Per-tenant settings (<c>GET/PUT /settings</c>).</summary>
public sealed class TenantSettingsApi(ApiAuthenticator auth, SettingsService settings, ApiOptions options)
{
    public void Map(RouteGroupBuilder api)
    {
        api.GetRoute("/settings", GetAsync);
        api.PutRoute("/settings", PutAsync);
    }

    private async Task<IResult> GetAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Read).ConfigureAwait(false);
        return ApiResults.Ok(await settings.ListTenantAsync(caller.Tenant!, caller.IsAdmin, context.RequestAborted).ConfigureAwait(false));
    }

    private async Task<IResult> PutAsync(HttpContext context)
    {
        // Settings change what a tenant is allowed to do, so API keys never edit them: only a signed-in user (or an admin acting on a tenant).
        ApiCaller caller = await auth.RequireTenantAsync(context).ConfigureAwait(false);
        if (caller.Kind == CallerKind.ApiKey)
        {
            throw ApiException.Forbidden("Settings can only be changed from a dashboard session.");
        }

        SettingsUpdateRequest body = await ApiJson.ReadBodyAsync<SettingsUpdateRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        if (body.Values is null)
        {
            throw ApiException.Validation("values", "An object of setting values is required.");
        }

        return ApiResults.Ok(await settings.UpdateTenantAsync(caller.Tenant!, caller.IsAdmin, body.Values, context.RequestAborted).ConfigureAwait(false));
    }
}
