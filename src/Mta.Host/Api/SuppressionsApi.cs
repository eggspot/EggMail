using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Mta.Core;
using Mta.Storage;

namespace Mta.Host.Api;

public sealed class AddSuppressionRequest
{
    [JsonPropertyName("address")]
    public string? Address { get; set; }

    [JsonPropertyName("reason")]
    public string? Reason { get; set; }
}

public sealed record SuppressionResponse(string Address, string Reason, DateTimeOffset CreatedAt, string? Source);

/// <summary>The tenant's suppression list. Every call is keyed by the caller's tenant; addresses are compared case-insensitively.</summary>
public sealed class SuppressionsApi(ApiAuthenticator auth, IStorage storage, ApiOptions options, IClock clock)
{
    public void Map(RouteGroupBuilder api)
    {
        api.GetRoute("/suppressions", ListAsync);
        api.PostRoute("/suppressions", AddAsync);
        api.DeleteRoute("/suppressions/{address}", RemoveAsync);
    }

    private static SuppressionResponse ToResponse(SuppressionRecord s) => new(s.Address, ApiMap.SuppressionReason(s.Reason), s.CreatedAt, s.Source);

    private async Task<IResult> ListAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Suppressions).ConfigureAwait(false);
        var errors = new ValidationErrors();
        var q = new QueryReader(context.Request, errors);
        int limit = q.Int("limit", 50, 1, 500);
        string? cursor = q.String("cursor", 512);
        errors.ThrowIfAny();
        Page<SuppressionRecord> page = await storage.Config.GetSuppressionsAsync(caller.TenantId, cursor, limit, context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(new ListResponse<SuppressionResponse>(page.Items.Select(ToResponse).ToList(), page.NextCursor));
    }

    private async Task<IResult> AddAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Suppressions).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        AddSuppressionRequest body = await ApiJson.ReadBodyAsync<AddSuppressionRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        EmailAddress address = default;
        if (string.IsNullOrWhiteSpace(body.Address) || body.Address.Length > 320 || !EmailAddress.TryParse(body.Address.Trim(), allowUtf8: true, out address))
        {
            errors.Add("address", "Enter a valid email address.");
        }

        if (!ApiMap.TryParseSuppressionReason(body.Reason, out SuppressionReason reason))
        {
            errors.Add("reason", "Reason must be manual, bounce, complaint or unsubscribe.");
        }

        errors.ThrowIfAny();
        string text = address.ToString().ToLowerInvariant();
        bool existed = await storage.Config.IsSuppressedAsync(caller.TenantId, text, ct).ConfigureAwait(false);
        var record = new SuppressionRecord(caller.TenantId, text, reason, "api:" + caller.Name, clock.UtcNow, null);
        // Adding an address that is already listed updates its entry (200); a new entry answers 201.
        await storage.Config.AddSuppressionAsync(record, ct).ConfigureAwait(false);
        return existed
            ? ApiResults.Ok(ToResponse(record))
            : ApiResults.Created("/api/v1/suppressions/" + Uri.EscapeDataString(text), ToResponse(record));
    }

    private async Task<IResult> RemoveAsync(HttpContext context, string address)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Suppressions).ConfigureAwait(false);
        if (!await storage.Config.RemoveSuppressionAsync(caller.TenantId, address, context.RequestAborted).ConfigureAwait(false))
        {
            throw ApiException.NotFound("That address is not on the suppression list.");
        }

        return ApiResults.NoContent();
    }
}
