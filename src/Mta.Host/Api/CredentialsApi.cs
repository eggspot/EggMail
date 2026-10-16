using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Mta.Core;
using Mta.Host.Security;
using Mta.Storage;

namespace Mta.Host.Api;

public sealed class CreateApiKeyRequest
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("scopes")]
    public List<string>? Scopes { get; set; }
}

public sealed class CreateSmtpCredentialRequest
{
    [JsonPropertyName("username")]
    public string? Username { get; set; }
}

public sealed record ApiKeyResponse(
    Guid Id,
    string Name,
    string Prefix,
    IReadOnlyList<string> Scopes,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Key = null);

public sealed record SmtpCredentialResponse(
    Guid Id,
    string Username,
    DateTimeOffset CreatedAt,
    bool Enabled,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Password = null);

/// <summary>API keys and SMTP credentials of the caller's tenant (scope <c>keys</c>). Secrets are returned once, by the create call.</summary>
public sealed partial class CredentialsApi(ApiAuthenticator auth, IStorage storage, ApiOptions options, IClock clock)
{
    public void Map(RouteGroupBuilder api)
    {
        api.GetRoute("/api-keys", ListKeysAsync);
        api.PostRoute("/api-keys", CreateKeyAsync);
        api.DeleteRoute("/api-keys/{id}", RevokeKeyAsync);
        api.GetRoute("/smtp-credentials", ListSmtpAsync);
        api.PostRoute("/smtp-credentials", CreateSmtpAsync);
        api.DeleteRoute("/smtp-credentials/{id}", DeleteSmtpAsync);
    }

    [GeneratedRegex("^[A-Za-z0-9._@-]{3,64}$")]
    private static partial Regex UsernamePattern();

    private IConfigStore Config => storage.Config;

    private static ApiKeyResponse ToResponse(ApiKeyRecord k, string? key = null) =>
        new(k.Id, k.Name, k.Prefix, ApiScopes.Parse(k.Scopes).OrderBy(s => ApiScopes.All.ToList().IndexOf(s)).ToList(), k.CreatedAt, k.LastUsedAt, key);

    private async Task<IResult> ListKeysAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Keys).ConfigureAwait(false);
        var keys = await Config.GetApiKeysAsync(caller.TenantId, context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(keys.Where(k => k.RevokedAt is null).Select(k => ToResponse(k)).ToList());
    }

    private async Task<IResult> CreateKeyAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Keys).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        CreateApiKeyRequest body = await ApiJson.ReadBodyAsync<CreateApiKeyRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        string name = body.Name?.Trim() ?? "";
        if (name.Length is 0 or > 80 || ApiText.HasUnsafeCharacter(name))
        {
            errors.Add("name", "A name of 1 to 80 characters is required.");
        }

        if (body.Scopes is null || body.Scopes.Count == 0)
        {
            errors.Add("scopes", "Select at least one scope.");
        }
        else if (body.Scopes.Any(s => !ApiScopes.IsKnown(s)))
        {
            errors.Add("scopes", "Unknown scope. Known: " + string.Join(", ", ApiScopes.All) + ".");
        }
        else if (!body.Scopes.All(caller.HasScope))
        {
            // A key can only mint keys that are no more powerful than itself.
            errors.Add("scopes", "An API key can only create keys with scopes it has itself.");
        }

        errors.ThrowIfAny();

        var existing = await Config.GetApiKeysAsync(caller.TenantId, ct).ConfigureAwait(false);
        if (existing.Count(k => k.RevokedAt is null) >= options.MaxApiKeysPerTenant)
        {
            throw ApiException.Validation("name", $"At most {options.MaxApiKeysPerTenant} active API keys per tenant.");
        }

        var (token, prefix, digest) = ApiKeys.Generate();
        var record = new ApiKeyRecord(Ids.New(clock.UtcNow), caller.TenantId, name, prefix, digest, ApiScopes.Format(body.Scopes!), clock.UtcNow, null, null);
        await Config.AddApiKeyAsync(record, ct).ConfigureAwait(false);
        return ApiResults.Created("/api/v1/api-keys/" + ApiJson.Id(record.Id), ToResponse(record, token));
    }

    private async Task<IResult> RevokeKeyAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Keys).ConfigureAwait(false);
        if (!ApiJson.TryParseId(id, out Guid guid) || !await Config.RevokeApiKeyAsync(caller.TenantId, guid, clock.UtcNow, context.RequestAborted).ConfigureAwait(false))
        {
            throw ApiException.NotFound("API key not found.");
        }

        return ApiResults.NoContent();
    }

    private async Task<IResult> ListSmtpAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Keys).ConfigureAwait(false);
        var credentials = await Config.GetSmtpCredentialsAsync(caller.TenantId, context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(credentials.Select(c => new SmtpCredentialResponse(c.Id, c.UserName, c.CreatedAt, c.Enabled)).ToList());
    }

    private async Task<IResult> CreateSmtpAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Keys).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        if (!caller.HasScope(ApiScopes.Send))
        {
            // An SMTP credential sends mail; a key may not hand out a capability it does not have itself.
            throw ApiException.Forbidden("Creating SMTP credentials needs the 'send' scope as well as 'keys'.");
        }

        CreateSmtpCredentialRequest body = await ApiJson.ReadBodyAsync<CreateSmtpCredentialRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        string username = body.Username?.Trim() ?? "";
        if (!UsernamePattern().IsMatch(username))
        {
            throw ApiException.Validation("username", "Use 3 to 64 letters, digits, dot, dash, underscore or @.");
        }

        if ((await Config.GetSmtpCredentialsAsync(caller.TenantId, ct).ConfigureAwait(false)).Count >= options.MaxSmtpCredentialsPerTenant)
        {
            throw ApiException.Validation("username", $"At most {options.MaxSmtpCredentialsPerTenant} SMTP credentials per tenant.");
        }

        if (await Config.FindSmtpCredentialAsync(username, ct).ConfigureAwait(false) is not null)
        {
            throw ApiException.Validation("username", "This username already exists.");
        }

        string password = SessionService.Base64Url(RandomNumberGenerator.GetBytes(18));
        string hash = await Task.Run(() => PasswordHasher.Hash(password), ct).ConfigureAwait(false);
        var record = new SmtpCredential(Ids.New(clock.UtcNow), caller.TenantId, username, hash, true, clock.UtcNow);
        try
        {
            await Config.UpsertSmtpCredentialAsync(record, ct).ConfigureAwait(false);
        }
        catch (StorageConflictException)
        {
            throw ApiException.Validation("username", "This username already exists.");
        }

        return ApiResults.Created("/api/v1/smtp-credentials/" + ApiJson.Id(record.Id), new SmtpCredentialResponse(record.Id, record.UserName, record.CreatedAt, true, password));
    }

    private async Task<IResult> DeleteSmtpAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Keys).ConfigureAwait(false);
        if (!ApiJson.TryParseId(id, out Guid guid) || !await Config.DeleteSmtpCredentialAsync(caller.TenantId, guid, context.RequestAborted).ConfigureAwait(false))
        {
            throw ApiException.NotFound("SMTP credential not found.");
        }

        return ApiResults.NoContent();
    }
}
