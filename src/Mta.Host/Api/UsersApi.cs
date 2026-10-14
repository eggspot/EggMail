using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Mta.Core;
using Mta.Host.Security;
using Mta.Storage;
using Mta.Storage.Model;

namespace Mta.Host.Api;

public sealed class CreateUserRequest
{
    [JsonPropertyName("userName")]
    public string? UserName { get; set; }

    /// <summary>Optional: when absent the server generates one and returns it once.</summary>
    [JsonPropertyName("password")]
    public string? Password { get; set; }

    /// <summary><c>admin</c> or <c>tenant</c>.</summary>
    [JsonPropertyName("role")]
    public string? Role { get; set; }

    [JsonPropertyName("tenantId")]
    public string? TenantId { get; set; }
}

public sealed class UpdateUserRequest
{
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("role")]
    public string? Role { get; set; }

    [JsonPropertyName("tenantId")]
    public string? TenantId { get; set; }
}

public sealed class ResetUserPasswordRequest
{
    /// <summary>Optional: when absent the server generates one and returns it once.</summary>
    [JsonPropertyName("password")]
    public string? Password { get; set; }
}

public sealed class ChangePasswordRequest
{
    [JsonPropertyName("currentPassword")]
    public string? CurrentPassword { get; set; }

    [JsonPropertyName("newPassword")]
    public string? NewPassword { get; set; }
}

/// <summary>A dashboard user. The password hash is never part of it; <see cref="Password"/> is present only when the server generated one (create, reset) and only in that response.</summary>
public sealed record UserResponse(
    Guid Id,
    string UserName,
    string Role,
    Guid? TenantId,
    bool Enabled,
    DateTimeOffset CreatedAt,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Password = null);

/// <summary>
/// Dashboard user management (admin role only, <c>/admin/users</c>) and the signed-in user's own password change (<c>/me/password</c>).
/// Every state change that should end access (disable, role or tenant change, password reset, delete) ends the user's sessions in the same
/// storage write; the last enabled administrator cannot be disabled, demoted or deleted (checked atomically by the store). There is no audit log
/// table: each change is a structured log line that names the actor and the target and never carries a password or hash.
/// </summary>
public sealed class UsersApi(
    ApiAuthenticator auth,
    IStorage storage,
    ApiOptions options,
    IClock clock,
    AuthThrottle throttle,
    ILogger<UsersApi> logger)
{
    private IConfigStore Config => storage.Config;

    /// <summary>Test seam: runs after a PATCH validated its request and before it writes, to make a concurrent change deterministic.</summary>
    internal Func<Task>? AfterReadForTest { get; set; }

    public void Map(RouteGroupBuilder api)
    {
        var users = api.MapGroup("/admin/users");
        users.GetRoute("", ListAsync);
        users.PostRoute("", CreateAsync);
        users.GetRoute("/{id}", GetAsync);
        users.PatchRoute("/{id}", UpdateAsync);
        users.DeleteRoute("/{id}", DeleteAsync);
        users.PostRoute("/{id}/reset-password", ResetPasswordAsync);
        api.PostRoute("/me/password", ChangeOwnPasswordAsync);
    }

    private static UserResponse ToResponse(DashboardUser u, string? generatedPassword = null) =>
        new(u.Id, u.UserName, SessionApi.RoleName(u.Role), u.TenantId, u.Enabled, u.CreatedAt, generatedPassword);

    private async Task<IResult> ListAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        var users = await Config.GetDashboardUsersAsync(context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(users.Select(u => ToResponse(u)).ToList());
    }

    private async Task<IResult> GetAsync(HttpContext context, string id)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        return ApiResults.Ok(ToResponse(await FindAsync(id, context.RequestAborted).ConfigureAwait(false)));
    }

    private async Task<DashboardUser> FindAsync(string id, CancellationToken ct) =>
        (ApiJson.TryParseId(id, out Guid guid) ? await Config.GetDashboardUserAsync(guid, ct).ConfigureAwait(false) : null)
        ?? throw ApiException.NotFound("User not found.");

    private async Task<IResult> CreateAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        CreateUserRequest body = await ApiJson.ReadBodyAsync<CreateUserRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        if (DashboardAccounts.UserNameProblem(body.UserName) is { } nameProblem)
        {
            errors.Add("userName", nameProblem);
        }

        DashboardRole? role = ParseRole(body.Role, "role", errors, required: true);
        Guid? tenantId = null;
        if (role == DashboardRole.Tenant)
        {
            tenantId = await RequireActiveTenantAsync(body.TenantId, "tenantId", errors, ct).ConfigureAwait(false);
        }
        else if (role == DashboardRole.Admin && body.TenantId is not null)
        {
            errors.Add("tenantId", "An administrator does not belong to a tenant.");
        }

        string? generated = null;
        if (body.Password is null)
        {
            generated = DashboardAccounts.GeneratePassword();
        }
        else if (DashboardAccounts.PasswordProblem(body.Password) is { } passwordProblem)
        {
            errors.Add("password", passwordProblem);
        }

        errors.ThrowIfAny();
        string name = ConfigMapping.NormalizeUserName(body.UserName!); // the stored form: user names are unique case-insensitively and kept in lower case
        if (await Config.FindDashboardUserAsync(name, ct).ConfigureAwait(false) is not null)
        {
            throw ApiException.Validation("userName", "A user with this name already exists.");
        }

        string password = generated ?? body.Password!;
        string hash = await Task.Run(() => DashboardAccounts.HashPassword(password, options.PasswordHashIterations), ct).ConfigureAwait(false);
        var user = new DashboardUser(Ids.New(clock.UtcNow), name, hash, role!.Value, tenantId, true, clock.UtcNow);
        try
        {
            await Config.UpsertDashboardUserAsync(user, ct).ConfigureAwait(false);
        }
        catch (StorageConflictException)
        {
            throw ApiException.Validation("userName", "A user with this name already exists.");
        }

        Log("created", caller, user, $"role={SessionApi.RoleName(user.Role)}");
        return ApiResults.Created("/api/v1/admin/users/" + ApiJson.Id(user.Id), ToResponse(user, generated));
    }

    private async Task<IResult> UpdateAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        DashboardUser current = await FindAsync(id, ct).ConfigureAwait(false);
        UpdateUserRequest body = await ApiJson.ReadBodyAsync<UpdateUserRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        if (body.Enabled is null && body.Role is null && body.TenantId is null)
        {
            throw ApiException.Validation("$", "Send at least one of enabled, role or tenantId.");
        }

        var errors = new ValidationErrors();
        DashboardRole? newRole = ParseRole(body.Role, "role", errors, required: false);
        DashboardRole role = newRole ?? current.Role; // for validation only: the write below derives everything again from the row it reads
        Guid? requestedTenant = null;
        if (role == DashboardRole.Admin)
        {
            if (body.TenantId is not null)
            {
                errors.Add("tenantId", "An administrator does not belong to a tenant.");
            }
        }
        else if (body.TenantId is not null || current.Role != DashboardRole.Tenant)
        {
            requestedTenant = await RequireActiveTenantAsync(body.TenantId, "tenantId", errors, ct).ConfigureAwait(false);
        }

        errors.ThrowIfAny();
        if (AfterReadForTest is { } hook)
        {
            await hook().ConfigureAwait(false);
        }

        // Everything is derived from the stored row inside the write (not from the copy read above), so a change made in between, for example a
        // demotion, is neither undone by this request's stale view nor lost: only the members the request names are changed. A request that
        // names a role or a tenant ends the sessions (the dashboard sends only what changed).
        bool endSessions = body.Enabled == false || newRole is not null || body.TenantId is not null;
        DashboardUserUpdate result = await Config.UpdateDashboardUserGuardedAsync(
            current.Id,
            u =>
            {
                DashboardRole r = newRole ?? u.Role;
                Guid? t = r == DashboardRole.Admin ? null : requestedTenant ?? u.TenantId;
                return r == DashboardRole.Tenant && t is null
                    ? u // a tenant user needs a tenant and a concurrent change removed the one this request relied on: change nothing; the check below answers 409
                    : u with { Enabled = body.Enabled ?? u.Enabled, Role = r, TenantId = t };
            },
            endSessions,
            keepSessionHash: null,
            ct).ConfigureAwait(false);
        DashboardUser updated = Applied(result);
        if ((newRole is { } wantedRole && updated.Role != wantedRole) || (body.Enabled is { } wantedEnabled && updated.Enabled != wantedEnabled))
        {
            throw ApiException.Conflict("The user was changed by someone else while this request ran. Reload and try again.");
        }

        Log("updated", caller, updated, $"enabled={updated.Enabled} role={SessionApi.RoleName(updated.Role)} tenant={(updated.TenantId is { } t ? ApiJson.Id(t) : "-")}");
        return ApiResults.Ok(ToResponse(updated));
    }

    private async Task<IResult> DeleteAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        DashboardUser current = await FindAsync(id, ct).ConfigureAwait(false);
        switch (await Config.DeleteDashboardUserGuardedAsync(current.Id, ct).ConfigureAwait(false))
        {
            case DashboardUserWriteResult.WouldRemoveLastAdmin:
                throw LastAdmin();
            case DashboardUserWriteResult.NotFound:
                throw ApiException.NotFound("User not found.");
        }

        Log("deleted", caller, current, null);
        return ApiResults.NoContent();
    }

    private async Task<IResult> ResetPasswordAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        DashboardUser current = await FindAsync(id, ct).ConfigureAwait(false);
        if (current.Id == caller.UserId)
        {
            throw ApiException.Conflict("Use the change-password form (POST /me/password) for your own password.");
        }

        ResetUserPasswordRequest body = await ApiJson.ReadBodyAsync<ResetUserPasswordRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        string? generated = body.Password is null ? DashboardAccounts.GeneratePassword() : null;
        if (generated is null && DashboardAccounts.PasswordProblem(body.Password) is { } problem)
        {
            throw ApiException.Validation("password", problem);
        }

        string password = generated ?? body.Password!;
        string hash = await Task.Run(() => DashboardAccounts.HashPassword(password, options.PasswordHashIterations), ct).ConfigureAwait(false);
        DashboardUserUpdate result = await Config.UpdateDashboardUserGuardedAsync(current.Id, u => u with { PasswordHash = hash }, endSessions: true, keepSessionHash: null, ct).ConfigureAwait(false);
        DashboardUser updated = Applied(result);
        Log("password reset", caller, updated, generated is null ? "password supplied" : "password generated");
        return ApiResults.Ok(ToResponse(updated, generated));
    }

    private async Task<IResult> ChangeOwnPasswordAsync(HttpContext context)
    {
        ApiCaller caller = await auth.AuthenticateAsync(context).ConfigureAwait(false);
        if (caller.Kind != CallerKind.Session || caller.UserId is not { } userId)
        {
            throw ApiException.Forbidden("Only a signed-in dashboard user can change a password; an API key cannot.");
        }

        CancellationToken ct = context.RequestAborted;
        ChangePasswordRequest body = await ApiJson.ReadBodyAsync<ChangePasswordRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        if (string.IsNullOrEmpty(body.CurrentPassword) || body.CurrentPassword.Length > DashboardAccounts.MaximumPasswordLength)
        {
            errors.Add("currentPassword", "The current password is required.");
        }

        if (DashboardAccounts.PasswordProblem(body.NewPassword) is { } problem)
        {
            errors.Add("newPassword", problem);
        }
        else if (body.NewPassword == body.CurrentPassword)
        {
            errors.Add("newPassword", "The new password must differ from the current one.");
        }

        errors.ThrowIfAny();

        // The current password is checked under the same lockout as sign-in (and SMTP AUTH): a stolen session must not be able to guess it.
        string ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        string userKey = "user:" + ConfigMapping.NormalizeUserName(caller.Name);
        var check = await throttle.CheckAsync(ct, ip, userKey).ConfigureAwait(false);
        if (check.RetryAfter is { } retryAfter)
        {
            throw ApiException.RateLimited("Too many failed password attempts. Try again later.", retryAfter);
        }

        DashboardUser user = await Config.GetDashboardUserAsync(userId, ct).ConfigureAwait(false) ?? throw ApiException.Unauthorized("The session has ended. Sign in again.");
        if (!await Task.Run(() => PasswordHasher.Verify(body.CurrentPassword!, user.PasswordHash), ct).ConfigureAwait(false))
        {
            await throttle.RecordFailureAsync(ip, userKey).ConfigureAwait(false);
            throw ApiException.Validation("currentPassword", "The current password is not correct.");
        }

        await throttle.RecordSuccessAsync(check, userKey).ConfigureAwait(false);
        string hash = await Task.Run(() => DashboardAccounts.HashPassword(body.NewPassword!, options.PasswordHashIterations), ct).ConfigureAwait(false);

        // Every other session of the user ends in the same write; the one that made the request stays, so the person is not thrown out of the page.
        // The change applies only to the password that was verified: if an administrator reset it meanwhile, the reset wins and this request is refused.
        string verifiedHash = user.PasswordHash;
        if (AfterReadForTest is { } hook)
        {
            await hook().ConfigureAwait(false);
        }

        DashboardUserUpdate result = await Config.UpdateDashboardUserGuardedAsync(
            userId, u => u.PasswordHash == verifiedHash ? u with { PasswordHash = hash } : u, endSessions: true, keepSessionHash: caller.SessionHash, ct).ConfigureAwait(false);
        if (Applied(result).PasswordHash != hash)
        {
            throw ApiException.Conflict("The password was changed by someone else while this request ran. Sign in again with the new password.");
        }

        Log("password changed", caller, user, "other sessions ended");
        return ApiResults.NoContent();
    }

    private static DashboardUser Applied(DashboardUserUpdate result) => result.Result switch
    {
        DashboardUserWriteResult.Applied => result.User!,
        DashboardUserWriteResult.WouldRemoveLastAdmin => throw LastAdmin(),
        _ => throw ApiException.NotFound("User not found."),
    };

    private static ApiException LastAdmin() => new(
        StatusCodes.Status409Conflict,
        ApiCodes.Conflict,
        "This is the only enabled administrator. Create or enable another administrator first.",
        extensions: new Dictionary<string, object?> { ["reason"] = "last_admin" });

    private static DashboardRole? ParseRole(string? value, string field, ValidationErrors errors, bool required)
    {
        switch (value)
        {
            case "admin":
                return DashboardRole.Admin;
            case "tenant":
                return DashboardRole.Tenant;
            case null when !required:
                return null;
            default:
                errors.Add(field, "Must be \"admin\" or \"tenant\".");
                return null;
        }
    }

    /// <summary>A tenant user belongs to an existing, active tenant. Problems are added to <paramref name="errors"/>; returns the id when it is usable.</summary>
    private async Task<Guid?> RequireActiveTenantAsync(string? value, string field, ValidationErrors errors, CancellationToken ct)
    {
        if (!ApiJson.TryParseId(value, out Guid id))
        {
            errors.Add(field, "A tenant user needs a tenant id.");
            return null;
        }

        Tenant? tenant = await Config.GetTenantAsync(id, ct).ConfigureAwait(false);
        if (tenant is null)
        {
            errors.Add(field, "Unknown tenant.");
            return null;
        }

        if (!tenant.Enabled)
        {
            errors.Add(field, "The tenant is suspended.");
            return null;
        }

        return id;
    }

    private void Log(string action, ApiCaller actor, DashboardUser target, string? detail) =>
        logger.LogInformation("Dashboard user {Action}: actor {Actor}, user {TargetId} ({TargetName}){Detail}", action, actor.Name, ApiJson.Id(target.Id), target.UserName, detail is null ? "" : ", " + detail);
}
