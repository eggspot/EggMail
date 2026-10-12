using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Mta.Storage;

namespace Mta.Host.Api;

public sealed class LoginRequest
{
    [JsonPropertyName("user")]
    public string? User { get; set; }

    [JsonPropertyName("password")]
    public string? Password { get; set; }
}

public sealed record SessionResponse(string User, string Role, Guid? TenantId);

public sealed record MeResponse(string User, string Role, Guid? TenantId, string? TenantName, string? CsrfToken, string AuthenticatedBy, IReadOnlyList<string>? Scopes);

/// <summary><c>POST/DELETE /session</c> and <c>GET /me</c>.</summary>
public sealed class SessionApi(SessionService sessions, ApiAuthenticator auth, ApiOptions options)
{
    public void Map(RouteGroupBuilder api)
    {
        api.PostRoute("/session", LoginAsync);
        api.DeleteRoute("/session", LogoutAsync);
        api.GetRoute("/me", MeAsync);
    }

    public static string RoleName(DashboardRole role) => role == DashboardRole.Admin ? "admin" : "tenant";

    private async Task<IResult> LoginAsync(HttpContext context)
    {
        LoginRequest body = await ApiJson.ReadBodyAsync<LoginRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        if (string.IsNullOrWhiteSpace(body.User) || body.User.Length > 256)
        {
            errors.Add("user", "A user name is required.");
        }

        if (string.IsNullOrEmpty(body.Password) || body.Password.Length > 1024)
        {
            errors.Add("password", "A password is required.");
        }

        errors.ThrowIfAny();
        DashboardUser user = await sessions.SignInAsync(context, body.User!, body.Password!).ConfigureAwait(false);
        return ApiResults.Ok(new SessionResponse(user.UserName, RoleName(user.Role), user.TenantId));
    }

    private async Task<IResult> LogoutAsync(HttpContext context)
    {
        // Signing out is idempotent: no session (or an expired one) is still a success, but a live session needs its CSRF token.
        byte[]? hash = null;
        if (context.Request.Cookies.ContainsKey(options.SessionCookieName) && string.IsNullOrEmpty(context.Request.Headers.Authorization.ToString()))
        {
            try
            {
                hash = (await auth.AuthenticateAsync(context).ConfigureAwait(false)).SessionHash;
            }
            catch (ApiException ex) when (ex.Status == StatusCodes.Status401Unauthorized)
            {
                hash = null;
            }
        }

        await sessions.SignOutAsync(context, hash).ConfigureAwait(false);
        return ApiResults.NoContent();
    }

    private async Task<IResult> MeAsync(HttpContext context)
    {
        ApiCaller caller = await auth.AuthenticateAsync(context).ConfigureAwait(false);
        return ApiResults.Ok(new MeResponse(
            caller.Name,
            RoleName(caller.Role),
            caller.HomeTenantId,
            caller.Tenant?.Name,
            caller.CsrfToken,
            caller.Kind == CallerKind.Session ? "session" : "api_key",
            caller.Scopes?.OrderBy(s => s, StringComparer.Ordinal).ToList()));
    }
}
