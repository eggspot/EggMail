using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Mta.Core;
using Mta.Host.Security;
using Mta.Storage;

namespace Mta.Host.Api;

/// <summary>Scopes of an API key (docs/api.md, "Authentication").</summary>
public static class ApiScopes
{
    public const string Send = "send";
    public const string Read = "read";
    public const string Domains = "domains";
    public const string Webhooks = "webhooks";
    public const string Suppressions = "suppressions";
    public const string Keys = "keys";

    public static readonly IReadOnlyList<string> All = [Send, Read, Domains, Webhooks, Suppressions, Keys];

    public static bool IsKnown(string scope) => All.Contains(scope, StringComparer.Ordinal);

    /// <summary>Parses the stored comma-separated list.</summary>
    public static IReadOnlySet<string> Parse(string stored) =>
        stored.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet(StringComparer.Ordinal);

    public static string Format(IEnumerable<string> scopes) => string.Join(',', scopes.Distinct(StringComparer.Ordinal).OrderBy(s => All.ToList().IndexOf(s)));
}

public enum CallerKind : byte
{
    ApiKey,
    Session,
}

/// <summary>The authenticated party of a request and the tenant it acts on.</summary>
public sealed class ApiCaller
{
    public required CallerKind Kind { get; init; }

    /// <summary>The dashboard user name, or the API key's name.</summary>
    public required string Name { get; init; }

    public required DashboardRole Role { get; init; }

    /// <summary>The tenant the request acts on: the key's or user's tenant, or the one an admin selected with <c>X-Tenant-Id</c>. Null for an admin who selected none.</summary>
    public Tenant? Tenant { get; init; }

    /// <summary>The tenant this identity belongs to (null for admins).</summary>
    public Guid? HomeTenantId { get; init; }

    /// <summary>Scopes of an API key; null for a session (sessions have every scope).</summary>
    public IReadOnlySet<string>? Scopes { get; init; }

    public string? CsrfToken { get; init; }
    public Guid? ApiKeyId { get; init; }
    public Guid? UserId { get; init; }
    public byte[]? SessionHash { get; init; }

    public bool IsAdmin => Role == DashboardRole.Admin;

    /// <summary>The effective tenant id; throws if the call has none (use after a tenant check).</summary>
    public Guid TenantId => Tenant?.Id ?? throw new InvalidOperationException("The call has no tenant.");

    public bool HasScope(string scope) => Scopes is null || Scopes.Contains(scope);
}

/// <summary>
/// Authenticates API requests: Bearer API keys (SHA-256 digest lookup) and the dashboard session cookie (server-side sessions, CSRF
/// token on mutations). Every lookup that follows is keyed by the tenant resolved here, which is how tenant isolation is enforced.
/// </summary>
public sealed class ApiAuthenticator
{
    public const string CsrfHeader = "X-CSRF-Token";
    public const string TenantHeader = "X-Tenant-Id";

    private readonly IStorage _storage;
    private readonly IClock _clock;
    private readonly ApiOptions _options;
    private readonly ConcurrentDictionary<Guid, long> _keyTouched = new();
    private readonly ConcurrentDictionary<string, long> _sessionTouched = new();

    public ApiAuthenticator(IStorage storage, IClock clock, ApiOptions options)
    {
        _storage = storage;
        _clock = clock;
        _options = options;
    }

    private IConfigStore Config => _storage.Config;

    /// <summary>Authenticates and requires a tenant (the caller's own, or the one an admin selected); checks the scope for API keys.</summary>
    public async ValueTask<ApiCaller> RequireTenantAsync(HttpContext context, string? scope = null)
    {
        ApiCaller identity = await AuthenticateAsync(context).ConfigureAwait(false);
        if (scope is not null && !identity.HasScope(scope))
        {
            throw ApiException.Forbidden($"This API key lacks the '{scope}' scope.");
        }

        return await WithTenantAsync(context, identity).ConfigureAwait(false);
    }

    /// <summary>Authenticates and requires the admin role (API keys are tenant-scoped and never admin).</summary>
    public async ValueTask<ApiCaller> RequireAdminAsync(HttpContext context)
    {
        ApiCaller identity = await AuthenticateAsync(context).ConfigureAwait(false);
        if (!identity.IsAdmin)
        {
            throw ApiException.Forbidden("This endpoint requires the admin role.");
        }

        return identity;
    }

    /// <summary>Resolves who is calling without requiring a tenant (also enforces CSRF for sessions).</summary>
    public async ValueTask<ApiCaller> AuthenticateAsync(HttpContext context)
    {
        string? authorization = context.Request.Headers.Authorization.ToString();
        if (!string.IsNullOrEmpty(authorization))
        {
            return await AuthenticateKeyAsync(authorization, context.RequestAborted).ConfigureAwait(false);
        }

        if (context.Request.Cookies.TryGetValue(_options.SessionCookieName, out string? cookie) && !string.IsNullOrEmpty(cookie))
        {
            return await AuthenticateSessionAsync(context, cookie).ConfigureAwait(false);
        }

        throw ApiException.Unauthorized();
    }

    private async ValueTask<ApiCaller> AuthenticateKeyAsync(string authorization, CancellationToken ct)
    {
        const string scheme = "Bearer ";
        if (!authorization.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
        {
            throw ApiException.Unauthorized("Use the Authorization: Bearer <api key> header.");
        }

        string token = authorization[scheme.Length..].Trim();
        if (!ApiKeys.LooksLikeKey(token))
        {
            throw ApiException.Unauthorized("The API key is not valid.");
        }

        byte[] digest = ApiKeys.Digest(token);
        ApiKeyRecord? key = await Config.FindApiKeyAsync(digest, ct).ConfigureAwait(false);
        if (key is null || key.RevokedAt is not null || !CryptographicOperations.FixedTimeEquals(key.KeyHash, digest))
        {
            throw ApiException.Unauthorized("The API key is not valid.");
        }

        Tenant tenant = await RequireEnabledTenantAsync(key.TenantId, ct).ConfigureAwait(false);
        await TouchKeyAsync(key.Id, ct).ConfigureAwait(false);
        return new ApiCaller
        {
            Kind = CallerKind.ApiKey,
            Name = key.Name,
            Role = DashboardRole.Tenant,
            Tenant = tenant,
            HomeTenantId = tenant.Id,
            Scopes = ApiScopes.Parse(key.Scopes),
            ApiKeyId = key.Id,
        };
    }

    private async ValueTask<ApiCaller> AuthenticateSessionAsync(HttpContext context, string cookie)
    {
        CancellationToken ct = context.RequestAborted;
        byte[] hash = SessionService.HashSecret(cookie);
        DashboardSession? session = await Config.FindDashboardSessionAsync(hash, ct).ConfigureAwait(false);
        DateTimeOffset now = _clock.UtcNow;
        if (session is null || !CryptographicOperations.FixedTimeEquals(session.IdHash, hash) || session.ExpiresAt <= now || now - session.LastSeenAt > _options.SessionIdleTimeout)
        {
            if (session is not null)
            {
                await Config.DeleteDashboardSessionAsync(hash, ct).ConfigureAwait(false);
            }

            throw ApiException.Unauthorized("The session has ended. Sign in again.");
        }

        DashboardUser? user = await Config.GetDashboardUserAsync(session.UserId, ct).ConfigureAwait(false);
        if (user is null || !user.Enabled)
        {
            await Config.DeleteDashboardSessionAsync(hash, ct).ConfigureAwait(false);
            throw ApiException.Unauthorized("The session has ended. Sign in again.");
        }

        if (IsMutation(context.Request.Method) && !CsrfMatches(context, session.CsrfToken))
        {
            throw ApiException.Forbidden($"Missing or invalid {CsrfHeader} header.");
        }

        Tenant? tenant = null;
        if (user.Role == DashboardRole.Tenant)
        {
            tenant = await RequireEnabledTenantAsync(user.TenantId ?? Guid.Empty, ct).ConfigureAwait(false);
        }

        await TouchSessionAsync(session, hash, now, ct).ConfigureAwait(false);
        return new ApiCaller
        {
            Kind = CallerKind.Session,
            Name = user.UserName,
            Role = user.Role,
            Tenant = tenant,
            HomeTenantId = user.TenantId,
            CsrfToken = session.CsrfToken,
            UserId = user.Id,
            SessionHash = hash,
        };
    }

    private async ValueTask<ApiCaller> WithTenantAsync(HttpContext context, ApiCaller identity)
    {
        string? header = context.Request.Headers[TenantHeader].ToString();
        bool hasHeader = !string.IsNullOrWhiteSpace(header);
        if (!identity.IsAdmin)
        {
            if (hasHeader && (!ApiJson.TryParseId(header, out Guid asked) || asked != identity.HomeTenantId))
            {
                throw ApiException.Forbidden("The X-Tenant-Id header does not match your tenant.");
            }

            return identity;
        }

        if (!hasHeader)
        {
            throw ApiException.Validation(TenantHeader, "Admins must send the X-Tenant-Id header for tenant endpoints.");
        }

        if (!ApiJson.TryParseId(header, out Guid tenantId))
        {
            throw ApiException.Validation(TenantHeader, "Not a valid tenant id.");
        }

        Tenant tenant = await Config.GetTenantAsync(tenantId, context.RequestAborted).ConfigureAwait(false) ?? throw ApiException.NotFound("Unknown tenant.");
        return new ApiCaller
        {
            Kind = identity.Kind,
            Name = identity.Name,
            Role = identity.Role,
            Tenant = tenant,
            HomeTenantId = identity.HomeTenantId,
            Scopes = identity.Scopes,
            CsrfToken = identity.CsrfToken,
            ApiKeyId = identity.ApiKeyId,
            UserId = identity.UserId,
            SessionHash = identity.SessionHash,
        };
    }

    private async ValueTask<Tenant> RequireEnabledTenantAsync(Guid tenantId, CancellationToken ct)
    {
        Tenant? tenant = await Config.GetTenantAsync(tenantId, ct).ConfigureAwait(false);
        if (tenant is null)
        {
            throw ApiException.Unauthorized("The account no longer exists.");
        }

        if (!tenant.Enabled)
        {
            throw new ApiException(StatusCodes.Status403Forbidden, ApiCodes.TenantDisabled, "This account is suspended.");
        }

        return tenant;
    }

    internal static bool IsMutation(string method) =>
        !(HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method));

    private static bool CsrfMatches(HttpContext context, string expected)
    {
        string supplied = context.Request.Headers[CsrfHeader].ToString();
        return supplied.Length > 0 && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(supplied), Encoding.UTF8.GetBytes(expected));
    }

    private async ValueTask TouchKeyAsync(Guid keyId, CancellationToken ct)
    {
        long now = _clock.Timestamp;
        long interval = (long)(_options.TouchInterval.TotalSeconds * System.Diagnostics.Stopwatch.Frequency);
        if (_keyTouched.TryGetValue(keyId, out long last) && now - last < interval)
        {
            return;
        }

        _keyTouched[keyId] = now;
        try
        {
            await Config.TouchApiKeyAsync(keyId, _clock.UtcNow, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Last-used is a convenience; a failed write must not fail the request.
            _keyTouched.TryRemove(keyId, out _);
        }
    }

    private async ValueTask TouchSessionAsync(DashboardSession session, byte[] hash, DateTimeOffset now, CancellationToken ct)
    {
        if (now - session.LastSeenAt < _options.TouchInterval)
        {
            return;
        }

        string key = Convert.ToHexString(hash);
        long ticks = _clock.Timestamp;
        long interval = (long)(_options.TouchInterval.TotalSeconds * System.Diagnostics.Stopwatch.Frequency);
        if (_sessionTouched.TryGetValue(key, out long last) && ticks - last < interval)
        {
            return;
        }

        _sessionTouched[key] = ticks;
        if (_sessionTouched.Count > 10_000)
        {
            _sessionTouched.Clear();
        }

        try
        {
            await Config.TouchDashboardSessionAsync(hash, now, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _sessionTouched.TryRemove(key, out _);
        }
    }
}

/// <summary>Sign-in, sign-out and the session cookie.</summary>
public sealed class SessionService
{
    private readonly IStorage _storage;
    private readonly IClock _clock;
    private readonly ApiOptions _options;
    private readonly AuthThrottle _throttle;
    private long _lastPurgeTimestamp;

    public SessionService(IStorage storage, IClock clock, ApiOptions options, AuthThrottle throttle)
    {
        _storage = storage;
        _clock = clock;
        _options = options;
        _throttle = throttle;
    }

    public static byte[] HashSecret(string secret) => SHA256.HashData(Encoding.UTF8.GetBytes(secret));

    /// <summary>Verifies the password, creates a session and sets the cookie. Failed attempts count towards the lockout shared with SMTP AUTH.</summary>
    public async ValueTask<DashboardUser> SignInAsync(HttpContext context, string userName, string password)
    {
        CancellationToken ct = context.RequestAborted;
        string ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        string userKey = "user:" + Mta.Storage.Model.ConfigMapping.NormalizeUserName(userName); // the lookup's normalization: padding cannot buy a fresh budget
        if (_throttle.IsLockedOut(out TimeSpan retryAfter, ip, userKey))
        {
            throw ApiException.RateLimited("Too many failed sign-in attempts. Try again later.", retryAfter);
        }

        IConfigStore config = _storage.Config;
        DashboardUser? user = await config.FindDashboardUserAsync(userName, ct).ConfigureAwait(false);
        bool ok;
        if (user is null)
        {
            PasswordHasher.VerifyDummy(password); // the same work for unknown users: no user enumeration by timing
            ok = false;
        }
        else
        {
            ok = PasswordHasher.Verify(password, user.PasswordHash) && user.Enabled;
        }

        if (ok && user!.Role == DashboardRole.Tenant)
        {
            Tenant? tenant = user.TenantId is { } t ? await config.GetTenantAsync(t, ct).ConfigureAwait(false) : null;
            ok = tenant is { Enabled: true };
        }

        if (!ok)
        {
            _throttle.RecordFailure(ip, userKey);
            throw ApiException.Unauthorized("Invalid user or password.");
        }

        _throttle.RecordSuccess(userKey); // only the user's count: a valid account must not reset the address limit that guards password guessing elsewhere
        if (PasswordHasher.NeedsRehash(user!.PasswordHash))
        {
            // Written through the guarded update so that the stored row is changed, not the copy read above: a concurrent disable, role change or
            // password reset must not be undone by an upgrade of the hash (and an upgrade of a hash that was reset in the meantime is skipped).
            string verifiedHash = user.PasswordHash;
            string upgraded = PasswordHasher.Hash(password);
            await config.UpdateDashboardUserGuardedAsync(user.Id, u => u.PasswordHash == verifiedHash ? u with { PasswordHash = upgraded } : u, endSessions: false, keepSessionHash: null, ct).ConfigureAwait(false);
        }

        // A new sign-in replaces the session the browser presented (no fixation, no accumulation).
        if (context.Request.Cookies.TryGetValue(_options.SessionCookieName, out string? previous) && !string.IsNullOrEmpty(previous))
        {
            await config.DeleteDashboardSessionAsync(HashSecret(previous), ct).ConfigureAwait(false);
        }

        await PurgeExpiredAsync(ct).ConfigureAwait(false);
        DateTimeOffset now = _clock.UtcNow;
        string secret = Base64Url(RandomNumberGenerator.GetBytes(32));
        var session = new DashboardSession(HashSecret(secret), user.Id, Base64Url(RandomNumberGenerator.GetBytes(16)), now, now, now + _options.SessionLifetime);
        await config.AddDashboardSessionAsync(session, ct).ConfigureAwait(false);
        SetCookie(context, secret);
        return user;
    }

    /// <summary>Ends the session the request presented (if any) and clears the cookie.</summary>
    public async ValueTask SignOutAsync(HttpContext context, byte[]? sessionHash)
    {
        if (sessionHash is not null)
        {
            await _storage.Config.DeleteDashboardSessionAsync(sessionHash, context.RequestAborted).ConfigureAwait(false);
        }

        context.Response.Cookies.Delete(_options.SessionCookieName, CookieOptionsFor(context));
    }

    private void SetCookie(HttpContext context, string secret) =>
        context.Response.Cookies.Append(_options.SessionCookieName, secret, CookieOptionsFor(context));

    private CookieOptions CookieOptionsFor(HttpContext context) => new()
    {
        HttpOnly = true,
        SameSite = SameSiteMode.Strict,
        Secure = ShouldBeSecure(context),
        Path = "/",
        IsEssential = true,
    };

    /// <summary>Secure unless this is plain HTTP from a loopback peer (local development).</summary>
    public bool ShouldBeSecure(HttpContext context) => _options.CookieSecure switch
    {
        CookieSecureMode.Always => true,
        CookieSecureMode.Never => false,
        _ => context.Request.IsHttps || !(context.Connection.RemoteIpAddress is null || IPAddress.IsLoopback(context.Connection.RemoteIpAddress)),
    };

    private async ValueTask PurgeExpiredAsync(CancellationToken ct)
    {
        long now = _clock.Timestamp;
        long interval = 10 * 60 * System.Diagnostics.Stopwatch.Frequency;
        long last = Interlocked.Read(ref _lastPurgeTimestamp);
        if ((last != 0 && now - last < interval) || Interlocked.CompareExchange(ref _lastPurgeTimestamp, now, last) != last)
        {
            return;
        }

        await _storage.Config.DeleteExpiredDashboardSessionsAsync(_clock.UtcNow, ct).ConfigureAwait(false);
    }

    internal static string Base64Url(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
