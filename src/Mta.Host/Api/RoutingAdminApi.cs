using System.Net;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Mta.Core;
using Mta.Dns;
using Mta.Policy;
using Mta.Storage;

namespace Mta.Host.Api;

/// <summary>
/// Told when an administrator changed the relay routes or the per-domain TLS policies, so the delivery engine of this process can reload them at once
/// instead of at its next refresh interval. Other replicas still pick the change up within <c>ConfigRefreshInterval</c>. The default is "nobody listens".
/// </summary>
public interface IRoutingConfigNotifier
{
    void Changed();
}

public sealed class CreateRelayRouteRequest
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("host")]
    public string? Host { get; set; }

    [JsonPropertyName("port")]
    public int? Port { get; set; }

    /// <summary><c>none</c>, <c>starttls</c>, <c>required</c>, <c>verify</c> (default) or <c>implicit</c>.</summary>
    [JsonPropertyName("tlsMode")]
    public string? TlsMode { get; set; }

    [JsonPropertyName("userName")]
    public string? UserName { get; set; }

    [JsonPropertyName("password")]
    public string? Password { get; set; }

    [JsonPropertyName("priority")]
    public int? Priority { get; set; }

    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("domains")]
    public List<string>? Domains { get; set; }
}

public sealed class UpdateRelayRouteRequest
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("host")]
    public string? Host { get; set; }

    [JsonPropertyName("port")]
    public int? Port { get; set; }

    [JsonPropertyName("tlsMode")]
    public string? TlsMode { get; set; }

    [JsonPropertyName("userName")]
    public string? UserName { get; set; }

    [JsonPropertyName("password")]
    public string? Password { get; set; }

    /// <summary>True removes the stored user name and password.</summary>
    [JsonPropertyName("removeCredentials")]
    public bool? RemoveCredentials { get; set; }

    [JsonPropertyName("priority")]
    public int? Priority { get; set; }

    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("domains")]
    public List<string>? Domains { get; set; }
}

/// <summary>A relay route as the API shows it. The password is never part of it: <see cref="HasPassword"/> says whether one is stored.</summary>
public sealed record RelayRouteResponse(
    Guid Id,
    string Name,
    string Host,
    int Port,
    string TlsMode,
    string? UserName,
    bool HasPassword,
    int Priority,
    bool Enabled,
    IReadOnlyList<string> Domains,
    IReadOnlyList<string> Warnings);

public sealed class CreateTlsPolicyRequest
{
    [JsonPropertyName("domainPattern")]
    public string? DomainPattern { get; set; }

    /// <summary><c>none</c>, <c>may</c>, <c>encrypt</c> or <c>verify</c>.</summary>
    [JsonPropertyName("level")]
    public string? Level { get; set; }
}

public sealed class UpdateTlsPolicyRequest
{
    [JsonPropertyName("domainPattern")]
    public string? DomainPattern { get; set; }

    [JsonPropertyName("level")]
    public string? Level { get; set; }
}

public sealed record TlsPolicyResponse(Guid Id, string DomainPattern, string Level, IReadOnlyList<string> Warnings);

/// <summary>
/// Relay routes (design 7.2) and per-domain outbound TLS policies (design 7.3). Both are server-wide records of the config store without a tenant (a relay
/// changes the sending IP of every tenant whose recipients it carries), so only the admin role reaches them. The delivery engine reloads them every
/// <c>ConfigRefreshInterval</c> and, in the process that served the request, immediately (<see cref="IRoutingConfigNotifier"/>).
/// <para>There is no audit table: every change is written to the log as a structured line (who, what, never a secret).</para>
/// </summary>
public sealed partial class RoutingAdminApi(
    ApiAuthenticator auth,
    IStorage storage,
    ApiOptions options,
    IClock clock,
    ISecretProtector protector,
    ILogger<RoutingAdminApi> logger,
    IRoutingConfigNotifier? notifier = null)
{
    public const int MaxRelayRoutes = 50;
    public const int MaxTlsPolicies = 500;
    public const int MaxDomainsPerRoute = 100;
    public const int MaxPasswordLength = 512;

    private static readonly string[] TlsModes = ["none", "starttls", "required", "verify", "implicit"];
    private static readonly string[] TlsLevels = ["none", "may", "encrypt", "verify"];

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
    private static partial Regex NamePattern();

    [GeneratedRegex("^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$")]
    private static partial Regex HostPattern();

    private IConfigStore Config => storage.Config;

    public void Map(RouteGroupBuilder api)
    {
        var admin = api.MapGroup("/admin");
        admin.GetRoute("/relay-routes", ListRoutesAsync);
        admin.PostRoute("/relay-routes", CreateRouteAsync);
        admin.GetRoute("/relay-routes/{id}", GetRouteAsync);
        admin.PatchRoute("/relay-routes/{id}", UpdateRouteAsync);
        admin.DeleteRoute("/relay-routes/{id}", DeleteRouteAsync);
        admin.GetRoute("/tls-policies", ListPoliciesAsync);
        admin.PostRoute("/tls-policies", CreatePolicyAsync);
        admin.GetRoute("/tls-policies/{id}", GetPolicyAsync);
        admin.PatchRoute("/tls-policies/{id}", UpdatePolicyAsync);
        admin.DeleteRoute("/tls-policies/{id}", DeletePolicyAsync);
    }

    // Relay routes

    private static RelayRouteResponse ToResponse(RelayRouteRecord r)
    {
        var warnings = new List<string>();
        string mode = r.TlsMode.ToLowerInvariant();
        bool credentials = !string.IsNullOrEmpty(r.UserName);
        if (mode is "required" && credentials)
        {
            warnings.Add("The certificate of this relay is not validated, so the password could be given to an impostor. Use tlsMode verify or implicit.");
        }

        if (mode is "starttls" or "none")
        {
            warnings.Add(mode == "none" ? "Mail goes to this relay in plaintext." : "TLS is only used when the relay offers it, and its certificate is not validated.");
        }

        if (r.Domains.Contains("*"))
        {
            warnings.Add("Matches every recipient domain: this relay is used whenever direct delivery cannot connect.");
        }

        return new RelayRouteResponse(r.Id, r.Name, r.Host, r.Port, mode, r.UserName, r.PasswordProtected is { Length: > 0 }, r.Priority, r.Enabled, r.Domains, warnings);
    }

    private async Task<IResult> ListRoutesAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        return ApiResults.Ok((await Config.GetRelayRoutesAsync(context.RequestAborted).ConfigureAwait(false)).Select(ToResponse).ToList());
    }

    private async Task<IResult> GetRouteAsync(HttpContext context, string id)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        return ApiResults.Ok(ToResponse(await FindRouteAsync(id, context.RequestAborted).ConfigureAwait(false)));
    }

    private async Task<RelayRouteRecord> FindRouteAsync(string id, CancellationToken ct)
    {
        if (ApiJson.TryParseId(id, out Guid guid) && (await Config.GetRelayRoutesAsync(ct).ConfigureAwait(false)).FirstOrDefault(r => r.Id == guid) is { } route)
        {
            return route;
        }

        throw ApiException.NotFound("Relay route not found.");
    }

    private async Task<IResult> CreateRouteAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        CreateRelayRouteRequest body = await ApiJson.ReadBodyAsync<CreateRelayRouteRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        body.UserName = string.IsNullOrWhiteSpace(body.UserName) ? null : body.UserName.Trim();
        var existing = await Config.GetRelayRoutesAsync(ct).ConfigureAwait(false);
        if (existing.Count >= MaxRelayRoutes)
        {
            errors.Add("name", $"At most {MaxRelayRoutes} relay routes.");
        }

        string tlsMode = ValidTlsMode(body.TlsMode ?? "verify", errors);
        string name = ValidName(body.Name, existing, null, errors);
        string host = ValidHost(body.Host, errors);
        int port = ValidPort(body.Port ?? (tlsMode == "implicit" ? 465 : 587), errors);
        int priority = ValidPriority(body.Priority ?? 100, errors);
        var domains = ValidDomains(body.Domains, errors);
        ValidateCredentials(body.UserName, body.Password, hasStoredPassword: false, tlsMode, errors);
        errors.ThrowIfAny();

        byte[]? protectedPassword = string.IsNullOrEmpty(body.UserName) ? null : Protect(body.Password!);
        var route = new RelayRouteRecord(Ids.New(clock.UtcNow), name, host, port, tlsMode, string.IsNullOrEmpty(body.UserName) ? null : body.UserName, protectedPassword, priority, body.Enabled ?? true, domains);
        await Config.UpsertRelayRouteAsync(route, ct).ConfigureAwait(false);
        Audit(caller, "created", route);
        return ApiResults.Created("/api/v1/admin/relay-routes/" + ApiJson.Id(route.Id), ToResponse(route));
    }

    private async Task<IResult> UpdateRouteAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        RelayRouteRecord current = await FindRouteAsync(id, ct).ConfigureAwait(false);
        UpdateRelayRouteRequest body = await ApiJson.ReadBodyAsync<UpdateRelayRouteRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        if (body.UserName is not null)
        {
            body.UserName = body.UserName.Trim();
            if (body.UserName.Length == 0)
            {
                errors.Add("userName", "Cannot be empty; use removeCredentials to remove the credentials.");
                body.UserName = null;
            }
        }

        var existing = await Config.GetRelayRoutesAsync(ct).ConfigureAwait(false);

        string tlsMode = body.TlsMode is null ? current.TlsMode.ToLowerInvariant() : ValidTlsMode(body.TlsMode, errors);
        string name = body.Name is null ? current.Name : ValidName(body.Name, existing, current.Id, errors);
        string host = body.Host is null ? current.Host : ValidHost(body.Host, errors);
        int port = body.Port is null ? current.Port : ValidPort(body.Port.Value, errors);
        int priority = body.Priority is null ? current.Priority : ValidPriority(body.Priority.Value, errors);
        var domains = body.Domains is null ? current.Domains : ValidDomains(body.Domains, errors);

        string? userName = current.UserName;
        byte[]? password = current.PasswordProtected;
        if (body.RemoveCredentials == true)
        {
            if (body.UserName is not null || body.Password is not null)
            {
                errors.Add("removeCredentials", "Cannot be combined with userName or password.");
            }

            userName = null;
            password = null;
        }
        else if (body.UserName is not null || body.Password is not null)
        {
            bool hadPassword = current.PasswordProtected is { Length: > 0 };
            string? newUser = body.UserName ?? current.UserName;
            // Keeping the stored password is only allowed when the user name stays the same: a password belongs to its user.
            bool userChanged = body.UserName is not null && !string.Equals(body.UserName, current.UserName, StringComparison.Ordinal);
            ValidateCredentials(newUser, body.Password, hasStoredPassword: hadPassword && !userChanged, tlsMode, errors);
            if (!errors.Any)
            {
                userName = newUser;
                password = body.Password is null ? current.PasswordProtected : Protect(body.Password);
            }
        }
        else if (userName is not null && tlsMode == "none")
        {
            errors.Add("tlsMode", "Not with stored credentials: the password would be sent in plaintext. Remove the credentials first.");
        }

        errors.ThrowIfAny();
        var updated = new RelayRouteRecord(current.Id, name, host, port, tlsMode, userName, password, priority, body.Enabled ?? current.Enabled, domains);
        await Config.UpsertRelayRouteAsync(updated, ct).ConfigureAwait(false);
        Audit(caller, "updated", updated);
        return ApiResults.Ok(ToResponse(updated));
    }

    private async Task<IResult> DeleteRouteAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        RelayRouteRecord route = await FindRouteAsync(id, ct).ConfigureAwait(false);
        await Config.DeleteRelayRouteAsync(route.Id, ct).ConfigureAwait(false);
        Audit(caller, "deleted", route);
        return ApiResults.NoContent();
    }

    private byte[] Protect(string password) =>
        protector.Protect(System.Text.Encoding.UTF8.GetBytes(password), SecretPurposes.RelayPassword);

    private static string ValidTlsMode(string value, ValidationErrors errors)
    {
        string mode = value.Trim().ToLowerInvariant();
        if (!TlsModes.Contains(mode))
        {
            errors.Add("tlsMode", "Must be one of: " + string.Join(", ", TlsModes) + ".");
        }

        return mode;
    }

    private static string ValidName(string? value, IReadOnlyList<RelayRouteRecord> existing, Guid? self, ValidationErrors errors)
    {
        string name = value?.Trim() ?? "";
        if (!NamePattern().IsMatch(name))
        {
            errors.Add("name", "Use 1 to 64 letters, digits, dot, dash or underscore, starting with a letter or digit.");
        }
        else if (string.Equals(name, RoutePlanner.DirectRouteName, StringComparison.OrdinalIgnoreCase))
        {
            errors.Add("name", $"\"{RoutePlanner.DirectRouteName}\" is the name of direct delivery.");
        }
        else if (existing.Any(r => r.Id != self && string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase)))
        {
            errors.Add("name", "A relay route with this name already exists.");
        }

        return name;
    }

    private static string ValidHost(string? value, ValidationErrors errors)
    {
        string host = value?.Trim() ?? "";
        if (IPAddress.TryParse(host.Trim('[', ']'), out IPAddress? ip))
        {
            return ip.ToString();
        }

        if (host.Length == 0 || host.Contains('*') || !DnsName.TryNormalize(host, out string? normalized) || normalized.Length == 0 || !HostPattern().IsMatch(normalized))
        {
            errors.Add("host", "Enter a host name such as smtp.relay.example, or an IP address.");
            return host;
        }

        return normalized;
    }

    private static int ValidPort(int port, ValidationErrors errors)
    {
        if (port is < 1 or > 65535)
        {
            errors.Add("port", "Must be between 1 and 65535.");
        }

        return port;
    }

    private static int ValidPriority(int priority, ValidationErrors errors)
    {
        if (priority is < 0 or > 1000)
        {
            errors.Add("priority", "Must be between 0 and 1000 (lower numbers are tried first).");
        }

        return priority;
    }

    private static List<string> ValidDomains(List<string>? domains, ValidationErrors errors)
    {
        var result = new List<string>();
        if (domains is null || domains.Count == 0)
        {
            errors.Add("domains", "Name at least one recipient domain: a relay is only used for the domains it lists. Use \"*\" for all of them.");
            return result;
        }

        if (domains.Count > MaxDomainsPerRoute)
        {
            errors.Add("domains", $"At most {MaxDomainsPerRoute} domains per route.");
            return result;
        }

        for (int i = 0; i < domains.Count; i++)
        {
            if (TryNormalizePattern(domains[i], out string pattern))
            {
                if (!result.Contains(pattern))
                {
                    result.Add(pattern);
                }
            }
            else
            {
                errors.Add($"domains[{i}]", "Use a domain name, \"*.suffix\" for a domain and everything below it, or \"*\" for every domain.");
            }
        }

        return result;
    }

    /// <summary>Normalizes an exact domain, <c>*.suffix</c> or <c>*</c> (lower case, A-labels, no trailing dot).</summary>
    internal static bool TryNormalizePattern(string? value, out string pattern)
    {
        pattern = "";
        string v = value?.Trim() ?? "";
        if (v == "*")
        {
            pattern = "*";
            return true;
        }

        string prefix = "";
        if (v.StartsWith("*.", StringComparison.Ordinal))
        {
            prefix = "*.";
            v = v[2..];
        }

        if (v.Length == 0 || v.Contains('*') || IPAddress.TryParse(v, out _) || !DnsName.TryNormalize(v, out string? normalized) || normalized.Length == 0 || !HostPattern().IsMatch(normalized))
        {
            return false;
        }

        pattern = prefix + normalized;
        return true;
    }

    private static void ValidateCredentials(string? userName, string? password, bool hasStoredPassword, string tlsMode, ValidationErrors errors)
    {
        bool hasUser = !string.IsNullOrEmpty(userName);
        if (!hasUser && string.IsNullOrEmpty(password))
        {
            return;
        }

        if (!hasUser)
        {
            errors.Add("userName", "A password needs a user name.");
            return;
        }

        if (userName!.Length > 255 || userName.Any(char.IsControl))
        {
            errors.Add("userName", "Use at most 255 characters without control characters.");
        }

        if (string.IsNullOrEmpty(password))
        {
            if (!hasStoredPassword)
            {
                errors.Add("password", "A password is required with a user name.");
            }
        }
        else if (password.Length > MaxPasswordLength || password.Any(c => c is '\r' or '\n' or '\0'))
        {
            errors.Add("password", $"Use at most {MaxPasswordLength} characters, without line breaks.");
        }

        if (tlsMode == "none")
        {
            errors.Add("tlsMode", "Credentials need TLS: with tlsMode none the password would be sent in plaintext.");
        }
    }

    private void Audit(ApiCaller caller, string action, RelayRouteRecord r)
    {
        // Never the password, only whether there is one.
        logger.LogInformation(
            "Relay route {RouteName} ({RouteId}) {Action} by {Actor}: host {Host}:{Port}, tlsMode {TlsMode}, user {UserName}, password {PasswordState}, priority {Priority}, enabled {Enabled}, domains {Domains}",
            r.Name, ApiJson.Id(r.Id), action, caller.Name, r.Host, r.Port, r.TlsMode, r.UserName ?? "(none)", r.PasswordProtected is { Length: > 0 } ? "set" : "none", r.Priority, r.Enabled, string.Join(',', r.Domains));
        notifier?.Changed();
    }

    // TLS policies

    private static TlsPolicyResponse ToResponse(TlsPolicyRecord p)
    {
        var warnings = new List<string>();
        if (p.Level == TlsLevel.None)
        {
            warnings.Add("Level none turns TLS off for these destinations and MTA-STS and DANE are not consulted: mail can go in plaintext even where the destination publishes an enforcing policy.");
        }

        if (p.DomainPattern == "*" && p.Level is TlsLevel.Encrypt or TlsLevel.Verify)
        {
            warnings.Add(p.Level == TlsLevel.Verify
                ? "Applies to every destination: mail to servers without STARTTLS or without a valid certificate for their MX name is deferred and eventually bounces."
                : "Applies to every destination: mail to servers without STARTTLS is deferred and eventually bounces.");
        }

        return new TlsPolicyResponse(p.Id, p.DomainPattern, LevelName(p.Level), warnings);
    }

    internal static string LevelName(TlsLevel level) => level switch
    {
        TlsLevel.None => "none",
        TlsLevel.May => "may",
        TlsLevel.Encrypt => "encrypt",
        _ => "verify",
    };

    private async Task<IResult> ListPoliciesAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        return ApiResults.Ok((await Config.GetTlsPoliciesAsync(context.RequestAborted).ConfigureAwait(false)).Select(ToResponse).ToList());
    }

    private async Task<TlsPolicyRecord> FindPolicyAsync(string id, CancellationToken ct)
    {
        if (ApiJson.TryParseId(id, out Guid guid) && (await Config.GetTlsPoliciesAsync(ct).ConfigureAwait(false)).FirstOrDefault(p => p.Id == guid) is { } policy)
        {
            return policy;
        }

        throw ApiException.NotFound("TLS policy not found.");
    }

    private async Task<IResult> GetPolicyAsync(HttpContext context, string id)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        return ApiResults.Ok(ToResponse(await FindPolicyAsync(id, context.RequestAborted).ConfigureAwait(false)));
    }

    private async Task<IResult> CreatePolicyAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        CreateTlsPolicyRequest body = await ApiJson.ReadBodyAsync<CreateTlsPolicyRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        var existing = await Config.GetTlsPoliciesAsync(ct).ConfigureAwait(false);
        if (existing.Count >= MaxTlsPolicies)
        {
            errors.Add("domainPattern", $"At most {MaxTlsPolicies} TLS policies.");
        }

        string pattern = ValidPolicyPattern(body.DomainPattern, existing, null, errors);
        TlsLevel level = ValidLevel(body.Level, errors);
        errors.ThrowIfAny();

        var policy = new TlsPolicyRecord(Ids.New(clock.UtcNow), pattern, level);
        await SavePolicyAsync(policy, ct).ConfigureAwait(false);
        Audit(caller, "created", policy);
        return ApiResults.Created("/api/v1/admin/tls-policies/" + ApiJson.Id(policy.Id), ToResponse(policy));
    }

    private async Task<IResult> UpdatePolicyAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        TlsPolicyRecord current = await FindPolicyAsync(id, ct).ConfigureAwait(false);
        UpdateTlsPolicyRequest body = await ApiJson.ReadBodyAsync<UpdateTlsPolicyRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        var existing = await Config.GetTlsPoliciesAsync(ct).ConfigureAwait(false);
        string pattern = body.DomainPattern is null ? current.DomainPattern : ValidPolicyPattern(body.DomainPattern, existing, current.Id, errors);
        TlsLevel level = body.Level is null ? current.Level : ValidLevel(body.Level, errors);
        errors.ThrowIfAny();

        var updated = new TlsPolicyRecord(current.Id, pattern, level);
        await SavePolicyAsync(updated, ct).ConfigureAwait(false);
        Audit(caller, "updated", updated);
        return ApiResults.Ok(ToResponse(updated));
    }

    private async Task<IResult> DeletePolicyAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        TlsPolicyRecord policy = await FindPolicyAsync(id, ct).ConfigureAwait(false);
        await Config.DeleteTlsPolicyAsync(policy.Id, ct).ConfigureAwait(false);
        Audit(caller, "deleted", policy);
        return ApiResults.NoContent();
    }

    private async Task SavePolicyAsync(TlsPolicyRecord policy, CancellationToken ct)
    {
        try
        {
            await Config.UpsertTlsPolicyAsync(policy, ct).ConfigureAwait(false);
        }
        catch (StorageConflictException)
        {
            // A concurrent request took the same pattern between the check and the write (the store has a unique index on it).
            throw ApiException.Validation("domainPattern", "A policy for this pattern already exists.");
        }
    }

    private static string ValidPolicyPattern(string? value, IReadOnlyList<TlsPolicyRecord> existing, Guid? self, ValidationErrors errors)
    {
        if (!TryNormalizePattern(value, out string pattern))
        {
            errors.Add("domainPattern", "Use a domain name, \"*.suffix\" for a domain and everything below it, or \"*\" for every destination.");
            return value ?? "";
        }

        if (existing.Any(p => p.Id != self && p.DomainPattern == pattern))
        {
            errors.Add("domainPattern", "A policy for this pattern already exists.");
        }

        return pattern;
    }

    private static TlsLevel ValidLevel(string? value, ValidationErrors errors)
    {
        string level = value?.Trim().ToLowerInvariant() ?? "";
        int index = Array.IndexOf(TlsLevels, level);
        if (index < 0)
        {
            errors.Add("level", "Must be one of: " + string.Join(", ", TlsLevels) + ".");
            return TlsLevel.May;
        }

        return (TlsLevel)index;
    }

    private void Audit(ApiCaller caller, string action, TlsPolicyRecord p)
    {
        logger.LogInformation("TLS policy {DomainPattern} ({PolicyId}) {Action} by {Actor}: level {Level}", p.DomainPattern, ApiJson.Id(p.Id), action, caller.Name, LevelName(p.Level));
        notifier?.Changed();
    }
}
