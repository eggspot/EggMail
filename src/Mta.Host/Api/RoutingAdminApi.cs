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

    /// <summary>Must be true to save level <c>none</c> for the pattern <c>*</c> (TLS off for every destination, MTA-STS and DANE not consulted).</summary>
    [JsonPropertyName("acknowledgeInsecure")]
    public bool? AcknowledgeInsecure { get; set; }
}

public sealed class UpdateTlsPolicyRequest
{
    [JsonPropertyName("domainPattern")]
    public string? DomainPattern { get; set; }

    [JsonPropertyName("level")]
    public string? Level { get; set; }

    /// <summary>Must be true when the update makes the policy level <c>none</c> for the pattern <c>*</c>.</summary>
    [JsonPropertyName("acknowledgeInsecure")]
    public bool? AcknowledgeInsecure { get; set; }
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
    IRoutingConfigNotifier? notifier = null,
    IDnsResolver? dns = null)
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

    /// <summary>Both lists, read once per request: the advice about one record depends on the other list.</summary>
    private sealed record Snapshot(IReadOnlyList<RelayRouteRecord> Routes, IReadOnlyList<TlsPolicyRecord> Policies);

    private async Task<Snapshot> LoadAsync(CancellationToken ct) =>
        new(await Config.GetRelayRoutesAsync(ct).ConfigureAwait(false), await Config.GetTlsPoliciesAsync(ct).ConfigureAwait(false));

    private static RelayRouteResponse ToResponse(RelayRouteRecord r, Snapshot snapshot, string? extraWarning = null)
    {
        var warnings = new List<string>();
        string mode = r.TlsMode.ToLowerInvariant();
        bool credentials = !string.IsNullOrEmpty(r.UserName);
        if (credentials && mode is "required" or "starttls")
        {
            warnings.Add("The certificate of this relay is not validated, so the password could be given to an impostor. Use tlsMode verify or implicit.");
        }

        if (mode == "starttls")
        {
            warnings.Add("TLS is only used when the relay offers it, and its certificate is not validated.");
        }
        else if (mode == "none")
        {
            warnings.Add("Mail goes to this relay in plaintext.");
        }

        if (r.Domains.Contains("*"))
        {
            warnings.Add("Matches every recipient domain: this relay is used whenever direct delivery cannot connect.");
        }

        foreach (string d in r.Domains.Where(d => d.StartsWith("*.", StringComparison.Ordinal) && !r.Domains.Contains(d[2..])))
        {
            warnings.Add($"{d} covers the subdomains of {d[2..]} only, not {d[2..]} itself; list {d[2..]} as well to carry it.");
        }

        foreach (TlsPolicyRecord p in snapshot.Policies.Where(p => p.Level is TlsLevel.Encrypt or TlsLevel.Verify && r.Domains.Any(d => PatternsOverlap(d, p.DomainPattern))).Take(3))
        {
            warnings.Add($"The TLS policy for {p.DomainPattern} ({LevelName(p.Level)}) applies to direct delivery only, not to the hop to this relay: mail for these domains is as protected as the connection to this relay and the relay's own onward delivery. The same holds for MTA-STS and DANE of the destination.");
        }

        if (extraWarning is not null)
        {
            warnings.Add(extraWarning);
        }

        return new RelayRouteResponse(r.Id, r.Name, r.Host, r.Port, mode, r.UserName, r.PasswordProtected is { Length: > 0 }, r.Priority, r.Enabled, r.Domains, warnings);
    }

    /// <summary>True when some domain matches both patterns (exact name, <c>*.suffix</c> for every subdomain at any depth, or <c>*</c>).</summary>
    internal static bool PatternsOverlap(string a, string b)
    {
        if (a == "*" || b == "*")
        {
            return true;
        }

        bool aw = a.StartsWith("*.", StringComparison.Ordinal);
        bool bw = b.StartsWith("*.", StringComparison.Ordinal);
        string ah = aw ? a[2..] : a, bh = bw ? b[2..] : b;
        if (!aw && !bw)
        {
            return ah == bh;
        }

        if (aw && bw)
        {
            return ah == bh || ah.EndsWith("." + bh, StringComparison.Ordinal) || bh.EndsWith("." + ah, StringComparison.Ordinal);
        }

        (string exact, string suffix) = aw ? (bh, ah) : (ah, bh);
        return exact.EndsWith("." + suffix, StringComparison.Ordinal);
    }

    private async Task<IResult> ListRoutesAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        Snapshot snapshot = await LoadAsync(context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(snapshot.Routes.Select(r => ToResponse(r, snapshot)).ToList());
    }

    private async Task<IResult> GetRouteAsync(HttpContext context, string id)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        Snapshot snapshot = await LoadAsync(context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(ToResponse(FindRoute(id, snapshot), snapshot));
    }

    private static RelayRouteRecord FindRoute(string id, Snapshot snapshot) =>
        ApiJson.TryParseId(id, out Guid guid) && snapshot.Routes.FirstOrDefault(r => r.Id == guid) is { } route ? route : throw ApiException.NotFound("Relay route not found.");

    private async Task<IResult> CreateRouteAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        CreateRelayRouteRequest body = await ApiJson.ReadBodyAsync<CreateRelayRouteRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        body.UserName = string.IsNullOrWhiteSpace(body.UserName) ? null : body.UserName.Trim();
        Snapshot before = await LoadAsync(ct).ConfigureAwait(false);
        if (before.Routes.Count >= MaxRelayRoutes)
        {
            errors.Add("name", $"At most {MaxRelayRoutes} relay routes.");
        }

        string tlsMode = ValidTlsMode(body.TlsMode ?? "verify", errors);
        string name = ValidName(body.Name, before.Routes, null, errors);
        string host = ValidHost(body.Host, errors);
        int port = ValidPort(body.Port ?? (tlsMode == "implicit" ? 465 : 587), errors);
        int priority = ValidPriority(body.Priority ?? 100, errors);
        var domains = ValidDomains(body.Domains, errors);
        ValidateCredentials(body.UserName, body.Password, hasStoredPassword: false, tlsMode, errors);
        errors.ThrowIfAny();

        byte[]? protectedPassword = body.UserName is null ? null : Protect(body.Password!);
        var route = new RelayRouteRecord(Ids.New(clock.UtcNow), name, host, port, tlsMode, body.UserName, protectedPassword, priority, body.Enabled ?? true, domains);
        await Config.UpsertRelayRouteAsync(route, ct).ConfigureAwait(false);
        Audit(caller, "created", route);
        NotifyChanged();
        string? addressWarning = await PrivateAddressWarningAsync(host, ct).ConfigureAwait(false);
        return ApiResults.Created("/api/v1/admin/relay-routes/" + ApiJson.Id(route.Id), ToResponse(route, await LoadAsync(ct).ConfigureAwait(false), addressWarning));
    }

    private async Task<IResult> UpdateRouteAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        Snapshot before = await LoadAsync(ct).ConfigureAwait(false);
        RelayRouteRecord current = FindRoute(id, before);
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

        string tlsMode = body.TlsMode is null ? current.TlsMode.ToLowerInvariant() : ValidTlsMode(body.TlsMode, errors);
        string name = body.Name is null ? current.Name : ValidName(body.Name, before.Routes, current.Id, errors);
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
                password = string.IsNullOrEmpty(body.Password) ? current.PasswordProtected : Protect(body.Password);
            }
        }
        else if (userName is not null && tlsMode == "none")
        {
            errors.Add("tlsMode", "Not with stored credentials: the password would be sent in plaintext. Remove the credentials first.");
        }

        // A stored password is only ever sent where an administrator who knows it chose to send it: moving the route to another host, port or TLS mode
        // (a weaker one, or an address someone else controls) needs the password typed again, like a changed user name does.
        bool destinationChanged = !string.Equals(host, current.Host, StringComparison.Ordinal) || port != current.Port || !string.Equals(tlsMode, current.TlsMode.ToLowerInvariant(), StringComparison.Ordinal);
        if (!errors.Any && destinationChanged && userName is not null && password is { Length: > 0 } && string.IsNullOrEmpty(body.Password))
        {
            errors.Add("password", "Changing the host, port or TLS mode of a route with a stored login needs the password again (or removeCredentials), so a stored secret is never sent somewhere you did not choose for it.");
        }

        errors.ThrowIfAny();
        var updated = new RelayRouteRecord(current.Id, name, host, port, tlsMode, userName, password, priority, body.Enabled ?? current.Enabled, domains);
        await Config.UpsertRelayRouteAsync(updated, ct).ConfigureAwait(false);
        Audit(caller, "updated", updated);
        NotifyChanged();
        string? addressWarning = string.Equals(host, current.Host, StringComparison.Ordinal) ? null : await PrivateAddressWarningAsync(host, ct).ConfigureAwait(false);
        return ApiResults.Ok(ToResponse(updated, await LoadAsync(ct).ConfigureAwait(false), addressWarning));
    }

    private async Task<IResult> DeleteRouteAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        RelayRouteRecord route = FindRoute(id, await LoadAsync(ct).ConfigureAwait(false));
        await Config.DeleteRelayRouteAsync(route.Id, ct).ConfigureAwait(false);
        Audit(caller, "deleted", route);
        NotifyChanged();
        return ApiResults.NoContent();
    }

    /// <summary>
    /// A relay host that resolves to a loopback or reserved address is not used unless <c>Delivery:AllowPrivateMxAddresses</c> is on: the route would save and never carry mail.
    /// Best effort (a lookup that fails says nothing), and only on create and when the host changes, so listing never queries DNS.
    /// </summary>
    private async Task<string?> PrivateAddressWarningAsync(string host, CancellationToken ct)
    {
        if (dns is null || options.AllowPrivateMxAddresses)
        {
            return null;
        }

        try
        {
            HostAddresses resolved = await new MxResolver(dns, new MxResolverOptions { ExcludeSpecialAddresses = false }).ResolveHostAsync(host, ct).ConfigureAwait(false);
            if (resolved.Addresses.Any(MxResolver.IsSpecialAddress))
            {
                return $"{host} resolves to a loopback or reserved address, which is not used unless Delivery:AllowPrivateMxAddresses is true: this route will not carry mail.";
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Nothing to warn about when the lookup itself failed.
        }

        return null;
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
        // The delivery engine looks the relay up in DNS, so an address is not a host here ("1" and "127.1" are addresses to IPAddress too).
        string bare = host.Trim('[', ']').TrimEnd('.');
        if (IPAddress.TryParse(bare, out _) || bare.Contains(':') || (bare.Length > 0 && bare.Split('.')[^1].All(char.IsAsciiDigit)))
        {
            errors.Add("host", "Use a host name such as smtp.relay.example, not an IP address: the address is looked up in DNS.");
            return host;
        }

        if (host.Length == 0 || host.Contains('*') || !DnsName.TryNormalize(host, out string? normalized) || normalized.Length == 0 || !HostPattern().IsMatch(normalized))
        {
            errors.Add("host", "Enter a host name such as smtp.relay.example.");
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
                errors.Add($"domains[{i}]", "Use a domain name, \"*.suffix\" for every subdomain at any depth (not the domain itself), or \"*\" for every domain.");
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
    }

    private void NotifyChanged() => notifier?.Changed();

    // TLS policies

    private static TlsPolicyResponse ToResponse(TlsPolicyRecord p, Snapshot snapshot)
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

        if (p.DomainPattern.StartsWith("*.", StringComparison.Ordinal) && snapshot.Policies.All(o => o.DomainPattern != p.DomainPattern[2..]))
        {
            warnings.Add($"{p.DomainPattern} covers the subdomains of {p.DomainPattern[2..]} only, not {p.DomainPattern[2..]} itself, which has no policy of its own; add one for it too.");
        }

        if (p.Level is TlsLevel.Encrypt or TlsLevel.Verify)
        {
            foreach (RelayRouteRecord r in snapshot.Routes.Where(r => r.Enabled && r.Domains.Any(d => PatternsOverlap(d, p.DomainPattern))).Take(3))
            {
                warnings.Add($"The relay route {r.Name} carries mail for some of these destinations: this level applies to direct delivery only, not to the hop to the relay.");
            }
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
        Snapshot snapshot = await LoadAsync(context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(snapshot.Policies.Select(p => ToResponse(p, snapshot)).ToList());
    }

    private static TlsPolicyRecord FindPolicy(string id, Snapshot snapshot) =>
        ApiJson.TryParseId(id, out Guid guid) && snapshot.Policies.FirstOrDefault(p => p.Id == guid) is { } policy ? policy : throw ApiException.NotFound("TLS policy not found.");

    private async Task<IResult> GetPolicyAsync(HttpContext context, string id)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        Snapshot snapshot = await LoadAsync(context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(ToResponse(FindPolicy(id, snapshot), snapshot));
    }

    private async Task<IResult> CreatePolicyAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        CreateTlsPolicyRequest body = await ApiJson.ReadBodyAsync<CreateTlsPolicyRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        Snapshot before = await LoadAsync(ct).ConfigureAwait(false);
        if (before.Policies.Count >= MaxTlsPolicies)
        {
            errors.Add("domainPattern", $"At most {MaxTlsPolicies} TLS policies.");
        }

        string pattern = ValidPolicyPattern(body.DomainPattern, before.Policies, null, errors);
        TlsLevel level = ValidLevel(body.Level, errors);
        RequireAcknowledgement(pattern, level, body.AcknowledgeInsecure, errors);
        errors.ThrowIfAny();

        var policy = new TlsPolicyRecord(Ids.New(clock.UtcNow), pattern, level);
        await SavePolicyAsync(policy, ct).ConfigureAwait(false);
        Audit(caller, "created", policy);
        NotifyChanged();
        return ApiResults.Created("/api/v1/admin/tls-policies/" + ApiJson.Id(policy.Id), ToResponse(policy, await LoadAsync(ct).ConfigureAwait(false)));
    }

    private async Task<IResult> UpdatePolicyAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        Snapshot before = await LoadAsync(ct).ConfigureAwait(false);
        TlsPolicyRecord current = FindPolicy(id, before);
        UpdateTlsPolicyRequest body = await ApiJson.ReadBodyAsync<UpdateTlsPolicyRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        string pattern = body.DomainPattern is null ? current.DomainPattern : ValidPolicyPattern(body.DomainPattern, before.Policies, current.Id, errors);
        TlsLevel level = body.Level is null ? current.Level : ValidLevel(body.Level, errors);
        if (body.DomainPattern is not null || body.Level is not null)
        {
            RequireAcknowledgement(pattern, level, body.AcknowledgeInsecure, errors);
        }

        errors.ThrowIfAny();

        var updated = new TlsPolicyRecord(current.Id, pattern, level);
        await SavePolicyAsync(updated, ct).ConfigureAwait(false);
        Audit(caller, "updated", updated);
        NotifyChanged();
        return ApiResults.Ok(ToResponse(updated, await LoadAsync(ct).ConfigureAwait(false)));
    }

    private async Task<IResult> DeletePolicyAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        TlsPolicyRecord policy = FindPolicy(id, await LoadAsync(ct).ConfigureAwait(false));
        await Config.DeleteTlsPolicyAsync(policy.Id, ct).ConfigureAwait(false);
        Audit(caller, "deleted", policy);
        NotifyChanged();
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
            errors.Add("domainPattern", "Use a domain name, \"*.suffix\" for every subdomain at any depth (not the domain itself), or \"*\" for every destination.");
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
        switch (value?.Trim().ToLowerInvariant())
        {
            case "none": return TlsLevel.None;
            case "may": return TlsLevel.May;
            case "encrypt": return TlsLevel.Encrypt;
            case "verify": return TlsLevel.Verify;
            default:
                errors.Add("level", "Must be one of: " + string.Join(", ", TlsLevels) + ".");
                return TlsLevel.May;
        }
    }

    /// <summary>Level none for every destination switches TLS, MTA-STS and DANE off server-wide: it is only saved when the request says it was meant.</summary>
    private static void RequireAcknowledgement(string pattern, TlsLevel level, bool? acknowledged, ValidationErrors errors)
    {
        if (pattern == "*" && level == TlsLevel.None && acknowledged != true)
        {
            errors.Add("acknowledgeInsecure", "Level none for \"*\" turns TLS off for every destination and skips MTA-STS and DANE: set acknowledgeInsecure to true if that is meant.");
        }
    }

    private void Audit(ApiCaller caller, string action, TlsPolicyRecord p)
    {
        // Turning TLS off is logged where an operator looks for problems.
        logger.Log(
            p.Level == TlsLevel.None && action != "deleted" ? LogLevel.Warning : LogLevel.Information,
            "TLS policy {DomainPattern} ({PolicyId}) {Action} by {Actor}: level {Level}",
            p.DomainPattern, ApiJson.Id(p.Id), action, caller.Name, LevelName(p.Level));
    }
}
