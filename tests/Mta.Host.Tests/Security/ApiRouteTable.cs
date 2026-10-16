using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.DependencyInjection;
using Mta.Host.Api;
using Mta.Host.Tests.Api;

namespace Mta.Host.Tests.Security;

/// <summary>Who may call an endpoint. Every API route must be listed in <see cref="ApiRouteTable.Classify"/>: a new endpoint without a decision fails the matrix tests.</summary>
internal enum AccessPolicy
{
    /// <summary>No credentials needed (sign-in, sign-out, capabilities).</summary>
    Public,

    /// <summary>Any signed-in dashboard user or API key, no tenant needed.</summary>
    AnyCaller,

    /// <summary>A signed-in dashboard user only (API keys never).</summary>
    SessionOnly,

    /// <summary>The admin role (API keys are never admin).</summary>
    Admin,

    /// <summary>A tenant caller; an API key needs <see cref="ApiRoute.Scope"/>.</summary>
    TenantScoped,

    /// <summary>A tenant caller, API keys allowed to read only (settings) and sessions to change.</summary>
    TenantSessionForWrites,
}

internal sealed record ApiRoute(string Method, string Pattern, AccessPolicy Policy, string? Scope)
{
    /// <summary>A second scope the route needs besides <see cref="Scope"/> (creating an SMTP credential also needs <c>send</c>).</summary>
    public string? AlsoNeeds => Method == "POST" && Pattern.EndsWith("/smtp-credentials", StringComparison.Ordinal) ? ApiScopes.Send : null;

    public bool Mutates => Method != "GET";

    /// <summary>The pattern with every route parameter replaced by a well-formed value.</summary>
    public string Fill(string id, string address = "someone@example.org") => Resolved(Pattern, id, address);

    private static string Resolved(string pattern, string id, string address)
    {
        string path = pattern;
        foreach (var name in new[] { "{id}", "{outboxId}" }) { path = path.Replace(name, id, StringComparison.Ordinal); }
        return path.Replace("{address}", Uri.EscapeDataString(address), StringComparison.Ordinal);
    }

    public override string ToString() => $"{Method} {Pattern}";
}

internal static class ApiRouteTable
{
    /// <summary>Every <c>/api/v1</c> route of the running server (read from the endpoint table, so a route added later is included automatically).</summary>
    public static IReadOnlyList<ApiRoute> Of(ApiFixture fixture)
    {
        var routes = new List<ApiRoute>();
        foreach (EndpointDataSource source in fixture.Services.GetServices<EndpointDataSource>())
        {
            foreach (Endpoint endpoint in source.Endpoints)
            {
                if (endpoint is not RouteEndpoint route || route.RoutePattern.RawText is not { } raw || !raw.StartsWith("/api/v1", StringComparison.Ordinal) || raw.Contains("{**", StringComparison.Ordinal))
                {
                    continue;
                }

                string pattern = raw.TrimEnd('/');
                foreach (string method in route.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? [])
                {
                    var (policy, scope) = Classify(method, pattern);
                    routes.Add(new ApiRoute(method, pattern, policy, scope));
                }
            }
        }

        return routes.DistinctBy(r => r.ToString()).OrderBy(r => r.Pattern, StringComparer.Ordinal).ThenBy(r => r.Method, StringComparer.Ordinal).ToList();
    }

    /// <summary>
    /// The security decision for each route, written down independently of the handlers (from docs/api.md): the matrix tests check the server against it.
    /// </summary>
    private static (AccessPolicy Policy, string? Scope) Classify(string method, string pattern)
    {
        string p = pattern["/api/v1".Length..];
        if (p == "/session" && method == "POST") { return (AccessPolicy.Public, null); }
        if (p == "/capabilities") { return (AccessPolicy.Public, null); }
        if (p == "/session" && method == "DELETE") { return (AccessPolicy.Public, null); }   // sign-out is idempotent: no session, nothing to end, 204
        if (p == "/me") { return (AccessPolicy.AnyCaller, null); }
        if (p == "/me/password") { return (AccessPolicy.SessionOnly, null); }
        if (p.StartsWith("/admin", StringComparison.Ordinal)) { return (AccessPolicy.Admin, null); }
        if (p == "/messages" && method == "POST") { return (AccessPolicy.TenantScoped, ApiScopes.Send); }
        if (p == "/messages/raw") { return (AccessPolicy.TenantScoped, ApiScopes.Send); }
        if (p.StartsWith("/messages", StringComparison.Ordinal))
        {
            return (AccessPolicy.TenantScoped, p.EndsWith("/resend", StringComparison.Ordinal) || p.EndsWith("/cancel", StringComparison.Ordinal) ? ApiScopes.Send : ApiScopes.Read);
        }

        if (p.StartsWith("/stats", StringComparison.Ordinal)) { return (AccessPolicy.TenantScoped, ApiScopes.Read); }
        if (p == "/settings") { return method == "GET" ? (AccessPolicy.TenantScoped, ApiScopes.Read) : (AccessPolicy.TenantSessionForWrites, null); }
        // Received mail (decision 95): reading needs inbound:read, every change (settings, routes, delete, erase, retry) inbound:write.
        if (p.StartsWith("/inbound", StringComparison.Ordinal) || (p.StartsWith("/domains/", StringComparison.Ordinal) && p.Contains("/inbound", StringComparison.Ordinal)))
        {
            return (AccessPolicy.TenantScoped, method == "GET" ? ApiScopes.InboundRead : ApiScopes.InboundWrite);
        }

        if (p.StartsWith("/domains", StringComparison.Ordinal)) { return (AccessPolicy.TenantScoped, ApiScopes.Domains); }
        if (p.StartsWith("/webhook", StringComparison.Ordinal)) { return (AccessPolicy.TenantScoped, ApiScopes.Webhooks); }
        if (p.StartsWith("/suppressions", StringComparison.Ordinal)) { return (AccessPolicy.TenantScoped, ApiScopes.Suppressions); }
        if (p.StartsWith("/api-keys", StringComparison.Ordinal) || p.StartsWith("/smtp-credentials", StringComparison.Ordinal)) { return (AccessPolicy.TenantScoped, ApiScopes.Keys); }

        throw new InvalidOperationException($"{method} {pattern} has no security classification: decide who may call it and add it to ApiRouteTable.Classify (and to docs/security-test-map.md).");
    }
}
