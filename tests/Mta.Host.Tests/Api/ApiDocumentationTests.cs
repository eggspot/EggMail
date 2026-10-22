using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Mta.Host.Tests.Api;

/// <summary>
/// The route index in docs/api.md and the routes the server maps must be the same set (gap G15 of the plan-coverage audit). A route added
/// without documenting it, a documented route that was removed or renamed, or a changed parameter name fails here.
/// </summary>
[Collection("api")]
public partial class ApiDocumentationTests
{
    /// <summary>The endpoints outside <c>/api/v1</c> that the API maps (docs/api.md, "Operational endpoints").</summary>
    private static readonly string[] OperationalPaths = ["/healthz", "/readyz", "/metrics"];

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "EggMail.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("EggMail.slnx not found above " + AppContext.BaseDirectory);
    }

    /// <summary>Rows of the route index: <c>METHOD /path</c>.</summary>
    private static List<string> DocumentedRoutes()
    {
        string[] lines = File.ReadAllLines(Path.Combine(RepoRoot(), "docs", "api.md"));
        int start = Array.FindIndex(lines, l => l.StartsWith("## Route index", StringComparison.Ordinal));
        Assert.True(start >= 0, "docs/api.md has no Route index section");
        var rows = new List<string>();
        for (int i = start + 1; i < lines.Length && !lines[i].StartsWith("## ", StringComparison.Ordinal); i++)
        {
            Match m = RouteRow().Match(lines[i]);
            if (m.Success)
            {
                rows.Add($"{m.Groups[1].Value} {m.Groups[2].Value}");
            }
        }

        return rows;
    }

    [GeneratedRegex(@"^\| `(GET|POST|PUT|PATCH|DELETE)` \| `(/[^`]*)` \|")]
    private static partial Regex RouteRow();

    /// <summary>Every <c>METHOD /pattern</c> the server maps under <c>/api/v1</c>, plus the operational endpoints (the dashboard's catch-all excluded).</summary>
    private static List<string> MappedRoutes(ApiFixture fixture)
    {
        var routes = new List<string>();
        foreach (EndpointDataSource source in fixture.Services.GetServices<EndpointDataSource>())
        {
            foreach (Endpoint endpoint in source.Endpoints)
            {
                if (endpoint is not RouteEndpoint route || route.RoutePattern.RawText is not { } raw || raw.Contains("{**", StringComparison.Ordinal))
                {
                    continue;
                }

                string pattern = raw.TrimEnd('/');
                if (!pattern.StartsWith("/api/v1/", StringComparison.Ordinal) && !OperationalPaths.Contains(pattern))
                {
                    continue;
                }

                foreach (string method in route.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? [])
                {
                    routes.Add($"{method} {pattern}");
                }
            }
        }

        return routes.Distinct(StringComparer.Ordinal).ToList();
    }

    [Fact]
    public async Task Every_mapped_route_is_in_the_route_index_and_every_indexed_route_is_mapped()
    {
        await using ApiFixture f = await ApiFixture.StartAsync();
        List<string> mapped = MappedRoutes(f);
        List<string> documented = DocumentedRoutes();

        // Guards the comparison itself: an empty endpoint table or index would make the two set checks pass for nothing.
        Assert.True(mapped.Count >= 70, $"only {mapped.Count} routes mapped");
        Assert.Contains("POST /api/v1/messages", mapped);
        Assert.Contains("GET /healthz", mapped);

        Assert.Empty(documented.GroupBy(r => r, StringComparer.Ordinal).Where(g => g.Count() > 1).Select(g => g.Key));   // listed twice
        Assert.Empty(mapped.Except(documented, StringComparer.Ordinal).Order(StringComparer.Ordinal));   // mapped, missing from the index
        Assert.Empty(documented.Except(mapped, StringComparer.Ordinal).Order(StringComparer.Ordinal));   // in the index, not mapped
    }
}
