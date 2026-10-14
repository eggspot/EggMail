using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Mta.Host.Hosting;

namespace Mta.Host.Tests;

public class DashboardHostingTests : IAsyncLifetime
{
    private readonly string _root = Directory.CreateTempSubdirectory("eggmail-wwwroot-").FullName;
    private WebApplication _app = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(Path.Combine(_root, "wwwroot", "assets"));
        await File.WriteAllTextAsync(Path.Combine(_root, "wwwroot", "index.html"), "<!doctype html><title>shell</title>");
        await File.WriteAllTextAsync(Path.Combine(_root, "wwwroot", "favicon.svg"), "<svg xmlns=\"http://www.w3.org/2000/svg\"/>");
        await File.WriteAllTextAsync(Path.Combine(_root, "wwwroot", "assets", "index-abc123.js"), "console.log(1)");

        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = _root, WebRootPath = Path.Combine(_root, "wwwroot") });
        builder.WebHost.UseTestServer();
        _app = builder.Build();
        DashboardHosting.Map(_app);
        await _app.StartAsync();
        _client = _app.GetTestClient();
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _app.DisposeAsync();
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    [Fact]
    public async Task Hashed_assets_are_cached_for_a_year_and_never_revalidated()
    {
        HttpResponseMessage response = await _client.GetAsync("/assets/index-abc123.js");

        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("public, max-age=31536000, immutable", response.Headers.CacheControl?.ToString());
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/index.html")]
    [InlineData("/favicon.svg")]
    [InlineData("/domains/0123456789abcdef0123456789abcdef")]
    [InlineData("/admin/storage")]
    public async Task The_shell_the_favicon_and_the_spa_fallback_are_revalidated(string path)
    {
        HttpResponseMessage response = await _client.GetAsync(path);

        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-cache", response.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task Every_response_carries_the_strict_headers_and_a_missing_api_path_is_not_the_shell()
    {
        HttpResponseMessage shell = await _client.GetAsync("/");
        Assert.Contains("script-src 'self'", string.Join(' ', shell.Headers.GetValues("Content-Security-Policy")));
        Assert.Equal("nosniff", shell.Headers.GetValues("X-Content-Type-Options").Single());

        HttpResponseMessage api = await _client.GetAsync("/api/v1/nothing");
        Assert.Equal(System.Net.HttpStatusCode.NotFound, api.StatusCode);
    }
}
