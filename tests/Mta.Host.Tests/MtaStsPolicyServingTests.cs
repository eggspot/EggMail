using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Mta.Core;
using Mta.Host.Domains;
using Mta.Host.Tests.Api;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests;

/// <summary>
/// EggMail serves <c>https://mta-sts.&lt;domain&gt;/.well-known/mta-sts.txt</c> itself for the domains registered in it, when <c>Domains:MtaStsMode</c> says so.
/// The server under test is the middleware in front of a catch-all that stands for the dashboard.
/// </summary>
public class MtaStsPolicyServingTests : IAsyncLifetime
{
    private readonly TestClock _clock = new(ApiFixture.Start);
    private InMemoryStorage _storage = null!;
    private readonly List<WebApplication> _apps = [];

    public async Task InitializeAsync()
    {
        _storage = new InMemoryStorage(new StorageOptions(), _clock, null, TimeSpan.Zero);
        await _storage.InitializeAsync(default);
        var tenant = new Tenant(Guid.NewGuid(), "Acme", "acme", true, _clock.UtcNow, false);
        await _storage.Config.UpsertTenantAsync(tenant, default);
        await AddDomainAsync(tenant.Id, "example.com");
    }

    public async Task DisposeAsync()
    {
        foreach (WebApplication app in _apps)
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }

        await _storage.DisposeAsync();
    }

    private Task AddDomainAsync(Guid tenantId, string name) =>
        _storage.Config.UpsertDomainAsync(new DomainRecord(Guid.NewGuid(), tenantId, name, DomainStatus.Pending, null, false, _clock.UtcNow, null, null, 0, null, false, null), default).AsTask();

    private async Task<HttpClient> StartAsync(DomainRecordOptions options)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton<IStorage>(_storage);
        builder.Services.AddSingleton<IClock>(_clock);
        builder.Services.AddSingleton(options);
        WebApplication app = builder.Build();
        app.UseMtaStsPolicy();
        app.Run(context => context.Response.WriteAsync("the dashboard"));   // stands for the dashboard behind the middleware
        await app.StartAsync();
        _apps.Add(app);
        return app.GetTestClient();
    }

    private static DomainRecordOptions Options(MtaStsServingMode mode = MtaStsServingMode.Testing) => new() { ServerHostname = "mta.mail.test", MtaStsMode = mode };

    private static async Task<(HttpResponseMessage Response, string Body)> GetAsync(HttpClient http, string host, string path = "/.well-known/mta-sts.txt", HttpMethod? method = null)
    {
        using var request = new HttpRequestMessage(method ?? HttpMethod.Get, path);
        request.Headers.Host = host;
        HttpResponseMessage response = await http.SendAsync(request);
        return (response, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A_registered_domains_mta_sts_host_gets_the_policy_file()
    {
        HttpClient http = await StartAsync(Options());
        var (response, body) = await GetAsync(http, "mta-sts.example.com");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/plain", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("version: STSv1\r\nmode: testing\r\nmx: mta.mail.test\r\nmax_age: 604800\r\n", body);
        Assert.Equal(body.Length, response.Content.Headers.ContentLength);
    }

    [Fact]
    public async Task The_mode_and_the_mx_lines_follow_the_configuration()
    {
        var options = new DomainRecordOptions { ServerHostname = "mta.mail.test", MtaStsMode = MtaStsServingMode.Enforce, MtaStsMx = ["mx1.mail.test", "*.mx.mail.test"], MtaStsMaxAge = TimeSpan.FromDays(30) };
        HttpClient http = await StartAsync(options);
        var (_, body) = await GetAsync(http, "mta-sts.example.com");
        Assert.Equal("version: STSv1\r\nmode: enforce\r\nmx: mx1.mail.test\r\nmx: *.mx.mail.test\r\nmax_age: 2592000\r\n", body);
    }

    [Fact]
    public async Task The_host_name_may_carry_a_port_a_trailing_dot_and_any_case()
    {
        HttpClient http = await StartAsync(Options());
        Assert.Equal(HttpStatusCode.OK, (await GetAsync(http, "MTA-STS.Example.COM:8443")).Response.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await GetAsync(http, "mta-sts.example.com.")).Response.StatusCode);
    }

    [Fact]
    public async Task The_policy_of_a_domain_that_is_not_registered_is_not_found_and_is_not_answered_by_the_dashboard()
    {
        HttpClient http = await StartAsync(Options());
        var (response, body) = await GetAsync(http, "mta-sts.stranger.test");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain("dashboard", body);
        Assert.Equal(HttpStatusCode.NotFound, (await GetAsync(http, "mta-sts.com")).Response.StatusCode);
    }

    [Fact]
    public async Task Other_paths_on_a_policy_host_are_not_found_other_hosts_reach_the_dashboard()
    {
        HttpClient http = await StartAsync(Options());
        Assert.Equal(HttpStatusCode.NotFound, (await GetAsync(http, "mta-sts.example.com", "/")).Response.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await GetAsync(http, "mta-sts.example.com", "/api/v1/session")).Response.StatusCode);

        var (response, body) = await GetAsync(http, "mail.example.com", "/");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("the dashboard", body);
        // Another name for the dashboard is untouched, also for the policy path.
        Assert.Equal("the dashboard", (await GetAsync(http, "mta.mail.test")).Body);
        // A host that merely contains the prefix is not a policy host.
        Assert.Equal("the dashboard", (await GetAsync(http, "xmta-sts.example.com", "/")).Body);
    }

    [Fact]
    public async Task Only_get_and_head_read_the_policy()
    {
        HttpClient http = await StartAsync(Options());
        var (head, headBody) = await GetAsync(http, "mta-sts.example.com", method: HttpMethod.Head);
        Assert.Equal(HttpStatusCode.OK, head.StatusCode);
        Assert.Equal("", headBody);
        Assert.True(head.Content.Headers.ContentLength > 0);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await GetAsync(http, "mta-sts.example.com", method: HttpMethod.Post)).Response.StatusCode);
    }

    [Fact]
    public async Task Nothing_is_served_when_the_mode_is_off()
    {
        HttpClient http = await StartAsync(Options(MtaStsServingMode.Off));
        Assert.Equal("the dashboard", (await GetAsync(http, "mta-sts.example.com")).Body);
    }

    [Fact]
    public async Task A_domain_registered_later_is_served_once_the_short_cache_expires()
    {
        HttpClient http = await StartAsync(Options());
        Assert.Equal(HttpStatusCode.NotFound, (await GetAsync(http, "mta-sts.later.example")).Response.StatusCode);
        await AddDomainAsync((await _storage.Config.GetTenantsAsync(default)).First().Id, "later.example");
        _clock.Advance(TimeSpan.FromSeconds(31));
        Assert.Equal(HttpStatusCode.OK, (await GetAsync(http, "mta-sts.later.example")).Response.StatusCode);
    }

    [Fact]
    public async Task The_policy_matches_what_the_txt_record_announces()
    {
        // The id in the _mta-sts TXT record is a hash of the file served: the record and the file always belong together.
        DomainRecordOptions options = Options();
        HttpClient http = await StartAsync(options);
        var (_, body) = await GetAsync(http, "mta-sts.example.com");
        Assert.Equal(MtaStsPolicyDocument.Render(options), body);
        Assert.Equal(MtaStsPolicyDocument.PolicyId(options), Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(body)), 0, 8).ToLowerInvariant());
    }
}
