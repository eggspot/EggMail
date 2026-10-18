using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Mta.Host.Api;
using Mta.Host.Hosting;
using Mta.Host.Tests.Api;

namespace Mta.Host.Tests.Security;

/// <summary>
/// Security regression tests for what a browser is told and what it may do (docs/security-test-map.md, WEB-*, SESSION-*): the headers on every
/// response of the real pipeline (dashboard middleware in front of the API), the session cookie, session fixation, API keys and session ids in places they
/// must not be accepted from, and the static file host. The in-house review, not an independent audit.
/// </summary>
[Collection("api")]
public class BrowserSecurityTests : IAsyncLifetime
{
    private ApiFixture _f = null!;

    public async Task InitializeAsync() =>
        _f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.PasswordHashIterations = 1000, ConfigureApp = DashboardHosting.Map });

    public async Task DisposeAsync() => await _f.DisposeAsync();

    // Headers

    [Fact]
    public async Task Every_response_of_the_API_carries_the_strict_headers_of_the_dashboard()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        ApiClient root = await _f.SignedInAsync("root");
        var replies = new List<Reply>
        {
            await _f.NewClient().GetAsync("/api/v1/capabilities"),
            await _f.NewClient().GetAsync("/api/v1/domains"),                                      // 401
            await alice.GetAsync("/api/v1/domains"),                                               // 200
            await alice.GetAsync("/api/v1/domains/ffffffffffffffffffffffffffffffff"),               // 404
            await alice.PostAsync("/api/v1/domains", new { name = "bad name" }),                   // 400
            await alice.GetAsync("/api/v1/admin/tenants"),                                         // 403
            await root.GetAsync("/api/v1/admin/tenants"),
            await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = "wrong" }),
            await _f.NewClient().GetAsync("/healthz"),
            await _f.NewClient().GetAsync("/readyz"),
            await _f.NewClient().GetAsync("/.well-known/security.txt"),
        };

        foreach (Reply r in replies)
        {
            string where = $"{(int)r.Status} {r.Body.AsSpan(0, Math.Min(60, r.Body.Length))}";
            string csp = r.Header("Content-Security-Policy") ?? "";
            Assert.True(csp.Length > 0, where);
            foreach (string directive in new[] { "default-src 'self'", "script-src 'self'", "style-src 'self'", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'", "object-src 'none'", "connect-src 'self'" })
            {
                Assert.Contains(directive, csp, StringComparison.Ordinal);
            }

            Assert.DoesNotContain("unsafe-inline", csp, StringComparison.Ordinal);
            Assert.DoesNotContain("unsafe-eval", csp, StringComparison.Ordinal);
            Assert.DoesNotContain(" *", csp, StringComparison.Ordinal);
            Assert.DoesNotContain("http:", csp, StringComparison.Ordinal);
            Assert.Equal("nosniff", r.Header("X-Content-Type-Options"));
            Assert.Equal("DENY", r.Header("X-Frame-Options"));
            Assert.Equal("no-referrer", r.Header("Referrer-Policy"));
            Assert.Equal("same-origin", r.Header("Cross-Origin-Opener-Policy"));
        }
    }

    [Fact]
    public async Task Strict_transport_security_is_sent_over_https_only_and_never_with_a_short_age()
    {
        ApiClient https = _f.NewClient();
        https.Scheme = "https";
        string? hsts = (await https.GetAsync("/api/v1/capabilities")).Header("Strict-Transport-Security");
        Assert.NotNull(hsts);
        Assert.Matches(@"max-age=(\d{8,})", hsts!);
        Assert.True(long.Parse(System.Text.RegularExpressions.Regex.Match(hsts!, @"max-age=(\d+)").Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture) >= 31_536_000);

        // Plain HTTP: the header would be ignored by browsers, and sending it invites mistakes behind proxies.
        Assert.Null((await _f.NewClient().GetAsync("/api/v1/capabilities")).Header("Strict-Transport-Security"));
    }

    // Cookie and session

    [Fact]
    public async Task The_session_cookie_has_no_domain_a_random_value_and_is_set_only_by_a_successful_sign_in()
    {
        var secrets = new HashSet<string>();
        for (int i = 0; i < 20; i++)
        {
            Reply ok = await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password });
            string cookie = Assert.Single(ok.SetCookies);
            string lower = cookie.ToLowerInvariant();
            Assert.DoesNotContain("domain=", lower);
            Assert.Contains("httponly", lower);
            Assert.Contains("samesite=strict", lower);
            Assert.Contains("path=/", lower);
            string secret = cookie["eggmail_session=".Length..cookie.IndexOf(';')];
            Assert.Equal(43, secret.Length);   // 256 bits, base64url
            Assert.True(secrets.Add(secret));
        }

        Reply wrong = await _f.NewClient().PostAsync("/api/v1/session", new { user = "alice", password = "wrong" });
        Assert.Empty(wrong.SetCookies);
        Reply malformed = await _f.NewClient().PostAsync("/api/v1/session", "{");
        Assert.Empty(malformed.SetCookies);
    }

    [Fact]
    public async Task A_session_id_chosen_by_an_attacker_is_never_adopted_at_sign_in_and_is_worthless_afterwards()
    {
        // Session fixation: the attacker plants a cookie value in the victim's browser, the victim signs in, and the attacker uses the planted value.
        string planted = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        ApiClient victim = _f.NewClient();
        victim.Cookie = "eggmail_session=" + planted;

        Reply login = await victim.PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password });

        Assert.Equal(HttpStatusCode.OK, login.Status);
        string issued = login.SetCookies.Single();
        Assert.DoesNotContain(planted, issued, StringComparison.Ordinal);
        ApiClient attacker = _f.NewClient();
        attacker.Cookie = "eggmail_session=" + planted;
        (await attacker.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");

        // And a session the victim already had is ended by a new sign-in from the same browser.
        string old = issued[..issued.IndexOf(';')];
        ApiClient again = _f.NewClient();
        again.Cookie = old;
        Assert.Equal(HttpStatusCode.OK, (await again.PostAsync("/api/v1/session", new { user = "alice", password = ApiFixture.Password })).Status);
        ApiClient replay = _f.NewClient();
        replay.Cookie = old;
        (await replay.GetAsync("/api/v1/me")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
    }

    [Fact]
    public async Task A_session_or_a_key_is_accepted_from_the_cookie_and_the_authorization_header_only()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        string secret = alice.Cookie!["eggmail_session=".Length..];
        string token = await _f.AddKeyAsync(ApiFixture.TenantAId, [.. ApiScopes.All]);

        foreach (string path in new[]
        {
            $"/api/v1/me?eggmail_session={secret}", $"/api/v1/me?session={secret}", $"/api/v1/me?access_token={token}", $"/api/v1/domains?api_key={token}",
            $"/api/v1/domains?key={token}", $"/api/v1/domains?token={token}", $"/api/v1/domains?Authorization=Bearer%20{token}",
        })
        {
            (await _f.NewClient().GetAsync(path)).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        }

        foreach (var header in new[] { ("X-Api-Key", token), ("X-Auth-Token", token), ("X-Session", secret), ("Api-Key", token), ("X-Authorization", "Bearer " + token), ("Proxy-Authorization", "Bearer " + token) })
        {
            (await _f.NewClient().GetAsync("/api/v1/domains", header)).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        }

        // A key in the cookie, or a session secret as a bearer token, is not a credential either.
        ApiClient keyInCookie = _f.NewClient();
        keyInCookie.Cookie = "eggmail_session=" + token;
        (await keyInCookie.GetAsync("/api/v1/domains")).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        (await _f.NewClient().WithBearer(secret).GetAsync("/api/v1/domains")).Problem(HttpStatusCode.Unauthorized, "unauthorized");

        // The scheme name is case-insensitive (RFC 9110), the token is not forgiving.
        Assert.Equal(HttpStatusCode.OK, (await _f.NewClient().GetAsync("/api/v1/domains", ("Authorization", "bearer " + token))).Status);
        Assert.Equal(HttpStatusCode.OK, (await _f.NewClient().GetAsync("/api/v1/domains", ("Authorization", "Bearer  " + token))).Status);
        (await _f.NewClient().GetAsync("/api/v1/domains", ("Authorization", "Bearer " + token.ToLowerInvariant()))).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        (await _f.NewClient().GetAsync("/api/v1/domains", ("Authorization", "Bearer " + token + "x"))).Problem(HttpStatusCode.Unauthorized, "unauthorized");
    }

    [Fact]
    public async Task A_sign_in_cannot_be_forged_from_another_site_with_a_form_post()
    {
        // A cross-site <form> can only send simple content types; the API accepts JSON only (and has no CORS, so a script from another origin cannot send it).
        foreach (string contentType in new[] { "application/x-www-form-urlencoded", "text/plain", "multipart/form-data; boundary=x" })
        {
            Reply r = await _f.NewClient().SendRawAsync(HttpMethod.Post, "/api/v1/session", $$"""{"user":"alice","password":"{{ApiFixture.Password}}"}""", contentType, ("Origin", "https://evil.example"));
            Assert.Equal(HttpStatusCode.UnsupportedMediaType, r.Status);
            Assert.Empty(r.SetCookies);
        }
    }

    [Fact]
    public async Task Session_secrets_and_csrf_tokens_are_random_per_session_and_the_token_is_not_derived_from_the_cookie()
    {
        var csrf = new HashSet<string>();
        for (int i = 0; i < 10; i++)
        {
            ApiClient c = await _f.SignedInAsync("alice");
            Assert.True(csrf.Add(c.Csrf!));
            Assert.NotEqual(c.Cookie!["eggmail_session=".Length..], c.Csrf);
            Assert.Equal(22, c.Csrf!.Length);   // 128 bits, base64url
        }

        ApiClient key = await _f.KeyClientAsync(ApiFixture.TenantAId);
        Reply me = await key.GetAsync("/api/v1/me");
        Assert.False(me.Json.TryGetProperty("csrfToken", out System.Text.Json.JsonElement t) && t.ValueKind == System.Text.Json.JsonValueKind.String);   // a key has no CSRF token
    }

    [Fact]
    public async Task Signing_out_removes_the_cookie_with_the_attributes_it_was_set_with_and_ends_the_session_on_the_server()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        string secret = alice.Cookie!["eggmail_session=".Length..];

        Reply out_ = await alice.DeleteAsync("/api/v1/session");

        Assert.Equal(HttpStatusCode.NoContent, out_.Status);
        string cleared = out_.SetCookies.Single().ToLowerInvariant();
        Assert.StartsWith("eggmail_session=;", cleared);
        Assert.Contains("expires=", cleared);
        Assert.Contains("path=/", cleared);
        Assert.Contains("samesite=strict", cleared);
        Assert.Contains("httponly", cleared);
        Assert.Null(await _f.Storage.Config.FindDashboardSessionAsync(SessionService.HashSecret(secret), default));
    }

    // The static host

    [Fact]
    public async Task The_security_txt_names_a_private_reporting_channel_and_expires_in_the_future()
    {
        Reply r = await _f.NewClient().GetAsync("/.well-known/security.txt");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Contains("Contact: https://github.com/eggspot/EggMail/security/advisories/new", r.Body, StringComparison.Ordinal);
        Assert.Matches(@"Expires: 20\d\d-\d\d-\d\dT00:00:00Z", r.Body);
        Assert.Contains("Policy: https://github.com/eggspot/EggMail/blob/main/SECURITY.md", r.Body, StringComparison.Ordinal);
    }
}

/// <summary>The static files of the dashboard: nothing outside the web root can be requested, whichever way the path is written.</summary>
public sealed class DashboardStaticFilesSecurityTests : IAsyncLifetime
{
    private const string Secret = "TOP-SECRET-OUTSIDE-THE-WEB-ROOT";
    private readonly string _root = Directory.CreateTempSubdirectory("eggmail-static-").FullName;
    private WebApplication _app = null!;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(Path.Combine(_root, "wwwroot", "assets"));
        await File.WriteAllTextAsync(Path.Combine(_root, "wwwroot", "index.html"), "<!doctype html><title>shell</title>");
        await File.WriteAllTextAsync(Path.Combine(_root, "wwwroot", "assets", "app.js"), "console.log(1)");
        await File.WriteAllTextAsync(Path.Combine(_root, "secret.txt"), Secret);
        await File.WriteAllTextAsync(Path.Combine(_root, "wwwroot", "assets", "secret.txt"), "inside");
        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = _root, WebRootPath = Path.Combine(_root, "wwwroot") });
        builder.WebHost.UseTestServer();
        _app = builder.Build();
        DashboardHosting.Map(_app);
        await _app.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _app.DisposeAsync();
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }   // created by this test
    }

    public static TheoryData<string> Paths() => new()
    {
        "/../secret.txt", "/assets/../../secret.txt", "/..%2fsecret.txt", "/%2e%2e/secret.txt", "/%2e%2e%2fsecret.txt", "/assets/..%2f..%2fsecret.txt",
        "/%252e%252e/secret.txt", "/..\\secret.txt", "/assets/..\\..\\secret.txt", "/assets/..%5c..%5csecret.txt", "/%c0%ae%c0%ae/secret.txt",
        "/%00/../secret.txt", "/secret.txt", "//secret.txt", "/./../secret.txt", "/assets/./../../secret.txt", "/wwwroot/../secret.txt", "/..;/secret.txt",
        "/assets/%2e%2e/%2e%2e/secret.txt", "/..%c0%afsecret.txt", "/%2e%2e%5csecret.txt", "/assets/....//....//secret.txt",
        "/" + "../".PadRight(300, '.') + "secret.txt",
    };

    [Theory]
    [MemberData(nameof(Paths))]
    public async Task Nothing_outside_the_web_root_is_served_whatever_the_path_looks_like(string path)
    {
        var server = _app.GetTestServer();
        string body = "";
        int status = 0;
        try
        {
            HttpContext context = await server.SendAsync(c =>
            {
                c.Request.Method = "GET";
                c.Request.Path = new PathString(path);
            });
            status = context.Response.StatusCode;
            body = await new StreamReader(context.Response.Body).ReadToEndAsync();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            status = 400;   // refused before it reached a file
        }

        Assert.DoesNotContain(Secret, body, StringComparison.Ordinal);
        Assert.True(status is 200 or 400 or 404, $"{path} -> {status}");
    }
}
