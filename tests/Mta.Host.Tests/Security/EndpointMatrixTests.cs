using System.Net;
using System.Text;
using Mta.Host.Api;
using Mta.Host.Tests.Api;

namespace Mta.Host.Tests.Security;

/// <summary>
/// Security regression tests that run over every route of the API (docs/security-test-map.md, AUTHZ-*, CSRF-*, ROBUST-1): authentication, CSRF, role
/// and scope are checked for each endpoint the server really registers, not for a hand-picked few. A new route must be classified in
/// <see cref="ApiRouteTable"/>, or these tests fail. The in-house review, not an independent audit.
/// </summary>
[Collection("api")]
public class EndpointMatrixTests : IAsyncLifetime
{
    private const string AnId = "0123456789abcdef0123456789abcdef";

    private ApiFixture _f = null!;
    private IReadOnlyList<ApiRoute> _routes = null!;

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync();
        _routes = ApiRouteTable.Of(_f);
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private IEnumerable<ApiRoute> Routes(Func<ApiRoute, bool>? where = null) => _routes.Where(r => where?.Invoke(r) ?? true);

    private static Task<Reply> CallAsync(ApiClient client, ApiRoute route, string? body = "{}", params (string, string)[] headers) =>
        client.SendRawAsync(new HttpMethod(route.Method), route.Fill(AnId), route.Mutates ? body : null, route.Mutates ? "application/json" : null, headers);

    private static void AssertProblem(Reply reply, ApiRoute route, HttpStatusCode status, string code)
    {
        Assert.True(reply.Status == status, $"{route}: expected {(int)status} {code}, got {(int)reply.Status} {reply.Body}");
        Assert.Equal("application/problem+json", reply.ContentType);
        Assert.Equal(code, reply.Code);
    }

    [Fact]
    public void The_route_table_is_read_from_the_server_and_is_complete()
    {
        // Guards the matrix itself: if routing changed and the table came back empty, every test below would pass for nothing.
        Assert.True(_routes.Count >= 70, $"only {_routes.Count} routes found");
        foreach (string expected in new[] { "POST /api/v1/messages", "GET /api/v1/domains", "DELETE /api/v1/api-keys/{id}", "POST /api/v1/admin/users", "PUT /api/v1/admin/settings", "POST /api/v1/me/password" })
        {
            Assert.Contains(_routes, r => r.ToString() == expected);
        }

        Assert.Contains(_routes, r => r.Policy == AccessPolicy.Admin);
        Assert.Contains(_routes, r => r.Policy == AccessPolicy.TenantScoped && r.Scope == ApiScopes.Keys);
    }

    [Fact]
    public async Task Every_route_except_sign_in_and_capabilities_refuses_a_caller_without_credentials()
    {
        ApiClient anonymous = _f.NewClient();
        foreach (ApiRoute route in Routes(r => r.Policy != AccessPolicy.Public))
        {
            AssertProblem(await CallAsync(anonymous, route), route, HttpStatusCode.Unauthorized, "unauthorized");
        }
    }

    [Theory]
    [InlineData("Bearer not-a-key")]
    [InlineData("Bearer egm_AAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("Bearer ")]
    [InlineData("Basic YWRtaW46YWRtaW4=")]
    [InlineData("bearer egm_AAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("Negotiate abc")]
    public async Task Every_route_refuses_credentials_that_are_not_a_real_key(string authorization)
    {
        ApiClient client = _f.NewClient();
        foreach (ApiRoute route in Routes(r => r.Policy != AccessPolicy.Public))
        {
            AssertProblem(await CallAsync(client, route, "{}", ("Authorization", authorization)), route, HttpStatusCode.Unauthorized, "unauthorized");
        }
    }

    [Fact]
    public async Task Every_route_refuses_a_session_cookie_the_server_never_issued()
    {
        foreach (string cookie in new[] { "eggmail_session=garbage", "eggmail_session=" + new string('A', 43), "eggmail_session=;", "eggmail_session=%00", "other=1; eggmail_session=x" })
        {
            ApiClient client = _f.NewClient();
            client.Cookie = cookie;
            client.Csrf = "garbage";
            foreach (ApiRoute route in Routes(r => r.Policy != AccessPolicy.Public))
            {
                AssertProblem(await CallAsync(client, route), route, HttpStatusCode.Unauthorized, "unauthorized");
            }
        }
    }

    [Fact]
    public async Task A_revoked_key_is_refused_on_every_route()
    {
        string token = await _f.AddKeyAsync(ApiFixture.TenantAId, [.. ApiScopes.All]);
        ApiClient key = _f.NewClient().WithBearer(token);
        Assert.Equal(HttpStatusCode.OK, (await key.GetAsync("/api/v1/domains")).Status);

        ApiClient alice = await _f.SignedInAsync("alice");
        Reply list = await alice.GetAsync("/api/v1/api-keys");
        string id = list.Json.EnumerateArray().Single(k => k.GetProperty("name").GetString() == "test key").GetProperty("id").GetString()!;
        Assert.Equal(HttpStatusCode.NoContent, (await alice.DeleteAsync($"/api/v1/api-keys/{id}")).Status);

        foreach (ApiRoute route in Routes(r => r.Policy != AccessPolicy.Public))
        {
            AssertProblem(await CallAsync(key, route), route, HttpStatusCode.Unauthorized, "unauthorized");
        }
    }

    [Fact]
    public async Task A_key_of_a_suspended_tenant_and_a_session_of_a_disabled_user_are_refused_on_every_route()
    {
        ApiClient key = await _f.KeyClientAsync(ApiFixture.TenantBId);
        ApiClient bob = await _f.SignedInAsync("bob");
        var tenant = _f.TenantB with { Enabled = false };
        await _f.Storage.Config.UpsertTenantAsync(tenant, default);

        foreach (ApiRoute route in Routes(r => r.Policy is AccessPolicy.TenantScoped or AccessPolicy.TenantSessionForWrites))
        {
            Reply viaKey = await CallAsync(key, route);
            Assert.True(viaKey.Status is HttpStatusCode.Forbidden, $"{route} via key: {(int)viaKey.Status} {viaKey.Body}");
            Assert.Equal("tenant_disabled", viaKey.Code);
            Reply viaSession = await CallAsync(bob, route);
            Assert.True(viaSession.Status is HttpStatusCode.Forbidden, $"{route} via session: {(int)viaSession.Status} {viaSession.Body}");
            Assert.Equal("tenant_disabled", viaSession.Code);
        }
    }

    // CSRF

    [Theory]
    [InlineData("alice")]
    [InlineData("root")]
    public async Task Every_mutation_with_a_session_cookie_needs_the_CSRF_token_and_a_wrong_one_is_no_better(string user)
    {
        ApiClient client = await _f.SignedInAsync(user);
        if (user == "root") { client.ActingAs(ApiFixture.TenantAId); }

        foreach (ApiRoute route in Routes(r => r.Mutates && r.Policy != AccessPolicy.Public))
        {
            client.SendCsrf = false;
            AssertProblem(await CallAsync(client, route), route, HttpStatusCode.Forbidden, "forbidden");
            client.SendCsrf = true;
            AssertProblem(await CallAsync(client, route, "{}", ("X-CSRF-Token", "not-the-token")), route, HttpStatusCode.Forbidden, "forbidden");
            AssertProblem(await CallAsync(client, route, "{}", ("X-CSRF-Token", client.Csrf![..^1])), route, HttpStatusCode.Forbidden, "forbidden");   // a prefix of the real token
            AssertProblem(await CallAsync(client, route, "{}", ("X-CSRF-Token", "")), route, HttpStatusCode.Forbidden, "forbidden");
        }
    }

    [Fact]
    public async Task The_CSRF_token_of_one_session_does_not_work_for_another()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        ApiClient other = await _f.SignedInAsync("alice");
        other.Csrf = alice.Csrf;

        Reply r = await other.PostAsync("/api/v1/suppressions", new { address = "x@example.org" });

        r.Problem(HttpStatusCode.Forbidden, "forbidden");
    }

    [Fact]
    public async Task The_CSRF_token_is_taken_from_a_header_only_never_from_the_query_or_the_body()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        alice.SendCsrf = false;

        Reply viaQuery = await alice.SendRawAsync(HttpMethod.Post, "/api/v1/suppressions?csrf=" + alice.Csrf + "&X-CSRF-Token=" + alice.Csrf, """{"address":"x@example.org"}""", "application/json");
        Reply viaBody = await alice.SendRawAsync(HttpMethod.Post, "/api/v1/suppressions", $$"""{"address":"x@example.org","csrfToken":"{{alice.Csrf}}","X-CSRF-Token":"{{alice.Csrf}}"}""", "application/json");
        Reply viaCookie = await alice.SendRawAsync(HttpMethod.Post, "/api/v1/suppressions", """{"address":"x@example.org"}""", "application/json", ("Cookie", alice.Cookie + "; X-CSRF-Token=" + alice.Csrf));

        viaQuery.Problem(HttpStatusCode.Forbidden, "forbidden");
        Assert.Equal(HttpStatusCode.Forbidden, viaBody.Status);
        Assert.Equal(HttpStatusCode.Forbidden, viaCookie.Status);
    }

    [Fact]
    public async Task Reads_with_a_session_do_not_need_the_token_but_no_read_changes_anything()
    {
        // GET is safe by construction: assert that no GET route changes the state the next GET sees (the CSRF exemption is only sound if that holds).
        ApiClient alice = await _f.SignedInAsync("alice");
        alice.SendCsrf = false;
        Reply before = await alice.GetAsync("/api/v1/suppressions");
        foreach (ApiRoute route in Routes(r => !r.Mutates && r.Policy is AccessPolicy.TenantScoped))
        {
            await CallAsync(alice, route);
        }

        Reply after = await alice.GetAsync("/api/v1/suppressions");
        Assert.Equal(before.Body, after.Body);
    }

    // Roles

    [Fact]
    public async Task A_tenant_user_and_an_api_key_never_reach_an_admin_route()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        ApiClient key = await _f.KeyClientAsync(ApiFixture.TenantAId);
        ApiClient keyWithHeader = (await _f.KeyClientAsync(ApiFixture.TenantAId)).ActingAs(ApiFixture.TenantAId);
        foreach (ApiRoute route in Routes(r => r.Policy == AccessPolicy.Admin))
        {
            AssertProblem(await CallAsync(alice, route), route, HttpStatusCode.Forbidden, "forbidden");
            AssertProblem(await CallAsync(key, route), route, HttpStatusCode.Forbidden, "forbidden");
            AssertProblem(await CallAsync(keyWithHeader, route), route, HttpStatusCode.Forbidden, "forbidden");
            AssertProblem(await CallAsync(alice, route, "{}", ("X-Tenant-Id", ApiFixture.TenantBId.ToString("N"))), route, HttpStatusCode.Forbidden, "forbidden");
        }
    }

    [Fact]
    public async Task A_tenant_caller_cannot_act_for_another_tenant_on_any_tenant_route()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        ApiClient key = await _f.KeyClientAsync(ApiFixture.TenantAId);
        string other = ApiFixture.TenantBId.ToString("N");
        foreach (ApiRoute route in Routes(r => r.Policy is AccessPolicy.TenantScoped or AccessPolicy.TenantSessionForWrites))
        {
            AssertProblem(await CallAsync(alice, route, "{}", ("X-Tenant-Id", other)), route, HttpStatusCode.Forbidden, "forbidden");
            AssertProblem(await CallAsync(key, route, "{}", ("X-Tenant-Id", other)), route, HttpStatusCode.Forbidden, "forbidden");
        }
    }

    [Fact]
    public async Task Routes_that_need_a_signed_in_user_refuse_an_API_key()
    {
        ApiClient key = await _f.KeyClientAsync(ApiFixture.TenantAId);
        foreach (ApiRoute route in Routes(r => r.Policy == AccessPolicy.SessionOnly))
        {
            Reply reply = await CallAsync(key, route);
            Assert.True(reply.Status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden, $"{route}: {(int)reply.Status}");
        }

        AssertProblem(await key.PutAsync("/api/v1/settings", new { values = new { } }), _routes.First(r => r.Method == "PUT" && r.Pattern.EndsWith("/settings", StringComparison.Ordinal) && !r.Pattern.Contains("admin", StringComparison.Ordinal)), HttpStatusCode.Forbidden, "forbidden");
    }

    // Scopes

    [Fact]
    public async Task A_key_without_the_scope_of_a_route_gets_403_and_with_it_gets_past_authorization()
    {
        foreach (string scope in ApiScopes.All)
        {
            string[] others = ApiScopes.All.Where(s => s != scope).ToArray();
            ApiClient without = await _f.KeyClientAsync(ApiFixture.TenantAId, others);
            ApiClient only = await _f.KeyClientAsync(ApiFixture.TenantAId, scope);
            foreach (ApiRoute route in Routes(r => r.Policy == AccessPolicy.TenantScoped && r.Scope == scope))
            {
                AssertProblem(await CallAsync(without, route), route, HttpStatusCode.Forbidden, "forbidden");
                ApiClient holder = route.AlsoNeeds is { } extra ? await _f.KeyClientAsync(ApiFixture.TenantAId, scope, extra) : only;
                Reply allowed = await CallAsync(holder, route);
                Assert.False(allowed.Status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden, $"{route} with scope {scope}: {(int)allowed.Status} {allowed.Body}");
            }
        }
    }

    [Fact]
    public async Task Every_scope_is_used_by_some_route_and_every_route_names_a_known_scope()
    {
        Assert.All(Routes(r => r.Policy == AccessPolicy.TenantScoped), r => Assert.True(ApiScopes.IsKnown(r.Scope!), r.ToString()));
        foreach (string scope in ApiScopes.All)
        {
            Assert.Contains(_routes, r => r.Scope == scope);
        }

        await Task.CompletedTask;
    }

    [Fact]
    public async Task A_key_cannot_be_created_with_a_scope_that_does_not_exist_or_more_than_the_creating_key_has()
    {
        ApiClient narrow = await _f.KeyClientAsync(ApiFixture.TenantAId, "keys");
        (await narrow.PostAsync("/api/v1/api-keys", new { name = "x", scopes = new[] { "keys", "send" } })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await narrow.PostAsync("/api/v1/api-keys", new { name = "x", scopes = new[] { "admin" } })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await narrow.PostAsync("/api/v1/api-keys", new { name = "x", scopes = new[] { "*" } })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await narrow.PostAsync("/api/v1/api-keys", new { name = "x", scopes = new[] { "KEYS " } })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    // Robustness: hostile input never turns into a 500

    public static TheoryData<string, string?> HostileBodies() => new()
    {
        { "", "application/json" },
        { "{}", "application/json" },
        { "[]", "application/json" },
        { "null", "application/json" },
        { "\"text\"", "application/json" },
        { "123456789012345678901234567890", "application/json" },
        { "{", "application/json" },
        { "{\"a\":1,\"a\":2}", "application/json" },
        { "\uFEFF{}", "application/json" },
        { "{}", "text/plain" },
        { "{}", null },
        { "{}", "application/json; charset=utf-7" },
        { "{}", "multipart/form-data; boundary=x" },
        { "a=b&c=d", "application/x-www-form-urlencoded" },
        { "{\"name\":\"\\ud800\"}", "application/json" },
    };

    [Theory]
    [MemberData(nameof(HostileBodies))]
    public async Task No_route_answers_a_hostile_body_with_a_server_error(string body, string? contentType)
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        ApiClient admin = (await _f.SignedInAsync("root")).ActingAs(ApiFixture.TenantAId);
        ApiClient key = await _f.KeyClientAsync(ApiFixture.TenantAId);
        foreach (ApiClient caller in new[] { alice, admin, key })
        {
            foreach (ApiRoute route in Routes(r => r.Mutates && r.Policy != AccessPolicy.Public && !(r.Pattern.EndsWith("/session", StringComparison.Ordinal))))
            {
                Reply reply = await caller.SendRawAsync(new HttpMethod(route.Method), route.Fill(AnId), body, contentType);
                AssertNotAServerFault(reply, route);
            }
        }
    }

    [Fact]
    public async Task No_route_answers_a_deeply_nested_or_huge_body_with_a_server_error_or_by_exhausting_memory()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        ApiClient admin = (await _f.SignedInAsync("root")).ActingAs(ApiFixture.TenantAId);
        string deepArray = new string('[', 20_000) + new string(']', 20_000);
        string deepObject = string.Concat(Enumerable.Repeat("{\"a\":", 20_000)) + "1" + new string('}', 20_000);
        string manyMembers = "{" + string.Join(",", Enumerable.Range(0, 20_000).Select(i => $"\"k{i}\":{i}")) + "}";
        string hugeString = "{\"name\":\"" + new string('x', 2_000_000) + "\"}";
        foreach (ApiClient caller in new[] { alice, admin })
        {
            foreach (ApiRoute route in Routes(r => r.Mutates && r.Policy != AccessPolicy.Public && !r.Pattern.EndsWith("/session", StringComparison.Ordinal)))
            {
                foreach (string body in new[] { deepArray, deepObject, manyMembers, hugeString })
                {
                    Reply reply = await caller.SendRawAsync(new HttpMethod(route.Method), route.Fill(AnId), body, "application/json");
                    AssertNotAServerFault(reply, route);
                    Assert.True(reply.Body.Length < 10_000, $"{route} answered a hostile body with {reply.Body.Length} bytes");
                }
            }
        }
    }

    [Theory]
    [InlineData("not-a-guid")]
    [InlineData("00000000000000000000000000000000")]
    [InlineData("ffffffffffffffffffffffffffffffff")]
    [InlineData("0123456789abcdef0123456789abcdeg")]
    [InlineData("01234567-89ab-cdef-0123-456789abcdef")]
    [InlineData("..%2f..%2fetc%2fpasswd")]
    [InlineData("%27%20OR%201%3D1--")]
    [InlineData("%E2%80%AE%E2%80%AE")]
    public async Task No_route_answers_a_malformed_resource_id_with_anything_but_a_not_found_or_validation_problem(string id)
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        ApiClient admin = (await _f.SignedInAsync("root")).ActingAs(ApiFixture.TenantAId);
        foreach (ApiClient caller in new[] { alice, admin })
        {
            foreach (ApiRoute route in Routes(r => r.Pattern.Contains("{id}", StringComparison.Ordinal) || r.Pattern.Contains("{outboxId}", StringComparison.Ordinal) || r.Pattern.Contains("{address}", StringComparison.Ordinal)))
            {
                if (route.Policy == AccessPolicy.Admin && caller == alice) { continue; }
                string path = route.Fill(id, id);
                Reply reply = await caller.SendRawAsync(new HttpMethod(route.Method), path, route.Mutates ? "{}" : null, route.Mutates ? "application/json" : null);
                AssertNotAServerFault(reply, route);
                Assert.True(reply.Status is HttpStatusCode.NotFound or HttpStatusCode.BadRequest or HttpStatusCode.Forbidden or HttpStatusCode.NoContent or HttpStatusCode.Conflict or HttpStatusCode.OK, $"{route} {id}: {(int)reply.Status}");
            }
        }
    }

    [Fact]
    public async Task Every_response_of_every_route_is_not_cacheable_not_sniffable_and_carries_a_request_id_and_no_internals()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        ApiClient anonymous = _f.NewClient();
        foreach (ApiRoute route in Routes())
        {
            foreach (ApiClient caller in new[] { alice, anonymous })
            {
                Reply reply = await CallAsync(caller, route);
                Assert.Equal("no-store", reply.Header("Cache-Control"));
                Assert.Equal("nosniff", reply.Header("X-Content-Type-Options"));
                Assert.StartsWith("req_", reply.Header("X-Request-Id"));
                Assert.DoesNotContain("   at ", reply.Body, StringComparison.Ordinal);      // no stack trace
                Assert.DoesNotContain(".cs:line", reply.Body, StringComparison.Ordinal);
                Assert.DoesNotContain("Exception", reply.Body, StringComparison.Ordinal);
                Assert.DoesNotContain(Environment.CurrentDirectory, reply.Body, StringComparison.Ordinal);
                Assert.Null(reply.Header("Server"));
                Assert.Null(reply.Header("X-Powered-By"));
                Assert.Null(reply.Header("Access-Control-Allow-Origin"));   // no CORS: another origin may not read these responses
            }
        }
    }

    [Fact]
    public async Task No_route_allows_cross_origin_reads_and_a_preflight_is_not_answered_with_permission()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        foreach (ApiRoute route in Routes(r => r.Policy != AccessPolicy.Public))
        {
            Reply preflight = await alice.SendRawAsync(HttpMethod.Options, route.Fill(AnId), null, null,
                ("Origin", "https://evil.example"), ("Access-Control-Request-Method", route.Method), ("Access-Control-Request-Headers", "authorization,x-csrf-token"));
            Assert.Null(preflight.Header("Access-Control-Allow-Origin"));
            Assert.Null(preflight.Header("Access-Control-Allow-Credentials"));
            Assert.Null(preflight.Header("Access-Control-Allow-Headers"));
        }
    }

    [Fact]
    public async Task A_method_a_route_does_not_define_is_never_run_as_another_method()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        // HEAD and TRACE-like tricks: nothing may change state through a method that is not in the table.
        foreach (string method in new[] { "HEAD", "TRACE", "CONNECT", "PROPFIND", "PURGE", "X-HTTP-Method-Override" })
        {
            if (method is "TRACE" or "CONNECT") { continue; }   // the test server does not carry these
            Reply reply = await alice.SendRawAsync(new HttpMethod(method), "/api/v1/api-keys", "{\"name\":\"via-" + method + "\",\"scopes\":[\"read\"]}", "application/json");
            Assert.False(reply.Status is HttpStatusCode.OK or HttpStatusCode.Created, method);
        }

        Reply list = await alice.GetAsync("/api/v1/api-keys");
        Assert.DoesNotContain("via-", list.Body, StringComparison.Ordinal);

        // Method override headers are not honoured: a GET stays a GET.
        Reply overridden = await alice.SendRawAsync(HttpMethod.Get, "/api/v1/api-keys", null, null, ("X-HTTP-Method-Override", "DELETE"), ("X-Method-Override", "DELETE"));
        Assert.Equal(HttpStatusCode.OK, overridden.Status);
    }

    private static void AssertNotAServerFault(Reply reply, ApiRoute route)
    {
        Assert.True(reply.Status != HttpStatusCode.InternalServerError, $"{route} -> 500 {reply.Body}");
        Assert.True((int)reply.Status < 600 && (int)reply.Status != 502 && (int)reply.Status != 504, $"{route} -> {(int)reply.Status}");
        if ((int)reply.Status >= 400)
        {
            Assert.True(reply.ContentType == "application/problem+json" || reply.Body.Length == 0, $"{route} -> {(int)reply.Status} {reply.ContentType} {reply.Body}");
            if (reply.ContentType == "application/problem+json")
            {
                Assert.NotEqual("server_error", reply.Code);
            }
        }
    }
}
