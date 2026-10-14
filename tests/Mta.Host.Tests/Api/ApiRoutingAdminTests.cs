using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Mta.Core;
using Mta.Host.Api;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

/// <summary>Admin endpoints for relay routes and per-domain TLS policies (docs/api.md, "Relay routes and TLS policies").</summary>
[Collection("api")]
public class ApiRoutingAdminTests : IAsyncLifetime
{
    private const string Secret = "S3cret-relay-passw0rd!";

    private readonly CapturingLoggerProvider _logs = new();
    private readonly CountingNotifier _notifier = new();
    private ApiFixture _f = null!;
    private ApiClient _admin = null!;

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync(new ApiFixtureOptions
        {
            ConfigureServices = s =>
            {
                s.AddSingleton<IRoutingConfigNotifier>(_notifier);
                s.AddLogging(b => b.AddProvider(_logs));
            },
        });
        _admin = await _f.SignedInAsync("root");
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private sealed class CountingNotifier : IRoutingConfigNotifier
    {
        public int Count;

        public void Changed() => Interlocked.Increment(ref Count);
    }

    private static object NewRoute(string name = "backup", object? domains = null) => new
    {
        name,
        host = "smtp.relay.example",
        tlsMode = "verify",
        userName = "relay-user",
        password = Secret,
        domains = domains ?? new[] { "partner.example" },
    };

    // Relay routes

    [Fact]
    public async Task A_route_is_created_listed_read_updated_and_deleted_and_every_change_notifies_the_engine()
    {
        Reply created = await _admin.PostAsync("/api/v1/admin/relay-routes", NewRoute());
        Assert.Equal(HttpStatusCode.Created, created.Status);
        Assert.Equal("backup", created.Str("name"));
        Assert.Equal("smtp.relay.example", created.Str("host"));
        Assert.Equal(587, created["port"].GetInt32());
        Assert.Equal("verify", created.Str("tlsMode"));
        Assert.Equal("relay-user", created.Str("userName"));
        Assert.True(created["hasPassword"].GetBoolean());
        Assert.Equal(100, created["priority"].GetInt32());
        Assert.True(created["enabled"].GetBoolean());
        Assert.Equal(["partner.example"], created["domains"].EnumerateArray().Select(d => d.GetString()!));
        string id = created.Str("id");

        Assert.Single(await _f.Storage.Config.GetRelayRoutesAsync(default));
        Assert.Equal(id, (await _admin.GetAsync("/api/v1/admin/relay-routes")).Json[0].GetProperty("id").GetString());
        Assert.Equal("backup", (await _admin.GetAsync("/api/v1/admin/relay-routes/" + id)).Str("name"));

        Reply updated = await _admin.PatchAsync("/api/v1/admin/relay-routes/" + id, new { port = 2525, priority = 5, enabled = false, domains = new[] { "*.partner.example", "Other.Example." } });
        Assert.Equal(2525, updated["port"].GetInt32());
        Assert.False(updated["enabled"].GetBoolean());
        Assert.Equal(["*.partner.example", "other.example"], updated["domains"].EnumerateArray().Select(d => d.GetString()!));
        Assert.True(updated["hasPassword"].GetBoolean(), "an update that does not mention the password keeps it");

        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync("/api/v1/admin/relay-routes/" + id)).Status);
        Assert.Empty(await _f.Storage.Config.GetRelayRoutesAsync(default));
        (await _admin.GetAsync("/api/v1/admin/relay-routes/" + id)).Problem(HttpStatusCode.NotFound, "not_found");
        (await _admin.DeleteAsync("/api/v1/admin/relay-routes/" + id)).Problem(HttpStatusCode.NotFound, "not_found");
        Assert.Equal(3, _notifier.Count);
    }

    [Fact]
    public async Task The_password_is_stored_protected_and_never_returned_or_logged()
    {
        Reply created = await _admin.PostAsync("/api/v1/admin/relay-routes", NewRoute());
        string id = created.Str("id");
        Reply patched = await _admin.PatchAsync("/api/v1/admin/relay-routes/" + id, new { password = Secret + "-2" });
        string listed = (await _admin.GetAsync("/api/v1/admin/relay-routes")).Body;
        string single = (await _admin.GetAsync("/api/v1/admin/relay-routes/" + id)).Body;
        foreach (string body in new[] { created.Body, patched.Body, listed, single })
        {
            Assert.DoesNotContain("S3cret", body);
            Assert.DoesNotContain("assword\":\"", body);
            Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes(Secret)), body);
        }

        var stored = Assert.Single(await _f.Storage.Config.GetRelayRoutesAsync(default));
        Assert.NotNull(stored.PasswordProtected);
        Assert.Equal(Secret + "-2", Encoding.UTF8.GetString(_f.Protector.Unprotect(stored.PasswordProtected, SecretPurposes.RelayPassword)));

        Assert.NotEmpty(_logs.Messages);
        Assert.All(_logs.Messages, m => Assert.DoesNotContain("S3cret", m));
        Assert.Contains(_logs.Messages, m => m.Contains("Relay route backup") && m.Contains("created by root") && m.Contains("password set"));
    }

    [Fact]
    public async Task Credentials_can_be_replaced_and_removed_and_never_without_a_pair_or_tls()
    {
        string id = (await _admin.PostAsync("/api/v1/admin/relay-routes", NewRoute())).Str("id");

        // Changing the user name needs the new password: the stored one belonged to the old user.
        Reply change = await _admin.PatchAsync("/api/v1/admin/relay-routes/" + id, new { userName = "other" });
        change.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["password"], change.ErrorFields);
        Assert.Equal("other", (await _admin.PatchAsync("/api/v1/admin/relay-routes/" + id, new { userName = "other", password = "pw" })).Str("userName"));

        // TLS none and credentials exclude each other, in both directions.
        Reply none = await _admin.PatchAsync("/api/v1/admin/relay-routes/" + id, new { tlsMode = "none" });
        none.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["tlsMode"], none.ErrorFields);
        (await _admin.PostAsync("/api/v1/admin/relay-routes", new { name = "plain", host = "smtp.plain.example", tlsMode = "none", userName = "u", password = "p", domains = new[] { "a.example" } }))
            .Problem(HttpStatusCode.BadRequest, "validation_failed");

        Reply removed = await _admin.PatchAsync("/api/v1/admin/relay-routes/" + id, new { removeCredentials = true });
        Assert.Null(removed.Json.GetProperty("userName").GetString());
        Assert.False(removed["hasPassword"].GetBoolean());
        Assert.Null((await _f.Storage.Config.GetRelayRoutesAsync(default)).Single().PasswordProtected);
        Assert.Equal("none", (await _admin.PatchAsync("/api/v1/admin/relay-routes/" + id, new { tlsMode = "none" })).Str("tlsMode"));

        (await _admin.PostAsync("/api/v1/admin/relay-routes", new { name = "nouser", host = "smtp.x.example", password = "p", domains = new[] { "a.example" } })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _admin.PostAsync("/api/v1/admin/relay-routes", new { name = "nopass", host = "smtp.x.example", userName = "u", domains = new[] { "a.example" } })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _admin.PatchAsync("/api/v1/admin/relay-routes/" + id, new { removeCredentials = true, userName = "u" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Theory]
    [InlineData("name", "")]
    [InlineData("name", "direct")]
    [InlineData("name", "has space")]
    [InlineData("host", "")]
    [InlineData("host", "not a host")]
    [InlineData("host", "*.relay.example")]
    [InlineData("host", "relay..example")]
    [InlineData("port", 0)]
    [InlineData("port", 65536)]
    [InlineData("tlsMode", "plaintext")]
    [InlineData("priority", -1)]
    [InlineData("priority", 1001)]
    [InlineData("domains", null)]
    public async Task Invalid_members_are_rejected_by_name(string field, object? value)
    {
        var body = new Dictionary<string, object?>
        {
            ["name"] = "relay1", ["host"] = "smtp.relay.example", ["tlsMode"] = "verify", ["domains"] = new[] { "a.example" },
        };
        body[field] = value;
        Reply reply = await _admin.PostAsync("/api/v1/admin/relay-routes", body);
        reply.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains(field, reply.ErrorFields);
        Assert.Empty(await _f.Storage.Config.GetRelayRoutesAsync(default));
    }

    [Fact]
    public async Task Domain_patterns_are_normalized_checked_and_deduplicated()
    {
        Reply ok = await _admin.PostAsync("/api/v1/admin/relay-routes", NewRoute(domains: new[] { "Example.COM.", "example.com", "*.Corp.Example", "*" }));
        Assert.Equal(["example.com", "*.corp.example", "*"], ok["domains"].EnumerateArray().Select(d => d.GetString()!));

        Reply bad = await _admin.PostAsync("/api/v1/admin/relay-routes", NewRoute("second", new[] { "ok.example", "a*b.example", "192.0.2.1", "*.", "" }));
        bad.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["domains[1]", "domains[2]", "domains[3]", "domains[4]"], bad.ErrorFields);
        (await _admin.PostAsync("/api/v1/admin/relay-routes", NewRoute("third", new string[0]))).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _admin.PostAsync("/api/v1/admin/relay-routes", NewRoute("fourth", Enumerable.Range(0, RoutingAdminApi.MaxDomainsPerRoute + 1).Select(i => $"d{i}.example").ToArray()))).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task Names_are_unique_ignoring_case_and_an_update_may_keep_its_own()
    {
        string id = (await _admin.PostAsync("/api/v1/admin/relay-routes", NewRoute("Backup"))).Str("id");
        Reply dup = await _admin.PostAsync("/api/v1/admin/relay-routes", NewRoute("BACKUP"));
        dup.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["name"], dup.ErrorFields);
        Assert.Equal("Backup", (await _admin.PatchAsync("/api/v1/admin/relay-routes/" + id, new { name = "Backup" })).Str("name"));
        string other = (await _admin.PostAsync("/api/v1/admin/relay-routes", NewRoute("other"))).Str("id");
        (await _admin.PatchAsync("/api/v1/admin/relay-routes/" + other, new { name = "backup" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task Defaults_follow_the_tls_mode_and_hosts_may_be_ip_addresses()
    {
        Reply implicitTls = await _admin.PostAsync("/api/v1/admin/relay-routes", new { name = "tls465", host = "SMTP.Relay.Example.", tlsMode = "implicit", domains = new[] { "a.example" } });
        Assert.Equal(465, implicitTls["port"].GetInt32());
        Assert.Equal("smtp.relay.example", implicitTls.Str("host"));
        Reply ip = await _admin.PostAsync("/api/v1/admin/relay-routes", new { name = "byip", host = "[2001:db8::25]", domains = new[] { "a.example" } });
        Assert.Equal("2001:db8::25", ip.Str("host"));
        Assert.Equal("verify", ip.Str("tlsMode"));
    }

    [Fact]
    public async Task Weak_configurations_carry_warnings()
    {
        Reply required = await _admin.PostAsync("/api/v1/admin/relay-routes", new { name = "r1", host = "smtp.relay.example", tlsMode = "required", userName = "u", password = "p", domains = new[] { "*" } });
        var warnings = required["warnings"].EnumerateArray().Select(w => w.GetString()!).ToList();
        Assert.Equal(2, warnings.Count);
        Assert.Contains(warnings, w => w.Contains("not validated"));
        Assert.Contains(warnings, w => w.Contains("every recipient domain"));
        Assert.Empty((await _admin.PostAsync("/api/v1/admin/relay-routes", NewRoute("strong")))["warnings"].EnumerateArray());
    }

    [Fact]
    public async Task The_number_of_routes_is_capped()
    {
        for (int i = 0; i < RoutingAdminApi.MaxRelayRoutes; i++)
        {
            await _f.Storage.Config.UpsertRelayRouteAsync(new RelayRouteRecord(Ids.New(), "r" + i, "h.example", 587, "verify", null, null, 100, true, ["a.example"]), default);
        }

        Reply reply = await _admin.PostAsync("/api/v1/admin/relay-routes", NewRoute("one-too-many"));
        reply.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["name"], reply.ErrorFields);
    }

    [Fact]
    public async Task Unknown_members_and_bad_ids_are_rejected_and_stored_mixed_case_modes_are_shown_in_lower_case()
    {
        (await _admin.PostAsync("/api/v1/admin/relay-routes", new { name = "x", host = "h.example", domains = new[] { "a.example" }, secret = "boo" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _admin.GetAsync("/api/v1/admin/relay-routes/not-an-id")).Problem(HttpStatusCode.NotFound, "not_found");
        await _f.Storage.Config.UpsertRelayRouteAsync(new RelayRouteRecord(Ids.New(), "legacy", "h.example", 587, "StartTls", null, null, 1, true, ["a.example"]), default);
        Assert.Equal("starttls", (await _admin.GetAsync("/api/v1/admin/relay-routes")).Json[0].GetProperty("tlsMode").GetString());
    }

    // TLS policies

    [Fact]
    public async Task A_policy_is_created_listed_read_updated_and_deleted_and_every_change_notifies_the_engine()
    {
        Reply created = await _admin.PostAsync("/api/v1/admin/tls-policies", new { domainPattern = "  *.Bank.Example. ", level = "verify" });
        Assert.Equal(HttpStatusCode.Created, created.Status);
        Assert.Equal("*.bank.example", created.Str("domainPattern"));
        Assert.Equal("verify", created.Str("level"));
        string id = created.Str("id");
        Assert.Equal([TlsLevel.Verify], (await _f.Storage.Config.GetTlsPoliciesAsync(default)).Select(p => p.Level));

        Assert.Equal(id, (await _admin.GetAsync("/api/v1/admin/tls-policies")).Json[0].GetProperty("id").GetString());
        Assert.Equal("verify", (await _admin.GetAsync("/api/v1/admin/tls-policies/" + id)).Str("level"));
        Reply updated = await _admin.PatchAsync("/api/v1/admin/tls-policies/" + id, new { level = "encrypt" });
        Assert.Equal("encrypt", updated.Str("level"));
        Assert.Equal("*.bank.example", updated.Str("domainPattern"));
        Assert.Equal("bank.example", (await _admin.PatchAsync("/api/v1/admin/tls-policies/" + id, new { domainPattern = "bank.example" })).Str("domainPattern"));

        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync("/api/v1/admin/tls-policies/" + id)).Status);
        Assert.Empty(await _f.Storage.Config.GetTlsPoliciesAsync(default));
        (await _admin.GetAsync("/api/v1/admin/tls-policies/" + id)).Problem(HttpStatusCode.NotFound, "not_found");
        (await _admin.DeleteAsync("/api/v1/admin/tls-policies/" + id)).Problem(HttpStatusCode.NotFound, "not_found");
        Assert.Equal(4, _notifier.Count);
    }

    [Theory]
    [InlineData("domainPattern", "")]
    [InlineData("domainPattern", "a b.example")]
    [InlineData("domainPattern", "a*.example")]
    [InlineData("domainPattern", "192.0.2.1")]
    [InlineData("level", "required")]
    [InlineData("level", "")]
    public async Task Invalid_policies_are_rejected_by_name(string field, string value)
    {
        var body = new Dictionary<string, object?> { ["domainPattern"] = "ok.example", ["level"] = "may" };
        body[field] = value;
        Reply reply = await _admin.PostAsync("/api/v1/admin/tls-policies", body);
        reply.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal([field], reply.ErrorFields);
    }

    [Fact]
    public async Task A_pattern_has_one_policy_and_a_move_onto_another_is_refused()
    {
        string first = (await _admin.PostAsync("/api/v1/admin/tls-policies", new { domainPattern = "a.example", level = "may" })).Str("id");
        Reply dup = await _admin.PostAsync("/api/v1/admin/tls-policies", new { domainPattern = "A.EXAMPLE", level = "verify" });
        dup.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["domainPattern"], dup.ErrorFields);
        string second = (await _admin.PostAsync("/api/v1/admin/tls-policies", new { domainPattern = "b.example", level = "may" })).Str("id");
        (await _admin.PatchAsync("/api/v1/admin/tls-policies/" + second, new { domainPattern = "a.example" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal("verify", (await _admin.PatchAsync("/api/v1/admin/tls-policies/" + first, new { domainPattern = "a.example", level = "verify" })).Str("level"));
    }

    [Fact]
    public async Task Level_none_and_a_catch_all_policy_carry_warnings()
    {
        Reply none = await _admin.PostAsync("/api/v1/admin/tls-policies", new { domainPattern = "legacy.example", level = "none" });
        Assert.Contains("MTA-STS and DANE are not consulted", Assert.Single(none["warnings"].EnumerateArray()).GetString());
        Reply strict = await _admin.PostAsync("/api/v1/admin/tls-policies", new { domainPattern = "*", level = "verify" });
        Assert.Contains("every destination", Assert.Single(strict["warnings"].EnumerateArray()).GetString());
        Assert.Empty((await _admin.PostAsync("/api/v1/admin/tls-policies", new { domainPattern = "fine.example", level = "encrypt" }))["warnings"].EnumerateArray());
    }

    [Fact]
    public async Task The_number_of_policies_is_capped()
    {
        for (int i = 0; i < RoutingAdminApi.MaxTlsPolicies; i++)
        {
            await _f.Storage.Config.UpsertTlsPolicyAsync(new TlsPolicyRecord(Ids.New(), $"d{i}.example", TlsLevel.May), default);
        }

        (await _admin.PostAsync("/api/v1/admin/tls-policies", new { domainPattern = "one-too-many.example", level = "may" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    // Authorization

    [Fact]
    public async Task Only_administrators_reach_the_endpoints()
    {
        string route = (await _admin.PostAsync("/api/v1/admin/relay-routes", NewRoute())).Str("id");
        string policy = (await _admin.PostAsync("/api/v1/admin/tls-policies", new { domainPattern = "a.example", level = "may" })).Str("id");
        ApiClient alice = await _f.SignedInAsync("alice");
        ApiClient key = await _f.KeyClientAsync(ApiFixture.TenantAId);
        ApiClient anonymous = _f.NewClient();

        foreach (string path in new[] { "/api/v1/admin/relay-routes", "/api/v1/admin/relay-routes/" + route, "/api/v1/admin/tls-policies", "/api/v1/admin/tls-policies/" + policy })
        {
            (await alice.GetAsync(path)).Problem(HttpStatusCode.Forbidden, "forbidden");
            (await key.GetAsync(path)).Problem(HttpStatusCode.Forbidden, "forbidden");
            (await anonymous.GetAsync(path)).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        }

        (await alice.DeleteAsync("/api/v1/admin/relay-routes/" + route)).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await alice.DeleteAsync("/api/v1/admin/tls-policies/" + policy)).Problem(HttpStatusCode.Forbidden, "forbidden");

        (await alice.PostAsync("/api/v1/admin/relay-routes", NewRoute("x"))).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await alice.PatchAsync("/api/v1/admin/tls-policies/" + policy, new { level = "none" })).Problem(HttpStatusCode.Forbidden, "forbidden");
        Assert.Single(await _f.Storage.Config.GetRelayRoutesAsync(default));
        Assert.Equal(TlsLevel.May, Assert.Single(await _f.Storage.Config.GetTlsPoliciesAsync(default)).Level);
    }

    [Fact]
    public async Task A_session_must_present_the_csrf_token_to_change_anything()
    {
        _admin.SendCsrf = false;
        (await _admin.PostAsync("/api/v1/admin/relay-routes", NewRoute())).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await _admin.PostAsync("/api/v1/admin/tls-policies", new { domainPattern = "a.example", level = "may" })).Problem(HttpStatusCode.Forbidden, "forbidden");
        Assert.Empty(await _f.Storage.Config.GetRelayRoutesAsync(default));
        Assert.Equal(0, _notifier.Count);
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly List<string> _messages = [];

        public IReadOnlyList<string> Messages
        {
            get
            {
                lock (_messages)
                {
                    return [.. _messages];
                }
            }
        }

        public ILogger CreateLogger(string categoryName) => new Capture(this);

        public void Dispose()
        {
        }

        private sealed class Capture(CapturingLoggerProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                lock (owner._messages)
                {
                    owner._messages.Add(formatter(state, exception));
                }
            }
        }
    }
}
