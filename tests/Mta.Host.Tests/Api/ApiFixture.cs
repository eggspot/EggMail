using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Mta.Core;
using Mta.Dns;
using Mta.Host.Api;
using Mta.Host.Security;
using Mta.Host.Submission;
using Mta.Policy;
using Mta.Storage;
using Mta.Storage.InMemory;
using Mta.Storage.Sqlite;

namespace Mta.Host.Tests.Api;

/// <summary>A controllable clock whose monotonic timestamp follows the wall clock (as <see cref="IClock.Timestamp"/> is defined: Stopwatch ticks).</summary>
internal sealed class TestClock : IClock
{
    private readonly long _startTicks;
    private long _utcTicks;

    public TestClock(DateTimeOffset start)
    {
        _startTicks = start.UtcTicks;
        _utcTicks = start.UtcTicks;
    }

    public DateTimeOffset UtcNow => new(Interlocked.Read(ref _utcTicks), TimeSpan.Zero);

    public long Timestamp => (long)((Interlocked.Read(ref _utcTicks) - _startTicks) / (double)TimeSpan.TicksPerSecond * Stopwatch.Frequency) + Stopwatch.Frequency;

    public void Advance(TimeSpan by) => Interlocked.Add(ref _utcTicks, by.Ticks);
}

/// <summary>A DNS resolver tests can change: records come and go, and answers can fail with SERVFAIL.</summary>
internal sealed class MutableDns : IDnsResolver
{
    private readonly object _gate = new();
    private readonly List<DnsRecord> _records = [];

    public bool ServerFailure { get; set; }

    private static string Normalize(string name) => name.TrimEnd('.').ToLowerInvariant();

    public MutableDns AddTxt(string name, string text)
    {
        lock (_gate)
        {
            _records.Add(new TxtRecord(Normalize(name), 300, text));
        }

        return this;
    }

    public MutableDns AddCname(string name, string target)
    {
        lock (_gate)
        {
            _records.Add(new CnameRecord(Normalize(name), 300, Normalize(target)));
        }

        return this;
    }

    public void RemoveAll(string name)
    {
        lock (_gate)
        {
            _records.RemoveAll(r => r.Name == Normalize(name));
        }
    }

    public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
    {
        if (ServerFailure)
        {
            return ValueTask.FromResult(new DnsResponse { Rcode = DnsRcode.ServerFailure });
        }

        lock (_gate)
        {
            string n = Normalize(name);
            var named = _records.Where(r => r.Name == n).ToList();
            if (named.Count == 0)
            {
                return ValueTask.FromResult(new DnsResponse { Rcode = DnsRcode.NameError, Ttl = 300 });
            }

            return ValueTask.FromResult(new DnsResponse { Rcode = DnsRcode.NoError, Answers = named.Where(r => r.Type == type).ToArray(), Ttl = 300 });
        }
    }
}

internal sealed class ApiFixtureOptions
{
    public bool Sqlite { get; init; }
    public HistoryMode History { get; init; } = HistoryMode.Full;
    public bool AllowAttachmentStorage { get; init; } = true;
    public Action<ApiOptions>? ConfigureApi { get; init; }
    public Action<IServiceCollection>? ConfigureServices { get; init; }
}

/// <summary>
/// An in-process API server (TestHost) over real storage (in-memory, or SQLite in a temp directory), with two tenants, users of both roles and
/// a controllable clock and DNS. Disposing removes the temp directory.
/// </summary>
internal sealed class ApiFixture : IAsyncDisposable
{
    public static readonly DateTimeOffset Start = new(2026, 10, 12, 12, 30, 0, TimeSpan.Zero);
    public static readonly Guid TenantAId = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    public static readonly Guid TenantBId = Guid.Parse("b0000000-0000-7000-8000-000000000002");
    public const string Password = "correct horse battery";

    private readonly string? _directory;
    private WebApplication _app = null!;

    private ApiFixture(string? directory) => _directory = directory;

    public TestClock Clock { get; private set; } = null!;
    public IStorage Storage { get; private set; } = null!;
    public StorageOptions StorageOptions { get; private set; } = null!;
    public ApiOptions Options { get; private set; } = null!;
    public MutableDns Dns { get; } = new();
    public AuthThrottle Throttle { get; private set; } = null!;
    public TestProtector Protector { get; } = new();
    public IServiceProvider Services => _app.Services;
    public HttpClient Http { get; private set; } = null!;
    public Tenant TenantA { get; private set; } = null!;
    public Tenant TenantB { get; private set; } = null!;

    public static async Task<ApiFixture> StartAsync(ApiFixtureOptions? o = null)
    {
        o ??= new ApiFixtureOptions();
        string? dir = o.Sqlite ? Path.Combine(Path.GetTempPath(), "eggmail-api-" + Guid.NewGuid().ToString("N")) : null;
        var fixture = new ApiFixture(dir);
        await fixture.InitializeAsync(o).ConfigureAwait(false);
        return fixture;
    }

    private async Task InitializeAsync(ApiFixtureOptions o)
    {
        Clock = new TestClock(Start);
        StorageOptions = new StorageOptions
        {
            History = new HistoryOptions { Mode = o.History },
            Content = new ContentOptions { AllowAttachmentStorage = o.AllowAttachmentStorage },
            Sqlite = _directory is null ? new SqliteOptions() : new SqliteOptions { DataDirectory = _directory, StatsFlushInterval = TimeSpan.Zero },
        };
        Storage = _directory is null
            ? new InMemoryStorage(StorageOptions, Clock, null, TimeSpan.Zero)
            : SqliteStorage.Create(StorageOptions, Clock);
        await Storage.InitializeAsync(default).ConfigureAwait(false);

        Options = new ApiOptions
        {
            BounceDomain = "bounces.egg.test",
            MessageIdDomain = "egg.test",
            VerificationPollInterval = TimeSpan.FromHours(1),
            MetricsAllowedNetworks = ApiOptions.DefaultMetricsNetworks(),
        };
        o.ConfigureApi?.Invoke(Options);
        Throttle = new AuthThrottle(Clock, maxFailures: 5, window: TimeSpan.FromMinutes(10));

        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton(Storage);
        builder.Services.AddSingleton(StorageOptions);
        builder.Services.AddSingleton<IClock>(Clock);
        builder.Services.AddSingleton<ISecretProtector>(Protector);
        builder.Services.AddSingleton<IDnsResolver>(Dns);
        builder.Services.AddSingleton(Throttle);
        builder.Services.AddSingleton(new SubmissionService(Storage, Clock, new SenderPolicy(), StorageOptions, new SubmissionOptions { MessageIdDomain = "egg.test" }));
        builder.Services.AddEggMailApi(Options);
        o.ConfigureServices?.Invoke(builder.Services);

        _app = builder.Build();
        _app.Use(async (context, next) =>
        {
            // Tests choose the peer address and scheme per request (loopback or not; http or https).
            if (context.Request.Headers.TryGetValue("X-Test-Remote-Ip", out var ip) && IPAddress.TryParse(ip.ToString(), out IPAddress? parsed))
            {
                context.Connection.RemoteIpAddress = parsed;
            }

            if (context.Request.Headers.TryGetValue("X-Test-Scheme", out var scheme))
            {
                context.Request.Scheme = scheme.ToString();
            }

            await next().ConfigureAwait(false);
        });
        _app.MapEggMailApi();
        await _app.StartAsync().ConfigureAwait(false);
        Http = _app.GetTestClient();

        TenantA = new Tenant(TenantAId, "Acme Corp", "acme", true, Clock.UtcNow, false);
        TenantB = new Tenant(TenantBId, "Globex", "globex", true, Clock.UtcNow, false);
        await Storage.Config.UpsertTenantAsync(TenantA, default).ConfigureAwait(false);
        await Storage.Config.UpsertTenantAsync(TenantB, default).ConfigureAwait(false);
        await AddVerifiedDomainAsync(TenantAId, "example.com").ConfigureAwait(false);
        await AddVerifiedDomainAsync(TenantBId, "globex.test").ConfigureAwait(false);
        await AddUserAsync("root", DashboardRole.Admin, null).ConfigureAwait(false);
        await AddUserAsync("alice", DashboardRole.Tenant, TenantAId).ConfigureAwait(false);
        await AddUserAsync("bob", DashboardRole.Tenant, TenantBId).ConfigureAwait(false);
    }

    public ApiClient NewClient() => new(Http);

    public T Get<T>() where T : notnull => Services.GetRequiredService<T>();

    public async Task<DomainRecord> AddVerifiedDomainAsync(Guid tenantId, string name, DomainStatus status = DomainStatus.Verified, bool paused = false)
    {
        var domain = new DomainRecord(Ids.New(Clock.UtcNow), tenantId, name, status, "bounce." + name, true, Clock.UtcNow, Clock.UtcNow, Clock.UtcNow.AddHours(24), 0, null, paused, null);
        await Storage.Config.UpsertDomainAsync(domain, default).ConfigureAwait(false);
        return domain;
    }

    public async Task<DashboardUser> AddUserAsync(string name, DashboardRole role, Guid? tenantId) =>
        await DashboardAccounts.CreateAsync(Storage.Config, Clock, name, Password, role, tenantId, default, hashIterations: 1000).ConfigureAwait(false);

    /// <summary>Creates an API key for the tenant and returns the token (shown once in real life).</summary>
    public async Task<string> AddKeyAsync(Guid tenantId, params string[] scopes)
    {
        var (token, prefix, digest) = ApiKeys.Generate();
        await Storage.Config.AddApiKeyAsync(new ApiKeyRecord(Ids.New(Clock.UtcNow), tenantId, "test key", prefix, digest, string.Join(',', scopes), Clock.UtcNow, null, null), default).ConfigureAwait(false);
        return token;
    }

    public async Task<ApiClient> KeyClientAsync(Guid tenantId, params string[] scopes) =>
        NewClient().WithBearer(await AddKeyAsync(tenantId, scopes.Length == 0 ? [.. ApiScopes.All] : scopes).ConfigureAwait(false));

    public async Task<ApiClient> SignedInAsync(string user)
    {
        ApiClient client = NewClient();
        Reply reply = await client.SignInAsync(user, Password).ConfigureAwait(false);
        Assert.Equal(HttpStatusCode.OK, reply.Status);
        return client;
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync().ConfigureAwait(false);
        await _app.DisposeAsync().ConfigureAwait(false);
        await Storage.DisposeAsync().ConfigureAwait(false);
        if (_directory is not null && Directory.Exists(_directory))
        {
            // The directory was created by this fixture (a unique name under the temp folder) and holds only its own files.
            try
            {
                Directory.Delete(_directory, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }
}

/// <summary>A decoded response.</summary>
internal sealed class Reply
{
    private readonly Lazy<JsonDocument> _json;

    public Reply(HttpResponseMessage response, string body)
    {
        Status = response.StatusCode;
        Headers = response.Headers;
        ContentType = response.Content.Headers.ContentType?.MediaType;
        Body = body;
        _json = new Lazy<JsonDocument>(() => JsonDocument.Parse(body.Length == 0 ? "null" : body));
    }

    public HttpStatusCode Status { get; }
    public HttpResponseHeaders Headers { get; }
    public string? ContentType { get; }
    public string Body { get; }
    public JsonElement Json => _json.Value.RootElement;

    public string? Header(string name) => Headers.TryGetValues(name, out var values) ? string.Join(",", values) : null;

    public IReadOnlyList<string> SetCookies => Headers.TryGetValues("Set-Cookie", out var values) ? values.ToList() : [];

    public string Code => Json.GetProperty("code").GetString()!;

    public JsonElement this[string name] => Json.GetProperty(name);

    public string Str(string name) => Json.GetProperty(name).GetString()!;

    /// <summary>Asserts an RFC 9457 problem with the given status and code and returns it.</summary>
    public Reply Problem(HttpStatusCode status, string code)
    {
        Assert.Equal(status, Status);
        Assert.Equal("application/problem+json", ContentType);
        Assert.Equal(code, Code);
        Assert.Equal((int)status, Json.GetProperty("status").GetInt32());
        Assert.False(string.IsNullOrEmpty(Json.GetProperty("title").GetString()));
        Assert.StartsWith("req_", Json.GetProperty("request_id").GetString());
        Assert.False(string.IsNullOrEmpty(Json.GetProperty("detail").GetString()));
        Assert.EndsWith(code, Json.GetProperty("type").GetString());
        return this;
    }

    /// <summary>The field names in <c>errors[]</c> of a validation_failed problem.</summary>
    public IReadOnlyList<string> ErrorFields => Json.GetProperty("errors").EnumerateArray().Select(e => e.GetProperty("field").GetString()!).ToList();
}

/// <summary>An HTTP client with the state a browser or SDK would keep: bearer key or session cookie plus CSRF token, and the acting tenant of an admin.</summary>
internal sealed class ApiClient(HttpClient http)
{
    public string? Bearer { get; set; }
    public string? Cookie { get; set; }
    public string? Csrf { get; set; }
    public Guid? TenantId { get; set; }
    public string? RemoteIp { get; set; }
    public string? Scheme { get; set; }
    public bool SendCsrf { get; set; } = true;

    public ApiClient WithBearer(string token)
    {
        Bearer = token;
        return this;
    }

    public ApiClient ActingAs(Guid tenantId)
    {
        TenantId = tenantId;
        return this;
    }

    public Task<Reply> GetAsync(string path, params (string Name, string Value)[] headers) => SendAsync(HttpMethod.Get, path, null, headers);

    public Task<Reply> PostAsync(string path, object? body = null, params (string Name, string Value)[] headers) => SendAsync(HttpMethod.Post, path, body, headers);

    public Task<Reply> PutAsync(string path, object? body = null) => SendAsync(HttpMethod.Put, path, body);

    public Task<Reply> PatchAsync(string path, object? body = null) => SendAsync(HttpMethod.Patch, path, body);

    public Task<Reply> DeleteAsync(string path) => SendAsync(HttpMethod.Delete, path, null);

    /// <summary>POST /session, keeps the cookie, then reads the CSRF token from /me like the dashboard does.</summary>
    public async Task<Reply> SignInAsync(string user, string password)
    {
        Reply reply = await PostAsync("/api/v1/session", new { user, password }).ConfigureAwait(false);
        if (reply.Status == HttpStatusCode.OK)
        {
            string cookie = reply.SetCookies.First(c => c.StartsWith("eggmail_session=", StringComparison.Ordinal));
            Cookie = cookie[..cookie.IndexOf(';')];
            Reply me = await GetAsync("/api/v1/me").ConfigureAwait(false);
            Csrf = me.Json.GetProperty("csrfToken").GetString();
        }

        return reply;
    }

    public async Task<Reply> SendAsync(HttpMethod method, string path, object? body, params (string Name, string Value)[] headers)
    {
        string? json = body switch
        {
            null => null,
            string s => s,
            _ => JsonSerializer.Serialize(body),
        };
        return await SendRawAsync(method, path, json, "application/json", headers).ConfigureAwait(false);
    }

    public async Task<Reply> SendRawAsync(HttpMethod method, string path, string? body, string? contentType, params (string Name, string Value)[] headers)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8);
            request.Content.Headers.ContentType = null;
            if (contentType is not null)
            {
                request.Content.Headers.TryAddWithoutValidation("Content-Type", contentType);
            }
        }

        if (Bearer is not null)
        {
            request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + Bearer);
        }

        if (Cookie is not null)
        {
            request.Headers.TryAddWithoutValidation("Cookie", Cookie);
        }

        if (Csrf is not null && SendCsrf && method != HttpMethod.Get)
        {
            request.Headers.TryAddWithoutValidation("X-CSRF-Token", Csrf);
        }

        if (TenantId is { } tenant)
        {
            request.Headers.TryAddWithoutValidation("X-Tenant-Id", tenant.ToString("N"));
        }

        if (RemoteIp is not null)
        {
            request.Headers.TryAddWithoutValidation("X-Test-Remote-Ip", RemoteIp);
        }

        if (Scheme is not null)
        {
            request.Headers.TryAddWithoutValidation("X-Test-Scheme", Scheme);
        }

        foreach (var (name, value) in headers)
        {
            request.Headers.Remove(name);
            request.Headers.TryAddWithoutValidation(name, value);
        }

        using HttpResponseMessage response = await http.SendAsync(request).ConfigureAwait(false);
        return new Reply(response, await response.Content.ReadAsStringAsync().ConfigureAwait(false));
    }
}
