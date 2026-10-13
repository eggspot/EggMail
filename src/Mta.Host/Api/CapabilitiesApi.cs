using System.Net;
using System.Reflection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Mta.Core;
using Mta.Observability;
using Mta.Storage;

namespace Mta.Host.Api;

public sealed record CapabilityWarning(string Code, string Message);

public sealed record HistoryCapability(string Mode);

public sealed record ContentCapability(int RetentionDays, bool StoreAttachments);

public sealed record LimitsCapability(long MaxMessageBytes, int MaxRecipients);

public sealed record CapabilitiesResponse(string Version, string Backend, HistoryCapability History, ContentCapability Content, LimitsCapability Limits, IReadOnlyList<CapabilityWarning> Warnings);

/// <summary>Human text for the warning codes (the persistent banner of the dashboard, decision P).</summary>
public static class WarningTexts
{
    public static string For(string code) => code switch
    {
        "sqlite_sync_off" => "SQLite runs with synchronous=OFF: a process kill is safe, but an operating system crash or power loss can corrupt the database and lose queued mail that was already acknowledged. Set Sqlite:SyncMode to Normal or Full, or use PostgreSQL, if you need power-loss safety.",
        "queue_persistence_memory" => "Queued mail is held in memory only and is lost when the server restarts (Sqlite:QueuePersistence=Memory).",
        "self_signed_certificate" => "The server is using a self-signed certificate. Upload a certificate or request one through ACME.",
        "certificate_expiring" => "A TLS certificate expires within 14 days.",
        "certificate_expired" => "A TLS certificate has expired.",
        _ => "Warning: " + code,
    };
}

/// <summary>Storage readiness and its warnings, as a health contributor (the storage backend decides which warnings exist).</summary>
public sealed class StorageHealthContributor(IStorage storage) : IHealthContributor
{
    public string Name => "storage";

    public async ValueTask<HealthReport> CheckAsync(CancellationToken cancellationToken)
    {
        StorageHealth health = await storage.Maintenance.GetHealthAsync(cancellationToken).ConfigureAwait(false);
        return new HealthReport(health.Ready, health.Warnings.Select(w => new HealthWarning(w, WarningTexts.For(w))).ToList(), health.Details);
    }
}

/// <summary>Certificate warnings: only a self-signed certificate in use, and certificates close to or past expiry.</summary>
public sealed class CertificateHealthContributor(IStorage storage, IClock clock) : IHealthContributor
{
    public static readonly TimeSpan ExpiryWarning = TimeSpan.FromDays(14);

    public string Name => "certificates";

    public async ValueTask<HealthReport> CheckAsync(CancellationToken cancellationToken)
    {
        var certificates = (await storage.Config.GetCertificatesAsync(cancellationToken).ConfigureAwait(false)).Where(c => c.Active).ToList();
        var warnings = new List<HealthWarning>();
        DateTimeOffset now = clock.UtcNow;
        if (certificates.Count > 0 && certificates.All(c => c.Source == "selfsigned"))
        {
            warnings.Add(new HealthWarning("self_signed_certificate", WarningTexts.For("self_signed_certificate")));
        }

        if (certificates.Any(c => c.Source != "selfsigned" && c.NotAfter <= now))
        {
            warnings.Add(new HealthWarning("certificate_expired", WarningTexts.For("certificate_expired")));
        }
        else if (certificates.Any(c => c.Source != "selfsigned" && c.NotAfter - now <= ExpiryWarning))
        {
            warnings.Add(new HealthWarning("certificate_expiring", WarningTexts.For("certificate_expiring")));
        }

        return new HealthReport(true, warnings, new Dictionary<string, string>());
    }
}

/// <summary>Builds the (cached) answers of <c>/api/v1/capabilities</c>, <c>/readyz</c> and <c>/healthz</c>. These endpoints are unauthenticated, so the work behind them is cached briefly.</summary>
public sealed class CapabilitiesService
{
    private readonly IStorage _storage;
    private readonly StorageOptions _storageOptions;
    private readonly ApiOptions _options;
    private readonly HealthService _health;
    private readonly IClock _clock;
    private readonly string _version;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private (long At, HealthReport Report)? _cached;

    public CapabilitiesService(IStorage storage, StorageOptions storageOptions, ApiOptions options, HealthService health, IClock clock)
    {
        _storage = storage;
        _storageOptions = storageOptions;
        _options = options;
        _health = health;
        _clock = clock;
        _version = VersionOf();
    }

    public static string VersionOf()
    {
        string? informational = typeof(CapabilitiesService).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (string.IsNullOrEmpty(informational))
        {
            return "0.1.0";
        }

        int plus = informational.IndexOf('+', StringComparison.Ordinal);
        return plus < 0 ? informational : informational[..plus];
    }

    public string Version => _version;

    public async ValueTask<HealthReport> GetHealthAsync(CancellationToken ct)
    {
        long now = _clock.Timestamp;
        long ttl = (long)(_options.CapabilitiesCacheTime.TotalSeconds * System.Diagnostics.Stopwatch.Frequency);
        if (_cached is { } c && now - c.At < ttl)
        {
            return c.Report;
        }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_cached is { } again && _clock.Timestamp - again.At < ttl)
            {
                return again.Report;
            }

            HealthReport report = await _health.CheckAsync(ct).ConfigureAwait(false);
            _cached = (_clock.Timestamp, report);
            return report;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<CapabilitiesResponse> GetAsync(CancellationToken ct)
    {
        HealthReport health = await GetHealthAsync(ct).ConfigureAwait(false);
        return new CapabilitiesResponse(
            _version,
            ApiMap.Backend(_storage.Backend),
            new HistoryCapability(ApiMap.HistoryMode(_storage.HistoryMode)),
            new ContentCapability(_storageOptions.Content.RetentionDays, _storageOptions.Content.StoreAttachments && _storageOptions.Content.AllowAttachmentStorage),
            new LimitsCapability(_options.MaxMessageBytes, _options.MaxRecipients),
            health.Warnings.Select(w => new CapabilityWarning(w.Code, w.Message)).ToList());
    }
}

/// <summary>Capabilities and the operational endpoints (<c>/healthz</c>, <c>/readyz</c>, <c>/metrics</c>).</summary>
public sealed class CapabilitiesApi(CapabilitiesService capabilities, ApiOptions options, PrometheusTextExporter? metrics = null)
{
    public void MapApi(RouteGroupBuilder api) => api.GetRoute("/capabilities", GetCapabilitiesAsync);

    public void MapOperational(IEndpointRouteBuilder endpoints)
    {
        endpoints.GetRoute("/healthz", () => Results.Json(new { status = "ok" }, ApiJson.Write));
        endpoints.GetRoute("/readyz", ReadyAsync);
        endpoints.GetRoute("/metrics", MetricsAsync);
    }

    private async Task<IResult> GetCapabilitiesAsync(HttpContext context) => ApiResults.Ok(await capabilities.GetAsync(context.RequestAborted).ConfigureAwait(false));

    private async Task<IResult> ReadyAsync(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        Mta.Observability.HealthReport report = await capabilities.GetHealthAsync(context.RequestAborted).ConfigureAwait(false);
        var body = new { status = report.Ready ? "ready" : "not_ready", warnings = report.Warnings.Select(w => new CapabilityWarning(w.Code, w.Message)).ToList() };
        if (!report.Ready)
        {
            context.Response.Headers.RetryAfter = "5";
        }

        return Results.Json(body, ApiJson.Write, statusCode: report.Ready ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable);
    }

    private Task<IResult> MetricsAsync(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (!options.MetricsEnabled || metrics is null)
        {
            return Task.FromResult(Results.NotFound());
        }

        // A request that went through a proxy (forwarded headers still present: the host did not translate them) is never "inside the network".
        IPAddress? remote = context.Connection.RemoteIpAddress;
        if (remote is null || context.Request.Headers.ContainsKey("X-Forwarded-For") || context.Request.Headers.ContainsKey("Forwarded")
            || !options.MetricsAllowedNetworks.Any(n => n.Contains(remote)))
        {
            return Task.FromResult(Results.StatusCode(StatusCodes.Status403Forbidden));
        }

        return Task.FromResult(Results.Text(metrics.Render(), "text/plain; version=0.0.4; charset=utf-8"));
    }
}
