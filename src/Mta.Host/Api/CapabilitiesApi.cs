using System.Net;
using System.Reflection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Mta.Core;
using Mta.Host.Tls;
using Mta.Observability;
using Mta.Storage;

namespace Mta.Host.Api;

public sealed record CapabilityWarning(string Code, string Message);

public sealed record HistoryCapability(string Mode);

public sealed record ContentCapability(int RetentionDays, bool StoreAttachments);

public sealed record LimitsCapability(long MaxMessageBytes, int MaxRecipients);

/// <summary>Whether this server receives mail (<c>Inbound:Enabled</c>): the dashboard shows or hides its inbound pages by this.</summary>
public sealed record InboundCapability(bool Enabled);

public sealed record CapabilitiesResponse(string Version, string Backend, HistoryCapability History, ContentCapability Content, LimitsCapability Limits, InboundCapability Inbound, IReadOnlyList<CapabilityWarning> Warnings);

/// <summary>Human text for the warning codes (the persistent banner of the dashboard, decision P).</summary>
public static class WarningTexts
{
    public static string For(string code) => code switch
    {
        "sqlite_sync_off" => "SQLite runs with synchronous=OFF: a process kill is safe, but an operating system crash or power loss can corrupt the database and lose queued mail that was already acknowledged. Set Sqlite:SyncMode to Normal or Full, or use PostgreSQL, if you need power-loss safety.",
        "queue_persistence_memory" => "Queued mail is held in memory only and is lost when the server restarts (Sqlite:QueuePersistence=Memory).",
        "self_signed_certificate" => "The server is using a SELF-SIGNED certificate: mail servers and browsers will not trust it. Set EGGMAIL_HOSTNAME and EGGMAIL_ACME_EMAIL for a free trusted certificate (ACME), or upload one under Certificates.",
        "certificate_expiring" => "A TLS certificate expires within 14 days.",
        "certificate_expired" => "A TLS certificate has expired.",
        "acme_pending" => "A certificate is being requested from the certificate authority (ACME). Until it is issued the server uses a self-signed certificate.",
        "acme_failing" => "Requesting or renewing a certificate through ACME is failing; see the server log.",
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

/// <summary>
/// Certificate warnings: only a self-signed certificate in use, certificates close to or past expiry, and the state of ACME: <c>acme_pending</c> while
/// the first certificate is awaited and <c>acme_failing</c> while an order or a renewal fails (with the last error and the next attempt, from the
/// renewal state in the config store, so every replica says the same). The self-signed certificate keeps serving meanwhile.
/// </summary>
public sealed class CertificateHealthContributor(IStorage storage, IClock clock, Mta.Host.Configuration.MtaConfig? config = null) : IHealthContributor
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

        if (config is null || config.Acme.Enabled)
        {
            var acmeWarning = await AcmeWarningAsync(certificates, now, cancellationToken).ConfigureAwait(false);
            if (acmeWarning is not null)
            {
                warnings.Add(acmeWarning);
            }
        }

        return new HealthReport(true, warnings, new Dictionary<string, string>());
    }

    private async ValueTask<HealthWarning?> AcmeWarningAsync(IReadOnlyList<CertificateRecord> active, DateTimeOffset now, CancellationToken ct)
    {
        var renewals = await storage.Config.GetAcmeRenewalsAsync(ct).ConfigureAwait(false);
        // Only what the renewal service retries by itself is a state worth a banner; a failed record of names nobody retries is in the admin view only.
        var retried = config is null ? null : AcmeFailureCategory.RetriedNames(config.Acme, active);
        var failing = renewals.Where(r => r.Status == "failed" && (retried is null || retried.Contains(r.CertificateName)))
            .OrderBy(r => r.CertificateName == config?.Acme.CertificateName ? 0 : 1).ThenBy(r => r.CertificateName, StringComparer.Ordinal).ToList();
        if (failing.Count > 0)
        {
            var row = failing[0];
            var current = active.Where(c => c.Source == "acme" && c.Name == row.CertificateName).OrderByDescending(c => c.NotAfter).FirstOrDefault();
            string serving = current is null
                ? (active.All(c => c.Source == "selfsigned") ? "Until one is issued the server uses a self-signed certificate." : "The server keeps using the certificate it has.")
                : current.NotAfter <= now
                    ? $"The previous certificate expired on {current.NotAfter:yyyy-MM-dd}."
                    : $"The previous certificate stays in use until {current.NotAfter:yyyy-MM-dd}.";
            string next = row.NextAttemptAt is { } at ? $" Next attempt: {at:yyyy-MM-dd HH:mm} UTC." : "";
            string more = failing.Count > 1 ? $" ({failing.Count - 1} more certificate{(failing.Count > 2 ? "s" : "")} failing.)" : "";
            // The category only, never the error text: this endpoint is unauthenticated. The text is in the log and in the admin view.
            return new HealthWarning("acme_failing",
                $"Getting a certificate from the certificate authority failed {row.Failures} time{(row.Failures == 1 ? "" : "s")} in a row: {AcmeFailureCategory.Describe(row.LastError)}.{next} {serving}{more} Details: server log and the ACME renewals in the admin certificates page.");
        }

        if (config is not null && config.Acme.Domains.Count > 0
            && !active.Any(c => c.Source == "acme" && c.Name == config.Acme.CertificateName && c.NotAfter > now))
        {
            string names = string.Join(", ", config.Acme.Domains);
            return new HealthWarning("acme_pending",
                $"The certificate for {names} is being requested from the certificate authority. {(active.All(c => c.Source == "selfsigned") ? "Until it is issued the server uses a self-signed certificate; this takes a few minutes after the first start." : "Until it is issued the server keeps using the certificate it has.")}");
        }

        return null;
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
    private readonly bool _inboundEnabled;
    private readonly string _version;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private (long At, HealthReport Report)? _cached;

    public CapabilitiesService(IStorage storage, StorageOptions storageOptions, ApiOptions options, HealthService health, IClock clock, Mta.Host.Configuration.MtaConfig? config = null)
    {
        _inboundEnabled = config?.Inbound.Enabled ?? false;
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
            // A contributor that threw is reported with the exception text; unauthenticated callers must not see it (host names, paths, user names).
            report = report with
            {
                Warnings = report.Warnings.Select(w => w.Code.EndsWith("_check_failed", StringComparison.Ordinal) ? new HealthWarning(w.Code, "A health check failed; see the server log.") : w).ToList(),
            };
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
            new InboundCapability(_inboundEnabled),
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
