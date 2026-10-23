using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Mta.Core;
using Mta.Host.Tls;
using Mta.Storage;

namespace Mta.Host.Api;

public enum MaintenanceStartResult : byte
{
    Started,
    AlreadyRunning,
}

/// <summary>What the last maintenance run did.</summary>
public sealed record MaintenanceRunState(bool Running, DateTimeOffset? StartedAt, DateTimeOffset? FinishedAt, string? Error, IReadOnlyList<MaintenanceReport> Reports);

/// <summary>
/// Runs <see cref="IStorageMaintenance.RunAsync"/> on request (<c>POST /admin/maintenance/run</c>). A run can take a long time (retention deletes in
/// batches, vacuum), so the request returns at once and at most one run is active.
/// </summary>
public sealed class MaintenanceRunner(IStorage storage, IClock clock, ILogger<MaintenanceRunner> logger, IHostApplicationLifetime? lifetime = null)
{
    private readonly object _gate = new();
    private Task _current = Task.CompletedTask;
    private bool _running;
    private MaintenanceRunState _last = new(false, null, null, null, []);

    /// <summary>The run in progress, or a completed task. Tests await it.</summary>
    public Task Current
    {
        get
        {
            lock (_gate)
            {
                return _current;
            }
        }
    }

    public MaintenanceRunState State
    {
        get
        {
            lock (_gate)
            {
                return _last;
            }
        }
    }

    public MaintenanceStartResult TryStart()
    {
        lock (_gate)
        {
            if (_running)
            {
                return MaintenanceStartResult.AlreadyRunning;
            }

            _running = true;
            DateTimeOffset started = clock.UtcNow;
            _last = new MaintenanceRunState(true, started, null, null, _last.Reports);
            _current = Task.Run(() => RunAsync(started));
            return MaintenanceStartResult.Started;
        }
    }

    private async Task RunAsync(DateTimeOffset started)
    {
        IReadOnlyList<MaintenanceReport> reports = [];
        string? error = null;
        try
        {
            reports = await storage.Maintenance.RunAsync(clock.UtcNow, lifetime?.ApplicationStopping ?? CancellationToken.None).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            error = "Cancelled because the server is stopping.";
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Maintenance run failed");
            error = "The maintenance run failed; see the server log.";
        }
        finally
        {
            lock (_gate)
            {
                _running = false;
                _last = new MaintenanceRunState(false, started, clock.UtcNow, error, reports);
            }
        }
    }
}

public enum AcmeStartResult : byte
{
    Started,
    AlreadyRunning,
    NotConfigured,
}

/// <summary>Starts an ACME certificate order for the given names (<c>POST /admin/certificates/acme</c>).</summary>
public interface IAcmeCertificateRequester
{
    /// <summary>Begins the order in the background (a DNS-01 order takes minutes). The outcome is recorded in the renewal state.</summary>
    AcmeStartResult Start(IReadOnlyList<string> domains);
}

/// <summary>Runs the order through <see cref="AcmeRenewalService"/>; without that service (ACME not configured) there is nothing to start.</summary>
public sealed class AcmeCertificateRequester(ILogger<AcmeCertificateRequester> logger, AcmeRenewalService? service = null, IHostApplicationLifetime? lifetime = null) : IAcmeCertificateRequester
{
    private readonly object _gate = new();
    private Task _current = Task.CompletedTask;
    private bool _running;

    /// <summary>The order in progress, or a completed task. Tests await it.</summary>
    public Task Current
    {
        get
        {
            lock (_gate)
            {
                return _current;
            }
        }
    }

    public AcmeStartResult Start(IReadOnlyList<string> domains)
    {
        if (service is null)
        {
            return AcmeStartResult.NotConfigured;
        }

        lock (_gate)
        {
            if (_running)
            {
                return AcmeStartResult.AlreadyRunning;
            }

            _running = true;
            var names = domains.ToList();
            _current = Task.Run(async () =>
            {
                try
                {
                    await service.RequestAsync(names, lifetime?.ApplicationStopping ?? CancellationToken.None).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "ACME request for {Domains} failed", string.Join(", ", names));
                }
                finally
                {
                    lock (_gate)
                    {
                        _running = false;
                    }
                }
            });
            return AcmeStartResult.Started;
        }
    }
}

/// <summary>The VERP signing keys as the admin API manages them (decision 111): implemented over <c>Hosting.VerpKeyRotation</c> by the process that runs it; absent elsewhere.</summary>
public interface IVerpKeyAdmin
{
    /// <summary>The keys in <c>verp_key</c>, without their key material, with their state now.</summary>
    Task<IReadOnlyList<VerpKeyResponse>> ListAsync(CancellationToken ct);

    /// <summary>A new key that signs at once; the old keys deleted (<paramref name="revokeOldKeys"/>) or retired. Null when another replica holds the key lease; <c>409</c> when no key id is free.</summary>
    Task<VerpKeyRotationResponse?> RotateNowAsync(bool revokeOldKeys, CancellationToken ct);
}

/// <summary>Storage-pressure indicators for the advisory hint on the dashboard (decision C). Optional: only backends that can measure it register one.</summary>
public interface IStoragePressureSource
{
    StoragePressure Get();
}

/// <summary>
/// The figures and the thresholds they are judged against (so the dashboard shows the configured ones, not the defaults). SQLite fills the writer
/// fields (decision 108), PostgreSQL the pool fields (decision 109); the other backend's fields stay null.
/// </summary>
public sealed record StoragePressure(long? WriterQueueDepth, long? WriterQueueOverThresholdSeconds, double? CommitP99Ms, bool Advisory,
    long? QueueDepthThreshold = null, long? QueueThresholdSeconds = null, double? CommitP99ThresholdMs = null)
{
    public long? PoolPendingRequests { get; init; }
    public long? PoolConnectionsInUse { get; init; }
    public long? PoolMaxSize { get; init; }
    public double? PoolWaitingPercent { get; init; }
    public int? PoolSamples { get; init; }
    public long? PoolTimeouts { get; init; }
    public long? PoolWindowSeconds { get; init; }
    public int? PoolWaitingPercentThreshold { get; init; }
}

/// <summary>The pressure source of the SQLite backend (decision 108): the writer queues and commit latency.</summary>
public sealed class SqliteStoragePressureSource(Mta.Storage.Sqlite.SqliteStorage storage, Mta.Storage.SqliteOptions options) : IStoragePressureSource
{
    /// <summary>The source for <paramref name="storage"/>, or null when it is not a SQLite storage.</summary>
    public static IStoragePressureSource? For(IStorage storage) => storage is Mta.Storage.Sqlite.SqliteStorage sqlite ? new SqliteStoragePressureSource(sqlite, sqlite.Options.Sqlite) : null;

    public StoragePressure Get()
    {
        Mta.Storage.Sqlite.SqliteStoragePressure p = storage.GetPressure();
        return new StoragePressure(p.WriterQueueDepth, (long)p.WriterQueueOverThreshold.TotalSeconds, Math.Round(p.CommitP99.TotalMilliseconds, 1), p.Advisory,
            options.PressureQueueDepth, (long)options.PressureQueueDuration.TotalSeconds, options.PressureCommitP99.TotalMilliseconds);
    }
}

/// <summary>The pressure source of the PostgreSQL backend (decision 109): how often callers waited for the runtime connection pool.</summary>
public sealed class PostgresStoragePressureSource(Mta.Storage.Postgres.PostgresStorage storage, Mta.Storage.PostgresOptions options) : IStoragePressureSource
{
    /// <summary>The source for <paramref name="storage"/>, or null when it is not a PostgreSQL storage.</summary>
    public static IStoragePressureSource? For(IStorage storage) => storage is Mta.Storage.Postgres.PostgresStorage pg ? new PostgresStoragePressureSource(pg, pg.Options.Postgres) : null;

    public StoragePressure Get()
    {
        // Before InitializeAsync there is no sampler yet: report an empty window rather than nothing, so the card does not come and go.
        Mta.Storage.Postgres.PostgresStoragePressure p = storage.GetPressure() ?? new(0, 0, 0, 0, 0, 0, false);
        return new StoragePressure(null, null, null, p.Advisory)
        {
            PoolPendingRequests = p.PendingRequests,
            PoolConnectionsInUse = p.ConnectionsInUse,
            PoolMaxSize = p.MaxPoolSize,
            PoolWaitingPercent = p.WaitingPercent,
            PoolSamples = p.Samples,
            PoolTimeouts = p.Timeouts,
            PoolWindowSeconds = (long)options.PressureWindow.TotalSeconds,
            PoolWaitingPercentThreshold = options.PressureWaitingPercent,
        };
    }
}

/// <summary>When this process started (for the uptime in the admin status).</summary>
public sealed class ApiRuntimeInfo(IClock clock)
{
    public DateTimeOffset StartedAt { get; } = clock.UtcNow;
}
