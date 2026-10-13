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

/// <summary>Storage write-pressure indicators for the advisory "consider switching backend" hint (decision C). Optional: only backends that can measure it register one.</summary>
public interface IStoragePressureSource
{
    StoragePressure Get();
}

public sealed record StoragePressure(long WriterQueueDepth, long WriterQueueOverThresholdSeconds, double CommitP99Ms, bool Advisory);

/// <summary>When this process started (for the uptime in the admin status).</summary>
public sealed class ApiRuntimeInfo(IClock clock)
{
    public DateTimeOffset StartedAt { get; } = clock.UtcNow;
}
