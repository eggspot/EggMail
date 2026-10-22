using Microsoft.Extensions.Hosting;
using Mta.Core;

namespace Mta.Host.Hosting;

/// <summary>Starts the SMTP listeners and drains them on shutdown.</summary>
internal sealed class SmtpListenerService(EggMailRuntime runtime) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        runtime.SmtpServer.Start();
        foreach (var (name, endpoint) in runtime.SmtpServer.LocalEndPoints)
        {
            runtime.Log.Write(MtaLogLevel.Information, "smtp", $"listener {name} on {endpoint}");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => runtime.SmtpServer.StopAsync(TimeSpan.FromSeconds(20));
}

/// <summary>
/// Keeps the receive path's copy of the inbound domains and routes fresh (every 30 seconds, and when the API asks). It loads once in <see cref="StartAsync"/>, before the SMTP listeners open, so the
/// first sender does not meet a receiver that does not know its domains yet (a load that fails leaves the listener answering <c>451</c> until a refresh works). Nothing to do without inbound mail.
/// </summary>
internal sealed class InboundConfigurationService(EggMailRuntime runtime) : BackgroundService
{
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        if (runtime.InboundConfiguration is { } cache)
        {
            try
            {
                await cache.RefreshAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                runtime.Log.Write(MtaLogLevel.Warning, "inbound", "could not load the inbound domains at start; inbound mail is deferred with 451 until a refresh succeeds", ex);
            }
        }

        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken) => runtime.InboundConfiguration is { } cache ? cache.RunAsync(stoppingToken) : Task.CompletedTask;
}

/// <summary>
/// Coordinates with the other replicas on the same database (live set, shares of the per-destination limits, slowdowns and open circuits learned from remote servers)
/// every few seconds and leaves the replica set when the host stops, so the others take over this replica's share at once. Nothing to do without replica coordination.
/// It joins the set in <see cref="StartAsync"/>, before the services registered after it (the delivery engine) start, so this replica sends at its share from the first message.
/// </summary>
internal sealed class ReplicaCoordinationService(EggMailRuntime runtime) : BackgroundService
{
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        if (runtime.ReplicaCoordinator is { } coordinator)
        {
            try
            {
                await coordinator.RunOnceAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                runtime.Log.Write(MtaLogLevel.Warning, "replicas", "could not join the replica set at start; the periodic coordination will retry (the destination ceilings are not shared until it succeeds)", ex);
            }
        }

        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (runtime.ReplicaCoordinator is { } coordinator)
        {
            await coordinator.RunAsync(stoppingToken).ConfigureAwait(false);
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
        if (runtime.ReplicaCoordinator is { } coordinator)
        {
            using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await coordinator.LeaveAsync(limit.Token).ConfigureAwait(false);
        }
    }
}

/// <summary>Runs the delivery engine.</summary>
internal sealed class DeliveryService(EggMailRuntime runtime) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => runtime.Delivery.RunAsync(stoppingToken);
}

/// <summary>Runs the webhook dispatcher.</summary>
internal sealed class WebhookService(EggMailRuntime runtime) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => runtime.Webhooks.RunAsync(stoppingToken);
}

/// <summary>Runs the route actions of received mail (inbound webhook and forward actions).</summary>
internal sealed class InboundActionService(EggMailRuntime runtime) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => runtime.InboundActions.RunAsync(stoppingToken);
}

/// <summary>Certificate hot reload from the database and (when enabled) ACME renewal.</summary>
internal sealed class CertificateService(EggMailRuntime runtime) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var tasks = new List<Task> { runtime.Certificates.RunAsync(stoppingToken) };
        if (runtime.Acme is { } acme)
        {
            tasks.Add(acme.RunAsync(stoppingToken));
        }

        if (runtime.AcmeHttpListener is { } listener)
        {
            tasks.Add(listener.RunAsync(stoppingToken));   // on every replica: the CA connects to whichever one the load balancer picks
        }

        return Task.WhenAll(tasks);
    }
}

/// <summary>Rotates the VERP signing keys and reloads the key set every few minutes (decision 110).</summary>
internal sealed class VerpKeyRotationService(EggMailRuntime runtime) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => runtime.VerpKeys.RunAsync(stoppingToken);
}

/// <summary>Retention, rollups and other upkeep of the storage backend, every few minutes.</summary>
internal sealed class MaintenanceService(EggMailRuntime runtime) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);
        try
        {
            do
            {
                try
                {
                    var reports = await runtime.Storage.Maintenance.RunAsync(runtime.Clock.UtcNow, stoppingToken).ConfigureAwait(false);
                    foreach (var r in reports.Where(r => r.RowsAffected > 0))
                    {
                        runtime.Log.Write(MtaLogLevel.Information, "maintenance", $"{r.Job}: {r.RowsAffected} rows in {r.Duration.TotalMilliseconds:F0} ms");
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    runtime.Log.Write(MtaLogLevel.Error, "maintenance", "maintenance run failed", ex);
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
        }
    }
}

/// <summary>
/// Writes the state the process keeps in memory for speed (sending counters every 10 seconds, TLS-RPT counters every minute) to the storage, and once more at shutdown. Registered before the
/// services that produce that state, so it stops after them and the last counts are written.
/// </summary>
public sealed class RuntimeStateService(EggMailRuntime runtime) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(10);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);
        int tick = 0;
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                // The TLS-RPT counters are a journal (one row per domain and flush), so they are written less often than the counters.
                await runtime.FlushRuntimeStateAsync(stoppingToken, includeTlsReports: ++tick % 6 == 0).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await runtime.FlushRuntimeStateAsync(limit.Token).ConfigureAwait(false);
    }
}

/// <summary>Sends the TLS-RPT reports of completed days, hourly.</summary>
internal sealed class TlsReportService(EggMailRuntime runtime) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (runtime.TlsReports is not { } sender)
        {
            return;
        }

        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        try
        {
            do
            {
                try
                {
                    int sent = await sender.RunOnceAsync(stoppingToken).ConfigureAwait(false);
                    if (sent > 0)
                    {
                        runtime.Log.Write(MtaLogLevel.Information, "tlsrpt", $"sent {sent} TLS report(s)");
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    runtime.Log.Write(MtaLogLevel.Error, "tlsrpt", "report run failed", ex);
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
        }
    }
}

/// <summary>Scheduled backups of the SQLite files (PostgreSQL deployments back up with their own tools).</summary>
internal sealed class BackupService(EggMailRuntime runtime) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var backup = runtime.Config.Backup;
        if (!backup.Enabled || runtime.Storage.Backend != Mta.Storage.StorageBackend.Sqlite)
        {
            return;
        }

        string directory = backup.Directory ?? Path.Combine(runtime.Config.Storage.Sqlite.DataDirectory, "backups");
        using var scheduler = new Backup.BackupScheduler(runtime.Storage, runtime.Clock, directory, TimeSpan.FromHours(backup.IntervalHours), backup.Keep, runtime.Log);
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(10));
        try
        {
            // First check shortly after start so a fresh install gets its first backup soon, then every ten minutes whether one is due.
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken).ConfigureAwait(false);
            do
            {
                try
                {
                    await scheduler.RunOnceAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    runtime.Log.Write(MtaLogLevel.Error, "backup", "backup failed", ex);
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
        }
    }
}

/// <summary>Keeps the sending caps (tenant overrides, warm-up) in step with the config store.</summary>
internal sealed class SendingLimitsService(EggMailRuntime runtime) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        try
        {
            do
            {
                try
                {
                    await SendingConfigurator.RefreshAsync(runtime.Limits, runtime.Config.Sending, runtime.Storage.Config, stoppingToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    runtime.Log.Write(MtaLogLevel.Warning, "sending", "could not refresh sending limits", ex);
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
        }
    }
}
