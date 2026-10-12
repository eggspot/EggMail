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

        return Task.WhenAll(tasks);
    }
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
