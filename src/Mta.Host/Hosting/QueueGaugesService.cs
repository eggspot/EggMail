using Microsoft.Extensions.Hosting;
using Mta.Delivery;

namespace Mta.Host.Hosting;

/// <summary>Keeps the queue gauges (<c>mta_delivery_queue_*</c>) fresh: one sample of the queue every few seconds, never one per scrape.</summary>
internal sealed class QueueGaugesService(EggMailRuntime runtime, TimeSpan interval) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) =>
        new QueueGauges(runtime.Storage.Deliveries, runtime.Clock, runtime.Log, interval).RunAsync(stoppingToken);
}
