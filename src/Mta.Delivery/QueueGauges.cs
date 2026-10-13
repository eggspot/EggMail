using Mta.Core;
using Mta.Storage;

namespace Mta.Delivery;

/// <summary>One reading of the queue: its counts, the oldest due delivery and the spooled bytes, and when it was taken.</summary>
public sealed record QueueSample(QueueStats Stats, DateTimeOffset At);

/// <summary>
/// Samples the queue in the background for the <c>mta_delivery_queue_*</c> gauges. The numbers come from
/// <see cref="IDeliveryStore.GetQueueStatsAsync"/>, which reads the whole queue table, so it runs every few seconds on one task and
/// never per scrape: any number of scrapers (Prometheus, OTLP, the admin status) read the cached <see cref="Latest"/>.
/// A failed sample (storage down) keeps the previous one and is counted; <c>mta_delivery_queue_sample_age_seconds</c> shows the staleness.
/// </summary>
public sealed class QueueGauges(IDeliveryStore store, IClock clock, IMtaLog log, TimeSpan interval)
{
    private QueueSample? _latest;
    private bool _failing;

    public IClock Clock => clock;

    /// <summary>The last successful sample, or null before the first one.</summary>
    public QueueSample? Latest => Volatile.Read(ref _latest);

    /// <summary>Takes one sample. Storage failures are counted and logged once per streak; cancellation propagates.</summary>
    public async Task SampleOnceAsync(CancellationToken cancellationToken)
    {
        try
        {
            QueueStats stats = await store.GetQueueStatsAsync(cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref _latest, new QueueSample(stats, clock.UtcNow));
            _failing = false;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            DeliveryMetrics.QueueSampleFailures.Add(1);
            if (!_failing)
            {
                _failing = true;
                log.Write(MtaLogLevel.Warning, "delivery", "could not sample the queue for the metrics; the gauges keep their last values until it works again", ex);
            }
        }
    }

    /// <summary>Samples now and then every interval until cancelled.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using IDisposable attached = DeliveryMetrics.AttachQueueGauges(this);
        using var timer = new PeriodicTimer(interval);
        try
        {
            do
            {
                await SampleOnceAsync(cancellationToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
        }
    }
}
