using System.Diagnostics.Metrics;

namespace Mta.Delivery;

public static class DeliveryMetrics
{
    public static readonly Meter Meter = new("Mta.Delivery");

    public static readonly Counter<long> Attempts = Meter.CreateCounter<long>("mta.delivery.attempts", "{recipient}", "Delivery attempts by outcome");

    public static readonly Histogram<double> GroupDuration = Meter.CreateHistogram<double>("mta.delivery.group.duration", "s", "Duration of one delivery group");

    public static readonly Counter<long> Held = Meter.CreateCounter<long>("mta.delivery.held", "{recipient}", "Deliveries held locally: sending limits, destination throttle, a DKIM key that cannot be read");

    public static readonly Counter<long> DkimKeyFailures = Meter.CreateCounter<long>("mta.delivery.dkim.key.failures", "{load}", "DKIM keys that could not be read; their mail is held");

    public static readonly Counter<long> Claimed = Meter.CreateCounter<long>("mta.delivery.claimed", "{recipient}", "Deliveries claimed from the queue");

    private static readonly KeyValuePair<string, object?>[] OutcomeTags = BuildOutcomeTags();

    public static KeyValuePair<string, object?> OutcomeTag(Mta.Storage.DeliveryOutcome outcome) =>
        (int)outcome < OutcomeTags.Length ? OutcomeTags[(int)outcome] : new KeyValuePair<string, object?>("outcome", outcome.ToString().ToLowerInvariant());

    private static KeyValuePair<string, object?>[] BuildOutcomeTags()
    {
        var values = Enum.GetValues<Mta.Storage.DeliveryOutcome>();
        var tags = new KeyValuePair<string, object?>[values.Max(v => (int)v) + 1];
        foreach (var value in values)
        {
            tags[(int)value] = new KeyValuePair<string, object?>("outcome", value.ToString().ToLowerInvariant());
        }

        return tags;
    }

    public static readonly Counter<long> Bounces = Meter.CreateCounter<long>("mta.delivery.bounces.generated", "{message}", "Bounce messages generated");

    public static readonly Histogram<double> ClaimDuration = Meter.CreateHistogram<double>("mta.delivery.claim.duration", "s", "Duration of one queue claim");

    public static readonly Histogram<double> RecordDuration = Meter.CreateHistogram<double>("mta.delivery.record.duration", "s", "Duration of storing the results of one delivery transaction");

    public static readonly Counter<long> QueueSampleFailures = Meter.CreateCounter<long>("mta.delivery.queue.sample.failures", "{sample}", "Queue samples that failed (storage unavailable)");

    private static QueueGauges? s_queue;

    private static QueueSample? Sample => Volatile.Read(ref s_queue)?.Latest;

    public static readonly ObservableGauge<long> QueueDepthGauge = Meter.CreateObservableGauge("mta.delivery.queue.depth", QueueDepth, "{delivery}", "Deliveries in the queue by state (queued: never tried, deferred: waiting for a retry, leased: being delivered); sampled in the background");

    public static readonly ObservableGauge<double> QueueOldestDueAgeGauge = Meter.CreateObservableGauge("mta.delivery.queue.oldest_due_age", OldestDueAge, "s", "How long the oldest due delivery has been waiting, 0 when none is overdue; sampled in the background");

    public static readonly ObservableGauge<long> QueueSpoolSizeGauge = Meter.CreateObservableGauge("mta.delivery.queue.spool.size", SpoolSize, "By", "Bytes of queued message bodies; sampled in the background");

    public static readonly ObservableGauge<double> QueueSampleAgeGauge = Meter.CreateObservableGauge("mta.delivery.queue.sample_age", SampleAge, "s", "Age of the last successful queue sample; alert when it keeps growing, the queue gauges are stale");

    private static IEnumerable<Measurement<long>> QueueDepth()
    {
        if (Sample is { } sample)
        {
            yield return new Measurement<long>(sample.Stats.Queued, new KeyValuePair<string, object?>("state", "queued"));
            yield return new Measurement<long>(sample.Stats.Deferred, new KeyValuePair<string, object?>("state", "deferred"));
            yield return new Measurement<long>(sample.Stats.Leased, new KeyValuePair<string, object?>("state", "leased"));
        }
    }

    private static IEnumerable<Measurement<double>> OldestDueAge()
    {
        if (Volatile.Read(ref s_queue) is { } source && source.Latest is { } sample)
        {
            double age = sample.Stats.OldestDueAt is { } due ? Math.Max(0, (source.Clock.UtcNow - due).TotalSeconds) : 0;
            yield return new Measurement<double>(age);
        }
    }

    private static IEnumerable<Measurement<long>> SpoolSize()
    {
        if (Sample is { } sample)
        {
            yield return new Measurement<long>(sample.Stats.SpoolBytes);
        }
    }

    private static IEnumerable<Measurement<double>> SampleAge()
    {
        if (Volatile.Read(ref s_queue) is { } source && source.Latest is { } sample)
        {
            yield return new Measurement<double>(Math.Max(0, (source.Clock.UtcNow - sample.At).TotalSeconds));
        }
    }

    public static IDisposable AttachQueueGauges(QueueGauges source)
    {
        Volatile.Write(ref s_queue, source);
        return new Detach(source);
    }

    private sealed class Detach(QueueGauges source) : IDisposable
    {
        public void Dispose() => Interlocked.CompareExchange(ref s_queue, null, source);
    }
}
