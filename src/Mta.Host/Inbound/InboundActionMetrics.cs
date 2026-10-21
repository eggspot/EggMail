using System.Diagnostics.Metrics;

namespace Mta.Host.Inbound;

/// <summary>
/// Meters of the inbound route actions (<c>Mta.Inbound.Actions</c>, design section 11.11). Labels are small fixed sets: never a domain, an address or a tenant.
/// </summary>
public static class InboundActionMetrics
{
    public static readonly Meter Meter = new("Mta.Inbound.Actions");

    /// <summary>Attempts at a route action by kind (<c>webhook</c>, <c>forward</c>, <c>store</c>, <c>discard</c>: the kind of the route when it ran) and outcome (<c>done</c>, <c>retry</c>, <c>failed</c>).</summary>
    public static readonly Counter<long> Actions = Meter.CreateCounter<long>("mta.inbound.actions", "{attempt}", "Inbound route action attempts by kind and outcome (done, retry, failed)");

    /// <summary>Time from claim to recorded result of one attempt.</summary>
    public static readonly Histogram<double> ActionDuration = Meter.CreateHistogram<double>("mta.inbound.action.duration", "s", "Duration of one inbound route action attempt, by kind");

    /// <summary>Forwards refused because the message already went through this server the maximum number of times (<c>loop_detected</c>).</summary>
    public static readonly Counter<long> ForwardLoops = Meter.CreateCounter<long>("mta.inbound.forward.loops", "{message}", "Inbound forwards refused by the signed hop marker (loop_detected)");

    /// <summary>Forwards that were not queued, by <c>reason</c>: <c>unauthenticated_local_sender</c>, <c>unusable_from</c>, <c>forward_target_is_local</c>, <c>forward_backlog_full</c>, <c>invalid_forward_target</c>, <c>srs_failed</c>, <c>forward_key_conflict</c>.</summary>
    public static readonly Counter<long> ForwardRefused = Meter.CreateCounter<long>("mta.inbound.forward.refused", "{message}", "Inbound forwards not queued, by reason");

    // The gauge reads the last sample the runner took (a count of pending and failed actions), so a scrape never queries the message table.
    private static InboundActionRunner? s_runner;

    public static readonly ObservableGauge<long> ActionStates = Meter.CreateObservableGauge("mta.inbound.actions", ObserveStates, "{action}", "Inbound route actions waiting (pending) and given up (failed), sampled in the background");

    internal static void Attach(InboundActionRunner runner) => Volatile.Write(ref s_runner, runner);

    internal static void Detach(InboundActionRunner runner) => Interlocked.CompareExchange(ref s_runner, null, runner);

    private static IEnumerable<Measurement<long>> ObserveStates()
    {
        if (Volatile.Read(ref s_runner)?.LatestCounts is { } usage)
        {
            yield return new Measurement<long>(usage.Pending, new KeyValuePair<string, object?>("state", "pending"));
            yield return new Measurement<long>(usage.Failed, new KeyValuePair<string, object?>("state", "failed"));
        }
    }
}
