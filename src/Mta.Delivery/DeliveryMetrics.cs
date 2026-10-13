using System.Diagnostics.Metrics;

namespace Mta.Delivery;

/// <summary>Meters of the delivery engine (<c>Mta.Delivery</c>).</summary>
public static class DeliveryMetrics
{
    public static readonly Meter Meter = new("Mta.Delivery");

    /// <summary>Recipients finished (or rescheduled) by an attempt, tagged with the outcome.</summary>
    public static readonly Counter<long> Attempts = Meter.CreateCounter<long>("mta.delivery.attempts", "{recipient}", "Delivery attempts by outcome");

    /// <summary>Time from claim to recorded result of one group.</summary>
    public static readonly Histogram<double> GroupDuration = Meter.CreateHistogram<double>("mta.delivery.group.duration", "s", "Duration of one delivery group");

    /// <summary>Deliveries held locally by sending limits or destination throttling (nothing was sent).</summary>
    public static readonly Counter<long> Held = Meter.CreateCounter<long>("mta.delivery.held", "{recipient}", "Deliveries held by local limits");

    public static readonly Counter<long> Claimed = Meter.CreateCounter<long>("mta.delivery.claimed", "{recipient}", "Deliveries claimed from the queue");

    private static readonly KeyValuePair<string, object?>[] OutcomeTags = BuildOutcomeTags();

    /// <summary>The <c>outcome</c> tag of <see cref="Attempts"/> for an outcome: built once per outcome, not per measurement.</summary>
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
}
