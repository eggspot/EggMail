using System.Diagnostics.Metrics;

namespace Mta.Host.Ingest;

/// <summary>Meters of the bounce listener (<c>Mta.Bounce</c>).</summary>
public static class BounceMetrics
{
    public static readonly Meter Meter = new("Mta.Bounce");

    /// <summary>
    /// Reports (bounces and complaints) that arrived under a valid bounce address and were not acted on (<c>kind</c> is <c>bounce</c> or <c>complaint</c>), by
    /// <c>reason</c>: <c>outside_destination_domain</c> (the address is outside the domain the bounce address was issued for), and with per-message history
    /// <c>no_message_id</c> (the report quotes no Message-ID) or <c>not_in_history</c> (the quoted message is unknown, past <c>Retention:MetadataDays</c>, or was not
    /// sent to the address). A steady trickle is forwarded mail whose server does not return the Original-Recipient, or retention shorter than a bounce
    /// address lives; a burst is somebody trying to get addresses suppressed.
    /// </summary>
    public static readonly Counter<long> ReportsIgnored = Meter.CreateCounter<long>("mta.bounce.reports.ignored", "{report}", "Bounce and complaint reports that arrived under a valid bounce address and were not acted on, by kind and reason");
}
