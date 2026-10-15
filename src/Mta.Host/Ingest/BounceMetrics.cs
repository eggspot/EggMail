using System.Diagnostics.Metrics;

namespace Mta.Host.Ingest;

/// <summary>Meters of the bounce listener (<c>Mta.Bounce</c>).</summary>
public static class BounceMetrics
{
    public static readonly Meter Meter = new("Mta.Bounce");

    /// <summary>
    /// Reports (bounces and complaints) that arrived under a valid bounce address and were not acted on because they name an address outside the
    /// domain the bounce address was issued for (<c>kind</c> is <c>bounce</c> or <c>complaint</c>). A steady trickle is forwarded mail whose
    /// server does not return the Original-Recipient; a burst is somebody trying to get addresses suppressed.
    /// </summary>
    public static readonly Counter<long> ReportsIgnored = Meter.CreateCounter<long>("mta.bounce.reports.ignored", "{report}", "Bounce and complaint reports ignored because they name an address outside the destination domain of their bounce address, by kind");
}
