using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using Mta.Core;

namespace Mta.Host.Tls;

/// <summary>
/// Meters of the certificates this process serves (<c>Mta.Tls</c>). Gauges only: a scrape reads the in-memory snapshot the certificate provider
/// already keeps, nothing touches the database. A certificate that expired is no longer served and therefore no longer listed, so alert on the
/// remaining time <em>and</em> on <c>mta_tls_certificates == 0</c>.
/// </summary>
public static class TlsMetrics
{
    public static readonly Meter Meter = new("Mta.Tls");

    private static readonly ConcurrentDictionary<DatabaseCertificateProvider, IClock> Live = new();

    /// <summary>Seconds until each served certificate expires (leaf <c>NotAfter</c> minus now), tagged with the certificate name and its source (<c>acme</c>, <c>upload</c>, <c>selfsigned</c>, <c>file</c>).</summary>
    public static readonly ObservableGauge<double> CertificateExpiry = Meter.CreateObservableGauge("mta.tls.certificate.expiry", ObserveExpiry, "s", "Seconds until a served TLS certificate expires");

    /// <summary>Certificates currently served.</summary>
    public static readonly ObservableGauge<long> Certificates = Meter.CreateObservableGauge("mta.tls.certificates", ObserveCount, "{certificate}", "TLS certificates currently served");

    /// <summary>Makes the certificates of <paramref name="provider"/> visible to the gauges. Dispose to detach.</summary>
    public static CertificateMeters Attach(DatabaseCertificateProvider provider, IClock clock)
    {
        Live[provider] = clock;
        return new CertificateMeters(provider);
    }

    /// <summary>True while <paramref name="provider"/> is observed by the gauges.</summary>
    public static bool IsAttached(DatabaseCertificateProvider provider) => Live.ContainsKey(provider);

    /// <summary>Providers the gauges currently read (a leak check: disposing the meters must detach the provider).</summary>
    internal static int AttachedCount => Live.Count;

    private static IEnumerable<Measurement<double>> ObserveExpiry()
    {
        foreach ((DatabaseCertificateProvider provider, IClock clock) in Live)
        {
            DateTime now = clock.UtcNow.UtcDateTime;
            foreach (CertificateInfo info in provider.Describe())
            {
                yield return new Measurement<double>(
                    (info.NotAfter.ToUniversalTime() - now).TotalSeconds,
                    new KeyValuePair<string, object?>("name", info.Name),
                    new KeyValuePair<string, object?>("source", info.Source));
            }
        }
    }

    private static IEnumerable<Measurement<long>> ObserveCount()
    {
        foreach (DatabaseCertificateProvider provider in Live.Keys)
        {
            yield return new Measurement<long>(provider.Count);
        }
    }

    /// <summary>Detaches a provider from the gauges when disposed.</summary>
    public sealed class CertificateMeters(DatabaseCertificateProvider provider) : IDisposable, IAsyncDisposable
    {
        public void Dispose() => Live.TryRemove(provider, out _);

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
