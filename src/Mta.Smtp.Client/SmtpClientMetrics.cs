using System.Diagnostics.Metrics;

namespace Mta.Smtp.Client;

public static class SmtpClientMetrics
{
    public static readonly Meter Meter = new("Mta.Smtp.Client");
    public static readonly Counter<long> Connections = Meter.CreateCounter<long>("mta.smtp.client.connections", "{connection}", "Outbound connections established");
    public static readonly Counter<long> TlsHandshakes = Meter.CreateCounter<long>("mta.smtp.client.tls.handshakes", "{handshake}", "Completed outbound TLS handshakes");
    public static readonly Counter<long> TlsFailures = Meter.CreateCounter<long>("mta.smtp.client.tls.failures", "{handshake}", "Failed outbound TLS handshakes");
    public static readonly Counter<long> PoolHits = Meter.CreateCounter<long>("mta.smtp.client.pool.hits", "{connection}", "Connections reused from the pool");
}
