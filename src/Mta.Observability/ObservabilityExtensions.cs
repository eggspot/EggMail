using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using Mta.Core;

namespace Mta.Observability;

public sealed class ObservabilityOptions
{
    /// <summary>OTLP endpoint (for example http://collector:4317). Null disables the exporter.</summary>
    public string? OtlpEndpoint { get; init; }

    public string ServiceName { get; init; } = "eggmail";

    public string ServiceVersion { get; init; } = "0.0.0";
}

public static class ObservabilityExtensions
{
    /// <summary>Registers the logging adapter, the Prometheus text exporter, health aggregation and (optionally) OTLP metrics.</summary>
    public static IServiceCollection AddMtaObservability(this IServiceCollection services, ObservabilityOptions options)
    {
        services.AddSingleton<IMtaLog>(sp => new MtaLogAdapter(sp.GetRequiredService<ILoggerFactory>()));
        services.AddSingleton<PrometheusTextExporter>();
        services.AddSingleton<HealthService>();
        var otel = services.AddOpenTelemetry().ConfigureResource(r => r.AddService(options.ServiceName, serviceVersion: options.ServiceVersion));
        otel.WithMetrics(m =>
        {
            m.AddMeter("Mta.*");
            if (!string.IsNullOrWhiteSpace(options.OtlpEndpoint))
            {
                m.AddOtlpExporter(o => o.Endpoint = new Uri(options.OtlpEndpoint));
            }
        });
        return services;
    }
}
