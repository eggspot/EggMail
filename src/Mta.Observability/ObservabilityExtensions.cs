using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Exporter;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Mta.Core;

namespace Mta.Observability;

/// <summary>How OTLP is carried: gRPC (default port 4317) or HTTP with protobuf bodies (default port 4318).</summary>
public enum OtlpTransport
{
    Grpc,
    HttpProtobuf,
}

public sealed class ObservabilityOptions
{
    /// <summary>OTLP endpoint (for example http://collector:4317). Null or empty disables every OTLP exporter, and with it every span.</summary>
    public string? OtlpEndpoint { get; init; }

    public OtlpTransport OtlpTransport { get; init; } = OtlpTransport.Grpc;

    /// <summary>
    /// Share of messages whose trace is exported. The decision is made from the message id (<see cref="MessageTrace.SampleRatio"/>), so a message is
    /// either traced in all of its spans (submission, queue wait, every delivery attempt, every webhook) or in none.
    /// </summary>
    public double TraceSampleRatio { get; init; } = 0.1;

    public string ServiceName { get; init; } = "eggmail";

    public string ServiceVersion { get; init; } = "0.0.0";

    public bool OtlpEnabled => !string.IsNullOrWhiteSpace(OtlpEndpoint);

    /// <summary>Keep the Prometheus text exporter (the <c>/metrics</c> endpoint). Off: no meter listener of ours exists and the instruments cost nothing for it.</summary>
    public bool PrometheusEnabled { get; init; } = true;
}

public static class ObservabilityExtensions
{
    /// <summary>
    /// Registers the logging adapter, the Prometheus text exporter, health aggregation and, when <see cref="ObservabilityOptions.OtlpEndpoint"/> is set,
    /// the OTLP exporters for metrics and traces (logs: see <see cref="AddMtaOtlpLogging"/>). Without an endpoint no OpenTelemetry pipeline exists, so
    /// instruments and activity sources have no listener beyond the Prometheus exporter and cost next to nothing.
    /// </summary>
    public static IServiceCollection AddMtaObservability(this IServiceCollection services, ObservabilityOptions options)
    {
        services.AddSingleton<IMtaLog>(sp => new MtaLogAdapter(sp.GetRequiredService<ILoggerFactory>()));
        if (options.PrometheusEnabled)
        {
            services.AddSingleton<PrometheusTextExporter>();
            services.AddHostedService<MetricsListenerStarter>();   // a MeterListener only sees measurements made after it started: create it with the host, not at the first scrape
        }

        services.AddSingleton<HealthService>();
        if (!options.OtlpEnabled)
        {
            return services;
        }

        MessageTrace.SampleRatio = options.TraceSampleRatio;
        var otel = services.AddOpenTelemetry().ConfigureResource(r => r.AddService(options.ServiceName, serviceVersion: options.ServiceVersion));
        otel.WithMetrics(m =>
        {
            m.AddMeter("Mta.*", "Npgsql");
            m.AddOtlpExporter(o => Configure(o, options, "v1/metrics"));
        });
        otel.WithTracing(t =>
        {
            t.AddSource(MessageTrace.SourceName);
            t.SetSampler(new AlwaysOnSampler());   // the share of messages is decided before a span exists (MessageTrace.SampleRatio)
            t.AddOtlpExporter(o => Configure(o, options, "v1/traces"));
        });
        return services;
    }

    /// <summary>
    /// Sends log records to OTLP as well (when an endpoint is set). Call it for every logger factory whose output should be exported: the one behind
    /// <see cref="IMtaLog"/> and the host's own.
    /// </summary>
    public static ILoggingBuilder AddMtaOtlpLogging(this ILoggingBuilder logging, ObservabilityOptions options)
    {
        if (options.OtlpEnabled)
        {
            // The provider is built by the dependency injection container (not by AddOpenTelemetry(Action<OpenTelemetryLoggerOptions>), which
            // keeps it private), so it is disposed with the container and can be reached.
            logging.Services.AddOpenTelemetry()
                .ConfigureResource(r => r.AddService(options.ServiceName, serviceVersion: options.ServiceVersion))
                .WithLogging(
                    l => l.AddOtlpExporter(e => Configure(e, options, "v1/logs")),
                    o => o.IncludeFormattedMessage = true);

            // The container disposes the exporter without delivering what it still holds (up to a few seconds of records, and the last ones are the
            // interesting ones), so a host flushes it when it stops. A logger factory outside a host flushes through OtlpLoggerFactory.
            logging.Services.AddHostedService(sp => new FlushLogsOnStop(sp.GetRequiredService<LoggerProvider>()));
        }

        return logging;
    }

    private static void Configure(OtlpExporterOptions exporter, ObservabilityOptions options, string httpSignalPath)
    {
        string endpoint = options.OtlpEndpoint!.Trim();
        if (options.OtlpTransport == OtlpTransport.HttpProtobuf)
        {
            // In code the endpoint is used as given, so the signal path is ours to add (the environment variable form adds it by itself).
            exporter.Protocol = OtlpExportProtocol.HttpProtobuf;
            exporter.Endpoint = new Uri(endpoint.TrimEnd('/') + "/" + httpSignalPath);
        }
        else
        {
            exporter.Protocol = OtlpExportProtocol.Grpc;
            exporter.Endpoint = new Uri(endpoint);
        }
    }

    private sealed class FlushLogsOnStop(LoggerProvider exporter) : IHostedService
    {
        public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public Task StopAsync(CancellationToken cancellationToken)
        {
            exporter.ForceFlush(5000);
            return Task.CompletedTask;
        }
    }

    /// <summary>Forces the Prometheus exporter (a <see cref="System.Diagnostics.Metrics.MeterListener"/>) to exist from the start of the host.</summary>
    private sealed class MetricsListenerStarter(PrometheusTextExporter exporter) : IHostedService
    {
        public Task StartAsync(CancellationToken cancellationToken)
        {
            _ = exporter;
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}

/// <summary>
/// A logger factory (for the log of the runtime, which exists before the host does) that exports to OTLP when an endpoint is configured and
/// delivers the records still queued when it is disposed.
/// </summary>
public sealed class OtlpLoggerFactory : IDisposable
{
    private readonly ServiceProvider _services;

    private OtlpLoggerFactory(ServiceProvider services)
    {
        _services = services;
        Factory = services.GetRequiredService<ILoggerFactory>();
    }

    public ILoggerFactory Factory { get; }

    /// <summary>Creates the factory; <paramref name="configure"/> adds the local providers (console), the OTLP exporter is added when configured.</summary>
    public static OtlpLoggerFactory Create(ObservabilityOptions options, Action<ILoggingBuilder> configure)
    {
        var services = new ServiceCollection();
        services.AddLogging(b =>
        {
            configure(b);
            b.AddMtaOtlpLogging(options);
        });
        return new OtlpLoggerFactory(services.BuildServiceProvider());
    }

    public void Dispose()
    {
        try
        {
            _services.GetService<LoggerProvider>()?.ForceFlush(5000);
        }
        finally
        {
            _services.Dispose();
        }
    }
}
