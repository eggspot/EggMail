using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Mta.Core;
using Mta.Observability;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace Mta.Observability.Tests;

/// <summary>The OTLP pipelines exist only when an endpoint is configured; without one, nothing listens to the activity source.</summary>
[Collection("activity-source")]
public class OtlpWiringTests
{
    private static ServiceProvider Build(ObservabilityOptions options)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMtaObservability(options);
        return services.BuildServiceProvider();
    }

    [Fact]
    public void Without_an_endpoint_no_tracer_or_meter_pipeline_is_built_and_spans_are_free()
    {
        using ServiceProvider sp = Build(new ObservabilityOptions());

        Assert.Null(sp.GetService<TracerProvider>());
        Assert.Null(sp.GetService<MeterProvider>());
        Assert.False(MessageTrace.IsEnabled);
        Assert.Null(MessageTrace.Start(MessageTrace.SubmitSpan, Guid.NewGuid()));
        Assert.NotNull(sp.GetRequiredService<PrometheusTextExporter>());   // /metrics does not depend on OTLP
    }

    [Theory]
    [InlineData(OtlpTransport.Grpc, "http://127.0.0.1:1")]
    [InlineData(OtlpTransport.HttpProtobuf, "http://127.0.0.1:1/")]
    public void With_an_endpoint_the_message_source_is_listened_to_and_the_sampler_decides_by_message(OtlpTransport transport, string endpoint)
    {
        using (ServiceProvider sp = Build(new ObservabilityOptions { OtlpEndpoint = endpoint, OtlpTransport = transport, TraceSampleRatio = 0 }))
        {
            Assert.NotNull(sp.GetRequiredService<TracerProvider>());
            Assert.NotNull(sp.GetRequiredService<MeterProvider>());
            Assert.True(MessageTrace.IsEnabled);

            // Ratio 0: the sampler drops every trace, so no span is created or exported.
            Assert.Null(MessageTrace.Start(MessageTrace.DeliveryAttemptSpan, Guid.NewGuid()));
        }

        Assert.False(MessageTrace.IsEnabled);   // disposing the provider detaches the listener
    }

    [Fact]
    public void Ratio_one_samples_every_message()
    {
        using ServiceProvider sp = Build(new ObservabilityOptions { OtlpEndpoint = "http://127.0.0.1:1", TraceSampleRatio = 1 });
        _ = sp.GetRequiredService<TracerProvider>();

        Guid message = Guid.NewGuid();
        using var span = MessageTrace.Start(MessageTrace.SubmitSpan, message);
        Assert.NotNull(span);
        Assert.Equal(Ids.ToCompact(message), span.TraceId.ToHexString());
    }

    [Fact]
    public void The_log_exporter_exists_only_with_an_endpoint()
    {
        var off = new ServiceCollection();
        off.AddLogging(b => b.AddMtaOtlpLogging(new ObservabilityOptions()));
        using (ServiceProvider sp = off.BuildServiceProvider())
        {
            Assert.Null(sp.GetService<OpenTelemetry.Logs.LoggerProvider>());
        }

        var on = new ServiceCollection();
        on.AddLogging(b => b.AddMtaOtlpLogging(new ObservabilityOptions { OtlpEndpoint = "http://127.0.0.1:1" }));
        using (ServiceProvider sp = on.BuildServiceProvider())
        {
            Assert.NotNull(sp.GetService<OpenTelemetry.Logs.LoggerProvider>());
        }
    }

    [Fact]
    public void Prometheus_can_be_switched_off_and_then_no_exporter_or_listener_exists()
    {
        using ServiceProvider sp = Build(new ObservabilityOptions { PrometheusEnabled = false });

        Assert.Null(sp.GetService<PrometheusTextExporter>());
        Assert.DoesNotContain(sp.GetServices<Microsoft.Extensions.Hosting.IHostedService>(), s => s.GetType().Name == "MetricsListenerStarter");
    }

    [Fact]
    public void Prometheus_is_on_by_default_and_created_with_the_host()
    {
        using ServiceProvider sp = Build(new ObservabilityOptions());

        Assert.Contains(sp.GetServices<Microsoft.Extensions.Hosting.IHostedService>(), s => s.GetType().Name == "MetricsListenerStarter");
    }
}
