using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Mta.Core;
using Mta.Observability;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace Mta.Observability.Tests;

/// <summary>Spans, metrics and logs really leave the process: an in-process OTLP/HTTP receiver sees the three signals on their paths.</summary>
[Collection("activity-source")]
public sealed class OtlpExportTests : IDisposable
{
    private sealed record Received(string Path, string? ContentType, byte[] Body);

    private readonly HttpListener _listener = new();
    private readonly ConcurrentQueue<Received> _requests = new();
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _loop;
    private readonly string _endpoint;

    public OtlpExportTests()
    {
        int port;
        using (var probe = new TcpListener(IPAddress.Loopback, 0))
        {
            probe.Start();
            port = ((IPEndPoint)probe.LocalEndpoint).Port;
        }

        _endpoint = $"http://127.0.0.1:{port}/";
        _listener.Prefixes.Add(_endpoint);
        _listener.Start();
        _loop = Task.Run(async () =>
        {
            while (!_stop.IsCancellationRequested)
            {
                HttpListenerContext context;
                try
                {
                    context = await _listener.GetContextAsync();
                }
                catch (Exception ex) when (ex is HttpListenerException or ObjectDisposedException or InvalidOperationException)
                {
                    return;
                }

                using var ms = new MemoryStream();
                await context.Request.InputStream.CopyToAsync(ms);
                _requests.Enqueue(new Received(context.Request.Url!.AbsolutePath, context.Request.ContentType, ms.ToArray()));
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/x-protobuf";
                context.Response.Close();
            }
        });
    }

    public void Dispose()
    {
        _stop.Cancel();
        _listener.Close();
        _loop.Wait(TimeSpan.FromSeconds(5));
        _stop.Dispose();
    }

    private async Task<Received> WaitForAsync(string path)
    {
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (DateTime.UtcNow < deadline)
        {
            if (_requests.FirstOrDefault(r => r.Path == path) is { } found)
            {
                return found;
            }

            await Task.Delay(25);
        }

        throw new TimeoutException($"no request on {path}; saw: {string.Join(", ", _requests.Select(r => r.Path))}");
    }

    private ObservabilityOptions Options() => new() { OtlpEndpoint = _endpoint, OtlpTransport = OtlpTransport.HttpProtobuf, TraceSampleRatio = 1 };

    [Fact]
    public async Task A_span_of_a_message_is_exported_to_the_traces_path_with_the_message_id_as_trace_id()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMtaObservability(Options());
        using ServiceProvider sp = services.BuildServiceProvider();
        TracerProvider tracer = sp.GetRequiredService<TracerProvider>();
        Guid message = Ids.New();

        using (var span = MessageTrace.Start(MessageTrace.SubmitSpan, message))
        {
            Assert.NotNull(span);
        }

        Assert.True(tracer.ForceFlush(10_000));
        Received request = await WaitForAsync("/v1/traces");

        Assert.Equal("application/x-protobuf", request.ContentType);
        // The trace id is 16 raw bytes in the protobuf; the message id is the same 16 bytes in RFC 4122 order.
        byte[] traceId = new byte[16];
        message.TryWriteBytes(traceId, bigEndian: true, out _);
        Assert.True(request.Body.AsSpan().IndexOf(traceId) >= 0, "the exported span carries the message id as its trace id");
        Assert.True(request.Body.AsSpan().IndexOf("mta.submit"u8) >= 0);
    }

    [Fact]
    public async Task Mta_metrics_are_exported_to_the_metrics_path()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMtaObservability(Options());
        using ServiceProvider sp = services.BuildServiceProvider();
        MeterProvider meters = sp.GetRequiredService<MeterProvider>();
        using var meter = new Meter("Mta.Test.OtlpExport");
        meter.CreateCounter<long>("mta.test.otlp.sent", "{message}").Add(3);

        Assert.True(meters.ForceFlush(10_000));
        Received request = await WaitForAsync("/v1/metrics");

        Assert.Equal("application/x-protobuf", request.ContentType);
        Assert.True(request.Body.AsSpan().IndexOf("mta.test.otlp.sent"u8) >= 0);
    }

    [Fact]
    public async Task Log_records_are_exported_to_the_logs_path()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddMtaOtlpLogging(Options()));
        using ServiceProvider sp = services.BuildServiceProvider();
        sp.GetRequiredService<ILoggerFactory>().CreateLogger("Mta.delivery").LogWarning("queue sample failed for test {Reason}", "unit-test");

        Assert.True(sp.GetRequiredService<OpenTelemetry.Logs.LoggerProvider>().ForceFlush(10_000));
        Received request = await WaitForAsync("/v1/logs");

        Assert.Equal("application/x-protobuf", request.ContentType);
        Assert.True(request.Body.AsSpan().IndexOf("queue sample failed for test unit-test"u8) >= 0);
    }

    [Fact]
    public async Task Disposing_the_provider_delivers_what_is_still_queued()
    {
        Guid message = Ids.New();
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddMtaObservability(Options());
            using ServiceProvider sp = services.BuildServiceProvider();
            _ = sp.GetRequiredService<TracerProvider>();
            using (MessageTrace.Start(MessageTrace.DeliveryAttemptSpan, message)) { }
        }   // no explicit flush: the process is shutting down

        Received request = await WaitForAsync("/v1/traces");
        byte[] traceId = new byte[16];
        message.TryWriteBytes(traceId, bigEndian: true, out _);
        Assert.True(request.Body.AsSpan().IndexOf(traceId) >= 0);
    }

    [Fact]
    public async Task Disposing_the_otlp_logger_factory_delivers_the_last_log_records()
    {
        using (var logs = OtlpLoggerFactory.Create(Options(), _ => { }))
        {
            logs.Factory.CreateLogger("Mta.delivery").LogError("the very last record {Reason}", "shutdown");
        }

        Received request = await WaitForAsync("/v1/logs");
        Assert.True(request.Body.AsSpan().IndexOf("the very last record shutdown"u8) >= 0);
    }

    [Fact]
    public async Task A_host_flushes_the_logs_when_it_stops()
    {
        var builder = Microsoft.Extensions.Hosting.Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders().AddMtaOtlpLogging(Options());
        using var host = builder.Build();
        await host.StartAsync();
        host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Mta.smtp").LogWarning("stopping with a record queued {Reason}", "host");

        await host.StopAsync();

        Received request = await WaitForAsync("/v1/logs");
        Assert.True(request.Body.AsSpan().IndexOf("stopping with a record queued host"u8) >= 0);
    }
}
