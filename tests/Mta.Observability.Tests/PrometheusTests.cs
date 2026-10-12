using System.Diagnostics.Metrics;
using Microsoft.Extensions.Logging;
using Mta.Core;
using Mta.Observability;

namespace Mta.Observability.Tests;

public class PrometheusTests
{
    [Fact]
    public void Renders_counters_gauges_and_histograms()
    {
        using var meter = new Meter("Mta.Test.Prom");
        using var exporter = new PrometheusTextExporter(m => m.Name == "Mta.Test.Prom");
        var counter = meter.CreateCounter<long>("mta.test.messages", "{message}", "Messages");
        var updown = meter.CreateUpDownCounter<long>("mta.test.active", "{session}", "Active sessions");
        var hist = meter.CreateHistogram<double>("mta.test.duration", "s", "Duration");
        counter.Add(3, new KeyValuePair<string, object?>("listener", "sub\"mission"));
        counter.Add(2, new KeyValuePair<string, object?>("listener", "sub\"mission"));
        updown.Add(5);
        updown.Add(-2);
        hist.Record(0.002);
        hist.Record(0.3);
        meter.CreateObservableGauge("mta.test.queue", () => 7L, "{delivery}", "Queue depth");

        string text = exporter.Render();
        Assert.Contains("# TYPE mta_test_messages_total counter", text);
        Assert.Contains("mta_test_messages_total{listener=\"sub\\\"mission\"} 5", text);
        Assert.Contains("# TYPE mta_test_active gauge", text);
        Assert.Contains("mta_test_active 3", text);
        Assert.Contains("# TYPE mta_test_duration_seconds histogram", text);
        Assert.Contains("mta_test_duration_seconds_count 2", text);
        Assert.Contains("mta_test_duration_seconds_bucket{le=\"0.005\"} 1", text);
        Assert.Contains("mta_test_duration_seconds_bucket{le=\"+Inf\"} 2", text);
        Assert.Contains("mta_test_queue 7", text);
    }

    [Fact]
    public void Ignores_foreign_meters()
    {
        using var meter = new Meter("Other.Meter");
        using var exporter = new PrometheusTextExporter();
        meter.CreateCounter<long>("other.counter").Add(1);
        Assert.DoesNotContain("other_counter", exporter.Render());
    }

    private sealed class Fake(string name, bool ready, params HealthWarning[] warnings) : IHealthContributor
    {
        public string Name => name;
        public ValueTask<HealthReport> CheckAsync(CancellationToken ct) =>
            ready || warnings.Length > 0 ? ValueTask.FromResult(new HealthReport(ready, warnings, new Dictionary<string, string> { ["k"] = "v" })) : throw new InvalidOperationException("boom");
    }

    [Fact]
    public async Task Health_aggregation()
    {
        var svc = new HealthService([new Fake("storage", true, new HealthWarning("sqlite_sync_off", "x")), new Fake("tls", true)]);
        var r = await svc.CheckAsync(default);
        Assert.True(r.Ready);
        Assert.Single(r.Warnings);
        Assert.Equal("v", r.Details["storage.k"]);
        var bad = await new HealthService([new Fake("db", false)]).CheckAsync(default);
        Assert.False(bad.Ready);
        Assert.Contains(bad.Warnings, w => w.Code == "db_check_failed");
    }

    private sealed class Capture : ILoggerProvider, ILogger
    {
        public List<(LogLevel Level, string Category, string Text)> Entries { get; init; } = [];
        private string _category = "";
        public ILogger CreateLogger(string categoryName) => new Capture { _category = categoryName, Entries = Entries };
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, _category, formatter(state, exception)));
        public void Dispose() { }
    }

    [Fact]
    public void Log_adapter_maps_levels_and_categories()
    {
        var capture = new Capture();
        var factory = LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Warning).AddProvider(capture));
        IMtaLog log = new MtaLogAdapter(factory);
        Assert.False(log.IsEnabled(MtaLogLevel.Information));
        Assert.True(log.IsEnabled(MtaLogLevel.Error));
        log.Write(MtaLogLevel.Information, "test", "dropped");
        log.Write(MtaLogLevel.Warning, "smtp.server", "hello");
        var entry = Assert.Single(capture.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Equal("Mta.smtp.server", entry.Category);
        Assert.Equal("hello", entry.Text);
    }
}
