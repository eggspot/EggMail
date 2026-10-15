using System.Diagnostics.Metrics;
using Mta.Observability;

namespace Mta.Observability.Tests;

public class ExporterBehaviourTests
{
    private static KeyValuePair<string, object?> Tag(string key, object? value) => new(key, value);

    [Fact]
    public void Single_tag_multi_tag_and_untagged_measurements_get_separate_series()
    {
        using var meter = new Meter("Mta.Test.Tags");
        using var exporter = new PrometheusTextExporter(m => m.Name == "Mta.Test.Tags");
        var counter = meter.CreateCounter<long>("mta.test.events", "{event}", "Events");
        counter.Add(1);
        counter.Add(2, Tag("outcome", "ok"));
        counter.Add(3, Tag("outcome", "ok"));
        counter.Add(4, Tag("outcome", "bad"));
        counter.Add(5, Tag("outcome", "ok"), Tag("route", "direct"));
        counter.Add(6, Tag("other", "x"));   // a different key than the first single-tag use: still its own labelled series

        string text = exporter.Render();
        Assert.Contains("mta_test_events_total 1\n", text);
        Assert.Contains("mta_test_events_total{outcome=\"ok\"} 5\n", text);
        Assert.Contains("mta_test_events_total{outcome=\"bad\"} 4\n", text);
        Assert.Contains("mta_test_events_total{outcome=\"ok\",route=\"direct\"} 5\n", text);
        Assert.Contains("mta_test_events_total{other=\"x\"} 6\n", text);
        Assert.Equal(1, CountOccurrences(text, "# TYPE mta_test_events_total counter"));
    }

    [Fact]
    public void Concurrent_counter_updates_are_not_lost()
    {
        using var meter = new Meter("Mta.Test.Concurrent");
        using var exporter = new PrometheusTextExporter(m => m.Name == "Mta.Test.Concurrent");
        var counter = meter.CreateCounter<long>("mta.test.hits", "{hit}", "Hits");
        var hist = meter.CreateHistogram<double>("mta.test.latency", "s", "Latency");
        Parallel.For(0, 8, _ =>
        {
            for (int i = 0; i < 5000; i++)
            {
                counter.Add(1, Tag("kind", "a"));
                hist.Record(0.003);
            }
        });

        string text = exporter.Render();
        Assert.Contains("mta_test_hits_total{kind=\"a\"} 40000\n", text);
        Assert.Contains("mta_test_latency_seconds_count 40000\n", text);
        Assert.Contains("mta_test_latency_seconds_bucket{le=\"0.005\"} 40000\n", text);
        Assert.Contains("mta_test_latency_seconds_bucket{le=\"0.0025\"} 0\n", text);
    }

    [Fact]
    public void Histograms_not_in_seconds_use_count_buckets()
    {
        using var meter = new Meter("Mta.Test.Buckets");
        using var exporter = new PrometheusTextExporter(m => m.Name == "Mta.Test.Buckets");
        var batch = meter.CreateHistogram<long>("mta.test.batch.size", "{command}", "Batch size");
        batch.Record(1);
        batch.Record(40);
        batch.Record(700);

        string text = exporter.Render();
        Assert.Contains("mta_test_batch_size_bucket{le=\"1\"} 1\n", text);
        Assert.Contains("mta_test_batch_size_bucket{le=\"50\"} 2\n", text);
        Assert.Contains("mta_test_batch_size_bucket{le=\"1000\"} 3\n", text);
        Assert.Contains("mta_test_batch_size_bucket{le=\"+Inf\"} 3\n", text);
        Assert.Contains("mta_test_batch_size_sum 741\n", text);
    }

    [Fact]
    public void Observable_series_that_disappear_are_not_reported_stale()
    {
        using var meter = new Meter("Mta.Test.Observable");
        using var exporter = new PrometheusTextExporter(m => m.Name == "Mta.Test.Observable");
        var present = new List<string> { "a", "b" };
        meter.CreateObservableGauge("mta.test.members", () => present.Select(p => new Measurement<long>(1, Tag("member", p))).ToList(), "{member}", "Members");

        string first = exporter.Render();
        Assert.Contains("mta_test_members{member=\"a\"} 1\n", first);
        Assert.Contains("mta_test_members{member=\"b\"} 1\n", first);

        present.Remove("b");
        string second = exporter.Render();
        Assert.Contains("mta_test_members{member=\"a\"} 1\n", second);
        Assert.DoesNotContain("member=\"b\"", second);

        present.Clear();
        Assert.DoesNotContain("mta_test_members", exporter.Render());
    }

    [Fact]
    public void Observable_counters_are_exposed_as_counters_with_their_cumulative_value()
    {
        using var meter = new Meter("Mta.Test.ObservableCounter");
        using var exporter = new PrometheusTextExporter(m => m.Name == "Mta.Test.ObservableCounter");
        long total = 10;
        meter.CreateObservableCounter("mta.test.bytes.sent", () => total, "By", "Bytes sent");

        Assert.Contains("# TYPE mta_test_bytes_sent_bytes_total counter", exporter.Render());
        total = 25;
        Assert.Contains("mta_test_bytes_sent_bytes_total 25\n", exporter.Render());   // set, not summed with the earlier pull
    }

    [Fact]
    public void A_metric_keeps_at_most_the_series_limit()
    {
        using var meter = new Meter("Mta.Test.Cardinality");
        using var exporter = new PrometheusTextExporter(m => m.Name == "Mta.Test.Cardinality");
        var counter = meter.CreateCounter<long>("mta.test.byuser", "{event}", "Per user");
        for (int i = 0; i < PrometheusTextExporter.MaxSeriesPerMetric + 500; i++)
        {
            counter.Add(1, Tag("user", "u" + i));
        }

        string text = exporter.Render();
        Assert.Equal(PrometheusTextExporter.MaxSeriesPerMetric, CountOccurrences(text, "mta_test_byuser_total{"));
        counter.Add(1, Tag("user", "u0"));   // an existing series keeps counting
        Assert.Contains("mta_test_byuser_total{user=\"u0\"} 2\n", exporter.Render());
    }

    [Fact]
    public void A_number_and_its_text_are_the_same_label_value()
    {
        using var meter = new Meter("Mta.Test.BoxedKeys");
        using var exporter = new PrometheusTextExporter(m => m.Name == "Mta.Test.BoxedKeys");
        var counter = meter.CreateCounter<long>("mta.test.coded", "{event}", "By code");
        counter.Add(1, Tag("code", 250));
        counter.Add(2, Tag("code", "250"));
        counter.Add(4, Tag("code", 250L));

        string text = exporter.Render();
        Assert.Equal(1, CountOccurrences(text, "mta_test_coded_total{"));
        Assert.Contains("mta_test_coded_total{code=\"250\"} 7\n", text);
    }

    [Fact]
    public void Refused_series_are_counted_and_reported()
    {
        long before = PrometheusTextExporter.DroppedSeries;
        using var meter = new Meter("Mta.Test.Dropped");
        using var exporter = new PrometheusTextExporter(m => m.Name == "Mta.Test.Dropped");
        var counter = meter.CreateCounter<long>("mta.test.unbounded", "{event}", "Unbounded");
        for (int i = 0; i < PrometheusTextExporter.MaxSeriesPerMetric + 10; i++)
        {
            counter.Add(1, Tag("id", "x" + i));
        }

        Assert.True(PrometheusTextExporter.DroppedSeries - before >= 10);
        Assert.Contains("# TYPE eggmail_exporter_dropped_series_total counter", exporter.Render());
    }

    [Fact]
    public void Names_and_types_follow_the_prometheus_conventions()
    {
        using var meter = new Meter("Mta.Test.Names");
        Assert.Equal("mta_test_a_total", PrometheusTextExporter.NameFor(meter.CreateCounter<long>("mta.test.a", "{x}")));
        Assert.Equal("mta_test_dur_seconds", PrometheusTextExporter.NameFor(meter.CreateHistogram<double>("mta.test.dur", "s")));
        Assert.Equal("mta_test_size_bytes", PrometheusTextExporter.NameFor(meter.CreateObservableGauge("mta.test.size", () => 1L, "By")));
        Assert.Equal("gauge", PrometheusTextExporter.TypeFor(meter.CreateUpDownCounter<long>("mta.test.updown")));
        Assert.Equal("histogram", PrometheusTextExporter.TypeFor(meter.CreateHistogram<double>("mta.test.h")));
        Assert.Equal("counter", PrometheusTextExporter.TypeFor(meter.CreateObservableCounter("mta.test.oc", () => 1L)));
    }

    [Fact]
    public void Default_meter_filter_covers_mta_and_the_npgsql_pool_and_command_meters()
    {
        Assert.True(PrometheusTextExporter.IsDefaultMeter(new Meter("Mta.Delivery")));
        Assert.True(PrometheusTextExporter.IsDefaultMeter(new Meter("Npgsql")));
        Assert.True(PrometheusTextExporter.IsDefaultMeter(new Meter("System.Runtime")));
        Assert.False(PrometheusTextExporter.IsDefaultMeter(new Meter("System.Net.Http")));
        Assert.False(PrometheusTextExporter.IsDefaultMeter(new Meter("Mta")));   // "Mta." is the namespace, a meter literally called Mta is not ours
    }

    private static int CountOccurrences(string text, string needle)
    {
        int count = 0;
        for (int at = text.IndexOf(needle, StringComparison.Ordinal); at >= 0; at = text.IndexOf(needle, at + needle.Length, StringComparison.Ordinal))
        {
            count++;
        }

        return count;
    }
}
