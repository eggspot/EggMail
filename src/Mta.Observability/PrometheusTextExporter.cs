using System.Diagnostics.Metrics;
using System.Globalization;
using System.Text;

namespace Mta.Observability;

/// <summary>
/// Renders every <c>Mta.*</c> meter in the Prometheus text exposition format (0.0.4). Hand-rolled on
/// <see cref="MeterListener"/> because the OpenTelemetry Prometheus exporter is still pre-release (design §10).
/// Counters and gauges are exact; histograms are exposed as <c>_sum</c>/<c>_count</c> plus <c>_bucket</c> series with
/// fixed latency buckets.
/// </summary>
public sealed class PrometheusTextExporter : IDisposable
{
    private static readonly double[] Buckets = [0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60];

    private readonly MeterListener _listener = new();
    private readonly object _lock = new();
    private readonly Dictionary<string, Series> _series = new(StringComparer.Ordinal);
    private readonly Func<Meter, bool> _filter;

    public PrometheusTextExporter(Func<Meter, bool>? filter = null)
    {
        _filter = filter ?? (m => m.Name.StartsWith("Mta.", StringComparison.Ordinal));
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (_filter(instrument.Meter))
            {
                listener.EnableMeasurementEvents(instrument);
            }
        };
        _listener.SetMeasurementEventCallback<long>(OnLong);
        _listener.SetMeasurementEventCallback<int>((i, v, t, s) => OnLong(i, v, t, s));
        _listener.SetMeasurementEventCallback<double>(OnDouble);
        _listener.Start();
    }

    private void OnLong(Instrument instrument, long value, ReadOnlySpan<KeyValuePair<string, object?>> tags, object? state) =>
        Record(instrument, value, tags);

    private void OnDouble(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags, object? state) =>
        Record(instrument, value, tags);

    private void Record(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        string name = MetricName(instrument);
        string labels = Labels(tags);
        lock (_lock)
        {
            string key = name + labels;
            if (!_series.TryGetValue(key, out var s))
            {
                s = new Series(name, labels, Kind(instrument), instrument.Description, instrument.Unit);
                _series[key] = s;
            }

            switch (s.Kind)
            {
                case SeriesKind.Counter:
                case SeriesKind.UpDown:
                    s.Value += value;
                    break;
                case SeriesKind.Histogram:
                    s.Sum += value;
                    s.Count++;
                    for (int i = 0; i < Buckets.Length; i++)
                    {
                        if (value <= Buckets[i]) { s.BucketCounts[i]++; }
                    }

                    break;
                default:
                    s.Value = value;
                    break;
            }
        }
    }

    /// <summary>Pulls current values of observable instruments, then renders all series.</summary>
    public string Render()
    {
        _listener.RecordObservableInstruments();
        var sb = new StringBuilder(4096);
        lock (_lock)
        {
            string? lastName = null;
            foreach (var s in _series.Values.OrderBy(x => x.Name, StringComparer.Ordinal).ThenBy(x => x.Labels, StringComparer.Ordinal))
            {
                if (s.Name != lastName)
                {
                    sb.Append("# HELP ").Append(s.Name).Append(' ').Append(Escape(s.Description ?? s.Name)).Append('\n');
                    sb.Append("# TYPE ").Append(s.Name).Append(' ').Append(s.Kind switch { SeriesKind.Counter => "counter", SeriesKind.Histogram => "histogram", _ => "gauge" }).Append('\n');
                    lastName = s.Name;
                }

                if (s.Kind == SeriesKind.Histogram)
                {
                    for (int i = 0; i < Buckets.Length; i++)
                    {
                        sb.Append(s.Name).Append("_bucket").Append(WithLe(s.Labels, Buckets[i].ToString(CultureInfo.InvariantCulture))).Append(' ').Append(s.BucketCounts[i].ToString(CultureInfo.InvariantCulture)).Append('\n');
                    }

                    sb.Append(s.Name).Append("_bucket").Append(WithLe(s.Labels, "+Inf")).Append(' ').Append(s.Count.ToString(CultureInfo.InvariantCulture)).Append('\n');
                    sb.Append(s.Name).Append("_sum").Append(s.Labels).Append(' ').Append(s.Sum.ToString("R", CultureInfo.InvariantCulture)).Append('\n');
                    sb.Append(s.Name).Append("_count").Append(s.Labels).Append(' ').Append(s.Count.ToString(CultureInfo.InvariantCulture)).Append('\n');
                }
                else
                {
                    sb.Append(s.Name).Append(s.Labels).Append(' ').Append(s.Value.ToString("R", CultureInfo.InvariantCulture)).Append('\n');
                }
            }
        }

        return sb.ToString();
    }

    private static SeriesKind Kind(Instrument i) => i switch
    {
        _ when i.GetType().Name.StartsWith("Histogram", StringComparison.Ordinal) => SeriesKind.Histogram,
        _ when i.GetType().Name.StartsWith("UpDownCounter", StringComparison.Ordinal) => SeriesKind.UpDown,
        _ when i.GetType().Name.StartsWith("Counter", StringComparison.Ordinal) => SeriesKind.Counter,
        _ => SeriesKind.Gauge,
    };

    private static string MetricName(Instrument i)
    {
        var sb = new StringBuilder(i.Name.Length + 8);
        foreach (char c in i.Name)
        {
            sb.Append(char.IsAsciiLetterOrDigit(c) || c == '_' ? c : '_');
        }

        string name = sb.ToString();
        if (i.Unit is "s") { name += "_seconds"; }
        else if (i.Unit is "By") { name += "_bytes"; }
        if (Kind(i) == SeriesKind.Counter && !name.EndsWith("_total", StringComparison.Ordinal)) { name += "_total"; }
        return name;
    }

    private static string Labels(ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        if (tags.Length == 0) { return ""; }
        var pairs = new List<string>(tags.Length);
        foreach (var t in tags)
        {
            pairs.Add($"{Sanitize(t.Key)}=\"{Escape(Convert.ToString(t.Value, CultureInfo.InvariantCulture) ?? "")}\"");
        }

        pairs.Sort(StringComparer.Ordinal);
        return "{" + string.Join(',', pairs) + "}";
    }

    private static string WithLe(string labels, string le) => labels.Length == 0 ? $"{{le=\"{le}\"}}" : labels[..^1] + $",le=\"{le}\"}}";

    private static string Sanitize(string k)
    {
        var sb = new StringBuilder(k.Length);
        foreach (char c in k) { sb.Append(char.IsAsciiLetterOrDigit(c) || c == '_' ? c : '_'); }
        return sb.ToString();
    }

    private static string Escape(string v) => v.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);

    public void Dispose() => _listener.Dispose();

    private enum SeriesKind { Counter, UpDown, Gauge, Histogram }

    private sealed class Series(string name, string labels, SeriesKind kind, string? description, string? unit)
    {
        public readonly string Name = name;
        public readonly string Labels = labels;
        public readonly SeriesKind Kind = kind;
        public readonly string? Description = description;
        public readonly string? Unit = unit;
        public double Value;
        public double Sum;
        public long Count;
        public readonly long[] BucketCounts = new long[Buckets.Length];
    }
}
