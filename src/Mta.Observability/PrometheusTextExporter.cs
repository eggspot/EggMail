using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Text;

namespace Mta.Observability;

/// <summary>
/// Renders every <c>Mta.*</c> meter (and the <c>Npgsql</c> meter, which carries the PostgreSQL command and pool metrics) in the Prometheus text
/// exposition format (0.0.4). Hand-rolled on <see cref="MeterListener"/> because the OpenTelemetry Prometheus exporter is still pre-release
/// (design §10). Counters and gauges are exact; histograms are exposed as <c>_sum</c>/<c>_count</c> plus <c>_bucket</c> series (latency buckets
/// for instruments in seconds, count buckets otherwise).
/// <para>The measurement callback sits on the hot paths (one call per SMTP command), so it does not allocate for untagged and single-tag
/// measurements and does not take a global lock: counters add with a compare-exchange, gauges store, only histograms lock their own series.
/// A metric accepts at most <see cref="MaxSeriesPerMetric"/> label combinations; further ones are dropped, a safety net behind the rule that
/// labels are bounded sets (never a recipient, a message or a tenant).</para>
/// </summary>
public sealed class PrometheusTextExporter : IDisposable
{
    /// <summary>Upper bound of label combinations kept per metric.</summary>
    public const int MaxSeriesPerMetric = 1000;

    private static readonly double[] LatencyBuckets = [0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60];
    private static readonly double[] CountBuckets = [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];
    private static readonly object NullTagValue = new();
    private static long s_droppedSeries;

    /// <summary>Label combinations refused because a metric reached <see cref="MaxSeriesPerMetric"/> (process-wide); rendered as <c>eggmail_exporter_dropped_series_total</c> once it is above zero.</summary>
    public static long DroppedSeries => Interlocked.Read(ref s_droppedSeries);

    private readonly MeterListener _listener = new();
    private readonly object _renderLock = new();
    private readonly ConcurrentDictionary<string, Family> _families = new(StringComparer.Ordinal);
    private readonly Func<Meter, bool> _filter;

    /// <summary>Meters exported by default: every <c>Mta.*</c> meter and Npgsql's own (PostgreSQL command latency and connection pool).</summary>
    public static bool IsDefaultMeter(Meter meter) => meter.Name.StartsWith("Mta.", StringComparison.Ordinal) || meter.Name == "Npgsql";

    public PrometheusTextExporter(Func<Meter, bool>? filter = null)
    {
        _filter = filter ?? IsDefaultMeter;
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (_filter(instrument.Meter))
            {
                listener.EnableMeasurementEvents(instrument, _families.GetOrAdd(NameFor(instrument), static (n, i) => new Family(n, i), instrument));
            }
        };
        _listener.SetMeasurementEventCallback<long>(static (i, v, t, s) => Record(s, v, t));
        _listener.SetMeasurementEventCallback<int>(static (i, v, t, s) => Record(s, v, t));
        _listener.SetMeasurementEventCallback<double>(static (i, v, t, s) => Record(s, v, t));
        _listener.SetMeasurementEventCallback<short>(static (i, v, t, s) => Record(s, v, t));
        _listener.SetMeasurementEventCallback<byte>(static (i, v, t, s) => Record(s, v, t));
        _listener.SetMeasurementEventCallback<float>(static (i, v, t, s) => Record(s, v, t));
        _listener.SetMeasurementEventCallback<decimal>(static (i, v, t, s) => Record(s, (double)v, t));
        _listener.Start();
    }

    private static void Record(object? state, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        if (state is not Family family)
        {
            return;
        }

        Series? series = family.Resolve(tags);
        if (series is null)
        {
            return;
        }

        switch (family.Kind)
        {
            case SeriesKind.Counter:
            case SeriesKind.UpDown:
                series.Add(value);
                break;
            case SeriesKind.Histogram:
                series.Observe(value, family.Buckets);
                break;
            default:
                series.Set(value);
                break;
        }
    }

    /// <summary>Pulls current values of observable instruments, then renders all series.</summary>
    public string Render()
    {
        var sb = new StringBuilder(4096);
        lock (_renderLock)
        {
            // Observable instruments report their complete current state on every pull, so series that vanished (a removed certificate, a
            // closed writer) must not linger: forget the old ones first.
            foreach (Family f in _families.Values)
            {
                if (f.IsObservable)
                {
                    f.Clear();
                }
            }

            _listener.RecordObservableInstruments();
            foreach (Family f in _families.Values.OrderBy(x => x.Name, StringComparer.Ordinal))
            {
                f.Render(sb);
            }
        }

        if (DroppedSeries > 0)
        {
            sb.Append("# HELP eggmail_exporter_dropped_series_total Label combinations refused because a metric reached its series limit; a label is unbounded somewhere\n");
            sb.Append("# TYPE eggmail_exporter_dropped_series_total counter\n");
            sb.Append("eggmail_exporter_dropped_series_total ").Append(DroppedSeries.ToString(CultureInfo.InvariantCulture)).Append('\n');
        }

        return sb.ToString();
    }

    private static SeriesKind KindOf(Instrument i)
    {
        string type = i.GetType().Name;
        return type switch
        {
            _ when type.StartsWith("Histogram", StringComparison.Ordinal) => SeriesKind.Histogram,
            _ when type.StartsWith("UpDownCounter", StringComparison.Ordinal) => SeriesKind.UpDown,
            _ when type.StartsWith("Counter", StringComparison.Ordinal) => SeriesKind.Counter,
            _ when type.StartsWith("ObservableCounter", StringComparison.Ordinal) => SeriesKind.ObservedCounter,
            _ => SeriesKind.Gauge,
        };
    }

    /// <summary>The Prometheus metric name an instrument is exposed under (dots become underscores; unit and <c>_total</c> suffixes added).</summary>
    public static string NameFor(Instrument instrument)
    {
        var sb = new StringBuilder(instrument.Name.Length + 8);
        foreach (char c in instrument.Name)
        {
            sb.Append(char.IsAsciiLetterOrDigit(c) || c == '_' ? c : '_');
        }

        string name = sb.ToString();
        if (instrument.Unit is "s" && !name.EndsWith("_seconds", StringComparison.Ordinal)) { name += "_seconds"; }
        else if (instrument.Unit is "By" && !name.EndsWith("_bytes", StringComparison.Ordinal)) { name += "_bytes"; }
        if (KindOf(instrument) is SeriesKind.Counter or SeriesKind.ObservedCounter && !name.EndsWith("_total", StringComparison.Ordinal)) { name += "_total"; }
        return name;
    }

    /// <summary>The Prometheus type an instrument is exposed as: <c>counter</c>, <c>gauge</c> or <c>histogram</c>.</summary>
    public static string TypeFor(Instrument instrument) => KindOf(instrument) switch
    {
        SeriesKind.Counter or SeriesKind.ObservedCounter => "counter",
        SeriesKind.Histogram => "histogram",
        _ => "gauge",
    };

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

    private enum SeriesKind { Counter, UpDown, Gauge, Histogram, ObservedCounter }

    /// <summary>All series of one metric name.</summary>
    private sealed class Family
    {
        private readonly object _gate = new();
        private readonly ConcurrentDictionary<object, Series> _single = new();
        private readonly ConcurrentDictionary<string, Series> _byLabels = new(StringComparer.Ordinal);
        private Series? _untagged;
        private string? _singleKey;
        private int _count;

        public Family(string name, Instrument first)
        {
            Name = name;
            Kind = KindOf(first);
            Description = first.Description;
            IsObservable = first.IsObservable;
            Buckets = first.Unit == "s" ? LatencyBuckets : CountBuckets;
        }

        public string Name { get; }

        public SeriesKind Kind { get; }

        public string? Description { get; }

        public bool IsObservable { get; }

        public double[] Buckets { get; }

        public Series? Resolve(ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            if (tags.Length == 0)
            {
                return _untagged ?? CreateUntagged();
            }

            if (tags.Length == 1)
            {
                KeyValuePair<string, object?> tag = tags[0];
                string? key = Volatile.Read(ref _singleKey);
                if (key is null || string.Equals(key, tag.Key, StringComparison.Ordinal))
                {
                    // 1 and "1" are the same label value, so non-strings are keyed by their text (strings, the usual case, allocate nothing).
                    object value = tag.Value switch { null => NullTagValue, string text => text, var other => Convert.ToString(other, CultureInfo.InvariantCulture) ?? "" };
                    return _single.TryGetValue(value, out Series? hit) ? hit : CreateSingle(value, tag);
                }
            }

            string labels = Labels(tags);
            return _byLabels.TryGetValue(labels, out Series? known) ? known : CreateLabelled(labels);
        }

        private Series? CreateUntagged()
        {
            lock (_gate)
            {
                if (_untagged is not null)
                {
                    return _untagged;
                }

                Series? created = Admit(new Series("", Buckets.Length));
                _untagged = created;
                return created;
            }
        }

        private Series? CreateSingle(object value, KeyValuePair<string, object?> tag)
        {
            lock (_gate)
            {
                // The fast path remembers which tag key this metric uses; a different key falls back to the label-string path.
                _singleKey ??= tag.Key;
                if (!string.Equals(_singleKey, tag.Key, StringComparison.Ordinal))
                {
                    return CreateLabelledLocked(Labels([tag]));
                }

                if (_single.TryGetValue(value, out Series? existing))
                {
                    return existing;
                }

                Series? created = Admit(new Series(Labels([tag]), Buckets.Length));
                if (created is not null)
                {
                    _single[value] = created;
                }

                return created;
            }
        }

        private Series? CreateLabelled(string labels)
        {
            lock (_gate)
            {
                return CreateLabelledLocked(labels);
            }
        }

        private Series? CreateLabelledLocked(string labels)
        {
            if (_byLabels.TryGetValue(labels, out Series? existing))
            {
                return existing;
            }

            Series? created = Admit(new Series(labels, Buckets.Length));
            if (created is not null)
            {
                _byLabels[labels] = created;
            }

            return created;
        }

        private Series? Admit(Series series)
        {
            if (_count >= MaxSeriesPerMetric)
            {
                Interlocked.Increment(ref s_droppedSeries);
                return null;
            }

            _count++;
            return series;
        }

        public void Clear()
        {
            lock (_gate)
            {
                _single.Clear();
                _byLabels.Clear();
                _untagged = null;
                _singleKey = null;
                _count = 0;
            }
        }

        public void Render(StringBuilder sb)
        {
            List<Series> all;
            lock (_gate)
            {
                all = new List<Series>(_count);
                if (_untagged is not null) { all.Add(_untagged); }
                all.AddRange(_single.Values);
                all.AddRange(_byLabels.Values);
            }

            if (all.Count == 0)
            {
                return;
            }

            all.Sort((a, b) => string.CompareOrdinal(a.Labels, b.Labels));
            sb.Append("# HELP ").Append(Name).Append(' ').Append(Escape(Description ?? Name)).Append('\n');
            sb.Append("# TYPE ").Append(Name).Append(' ').Append(Kind switch { SeriesKind.Counter or SeriesKind.ObservedCounter => "counter", SeriesKind.Histogram => "histogram", _ => "gauge" }).Append('\n');
            foreach (Series s in all)
            {
                if (Kind == SeriesKind.Histogram)
                {
                    (double sum, long count, long[] buckets) = s.Snapshot();
                    for (int i = 0; i < Buckets.Length; i++)
                    {
                        sb.Append(Name).Append("_bucket").Append(WithLe(s.Labels, Buckets[i].ToString(CultureInfo.InvariantCulture))).Append(' ').Append(buckets[i].ToString(CultureInfo.InvariantCulture)).Append('\n');
                    }

                    sb.Append(Name).Append("_bucket").Append(WithLe(s.Labels, "+Inf")).Append(' ').Append(count.ToString(CultureInfo.InvariantCulture)).Append('\n');
                    sb.Append(Name).Append("_sum").Append(s.Labels).Append(' ').Append(sum.ToString("R", CultureInfo.InvariantCulture)).Append('\n');
                    sb.Append(Name).Append("_count").Append(s.Labels).Append(' ').Append(count.ToString(CultureInfo.InvariantCulture)).Append('\n');
                }
                else
                {
                    sb.Append(Name).Append(s.Labels).Append(' ').Append(s.Value.ToString("R", CultureInfo.InvariantCulture)).Append('\n');
                }
            }
        }
    }

    private sealed class Series(string labels, int bucketCount)
    {
        private readonly object _histogramLock = new();
        private long[]? _buckets;
        private long _count;
        private double _sum;
        private double _value;

        public string Labels { get; } = labels;

        public double Value => Volatile.Read(ref _value);

        public void Add(double delta)
        {
            double current = Volatile.Read(ref _value);
            while (true)
            {
                double seen = Interlocked.CompareExchange(ref _value, current + delta, current);
                if (seen.Equals(current))
                {
                    return;
                }

                current = seen;
            }
        }

        public void Set(double value) => Volatile.Write(ref _value, value);

        public void Observe(double value, double[] bounds)
        {
            lock (_histogramLock)
            {
                _buckets ??= new long[bucketCount];
                _sum += value;
                _count++;
                for (int i = 0; i < bounds.Length; i++)
                {
                    if (value <= bounds[i]) { _buckets[i]++; }
                }
            }
        }

        public (double Sum, long Count, long[] Buckets) Snapshot()
        {
            lock (_histogramLock)
            {
                return (_sum, _count, _buckets is null ? new long[bucketCount] : (long[])_buckets.Clone());
            }
        }
    }
}
