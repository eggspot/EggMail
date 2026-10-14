using System.Collections.Concurrent;
using System.Diagnostics.Metrics;

namespace Mta.Delivery.Tests;

/// <summary>Records every measurement of the meters selected by <c>filter</c>, with its tags, so a test can assert on what an instrument reported.</summary>
internal sealed class MeterCapture : IDisposable
{
    public sealed record Measured(string Instrument, double Value, IReadOnlyDictionary<string, object?> Tags);

    private readonly MeterListener _listener = new();
    private readonly ConcurrentQueue<Measured> _measurements = new();

    public MeterCapture(Func<Meter, bool> filter)
    {
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (filter(instrument.Meter))
            {
                listener.EnableMeasurementEvents(instrument);
            }
        };
        _listener.SetMeasurementEventCallback<long>((i, v, t, _) => Add(i, v, t));
        _listener.SetMeasurementEventCallback<int>((i, v, t, _) => Add(i, v, t));
        _listener.SetMeasurementEventCallback<double>((i, v, t, _) => Add(i, v, t));
        _listener.Start();
    }

    public IReadOnlyCollection<Measured> All => _measurements.ToArray();

    /// <summary>Pulls every observable instrument once (what a scrape does).</summary>
    public void Pull() => _listener.RecordObservableInstruments();

    public IEnumerable<Measured> Of(string instrument, params (string Key, object Value)[] tags) =>
        _measurements.Where(m => m.Instrument == instrument && tags.All(t => m.Tags.TryGetValue(t.Key, out object? v) && Equals(v, t.Value)));

    public double Sum(string instrument, params (string Key, object Value)[] tags) => Of(instrument, tags).Sum(m => m.Value);

    public double? Last(string instrument, params (string Key, object Value)[] tags) => Of(instrument, tags).LastOrDefault()?.Value;

    private void Add(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        var dictionary = new Dictionary<string, object?>();
        foreach (KeyValuePair<string, object?> tag in tags)
        {
            dictionary[tag.Key] = tag.Value;
        }

        _measurements.Enqueue(new Measured(instrument.Name, value, dictionary));
    }

    public void Dispose() => _listener.Dispose();
}
