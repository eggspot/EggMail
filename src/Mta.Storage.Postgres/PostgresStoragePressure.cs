using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Mta.Storage.Postgres;

/// <summary>
/// The advisory storage-pressure figures of the PostgreSQL backend (decision 109): how the runtime connection pool copes, from Npgsql's own pool
/// instruments. Advisory only: nothing in EggMail acts on it; the dashboard shows it.
/// </summary>
/// <param name="PendingRequests">Callers waiting for a free pooled connection right now.</param>
/// <param name="ConnectionsInUse">Pooled connections in use at the last sample.</param>
/// <param name="MaxPoolSize">The pool's size limit at the last sample (zero before the first sample).</param>
/// <param name="WaitingPercent">Share of the samples in <see cref="PostgresOptions.PressureWindow"/> that found a caller waiting, 0 to 100.</param>
/// <param name="Samples">Samples in the window.</param>
/// <param name="Timeouts">Connection requests that timed out waiting for the pool in the window.</param>
/// <param name="Advisory">The waiting share reached <see cref="PostgresOptions.PressureWaitingPercent"/> over enough samples, or a request timed out.</param>
public sealed record PostgresStoragePressure(long PendingRequests, long ConnectionsInUse, long MaxPoolSize, double WaitingPercent, int Samples, long Timeouts, bool Advisory)
{
    /// <summary>Samples the window needs before the waiting share counts (or half of what the window holds, if fewer), so one busy moment after a start does not turn the indicator on.</summary>
    public const int MinSamples = 20;

    /// <param name="samples">The ring, in any order; unwritten slots have <see cref="PoolSample.At"/> zero.</param>
    /// <param name="pendingNow">The live count of waiting callers.</param>
    /// <param name="now">A <see cref="Stopwatch"/> timestamp.</param>
    internal static PostgresStoragePressure Measure(ReadOnlySpan<PoolSample> samples, long pendingNow, PostgresOptions options, long now)
    {
        long since = now - (long)(options.PressureWindow.TotalSeconds * Stopwatch.Frequency);
        int count = 0;
        int waiting = 0;
        long timeouts = 0;
        PoolSample latest = default;
        foreach (PoolSample s in samples)
        {
            if (s.At == 0 || s.At < since || s.At > now)
            {
                continue;
            }

            count++;
            waiting += s.Pending > 0 ? 1 : 0;
            timeouts += s.Timeouts;
            if (s.At > latest.At)
            {
                latest = s;
            }
        }

        double percent = count == 0 ? 0 : Math.Round(100.0 * waiting / count, 1);
        bool advisory = (count >= RequiredSamples(options) && percent >= options.PressureWaitingPercent) || timeouts > 0;
        return new PostgresStoragePressure(Math.Max(0, pendingNow), latest.Used, latest.Max, percent, count, timeouts, advisory);
    }

    /// <summary>Samples the waiting share needs: <see cref="MinSamples"/>, or half of what the window holds when that is fewer (timer jitter can push one sample out of a short window).</summary>
    internal static int RequiredSamples(PostgresOptions options) => Math.Min(MinSamples, Math.Max(1, SamplesInWindow(options) / 2));

    /// <summary>How many samples one window holds at the configured interval.</summary>
    internal static int SamplesInWindow(PostgresOptions options) =>
        (int)Math.Clamp(Math.Ceiling(options.PressureWindow.TotalSeconds / options.PressureSampleInterval.TotalSeconds), 1, PostgresPoolSampler.MaxRingSize);
}

/// <summary>One sample of the pool: when (a <see cref="Stopwatch"/> timestamp), callers waiting, connections in use, the pool limit, and timeouts since the previous sample.</summary>
internal readonly record struct PoolSample(long At, long Pending, long Used, long Max, long Timeouts);

/// <summary>
/// Samples one Npgsql pool (by its <c>db.client.connection.pool.name</c>) every <see cref="PostgresOptions.PressureSampleInterval"/> into a fixed ring
/// (decision 109). It listens to four instruments of the <c>Npgsql</c> meter only: the pending-request counter and the timeout counter report on the
/// pool's slow path (a caller that has to wait), the connection count and limit are observable and cost nothing until a sample reads them. Pools of the
/// same name in one process (several storages during a backend switch, or tests) are summed.
/// </summary>
internal sealed class PostgresPoolSampler : IDisposable
{
    internal const int MaxRingSize = 4096;

    private const string PoolNameTag = "db.client.connection.pool.name";
    private const string StateTag = "db.client.connection.state";

    private enum Kind { Pending, Count, Max, Timeouts }

    private readonly string _poolName;
    private readonly PostgresOptions _options;
    private readonly MeterListener _listener;
    private readonly Timer? _timer;
    private readonly PoolSample[] _ring;
    private readonly Lock _gate = new();
    private int _next;
    private long _pending; // running sum of the pending-request deltas, at least zero
    private long _timeouts; // since the previous sample
    private long _used; // filled while a sample reads the observable instruments (under _gate)
    private long _max;

    /// <param name="startTimer">False in tests that call <see cref="Sample"/> themselves.</param>
    public PostgresPoolSampler(string poolName, PostgresOptions options, bool startTimer = true)
    {
        _poolName = poolName;
        _options = options;
        _ring = new PoolSample[PostgresStoragePressure.SamplesInWindow(options) + 1]; // one spare, so a late tick never leaves the window a sample short
        _listener = new MeterListener
        {
            InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name != "Npgsql")
                {
                    return;
                }

                Kind? kind = instrument.Name switch
                {
                    "db.client.connection.npgsql.pending_requests" => Kind.Pending,
                    "db.client.connection.count" => Kind.Count,
                    "db.client.connection.max" => Kind.Max,
                    "db.client.connection.npgsql.timeouts" => Kind.Timeouts,
                    _ => null,
                };
                if (kind is { } k)
                {
                    listener.EnableMeasurementEvents(instrument, k);
                }
            },
        };
        _listener.SetMeasurementEventCallback<int>((_, value, tags, state) => OnMeasurement(value, tags, state));
        _listener.SetMeasurementEventCallback<long>((_, value, tags, state) => OnMeasurement(value, tags, state));
        _listener.Start();
        if (startTimer)
        {
            _timer = new Timer(_ => SampleQuietly(), null, options.PressureSampleInterval, options.PressureSampleInterval);
        }
    }

    /// <summary>Takes one sample into the ring (the timer's work; tests call it directly).</summary>
    public void Sample()
    {
        lock (_gate)
        {
            PoolSample s = ReadNow();
            _ring[_next] = s with { Timeouts = Interlocked.Exchange(ref _timeouts, 0) };
            _next = (_next + 1) % _ring.Length;
        }
    }

    // An exception from a timer callback would end the process; a missed sample of an advisory figure is harmless (a tick racing Dispose, for example).
    private void SampleQuietly()
    {
        try
        {
            Sample();
        }
        catch (Exception)
        {
        }
    }

    /// <summary>The figures over the window, with the live count of waiting callers.</summary>
    public PostgresStoragePressure Measure()
    {
        lock (_gate)
        {
            return PostgresStoragePressure.Measure(_ring, Interlocked.Read(ref _pending), _options, Stopwatch.GetTimestamp());
        }
    }

    public void Dispose()
    {
        _timer?.Dispose();
        _listener.Dispose();
    }

    private PoolSample ReadNow()
    {
        _used = 0;
        _max = 0;
        _listener.RecordObservableInstruments();
        return new PoolSample(Stopwatch.GetTimestamp(), Interlocked.Read(ref _pending), _used, _max, 0);
    }

    /// <summary>
    /// Adds a pending-request delta, never going below zero: a caller that started waiting before the listener did (a storage started while another
    /// pool of the same name is busy) reports only its decrement, and a negative sum would hide every later wait for good.
    /// </summary>
    internal void AddPending(long delta)
    {
        long current;
        long next;
        do
        {
            current = Interlocked.Read(ref _pending);
            next = Math.Max(0, current + delta);
        }
        while (Interlocked.CompareExchange(ref _pending, next, current) != current);
    }

    private void OnMeasurement(long value, ReadOnlySpan<KeyValuePair<string, object?>> tags, object? state)
    {
        bool ours = false;
        bool used = false;
        foreach (KeyValuePair<string, object?> tag in tags)
        {
            if (tag.Key == PoolNameTag)
            {
                ours = tag.Value is string name && name == _poolName;
            }
            else if (tag.Key == StateTag)
            {
                used = tag.Value is string s && s == "used";
            }
        }

        if (!ours)
        {
            return;
        }

        switch ((Kind)state!)
        {
            case Kind.Pending:
                AddPending(value);
                break;
            case Kind.Timeouts:
                Interlocked.Add(ref _timeouts, value);
                break;
            case Kind.Count when used:
                _used += value; // observable: only reported inside RecordObservableInstruments, under _gate
                break;
            case Kind.Max:
                _max += value;
                break;
        }
    }
}
