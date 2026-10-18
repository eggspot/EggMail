using Mta.Core;

namespace Mta.TestSupport;

/// <summary>
/// Knobs and the virtual clock shared by the accelerated lifecycle tests (days of virtual time in seconds; see
/// docs/testing-offline-coverage.md, "Accelerated lifecycle and leaks"). The file is linked into each test project that uses it.
/// </summary>
public static class Accelerated
{
    /// <summary>
    /// <c>EGGMAIL_ACCEL_SCALE</c> (default 1) multiplies the iteration counts and virtual spans of the loops that are sized for a CI runner. The pull
    /// request defaults take seconds; <c>EGGMAIL_ACCEL_SCALE=10</c> or more is for a local run.
    /// </summary>
    public static int Scale { get; } = ReadInt("EGGMAIL_ACCEL_SCALE", 1, min: 1);

    /// <summary><c>EGGMAIL_ACCEL_SEED</c> overrides the seed of every randomized interleaving, so a failure that logged its seed can be replayed.</summary>
    public static int Seed(int fallback) => ReadInt("EGGMAIL_ACCEL_SEED", fallback, min: int.MinValue);

    /// <summary>The base count times <see cref="Scale"/>.</summary>
    public static int Scaled(int baseCount) => checked(baseCount * Scale);

    private static int ReadInt(string name, int fallback, int min)
    {
        string? text = Environment.GetEnvironmentVariable(name);
        return int.TryParse(text, out int value) && value >= min ? value : fallback;
    }
}

/// <summary>
/// A clock that only moves when the test moves it. <see cref="Timestamp"/> is the monotonic counter in the unit of
/// <see cref="System.Diagnostics.Stopwatch"/> (what <c>ClockExtensions.GetElapsedTime</c> converts with), derived from the virtual time, so durations
/// measured through the clock are virtual durations. Thread-safe.
/// </summary>
public sealed class VirtualClock : IClock
{
    private long _utcTicks;

    public VirtualClock(DateTimeOffset? start = null) =>
        _utcTicks = (start ?? new DateTimeOffset(2026, 10, 12, 12, 30, 0, TimeSpan.Zero)).UtcTicks;

    public DateTimeOffset UtcNow => new(Interlocked.Read(ref _utcTicks), TimeSpan.Zero);

    public long Timestamp => (long)(Interlocked.Read(ref _utcTicks) * ((double)System.Diagnostics.Stopwatch.Frequency / TimeSpan.TicksPerSecond));

    public void Advance(TimeSpan by) => Interlocked.Add(ref _utcTicks, by.Ticks);

    public void Set(DateTimeOffset to) => Interlocked.Exchange(ref _utcTicks, to.UtcTicks);
}
