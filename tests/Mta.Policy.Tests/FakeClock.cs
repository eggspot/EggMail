using Mta.Core;

namespace Mta.Policy.Tests;

/// <summary>Manually advanced clock. Thread-safe.</summary>
public sealed class FakeClock : IClock
{
    private long _utcTicks;

    public FakeClock(DateTimeOffset? start = null) =>
        _utcTicks = (start ?? new DateTimeOffset(2026, 10, 12, 8, 30, 0, TimeSpan.Zero)).UtcTicks;

    public DateTimeOffset UtcNow => new(Interlocked.Read(ref _utcTicks), TimeSpan.Zero);

    public long Timestamp => Interlocked.Read(ref _utcTicks);

    public void Advance(TimeSpan by) => Interlocked.Add(ref _utcTicks, by.Ticks);

    public void Set(DateTimeOffset to) => Interlocked.Exchange(ref _utcTicks, to.UtcTicks);
}

/// <summary>Random source returning a fixed value, to test jitter bounds exactly.</summary>
public sealed class FixedRandom(double value) : IRandomSource
{
    public double NextDouble() => value;
}
