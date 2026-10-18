using System.Diagnostics;
using Mta.Core;

namespace Mta.RemoteMta.Tests.Harness;

/// <summary>
/// The clock of a lab: it starts at the real current time (certificates are issued relative to it) and then moves only when the test advances it.
/// Retry delays, lifetimes, policy caches, idle timeouts and certificate validity all read this clock, so a five day retry schedule takes no time.
/// </summary>
public sealed class FakeClock : IClock
{
    private long _utcTicks;
    private long _monotonic;

    public FakeClock(DateTimeOffset? start = null)
    {
        // Whole seconds: the stores keep instants at millisecond precision, and a test compares due times exactly.
        var begin = start ?? DateTimeOffset.UtcNow;
        _utcTicks = begin.UtcTicks - (begin.UtcTicks % TimeSpan.TicksPerSecond);
        _monotonic = Stopwatch.Frequency;
    }

    public DateTimeOffset UtcNow => new(Interlocked.Read(ref _utcTicks), TimeSpan.Zero);

    /// <summary>Monotonic ticks in <see cref="Stopwatch"/> units, moved by <see cref="Advance"/> like the wall clock.</summary>
    public long Timestamp => Interlocked.Read(ref _monotonic);

    public void Advance(TimeSpan by)
    {
        Interlocked.Add(ref _utcTicks, by.Ticks);
        Interlocked.Add(ref _monotonic, (long)(by.TotalSeconds * Stopwatch.Frequency));
    }
}
