namespace Mta.Core;

/// <summary>Time source abstraction; every time-dependent component takes one so tests can control time.</summary>
public interface IClock
{
    DateTimeOffset UtcNow { get; }

    /// <summary>Monotonic timestamp in ticks (use for measuring durations, not for wall-clock time).</summary>
    long Timestamp { get; }
}

/// <summary>The real clock.</summary>
public sealed class SystemClock : IClock
{
    public static readonly SystemClock Instance = new();

    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;

    public long Timestamp => System.Diagnostics.Stopwatch.GetTimestamp();
}
