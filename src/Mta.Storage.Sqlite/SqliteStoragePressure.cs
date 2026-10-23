using System.Diagnostics;

namespace Mta.Storage.Sqlite;

/// <summary>
/// The advisory storage-pressure figures of the SQLite backend (decision C, decision 108), over all four files: the deepest writer queue right now,
/// how long the deepest queue has stayed deep without a break, and the p99 commit latency of the file with the slowest commits in the window.
/// Advisory only: nothing in EggMail acts on it; the dashboard shows it.
/// </summary>
/// <param name="WriterQueueDepth">Commands waiting for the busiest writer right now.</param>
/// <param name="WriterQueueOverThreshold">How long a writer's queue has been at or over <see cref="SqliteOptions.PressureQueueDepth"/> without a break (zero when none is).</param>
/// <param name="CommitP99">p99 commit latency over <see cref="SqliteOptions.PressureWindow"/> of the slowest file with enough commits in the window, else zero.</param>
/// <param name="CommitSamples">Commits the p99 was taken over (zero when no file had enough).</param>
/// <param name="Advisory">The queue stayed deep for <see cref="SqliteOptions.PressureQueueDuration"/>, or the p99 is over <see cref="SqliteOptions.PressureCommitP99"/>.</param>
public sealed record SqliteStoragePressure(long WriterQueueDepth, TimeSpan WriterQueueOverThreshold, TimeSpan CommitP99, int CommitSamples, bool Advisory)
{
    /// <summary>Commits a file needs in the window before its p99 counts, so one slow fsync on an idle server does not turn the indicator on.</summary>
    public const int MinCommitSamples = 20;

    /// <param name="writers">Each writer's live queue length and its metrics.</param>
    /// <param name="now">A <see cref="Stopwatch"/> timestamp.</param>
    internal static SqliteStoragePressure Measure(IEnumerable<(int Pending, WriterMetrics Metrics)> writers, SqliteOptions options, long now)
    {
        long depth = 0;
        long deepTicks = 0;
        long p99Ticks = 0;
        int p99Samples = 0;
        long since = now - (long)(options.PressureWindow.TotalSeconds * Stopwatch.Frequency);
        var samples = new List<long>();
        foreach ((int pending, WriterMetrics metrics) in writers)
        {
            depth = Math.Max(depth, pending);
            long deepSince = metrics.DeepSince;
            if (deepSince != 0 && pending >= options.PressureQueueDepth)
            {
                deepTicks = Math.Max(deepTicks, now - deepSince);
            }

            samples.Clear();
            metrics.CopyCommitsSince(since, samples);
            if (samples.Count >= MinCommitSamples)
            {
                long p99 = Percentile99(samples);
                if (p99 > p99Ticks)
                {
                    p99Ticks = p99;
                    p99Samples = samples.Count;
                }
            }
        }

        TimeSpan deep = Duration(deepTicks);
        TimeSpan commitP99 = Duration(p99Ticks);
        bool advisory = (deepTicks > 0 && deep >= options.PressureQueueDuration) || commitP99 > options.PressureCommitP99;
        return new SqliteStoragePressure(depth, deep, commitP99, p99Samples, advisory);
    }

    /// <summary>Nearest-rank p99 (sorts <paramref name="samples"/>).</summary>
    internal static long Percentile99(List<long> samples)
    {
        samples.Sort();
        int rank = (int)Math.Ceiling(0.99 * samples.Count);
        return samples[Math.Max(rank, 1) - 1];
    }

    // Through double: stopwatch ticks times TimeSpan.TicksPerSecond overflows a long after about 15 minutes where Stopwatch.Frequency is 1 GHz (Linux, macOS).
    private static TimeSpan Duration(long stopwatchTicks) => TimeSpan.FromSeconds((double)stopwatchTicks / Stopwatch.Frequency);
}
