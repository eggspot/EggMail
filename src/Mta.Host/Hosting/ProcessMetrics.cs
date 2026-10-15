using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Globalization;

namespace Mta.Host.Hosting;

/// <summary>
/// Meters of the server process itself (<c>Mta.Process</c>) that the .NET runtime meter does not carry: open file descriptors and operating-system
/// threads. They exist so that a long run (the 7-day soak of <c>docs/go-live-checklist.md</c>) can judge "descriptors and threads stay flat" from the
/// same <c>/metrics</c> endpoint as everything else, instead of from outside the container (the chiseled image has no shell). Gauges only: a scrape
/// reads the operating system's counters for this process and touches nothing else (no database, no lock held by the mail path).
/// <para>On Linux both come from <c>/proc/self</c>; elsewhere the descriptor gauge reports nothing (no series) rather than a made-up number.</para>
/// </summary>
public static class ProcessMetrics
{
    public static readonly Meter Meter = new("Mta.Process");

    /// <summary>Open file descriptors (sockets and files). A steady climb under constant load is a leak. Linux only.</summary>
    public static readonly ObservableGauge<long> OpenFileDescriptors = Meter.CreateObservableGauge("mta.process.open_fds", ObserveOpenFileDescriptors, "{descriptor}", "Open file descriptors of the server process (Linux)");

    /// <summary>Operating-system threads of the process (not only the thread pool's).</summary>
    public static readonly ObservableGauge<long> Threads = Meter.CreateObservableGauge("mta.process.threads", ObserveThreads, "{thread}", "Operating-system threads of the server process");

    private static IEnumerable<Measurement<long>> ObserveOpenFileDescriptors()
    {
        if (CountOpenFileDescriptors() is { } count)
        {
            yield return new Measurement<long>(count);
        }
    }

    private static IEnumerable<Measurement<long>> ObserveThreads()
    {
        yield return new Measurement<long>(CountThreads());
    }

    /// <summary>Entries of <c>/proc/self/fd</c> (the directory listing itself opens one descriptor, which is counted out), or null where that does not exist.</summary>
    internal static long? CountOpenFileDescriptors(string procFdDirectory = "/proc/self/fd")
    {
        try
        {
            if (!Directory.Exists(procFdDirectory))
            {
                return null;
            }

            long count = 0;
            foreach (string _ in Directory.EnumerateFileSystemEntries(procFdDirectory))
            {
                count++;
            }

            return Math.Max(0, count - 1);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>The <c>Threads:</c> line of <c>/proc/self/status</c> on Linux, otherwise the thread count the process API reports.</summary>
    internal static long CountThreads(string procStatusFile = "/proc/self/status")
    {
        try
        {
            if (File.Exists(procStatusFile))
            {
                foreach (string line in File.ReadLines(procStatusFile))
                {
                    if (line.StartsWith("Threads:", StringComparison.Ordinal) && long.TryParse(line.AsSpan(8).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out long threads))
                    {
                        return threads;
                    }
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // fall through to the portable answer
        }

        using Process process = Process.GetCurrentProcess();
        return process.Threads.Count;
    }
}
