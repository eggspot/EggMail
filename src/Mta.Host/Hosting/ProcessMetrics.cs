using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Globalization;

namespace Mta.Host.Hosting;

/// <summary>
/// Meters of the server process itself (<c>Mta.Process</c>): resident memory, managed heap, open file descriptors, threads, CPU time and garbage
/// collections. They exist so that a long run (the 7-day soak of <c>docs/go-live-checklist.md</c>) can judge "memory, descriptors and threads stay
/// flat" from the same <c>/metrics</c> endpoint as everything else, instead of from outside the container. Gauges only: a scrape reads the
/// operating system's counters for this process and touches nothing else (no database, no lock held by the mail path).
/// <para>On Linux the descriptor and thread counts come from <c>/proc/self</c>; elsewhere the descriptor gauge reports nothing (no series) rather
/// than a made-up number.</para>
/// </summary>
public static class ProcessMetrics
{
    public static readonly Meter Meter = new("Mta.Process");

    /// <summary>Resident set size (the working set on Windows and macOS).</summary>
    public static readonly ObservableGauge<long> ResidentMemory = Meter.CreateObservableGauge("mta.process.resident_memory", ObserveResidentMemory, "By", "Resident memory of the server process");

    /// <summary>Bytes the garbage collector manages: the managed heap as of the last collection.</summary>
    public static readonly ObservableGauge<long> ManagedHeap = Meter.CreateObservableGauge("mta.process.managed_heap", ObserveManagedHeap, "By", "Managed heap size as of the last garbage collection");

    /// <summary>Open file descriptors (sockets and files). A steady climb under constant load is a leak. Linux only.</summary>
    public static readonly ObservableGauge<long> OpenFileDescriptors = Meter.CreateObservableGauge("mta.process.open_fds", ObserveOpenFileDescriptors, "{descriptor}", "Open file descriptors of the server process (Linux)");

    /// <summary>Operating-system threads of the process.</summary>
    public static readonly ObservableGauge<long> Threads = Meter.CreateObservableGauge("mta.process.threads", ObserveThreads, "{thread}", "Operating-system threads of the server process");

    /// <summary>CPU time used by the process (user plus system), in seconds; take its rate for the CPU share.</summary>
    public static readonly ObservableCounter<double> CpuTime = Meter.CreateObservableCounter("mta.process.cpu.time", ObserveCpuTime, "s", "CPU time used by the server process");

    /// <summary>Garbage collections since the process started, by generation (0, 1, 2).</summary>
    public static readonly ObservableCounter<long> GcCollections = Meter.CreateObservableCounter("mta.process.gc.collections", ObserveGcCollections, "{collection}", "Garbage collections since start, by generation");

    private static IEnumerable<Measurement<long>> ObserveResidentMemory()
    {
        using Process process = Process.GetCurrentProcess();
        yield return new Measurement<long>(process.WorkingSet64);
    }

    private static IEnumerable<Measurement<long>> ObserveManagedHeap()
    {
        yield return new Measurement<long>(GC.GetGCMemoryInfo().HeapSizeBytes);
    }

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

    private static IEnumerable<Measurement<double>> ObserveCpuTime()
    {
        using Process process = Process.GetCurrentProcess();
        yield return new Measurement<double>(process.TotalProcessorTime.TotalSeconds);
    }

    private static IEnumerable<Measurement<long>> ObserveGcCollections()
    {
        for (int generation = 0; generation <= 2; generation++)
        {
            yield return new Measurement<long>(GC.CollectionCount(generation), new KeyValuePair<string, object?>("generation", generation.ToString(CultureInfo.InvariantCulture)));
        }
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
