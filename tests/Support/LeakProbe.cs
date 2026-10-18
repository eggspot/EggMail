using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Text;

namespace Mta.TestSupport;

/// <summary>
/// "No growth between iteration batches": the leak assertion of the accelerated lifecycle tests (docs/testing-offline-coverage.md, "Accelerated
/// lifecycle and leaks"). It does not assert absolute numbers (they measure the machine and the runtime version, not the code). Instead:
/// <list type="number">
/// <item>one or more <b>warm-up</b> batches run the flow so that JIT, pools, caches, lazily created singletons and the thread pool reach their steady state;</item>
/// <item>then three measured batches B1, B2, B3 of N iterations each run, and before each sample the process is brought to a quiet point
/// (<c>GC.Collect(2, Forced, blocking, compacting)</c>, <c>WaitForPendingFinalizers</c>, collect again, twice);</item>
/// <item>a metric is reported only when it grew by more than its tolerance in <b>both</b> measured intervals, <c>level(B2) - level(B1)</c> and
/// <c>level(B3) - level(B2)</c>. A leak of K per batch shows up as K in both however big the level is; a one-off growth (a cache that fills during B1, a
/// thread-pool thread or a descriptor that happens to be open at one sample) shows up in one interval only and is not reported.</item>
/// </list>
/// Built-in metrics: managed heap after a full collection (tolerance <c>max(256 KiB, 2 % of the level after warm-up)</c>), process thread count (4), open file
/// descriptors (0; <c>/proc/self/fd</c> on Linux, <c>/dev/fd</c> on macOS, not available on Windows and then skipped), active
/// <see cref="Timer"/>s (2; <c>Timer.ActiveCount</c> is the runtime's own count, so an undisposed <c>CancellationTokenSource.CancelAfter</c> or
/// <c>Timer</c> shows up here), thread-pool pending work items (8). Custom counters are added with <see cref="Track"/>; the outstanding
/// <c>ArrayPool&lt;byte&gt;.Shared</c> rentals (rented minus returned, from the runtime's <c>System.Buffers.ArrayPoolEventSource</c>) with
/// <see cref="TrackArrayPoolBalance"/>.
/// <para>Sensitivity: a heap leak is seen when it exceeds the tolerance in each interval, so with a batch of N iterations the smallest leak per iteration that is
/// seen is the tolerance divided by N. The tolerance is the larger of 256 KiB and 2 % of the heap: the test host's heap is 45 to 100 MB, so in practice 1 to 2 MB per
/// batch, which is 20 to 40 KB per iteration for a batch of 50, 2.5 to 5 KB for 400, and 100 to 200 bytes for 10,000 (<c>EGGMAIL_ACCEL_SCALE</c> raises N). The heap after a
/// forced collection is stable to a few KB between batches, so the tolerance is not there to absorb noise but to ignore what a flow legitimately keeps (a cache filling up).</para>
/// <para>Not covered by design: a leak smaller than the tolerance per batch (use a bigger N, <c>EGGMAIL_ACCEL_SCALE</c>), native memory outside
/// counters that the caller adds, and OS-level leaks that only appear under real load (the soak test, docs/soak.md, samples the real process).</para>
/// </summary>
public sealed class LeakProbe : IDisposable
{
    private readonly List<Metric> _metrics = [];
    private readonly Action<string> _log;
    private ArrayPoolListener? _arrayPool;

    public LeakProbe(Action<string>? log = null)
    {
        _log = log ?? (_ => { });
        _metrics.Add(new Metric("managed heap (bytes)", () => GC.GetTotalMemory(forceFullCollection: true), 256 * 1024, 0.02));
        _metrics.Add(new Metric("threads", () => Process.GetCurrentProcess().Threads.Count, 4, 0));
        _metrics.Add(new Metric("timers", () => Timer.ActiveCount, 2, 0));
        _metrics.Add(new Metric("thread-pool pending work items", () => ThreadPool.PendingWorkItemCount, 8, 0));
        if (OpenFileDescriptors() >= 0)
        {
            _metrics.Add(new Metric("open file descriptors", () => OpenFileDescriptors(), 0, 0));
        }
    }

    /// <summary>Batches that run before measuring (default 1). A flow with a big lazily filled cache can ask for more.</summary>
    public int WarmupBatches { get; set; } = 1;

    /// <summary>Widens the allowance of a metric (by name) for flows whose steady state legitimately moves a little, such as sockets that come and go in a connection pool.</summary>
    public LeakProbe Allow(string metricName, long absolute)
    {
        int index = _metrics.FindIndex(m => m.Name == metricName);
        if (index < 0)
        {
            throw new ArgumentException("No metric named " + metricName, nameof(metricName));
        }

        _metrics[index] = _metrics[index] with { Absolute = absolute };
        return this;
    }

    /// <summary>Adds a counter that is reported when it grows by more than <paramref name="absolute"/> or <paramref name="relative"/> times its level (whichever is larger) in both measured intervals.</summary>
    public LeakProbe Track(string name, Func<long> read, long absolute = 0, double relative = 0)
    {
        _metrics.Add(new Metric(name, read, absolute, relative));
        return this;
    }

    /// <summary>
    /// Tracks rented minus returned buffers of <c>ArrayPool&lt;T&gt;.Shared</c>. Only meaningful when the flow is the only user of pooled arrays in the process, so keep these
    /// tests in the non-parallel collection. <paramref name="captureStacks"/> remembers the stack of every rental until it is returned (slow; for finding a leak), and
    /// <see cref="DescribeOutstandingRentals"/> then names the call sites that rented and never returned.
    /// </summary>
    /// <param name="absolute">Growth allowed between batches.</param>
    /// <param name="captureStacks">Remember the stack of every rental (slow; for finding a leak).</param>
    /// <param name="ignoreRentalsFrom">
    /// Rentals whose stack contains this text are not counted (implies <paramref name="captureStacks"/>). For code the project does not own: Entity Framework Core's
    /// expression funcletizer rents a <c>State[]</c> for every LINQ query and does not return it, so a flow that reads the configuration through EF can only be
    /// judged on the rentals outside <c>Microsoft.EntityFrameworkCore</c>.
    /// </param>
    public LeakProbe TrackArrayPoolBalance(long absolute = 0, bool captureStacks = false, string[]? ignoreRentalsFrom = null)
    {
        _arrayPool ??= new ArrayPoolListener(captureStacks || ignoreRentalsFrom is not null, ignoreRentalsFrom);
        ArrayPoolListener listener = _arrayPool;
        _metrics.Add(new Metric(ignoreRentalsFrom is null ? "ArrayPool rentals outstanding" : $"ArrayPool rentals outstanding (not from {string.Join(", ", ignoreRentalsFrom)})", () => listener.Outstanding, absolute, 0));
        return this;
    }

    /// <summary>The call sites (top frames) of the rentals that are still outstanding, most frequent first; needs <c>captureStacks: true</c>.</summary>
    public string DescribeOutstandingRentals(int top = 8) => _arrayPool?.Describe(top) ?? "(array pool not tracked)";

    /// <summary>Runs the batches and returns the report; call <see cref="LeakReport.AssertNoGrowth"/> on it.</summary>
    public async Task<LeakReport> RunAsync(Func<int, Task> iteration, int batchSize)
    {
        for (int w = 0; w < WarmupBatches; w++)
        {
            await Batch(iteration, batchSize).ConfigureAwait(false);
        }

        var levels = new long[_metrics.Count][];
        for (int m = 0; m < _metrics.Count; m++)
        {
            levels[m] = new long[4];
        }

        Sample(levels, 0);
        for (int b = 1; b <= 3; b++)
        {
            await Batch(iteration, batchSize).ConfigureAwait(false);
            Sample(levels, b);
        }

        var rows = new List<LeakRow>();
        for (int m = 0; m < _metrics.Count; m++)
        {
            Metric metric = _metrics[m];
            long b1 = levels[m][1];
            long b2 = levels[m][2];
            long b3 = levels[m][3];
            long allowed = Math.Max(metric.Absolute, (long)(metric.Relative * Math.Max(levels[m][0], 0)));
            rows.Add(new LeakRow(metric.Name, levels[m][0], b1, b2, b3, allowed));
        }

        var report = new LeakReport(batchSize, rows);
        if (_arrayPool is { CapturesStacks: true } && report.Leaks.Any())
        {
            report.Notes = "Pooled arrays rented and not returned, by call site:" + Environment.NewLine + _arrayPool.Describe(6);
        }

        _log(report.ToString());
        return report;
    }

    /// <summary>The synchronous flavour for flows that do not await.</summary>
    public Task<LeakReport> RunAsync(Action<int> iteration, int batchSize) =>
        RunAsync(i =>
        {
            iteration(i);
            return Task.CompletedTask;
        }, batchSize);

    private static async Task Batch(Func<int, Task> iteration, int batchSize)
    {
        for (int i = 0; i < batchSize; i++)
        {
            await iteration(i).ConfigureAwait(false);
        }
    }

    private void Sample(long[][] levels, int batch)
    {
        Quiesce();
        for (int m = 0; m < _metrics.Count; m++)
        {
            levels[m][batch] = _metrics[m].Read();
        }
    }

    /// <summary>A full, compacting, blocking collection with finalizers run, twice (finalizers can release the last references of objects of the first round).</summary>
    public static void Quiesce()
    {
        for (int i = 0; i < 2; i++)
        {
            GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
            GC.WaitForPendingFinalizers();
        }

        GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
    }

    /// <summary>Open descriptors of this process, or -1 where they cannot be counted cheaply.</summary>
    public static int OpenFileDescriptors()
    {
        foreach (string directory in new[] { "/proc/self/fd", "/dev/fd" })
        {
            try
            {
                if (Directory.Exists(directory))
                {
                    // Enumerating opens one descriptor itself, the same one every time.
                    return Directory.GetFileSystemEntries(directory).Length;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }

        return -1;
    }

    public void Dispose() => _arrayPool?.Dispose();

    private sealed record Metric(string Name, Func<long> Read, long Absolute, double Relative);

    /// <summary>Counts <c>BufferRented</c> and <c>BufferReturned</c> of the runtime's array pool event source.</summary>
    private sealed class ArrayPoolListener(bool captureStacks, string[]? ignoreFrom) : EventListener
    {
        [ThreadStatic]
        private static bool s_inside;

        private readonly Dictionary<int, string> _stacks = [];
        private long _outstanding;

        public bool CapturesStacks => captureStacks;

        public long Outstanding
        {
            get
            {
                if (!captureStacks)
                {
                    return Interlocked.Read(ref _outstanding);
                }

                lock (_stacks)
                {
                    return _stacks.Count;
                }
            }
        }

        protected override void OnEventSourceCreated(EventSource eventSource)
        {
            if (eventSource.Name == "System.Buffers.ArrayPoolEventSource")
            {
                EnableEvents(eventSource, EventLevel.Verbose, EventKeywords.All);
            }
        }

        protected override void OnEventWritten(EventWrittenEventArgs e)
        {
            // Capturing or formatting a stack rents pooled arrays itself; those rentals are not the flow's and must not recurse.
            if (s_inside)
            {
                return;
            }

            s_inside = true;
            try
            {
                Observe(e);
            }
            finally
            {
                s_inside = false;
            }
        }

        private void Observe(EventWrittenEventArgs e)
        {
            // BufferRented = 1, BufferReturned = 3 (BufferAllocated = 2 is an allocation by the pool when it had none to rent; the rental event follows).
            if (e.EventName == "BufferRented")
            {
                if (!captureStacks)
                {
                    Interlocked.Increment(ref _outstanding);
                }
                else if (e.Payload is { Count: > 0 } && e.Payload[0] is int id)
                {
                    string? stack = Capture();
                    if (stack is not null)
                    {
                        lock (_stacks)
                        {
                            _stacks[id] = stack;
                        }
                    }
                }
            }
            else if (e.EventName == "BufferReturned")
            {
                if (!captureStacks)
                {
                    Interlocked.Decrement(ref _outstanding);
                }
                else if (e.Payload is { Count: > 0 } && e.Payload[0] is int id)
                {
                    lock (_stacks)
                    {
                        _stacks.Remove(id);
                    }
                }
            }
        }

        /// <summary>The innermost frames of the rental as text, or null when a frame belongs to a type the caller said not to count. Reads the frames' methods only: formatting a whole stack trace costs about 100 times as much.</summary>
        private string? Capture()
        {
            var frames = new StackTrace(fNeedFileInfo: false).GetFrames();
            var kept = new List<string>(6);
            foreach (StackFrame frame in frames)
            {
                Type? type = frame.GetMethod()?.DeclaringType;
                string name = type?.FullName ?? string.Empty;
                if (ignoreFrom is not null && ignoreFrom.Any(marker => name.Contains(marker, StringComparison.Ordinal)))
                {
                    return null;
                }

                if (kept.Count < 6 && !name.StartsWith("System.", StringComparison.Ordinal) && !name.Contains("LeakProbe", StringComparison.Ordinal))
                {
                    kept.Add("at " + name + "." + frame.GetMethod()!.Name);
                }
            }

            return string.Join(Environment.NewLine, kept);
        }

        public string Describe(int top)
        {
            s_inside = true;
            try
            {
                string[] snapshot;
                lock (_stacks)
                {
                    snapshot = [.. _stacks.Values];
                }

                if (snapshot.Length == 0)
                {
                    return captureStacks ? "(no outstanding rentals)" : "(stacks were not captured: TrackArrayPoolBalance(captureStacks: true))";
                }

                var groups = snapshot
                    .Select(stack => string.Join(" <- ", stack.Split('\n').Select(l => l.Trim())))
                    .GroupBy(x => x)
                    .OrderByDescending(g => g.Count())
                    .Take(top);
                return string.Join(Environment.NewLine, groups.Select(g => $"{g.Count(),6} x {g.Key}"));
            }
            finally
            {
                s_inside = false;
            }
        }
    }
}

public sealed record LeakRow(string Name, long Warm, long B1, long B2, long B3, long Allowed)
{
    /// <summary>Growth in the last interval (B3 - B2).</summary>
    public long Growth => B3 - B2;

    /// <summary>Growth in the interval before (B2 - B1).</summary>
    public long PreviousGrowth => B2 - B1;

    /// <summary>Grew by more than the allowance in both intervals: a steady leak, not a one-off.</summary>
    public bool Leaks => Growth > Allowed && PreviousGrowth > Allowed;
}

public sealed class LeakReport(int batchSize, IReadOnlyList<LeakRow> rows)
{
    /// <summary>Extra diagnostics (the call sites of leaked pooled arrays) when the probe captured them.</summary>
    public string? Notes { get; set; }

    public int BatchSize { get; } = batchSize;

    public IReadOnlyList<LeakRow> Rows { get; } = rows;

    public IEnumerable<LeakRow> Leaks => Rows.Where(r => r.Leaks);

    public LeakRow this[string name] => Rows.Single(r => r.Name == name);

    /// <summary>Throws (an xUnit failure) naming each metric that grew between the last two batches.</summary>
    public void AssertNoGrowth()
    {
        if (Leaks.Any())
        {
            throw new Xunit.Sdk.XunitException("Growth between iteration batches (" + BatchSize + " iterations each):" + Environment.NewLine + this);
        }
    }

    public override string ToString()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{"metric",-36} {"after warm-up",14} {"B1",14} {"B2",14} {"B3",14} {"B2-B1",10} {"B3-B2",10} {"allowed",10}");
        foreach (LeakRow r in Rows)
        {
            sb.AppendLine($"{r.Name,-36} {r.Warm,14} {r.B1,14} {r.B2,14} {r.B3,14} {r.PreviousGrowth,10} {r.Growth,10} {r.Allowed,10}{(r.Leaks ? "  <-- GROWS" : string.Empty)}");
        }

        if (Notes is not null)
        {
            sb.AppendLine(Notes);
        }

        return sb.ToString();
    }
}
