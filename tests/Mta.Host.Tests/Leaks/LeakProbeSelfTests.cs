using System.Buffers;
using Mta.TestSupport;
using Xunit.Abstractions;

namespace Mta.Host.Tests.Leaks;

/// <summary>
/// Accelerated lifecycle: the probe itself. A leak detector that has never seen a leak proves nothing, so each kind of resource it watches is
/// leaked on purpose (and released at the end of the test) and the probe must name it; the control flow, which only allocates garbage and
/// disposes what it opens, must pass.
/// </summary>
[Collection(LeakCollection.Name)]
public sealed class LeakProbeSelfTests(ITestOutputHelper output)
{
    private const int Batch = 400;

    private static readonly List<object> Hold = [];

    private LeakProbe NewProbe() => new(output.WriteLine);

    [Fact]
    public async Task Leak_probe_passes_a_flow_that_only_makes_garbage_and_disposes_what_it_opens()
    {
        using LeakProbe probe = NewProbe();
        probe.TrackArrayPoolBalance();
        string path = typeof(LeakProbeSelfTests).Assembly.Location;
        LeakReport report = await probe.RunAsync(i =>
        {
            GC.KeepAlive(new byte[4096]);
            using var file = File.OpenRead(path);
            using var cts = new CancellationTokenSource(TimeSpan.FromHours(1));
            byte[] rented = ArrayPool<byte>.Shared.Rent(4096);
            ArrayPool<byte>.Shared.Return(rented);
        }, Batch);
        report.AssertNoGrowth();
    }

    [Fact]
    public async Task Leak_probe_names_managed_memory_that_a_static_list_keeps()
    {
        using LeakProbe probe = NewProbe();
        try
        {
            LeakReport report = await probe.RunAsync(_ => Hold.Add(new byte[64 * 1024]), Batch);
            Assert.Contains(report.Leaks, r => r.Name.StartsWith("managed heap", StringComparison.Ordinal));
            Assert.Throws<Xunit.Sdk.XunitException>(report.AssertNoGrowth);
        }
        finally
        {
            Hold.Clear();
        }
    }

    [Fact]
    public async Task Leak_probe_sees_a_heap_leak_of_several_kilobytes_per_iteration_at_the_batch_sizes_the_tests_use()
    {
        // 8 KB kept per iteration in a batch of 400 is 3.2 MB per batch: above max(256 KiB, 2 %) of the test host heap (50 to 100 MB, so 1 to 2 MB) in both intervals.
        using LeakProbe probe = NewProbe();
        try
        {
            LeakReport report = await probe.RunAsync(_ => Hold.Add(new byte[8192]), Batch);
            Assert.Contains(report.Leaks, r => r.Name.StartsWith("managed heap", StringComparison.Ordinal));
        }
        finally
        {
            Hold.Clear();
        }
    }

    [Fact]
    public async Task Leak_probe_does_not_report_growth_that_happens_in_one_interval_only()
    {
        // A cache that fills once, a thread or a descriptor that is open at one sample: not a leak, so not reported.
        using LeakProbe probe = NewProbe();
        int calls = 0;
        long counter = 0;
        probe.Track("one-off counter", () => counter);
        LeakReport report = await probe.RunAsync(_ =>
        {
            // Batches are 400 iterations; the counter jumps once, in the last batch only (batch 1 is the warm-up, B1 to B3 are batches 2 to 4).
            if (++calls == 3 * Batch + 1)
            {
                counter += 1000;
            }
        }, Batch);
        Assert.Equal(1000, report["one-off counter"].Growth);
        Assert.False(report["one-off counter"].Leaks);
        report.AssertNoGrowth();
    }

    [Fact]
    public async Task Leak_probe_names_undisposed_timers_and_cancel_after_sources()
    {
        using LeakProbe probe = NewProbe();
        var held = new List<IDisposable>();
        try
        {
            LeakReport report = await probe.RunAsync(i =>
            {
                held.Add(i % 2 == 0 ? new Timer(_ => { }, null, TimeSpan.FromHours(1), Timeout.InfiniteTimeSpan) : CancelAfter());
            }, Batch);
            Assert.Contains(report.Leaks, r => r.Name == "timers");
        }
        finally
        {
            held.ForEach(h => h.Dispose());
        }

        static CancellationTokenSource CancelAfter()
        {
            var cts = new CancellationTokenSource();
            cts.CancelAfter(TimeSpan.FromHours(1));
            return cts;
        }
    }

    [Fact]
    public async Task Leak_probe_names_file_descriptors_that_are_never_closed()
    {
        if (LeakProbe.OpenFileDescriptors() < 0)
        {
            return;   // descriptors cannot be counted on this platform
        }

        using LeakProbe probe = NewProbe();
        string path = typeof(LeakProbeSelfTests).Assembly.Location;
        var held = new List<FileStream>();
        try
        {
            LeakReport report = await probe.RunAsync(_ => held.Add(File.OpenRead(path)), 50);
            Assert.Contains(report.Leaks, r => r.Name == "open file descriptors");
        }
        finally
        {
            held.ForEach(f => f.Dispose());
        }
    }

    [Fact]
    public async Task Leak_probe_names_threads_that_never_end()
    {
        using LeakProbe probe = NewProbe();
        using var release = new ManualResetEventSlim();
        var threads = new List<Thread>();
        try
        {
            LeakReport report = await probe.RunAsync(_ =>
            {
                var t = new Thread(() => release.Wait()) { IsBackground = true };
                t.Start();
                threads.Add(t);
            }, 12);
            Assert.Contains(report.Leaks, r => r.Name == "threads");
        }
        finally
        {
            release.Set();
            threads.ForEach(t => t.Join());
        }
    }

    [Fact]
    public async Task Leak_probe_names_pooled_arrays_that_are_rented_and_never_returned()
    {
        using LeakProbe probe = NewProbe();
        probe.TrackArrayPoolBalance();
        LeakReport report = await probe.RunAsync(_ => ArrayPool<byte>.Shared.Rent(1024), Batch);
        Assert.Contains(report.Leaks, r => r.Name == "ArrayPool rentals outstanding");
    }

    [Fact]
    public async Task Leak_probe_names_a_custom_counter()
    {
        using LeakProbe probe = NewProbe();
        long live = 0;
        probe.Track("live handles", () => Interlocked.Read(ref live));
        LeakReport report = await probe.RunAsync(_ => Interlocked.Increment(ref live), 10);
        Assert.Equal(["live handles"], report.Leaks.Select(r => r.Name).ToArray());
    }
}
