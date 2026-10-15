using System.Globalization;
using Mta.Host.Hosting;

namespace Mta.Host.Tests;

public class ProcessMetricsTests
{
    private static void Touch() => System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(typeof(ProcessMetrics).TypeHandle);   // the instruments exist once the class has been touched

    [Fact]
    public void The_thread_gauge_counts_the_threads_of_this_process_and_follows_new_ones()
    {
        Touch();
        using var capture = new MeterCapture("Mta.Process");
        capture.Pull();
        double before = Assert.Single(capture.Of("mta.process.threads")).Value;
        Assert.True(before >= 2, "a test host has at least a main thread and the runtime's");

        using var release = new ManualResetEventSlim();
        var threads = Enumerable.Range(0, 20).Select(_ => new Thread(() => release.Wait()) { IsBackground = true }).ToList();
        threads.ForEach(t => t.Start());
        try
        {
            using var again = new MeterCapture("Mta.Process");
            again.Pull();
            // Other tests start and stop threads at the same time: only the 20 this test holds are certain.
            Assert.True(Assert.Single(again.Of("mta.process.threads")).Value >= 20, "twenty live threads of this test alone");
        }
        finally
        {
            release.Set();
            threads.ForEach(t => t.Join());
        }
    }

    [Fact]
    public void The_descriptor_gauge_reports_stdin_stdout_and_stderr_at_least_on_linux_and_nothing_elsewhere()
    {
        Touch();
        using var capture = new MeterCapture("Mta.Process");

        capture.Pull();

        if (OperatingSystem.IsLinux())
        {
            Assert.True(Assert.Single(capture.Of("mta.process.open_fds")).Value >= 3);
        }
        else
        {
            Assert.Empty(capture.Of("mta.process.open_fds"));   // no series rather than an invented number
        }
    }

    [Fact]
    public void The_prometheus_exporter_renders_the_documented_series_with_numeric_values()
    {
        Touch();
        using var exporter = new Mta.Observability.PrometheusTextExporter(meter => meter.Name == "Mta.Process");

        string text = exporter.Render();

        AssertSeries(text, "mta_process_threads");
        if (OperatingSystem.IsLinux())
        {
            AssertSeries(text, "mta_process_open_fds");
        }
    }

    private static void AssertSeries(string text, string name)
    {
        string line = text.Split('\n').Single(l => l.StartsWith(name + " ", StringComparison.Ordinal));
        Assert.True(double.TryParse(line[(name.Length + 1)..], NumberStyles.Float, CultureInfo.InvariantCulture, out double value) && value >= 1, line);
        Assert.Contains("# TYPE " + name + " gauge", text);
    }

    [Fact]
    public void The_descriptor_count_is_the_number_of_entries_minus_the_one_the_listing_itself_holds()
    {
        string directory = Directory.CreateTempSubdirectory("fake-proc-fd-").FullName;
        try
        {
            foreach (string name in new[] { "0", "1", "2", "3", "4" })
            {
                File.WriteAllText(Path.Combine(directory, name), "");
            }

            Assert.Equal(4, ProcessMetrics.CountOpenFileDescriptors(directory));   // five entries, one of which is the directory handle the real listing opens
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void A_missing_proc_directory_gives_no_descriptor_count_and_the_thread_count_falls_back_to_the_process_api()
    {
        Assert.Null(ProcessMetrics.CountOpenFileDescriptors(Path.Combine(Path.GetTempPath(), "no-such-proc-" + Guid.NewGuid().ToString("N"))));
        Assert.True(ProcessMetrics.CountThreads(Path.Combine(Path.GetTempPath(), "no-such-status-" + Guid.NewGuid().ToString("N"))) >= 1);
    }

    [Fact]
    public void The_thread_count_is_read_from_the_threads_line_of_the_status_file()
    {
        string file = Path.GetTempFileName();
        try
        {
            File.WriteAllText(file, "Name:\tmta\nVmRSS:\t  123456 kB\nThreads:\t  42\nVoluntary_ctxt_switches:\t7\n");

            Assert.Equal(42, ProcessMetrics.CountThreads(file));
        }
        finally
        {
            File.Delete(file);
        }
    }
}
