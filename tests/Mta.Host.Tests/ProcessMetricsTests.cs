using Mta.Host.Hosting;

namespace Mta.Host.Tests;

public class ProcessMetricsTests
{
    [Fact]
    public void The_process_gauges_report_plausible_values_for_this_process()
    {
        System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(typeof(ProcessMetrics).TypeHandle);   // the instruments exist once the class has been touched
        using var capture = new MeterCapture("Mta.Process");

        capture.Pull();

        Assert.True(Assert.Single(capture.Of("mta.process.threads")).Value >= 1);
        if (OperatingSystem.IsLinux())
        {
            Assert.True(Assert.Single(capture.Of("mta.process.open_fds")).Value >= 3, "stdin, stdout and stderr are open");
        }
    }

    [Fact]
    public void The_prometheus_exporter_renders_the_documented_process_series()
    {
        System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(typeof(ProcessMetrics).TypeHandle);
        using var exporter = new Mta.Observability.PrometheusTextExporter(meter => meter.Name == "Mta.Process");

        string text = exporter.Render();

        Assert.Contains("\nmta_process_threads ", "\n" + text);
        if (OperatingSystem.IsLinux())
        {
            Assert.Contains("\nmta_process_open_fds ", "\n" + text);
        }
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
