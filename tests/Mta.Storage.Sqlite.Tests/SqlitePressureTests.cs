using System.Diagnostics;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>The advisory storage-pressure figures (decision 108): the deep-queue timer, the windowed commit p99 and when they turn advisory.</summary>
public class SqlitePressureTests : SqliteTestBase
{
    private static readonly long Second = Stopwatch.Frequency;

    private static readonly SqliteOptions Defaults = new();

    private static long Ms(double ms) => (long)(ms * Stopwatch.Frequency / 1000);

    private static WriterMetrics Metrics() => new() { File = "queue.db", DeepQueueDepth = Defaults.PressureQueueDepth };

    private static SqliteStoragePressure Measure(WriterMetrics m, int pending, long now, SqliteOptions? options = null) =>
        SqliteStoragePressure.Measure([(pending, m)], options ?? Defaults, now);

    [Fact]
    public void An_idle_writer_reports_nothing_and_is_not_advisory()
    {
        SqliteStoragePressure p = Measure(Metrics(), 0, 1000 * Second);
        Assert.Equal(0, p.WriterQueueDepth);
        Assert.Equal(TimeSpan.Zero, p.WriterQueueOverThreshold);
        Assert.Equal(TimeSpan.Zero, p.CommitP99);
        Assert.Equal(0, p.CommitSamples);
        Assert.False(p.Advisory);
    }

    [Fact]
    public void A_deep_queue_turns_advisory_only_after_it_stayed_deep_for_the_duration()
    {
        WriterMetrics m = Metrics();
        long start = 1000 * Second;
        m.SetQueueDepth(1500, start);
        m.SetQueueDepth(1200, start + (100 * Second)); // still deep: the timer keeps its start

        SqliteStoragePressure early = Measure(m, 1300, start + (299 * Second));
        Assert.Equal(1300, early.WriterQueueDepth);
        Assert.Equal(299, (int)early.WriterQueueOverThreshold.TotalSeconds);
        Assert.False(early.Advisory);

        SqliteStoragePressure late = Measure(m, 1300, start + (300 * Second));
        Assert.Equal(300, (int)late.WriterQueueOverThreshold.TotalSeconds);
        Assert.True(late.Advisory);
    }

    [Fact]
    public void A_dip_below_the_depth_restarts_the_timer()
    {
        WriterMetrics m = Metrics();
        long start = 1000 * Second;
        m.SetQueueDepth(1500, start);
        m.SetQueueDepth(999, start + (200 * Second));
        m.SetQueueDepth(1500, start + (250 * Second));

        SqliteStoragePressure p = Measure(m, 1500, start + (400 * Second));
        Assert.Equal(150, (int)p.WriterQueueOverThreshold.TotalSeconds);
        Assert.False(p.Advisory);
    }

    [Fact]
    public void A_queue_that_drained_since_the_last_sample_is_not_counted_as_deep()
    {
        WriterMetrics m = Metrics();
        m.SetQueueDepth(1500, 1000 * Second);

        SqliteStoragePressure p = Measure(m, 3, 2000 * Second); // the live queue is short again; the writer has not sampled yet
        Assert.Equal(TimeSpan.Zero, p.WriterQueueOverThreshold);
        Assert.False(p.Advisory);
    }

    [Fact]
    public void The_p99_of_the_window_turns_advisory_when_it_is_over_the_threshold()
    {
        WriterMetrics m = Metrics();
        long now = 1000 * Second;
        for (int i = 0; i < 98; i++)
        {
            m.RecordBatch(1, Ms(2), now - (i * Ms(10)));
        }

        m.RecordBatch(1, Ms(150), now);
        m.RecordBatch(1, Ms(400), now);

        // 100 samples: nearest-rank p99 is the 99th smallest, the 150 ms commit (the 400 ms one alone does not set it).
        SqliteStoragePressure p = Measure(m, 0, now);
        Assert.Equal(100, p.CommitSamples);
        Assert.Equal(150, p.CommitP99.TotalMilliseconds, 3);
        Assert.True(p.Advisory);
    }

    [Fact]
    public void Commits_older_than_the_window_do_not_count()
    {
        WriterMetrics m = Metrics();
        long now = 10_000 * Second;
        for (int i = 0; i < 50; i++)
        {
            m.RecordBatch(1, Ms(500), now - (301 * Second)); // slow, but more than five minutes ago
        }

        for (int i = 0; i < 30; i++)
        {
            m.RecordBatch(1, Ms(1), now - Second);
        }

        SqliteStoragePressure p = Measure(m, 0, now);
        Assert.Equal(30, p.CommitSamples);
        Assert.Equal(1, p.CommitP99.TotalMilliseconds, 3);
        Assert.False(p.Advisory);
    }

    [Fact]
    public void Too_few_commits_in_the_window_give_no_p99()
    {
        WriterMetrics m = Metrics();
        long now = 1000 * Second;
        for (int i = 0; i < SqliteStoragePressure.MinCommitSamples - 1; i++)
        {
            m.RecordBatch(1, Ms(900), now);
        }

        SqliteStoragePressure p = Measure(m, 0, now);
        Assert.Equal(0, p.CommitSamples);
        Assert.Equal(TimeSpan.Zero, p.CommitP99);
        Assert.False(p.Advisory);
    }

    [Fact]
    public void The_ring_keeps_only_the_most_recent_commits()
    {
        WriterMetrics m = Metrics();
        long now = 1000 * Second;
        for (int i = 0; i < WriterMetrics.CommitSampleCapacity; i++)
        {
            m.RecordBatch(1, Ms(500), now);
        }

        for (int i = 0; i < WriterMetrics.CommitSampleCapacity; i++)
        {
            m.RecordBatch(1, Ms(1), now); // overwrites every slow sample
        }

        SqliteStoragePressure p = Measure(m, 0, now);
        Assert.Equal(WriterMetrics.CommitSampleCapacity, p.CommitSamples);
        Assert.Equal(1, p.CommitP99.TotalMilliseconds, 3);
    }

    [Fact]
    public void The_slowest_file_and_the_deepest_queue_are_reported()
    {
        WriterMetrics fast = Metrics();
        var slow = new WriterMetrics { File = "stats.db", DeepQueueDepth = Defaults.PressureQueueDepth };
        long now = 1000 * Second;
        for (int i = 0; i < 40; i++)
        {
            fast.RecordBatch(1, Ms(1), now);
            slow.RecordBatch(1, Ms(20), now);
        }

        SqliteStoragePressure p = SqliteStoragePressure.Measure([(700, fast), (5, slow)], Defaults, now);
        Assert.Equal(700, p.WriterQueueDepth);
        Assert.Equal(20, p.CommitP99.TotalMilliseconds, 3);
        Assert.False(p.Advisory);
    }

    [Fact]
    public async Task A_real_storage_measures_its_commits_with_the_configured_thresholds()
    {
        await ReopenAsync(b =>
        {
            b.SyncMode = SqliteSyncMode.Normal;
            b.PressureCommitP99 = TimeSpan.FromTicks(1); // any real commit is slower than one tick
        });
        for (int i = 0; i < SqliteStoragePressure.MinCommitSamples + 5; i++)
        {
            await Storage.Intake.AcceptAsync(Msg(size: 128), default); // one at a time: one commit each
        }

        SqliteStoragePressure p = ((SqliteStorage)Storage).GetPressure();
        Assert.InRange(p.CommitSamples, SqliteStoragePressure.MinCommitSamples, WriterMetrics.CommitSampleCapacity);
        Assert.True(p.CommitP99 > TimeSpan.Zero);
        Assert.True(p.Advisory);
        Assert.Equal(TimeSpan.Zero, p.WriterQueueOverThreshold);
    }

    [Fact]
    public async Task A_real_storage_under_the_default_thresholds_is_not_advisory()
    {
        await ReopenAsync(b =>
        {
            b.SyncMode = SqliteSyncMode.Off;
            b.ConfigSyncMode = SqliteSyncMode.Off; // no fsync anywhere: a slow CI disk cannot push a start-up commit over 100 ms
        });
        for (int i = 0; i < 5; i++)
        {
            await Storage.Intake.AcceptAsync(Msg(size: 128), default);
        }

        SqliteStoragePressure p = ((SqliteStorage)Storage).GetPressure();
        Assert.False(p.Advisory);
        Assert.Equal(0, p.WriterQueueDepth);
    }
}
