namespace Mta.Storage.Sqlite.Tests;

/// <summary>Group commit, ordering, batch limits, back-pressure and fault isolation of the per-file writer.</summary>
public class WriterTests : SqliteTestBase
{
    private WriterMetrics Queue => Sql.WriterMetrics["queue"];

    [Theory]
    [InlineData(SqliteSyncMode.Off)]
    [InlineData(SqliteSyncMode.Normal)]
    [InlineData(SqliteSyncMode.Full)]
    public async Task Many_concurrent_accepts_are_all_committed_in_due_order(SqliteSyncMode mode)
    {
        await ReopenAsync(b => b.SyncMode = mode);
        const int count = 800;
        var messages = Enumerable.Range(0, count).Select(i => Msg(to: [$"r{i}@example.org"], size: 512, received: Start.AddMilliseconds(i))).ToList();
        long before = Queue.Commands;

        await Task.WhenAll(messages.Select(m => Storage.Intake.AcceptAsync(m, default).AsTask()));

        Assert.Equal(count, (await Storage.Deliveries.GetQueueStatsAsync(default)).Queued);
        Assert.True(Queue.Commands - before >= count);
        Assert.True(Queue.Batches < Queue.Commands, "commands must share transactions");

        var claimed = await ClaimAsync(max: count + 10, now: Start.AddMinutes(1));
        Assert.Equal(count, claimed.Count);
        Assert.Equal(messages.Select(m => m.MessageId), claimed.Select(c => c.MessageId));
        Assert.Equal(500, (await Storage.History.SearchAsync(new MessageQuery(Limit: 500), default)).Items.Count);
    }

    [Fact]
    public async Task Batches_grow_under_load()
    {
        await ReopenAsync(b => b.SyncMode = SqliteSyncMode.Full);

        long commands0 = Queue.Commands, batches0 = Queue.Batches;
        for (int i = 0; i < 40; i++)
        {
            await AcceptAsync(Msg(size: 256));
        }

        double sequential = (double)(Queue.Commands - commands0) / (Queue.Batches - batches0);

        commands0 = Queue.Commands;
        batches0 = Queue.Batches;
        await Task.WhenAll(Enumerable.Range(0, 400).Select(_ => Storage.Intake.AcceptAsync(Msg(size: 256), default).AsTask()));
        double concurrent = (double)(Queue.Commands - commands0) / (Queue.Batches - batches0);

        Assert.True(sequential < 1.5, $"one caller at a time commits about one command per transaction (was {sequential:F2})");
        Assert.True(concurrent > 3 * sequential, $"batches must grow under load (sequential {sequential:F2}, concurrent {concurrent:F2})");
        Assert.True(Queue.MaxBatchSize > 5);
    }

    [Fact]
    public async Task The_batch_size_limit_is_respected()
    {
        await ReopenAsync(b => b.WriterMaxBatch = 8);
        await Task.WhenAll(Enumerable.Range(0, 200).Select(_ => Storage.Intake.AcceptAsync(Msg(size: 128), default).AsTask()));
        Assert.True(Queue.MaxBatchSize <= 8, $"max batch was {Queue.MaxBatchSize}");
        Assert.Equal(200, (await Storage.Deliveries.GetQueueStatsAsync(default)).Queued);
    }

    /// <summary>Occupies the queue writer until the returned event is set.</summary>
    private (Task Blocked, ManualResetEventSlim Release) BlockQueueWriter()
    {
        var started = new ManualResetEventSlim();
        var release = new ManualResetEventSlim();
        Task blocked = Sql.Runtime.QueueWriter.SubmitAsync((started, release), static (_, s) =>
        {
            s.started.Set();
            s.release.Wait();
            return 0;
        }).AsTask();
        Assert.True(started.Wait(TimeSpan.FromSeconds(10)));
        return (blocked, release);
    }

    [Fact]
    public async Task A_full_writer_queue_applies_back_pressure_to_callers()
    {
        await ReopenAsync(b => b.WriterQueueCapacity = 4);
        var (blocked, release) = BlockQueueWriter();
        List<Task<IntakeResult>> tasks;
        try
        {
            tasks = Enumerable.Range(0, 20).Select(_ => Storage.Intake.AcceptAsync(Msg(size: 64), default).AsTask()).ToList();
            await Task.Delay(300);
            Assert.All(tasks, t => Assert.False(t.IsCompleted));

            // Once the 4 slots are taken, a caller that cannot wait any longer is turned away instead of piling up.
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await Storage.Intake.AcceptAsync(Msg(size: 64), cts.Token));
        }
        finally
        {
            release.Set();
        }

        await blocked;
        await Task.WhenAll(tasks);   // every accepted message is committed before the queue is counted
        Assert.Equal(20, (await Storage.Deliveries.GetQueueStatsAsync(default)).Queued);
    }

    [Fact]
    public async Task One_failing_command_does_not_fail_the_commands_batched_with_it()
    {
        var (blocked, release) = BlockQueueWriter();
        var good1 = Sql.Runtime.QueueWriter.SubmitAsync(1, static (_, v) => v).AsTask();
        var bad = Sql.Runtime.QueueWriter.SubmitAsync(2, static (_, v) => v == 2 ? throw new InvalidOperationException("boom") : v).AsTask();
        var good2 = Sql.Runtime.QueueWriter.SubmitAsync(3, static (_, v) => v).AsTask();
        release.Set();
        await blocked;

        Assert.Equal(1, await good1);
        Assert.Equal(3, await good2);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(async () => await bad);
        Assert.Equal("boom", ex.Message);
        Assert.True(Queue.FailedBatches >= 1);

        // The writer keeps working.
        await AcceptAsync();
    }

    [Fact]
    public async Task A_constraint_violation_inside_a_batch_only_fails_its_own_caller()
    {
        var dup = Msg();
        await AcceptAsync(dup);
        var (blocked, release) = BlockQueueWriter();
        var ok = Storage.Intake.AcceptAsync(Msg(), default).AsTask();
        var bad = Storage.Intake.AcceptAsync(dup, default).AsTask();
        var ok2 = Storage.Intake.AcceptAsync(Msg(), default).AsTask();
        release.Set();
        await blocked;

        Assert.Equal(IntakeStatus.Accepted, (await ok).Status);
        Assert.Equal(IntakeStatus.Accepted, (await ok2).Status);
        await Assert.ThrowsAsync<StorageConflictException>(async () => await bad);
        Assert.Equal(3, (await Storage.Deliveries.GetQueueStatsAsync(default)).Queued);
    }

    [Fact]
    public async Task Submitting_after_dispose_fails_cleanly()
    {
        SqliteFileWriter writer = Sql.Runtime.QueueWriter;
        await Storage.DisposeAsync();
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await writer.SubmitAsync(0, static (_, v) => v));
    }

    [Fact]
    public async Task Queue_depth_and_commit_latency_are_reported_in_health()
    {
        await AcceptAsync();
        StorageHealth h = await Storage.Maintenance.GetHealthAsync(default);
        Assert.True(long.Parse(h.Details["writer.queue.commands"], System.Globalization.CultureInfo.InvariantCulture) >= 1);
        Assert.True(h.Details.ContainsKey("writer.queue.last_commit_ms"));
        Assert.True(h.Details.ContainsKey("writer.queue.queue_depth"));
        Assert.True(h.Details.ContainsKey("writer.queue.max_batch"));
    }

    [Fact]
    public async Task The_statistics_flush_timer_makes_counters_visible_without_an_explicit_flush()
    {
        await ReopenAsync(b => b.StatsFlushInterval = TimeSpan.FromMilliseconds(100));
        await AcceptAsync();
        for (int i = 0; i < 300; i++)
        {
            var rows = await Storage.Stats.QueryAsync(TenantA, Start.AddHours(-1), Start.AddHours(1), false, default);
            if (rows.Count == 1 && rows[0].Accepted == 1)
            {
                return;
            }

            await Task.Delay(100);
        }

        Assert.Fail("the periodic flush did not write the counters");
    }
}
