using System.Globalization;
using Mta.Core;
using Mta.Storage.Logic;
using Npgsql;

namespace Mta.Storage.Postgres.Tests;

/// <summary>Day partitions of the history tables: creation ahead, on demand, retention by DETACH CONCURRENTLY + DROP, and the advisory-lock job guard.</summary>
public class PartitionTests : PgTestBase
{
    private static string Name(string table, DateTimeOffset day) => table + "_p" + day.UtcDateTime.ToString("yyyyMMdd", CultureInfo.InvariantCulture);

    [Fact]
    public async Task Start_creates_the_partitions_of_yesterday_today_and_the_days_ahead_for_every_history_table()
    {
        foreach (string table in PostgresPartitions.Tables)
        {
            var names = await PartitionNamesAsync(table);
            Assert.Contains(Name(table, Start), names);
            Assert.Contains(Name(table, Start.AddDays(-1)), names);
            Assert.Contains(Name(table, Start.AddDays(Options.Postgres.PartitionsAheadDays)), names);
            Assert.DoesNotContain(Name(table, Start.AddDays(Options.Postgres.PartitionsAheadDays + 2)), names);
        }
    }

    [Fact]
    public async Task Maintenance_creates_partitions_ahead_as_time_moves_on_and_is_idempotent()
    {
        Clock.Advance(TimeSpan.FromDays(3));
        var first = await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        var created = first.Single(r => r.Job == "partitions.create");
        Assert.Equal(3 * PostgresPartitions.Tables.Length, created.RowsAffected);
        Assert.Contains(Name("message_event", Clock.UtcNow.AddDays(Options.Postgres.PartitionsAheadDays)), await PartitionNamesAsync("message_event"));

        var second = await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        Assert.Equal(0, second.Single(r => r.Job == "partitions.create").RowsAffected);
    }

    [Fact]
    public async Task A_message_for_a_day_without_a_partition_creates_it_on_demand()
    {
        DateTimeOffset far = Start.AddDays(3);
        var m = await AcceptAsync(Msg(received: far));
        Assert.Contains(Name("message_index", far), await PartitionNamesAsync("message_index"));
        Assert.NotNull(await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None));
    }

    [Fact]
    public async Task Writes_to_a_dropped_partition_recreate_it_and_succeed()
    {
        // Another replica (or an operator) dropped today's partitions behind this process's back.
        foreach (string table in PostgresPartitions.Tables)
        {
            await ExecuteAsync($"DROP TABLE {Name(table, Start)}");
        }

        var m = await AcceptAsync(Msg(received: Start));
        Assert.NotNull(await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None));
        Assert.Contains(Name("message_index", Start), await PartitionNamesAsync("message_index"));
    }

    [Fact]
    public async Task Retention_detaches_and_drops_expired_day_partitions_and_reports_the_rows()
    {
        var old = await AcceptAsync(Msg(received: Start));
        Clock.Advance(TimeSpan.FromDays(10));
        await AcceptAsync(Msg(received: Clock.UtcNow));
        Assert.Contains(Name("message_index", Start), await PartitionNamesAsync("message_index"));

        // Metadata retention is 30 days and content retention 7 days by default: the 10 days old content goes first.
        var reports = await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        Assert.DoesNotContain(Name("message_content", Start), await PartitionNamesAsync("message_content"));
        Assert.Contains(Name("message_index", Start), await PartitionNamesAsync("message_index"));
        Assert.True(reports.Single(r => r.Job == "retention.content").RowsAffected >= 1);

        Clock.Advance(TimeSpan.FromDays(25));
        reports = await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        foreach (string table in PostgresPartitions.MetadataTables)
        {
            Assert.DoesNotContain(Name(table, Start), await PartitionNamesAsync(table));
        }

        Assert.True(reports.Single(r => r.Job == "retention.metadata").RowsAffected >= 3, "index + recipient + event rows of the old message");
        Assert.Equal(0, await ScalarAsync<long>("SELECT count(*) FROM pg_class WHERE relname = $1", Name("message_index", Start)));
        Assert.Null(await Storage.History.GetAsync(TenantA, old.MessageId, CancellationToken.None));
    }

    [Fact]
    public async Task Retention_keeps_the_partitions_inside_the_window_and_the_default_partition()
    {
        await ExecuteAsync("CREATE TABLE message_event_default PARTITION OF message_event DEFAULT");
        var m = await AcceptAsync(Msg(received: Start));
        Clock.Advance(TimeSpan.FromDays(2));
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        Assert.Contains(Name("message_event", Start), await PartitionNamesAsync("message_event"));
        Assert.NotNull(await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None));

        // Past the window the old partition is dropped even though a concurrent detach is impossible with a default partition.
        Clock.Advance(TimeSpan.FromDays(40));
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        var remaining = await PartitionNamesAsync("message_event");
        Assert.DoesNotContain(Name("message_event", Start), remaining);
        Assert.Contains("message_event_default", remaining);
    }

    [Fact]
    public async Task An_interrupted_concurrent_detach_is_finished_by_the_next_run()
    {
        await AcceptAsync(Msg(received: Start));
        string partition = Name("message_event", Start);

        // A long reader makes DETACH … CONCURRENTLY wait; cancelling it leaves the partition in "detach pending".
        await using var reader = new NpgsqlConnection(Db.ConnectionString);
        await reader.OpenAsync();
        await using NpgsqlTransaction tx = await reader.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead);
        await using (var read = new NpgsqlCommand($"SELECT count(*) FROM {partition}", reader, tx))
        {
            await read.ExecuteScalarAsync();
        }

        var partitions = new PostgresPartitions(Pg.Runtime.Owner);
        int cutoff = StorageTime.DayNumber(Start) + 1;
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(1500));
        await Assert.ThrowsAnyAsync<Exception>(async () => await partitions.DropBeforeAsync(["message_event"], cutoff, cts.Token));
        Assert.Equal(1, await ScalarAsync<long>("SELECT count(*) FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid WHERE c.relname = $1 AND i.inhdetachpending", partition));

        await tx.RollbackAsync();
        (_, int dropped) = await partitions.DropBeforeAsync(["message_event"], cutoff, CancellationToken.None);
        Assert.True(dropped >= 1);
        Assert.Equal(0, await ScalarAsync<long>("SELECT count(*) FROM pg_class WHERE relname = $1", partition));
    }

    [Fact]
    public async Task A_job_held_by_another_node_is_reported_as_skipped()
    {
        await using AdvisoryLock? other = await AdvisoryLock.TryAcquireAsync(Pg.Runtime.Owner, AdvisoryLockKeys.Job("retention.metadata"), CancellationToken.None);
        Assert.NotNull(other);

        var reports = await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        Assert.Contains("skipped", reports.Single(r => r.Job == "retention.metadata").Detail);
        Assert.DoesNotContain("skipped", reports.Single(r => r.Job == "retention.content").Detail ?? "");
    }

    [Fact]
    public async Task Two_nodes_creating_the_same_partitions_at_once_do_not_fail()
    {
        PostgresStorage other = await OpenReplicaAsync();
        DateTimeOffset far = Start.AddDays(20);
        var tasks = new List<Task>();
        for (int i = 0; i < 6; i++)
        {
            tasks.Add(Pg.Intake.AcceptAsync(Msg(received: far.AddDays(i % 2)), CancellationToken.None).AsTask());
            tasks.Add(other.Intake.AcceptAsync(Msg(received: far.AddDays(i % 2)), CancellationToken.None).AsTask());
        }

        await Task.WhenAll(tasks);
        Assert.Equal(12, (await Storage.History.SearchAsync(new MessageQuery(Limit: 50, From: far.AddDays(-1)), CancellationToken.None)).Items.Count);
    }
}

public class PartitionStatsOnlyTests : PgTestBase
{
    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    [Fact]
    public async Task Stats_only_creates_no_partitions_and_writes_no_history_rows()
    {
        Assert.Empty(await PartitionNamesAsync("message_index"));
        await AcceptAsync();
        await RecordAsync((await ClaimAsync()).Single(), DeliveryOutcome.Delivered);
        foreach (string table in PostgresPartitions.Tables)
        {
            Assert.Equal(0, await ScalarAsync<long>($"SELECT count(*) FROM {table}"));
        }

        var reports = await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        Assert.DoesNotContain(reports, r => r.Job == "partitions.create");
        Assert.Empty(await PartitionNamesAsync("message_index"));
    }
}
