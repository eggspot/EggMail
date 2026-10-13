using Mta.Core;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>
/// The reads of the delivery path (the raw message, the suppression check) run on open read connections with prepared statements instead of
/// a pooled connection and an EF query per call. They must see every committed change at once, survive the files being released, and
/// give the same answers under concurrency.
/// </summary>
public class ReadSessionTests : SqliteTestBase
{
    [Fact]
    public async Task The_suppression_check_sees_each_change_as_soon_as_it_is_committed()
    {
        Assert.False(await Storage.Config.IsSuppressedAsync(TenantA, "bounce@example.org", default));   // opens (and keeps) a read session

        await Storage.Config.AddSuppressionAsync(new SuppressionRecord(TenantA, "Bounce@Example.ORG", SuppressionReason.HardBounce, "smtp 550", Clock.UtcNow, Ids.New()), default);
        Assert.True(await Storage.Config.IsSuppressedAsync(TenantA, "bounce@example.org", default));
        Assert.True(await Storage.Config.IsSuppressedAsync(TenantA, "  BOUNCE@example.org ", default));   // normalized like before
        Assert.False(await Storage.Config.IsSuppressedAsync(TenantB, "bounce@example.org", default));

        Assert.True(await Storage.Config.RemoveSuppressionAsync(TenantA, "bounce@example.org", default));
        Assert.False(await Storage.Config.IsSuppressedAsync(TenantA, "bounce@example.org", default));
    }

    [Fact]
    public async Task The_raw_message_is_read_back_exactly_and_disappears_with_the_message()
    {
        var small = await AcceptAsync(Msg(size: 1));
        var large = await AcceptAsync(Msg(size: 600_000));
        Assert.Equal(small.Raw.ToArray(), await Storage.Deliveries.GetRawAsync(small.MessageId, default));
        Assert.Equal(large.Raw.ToArray(), await Storage.Deliveries.GetRawAsync(large.MessageId, default));
        Assert.Null(await Storage.Deliveries.GetRawAsync(Ids.New(), default));

        foreach (var d in await ClaimAsync(now: Clock.UtcNow.AddSeconds(1)))
        {
            await RecordAsync(d, DeliveryOutcome.Delivered);
        }

        Assert.Null(await Storage.Deliveries.GetRawAsync(small.MessageId, default));   // freed with the last recipient
        Assert.Null(await Storage.Deliveries.GetRawAsync(large.MessageId, default));
    }

    [Fact]
    public async Task An_empty_raw_message_is_not_null()
    {
        var empty = await AcceptAsync(Msg(size: 0));
        Assert.Empty((await Storage.Deliveries.GetRawAsync(empty.MessageId, default))!);
    }

    [Fact]
    public async Task Many_concurrent_readers_get_the_right_answers()
    {
        var messages = new List<AcceptedMessage>();
        for (int i = 0; i < 40; i++)
        {
            messages.Add(await AcceptAsync(Msg(size: 3000 + i, to: [$"r{i}@example.org"])));
        }

        await Storage.Config.AddSuppressionAsync(new SuppressionRecord(TenantA, "r7@example.org", SuppressionReason.Complaint, "x", Clock.UtcNow, Ids.New()), default);

        await Parallel.ForEachAsync(Enumerable.Range(0, 2000), new ParallelOptions { MaxDegreeOfParallelism = 48 }, async (n, ct) =>
        {
            var m = messages[n % messages.Count];
            Assert.Equal(m.Raw.ToArray(), await Storage.Deliveries.GetRawAsync(m.MessageId, ct));
            Assert.Equal(n % messages.Count == 7, await Storage.Config.IsSuppressedAsync(TenantA, $"r{n % messages.Count}@example.org", ct));
        });
    }

    [Fact]
    public async Task Releasing_the_files_closes_the_read_sessions_and_reads_keep_working_afterwards()
    {
        var message = await AcceptAsync(Msg(size: 100));
        Assert.NotNull(await Storage.Deliveries.GetRawAsync(message.MessageId, default));
        Assert.False(await Storage.Config.IsSuppressedAsync(TenantA, "x@example.org", default));

        foreach (SqliteFile file in Sql.Runtime.Files)
        {
            file.ClearPool();   // what moving, backing up or quarantining a file does first
        }

        Assert.NotNull(await Storage.Deliveries.GetRawAsync(message.MessageId, default));
        Assert.False(await Storage.Config.IsSuppressedAsync(TenantA, "x@example.org", default));
    }

    [Fact]
    public async Task The_memory_queue_reads_the_raw_message_on_its_writer()
    {
        await ReopenAsync(b => b.QueuePersistence = QueuePersistence.Memory);
        var message = await AcceptAsync(Msg(size: 2500));
        Assert.Equal(message.Raw.ToArray(), await Storage.Deliveries.GetRawAsync(message.MessageId, default));
        Assert.Null(await Storage.Deliveries.GetRawAsync(Ids.New(), default));
    }
}
