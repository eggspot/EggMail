using Microsoft.Data.Sqlite;
using Mta.Storage.Tests;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>
/// SQLite keeps the history in its own file and writes it after the queue commit. A kill between the two (or a failed history write, which is logged and not fatal) leaves a message that is
/// queued but has no history entry. That state must be harmless: the message is delivered, reported, its spool freed and its statistics counted, nothing throws and nothing is retried forever,
/// and the missing history is not invented later.
/// </summary>
public class CrashLoopLifecycleHistoryGapTests : SqliteTestBase
{
    [Fact]
    public async Task A_message_without_a_history_entry_is_delivered_and_reported_like_any_other()
    {
        AcceptedMessage kept = await AcceptAsync(Msg(to: ["a@example.org"]));
        AcceptedMessage gap = await AcceptAsync(Msg(to: ["b@example.org", "c@example.org"]));
        await FlushStatsAsync();

        // The state a kill between the queue commit and the history write leaves behind: the entry is not there.
        using (var history = new SqliteConnection($"Data Source={PathOf("history.db")};Pooling=False"))
        {
            history.Open();
            foreach (string table in new[] { "message_index", "message_content", "message_event" })
            {
                using SqliteCommand cmd = history.CreateCommand();
                cmd.CommandText = $"DELETE FROM {table} WHERE message_id = @m";
                cmd.Parameters.AddWithValue("@m", gap.MessageId.ToString("D").ToUpperInvariant());
                cmd.ExecuteNonQuery();
            }
        }

        // A crash and restart on top of it.
        await ReopenAsync();
        Assert.Null(await Storage.History.GetAsync(TenantA, gap.MessageId, default));
        Assert.NotNull(await Storage.History.GetAsync(TenantA, kept.MessageId, default));
        Assert.NotNull(await Storage.Deliveries.GetRawAsync(gap.MessageId, default));

        var claimed = await ClaimAsync();
        Assert.Equal(3, claimed.Count);
        foreach (ClaimedDelivery c in claimed)
        {
            await RecordAsync(c, c.Recipient.ToString() == "c@example.org" ? DeliveryOutcome.Failed : DeliveryOutcome.Delivered, suppress: c.Recipient.ToString() == "c@example.org" ? SuppressionReason.HardBounce : null);
        }

        QueueStats stats = await Storage.Deliveries.GetQueueStatsAsync(default);
        Assert.True(stats is { Queued: 0, Leased: 0, Deferred: 0, SpoolBytes: 0 }, stats.ToString());
        Assert.Null(await Storage.Deliveries.GetRawAsync(gap.MessageId, default));
        Assert.True(await Storage.Config.IsSuppressedAsync(TenantA, "c@example.org", default));
        Assert.Null(await Storage.History.GetAsync(TenantA, gap.MessageId, default));   // not invented afterwards
        Assert.Equal(MessageEventType.Delivered, Assert.Single(await Storage.History.GetEventsAsync(TenantA, kept.MessageId, default), e => e.Type == MessageEventType.Delivered).Type);

        await FlushStatsAsync();
        var rows = await Storage.Stats.QueryAsync(TenantA, Start.AddDays(-1), Start.AddDays(2), false, default);
        Assert.Equal(2, rows.Sum(r => r.Delivered));
        Assert.Equal(1, rows.Sum(r => r.HardBounce));
    }
}
