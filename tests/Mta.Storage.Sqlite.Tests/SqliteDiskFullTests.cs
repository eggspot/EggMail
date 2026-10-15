using Microsoft.Data.Sqlite;
using Mta.Storage;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>SQLITE_FULL for real: <c>PRAGMA max_page_count</c> makes the queue file unable to grow, as a full disk would.</summary>
public class SqliteDiskFullTests : SqliteTestBase
{
    [Fact]
    public async Task A_queue_file_that_cannot_grow_fails_the_accept_with_a_storage_full_exception_and_keeps_what_was_stored()
    {
        await Storage.Intake.AcceptAsync(Msg(size: 1024), default);
        await ReopenAsync();   // closes the files so that the page count below includes everything
        string queue = PathOf("queue.db");
        long pages = ScalarLong(queue, "PRAGMA page_count");
        SqliteFile.PageLimitsForTests[queue] = (int)pages + 6;
        try
        {
            await ReopenAsync();   // the writer connection of the reopened file carries the limit

            int accepted = 0;
            StorageFullException? full = null;
            for (int i = 0; i < 100 && full is null; i++)
            {
                try
                {
                    await Storage.Intake.AcceptAsync(Msg(size: 65536), default);
                    accepted++;
                }
                catch (StorageFullException ex)
                {
                    full = ex;
                }
            }

            Assert.NotNull(full);
            Assert.IsAssignableFrom<StorageUnavailableException>(full);
            var inner = Assert.IsType<SqliteException>(full!.InnerException);
            Assert.Equal(13, inner.SqliteErrorCode & 0xFF);   // SQLITE_FULL, whatever the extended code says
            Assert.True(accepted < 100, "the cap must bite");
            // What was stored before the disk filled is intact.
            Assert.Equal(1 + accepted, (await Storage.Deliveries.GetQueueStatsAsync(default)).Queued);
        }
        finally
        {
            SqliteFile.PageLimitsForTests.TryRemove(queue, out _);
        }
    }
}
