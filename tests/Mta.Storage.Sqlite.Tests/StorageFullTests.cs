using Microsoft.Data.Sqlite;
using Mta.Storage;

namespace Mta.Storage.Sqlite.Tests;

public class StorageFullTests
{
    [Fact]
    public void Sqlite_full_becomes_a_storage_full_exception_that_is_still_a_storage_unavailable_exception()
    {
        var original = new SqliteException("database or disk is full", 13);

        Exception translated = SqliteFileWriter.Translate(original);

        var full = Assert.IsType<StorageFullException>(translated);
        Assert.IsAssignableFrom<StorageUnavailableException>(full);   // every caller that already treats unavailability as transient keeps doing so
        Assert.Same(original, full.InnerException);
    }

    [Theory]
    [InlineData(13)]
    [InlineData(13 | (1 << 8))]   // an extended result code of SQLITE_FULL
    public void The_extended_result_code_is_masked_off(int code)
    {
        Assert.IsType<StorageFullException>(SqliteFileWriter.Translate(new SqliteException("full", code)));
    }

    [Theory]
    [InlineData(19)]   // constraint
    [InlineData(5)]    // busy
    [InlineData(11)]   // corrupt
    public void Other_sqlite_errors_and_other_exceptions_pass_through_untouched(int code)
    {
        var sqlite = new SqliteException("something else", code);
        Assert.Same(sqlite, SqliteFileWriter.Translate(sqlite));

        var other = new InvalidOperationException("x");
        Assert.Same(other, SqliteFileWriter.Translate(other));
    }
}
