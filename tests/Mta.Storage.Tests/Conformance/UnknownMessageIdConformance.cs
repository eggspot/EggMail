using Mta.Core;
using Mta.Storage.Logic;

namespace Mta.Storage.Tests;

/// <summary>
/// Found by the API leak check: a message id arrives from a URL and need not be one of ours. The history day key is read from the first 48 bits of the id, and
/// for a random GUID (about one in ten) that is later than the year 9999, which used to make the lookup throw <see cref="ArgumentOutOfRangeException"/> (HTTP 500)
/// instead of answering "not found". Every backend must answer "nothing there" for any GUID.
/// </summary>
public abstract class UnknownMessageIdConformance : StorageTestBase
{
    public static IEnumerable<object[]> Ids_that_are_not_uuid_v7() =>
    [
        ["ffffffff-ffff-ffff-ffff-ffffffffffff"],
        ["f82354e1-c8e3-4b2e-82da-d07d476795df"],
        ["00000000-0000-0000-0000-000000000000"],
        ["e6f0a1b2-0000-4000-8000-000000000000"],
    ];

    [Fact]
    public void The_day_of_any_guid_is_a_number_and_never_throws()
    {
        Assert.Equal(0, StorageTime.DayNumber(Guid.Empty));
        Assert.Equal((int)(((1L << 48) - 1) / 86_400_000L), StorageTime.DayNumber(Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff")));
        Assert.Equal(StorageTime.DayNumber(Start), StorageTime.DayNumber(Ids.New(Start)));
    }

    [Theory]
    [MemberData(nameof(Ids_that_are_not_uuid_v7))]
    public async Task Reading_a_message_that_does_not_exist_answers_nothing_whatever_the_id(string text)
    {
        Guid id = Guid.Parse(text);
        await AcceptAsync();   // the store is not empty

        Assert.Null(await Storage.History.GetAsync(TenantA, id, default));
        Assert.Empty(await Storage.History.GetEventsAsync(TenantA, id, default));
        Assert.Null(await Storage.History.GetRetainedRawAsync(TenantA, id, default));
        Assert.Null(await Storage.Deliveries.GetRawAsync(id, default));
        CancelResult cancelled = await Storage.Deliveries.CancelAsync(TenantA, id, null, Clock.UtcNow, null, default);
        Assert.Empty(cancelled.Cancelled);
        Assert.Equal(0, cancelled.Waiting);
    }
}
