using Mta.Storage.Transfer;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>The backend switch fence and marks must hold after a restart (design §4.6): they live in the files, not in memory.</summary>
public class SwitchGateTests : SqliteTestBase
{
    private static readonly Guid SwitchId = Guid.Parse("01900000-0000-7000-8000-0000000000bb");

    [Fact]
    public async Task A_fenced_source_stays_closed_after_a_restart_and_is_left_untouched()
    {
        await AcceptAsync(Msg(to: ["a@example.org"]));
        await ClaimAsync(lease: TimeSpan.FromHours(1)); // a lease that startup would normally clear
        await Storage.Transfer!.SetStateAsync(new SwitchStateRecord(SwitchId, SwitchRoles.Source, SwitchStates.Fenced, Clock.UtcNow, null), default);

        await ReopenAsync();

        Assert.True(Storage.Transfer!.Gate.IsClosed);
        await Assert.ThrowsAsync<StorageFencedException>(async () => await Storage.Intake.AcceptAsync(Msg(), default));
        Assert.Empty(await ClaimAsync());
        Assert.Equal(1, ScalarLong(PathOf("queue.db"), "SELECT count(*) FROM delivery_queue WHERE lease_owner IS NOT NULL"));
    }

    [Fact]
    public async Task A_transfer_mark_survives_a_restart_even_when_the_fence_is_cleared_by_mistake()
    {
        await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"]));
        await Storage.Transfer!.MarkQueueTransferredAsync(SwitchId, default);
        Assert.Equal(2, ScalarLong(PathOf("queue.db"), $"SELECT count(*) FROM delivery_queue WHERE transfer_switch_id = '{SwitchId.ToString().ToUpperInvariant()}'"));

        await ReopenAsync();
        Assert.False(Storage.Transfer!.Gate.IsClosed); // no fence record: a store that was not fenced
        Assert.Empty(await ClaimAsync());

        await Storage.Transfer.ReleaseQueueAsync(SwitchId, default);
        Assert.Equal(2, (await ClaimAsync()).Count);
    }

    [Fact]
    public async Task A_target_that_is_still_importing_stays_closed_after_a_restart()
    {
        await Storage.Transfer!.SetStateAsync(new SwitchStateRecord(SwitchId, SwitchRoles.Target, SwitchStates.Confirmed, Clock.UtcNow, null), default);
        await ReopenAsync();
        Assert.True(Storage.Transfer!.Gate.IsClosed);
        await Assert.ThrowsAsync<StorageFencedException>(async () => await Storage.Intake.AcceptAsync(Msg(), default));
    }
}
