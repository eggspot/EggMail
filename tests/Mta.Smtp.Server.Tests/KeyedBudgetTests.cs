namespace Mta.Smtp.Server.Tests;

public class KeyedBudgetTests
{
    [Fact]
    public void A_key_is_reserved_refused_and_given_back_exactly()
    {
        var budget = new KeyedInFlightBudget(55_000);

        Assert.True(budget.TryReserve("a", 16_384));
        Assert.True(budget.TryReserve("a", 32_768));
        Assert.False(budget.TryReserve("a", 16_384));
        Assert.True(budget.TryReserve("b", 16_384));   // another key has its own share
        budget.Release("a", 49_152);
        Assert.True(budget.TryReserve("a", 50_000));   // nothing of "a" is left
        budget.Release("a", 50_000);
        budget.Release("b", 16_384);
        Assert.True(budget.TryReserve("a", 55_000));
        Assert.False(budget.TryReserve("a", 1));
    }

    [Fact]
    public void A_session_budget_gives_everything_back_when_one_of_its_parts_refuses()
    {
        var global = new InFlightBudget(100_000);
        var listener = new InFlightBudget(60_000);
        var perRemote = new KeyedInFlightBudget(55_000);
        var one = new SessionBudget(global, listener, perRemote, "k");
        var two = new SessionBudget(global, listener, perRemote, "k");

        Assert.True(one.TryReserve(49_152));
        Assert.False(two.TryReserve(16_384));   // the per-network share refuses
        one.Release(49_152);

        Assert.Equal(0, global.Used);
        Assert.Equal(0, listener.Used);
        Assert.True(two.TryReserve(55_000));
    }
}
