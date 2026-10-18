using Mta.Host.Ingest;

namespace Mta.Host.Tests.Inbound;

/// <summary>
/// The budget of uncached return-path host lookups of the bounce listener (a caller with a valid token can make the server ask storage about any <c>bounce.&lt;name&gt;</c>): per client, per process, and the
/// bounded table of clients. The second is read through a function the test moves, so none of this depends on the time the test runs.
/// </summary>
public class LookupBudgetTests
{
    private sealed class Seconds
    {
        public long Value = 1_000;

        public long Read() => Interlocked.Read(ref Value);
    }

    [Fact]
    public void A_client_gets_ten_lookups_a_second_and_a_new_second_starts_again()
    {
        var clock = new Seconds();
        var budget = new LookupBudget(clock.Read);

        for (int i = 0; i < LookupBudget.PerClientPerSecond; i++)
        {
            Assert.True(budget.TryTake("203.0.113.9"), $"lookup {i + 1}");
        }

        Assert.False(budget.TryTake("203.0.113.9"));
        Assert.True(budget.TryTake("203.0.113.10"));   // another client has its own
        clock.Value++;
        Assert.True(budget.TryTake("203.0.113.9"));
    }

    [Fact]
    public void A_client_past_its_own_budget_does_not_use_up_the_process_budget()
    {
        var clock = new Seconds();
        var budget = new LookupBudget(clock.Read);

        // One greedy client asks a thousand times: ten pass, and only those ten were counted against the process.
        int passed = Enumerable.Range(0, 1_000).Count(_ => budget.TryTake("greedy"));
        Assert.Equal(LookupBudget.PerClientPerSecond, passed);

        int others = 0;
        for (int i = 0; i < 500 && budget.TryTake("other-" + i); i++)
        {
            others++;
        }

        Assert.Equal(LookupBudget.PerProcessPerSecond - LookupBudget.PerClientPerSecond, others);
    }

    [Fact]
    public void The_process_budget_is_two_hundred_a_second_and_comes_back_with_the_next_second()
    {
        var clock = new Seconds();
        var budget = new LookupBudget(clock.Read);

        Assert.Equal(LookupBudget.PerProcessPerSecond, Enumerable.Range(0, 1_000).Count(i => budget.TryTake("client-" + i)));
        clock.Value++;
        Assert.Equal(LookupBudget.PerProcessPerSecond, Enumerable.Range(0, 1_000).Count(i => budget.TryTake("client-" + i)));
    }

    [Fact]
    public void When_the_table_of_clients_is_full_of_this_seconds_clients_a_new_one_is_refused_and_the_next_second_makes_room()
    {
        var clock = new Seconds();
        var budget = new LookupBudget(clock.Read);
        for (int i = 0; i < LookupBudget.MaxTrackedClients; i++)
        {
            budget.TryTake("client-" + i);   // whether the process budget lets it through or not, the client is tracked
        }

        Assert.Equal(LookupBudget.MaxTrackedClients, budget.TrackedClients);
        Assert.False(budget.TryTake("newcomer"));   // refused although it has not used anything: the table is full of this second
        Assert.Equal(LookupBudget.MaxTrackedClients, budget.TrackedClients);   // and it was not added: the table does not grow past its bound

        clock.Value++;
        Assert.True(budget.TryTake("newcomer"));
        Assert.Equal(1, budget.TrackedClients);   // the entries of the earlier second went when the table was full and a newcomer came
    }

    [Fact]
    public void A_table_that_is_not_full_keeps_the_entries_of_earlier_seconds_until_it_is_needed()
    {
        var clock = new Seconds();
        var budget = new LookupBudget(clock.Read);
        for (int i = 0; i < 100; i++)
        {
            budget.TryTake("old-" + i);
        }

        clock.Value += 5;
        budget.TryTake("new");

        Assert.Equal(101, budget.TrackedClients);
    }

    [Fact]
    public void However_many_threads_ask_at_the_turn_of_a_second_the_process_never_gets_more_than_its_budget()
    {
        for (int round = 0; round < 200; round++)
        {
            var clock = new Seconds { Value = 5_000 + round };
            var budget = new LookupBudget(clock.Read);
            int granted = 0;
            using var gate = new ManualResetEventSlim();
            Thread[] threads = Enumerable.Range(0, 16).Select(t => new Thread(() =>
            {
                gate.Wait();
                for (int i = 0; i < 40; i++)
                {
                    if (budget.TryTake($"client-{t}-{i}"))
                    {
                        Interlocked.Increment(ref granted);
                    }
                }
            })).ToArray();
            foreach (Thread thread in threads)
            {
                thread.Start();
            }

            gate.Set();
            foreach (Thread thread in threads)
            {
                thread.Join();
            }

            // 640 asks from 640 different clients in one second: exactly the process budget passes. (With separate steps for the window and the count, asks at the first instant of a second were lost or double counted.)
            Assert.Equal(LookupBudget.PerProcessPerSecond, granted);
        }
    }
}
