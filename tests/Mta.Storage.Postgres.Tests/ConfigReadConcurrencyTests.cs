using Mta.Storage;

namespace Mta.Storage.Postgres.Tests;

/// <summary>
/// The configuration queries are synchronous (shared with SQLite). Run inline, a burst of delivery workers blocks most of the
/// thread pool inside Npgsql; the async work that would free the pooled connections then cannot run, new connections time out
/// ("Timeout during connection attempt", seen as StorageUnavailableException about 10 s into a busy start) while the server
/// itself sits idle. The access therefore bounds how many reads run at once.
/// </summary>
public class ConfigReadConcurrencyTests : PgTestBase
{
    [Fact]
    public async Task Config_reads_run_a_few_at_a_time_however_many_callers_there_are()
    {
        var access = new PostgresConfigAccess(Pg.Runtime.Data, PostgresModelHooks.Instance, maxPoolSize: 32);
        int running = 0, max = 0;
        var tasks = Enumerable.Range(0, 200).Select(_ => access.ReadAsync(_ =>
        {
            int now = Interlocked.Increment(ref running);
            int seen;
            while (now > (seen = Volatile.Read(ref max)) && Interlocked.CompareExchange(ref max, now, seen) != seen)
            {
            }

            Thread.Sleep(5);
            Interlocked.Decrement(ref running);
            return 1;
        }).AsTask()).ToList();
        await Task.WhenAll(tasks);

        Assert.Equal(200, tasks.Sum(t => t.Result));
        Assert.InRange(max, 1, 4);
    }

    [Fact]
    public async Task A_burst_of_config_reads_does_not_keep_a_claim_from_getting_through()
    {
        await AcceptAsync(Msg(to: ["a@example.org"]));
        await Storage.Config.UpsertTenantAsync(new Tenant(TenantA, "T", "t", true, Clock.UtcNow, false), CancellationToken.None);

        var reads = Enumerable.Range(0, 300).Select(i => Storage.Config.IsSuppressedAsync(TenantA, $"x{i}@example.org", CancellationToken.None).AsTask()).ToList();
        var claim = Task.Run(async () => await ClaimAsync());
        Assert.Same(claim, await Task.WhenAny(claim, Task.Delay(TimeSpan.FromSeconds(60))));
        await Task.WhenAll(reads);
        Assert.Single(await claim);
    }
}
