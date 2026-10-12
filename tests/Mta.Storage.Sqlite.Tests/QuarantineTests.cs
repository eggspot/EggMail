using Mta.Core;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>A corrupt database file is quarantined (moved, never deleted), replaced by an empty one, and reported.</summary>
public class QuarantineTests : SqliteTestBase
{
    private async Task PopulateAsync()
    {
        await AcceptAsync(Msg(to: ["a@example.org"]));
        await Storage.Config.UpsertTenantAsync(new Tenant(Ids.New(), "Acme", "acme", true, Clock.UtcNow, false), default);
        await FlushStatsAsync();
        await Storage.DisposeAsync();
    }

    private static void GarbleHeader(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Write);
        byte[] junk = new byte[128];
        new Random(42).NextBytes(junk);
        fs.Write(junk);
    }

    [Theory]
    [InlineData("queue")]
    [InlineData("stats")]
    [InlineData("config")]
    [InlineData("history")]
    public async Task A_garbled_file_is_quarantined_and_the_other_files_are_untouched(string file)
    {
        await PopulateAsync();
        string path = PathOf(file + ".db");
        GarbleHeader(path);
        long garbledSize = new FileInfo(path).Length;

        await ReopenAsync();

        var events = Sql.QuarantineEvents;
        var evt = Assert.Single(events);
        Assert.Equal(file + ".db", evt.File);
        string moved = Path.Combine(evt.QuarantinedTo, file + ".db");
        Assert.True(File.Exists(moved), "the corrupt file is kept");
        Assert.Equal(garbledSize, new FileInfo(moved).Length);
        Assert.StartsWith(Path.Combine(Dir, "quarantine"), evt.QuarantinedTo, StringComparison.Ordinal);

        StorageHealth health = await Storage.Maintenance.GetHealthAsync(default);
        Assert.Contains("sqlite_quarantined:" + file + ".db", health.Warnings);
        Assert.Contains(evt.QuarantinedTo, health.Details["quarantine." + file + ".db"], StringComparison.Ordinal);

        // The quarantined database starts empty, the others keep their data.
        Assert.Equal(file == "queue" ? 0 : 1, (await ClaimAsync(now: Clock.UtcNow.AddMinutes(1))).Count);
        Assert.Equal(file == "config" ? 0 : 1, (await Storage.Config.GetTenantsAsync(default)).Count);
        Assert.Equal(file == "history" ? 0 : 1, (await Storage.History.SearchAsync(new MessageQuery(), default)).Items.Count);
        var stats = await Storage.Stats.QueryAsync(TenantA, Start.AddHours(-1), Start.AddHours(1), false, default);
        Assert.Equal(file == "stats" ? 0 : 1, stats.Count);

        // And it is fully usable again.
        await AcceptAsync();
        await Storage.Config.UpsertTenantAsync(new Tenant(Ids.New(), "Beta", "beta", true, Clock.UtcNow, false), default);
    }

    [Fact]
    public async Task Overwritten_pages_inside_a_populated_file_are_detected()
    {
        for (int i = 0; i < 400; i++)
        {
            await AcceptAsync(Msg(to: [$"r{i}@example.org"], size: 300));
        }

        await Storage.DisposeAsync();
        string path = PathOf("queue.db");
        long length = new FileInfo(path).Length;
        Assert.True(length > 4096 * 8, "the file must span several pages for this test");
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write))
        {
            byte[] junk = new byte[4096 * 3];
            new Random(7).NextBytes(junk);
            fs.Seek(4096 * 3, SeekOrigin.Begin);
            fs.Write(junk);
        }

        await ReopenAsync();
        Assert.Single(Sql.QuarantineEvents);
        Assert.Empty(await ClaimAsync(now: Clock.UtcNow.AddMinutes(1)));
    }

    [Fact]
    public async Task The_full_integrity_check_can_be_selected()
    {
        await PopulateAsync();
        GarbleHeader(PathOf("config.db"));
        await ReopenAsync(b => b.QuickCheck = false);
        Assert.Equal("config.db", Assert.Single(Sql.QuarantineEvents).File);
    }

    [Fact]
    public async Task Several_corrupt_files_are_quarantined_together()
    {
        await PopulateAsync();
        GarbleHeader(PathOf("queue.db"));
        GarbleHeader(PathOf("stats.db"));
        await ReopenAsync();
        Assert.Equal(["queue.db", "stats.db"], Sql.QuarantineEvents.Select(e => e.File).Order(StringComparer.Ordinal));
        Assert.Equal(2, (await Storage.Maintenance.GetHealthAsync(default)).Warnings.Count(w => w.StartsWith("sqlite_quarantined:", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task A_healthy_restart_quarantines_nothing()
    {
        await PopulateAsync();
        await ReopenAsync();
        Assert.Empty(Sql.QuarantineEvents);
        Assert.False(Directory.Exists(PathOf("quarantine")));
    }
}
