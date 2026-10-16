using System.Diagnostics;
using Microsoft.Data.Sqlite;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>
/// The real thing behind the in-process crash loop (<see cref="SqliteCrashLoopLifecycleBase"/>): a child process that accepts, claims and reports deliveries is killed with SIGKILL, twice in a row
/// over the same data directory, and the parent applies to what is left the same contract as the model: every acknowledged message survives; a delivery reported before the kill is gone (at most one
/// report was in flight and may have gone either way); a delivery the dead worker held is claimable at once and flagged <c>possible_duplicate</c>; a delivery nobody held is not flagged;
/// nothing appears that was never accepted (apart from one accept that was in flight). Like the other process-kill test this proves survival of a <b>process</b> kill, not of power loss.
/// </summary>
public class CrashLoopLifecycleProcessKillTests : IAsyncLifetime
{
    private string _dir = "";

    public Task InitializeAsync()
    {
        _dir = SqliteTestStorage.NewDirectory();
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        SqliteTestStorage.TryDelete(_dir);
        return Task.CompletedTask;
    }

    [Theory]
    [InlineData(SqliteSyncMode.Off)]
    [InlineData(SqliteSyncMode.Full)]
    public async Task Killing_a_worker_process_twice_leaves_what_the_in_process_crash_model_predicts(SqliteSyncMode mode)
    {
        for (int cycle = 0; cycle < 2; cycle++)
        {
            await RunCycleAsync(mode, cycle);
        }

        using var raw = new SqliteConnection($"Data Source={Path.Combine(_dir, "queue.db")};Pooling=False");
        raw.Open();
        using SqliteCommand cmd = raw.CreateCommand();
        cmd.CommandText = "PRAGMA integrity_check";
        Assert.Equal("ok", (string)cmd.ExecuteScalar()!);
    }

    private async Task RunCycleAsync(SqliteSyncMode mode, int cycle)
    {
        var acked = new List<(Guid Message, Guid Delivery)>();
        var claimed = new HashSet<Guid>();
        var done = new HashSet<Guid>();
        Guid? recording = null;
        var errors = new System.Text.StringBuilder();

        var psi = new ProcessStartInfo("dotnet") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        psi.ArgumentList.Add(typeof(CrashWorkerChild).Assembly.Location);
        psi.ArgumentList.Add(CrashWorkerChild.Argument);
        psi.ArgumentList.Add(_dir);
        psi.ArgumentList.Add(mode.ToString());
        using Process child = Process.Start(psi)!;
        child.ErrorDataReceived += (_, e) => errors.AppendLine(e.Data);
        child.BeginErrorReadLine();

        void Parse(string line)
        {
            string[] parts = line.Split(' ');
            switch (parts[0])
            {
                case "ACK":
                    acked.Add((Guid.ParseExact(parts[1], "N"), Guid.ParseExact(parts[2], "N")));
                    break;
                case "CLAIM":
                    claimed.Add(Guid.ParseExact(parts[1], "N"));
                    break;
                case "RECORDING":
                    recording = Guid.ParseExact(parts[1], "N");
                    break;
                case "DONE":
                    done.Add(Guid.ParseExact(parts[1], "N"));
                    break;
            }
        }

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        string? line;
        while ((line = await child.StandardOutput.ReadLineAsync(deadline.Token)) is not null && line != "READY")
        {
        }

        Assert.True(line == "READY", "the child did not start: " + errors);
        int target = mode == SqliteSyncMode.Full ? 30 : 120;
        while (acked.Count < target && done.Count < target / 3 + 1 && (line = await child.StandardOutput.ReadLineAsync(deadline.Token)) is not null)
        {
            Parse(line);
        }

        child.Kill();
        child.WaitForExit();
        while ((line = await child.StandardOutput.ReadLineAsync(deadline.Token)) is not null)
        {
            Parse(line);
        }

        Assert.True(acked.Count >= 10 && done.Count > 0, $"the child did only {acked.Count} accepts and {done.Count} reports before it was killed: {errors}");

        // Reopen over what the dead process left behind and look at the queue.
        var options = new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _dir, SyncMode = mode, StatsFlushInterval = TimeSpan.Zero } };
        await using SqliteStorage storage = SqliteStorage.Create(options);
        await storage.InitializeAsync(default);
        Assert.Empty(storage.QuarantineEvents);
        IReadOnlyList<ClaimedDelivery> queue = await storage.Deliveries.ClaimAsync("parent", 1_000_000, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5), default);
        var inQueue = queue.ToDictionary(c => c.DeliveryId);

        var ackedDeliveries = acked.Select(a => a.Delivery).ToHashSet();
        var lost = ackedDeliveries.Where(d => !inQueue.ContainsKey(d) && !done.Contains(d)).ToList();
        Assert.True(lost.Count == 0 || (lost.Count == 1 && lost[0] == recording), $"cycle {cycle}: {lost.Count} acknowledged deliveries are missing after the kill (one may be the report in flight)");
        Assert.DoesNotContain(done, d => inQueue.ContainsKey(d));
        Assert.True(inQueue.Keys.Count(d => !ackedDeliveries.Contains(d)) <= 1, "more deliveries than were ever accepted (one accept may have been in flight)");

        foreach (ClaimedDelivery c in queue)
        {
            bool heldByDeadWorker = claimed.Contains(c.DeliveryId);
            if (ackedDeliveries.Contains(c.DeliveryId))
            {
                Assert.Equal(heldByDeadWorker, c.PossibleDuplicate);
            }
        }

        // The messages the dead worker held are claimable again right away: the lease was not honoured. Report everything and leave an empty queue for the next cycle.
        foreach (ClaimedDelivery c in queue)
        {
            await storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = c.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = DateTimeOffset.UtcNow, SmtpCode = 250, PossibleDuplicate = c.PossibleDuplicate }, default);
        }

        QueueStats stats = await storage.Deliveries.GetQueueStatsAsync(default);
        Assert.Equal(0, stats.Queued + stats.Leased + stats.Deferred);
        Assert.Equal(0, stats.SpoolBytes);
    }
}
