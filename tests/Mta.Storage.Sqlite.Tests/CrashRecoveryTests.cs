using System.Diagnostics;
using Microsoft.Data.Sqlite;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>
/// Kills a process that is accepting messages with SIGKILL and verifies every acknowledged message survives.
/// <para>
/// What this proves: with <c>synchronous=OFF</c>, <c>NORMAL</c> and <c>FULL</c> alike, data whose commit returned is safe
/// against a <b>process</b> kill, because the bytes are already in the operating system's page cache and the WAL index is
/// recovered from the WAL. What it cannot prove (and does not try to): behaviour on <b>power loss or an OS crash</b>, where
/// <c>OFF</c> may corrupt the database, <c>NORMAL</c> may lose the latest commits and <c>FULL</c> is durable. That needs a
/// VM or hardware fault injection; it is documented, not tested.
/// </para>
/// </summary>
public class CrashRecoveryTests : SqliteTestBase
{
    [Theory]
    [InlineData(SqliteSyncMode.Off)]
    [InlineData(SqliteSyncMode.Normal)]
    [InlineData(SqliteSyncMode.Full)]
    public async Task Acknowledged_messages_survive_a_sigkill(SqliteSyncMode mode)
    {
        await Storage.DisposeAsync(); // the child owns the directory now
        string dll = typeof(CrashWriterChild).Assembly.Location;
        var psi = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add(dll);
        psi.ArgumentList.Add(CrashWriterChild.Argument);
        psi.ArgumentList.Add(Dir);
        psi.ArgumentList.Add(mode.ToString());
        psi.ArgumentList.Add("4096");

        using Process child = Process.Start(psi)!;
        var acked = new List<Guid>();
        var errors = new System.Text.StringBuilder();
        child.ErrorDataReceived += (_, e) => errors.AppendLine(e.Data);
        child.BeginErrorReadLine();

        using var startup = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        string? line;
        while ((line = await child.StandardOutput.ReadLineAsync(startup.Token)) is not null && line != "READY")
        {
        }

        Assert.True(line == "READY", "child did not start: " + errors);

        // Let it run for a while, then kill it in the middle of whatever it is doing.
        var sw = Stopwatch.StartNew();
        int target = mode == SqliteSyncMode.Full ? 40 : 400;
        while (sw.Elapsed < TimeSpan.FromSeconds(8) && acked.Count < target)
        {
            line = await child.StandardOutput.ReadLineAsync(startup.Token);
            if (line is null)
            {
                break;
            }

            if (line.StartsWith("ACK ", StringComparison.Ordinal))
            {
                acked.Add(Guid.ParseExact(line[4..], "N"));
            }
        }

        child.Kill(); // SIGKILL on Unix, TerminateProcess on Windows: no cleanup code runs in the child
        child.WaitForExit();

        // Everything the child printed before dying had been acknowledged before it was printed.
        while ((line = await child.StandardOutput.ReadLineAsync(startup.Token)) is not null)
        {
            if (line.StartsWith("ACK ", StringComparison.Ordinal))
            {
                acked.Add(Guid.ParseExact(line[4..], "N"));
            }
        }

        Assert.True(acked.Count >= 10, $"the child acknowledged only {acked.Count} messages; stderr: {errors}");

        // Reopen over the files the dead process left behind (WAL included).
        await ReopenAsync(b => b.SyncMode = mode);
        Assert.Empty(Sql.QuarantineEvents);
        var missing = new List<Guid>();
        foreach (Guid id in acked)
        {
            if (await Storage.Deliveries.GetRawAsync(id, default) is null)
            {
                missing.Add(id);
            }
        }

        Assert.Empty(missing);

        // Each message has its delivery and its history entry (history is written right after the queue commit, so the very
        // last in-flight messages may lack one, but acknowledged ones were awaited together with it).
        var claimed = await ClaimAsync(max: 100_000, now: DateTimeOffset.UtcNow.AddDays(1));
        var claimedMessages = claimed.Select(c => c.MessageId).ToHashSet();
        Assert.All(acked, id => Assert.Contains(id, claimedMessages));
        foreach (Guid id in acked.Take(25))
        {
            Assert.NotNull(await Storage.History.GetAsync(Guid.Parse("a0000000-0000-7000-8000-000000000001"), id, default));
        }

        await Storage.DisposeAsync();
        using var raw = new SqliteConnection($"Data Source={PathOf("queue.db")};Pooling=False");
        raw.Open();
        using SqliteCommand cmd = raw.CreateCommand();
        cmd.CommandText = "PRAGMA integrity_check";
        Assert.Equal("ok", (string)cmd.ExecuteScalar()!);
    }
}
