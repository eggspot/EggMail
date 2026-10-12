using Mta.Core;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>
/// The child process of the crash-recovery test: opens a storage in the given directory and accepts messages in a loop,
/// printing <c>ACK &lt;message id&gt;</c> (flushed) after each <c>AcceptAsync</c> returned. The parent kills it with SIGKILL.
/// Arguments: <c>--crash-writer &lt;dataDirectory&gt; &lt;Off|Normal|Full&gt; &lt;messageBytes&gt;</c>.
/// </summary>
public static class CrashWriterChild
{
    public const string Argument = "--crash-writer";

    public static async Task<int> RunAsync(string[] args)
    {
        string dir = args[1];
        var sync = Enum.Parse<SqliteSyncMode>(args[2]);
        int size = int.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture);
        var options = new StorageOptions
        {
            Sqlite = new SqliteOptions { DataDirectory = dir, SyncMode = sync, StatsFlushInterval = TimeSpan.Zero },
        };
        await using SqliteStorage storage = SqliteStorage.Create(options);
        await storage.InitializeAsync(CancellationToken.None);
        Console.Out.WriteLine("READY");
        Console.Out.Flush();

        byte[] raw = new byte[size];
        Random.Shared.NextBytes(raw);
        var tenant = Guid.Parse("a0000000-0000-7000-8000-000000000001");
        // 8 concurrent producers so the writer is committing real batches when it is killed.
        var producers = Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
        {
            while (true)
            {
                Guid id = Ids.New();
                var message = new AcceptedMessage
                {
                    MessageId = id,
                    TenantId = tenant,
                    Source = MessageSource.Api,
                    EnvelopeFrom = EmailAddress.Parse("sender@example.com"),
                    Recipients = [new AcceptedRecipient(Ids.New(), EmailAddress.Parse("rcpt@example.org"))],
                    Raw = raw,
                    ReceivedAt = DateTimeOffset.UtcNow,
                    ExpiresAt = DateTimeOffset.UtcNow.AddDays(5),
                    SendingDomain = "example.com",
                };
                await storage.Intake.AcceptAsync(message, CancellationToken.None);
                lock (Console.Out)
                {
                    Console.Out.WriteLine("ACK " + id.ToString("N"));
                    Console.Out.Flush();
                }
            }
        })).ToArray();
        await Task.WhenAll(producers);
        return 0;
    }
}
