using Mta.Core;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>
/// The child process of the process-kill lifecycle test: a one-recipient message is accepted, every third round two deliveries are claimed and the first one is reported delivered, the second
/// stays leased. Every step is printed (and flushed) <b>after</b> it returned, and the report is announced <b>before</b> it is made, so the parent knows exactly what was acknowledged:
/// <c>ACK &lt;message&gt; &lt;delivery&gt;</c>, <c>CLAIM &lt;delivery&gt;</c>, <c>RECORDING &lt;delivery&gt;</c>, <c>DONE &lt;delivery&gt;</c>. The parent kills it with SIGKILL.
/// Arguments: <c>--crash-worker &lt;dataDirectory&gt; &lt;Off|Normal|Full&gt;</c>.
/// </summary>
public static class CrashWorkerChild
{
    public const string Argument = "--crash-worker";

    public static async Task<int> RunAsync(string[] args)
    {
        string dir = args[1];
        var sync = Enum.Parse<SqliteSyncMode>(args[2]);
        var options = new StorageOptions
        {
            Sqlite = new SqliteOptions { DataDirectory = dir, SyncMode = sync, StatsFlushInterval = TimeSpan.Zero },
        };
        await using SqliteStorage storage = SqliteStorage.Create(options);
        await storage.InitializeAsync(CancellationToken.None);
        Print("READY");

        var tenant = Guid.Parse("a0000000-0000-7000-8000-000000000001");
        byte[] raw = new byte[1024];
        Random.Shared.NextBytes(raw);
        for (int round = 0; ; round++)
        {
            Guid message = Ids.New();
            Guid delivery = Ids.New();
            await storage.Intake.AcceptAsync(new AcceptedMessage
            {
                MessageId = message,
                TenantId = tenant,
                Source = MessageSource.Api,
                EnvelopeFrom = EmailAddress.Parse("sender@example.com"),
                Recipients = [new AcceptedRecipient(delivery, EmailAddress.Parse("rcpt@example.org"))],
                Raw = raw,
                ReceivedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(5),
                SendingDomain = "example.com",
            }, CancellationToken.None);
            Print($"ACK {message:N} {delivery:N}");

            if (round % 3 != 2)
            {
                continue;
            }

            IReadOnlyList<ClaimedDelivery> claimed = await storage.Deliveries.ClaimAsync("worker-child", 2, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5), CancellationToken.None);
            foreach (ClaimedDelivery c in claimed)
            {
                Print($"CLAIM {c.DeliveryId:N}");
            }

            if (claimed.Count > 0)
            {
                ClaimedDelivery first = claimed[0];
                Print($"RECORDING {first.DeliveryId:N}");
                await storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt
                {
                    DeliveryId = first.DeliveryId,
                    Outcome = DeliveryOutcome.Delivered,
                    At = DateTimeOffset.UtcNow,
                    SmtpCode = 250,
                }, CancellationToken.None);
                Print($"DONE {first.DeliveryId:N}");
            }
        }
    }

    private static void Print(string line)
    {
        Console.Out.WriteLine(line);
        Console.Out.Flush();
    }
}
