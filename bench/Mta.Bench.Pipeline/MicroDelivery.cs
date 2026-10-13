using System.Diagnostics;
using System.Security.Cryptography;
using Mta.Core;
using Mta.Dkim;
using Mta.Host.Submission;
using Mta.Policy;
using Mta.Storage;
using Mta.Storage.Sqlite;

/// <summary>
/// Allocation (and time) per delivery for each storage and signing step of the delivery path in isolation, one caller at a time (and
/// 32 concurrent callers where batching matters): <c>dotnet run -c Release --project bench/Mta.Bench.Pipeline -- --micro-delivery true</c>.
/// </summary>
internal static class MicroDelivery
{
    private const int Messages = 4000;

    public static async Task RunAsync()
    {
        string head = "From: Tester <news@bench.test>\r\nTo: rcpt0@dest.test\r\nSubject: load test\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\nMessage-ID: <abcdef@bench.test>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n";
        byte[] message = System.Text.Encoding.ASCII.GetBytes(head + new string('x', 1800) + "\r\n");
        byte[] received = System.Text.Encoding.ASCII.GetBytes("Received: from client.test (127.0.0.1) by egg.local with ESMTPSA id abc; Mon, 12 Oct 2026 08:00:00 +0000\r\n");
        var tenant = new Tenant(Guid.NewGuid(), "T", "t", true, DateTimeOffset.UtcNow, false);

        Console.WriteLine($"delivery path per delivery, 1 recipient, {message.Length} byte message, {Messages} deliveries per step; B = bytes allocated, us = microseconds");
        string dir = Directory.CreateTempSubdirectory("eggmail-microdelivery-").FullName;
        try
        {
            foreach (var (label, storage) in new (string, IStorage)[]
            {
                ("InMemory", new Mta.Storage.InMemory.InMemoryStorage(new StorageOptions())),
                ("SQLite (sync off)", SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = dir, SyncMode = SqliteSyncMode.Off } })),
            })
            {
                await storage.InitializeAsync(default);
                await storage.Config.UpsertDomainAsync(new DomainRecord(Guid.NewGuid(), tenant.Id, "bench.test", DomainStatus.Verified, null, false, DateTimeOffset.UtcNow, null, null, 0, null, false, null), default);
                var submission = new SubmissionService(storage, SystemClock.Instance, new SenderPolicy(), new StorageOptions());
                var request = new SubmissionRequest { Tenant = tenant, Source = MessageSource.Smtp, EnvelopeFrom = EmailAddress.Parse("load0@bench.test"), Recipients = [EmailAddress.Parse("rcpt0@dest.test")], Message = message, ReceivedHeader = received };
                await Parallel.ForEachAsync(Enumerable.Range(0, Messages), new ParallelOptions { MaxDegreeOfParallelism = 16 }, async (_, ct) => await submission.SubmitAsync(request, ct));

                Console.WriteLine($"--- {label}");
                var claimed = new List<ClaimedDelivery>();
                await Step("ClaimAsync (batches of 64)", Messages, async () =>
                {
                    while (true)
                    {
                        var batch = await storage.Deliveries.ClaimAsync("bench", 64, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5), default);
                        if (batch.Count == 0) { break; }
                        claimed.AddRange(batch);
                    }
                });

                await Step("IsSuppressedAsync", claimed.Count, async () =>
                {
                    foreach (var d in claimed) { await storage.Config.IsSuppressedAsync(d.TenantId, d.Recipient.ToString(), default); }
                });

                await Step("GetRawAsync", claimed.Count, async () =>
                {
                    foreach (var d in claimed) { await storage.Deliveries.GetRawAsync(d.MessageId, default); }
                });

                await Step("IsSuppressedAsync, 32 concurrent", claimed.Count, async () =>
                {
                    await Parallel.ForEachAsync(claimed, new ParallelOptions { MaxDegreeOfParallelism = 32 }, async (d, ct) => await storage.Config.IsSuppressedAsync(d.TenantId, d.Recipient.ToString(), ct));
                });

                await Step("GetRawAsync, 32 concurrent", claimed.Count, async () =>
                {
                    await Parallel.ForEachAsync(claimed, new ParallelOptions { MaxDegreeOfParallelism = 32 }, async (d, ct) => await storage.Deliveries.GetRawAsync(d.MessageId, ct));
                });

                if (label == "InMemory")
                {
                    using var rsa = RSA.Create(2048);
                    using var signer = new DkimSigner(new DkimSignerOptions { Domain = "bench.test", Selector = "bench1" }, rsa);
                    await Step("DkimSigner.SignToBytes (RSA-2048)", 500, () =>
                    {
                        for (int i = 0; i < 500; i++) { signer.SignToBytes(message); }
                        return Task.CompletedTask;
                    });
                }

                var at = DateTimeOffset.UtcNow;
                var half = claimed.Count / 2;
                await Step("RecordAttemptAsync Delivered, one at a time", half, async () =>
                {
                    for (int i = 0; i < half; i++) { await storage.Deliveries.RecordAttemptAsync(Delivered(claimed[i], at), default); }
                });

                await Step("RecordAttemptAsync Delivered, 32 concurrent", claimed.Count - half, async () =>
                {
                    await Parallel.ForEachAsync(claimed.Skip(half), new ParallelOptions { MaxDegreeOfParallelism = 32 }, async (d, ct) => await storage.Deliveries.RecordAttemptAsync(Delivered(d, at), ct));
                });

                await storage.DisposeAsync();
            }
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }

    private static DeliveryAttempt Delivered(ClaimedDelivery d, DateTimeOffset at) => new()
    {
        DeliveryId = d.DeliveryId,
        Outcome = DeliveryOutcome.Delivered,
        At = at,
        SmtpCode = 250,
        EnhancedCode = "2.0.0",
        Message = "OK",
        MxHost = "mx.dest.test",
        Route = "direct",
        Duration = TimeSpan.FromMilliseconds(5),
    };

    private static async Task Step(string name, int operations, Func<Task> work)
    {
        GC.Collect();
        long before = GC.GetTotalAllocatedBytes(precise: true);
        long started = Stopwatch.GetTimestamp();
        await work();
        double us = Stopwatch.GetElapsedTime(started).TotalMicroseconds / operations;
        long bytes = (GC.GetTotalAllocatedBytes(precise: true) - before) / operations;
        Console.WriteLine($"{name,-60} {bytes,8} B/op {us,9:F1} us/op");
    }
}
