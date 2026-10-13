using System.Diagnostics;
using Mta.Core;
using Xunit.Abstractions;

namespace Mta.Storage.Portability.Tests;

/// <summary>
/// Measures the switch on a larger data set. Not part of the normal run: set <c>EGGMAIL_SWITCH_BENCH=1</c> (and optionally
/// <c>EGGMAIL_SWITCH_BENCH_N</c>, default 20000 messages of each kind) and run with <c>--logger "console;verbosity=detailed"</c> to see
/// the figures. The numbers are for the machine they ran on (docs/components/switch.md records what was measured).
/// </summary>
public static class SwitchThroughput
{
    public static bool Enabled => Environment.GetEnvironmentVariable("EGGMAIL_SWITCH_BENCH") == "1";

    public static int Messages => int.TryParse(Environment.GetEnvironmentVariable("EGGMAIL_SWITCH_BENCH_N"), out int n) && n > 0 ? n : 20_000;

    /// <summary><paramref name="queued"/> messages stay queued (2 KB each); <paramref name="history"/> messages are delivered and leave events and content.</summary>
    public static async Task SeedAsync(IStorage storage, int queued, int history)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Guid tenant = Seed.TenantA;
        await storage.Config.UpsertTenantAsync(new Tenant(tenant, "Acme", "acme", true, now, false), default);
        for (int batch = 0; batch < history; batch += 1000)
        {
            int count = Math.Min(1000, history - batch);
            var accepts = new List<Task>();
            for (int i = 0; i < count; i++)
            {
                DateTimeOffset received = now.AddDays(-(i % 5) - 1);
                accepts.Add(storage.Intake.AcceptAsync(Seed.Message(received, now.AddDays(1), [$"h{batch + i}@example.org"], size: 2000), default).AsTask());
            }

            await Task.WhenAll(accepts);
            while (await storage.Deliveries.ClaimAsync("seed", 500, now, TimeSpan.FromMinutes(5), default) is { Count: > 0 } claimed)
            {
                foreach (ClaimedDelivery d in claimed)
                {
                    await storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = now, SmtpCode = 250, MxHost = "mx.example.org", Duration = TimeSpan.FromMilliseconds(30) }, default);
                }
            }
        }

        for (int batch = 0; batch < queued; batch += 1000)
        {
            int count = Math.Min(1000, queued - batch);
            var accepts = new List<Task>();
            for (int i = 0; i < count; i++)
            {
                accepts.Add(storage.Intake.AcceptAsync(Seed.Message(now, now.AddDays(5), [$"q{batch + i}@example.org"], size: 2000), default).AsTask());
            }

            await Task.WhenAll(accepts);
        }

        await storage.Stats.FlushAsync(default);
    }

    public static async Task<string> RunAsync(StorageSwitchEngine engine, TestStore source, TestStore target, string bundle, ITestOutputHelper output, string label)
    {
        var sw = Stopwatch.StartNew();
        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = bundle, Passphrase = "correct horse battery staple", QuiesceTimeout = TimeSpan.FromMilliseconds(50) }, null, default);
        TimeSpan start = sw.Elapsed;

        sw.Restart();
        ExportResult export = await engine.ExportAsync(new BundleRequest { BundlePath = bundle, Passphrase = "correct horse battery staple" }, null, default);
        TimeSpan exportTime = sw.Elapsed;

        sw.Restart();
        ImportResult import = await engine.ImportAsync(new ImportRequest { BundlePath = bundle, Passphrase = "correct horse battery staple" }, null, default);
        TimeSpan importTime = sw.Elapsed;

        sw.Restart();
        VerifyReport verify = await engine.VerifyAsync(new BundleRequest { BundlePath = bundle, Passphrase = "correct horse battery staple" }, null, default);
        TimeSpan verifyTime = sw.Elapsed;

        if (!verify.Ok)
        {
            throw new InvalidOperationException(string.Join("; ", verify.Problems));
        }

        string line =
            $"{label}: {export.Rows:N0} rows, bundle {export.Bytes / 1_048_576.0:N1} MiB | export {exportTime.TotalSeconds:N1} s ({export.Rows / exportTime.TotalSeconds:N0} rows/s, {export.Bytes / 1_048_576.0 / exportTime.TotalSeconds:N1} MiB/s) | " +
            $"import {importTime.TotalSeconds:N1} s ({import.RowsApplied / importTime.TotalSeconds:N0} rows/s) | verify {verifyTime.TotalSeconds:N1} s | fence {start.TotalMilliseconds:N0} ms";
        output.WriteLine(line);
        return line;
    }
}

public class SwitchThroughputTests(ITestOutputHelper output) : SwitchTestBase
{
    [Theory]
    [InlineData(StoreKind.Sqlite, StoreKind.Sqlite)]
    [InlineData(StoreKind.Sqlite, StoreKind.InMemory)]
    public async Task Measure(StoreKind from, StoreKind to)
    {
        if (!SwitchThroughput.Enabled)
        {
            return; // the normal run does not measure
        }

        int n = SwitchThroughput.Messages;
        TestStore source = await NewStoreAsync(from, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(to, HistoryMode.Full, "target");
        var sw = Stopwatch.StartNew();
        await SwitchThroughput.SeedAsync(source.Storage, n, n);
        output.WriteLine($"seeded {n:N0} queued + {n:N0} delivered messages in {sw.Elapsed.TotalSeconds:N1} s");
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator(), options: new SwitchOptions());
        await SwitchThroughput.RunAsync(engine, source, target, BundleDir(), output, $"{from} to {to}");
    }
}
