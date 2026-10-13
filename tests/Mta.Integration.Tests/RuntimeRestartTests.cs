using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Reports;
using Mta.Policy;
using Mta.Storage;
using Mta.Storage.Sqlite;
using Mta.Tls;
using Mta.Tls.TlsRpt;

namespace Mta.Integration.Tests;

/// <summary>
/// The state the runtime keeps in memory for speed is written behind and read back at the next start: the sending counters of the current hour and day (so a restart does not reset a cap) and
/// the TLS-RPT counters (so a restart does not lose the day's report). Each test runs a real runtime over SQLite files, stops it the way the host does (the runtime state service flushes
/// at stop), and starts another one over the same files.
/// </summary>
[Collection("Runtime")]
public sealed class RuntimeRestartTests : IAsyncLifetime
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    /// <summary>Fixed in the middle of the current hour, so a test that runs across an hour boundary cannot move into another counter window.</summary>
    private sealed class FrozenClock : IClock
    {
        private readonly DateTimeOffset _at;

        public FrozenClock()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            _at = new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, 30, 0, TimeSpan.Zero);
        }

        public DateTimeOffset UtcNow => _at;

        public long Timestamp => System.Diagnostics.Stopwatch.GetTimestamp();
    }

    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-restart-it-").FullName;
    private readonly FrozenClock _clock = new();

    public Task InitializeAsync() => Task.CompletedTask;

    public Task DisposeAsync()
    {
        // The directory was created by this test (a unique name under the temp folder) and holds only its own files.
        Directory.Delete(_dir, recursive: true);
        return Task.CompletedTask;
    }

    private async Task<EggMailRuntime> StartAsync()
    {
        var config = new MtaConfig
        {
            Hostname = "egg.test",
            Storage = new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _dir, StatsFlushInterval = TimeSpan.Zero } },
            Smtp = new SmtpSection { Listeners = new Dictionary<string, ListenerSection>() },
            Sending = new SendingSection { TenantPerHour = 3, TenantPerDay = 5 },
            Delivery = new DeliverySection { AllowPrivateMxAddresses = true },
        };
        var storage = SqliteStorage.Create(config.Storage);
        await storage.InitializeAsync(default);
        return await EggMailRuntime.CreateAsync(config, storage, _clock, NullMtaLog.Instance, default);
    }

    /// <summary>A graceful stop: the runtime state service writes the last counts, then the runtime and the storage are closed.</summary>
    private static async Task StopGracefullyAsync(EggMailRuntime runtime)
    {
        var service = new RuntimeStateService(runtime);
        await service.StartAsync(default);
        await service.StopAsync(default);
        await Close(runtime);
    }

    /// <summary>A crash: nothing is flushed.</summary>
    private static async Task CrashAsync(EggMailRuntime runtime) => await Close(runtime);

    private static async Task Close(EggMailRuntime runtime)
    {
        await runtime.DisposeAsync();
        await runtime.Storage.DisposeAsync();
    }

    private static long Used(EggMailRuntime runtime, CounterScope scope, CounterWindow window) =>
        runtime.Limits.GetUsage(TenantId, null).Single(u => u.Scope == scope && u.Window == window).Used;

    [Fact]
    public async Task A_restart_does_not_reset_the_hourly_and_daily_sending_counters()
    {
        EggMailRuntime first = await StartAsync();
        for (int i = 0; i < 3; i++)
        {
            Assert.True(first.Limits.TryReserve(TenantId, null).IsAllowed);
        }

        Assert.Equal(SendingDecisionKind.Deferred, first.Limits.TryReserve(TenantId, null).Kind);   // 3 per hour
        await StopGracefullyAsync(first);

        EggMailRuntime second = await StartAsync();
        try
        {
            Assert.Equal(3, Used(second, CounterScope.Tenant, CounterWindow.Hour));
            Assert.Equal(3, Used(second, CounterScope.Tenant, CounterWindow.Day));
            SendingDecision decision = second.Limits.TryReserve(TenantId, null);
            Assert.Equal(SendingDecisionKind.Deferred, decision.Kind);
            Assert.Equal("tenant hourly limit reached", decision.Reason);
        }
        finally
        {
            await Close(second);
        }
    }

    [Fact]
    public async Task A_crash_loses_only_what_was_counted_since_the_last_flush()
    {
        EggMailRuntime first = await StartAsync();
        first.Limits.TryReserve(TenantId, null, 2);
        await first.FlushRuntimeStateAsync(default);   // what the runtime state service does every 10 seconds
        first.Limits.TryReserve(TenantId, null, 1);
        await CrashAsync(first);

        EggMailRuntime second = await StartAsync();
        try
        {
            Assert.Equal(2, Used(second, CounterScope.Tenant, CounterWindow.Hour));
        }
        finally
        {
            await Close(second);
        }
    }

    [Fact]
    public async Task TLS_RPT_counters_are_written_at_a_graceful_stop_and_found_again_by_the_next_runtime()
    {
        EggMailRuntime first = await StartAsync();
        var policy = TlsRptPolicyDescriptor.FromTlsa([]);
        first.TlsCollector!.RecordSuccess("example.net", policy, "mx.example.net");
        first.TlsCollector.RecordFailure("example.net", policy, "mx.example.net", TlsResultType.CertificateExpired);
        await StopGracefullyAsync(first);

        EggMailRuntime second = await StartAsync();
        try
        {
            // The collector of the new process is empty; the counters are in the store, waiting for the day to end.
            Assert.Empty(second.TlsCollector!.Snapshot());
            int tomorrow = TlsReportJournal.DayNumber(DateOnly.FromDateTime(_clock.UtcNow.UtcDateTime)) + 1;
            var bucket = Assert.Single(await second.Storage.Config.GetTlsRptBucketsAsync(tomorrow, 10, default));
            Assert.Equal("example.net", bucket.PolicyDomain);
            Assert.Contains("CertificateExpired", bucket.DataJson);
        }
        finally
        {
            await Close(second);
        }
    }
}
