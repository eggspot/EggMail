using Mta.Core;
using Mta.Storage.Tests;
using Mta.TestSupport;
using Xunit.Abstractions;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>
/// <c>Sqlite:QueuePersistence=Memory</c> loses the queue on every restart by design ("accepted mail is held in memory and lost on restart", a startup warning says so). The crash loop checks the
/// rest of that promise over many kills: nothing a restart does brings a delivery back, no delivery is handed out again after the restart that lost it, the files that are persistent stay
/// persistent (configuration written and acknowledged before a kill is readable after it, flushed statistics are kept and the unflushed window is lost, never counted twice), and the store accepts
/// new mail at once.
/// </summary>
public class CrashLoopLifecycleMemoryQueueTests(ITestOutputHelper output) : IAsyncLifetime
{
    private static readonly Guid Tenant = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 10, 12, 12, 30, 0, TimeSpan.Zero));
    private readonly string _dir = SqliteTestStorage.NewDirectory();
    private SqliteStorage _storage = null!;

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        if (_storage is not null)
        {
            await _storage.DisposeAsync();
        }

        SqliteTestStorage.TryDelete(_dir);
    }

    private async Task OpenAsync()
    {
        var options = SqliteTestStorage.WithDirectory(new StorageOptions(), _dir, b => b.QueuePersistence = QueuePersistence.Memory);
        _storage = SqliteStorage.Create(options, _clock);
        await _storage.InitializeAsync(default);
    }

    private async Task KillAndReopenAsync()
    {
        _storage.Runtime.Aggregator.Drain(_clock.UtcNow);
        _storage.Runtime.Aggregator.DrainRecent();
        await _storage.DisposeAsync();
        await OpenAsync();
    }

    private static AcceptedMessage Message(DateTimeOffset at, int recipients, byte[] raw) => new()
    {
        MessageId = Ids.New(at),
        TenantId = Tenant,
        Source = MessageSource.Api,
        EnvelopeFrom = EmailAddress.Parse("sender@example.com"),
        Recipients = Enumerable.Range(0, recipients).Select(i => new AcceptedRecipient(Ids.New(at), EmailAddress.Parse($"user{i}@dest.example"))).ToList(),
        Raw = raw,
        ReceivedAt = at,
        ExpiresAt = at.AddDays(5),
        SendingDomain = "example.com",
    };

    [Fact]
    public async Task A_memory_queue_loses_its_mail_at_every_kill_and_keeps_everything_else()
    {
        int seed = Accelerated.Seed(4242);
        int cycles = Accelerated.Scaled(25);
        output.WriteLine($"memory queue crash loop: seed {seed}, {cycles} cycles");
        var rng = new Random(seed);
        await OpenAsync();
        var everClaimed = new HashSet<Guid>();
        var everAccepted = new List<Guid>();
        var tenants = new List<Guid>();
        long flushedAccepted = 0;
        long pendingAccepted = 0;
        byte[] raw = new byte[600];
        rng.NextBytes(raw);

        for (int cycle = 0; cycle < cycles; cycle++)
        {
            string at = $"(seed {seed}, cycle {cycle})";
            var inQueue = new List<Guid>();
            for (int i = rng.Next(1, 5); i > 0; i--)
            {
                AcceptedMessage m = Message(_clock.UtcNow, rng.Next(1, 4), raw);
                Assert.Equal(IntakeStatus.Accepted, (await _storage.Intake.AcceptAsync(m, default)).Status);
                everAccepted.Add(m.MessageId);
                inQueue.Add(m.MessageId);
                pendingAccepted += m.Recipients.Count;
            }

            IReadOnlyList<ClaimedDelivery> claimed = await _storage.Deliveries.ClaimAsync("w", 100, _clock.UtcNow, TimeSpan.FromMinutes(5), default);
            Assert.NotEmpty(claimed);
            Assert.All(claimed, c => Assert.True(everClaimed.Add(c.DeliveryId), $"a delivery was handed out again after a restart lost it {at}"));
            foreach (ClaimedDelivery c in claimed.Take(rng.Next(0, claimed.Count)))
            {
                await _storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = c.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = _clock.UtcNow, SmtpCode = 250 }, default);
            }

            var tenant = new Tenant(Ids.New(), "T" + cycle, "t" + cycle, true, _clock.UtcNow, false);
            await _storage.Config.UpsertTenantAsync(tenant, default);
            tenants.Add(tenant.Id);
            if (rng.NextDouble() < 0.5)
            {
                await _storage.Stats.FlushAsync(default);
                flushedAccepted += pendingAccepted;
                pendingAccepted = 0;
            }

            _clock.Advance(TimeSpan.FromMinutes(rng.Next(1, 600)));
            await KillAndReopenAsync();
            pendingAccepted = 0;

            // The queue is empty and nothing of it comes back.
            QueueStats stats = await _storage.Deliveries.GetQueueStatsAsync(default);
            Assert.True(stats is { Queued: 0, Leased: 0, Deferred: 0, SpoolBytes: 0 }, $"the memory queue is not empty after a restart: {stats} {at}");
            foreach (Guid id in inQueue)
            {
                Assert.Null(await _storage.Deliveries.GetRawAsync(id, default));
            }

            Assert.Empty(await _storage.Deliveries.ClaimAsync("w", 100, _clock.UtcNow.AddDays(10), TimeSpan.FromMinutes(5), default));
            Assert.Empty(await _storage.Deliveries.ClaimExpiredAsync("reaper", 100, _clock.UtcNow.AddDays(10), default));

            // The persistent files kept what was acknowledged.
            var stored = (await _storage.Config.GetTenantsAsync(default)).Select(t => t.Id).ToHashSet();
            Assert.All(tenants, id => Assert.Contains(id, stored));
            long accepted = (await _storage.Stats.QueryAsync(null, _clock.UtcNow.AddDays(-30), _clock.UtcNow.AddDays(30), false, default)).Sum(r => r.Accepted);
            Assert.True(accepted == flushedAccepted, $"statistics: {accepted} accepted stored, expected exactly the flushed {flushedAccepted} {at}");
            Assert.Empty(_storage.QuarantineEvents);
        }
    }
}
