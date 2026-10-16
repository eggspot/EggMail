using Mta.Core;
using Mta.Storage;
using Mta.Storage.InMemory;
using Mta.Storage.Postgres;
using Mta.Storage.Postgres.Tests;
using Mta.Storage.Sqlite;
using Mta.TestSupport;
using Npgsql;
using Xunit.Abstractions;

namespace Mta.Host.Tests.Leaks;

/// <summary>
/// Accelerated lifecycle, leaks: the hot storage flow of a message (accept, claim, defer, lease expiry and re-claim, record, statistics, daily
/// retention) repeated for 10,000 messages per test on every backend. After a warm-up batch, three batches must not grow the managed heap,
/// threads, descriptors, timers, pooled-array rentals, prepared SQLite statements and native SQLite memory (SQLite), or server connections of the
/// test database (PostgreSQL). The retention runs inside the measured batches (the virtual clock moves a day every few rounds), so the delete
/// paths are part of what is measured.
/// </summary>
[Collection(LeakCollection.Name)]
public sealed class StorageLeakTests(ITestOutputHelper output)
{
    private const int Width = 50;
    private static readonly Guid Tenant = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    /// <summary>10,000 messages in total at the default scale: one warm-up batch and three measured ones of 50 rounds of 50 messages.</summary>
    private static int RoundsPerBatch => Accelerated.Scaled(50);

    [Fact]
    public async Task Leak_in_memory_storage_message_flow_does_not_grow()
    {
        var clock = new VirtualClock();
        await using var storage = new InMemoryStorage(Options(), clock, null, TimeSpan.Zero);
        await storage.InitializeAsync(default);

        using var probe = new LeakProbe(output.WriteLine) { WarmupBatches = 2 };
        probe.TrackArrayPoolBalance();
        LeakReport report = await probe.RunAsync(new StorageFlow(storage, clock).RoundAsync, RoundsPerBatch);
        report.AssertNoGrowth();
    }

    [Fact]
    public async Task Leak_sqlite_storage_message_flow_does_not_grow()
    {
        string dir = Directory.CreateTempSubdirectory("eggmail-leak-sqlite-").FullName;
        try
        {
            var clock = new VirtualClock();
            long statementsAtStart = PreparedStatements();
            await using (SqliteStorage storage = SqliteStorage.Create(Options(sqlite: dir), clock))
            {
                await storage.InitializeAsync(default);
                using var probe = new LeakProbe(output.WriteLine) { WarmupBatches = 2 };
                probe.TrackArrayPoolBalance(ignoreRentalsFrom: ["Microsoft.EntityFrameworkCore"]);   // EF Core rents an array per query (its expression funcletizer) and keeps it; the maintenance run queries through EF
                probe.Track("prepared SQLite statements", PreparedStatements);
                probe.Track("native SQLite memory (bytes)", () => SQLitePCL.raw.sqlite3_memory_used(), absolute: 1024 * 1024, relative: 0.25);
                LeakReport report = await probe.RunAsync(new StorageFlow(storage, clock).RoundAsync, RoundsPerBatch);
                report.AssertNoGrowth();
            }

            // Closing the storage finalizes every statement it prepared and detaches it from the gauges.
            Assert.Equal(statementsAtStart, PreparedStatements());
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [PostgresFact]
    public async Task Leak_postgres_storage_message_flow_does_not_grow()
    {
        await using TestDatabase db = await PostgresTestServer.Instance.CreateDatabaseAsync();
        var clock = new VirtualClock();
        var pg = new PostgresOptions { RuntimeConnectionString = db.ConnectionString, MaxPoolSize = 8, StatsFlushInterval = TimeSpan.Zero, RetentionDeletePause = TimeSpan.FromMilliseconds(1) };
        StorageOptions options = Options();
        await using PostgresStorage storage = PostgresStorage.Create(new StorageOptions { Backend = StorageBackend.Postgres, History = options.History, Retention = options.Retention, Content = options.Content, Queue = options.Queue, Postgres = pg }, clock);
        await storage.InitializeAsync(default);

        await using var monitor = new NpgsqlConnection(db.ConnectionString);
        await monitor.OpenAsync();
        using var probe = new LeakProbe(output.WriteLine) { WarmupBatches = 1 };
        probe.TrackArrayPoolBalance(ignoreRentalsFrom: ["Microsoft.EntityFrameworkCore"]);   // EF Core rents an array per query (its expression funcletizer) and keeps it; the maintenance run queries through EF
        probe.Allow("threads", 8);   // pool and thread-pool threads come and go with the load of a database round trip
        probe.Track("server connections of the database", () => ServerConnections(monitor, db.Name), absolute: 1);

        // A round costs a few milliseconds of server time and a virtual day (partition rotation and retention) more, so the default batch is smaller than on the other
        // backends (800 messages; EGGMAIL_ACCEL_SCALE=13 makes it 10,000). The server's tables are not what is measured here: the process is.
        LeakReport report = await probe.RunAsync(new StorageFlow(storage, clock, roundsPerDay: 8).RoundAsync, Accelerated.Scaled(16));
        report.AssertNoGrowth();
    }

    [Fact]
    public async Task Leak_opening_and_closing_sqlite_storages_releases_files_statements_and_gauge_registrations()
    {
        string dir = Directory.CreateTempSubdirectory("eggmail-leak-sqlite-cycle-").FullName;
        try
        {
            var clock = new VirtualClock();
            using var probe = new LeakProbe(output.WriteLine);
            probe.Track("prepared SQLite statements", PreparedStatements);
            probe.Track("native SQLite memory (bytes)", () => SQLitePCL.raw.sqlite3_memory_used(), absolute: 1024 * 1024, relative: 0.25);
            probe.Track("storages attached to the SQLite gauges", () => AttachedStorages());
            LeakReport report = await probe.RunAsync(async _ =>
            {
                // A restart of the storage over the same files, with a little work in between (a statement is prepared per kind of command).
                await using SqliteStorage storage = SqliteStorage.Create(Options(sqlite: dir), clock);
                await storage.InitializeAsync(default);
                await new StorageFlow(storage, clock).RoundAsync(0, width: 3);
            }, Accelerated.Scaled(20));
            report.AssertNoGrowth();
        }
        finally
        {
            TryDelete(dir);
        }
    }

    private static long PreparedStatements() => PreparedCommand.LiveCount;

    private static long AttachedStorages() => SqliteMetrics.AttachedCount;

    private static long ServerConnections(NpgsqlConnection monitor, string database)
    {
        using var cmd = new NpgsqlCommand("SELECT count(*) FROM pg_stat_activity WHERE datname = @d AND pid <> pg_backend_pid()", monitor);
        cmd.Parameters.AddWithValue("d", database);
        return (long)cmd.ExecuteScalar()!;
    }

    private static StorageOptions Options(string? sqlite = null) => new()
    {
        Sqlite = sqlite is null ? new SqliteOptions() : new SqliteOptions { DataDirectory = sqlite, StatsFlushInterval = TimeSpan.Zero },
    };

    private static void TryDelete(string directory)
    {
        try
        {
            // The directory was created by this test (a unique name under the temp folder) and holds only its own files.
            Directory.Delete(directory, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}

/// <summary>One round of the message flow against any storage, with a virtual clock the round moves.</summary>
internal sealed class StorageFlow(IStorage storage, VirtualClock clock, int roundsPerDay = 2)
{
    private static readonly Guid Tenant = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    private int _round;
    private int _sequence;

    public Task RoundAsync(int index) => RoundAsync(index, 50);

    /// <summary>Accepts <paramref name="width"/> messages, claims them, delivers a third, defers a third, lets a third lose its lease; then re-claims and delivers the rest.</summary>
    public async Task RoundAsync(int index, int width)
    {
        _ = index;
        DateTimeOffset now = clock.UtcNow;
        var messages = new AcceptedMessage[width];
        for (int i = 0; i < width; i++)
        {
            messages[i] = NewMessage(now);
        }

        await Task.WhenAll(messages.Select(m => storage.Intake.AcceptAsync(m, default).AsTask()));
        IReadOnlyList<ClaimedDelivery> claimed = await storage.Deliveries.ClaimAsync("leak-worker", width * 2, now, TimeSpan.FromMinutes(1), default);
        if (claimed.Count != width)
        {
            throw new InvalidOperationException($"Round {_round}: claimed {claimed.Count} of {width} accepted deliveries.");
        }

        var first = new List<Task>();
        for (int i = 0; i < claimed.Count; i++)
        {
            ClaimedDelivery d = claimed[i];
            switch (i % 3)
            {
                case 0:
                    first.Add(Record(d, DeliveryOutcome.Delivered, null, now).AsTask());
                    break;
                case 1:
                    first.Add(Record(d, DeliveryOutcome.Deferred, now.AddMinutes(2), now).AsTask());
                    break;
                default:
                    // Abandoned: the lease runs out and the delivery is handed out again.
                    first.Add(storage.Deliveries.ExtendLeaseAsync(d.DeliveryId, "leak-worker", now.AddMinutes(2), default).AsTask());
                    break;
            }
        }

        await Task.WhenAll(first);

        clock.Advance(TimeSpan.FromMinutes(3));
        now = clock.UtcNow;
        await storage.Deliveries.ReleaseExpiredLeasesAsync(now, default);
        IReadOnlyList<ClaimedDelivery> again = await storage.Deliveries.ClaimAsync("leak-worker", width * 2, now, TimeSpan.FromMinutes(1), default);
        if (again.Count != width - (width + 2) / 3)
        {
            throw new InvalidOperationException($"Round {_round}: re-claimed {again.Count} deliveries.");
        }

        await Task.WhenAll(again.Select(d => Record(d, DeliveryOutcome.Delivered, null, now).AsTask()));

        QueueStats stats = await storage.Deliveries.GetQueueStatsAsync(default);
        if (stats.Queued + stats.Leased + stats.Deferred != 0)
        {
            throw new InvalidOperationException($"Round {_round}: {stats.Queued}/{stats.Leased}/{stats.Deferred} deliveries are left in the queue.");
        }

        var key = new StatKey(new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, 0, 0, TimeSpan.Zero), Tenant, "example.com", "example.org");
        storage.Stats.Add(key, StatCounter.Accepted, width);
        storage.Stats.Add(key, StatCounter.Delivered, width);

        _round++;
        if (_round % roundsPerDay == 0)
        {
            // A day passes every few rounds (two by default, so the 30-day retention windows fill and start to delete inside the warm-up): statistics are flushed and rolled up, and the retention deletes what fell out of its window.
            clock.Advance(TimeSpan.FromDays(1));
            await storage.Stats.FlushAsync(default);
            await storage.Maintenance.RunAsync(clock.UtcNow, default);
        }
        else
        {
            clock.Advance(TimeSpan.FromMinutes(10));
        }
    }

    private ValueTask Record(ClaimedDelivery d, DeliveryOutcome outcome, DateTimeOffset? next, DateTimeOffset at) =>
        storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt
        {
            DeliveryId = d.DeliveryId,
            Outcome = outcome,
            At = at,
            SmtpCode = outcome == DeliveryOutcome.Delivered ? 250 : 451,
            Message = outcome == DeliveryOutcome.Delivered ? "queued" : "try later",
            MxHost = "mx.example.org",
            Route = "direct",
            Duration = TimeSpan.FromMilliseconds(120),
            NextAttemptAt = next,
        }, default);

    private AcceptedMessage NewMessage(DateTimeOffset at)
    {
        int n = Interlocked.Increment(ref _sequence);
        byte[] raw = new byte[2048];
        new Random(n).NextBytes(raw);
        return new AcceptedMessage
        {
            MessageId = Ids.New(at),
            TenantId = Tenant,
            Source = MessageSource.Api,
            EnvelopeFrom = EmailAddress.Parse("sender@example.com"),
            Recipients = [new AcceptedRecipient(Ids.New(at), EmailAddress.Parse($"user{n}@example.org"))],
            Raw = raw,
            ReceivedAt = at,
            ExpiresAt = at.AddDays(5),
            SendingDomain = "example.com",
            Content = new MessageContent("Hello", "plain body text", "<p>html body</p>", [new AttachmentInfo("a.pdf", "application/pdf", 1234, null)], false),
        };
    }
}
