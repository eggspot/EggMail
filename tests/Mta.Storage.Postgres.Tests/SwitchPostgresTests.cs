using Mta.Core;
using Mta.Storage.Model;
using Mta.Storage.Portability;
using Mta.Storage.Portability.Tests;
using Mta.Storage.Transfer;

namespace Mta.Storage.Postgres.Tests;

/// <summary>Drops the throwaway database(s) of a store when the test ends.</summary>
internal sealed class HarnessOwner(PgHarness harness) : IAsyncDisposable
{
    public async ValueTask DisposeAsync() => await harness.DisposeAsync();
}

/// <summary>The backend switch between SQLite and PostgreSQL, in both directions and both history modes (design §4.6).</summary>
public class SwitchPostgresTests : SwitchTestBase
{
    private async Task<TestStore> NewPgStoreAsync(HistoryMode history, string name, bool certificateRing = true)
    {
        var harness = new PgHarness();
        var options = new StorageOptions
        {
            History = new HistoryOptions { Mode = history },
            Content = new ContentOptions { StoreAttachments = true, AllowAttachmentStorage = true },
        };
        IStorage storage = await harness.CreateAsync(options, SystemClock.Instance);
        StorageOptions effective = PgHarness.WithDatabase(options, harness.Current!.ConnectionString);
        return Track(await TestStore.WrapAsync(StoreKind.Postgres, storage, effective, Root, name, o => PostgresStorage.Create(o), new HarnessOwner(harness), certificateRing));
    }

    private Task<TestStore> NewAsync(StoreKind kind, HistoryMode history, string name) =>
        kind == StoreKind.Postgres ? NewPgStoreAsync(history, name) : NewStoreAsync(kind, history, name);

    [Theory]
    [InlineData(StoreKind.Sqlite, StoreKind.Postgres, HistoryMode.Full, HistoryMode.Full)]
    [InlineData(StoreKind.Postgres, StoreKind.Sqlite, HistoryMode.Full, HistoryMode.Full)]
    [InlineData(StoreKind.Sqlite, StoreKind.Postgres, HistoryMode.Full, HistoryMode.StatsOnly)]
    [InlineData(StoreKind.Postgres, StoreKind.Sqlite, HistoryMode.Full, HistoryMode.StatsOnly)]
    [InlineData(StoreKind.Sqlite, StoreKind.Postgres, HistoryMode.StatsOnly, HistoryMode.Full)]
    [InlineData(StoreKind.Postgres, StoreKind.Sqlite, HistoryMode.StatsOnly, HistoryMode.StatsOnly)]
    public async Task Quiesce_switch_moves_config_stats_queue_and_history_between_SQLite_and_PostgreSQL(StoreKind from, StoreKind to, HistoryMode sourceHistory, HistoryMode targetHistory)
    {
        TestStore source = await NewAsync(from, sourceHistory, "source");
        TestStore target = await NewAsync(to, targetHistory, "target");
        Seed.Seeded seeded = await Seed.PopulateAsync(source.Storage, source.Protector, queued: 4);
        bool withHistory = sourceHistory == HistoryMode.Full && targetHistory == HistoryMode.Full;

        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());
        await SwitchToConfirmedAsync(engine, BundleDir());

        // Held until activation, then claimable with the same ids.
        Assert.Empty(await target.Storage.Deliveries.ClaimAsync("early", 100, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default));
        Assert.True(await TargetActivation.ActivateAsync(target.Transfer, SystemClock.Instance, default));
        var claimed = await target.Storage.Deliveries.ClaimAsync("after", 100, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default);
        Assert.Equal(seeded.QueuedDeliveryIds.Order(), claimed.Select(c => c.DeliveryId).Order());

        await AssertSameAsync(source, target, withHistory, "delivery_queue"); // the claim above leased the target rows
        await AssertSecretsAsync(source, target);
        if (withHistory)
        {
            Assert.True(await target.Transfer.CountAsync(TransferTables.MessageEvents, TransferRange.All, default) > 10);
        }
        else if (sourceHistory == HistoryMode.Full)
        {
            Assert.False(target.Transfer.HasPart(TransferPart.History));
        }

        IntakeResult dup = await target.Storage.Intake.AcceptAsync(Seed.Message(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(5), ["x@example.org"], idempotencyKey: seeded.IdempotencyKey), default);
        Assert.Equal(IntakeStatus.DuplicateIdempotencyKey, dup.Status);
        Assert.Equal(seeded.IdempotencyMessageId, dup.MessageId);
    }

    [Fact]
    public async Task A_fenced_PostgreSQL_source_stays_closed_after_a_restart_and_a_replica_cannot_claim_the_marked_rows()
    {
        TestStore source = await NewPgStoreAsync(HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 3);

        // A second replica on the same database that has not noticed anything yet.
        PostgresStorage replica = PostgresStorage.Create(source.Options);
        await replica.InitializeAsync(default);
        try
        {
            await SwitchToConfirmedAsync(NewEngine(source, target, activator: new RecordingActivator()), BundleDir());

            // Its gate is still open, but the transfer marks are in the rows: it claims nothing.
            Assert.False(replica.Transfer.Gate.IsClosed);
            Assert.Empty(await replica.Deliveries.ClaimAsync("replica", 100, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default));
            Assert.Empty(await replica.Webhooks.ClaimDueAsync("replica", 100, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default));

            // Reading the state (what the host's watcher does) closes the replica's gate.
            Assert.Equal(SwitchStates.Fenced, (await replica.Transfer.GetStateAsync(default))!.State);
            Assert.True(replica.Transfer.Gate.IsClosed);
            await Assert.ThrowsAsync<StorageFencedException>(async () => await replica.Intake.AcceptAsync(Seed.Message(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(5), ["r@example.org"]), default));
        }
        finally
        {
            await replica.DisposeAsync();
        }

        await source.ReopenAsync();
        Assert.True(source.Transfer.Gate.IsClosed);
        await Assert.ThrowsAsync<StorageFencedException>(async () => await source.Storage.Intake.AcceptAsync(Seed.Message(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(5), ["a@example.org"]), default));
        Assert.Empty(await source.Storage.Deliveries.ClaimAsync("restarted", 100, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default));
        Assert.Empty(await source.Storage.Maintenance.RunAsync(DateTimeOffset.UtcNow, default));
    }

    [Fact]
    public async Task Rollback_to_a_PostgreSQL_source_clears_the_marks_and_discards_the_SQLite_target()
    {
        TestStore source = await NewPgStoreAsync(HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 3);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());
        await SwitchToConfirmedAsync(engine, BundleDir());

        await engine.RollbackAsync(false, default);

        Assert.Empty(await target.Transfer.GetNonEmptyTablesAsync(default));
        Assert.False(source.Transfer.Gate.IsClosed);
        Assert.Equal(6, (await source.Storage.Deliveries.ClaimAsync("w", 100, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default)).Count);
    }

    [Fact]
    public async Task Rollback_to_a_SQLite_source_discards_the_PostgreSQL_target_including_its_history_partitions_data()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewPgStoreAsync(HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 2, days: 6);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());
        await SwitchToConfirmedAsync(engine, BundleDir());
        Assert.True(await target.Transfer.CountAsync(TransferTables.MessageIndex, TransferRange.All, default) > 0);

        await engine.RollbackAsync(false, default);
        Assert.Empty(await target.Transfer.GetNonEmptyTablesAsync(default));
        Assert.Null(await target.Transfer.GetStateAsync(default));
        Assert.False(source.Transfer.Gate.IsClosed);
    }

    [Fact]
    public async Task History_older_than_the_partitions_the_target_creates_by_itself_is_imported()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewPgStoreAsync(HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 1, days: 5);
        // Make one message much older than the partitions created at start (a month ago): its day has no partition yet.
        DateTimeOffset old = DateTimeOffset.UtcNow.AddDays(-25);
        AcceptedMessage m = Seed.Message(old, DateTimeOffset.UtcNow.AddDays(1), ["old@example.net"]);
        await source.Storage.Intake.AcceptAsync(m, default);
        var claimed = await source.Storage.Deliveries.ClaimAsync("w", 100, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1), default);
        foreach (ClaimedDelivery d in claimed.Where(d => d.MessageId == m.MessageId))
        {
            await source.Storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = DateTimeOffset.UtcNow, SmtpCode = 250 }, default);
        }

        await source.Storage.Deliveries.ReleaseOwnedLeasesAsync("w", default);
        await SwitchToConfirmedAsync(NewEngine(source, target, activator: new RecordingActivator()), BundleDir());
        await AssertSameAsync(source, target);
        Assert.Contains((await ReadAsync<MessageIndexEntity>(target, TransferTables.MessageIndex)), i => i.MessageId == m.MessageId);
    }

    [Fact]
    public async Task A_killed_history_import_into_PostgreSQL_resumes_after_the_last_applied_chunk()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewPgStoreAsync(HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 2, deliveredPerDay: 3, days: 5);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());
        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass, QuiesceTimeout = TimeSpan.FromMilliseconds(50) }, null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);

        using var cts = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => engine.ImportAsync(
            new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, new CancelOnProgress(cts, p => p.Phase == "import-history" && p.Done >= 3), cts.Token));
        int partial = (await target.Transfer.GetAppliedChunksAsync((await BundleReader.OpenAsync(BundleDir(), default)).Manifest.SwitchId, TransferPart.History, default)).Count;
        Assert.True(partial >= 1);

        await NewEngine(source, target).ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        VerifyReport report = await engine.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.True(report.Ok, string.Join("; ", report.Problems));
        await AssertSameAsync(source, target);
    }

    [Fact]
    public async Task Different_key_protection_between_SQLite_and_PostgreSQL_is_handled_by_re_protection()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source", certificateRing: true);
        TestStore target = await NewPgStoreAsync(HistoryMode.Full, "target", certificateRing: false);
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 1);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());
        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass, QuiesceTimeout = TimeSpan.FromMilliseconds(50), AcceptUnprotectedTarget = true }, null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        await engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass, AcceptUnprotectedTarget = true }, null, default);
        Assert.True((await engine.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default)).Ok);
        await AssertSecretsAsync(source, target);
    }
}

/// <summary>Throughput of the switch to and from PostgreSQL; only runs with EGGMAIL_SWITCH_BENCH=1 (see SwitchThroughput).</summary>
public class SwitchPostgresThroughputTests(Xunit.Abstractions.ITestOutputHelper output) : SwitchTestBase
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Measure(bool fromPostgres)
    {
        if (!SwitchThroughput.Enabled)
        {
            return;
        }

        int n = SwitchThroughput.Messages;
        TestStore pg = await NewPgAsync("pg");
        TestStore lite = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "lite");
        TestStore source = fromPostgres ? pg : lite;
        TestStore target = fromPostgres ? lite : pg;
        await SwitchThroughput.SeedAsync(source.Storage, n, n);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator(), options: new SwitchOptions());
        await SwitchThroughput.RunAsync(engine, source, target, BundleDir(), output, fromPostgres ? "PostgreSQL to SQLite" : "SQLite to PostgreSQL");
    }

    private async Task<TestStore> NewPgAsync(string name)
    {
        var harness = new PgHarness();
        var options = new StorageOptions { History = new HistoryOptions { Mode = HistoryMode.Full }, Content = new ContentOptions { StoreAttachments = true, AllowAttachmentStorage = true } };
        IStorage storage = await harness.CreateAsync(options, SystemClock.Instance);
        StorageOptions effective = PgHarness.WithDatabase(options, harness.Current!.ConnectionString);
        return Track(await TestStore.WrapAsync(StoreKind.Postgres, storage, effective, Root, name, o => PostgresStorage.Create(o), new HarnessOwner(harness)));
    }
}
