using System.Globalization;
using Microsoft.Data.Sqlite;
using Mta.Core;
using Mta.Host.Backup;
using Mta.Storage;
using Mta.Storage.Sqlite;
using Mta.TestSupport;

namespace Mta.Host.Tests.Lifecycle;

/// <summary>
/// The scheduled SQLite backup over weeks of virtual time: it makes a backup exactly when the interval is up, keeps exactly the newest N, deletes only what
/// it made, and a backup that fails, is cancelled by a shutdown, is killed half-way, or is stamped by a wrong clock does not cost the good backups or
/// delay the next one. Backups are real <c>VACUUM INTO</c> copies of real files; only the clock is virtual. (PostgreSQL has no scheduler of this kind:
/// <c>BackupAsync</c> returns null there and the operator's tools make the backups.) It does not prove the restore of a backup on another machine; the soak
/// harness's restore drill does that.
/// </summary>
public class BackupLifecycleTests : IAsyncLifetime
{
    private const string Prefix = "eggmail-backup-";

    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-backup-lifecycle-").FullName;
    private readonly VirtualClock _clock = new(new DateTimeOffset(2026, 10, 12, 8, 0, 0, TimeSpan.Zero));
    private SqliteStorage _storage = null!;
    private string Backups => Path.Combine(_dir, "backups");

    public async Task InitializeAsync()
    {
        _storage = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = Path.Combine(_dir, "data") } }, _clock);
        await _storage.InitializeAsync(default);
    }

    public async Task DisposeAsync()
    {
        await _storage.DisposeAsync();
        SqliteConnection.ClearAllPools();
        // The unique directory created by this test class instance.
        Directory.Delete(_dir, recursive: true);
    }

    private static string Name(DateTimeOffset at) => Prefix + at.ToString("yyyyMMddTHHmmssfff'Z'", CultureInfo.InvariantCulture);

    private static readonly System.Text.RegularExpressions.Regex BackupName = new(@"^eggmail-backup-\d{8}T\d{9}Z$");

    /// <summary>The directories that are named like a backup (and only those: the look-alikes the tests plant are not).</summary>
    private List<string> BackupNames() =>
        Directory.Exists(Backups) ? [.. Directory.EnumerateDirectories(Backups).Select(d => Path.GetFileName(d)!).Where(n => BackupName.IsMatch(n)).Order(StringComparer.Ordinal)] : [];

    private async Task AddTenantAsync(int n) =>
        await _storage.Config.UpsertTenantAsync(new Tenant(Ids.New(_clock.UtcNow), "Tenant " + n, "tenant-" + n, true, _clock.UtcNow, false), default);

    private static long TenantCount(string backupDirectory)
    {
        using var connection = new SqliteConnection($"Data Source={Path.Combine(backupDirectory, "config.db")};Mode=ReadOnly;Pooling=False");
        connection.Open();
        using var integrity = connection.CreateCommand();
        integrity.CommandText = "PRAGMA integrity_check";
        Assert.Equal("ok", integrity.ExecuteScalar());
        using var count = connection.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM tenant";
        return (long)count.ExecuteScalar()!;
    }

    /// <summary>A storage that fails its backups on demand, as a full disk does, and forwards everything else.</summary>
    private sealed class FailingBackupStorage(IStorage inner) : IStorage
    {
        public bool Fail { get; set; }

        public StorageBackend Backend => inner.Backend;

        public HistoryMode HistoryMode => inner.HistoryMode;

        public IMessageIntake Intake => inner.Intake;

        public IDeliveryStore Deliveries => inner.Deliveries;

        public IConfigStore Config => inner.Config;

        public IStatsStore Stats => inner.Stats;

        public IHistoryStore History => inner.History;

        public IWebhookOutbox Webhooks => inner.Webhooks;

        public IStorageMaintenance Maintenance => field ??= new FailingMaintenance(this, inner.Maintenance);

        public Task InitializeAsync(CancellationToken cancellationToken) => inner.InitializeAsync(cancellationToken);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        private sealed class FailingMaintenance(FailingBackupStorage owner, IStorageMaintenance real) : IStorageMaintenance
        {
            public ValueTask<IReadOnlyList<MaintenanceReport>> RunAsync(DateTimeOffset now, CancellationToken cancellationToken) => real.RunAsync(now, cancellationToken);

            public ValueTask<StorageHealth> GetHealthAsync(CancellationToken cancellationToken) => real.GetHealthAsync(cancellationToken);

            public ValueTask<string?> BackupAsync(string directory, CancellationToken cancellationToken) =>
                owner.Fail ? throw new IOException("No space left on device") : real.BackupAsync(directory, cancellationToken);
        }
    }

    [Fact]
    public async Task Lifecycle_six_weeks_keep_exactly_the_newest_backups_and_make_each_exactly_when_the_interval_is_up()
    {
        Directory.CreateDirectory(Path.Combine(Backups, "precious"));
        Directory.CreateDirectory(Path.Combine(Backups, "eggmail-backup-not-a-timestamp"));
        Directory.CreateDirectory(Path.Combine(Backups, Prefix + "20260101T000000000Z.keep"));   // looks like a backup, is not named like one
        File.WriteAllText(Path.Combine(Backups, "eggmail-backup-20200101T000000000Z"), "a file, not a backup directory");
        File.WriteAllText(Path.Combine(Backups, "notes.txt"), "do not touch");

        var scheduler = new BackupScheduler(_storage, _clock, Backups, TimeSpan.FromHours(24), keep: 3);
        var made = new List<DateTimeOffset>();
        int ticks = Accelerated.Scaled(6 * 7 * 4);   // every six hours
        for (int i = 0; i < ticks; i++)
        {
            if (i % 4 == 0)
            {
                await AddTenantAsync(i / 4);   // the data changes daily, so every backup is a different state
            }

            string? path = await scheduler.RunOnceAsync(default);
            if (path is not null)
            {
                made.Add(_clock.UtcNow);
                Assert.Equal(Name(_clock.UtcNow), Path.GetFileName(path));
                if (made.Count % 5 == 0)
                {
                    Assert.Equal(i / 4 + 1, TenantCount(path));   // a consistent copy of the state at that moment
                }
            }

            var present = BackupNames();
            Assert.Equal(made.TakeLast(3).Select(Name).Order(StringComparer.Ordinal), present);   // exactly the newest three, never more
            _clock.Advance(TimeSpan.FromHours(6));
        }

        // One a day, from the first run: the interval is exact, not "about a day".
        Assert.Equal(ticks / 4, made.Count);
        for (int i = 1; i < made.Count; i++)
        {
            Assert.Equal(TimeSpan.FromHours(24), made[i] - made[i - 1]);
        }

        Assert.True(Directory.Exists(Path.Combine(Backups, "precious")));
        Assert.True(Directory.Exists(Path.Combine(Backups, "eggmail-backup-not-a-timestamp")));
        Assert.True(Directory.Exists(Path.Combine(Backups, Prefix + "20260101T000000000Z.keep")));
        Assert.True(File.Exists(Path.Combine(Backups, "eggmail-backup-20200101T000000000Z")));
        Assert.True(File.Exists(Path.Combine(Backups, "notes.txt")));
        Assert.Equal(made[^1], scheduler.LastSuccessAt);
    }

    [Fact]
    public async Task Lifecycle_a_restart_in_the_middle_of_an_interval_keeps_the_schedule_of_the_backups_on_disk()
    {
        using (var first = new BackupScheduler(_storage, _clock, Backups, TimeSpan.FromHours(24), keep: 2))
        {
            Assert.NotNull(await first.RunOnceAsync(default));
        }

        DateTimeOffset firstAt = _clock.UtcNow;
        for (int restart = 1; restart <= 5; restart++)
        {
            _clock.Advance(TimeSpan.FromHours(4));   // each process lives four hours, then is replaced
            using var again = new BackupScheduler(_storage, _clock, Backups, TimeSpan.FromHours(24), keep: 2);
            Assert.Equal(firstAt, again.LastSuccessAt);   // known from the directory name before the first run
            if (restart < 5)
            {
                Assert.Null(await again.RunOnceAsync(default));   // 4, 8, ... 16 hours after the backup: not due, however often the process restarts
            }
            else
            {
                _clock.Advance(TimeSpan.FromHours(4));   // 24 hours after it
                Assert.NotNull(await again.RunOnceAsync(default));
            }
        }

        Assert.Equal(2, BackupNames().Count);
    }

    [Fact]
    public async Task Lifecycle_failed_backups_keep_the_good_ones_and_are_retried_at_the_next_check_not_after_a_whole_interval()
    {
        var storage = new FailingBackupStorage(_storage);
        var scheduler = new BackupScheduler(storage, _clock, Backups, TimeSpan.FromHours(24), keep: 2);
        Assert.NotNull(await scheduler.RunOnceAsync(default));
        _clock.Advance(TimeSpan.FromHours(24));
        Assert.NotNull(await scheduler.RunOnceAsync(default));
        List<string> good = BackupNames();
        Assert.Equal(2, good.Count);

        // Five days of a full disk, checked every ten minutes as the host does: every run fails, nothing is deleted, nothing half-made is left.
        storage.Fail = true;
        for (int check = 0; check < 5 * 24 * 6; check++)
        {
            _clock.Advance(TimeSpan.FromMinutes(10));
            if (_clock.UtcNow - scheduler.LastSuccessAt >= TimeSpan.FromHours(24))
            {
                await Assert.ThrowsAsync<IOException>(async () => await scheduler.RunOnceAsync(default));
            }
            else
            {
                Assert.Null(await scheduler.RunOnceAsync(default));
            }

            Assert.Equal(good, BackupNames());
        }

        // The disk has room again: the next check makes the backup and the oldest good one goes, the newest good one stays.
        storage.Fail = false;
        _clock.Advance(TimeSpan.FromMinutes(10));
        string? path = await scheduler.RunOnceAsync(default);
        Assert.NotNull(path);
        Assert.Equal([good[1], Path.GetFileName(path)!], BackupNames());
    }

    [Fact]
    public async Task Lifecycle_a_backup_cancelled_by_a_shutdown_leaves_nothing_that_counts_as_a_backup()
    {
        var scheduler = new BackupScheduler(_storage, _clock, Backups, TimeSpan.FromHours(24), keep: 2);
        Assert.NotNull(await scheduler.RunOnceAsync(default));
        _clock.Advance(TimeSpan.FromHours(24));

        using var stopping = new CancellationTokenSource();
        await stopping.CancelAsync();   // SIGTERM while the backup runs
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await scheduler.RunOnceAsync(stopping.Token));

        // Nothing half-made is left under a name that counts: the next process (a minute later) makes the backup that was due.
        Assert.Single(BackupNames());
        _clock.Advance(TimeSpan.FromMinutes(1));
        using var restarted = new BackupScheduler(_storage, _clock, Backups, TimeSpan.FromHours(24), keep: 2);
        Assert.NotNull(await restarted.RunOnceAsync(default));
        Assert.Equal(2, BackupNames().Count);
        Assert.All(BackupNames(), n => Assert.True(File.Exists(Path.Combine(Backups, n, "config.db")), $"{n} is not a complete backup"));
        Assert.Empty(Directory.EnumerateDirectories(Backups, "*.partial"));
    }

    [Fact]
    public async Task Lifecycle_a_backup_killed_half_way_is_ignored_and_swept_by_the_next_run()
    {
        var scheduler = new BackupScheduler(_storage, _clock, Backups, TimeSpan.FromHours(24), keep: 2);
        Assert.NotNull(await scheduler.RunOnceAsync(default));
        _clock.Advance(TimeSpan.FromHours(24));

        // What a kill -9 during the copy leaves: a directory with one of the files, under the work name of the backup that was being made.
        string killed = Path.Combine(Backups, Name(_clock.UtcNow) + ".partial");
        Directory.CreateDirectory(killed);
        File.WriteAllText(Path.Combine(killed, "config.db"), "half a file");
        // The look-alikes of other things stay: only "<backup name>.partial" is swept.
        string other = Path.Combine(Backups, "my-eggmail-backup-20260101T000000000Z.partial");
        Directory.CreateDirectory(other);

        using var restarted = new BackupScheduler(_storage, _clock, Backups, TimeSpan.FromHours(24), keep: 2);
        Assert.NotNull(await restarted.RunOnceAsync(default));   // due: the half-made one did not count as the latest backup

        Assert.False(Directory.Exists(killed));
        Assert.True(Directory.Exists(other));
        Assert.Equal(2, BackupNames().Count);
        Assert.All(BackupNames(), n => Assert.True(File.Exists(Path.Combine(Backups, n, "config.db"))));
    }

    [Fact]
    public async Task Lifecycle_a_backup_stamped_by_a_wrong_clock_does_not_stop_the_backups_after_the_clock_is_corrected()
    {
        // A host whose clock was a year ahead for a minute made a backup stamped in the future; the clock was corrected afterwards.
        DateTimeOffset wrong = _clock.UtcNow.AddYears(1);
        string futureName = Name(wrong);
        Directory.CreateDirectory(Path.Combine(Backups, futureName));
        File.WriteAllText(Path.Combine(Backups, futureName, "config.db"), "state of a minute under a wrong clock");

        var scheduler = new BackupScheduler(_storage, _clock, Backups, TimeSpan.FromHours(24), keep: 2);
        for (int day = 0; day < 6; day++)
        {
            Assert.NotNull(await scheduler.RunOnceAsync(default));   // due every day, whatever the future-dated directory says
            _clock.Advance(TimeSpan.FromHours(24));
        }

        // Two ordinary backups are kept (the future one does not use up a place), and the future one itself is left for the operator.
        var ordinary = BackupNames().Where(n => n != futureName).ToList();
        Assert.Equal(2, ordinary.Count);
        Assert.Contains(futureName, BackupNames());
        Assert.True(scheduler.LastSuccessAt < wrong);
    }
}
