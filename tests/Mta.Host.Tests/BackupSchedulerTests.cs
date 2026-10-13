using Microsoft.Data.Sqlite;
using Mta.Core;
using Mta.Host.Backup;
using Mta.Storage;
using Mta.Storage.Sqlite;

namespace Mta.Host.Tests;

public class BackupSchedulerTests : IAsyncLifetime
{
    private sealed class FakeClock(DateTimeOffset start) : IClock
    {
        public DateTimeOffset Now { get; set; } = start;
        public DateTimeOffset UtcNow => Now;
        public long Timestamp => Now.UtcTicks;
    }

    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-backup-test-").FullName;
    private readonly FakeClock _clock = new(new DateTimeOffset(2026, 10, 12, 8, 0, 0, TimeSpan.Zero));
    private SqliteStorage _storage = null!;

    public async Task InitializeAsync()
    {
        _storage = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = Path.Combine(_dir, "data") } }, _clock);
        await _storage.InitializeAsync(default);
        await _storage.Config.UpsertTenantAsync(new Tenant(Guid.Parse("a0000000-0000-7000-8000-000000000001"), "Acme", "acme", true, _clock.Now, false), default);
    }

    public async Task DisposeAsync()
    {
        await _storage.DisposeAsync();
        SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, recursive: true);
    }

    [Fact]
    public async Task A_backup_is_a_consistent_copy_that_opens_and_holds_the_data()
    {
        string backups = Path.Combine(_dir, "backups");
        var scheduler = new BackupScheduler(_storage, _clock, backups, TimeSpan.FromHours(24), keep: 3);

        string? path = await scheduler.RunOnceAsync(default);

        Assert.NotNull(path);
        Assert.True(File.Exists(Path.Combine(path!, "config.db")));
        using var connection = new SqliteConnection($"Data Source={Path.Combine(path, "config.db")};Mode=ReadOnly;Pooling=False");
        connection.Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM sqlite_master";
        Assert.True((long)cmd.ExecuteScalar()! > 0);
        Assert.Equal("ok", new SqliteCommand("PRAGMA integrity_check", connection).ExecuteScalar());
    }

    [Fact]
    public async Task Backups_follow_the_interval_and_only_the_newest_are_kept()
    {
        string backups = Path.Combine(_dir, "backups");
        var scheduler = new BackupScheduler(_storage, _clock, backups, TimeSpan.FromHours(24), keep: 2);

        Assert.NotNull(await scheduler.RunOnceAsync(default));
        _clock.Now = _clock.Now.AddHours(1);
        Assert.Null(await scheduler.RunOnceAsync(default));          // not due yet
        for (int i = 0; i < 3; i++)
        {
            _clock.Now = _clock.Now.AddHours(25);
            Assert.NotNull(await scheduler.RunOnceAsync(default));
        }

        var kept = Directory.GetDirectories(backups);
        Assert.Equal(2, kept.Length);
        Assert.Equal(_clock.Now, scheduler.LatestBackupAt());
    }

    [Fact]
    public async Task Unrelated_directories_next_to_the_backups_are_never_touched()
    {
        string backups = Path.Combine(_dir, "backups");
        Directory.CreateDirectory(Path.Combine(backups, "precious"));
        Directory.CreateDirectory(Path.Combine(backups, "eggmail-backup-not-a-timestamp"));
        var scheduler = new BackupScheduler(_storage, _clock, backups, TimeSpan.FromHours(1), keep: 1);

        for (int i = 0; i < 3; i++)
        {
            _clock.Now = _clock.Now.AddHours(2);
            await scheduler.RunOnceAsync(default);
        }

        Assert.True(Directory.Exists(Path.Combine(backups, "precious")));
        Assert.True(Directory.Exists(Path.Combine(backups, "eggmail-backup-not-a-timestamp")));
    }
}
