using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using Microsoft.Data.Sqlite;
using Mta.Core;
using Mta.Host.Backup;
using Mta.Host.Configuration;
using Mta.Host.Tls;
using Mta.Storage;
using Mta.Storage.InMemory;
using Mta.Storage.Sqlite;

namespace Mta.Host.Tests;

/// <summary>Records every measurement of one meter, with its tags.</summary>
internal sealed class MeterCapture : IDisposable
{
    public sealed record Measured(string Instrument, double Value, IReadOnlyDictionary<string, object?> Tags);

    private readonly MeterListener _listener = new();
    private readonly ConcurrentQueue<Measured> _measurements = new();

    public MeterCapture(string meterName)
    {
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == meterName)
            {
                listener.EnableMeasurementEvents(instrument);
            }
        };
        _listener.SetMeasurementEventCallback<long>((i, v, t, _) => Add(i, v, t));
        _listener.SetMeasurementEventCallback<double>((i, v, t, _) => Add(i, v, t));
        _listener.Start();
    }

    public void Pull() => _listener.RecordObservableInstruments();

    public IEnumerable<Measured> Of(string instrument, params (string Key, object Value)[] tags) =>
        _measurements.Where(m => m.Instrument == instrument && tags.All(t => m.Tags.TryGetValue(t.Key, out object? v) && Equals(v, t.Value)));

    public double Sum(string instrument, params (string Key, object Value)[] tags) => Of(instrument, tags).Sum(m => m.Value);

    private void Add(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        var dictionary = new Dictionary<string, object?>();
        foreach (KeyValuePair<string, object?> tag in tags)
        {
            dictionary[tag.Key] = tag.Value;
        }

        _measurements.Enqueue(new Measured(instrument.Name, value, dictionary));
    }

    public void Dispose() => _listener.Dispose();
}

public class BackupMetricsTests : IAsyncLifetime
{
    private sealed class FakeClock(DateTimeOffset start) : IClock
    {
        public DateTimeOffset Now { get; set; } = start;
        public DateTimeOffset UtcNow => Now;
        public long Timestamp => Now.UtcTicks;
    }

    private readonly FakeClock _clock = new(new DateTimeOffset(2090, 3, 4, 5, 6, 7, TimeSpan.Zero));
    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-backup-metrics-").FullName;
    private SqliteStorage _storage = null!;

    public async Task InitializeAsync()
    {
        _storage = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = Path.Combine(_dir, "data") } }, _clock);
        await _storage.InitializeAsync(default);
    }

    public async Task DisposeAsync()
    {
        await _storage.DisposeAsync();
        SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, recursive: true);
    }

    private static long LastSuccessGauge(BackupScheduler scheduler) =>
        Assert.Single(BackupMetrics.ObserveLastSuccess([scheduler])).Value;   // this scheduler alone: the gauge itself spans every live scheduler of the process

    [Fact]
    public async Task A_successful_backup_is_counted_and_sets_the_last_success_time()
    {
        using var capture = new MeterCapture("Mta.Backup");
        using var scheduler = new BackupScheduler(_storage, _clock, Path.Combine(_dir, "backups"), TimeSpan.FromHours(24), keep: 2);
        Assert.Empty(BackupMetrics.ObserveLastSuccess([scheduler]));   // no backup yet: the series is absent, which is what the absent() alert watches

        Assert.NotNull(await scheduler.RunOnceAsync(default));

        Assert.True(capture.Sum("mta.backup.runs", ("outcome", "success")) >= 1);
        Assert.Equal(_clock.Now.ToUnixTimeSeconds(), LastSuccessGauge(scheduler));
    }

    [Fact]
    public async Task A_backup_that_cannot_be_written_is_counted_as_failed_and_still_throws()
    {
        using var capture = new MeterCapture("Mta.Backup");
        string blocker = Path.Combine(_dir, "not-a-directory");
        await File.WriteAllTextAsync(blocker, "a file where the backup directory should be");
        using var scheduler = new BackupScheduler(_storage, _clock, Path.Combine(blocker, "backups"), TimeSpan.FromHours(24), keep: 2);

        await Assert.ThrowsAnyAsync<IOException>(() => scheduler.RunOnceAsync(default));

        Assert.Equal(1, capture.Sum("mta.backup.runs", ("outcome", "failed")));
        Assert.Empty(BackupMetrics.ObserveLastSuccess([scheduler]));
    }

    [Fact]
    public void The_newest_backup_on_disk_is_the_last_success_from_the_moment_the_scheduler_exists()
    {
        string backups = Path.Combine(_dir, "backups");
        Directory.CreateDirectory(Path.Combine(backups, "eggmail-backup-20900305T060607000Z"));
        Directory.CreateDirectory(Path.Combine(backups, "eggmail-backup-20900301T000000000Z"));

        using var scheduler = new BackupScheduler(_storage, _clock, backups, TimeSpan.FromHours(24), keep: 2);   // no run needed: a restart is visible at once

        Assert.Equal(new DateTimeOffset(2090, 3, 5, 6, 6, 7, TimeSpan.Zero).ToUnixTimeSeconds(), LastSuccessGauge(scheduler));
    }

    [Fact]
    public async Task A_disposed_scheduler_is_no_longer_observed()
    {
        using var capture = new MeterCapture("Mta.Backup");
        var scheduler = new BackupScheduler(_storage, _clock, Path.Combine(_dir, "backups"), TimeSpan.FromHours(24), keep: 2);
        await scheduler.RunOnceAsync(default);
        long mine = _clock.Now.ToUnixTimeSeconds();
        capture.Pull();
        Assert.Contains(capture.Of("mta.backup.last_success.timestamp"), m => m.Value >= mine);

        scheduler.Dispose();

        Assert.False(BackupMetrics.IsAttached(scheduler));
    }
}

public class CertificateMetricsTests
{
    private sealed class ShiftedClock(TimeSpan shift) : IClock
    {
        public DateTimeOffset UtcNow => DateTimeOffset.UtcNow + shift;
        public long Timestamp => System.Diagnostics.Stopwatch.GetTimestamp();
    }

    [Fact]
    public async Task The_expiry_gauge_counts_down_to_the_not_after_time_of_each_served_certificate()
    {
        await using var storage = new InMemoryStorage(new StorageOptions(), SystemClock.Instance);
        await storage.InitializeAsync(default);
        var provider = new DatabaseCertificateProvider(storage.Config, new TestProtector(), "metrics-test.example", new TlsSection(), SystemClock.Instance);
        await provider.InitializeAsync(default);   // generates the first-run self-signed certificate, valid for a year
        await using var attached = TlsMetrics.Attach(provider, new ShiftedClock(TimeSpan.FromDays(10)));   // the gauge's clock runs ten days ahead
        using var capture = new MeterCapture("Mta.Tls");

        capture.Pull();

        var mine = capture.Of("mta.tls.certificate.expiry", ("source", "selfsigned")).Where(m => (string)m.Tags["name"]! == provider.Describe()[0].Name).ToList();
        double seconds = Assert.Single(mine).Value;
        double daysLeft = seconds / 86400;
        Assert.InRange(daysLeft, 353, 356);   // a year, minus the ten days the gauge's clock runs ahead
        Assert.Contains(capture.Of("mta.tls.certificates"), m => m.Value >= 1);
    }

    [Fact]
    public async Task A_detached_provider_is_no_longer_observed()
    {
        var clock = SystemClock.Instance;
        await using var storage = new InMemoryStorage(new StorageOptions(), clock);
        await storage.InitializeAsync(default);
        var provider = new DatabaseCertificateProvider(storage.Config, new TestProtector(), "detached.example", new TlsSection(), clock);
        await provider.InitializeAsync(default);

        var attached = TlsMetrics.Attach(provider, clock);
        Assert.True(TlsMetrics.IsAttached(provider));
        await attached.DisposeAsync();

        Assert.False(TlsMetrics.IsAttached(provider));
    }
}
