using System.Collections.Concurrent;
using System.Diagnostics.Metrics;

namespace Mta.Host.Backup;

/// <summary>
/// Meters of the scheduled SQLite backups (<c>Mta.Backup</c>): how each run ended and when the last good backup was made. Alert when
/// <c>time() - mta_backup_last_success_timestamp_seconds</c> exceeds a few backup intervals, when failed runs keep coming, and (with backups
/// enabled on SQLite) on <c>absent(mta_backup_last_success_timestamp_seconds)</c>, which is what a fresh install with no backup yet looks like.
/// </summary>
public static class BackupMetrics
{
    public static readonly Meter Meter = new("Mta.Backup");

    private static readonly ConcurrentDictionary<BackupScheduler, byte> Live = new();

    /// <summary>Backup runs by outcome: <c>success</c> or <c>failed</c> (the storage could not write a backup).</summary>
    public static readonly Counter<long> Runs = Meter.CreateCounter<long>("mta.backup.runs", "{run}", "Backup runs by outcome (success, failed)");

    /// <summary>Unix time of the newest good backup, including one found on disk when the scheduler was created; absent until there is one (or when backups are off).</summary>
    public static readonly ObservableGauge<long> LastSuccess = Meter.CreateObservableGauge("mta.backup.last_success.timestamp", () => ObserveLastSuccess(Live.Keys), "s", "Unix time of the newest successful backup");

    internal static IDisposable Attach(BackupScheduler scheduler)
    {
        Live[scheduler] = 0;
        return new Detach(scheduler);
    }

    internal static bool IsAttached(BackupScheduler scheduler) => Live.ContainsKey(scheduler);

    /// <summary>Schedulers the gauges currently read (a leak check: disposing a scheduler must detach it).</summary>
    internal static int AttachedCount => Live.Count;

    internal static IEnumerable<Measurement<long>> ObserveLastSuccess(IEnumerable<BackupScheduler> schedulers)
    {
        long newest = 0;
        foreach (BackupScheduler scheduler in schedulers)
        {
            if (scheduler.LastSuccessAt is { } at)
            {
                newest = Math.Max(newest, at.ToUnixTimeSeconds());
            }
        }

        if (newest > 0)
        {
            yield return new Measurement<long>(newest);
        }
    }

    private sealed class Detach(BackupScheduler scheduler) : IDisposable
    {
        public void Dispose() => Live.TryRemove(scheduler, out _);
    }
}
