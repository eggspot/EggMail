using System.Diagnostics.Metrics;

namespace Mta.Host.Backup;

/// <summary>
/// Meters of the scheduled SQLite backups (<c>Mta.Backup</c>): how each run ended and when the last good backup was made. Alert when
/// <c>time() - mta_backup_last_success_timestamp_seconds</c> exceeds a few backup intervals, or when failed runs keep coming.
/// </summary>
public static class BackupMetrics
{
    public static readonly Meter Meter = new("Mta.Backup");

    private static long s_lastSuccessUnixSeconds;

    /// <summary>Backup runs by outcome: <c>success</c> or <c>failed</c> (the storage could not write a backup).</summary>
    public static readonly Counter<long> Runs = Meter.CreateCounter<long>("mta.backup.runs", "{run}", "Backup runs by outcome (success, failed)");

    /// <summary>Unix time of the newest good backup, including one found on disk at start; absent until there is one (or when backups are off).</summary>
    public static readonly ObservableGauge<long> LastSuccess = Meter.CreateObservableGauge("mta.backup.last_success.timestamp", ObserveLastSuccess, "s", "Unix time of the newest successful backup");

    /// <summary>Notes a good backup made at <paramref name="at"/> (an older value than the one known is ignored).</summary>
    public static void RecordSuccess(DateTimeOffset at)
    {
        long seconds = at.ToUnixTimeSeconds();
        long current;
        while (seconds > (current = Interlocked.Read(ref s_lastSuccessUnixSeconds)) && Interlocked.CompareExchange(ref s_lastSuccessUnixSeconds, seconds, current) != current)
        {
        }
    }

    private static IEnumerable<Measurement<long>> ObserveLastSuccess()
    {
        long seconds = Interlocked.Read(ref s_lastSuccessUnixSeconds);
        if (seconds > 0)
        {
            yield return new Measurement<long>(seconds);
        }
    }
}
