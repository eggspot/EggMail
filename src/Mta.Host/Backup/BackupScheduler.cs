using System.Globalization;
using Mta.Core;
using Mta.Storage;

namespace Mta.Host.Backup;

/// <summary>
/// Takes a consistent backup of the storage on a schedule and keeps the newest few. A backup is a directory
/// <c>eggmail-backup-&lt;UTC timestamp&gt;</c> holding one file per database; restoring means stopping EggMail and copying those files over
/// the data directory (the state returns to the moment of the backup; mail accepted since is lost). Only directories with exactly that
/// name pattern are ever deleted, one by one.
/// <para>A backup is written under <c>eggmail-backup-&lt;UTC timestamp&gt;.partial</c> and renamed when complete, so a backup that was cancelled by a
/// shutdown, failed, or was killed half-way never has the name of a backup: it is not the "newest backup" that postpones the next one, it does not use up one
/// of the <c>keep</c> places, and the next run removes the leftover. A directory stamped later than the clock allows (a clock that was wrong when it was made)
/// is neither counted nor deleted.</para>
/// </summary>
public sealed class BackupScheduler : IDisposable
{
    private const string Prefix = "eggmail-backup-";
    private const string PartialSuffix = ".partial";
    private const string StampFormat = "yyyyMMddTHHmmssfff'Z'";

    /// <summary>How far ahead of the clock a backup's name may be before it is taken for the work of a wrong clock (a step by the time service is not that).</summary>
    private static readonly TimeSpan FutureTolerance = TimeSpan.FromMinutes(5);

    private bool _warnedAboutFuture;

    private readonly IStorage _storage;
    private readonly IClock _clock;
    private readonly string _directory;
    private readonly TimeSpan _interval;
    private readonly int _keep;
    private readonly IMtaLog _log;
    private readonly IDisposable _meters;
    private long _lastSuccessTicks;

    public BackupScheduler(IStorage storage, IClock clock, string directory, TimeSpan interval, int keep, IMtaLog? log = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(keep, 1);
        if (interval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(interval));
        }

        _storage = storage;
        _clock = clock;
        _directory = directory;
        _interval = interval;
        _keep = keep;
        _log = log ?? NullMtaLog.Instance;
        if (LatestBackupAt() is { } onDisk)
        {
            _lastSuccessTicks = onDisk.UtcTicks;   // after a restart the newest backup on disk is the last success, visible before the first run
        }

        _meters = BackupMetrics.Attach(this);
    }

    /// <summary>The newest good backup this scheduler knows of (on disk when it was created, or made by it since); null when there is none.</summary>
    public DateTimeOffset? LastSuccessAt => Interlocked.Read(ref _lastSuccessTicks) is var ticks and > 0 ? new DateTimeOffset(ticks, TimeSpan.Zero) : null;

    public void Dispose() => _meters.Dispose();

    /// <summary>The newest backup's time, from its directory name (null when there is none).</summary>
    public DateTimeOffset? LatestBackupAt() => Backups().Select(b => b.At).Cast<DateTimeOffset?>().OrderByDescending(t => t).FirstOrDefault();

    /// <summary>Takes a backup when the newest one is older than the interval (or none exists), then prunes. Returns the new backup directory, or null when none was due.</summary>
    public async Task<string?> RunOnceAsync(CancellationToken ct)
    {
        var now = _clock.UtcNow;
        SweepPartial();
        if (LatestBackupAt() is { } latest)
        {
            NoteSuccess(latest);
            if (now - latest < _interval)
            {
                return null;
            }
        }

        string? path;
        try
        {
            Directory.CreateDirectory(_directory);
            path = await _storage.Maintenance.BackupAsync(_directory, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            BackupMetrics.Runs.Add(1, new KeyValuePair<string, object?>("outcome", "failed"));
            throw;
        }

        if (path is not null)
        {
            BackupMetrics.Runs.Add(1, new KeyValuePair<string, object?>("outcome", "success"));
            NoteSuccess(now);
            _log.Write(MtaLogLevel.Information, "backup", "backup written to " + path);
            Prune();
        }

        return path;
    }

    private void NoteSuccess(DateTimeOffset at)
    {
        long ticks = at.UtcTicks;
        long current;
        while (ticks > (current = Interlocked.Read(ref _lastSuccessTicks)) && Interlocked.CompareExchange(ref _lastSuccessTicks, ticks, current) != current)
        {
        }
    }

    /// <summary>Removes the work directories that a killed or failed run left (only <c>eggmail-backup-&lt;timestamp&gt;.partial</c>, nothing else).</summary>
    private void SweepPartial()
    {
        if (!Directory.Exists(_directory))
        {
            return;
        }

        foreach (string dir in Directory.EnumerateDirectories(_directory, Prefix + "*" + PartialSuffix))
        {
            string name = System.IO.Path.GetFileName(dir);
            if (!TryParseStamp(name[..^PartialSuffix.Length], out _))
            {
                continue;
            }

            try
            {
                Directory.Delete(dir, recursive: true);
                _log.Write(MtaLogLevel.Information, "backup", "removed the leftover of an interrupted backup: " + dir);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _log.Write(MtaLogLevel.Warning, "backup", "could not remove the leftover of an interrupted backup " + dir, ex);
            }
        }
    }

    private static bool TryParseStamp(string name, out DateTimeOffset at)
    {
        at = default;
        return name.StartsWith(Prefix, StringComparison.Ordinal)
            && DateTimeOffset.TryParseExact(name[Prefix.Length..], StampFormat, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out at);
    }

    private void Prune()
    {
        foreach (var old in Backups().OrderByDescending(b => b.At).Skip(_keep))
        {
            try
            {
                Directory.Delete(old.Path, recursive: true);
            }
            catch (IOException ex)
            {
                _log.Write(MtaLogLevel.Warning, "backup", "could not remove old backup " + old.Path, ex);
            }
        }
    }

    private IEnumerable<(string Path, DateTimeOffset At)> Backups()
    {
        if (!Directory.Exists(_directory))
        {
            yield break;
        }

        DateTimeOffset latestAllowed = _clock.UtcNow + FutureTolerance;
        foreach (string dir in Directory.EnumerateDirectories(_directory, Prefix + "*"))
        {
            if (!TryParseStamp(System.IO.Path.GetFileName(dir), out var at))
            {
                continue;
            }

            if (at > latestAllowed)
            {
                // Made while the clock was ahead of the real time: it cannot say when the next backup is due, must not push a real backup out of the kept
                // ones, and is not ours to delete.
                if (!_warnedAboutFuture)
                {
                    _warnedAboutFuture = true;
                    _log.Write(MtaLogLevel.Warning, "backup", $"{dir} is dated {at:u}, later than the clock; it is ignored (not counted, not deleted). Remove it when it is not needed");
                }

                continue;
            }

            yield return (dir, at);
        }
    }
}
