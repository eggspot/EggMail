using System.Globalization;
using Mta.Core;
using Mta.Storage;

namespace Mta.Host.Backup;

/// <summary>
/// Takes a consistent backup of the storage on a schedule and keeps the newest few. A backup is a directory
/// <c>eggmail-backup-&lt;UTC timestamp&gt;</c> holding one file per database; restoring means stopping EggMail and copying those files over
/// the data directory (the state returns to the moment of the backup; mail accepted since is lost). Only directories with exactly that
/// name pattern are ever deleted, one by one.
/// </summary>
public sealed class BackupScheduler : IDisposable
{
    private const string Prefix = "eggmail-backup-";

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

        foreach (string dir in Directory.EnumerateDirectories(_directory, Prefix + "*"))
        {
            string stamp = System.IO.Path.GetFileName(dir)[Prefix.Length..];
            if (DateTimeOffset.TryParseExact(stamp, "yyyyMMddTHHmmssfff'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var at))
            {
                yield return (dir, at);
            }
        }
    }
}
