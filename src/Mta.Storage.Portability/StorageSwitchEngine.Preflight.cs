using System.Globalization;
using Mta.Storage.Transfer;

namespace Mta.Storage.Portability;

/// <summary>The effective values of the settings that decide behavior (design §4.6: recorded in the manifest, never changed silently).</summary>
public static class EffectiveSettings
{
    public static IReadOnlyDictionary<string, string> Describe(StorageOptions o)
    {
        string I(int v) => v.ToString(CultureInfo.InvariantCulture);
        return new SortedDictionary<string, string>(StringComparer.Ordinal)
        {
            ["History:Mode"] = o.History.Mode.ToString(),
            ["History:RecentEvents"] = I(o.History.RecentEvents),
            ["Retention:MetadataDays"] = I(o.Retention.MetadataDays),
            ["Content:Mode"] = o.Content.Retain ? "Retain" : "None",
            ["Content:RetentionDays"] = I(o.Content.RetentionDays),
            ["Content:StoreAttachments"] = o.Content.StoreAttachments.ToString(),
            ["Content:AllowAttachmentStorage"] = o.Content.AllowAttachmentStorage.ToString(),
            ["Content:MaxStoredBodyBytes"] = I(o.Content.MaxStoredBodyBytes),
            ["Content:StoreSubject"] = o.Content.StoreSubject.ToString(),
            ["Queue:MaxLifetime"] = o.Queue.MaxLifetime.ToString("c", CultureInfo.InvariantCulture),
            ["Stats:HourlyRetentionDays"] = I(o.Retention.StatsHourlyDays),
            ["Stats:DailyRetentionDays"] = I(o.Retention.StatsDailyDays),
            ["Stats:RecipientDomainTopNHourly"] = I(o.Retention.RecipientDomainTopNHourly),
            ["Stats:RecipientDomainTopNDaily"] = I(o.Retention.RecipientDomainTopNDaily),
            ["Stats:MaxSeriesPerHour"] = I(o.Retention.MaxSeriesPerHour),
            ["Webhooks:OutboxRetentionDays"] = I(o.Retention.WebhookOutboxDays),
            ["Webhooks:AttemptLogDays"] = I(o.Retention.WebhookAttemptLogDays),
        };
    }

    /// <summary>The settings whose effective value differs between two option sets.</summary>
    public static IReadOnlyList<(string Key, string From, string To)> Differences(StorageOptions from, StorageOptions to)
    {
        var a = Describe(from);
        var b = Describe(to);
        return a.Where(kv => b.TryGetValue(kv.Key, out string? other) && other != kv.Value).Select(kv => (kv.Key, kv.Value, b[kv.Key])).ToList();
    }
}

public sealed partial class StorageSwitchEngine
{
    public async Task<PreflightReport> PreflightAsync(SwitchRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return await PreflightCoreAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private async Task<PreflightReport> PreflightCoreAsync(SwitchRequest request, CancellationToken ct)
    {
        var checks = new List<PreflightCheck>();
        var wontCarry = new List<string>();
        var rows = new Dictionary<string, long>();
        void Add(string name, CheckStatus status, string message) => checks.Add(new PreflightCheck(name, status, message));

        SwitchEndpoint? source = _source;
        if (source is null || source.Storage.Transfer is null)
        {
            Add("source", CheckStatus.Error, source is null ? "The source store is not configured." : $"The {source.Storage.Backend} backend does not support switching yet.");
            return new PreflightReport { Checks = checks, SourceRows = rows, WillNotCarryOver = wontCarry };
        }

        IStorageTransfer sourceTransfer = source.Storage.Transfer;
        Add("source", CheckStatus.Ok, $"Source is {source.Describe()}, history {source.Storage.HistoryMode}.");

        SwitchStateRecord? sourceState = await sourceTransfer.GetStateAsync(ct).ConfigureAwait(false);
        if (sourceState is { Role: SwitchRoles.Source } && sourceState.State != SwitchStates.Active)
        {
            Add("source-state", CheckStatus.Error, $"The source is already {sourceState.State} for switch {sourceState.SwitchId}; continue that switch or roll it back first.");
        }
        else if (sourceState is { Role: SwitchRoles.Target } && sourceState.State != SwitchStates.Active)
        {
            Add("source-state", CheckStatus.Error, $"The source store is itself the target of switch {sourceState.SwitchId} ({sourceState.State}); finish or roll back that switch first.");
        }
        else
        {
            Add("source-state", CheckStatus.Ok, "The source is active and not part of another switch.");
        }

        // What would move.
        long totalRows = 0;
        foreach (TransferTable table in TransferTables.All.Where(t => sourceTransfer.HasPart(t.Part)))
        {
            long n = await sourceTransfer.CountAsync(table, TransferRange.All, ct).ConfigureAwait(false);
            rows[table.Name] = n;
            totalRows += n;
        }

        QueueStats queue = await source.Storage.Deliveries.GetQueueStatsAsync(ct).ConfigureAwait(false);
        long queued = queue.Queued + queue.Leased + queue.Deferred;
        Add("queue", CheckStatus.Ok, request.Mode == SwitchMode.Drain
            ? $"Drain: {queued} queued deliveries must be delivered or expire before the switch continues; nothing queued moves."
            : $"Quiesce: {queued} queued deliveries ({queue.SpoolBytes} bytes of spooled messages) are transferred with their retry state; in-flight deliveries get {request.QuiesceTimeout.TotalSeconds:0} s to finish.");

        long historyRows = TransferTables.Of(TransferPart.History).Sum(t => rows.GetValueOrDefault(t.Name));
        Add("size", CheckStatus.Ok, $"{totalRows} rows in total ({historyRows} of them history); {queue.SpoolBytes} bytes of queued raw messages. The time depends on the disks and the target; no throughput is assumed (see docs/components/switch.md for the measured figures).");

        // Target.
        SwitchEndpoint? target = _target;
        if (target is null)
        {
            Add("target", CheckStatus.Warning, "No target store is configured; the target checks were skipped (export-only run).");
        }
        else if (target.Storage.Transfer is null)
        {
            Add("target", CheckStatus.Error, $"The {target.Storage.Backend} backend does not support switching yet.");
        }
        else
        {
            await CheckTargetAsync(request, source, target, checks, ct).ConfigureAwait(false);
        }

        // History.
        if (source.Storage.HistoryMode == HistoryMode.StatsOnly)
        {
            Add("history", CheckStatus.Ok, "The source records no per-message history (History:Mode=StatsOnly): there is none to move.");
        }
        else if (request.SkipHistory)
        {
            wontCarry.Add("Per-message history (events, content, retained raw) because --skip-history was given; it stays in the read-only source.");
            Add("history", CheckStatus.Warning, "History is skipped; it stays in the read-only source.");
        }
        else if (target is not null && target.Storage.HistoryMode == HistoryMode.StatsOnly)
        {
            wontCarry.Add("Per-message history, because the target runs History:Mode=StatsOnly; it stays in the read-only source.");
            Add("history", CheckStatus.Warning, "The target is StatsOnly: history is not carried to the target and stays in the read-only source.");
        }
        else
        {
            Add("history", CheckStatus.Ok, request.HistoryAfterActivation
                ? $"History ({historyRows} rows) is copied after activation from the read-only source; the source is kept until the backfill is verified."
                : $"History ({historyRows} rows) is copied before activation, day by day (resumable).");
        }

        wontCarry.Add("The Data Protection key ring of the source (the target keeps its own; secrets are re-protected), leases, in-flight ACME orders and DNS-01 challenge state (the target restarts a pending order), and deployment configuration (ports, connection strings, Storage:Backend, sync modes, the key-protection certificate).");

        // The bundle.
        if (request.BundlePath is { } bundle)
        {
            CheckBundleLocation(bundle, totalRows, queue.SpoolBytes, checks);
        }

        if (request.Passphrase is { } pass && pass.Length < BundleSecretProtector.MinimumPassphraseLength)
        {
            Add("passphrase", CheckStatus.Error, $"The export passphrase must be at least {BundleSecretProtector.MinimumPassphraseLength} characters.");
        }

        return new PreflightReport { Checks = checks, SourceRows = rows, SpoolBytes = queue.SpoolBytes, WillNotCarryOver = wontCarry };
    }

    private async Task CheckTargetAsync(SwitchRequest request, SwitchEndpoint source, SwitchEndpoint target, List<PreflightCheck> checks, CancellationToken ct)
    {
        void Add(string name, CheckStatus status, string message) => checks.Add(new PreflightCheck(name, status, message));
        IStorageTransfer transfer = target.Storage.Transfer!;
        Add("target", CheckStatus.Ok, $"Target is {target.Describe()}, history {target.Storage.HistoryMode}; it is reachable and its schema is current.");

        if (source.Storage.Backend == target.Storage.Backend && source.Storage.Backend == StorageBackend.Sqlite
            && string.Equals(Path.GetFullPath(source.Options.Sqlite.DataDirectory), Path.GetFullPath(target.Options.Sqlite.DataDirectory), StringComparison.Ordinal))
        {
            Add("target-distinct", CheckStatus.Error, "Source and target are the same SQLite data directory.");
        }

        SwitchStateRecord? state = await transfer.GetStateAsync(ct).ConfigureAwait(false);
        IReadOnlyList<string> nonEmpty = await transfer.GetNonEmptyTablesAsync(ct).ConfigureAwait(false);
        if (state is not null)
        {
            Add("target-state", CheckStatus.Error, $"The target already has a switch record ({state.Role} {state.State}, switch {state.SwitchId}); roll that switch back or use an empty target.");
        }
        else if (nonEmpty.Count > 0)
        {
            Add("target-empty", CheckStatus.Error, $"The target is not empty ({string.Join(", ", nonEmpty.Take(8))}{(nonEmpty.Count > 8 ? ", …" : string.Empty)}); the import refuses to merge into existing data.");
        }
        else
        {
            Add("target-empty", CheckStatus.Ok, "The target is empty.");
        }

        if (!target.KeysProtectedAtRest)
        {
            Add("key-protection", request.AcceptUnprotectedTarget ? CheckStatus.Warning : CheckStatus.Error,
                request.AcceptUnprotectedTarget
                    ? "The target runs with Secrets:KeyProtection=None: the re-protected secrets are only as safe as its database (acknowledged)."
                    : "The target runs with Secrets:KeyProtection=None: the re-protected secrets would be only as safe as its database. Configure a certificate, or acknowledge this explicitly (--accept-unprotected-keys).");
        }
        else
        {
            Add("key-protection", CheckStatus.Ok, "The target's key protection is available.");
        }

        if (target.Storage.Backend == StorageBackend.Sqlite && target.Options.Sqlite.SyncMode == SqliteSyncMode.Off)
        {
            Add("sync-mode", CheckStatus.Warning, "The target is SQLite with Sqlite:SyncMode=Off: process-crash-safe but not power-loss-safe; an OS crash can corrupt queue.db. Use Normal or Full if you need power-loss safety.");
        }

        var differences = EffectiveSettings.Differences(source.Options, target.Options).Where(d => d.Key != "History:Mode").ToList();
        if (differences.Count > 0)
        {
            Add("effective-settings", CheckStatus.Warning, "Effective settings differ between source and target: " + string.Join("; ", differences.Select(d => $"{d.Key} {d.From} to {d.To}")) + ". The cutover patch carries the source's values so behavior does not change.");
        }
    }

    private static void CheckBundleLocation(string bundle, long totalRows, long spoolBytes, List<PreflightCheck> checks)
    {
        string full = Path.GetFullPath(bundle);
        if (File.Exists(Path.Combine(full, "manifest.json")))
        {
            checks.Add(new PreflightCheck("bundle", CheckStatus.Warning, $"'{full}' already holds a bundle; an export resumes it only if it belongs to the same switch."));
        }
        else if (Directory.Exists(full) && Directory.EnumerateFileSystemEntries(full).Any())
        {
            checks.Add(new PreflightCheck("bundle", CheckStatus.Error, $"The bundle directory '{full}' is not empty."));
            return;
        }

        // A rough lower bound (about 400 bytes per row plus the raw messages): the real size depends on the data. Unverified.
        long estimate = totalRows * 400 + spoolBytes;
        try
        {
            string probe = full;
            while (!Directory.Exists(probe) && Path.GetDirectoryName(probe) is { Length: > 0 } parent)
            {
                probe = parent;
            }

            long free = new DriveInfo(Path.GetPathRoot(probe)!).AvailableFreeSpace;
            checks.Add(free < estimate * 2
                ? new PreflightCheck("disk-space", CheckStatus.Warning, $"Free space {free} bytes may be tight for a bundle of roughly {estimate} bytes (estimate, unverified).")
                : new PreflightCheck("disk-space", CheckStatus.Ok, $"Free space {free} bytes; the bundle is roughly {estimate} bytes (estimate, unverified)."));
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or UnauthorizedAccessException)
        {
            checks.Add(new PreflightCheck("disk-space", CheckStatus.Warning, "Free disk space could not be determined."));
        }
    }
}
