using System.Globalization;
using System.Security.Cryptography;
using Mta.Core;
using Mta.Storage.Logic;
using Mta.Storage.Transfer;

namespace Mta.Storage.Portability;

/// <summary>Writes the rows of one table (or one table-day) into numbered chunk files, rolling to the next file by row count and size.</summary>
internal sealed class ChunkSink(BundleWriter bundle, TransferTable table, string stem, string? day, int maxRows, long maxBytes) : IAsyncDisposable
{
    private int _index;
    private LineFileWriter? _lines;
    private BodyPackWriter? _bodies;

    public long Rows { get; private set; }

    public async ValueTask WriteAsync(string json, byte[]? body, CancellationToken ct)
    {
        if (_lines is null)
        {
            _index++;
            _lines = bundle.OpenLines($"{stem}.{_index:D5}.ndjson", table.Name, day, day);
            if (table.Body is not null)
            {
                _bodies = bundle.OpenBodies($"{stem}.{_index:D5}.bodies", table.Name, day, day);
            }
        }

        await _lines.WriteLineAsync(json, ct).ConfigureAwait(false);
        if (_bodies is not null)
        {
            await _bodies.WriteAsync(body ?? [], ct).ConfigureAwait(false);
        }

        Rows++;
        if (_lines.Rows >= maxRows || _lines.Bytes + (_bodies?.Bytes ?? 0) >= maxBytes)
        {
            await CloseAsync().ConfigureAwait(false);
        }
    }

    private async ValueTask CloseAsync()
    {
        if (_lines is not null)
        {
            await _lines.DisposeAsync().ConfigureAwait(false);
            _lines = null;
        }

        if (_bodies is not null)
        {
            await _bodies.DisposeAsync().ConfigureAwait(false);
            _bodies = null;
        }
    }

    public ValueTask DisposeAsync() => CloseAsync();
}

public sealed partial class StorageSwitchEngine
{
    private static readonly string[] CoreParts = ["config", "stats", "queue"];

    public async Task<ExportResult> ExportAsync(BundleRequest request, IProgress<SwitchProgress>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return await RunAsync("export", cancellationToken, async ct =>
        {
            if (request.Passphrase.Length < BundleSecretProtector.MinimumPassphraseLength)
            {
                throw new SwitchException($"The export passphrase must be at least {BundleSecretProtector.MinimumPassphraseLength} characters.");
            }

            SwitchEndpoint source = Source;
            IStorageTransfer transfer = SourceTransfer;
            SwitchStateRecord? state = await transfer.GetStateAsync(ct).ConfigureAwait(false);
            if (state is { Role: SwitchRoles.Source, State: SwitchStates.Draining })
            {
                if (!await TryFenceWhenDrainedAsync(ct).ConfigureAwait(false))
                {
                    QueueStats stats = await source.Storage.Deliveries.GetQueueStatsAsync(ct).ConfigureAwait(false);
                    throw new SwitchException($"The queue is not drained yet ({stats.Queued + stats.Leased + stats.Deferred} deliveries remain). Wait for it to empty, or roll back and use --quiesce.");
                }

                state = await transfer.GetStateAsync(ct).ConfigureAwait(false);
            }

            if (state is not { Role: SwitchRoles.Source, State: SwitchStates.Fenced })
            {
                throw new SwitchException($"The source is {state?.State ?? "not part of a switch"}; export needs it fenced. Start the switch (drain or quiesce) first.");
            }

            Guid switchId = state.SwitchId;
            var detail = SwitchDetail.Parse(state.Detail);
            bool includeHistory = !request.SkipHistory && !detail.SkipHistory && source.Storage.HistoryMode == HistoryMode.Full && transfer.HasPart(TransferPart.History);
            string dir = Path.GetFullPath(request.BundlePath);
            bool resuming = File.Exists(Path.Combine(dir, "manifest.json"));
            var notes = new List<string>();
            long rowsTotal = 0;
            long queueRows = 0;
            long marked = 0;

            BundleWriter writer;
            if (resuming)
            {
                BundleReader existing = await BundleReader.OpenAsync(dir, ct).ConfigureAwait(false);
                if (existing.Manifest.SwitchId != switchId)
                {
                    throw new SwitchException($"'{dir}' holds a bundle of another switch ({existing.Manifest.SwitchId}); use an empty directory.");
                }

                writer = await BundleWriter.OpenForAppendAsync(dir, ct).ConfigureAwait(false);
                notes.Add("Resumed an existing bundle: the core export was already complete.");
                rowsTotal = writer.Manifest.Tables.Sum(t => t.Rows);
            }
            else
            {
                await source.Storage.Stats.FlushAsync(ct).ConfigureAwait(false);
                var manifest = new BundleManifest
                {
                    SwitchId = switchId,
                    CreatedAt = Truncate(_clock.UtcNow),
                    CreatedBy = "mta " + _options.AppVersion,
                    Source = new BundleSource
                    {
                        Backend = source.Storage.Backend.ToString().ToLowerInvariant(),
                        SchemaVersion = Model.StorageModel.SchemaVersion.ToString(CultureInfo.InvariantCulture),
                        HistoryMode = source.Storage.HistoryMode.ToString(),
                        AppVersion = _options.AppVersion,
                    },
                    Includes = new BundleIncludes { Config = true, Stats = true, Queue = true, History = includeHistory },
                    EffectiveSettings = EffectiveSettings.Describe(source.Options).ToDictionary(kv => kv.Key, kv => kv.Value),
                    Switch = new BundleSwitch { Mode = detail.Mode, HistoryIncluded = includeHistory, HistoryComplete = !includeHistory },
                };

                writer = new BundleWriter(dir, manifest);
                try
                {
                    ISecretProtector bundleSecrets = BundleSecretProtector.CreateForExport(writer, manifest.Secrets, request.Passphrase);
                    byte[] digestKey = RandomNumberGenerator.GetBytes(32);
                    manifest.Secrets.DigestKeyProtected = Convert.ToBase64String(bundleSecrets.Protect(digestKey, DigestKeyPurpose));

                    foreach (TransferTable table in TransferTables.All.Where(t => t.Part != TransferPart.History && transfer.HasPart(t.Part)))
                    {
                        TableChecksum sum = await ExportTableAsync(writer, table, bundleSecrets, digestKey, progress, ct).ConfigureAwait(false);
                        manifest.Tables.Add(sum.ToManifest(table.Name, table.Directory));
                        rowsTotal += sum.Rows;
                        if (table.HasHold)
                        {
                            queueRows += sum.Rows;
                        }
                    }

                    if (includeHistory)
                    {
                        foreach (TransferTable table in TransferTables.Of(TransferPart.History))
                        {
                            manifest.Tables.Add(new TableChecksum().ToManifest(table.Name, table.Directory));
                        }
                    }

                    // The secrets files are part of the manifest like everything else (the key ring is complete after the first Protect above).
                    await writer.AddExistingFileAsync(manifest.Secrets.CertificateFile, ct).ConfigureAwait(false);
                    foreach (string file in Directory.EnumerateFiles(writer.ResolvePath(manifest.Secrets.KeyRingDirectory)))
                    {
                        await writer.AddExistingFileAsync(Path.GetRelativePath(writer.Root, file), ct).ConfigureAwait(false);
                    }

                    await writer.CheckpointAsync(ct).ConfigureAwait(false);
                }
                catch
                {
                    writer.Dispose();
                    throw;
                }
            }

            try
            {
                // Export and mark: the exported queue rows are marked transferred(switch_id); a marked row cannot be claimed.
                marked = await transfer.MarkQueueTransferredAsync(switchId, ct).ConfigureAwait(false);
                if (!resuming && marked != queueRows)
                {
                    throw new SwitchException($"{queueRows} queue rows were exported but {marked} rows were marked; the queue changed during the export. Roll back and start again.");
                }

                if (includeHistory)
                {
                    await ExportHistoryAsync(writer, progress, ct).ConfigureAwait(false);
                }
                else
                {
                    await writer.CheckpointAsync(ct).ConfigureAwait(false);
                }

                detail.Bundle = dir;
                detail.SkipHistory = !includeHistory;
                await transfer.SetStateAsync(state with { Detail = detail.ToJson(), UpdatedAt = Truncate(_clock.UtcNow) }, ct).ConfigureAwait(false);

                long bytes = writer.Manifest.Files.Sum(f => f.Bytes);
                Report(progress, "export", null, 1, 1, $"Exported {rowsTotal} rows in {writer.Manifest.Files.Count} files");
                if (!includeHistory && source.Storage.HistoryMode == HistoryMode.Full && transfer.HasPart(TransferPart.History))
                {
                    notes.Add("History was not exported; it stays in the read-only source.");
                }

                return new ExportResult(switchId, dir, rowsTotal, bytes, marked, writer.Manifest.Switch.HistoryComplete, notes);
            }
            finally
            {
                writer.Dispose();
            }
        }).ConfigureAwait(false);
    }

    private const string DigestKeyPurpose = "digest-key";

    private async Task<TableChecksum> ExportTableAsync(BundleWriter writer, TransferTable table, ISecretProtector bundleSecrets, byte[] digestKey, IProgress<SwitchProgress>? progress, CancellationToken ct)
    {
        var sum = new TableChecksum();
        IStorageTransfer transfer = SourceTransfer;
        long total = await transfer.CountAsync(table, TransferRange.All, ct).ConfigureAwait(false);
        await using var sink = new ChunkSink(writer, table, $"{table.Directory}/{table.Name}", null, _options.ChunkRows, _options.ChunkBytes);
        await foreach (object row in transfer.ReadAsync(table, TransferRange.All, ct).ConfigureAwait(false))
        {
            object copy = TransferTable.Clone(row);
            table.PrepareForExport(copy);
            string canonical = table.Canonical(copy);
            sum.AddRow(canonical);
            foreach (ITransferSecret secret in table.Secrets)
            {
                byte[]? stored = secret.Get(copy);
                if (stored is not { Length: > 0 })
                {
                    continue;
                }

                byte[] plain;
                try
                {
                    plain = Source.Secrets.Unprotect(stored, secret.Purpose);
                }
                catch (Exception ex) when (ex is CryptographicException or InvalidOperationException)
                {
                    throw new SwitchException($"A secret in {table.Name}.{secret.Column} cannot be unprotected with the source's Data Protection key ring ({ex.Message}). The source's key ring and its Secrets:KeyProtection certificate must be available during the export.", ex);
                }

                try
                {
                    sum.AddSecret(digestKey, canonical, secret.Column, plain);
                    secret.Set(copy, bundleSecrets.Protect(plain, secret.Purpose));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plain);
                }
            }

            await sink.WriteAsync(table.Serialize(copy), table.Body?.Get(row), ct).ConfigureAwait(false);
            if (sum.Rows % 1000 == 0)
            {
                Report(progress, "export", table.Name, sum.Rows, total, $"{table.Name}: {sum.Rows} of {total} rows");
            }
        }

        Report(progress, "export", table.Name, sum.Rows, total, $"{table.Name}: {sum.Rows} rows");
        return sum;
    }

    /// <summary>
    /// Appends history to the bundle one day at a time; the manifest is replaced atomically after each day, so a killed export
    /// resumes after the last complete day and never leaves a listed file half written.
    /// </summary>
    private async Task ExportHistoryAsync(BundleWriter writer, IProgress<SwitchProgress>? progress, CancellationToken ct)
    {
        IStorageTransfer transfer = SourceTransfer;
        BundleManifest manifest = writer.Manifest;
        if (manifest.Switch.HistoryComplete)
        {
            return;
        }

        writer.DeleteUnlistedUnder("history");
        IReadOnlyList<int> days = await transfer.GetHistoryDaysAsync(ct).ConfigureAwait(false);
        manifest.Switch.HistoryThroughDay ??= days.Count > 0 ? days[^1] : null;
        var sums = TransferTables.Of(TransferPart.History).ToDictionary(t => t.Name, t =>
        {
            BundleTable? saved = manifest.Tables.FirstOrDefault(x => x.Name == t.Name);
            return saved is null ? new TableChecksum() : TableChecksum.Resume(saved.Rows, saved.Checksum, saved.SecretDigest);
        });

        int done = 0;
        foreach (int day in days.Where(d => manifest.Switch.LastHistoryDay is not { } last || d > last))
        {
            ct.ThrowIfCancellationRequested();
            string date = Logic.StorageTime.DayStart(day).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            foreach (TransferTable table in TransferTables.Of(TransferPart.History))
            {
                TableChecksum sum = sums[table.Name];
                await using var sink = new ChunkSink(writer, table, $"history/{table.Name}/{date}", date, _options.ChunkRows, _options.ChunkBytes);
                await foreach (object row in transfer.ReadAsync(table, TransferRange.Day(day), ct).ConfigureAwait(false))
                {
                    object copy = TransferTable.Clone(row);
                    table.PrepareForExport(copy);
                    sum.AddRow(table.Canonical(copy));
                    await sink.WriteAsync(table.Serialize(copy), table.Body?.Get(row), ct).ConfigureAwait(false);
                }
            }

            foreach (TransferTable table in TransferTables.Of(TransferPart.History))
            {
                int at = manifest.Tables.FindIndex(x => x.Name == table.Name);
                BundleTable entry = sums[table.Name].ToManifest(table.Name, table.Directory);
                if (at < 0)
                {
                    manifest.Tables.Add(entry);
                }
                else
                {
                    manifest.Tables[at] = entry;
                }
            }

            manifest.Switch.LastHistoryDay = day;
            await writer.CheckpointAsync(ct).ConfigureAwait(false);
            done++;
            Report(progress, "export-history", null, done, days.Count, $"History day {date} exported ({done} of {days.Count} remaining-or-done days)");
        }

        manifest.Switch.HistoryComplete = true;
        await writer.CheckpointAsync(ct).ConfigureAwait(false);
    }
}
