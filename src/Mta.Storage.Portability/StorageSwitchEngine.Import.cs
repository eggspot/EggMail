using System.Security.Cryptography;
using System.Text.Json;
using Mta.Core;
using Mta.Storage.Transfer;

namespace Mta.Storage.Portability;

public sealed partial class StorageSwitchEngine
{
    private static int TableOrder(TransferTable table)
    {
        for (int i = 0; i < TransferTables.All.Count; i++)
        {
            if (ReferenceEquals(TransferTables.All[i], table))
            {
                return i;
            }
        }

        return int.MaxValue;
    }

    /// <summary>The row files of a bundle, in import order: config, stats and queue by table, then history by day.</summary>
    private static List<(BundleFile File, TransferTable Table)> RowFiles(BundleManifest manifest, bool history)
    {
        var list = new List<(BundleFile, TransferTable)>();
        foreach (BundleFile f in manifest.Files.Where(f => f.Kind == "rows" && f.Table is not null))
        {
            TransferTable table;
            try
            {
                table = TransferTables.ByName(f.Table!);
            }
            catch (KeyNotFoundException ex)
            {
                throw new BundleException($"{f.Path}: the manifest names a table this version does not know ('{f.Table}').", ex);
            }

            if ((table.Part == TransferPart.History) == history)
            {
                list.Add((f, table));
            }
        }

        return history
            ? list.OrderBy(x => x.Item1.ChunkFrom, StringComparer.Ordinal).ThenBy(x => TableOrder(x.Item2)).ThenBy(x => x.Item1.Path, StringComparer.Ordinal).ToList()
            : list.OrderBy(x => TableOrder(x.Item2)).ThenBy(x => x.Item1.Path, StringComparer.Ordinal).ToList();
    }

    public async Task<ImportResult> ImportAsync(ImportRequest request, IProgress<SwitchProgress>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return await RunAsync("import", cancellationToken, async ct =>
        {
            SwitchEndpoint target = Target;
            IStorageTransfer transfer = TargetTransfer;
            if (request.Passphrase.Length < BundleSecretProtector.MinimumPassphraseLength)
            {
                throw new SwitchException($"The export passphrase must be at least {BundleSecretProtector.MinimumPassphraseLength} characters.");
            }

            if (!target.KeysProtectedAtRest && !request.AcceptUnprotectedTarget)
            {
                throw new SwitchException("The target runs with Secrets:KeyProtection=None, so the re-protected secrets would be only as safe as its database. Configure a certificate for the target, or acknowledge this explicitly (--accept-unprotected-keys).");
            }

            BundleReader reader = await BundleReader.OpenAsync(request.BundlePath, ct).ConfigureAwait(false);
            BundleManifest manifest = reader.Manifest;
            Guid switchId = manifest.SwitchId;

            // Fails cleanly with a wrong passphrase, before anything is written.
            ISecretProtector bundleSecrets = BundleSecretProtector.OpenForImport(reader, request.Passphrase);

            SwitchStateRecord? state = await transfer.GetStateAsync(ct).ConfigureAwait(false);
            if (state is null)
            {
                if (request.Scope == ImportScope.HistoryOnly)
                {
                    throw new SwitchException("A history-only import continues a switch that was already imported into this target; there is none.");
                }

                IReadOnlyList<string> nonEmpty = await transfer.GetNonEmptyTablesAsync(ct).ConfigureAwait(false);
                if (nonEmpty.Count > 0)
                {
                    throw new SwitchException($"The target is not empty ({string.Join(", ", nonEmpty.Take(8))}) and does not carry switch {switchId}; the import refuses to merge into existing data.");
                }
            }
            else if (state.Role != SwitchRoles.Target || state.SwitchId != switchId)
            {
                throw new SwitchException($"The target already belongs to switch {state.SwitchId} as {state.Role} ({state.State}); this bundle is switch {switchId}. The import refuses a target that does not carry the same switch id.");
            }
            else if (state.State == SwitchStates.Active && request.Scope != ImportScope.HistoryOnly)
            {
                throw new SwitchException("The target is already active; only the history backfill (history-only) may still be imported.");
            }

            // Everything except history is verified file by file before the first row is written; history is verified chunk by chunk as it is applied.
            var coreFiles = RowFiles(manifest, history: false);
            if (request.Scope != ImportScope.HistoryOnly)
            {
                foreach (BundleFile f in manifest.Files.Where(f => !f.Path.StartsWith("history/", StringComparison.Ordinal)))
                {
                    ct.ThrowIfCancellationRequested();
                    await reader.VerifyFileAsync(f, ct).ConfigureAwait(false);
                }
            }

            var detail = SwitchDetail.Parse(state?.Detail);
            if (state is null)
            {
                detail.Bundle = reader.Root;
                detail.Mode = manifest.Switch.Mode;
                state = NewState(switchId, SwitchRoles.Target, SwitchStates.Importing, detail);
                await transfer.SetStateAsync(state, ct).ConfigureAwait(false);
            }

            var applied = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (TransferPart part in Enum.GetValues<TransferPart>().Where(transfer.HasPart))
            {
                foreach (TransferChunkRecord r in await transfer.GetAppliedChunksAsync(switchId, part, ct).ConfigureAwait(false))
                {
                    applied[r.ChunkId] = r.Checksum;
                }
            }

            var notes = new List<string>();
            long rows = 0, chunks = 0, already = 0, historyApplied = 0, historyTotal = 0;
            bool appliedNew = false;

            async Task ApplyAsync(BundleFile file, TransferTable table, bool isHistory)
            {
                ct.ThrowIfCancellationRequested();
                if (applied.TryGetValue(file.Path, out string? checksum))
                {
                    if (!string.Equals(checksum, file.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new BundleException($"{file.Path}: the chunk was imported earlier with another checksum; the bundle changed since the import started.");
                    }

                    already++;
                    if (isHistory)
                    {
                        historyApplied++;
                    }

                    return;
                }

                ChunkApplyOutcome outcome = await ImportFileAsync(reader, file, table, switchId, bundleSecrets, ct).ConfigureAwait(false);
                if (outcome == ChunkApplyOutcome.Applied)
                {
                    appliedNew = true;
                    chunks++;
                    rows += file.Rows;
                    if (isHistory)
                    {
                        historyApplied++;
                    }
                }
                else
                {
                    already++;
                }

                Report(progress, isHistory ? "import-history" : "import", table.Name, chunks + already, 0, $"{file.Path}: {file.Rows} rows");
            }

            if (request.Scope != ImportScope.HistoryOnly)
            {
                foreach ((BundleFile file, TransferTable table) in coreFiles.Where(x => transfer.HasPart(x.Table.Part)))
                {
                    await ApplyAsync(file, table, isHistory: false).ConfigureAwait(false);
                }
            }

            if (request.Scope != ImportScope.Core)
            {
                if (!manifest.Switch.HistoryIncluded)
                {
                    notes.Add("The bundle carries no history (skipped, or the source records none).");
                }
                else if (!transfer.HasPart(TransferPart.History))
                {
                    notes.Add("The target records no per-message history (History:Mode=StatsOnly): history is not carried over and stays in the read-only source.");
                }
                else
                {
                    var historyFiles = RowFiles(manifest, history: true);
                    historyTotal = historyFiles.Count;
                    foreach ((BundleFile file, TransferTable table) in historyFiles)
                    {
                        await ApplyAsync(file, table, isHistory: true).ConfigureAwait(false);
                    }

                    if (!manifest.Switch.HistoryComplete)
                    {
                        notes.Add($"The history export is incomplete (through day {manifest.Switch.LastHistoryDay}); import again after it finished.");
                    }
                }
            }
            else if (manifest.Switch.HistoryIncluded)
            {
                notes.Add("History was left out of this import; copy it later with a history-only import (before activation, or as a backfill after).");
            }

            if (appliedNew && state.State is SwitchStates.Verified or SwitchStates.Confirmed)
            {
                // New rows invalidate the earlier verification.
                await transfer.SetStateAsync(state with { State = SwitchStates.Importing, UpdatedAt = Truncate(_clock.UtcNow) }, ct).ConfigureAwait(false);
            }

            Report(progress, "import", null, 1, 1, $"Imported {rows} rows in {chunks} chunks ({already} chunks were already applied)");
            return new ImportResult(switchId, rows, chunks, already, historyApplied, historyTotal, notes);
        }).ConfigureAwait(false);
    }

    private async Task<ChunkApplyOutcome> ImportFileAsync(BundleReader reader, BundleFile file, TransferTable table, Guid switchId, ISecretProtector bundleSecrets, CancellationToken ct)
    {
        // The chunk (and its body pack) must match the manifest before a single row of it is applied.
        await reader.VerifyFileAsync(file, ct).ConfigureAwait(false);
        BodyPackReader? bodies = null;
        if (table.Body is not null)
        {
            string bodiesPath = file.Path[..^".ndjson".Length] + ".bodies";
            BundleFile bodyFile = reader.Manifest.Files.FirstOrDefault(f => f.Path == bodiesPath && f.Kind == "bodies")
                ?? throw new BundleException($"{file.Path}: the body pack {bodiesPath} is not listed in the manifest.");
            await reader.VerifyFileAsync(bodyFile, ct).ConfigureAwait(false);
            bodies = await BodyPackReader.OpenAsync(reader.PathOf(bodiesPath), ct).ConfigureAwait(false);
        }

        try
        {
            var rows = new List<object>((int)Math.Min(file.Rows, int.MaxValue));
            await foreach (string line in reader.ReadLinesAsync(file.Path, ct).ConfigureAwait(false))
            {
                object row;
                try
                {
                    row = table.Deserialize(line);
                }
                catch (JsonException ex)
                {
                    throw new BundleException($"{file.Path}: {ex.Message}", ex);
                }

                if (bodies is not null)
                {
                    byte[] body = await bodies.ReadNextAsync(ct).ConfigureAwait(false) ?? throw new BundleException($"{file.Path}: the body pack has fewer bodies than the chunk has rows.");
                    table.Body!.Set(row, body);
                }

                foreach (ITransferSecret secret in table.Secrets)
                {
                    byte[]? protectedByBundle = secret.Get(row);
                    if (protectedByBundle is not { Length: > 0 })
                    {
                        continue;
                    }

                    byte[] plain = bundleSecrets.Unprotect(protectedByBundle, secret.Purpose);
                    try
                    {
                        secret.Set(row, Target.Secrets.Protect(plain, secret.Purpose));
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(plain);
                    }
                }

                rows.Add(row);
            }

            if (bodies is not null && await bodies.ReadNextAsync(ct).ConfigureAwait(false) is not null)
            {
                throw new BundleException($"{file.Path}: the body pack has more bodies than the chunk has rows.");
            }

            if (rows.Count != file.Rows)
            {
                throw new BundleException($"{file.Path}: {rows.Count} rows read, the manifest says {file.Rows}.");
            }

            return await TargetTransfer.ApplyChunkAsync(new TransferChunk(switchId, table, file.Path, file.Sha256, HoldRows: table.HasHold), rows, ct).ConfigureAwait(false);
        }
        finally
        {
            if (bodies is not null)
            {
                await bodies.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    // ---- Verify

    public async Task<VerifyReport> VerifyAsync(BundleRequest request, IProgress<SwitchProgress>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return await RunAsync("verify", cancellationToken, async ct =>
        {
            SwitchEndpoint target = Target;
            IStorageTransfer transfer = TargetTransfer;
            SwitchStateRecord state = await RequireTargetStateAsync(ct, SwitchStates.Importing, SwitchStates.Verified, SwitchStates.Confirmed, SwitchStates.Active).ConfigureAwait(false);
            BundleReader reader = await BundleReader.OpenAsync(request.BundlePath, ct).ConfigureAwait(false);
            BundleManifest manifest = reader.Manifest;
            if (manifest.SwitchId != state.SwitchId)
            {
                throw new SwitchException($"The bundle is switch {manifest.SwitchId}, the target belongs to switch {state.SwitchId}.");
            }

            var problems = new List<string>();
            var notes = new List<string>();
            bool active = state.State == SwitchStates.Active;

            Report(progress, "verify", null, 0, 1, "Checking the bundle files");
            BundleVerification files = await reader.VerifyAsync(ct).ConfigureAwait(false);
            problems.AddRange(files.Problems);

            ISecretProtector bundleSecrets = BundleSecretProtector.OpenForImport(reader, request.Passphrase);
            byte[]? digestKey = manifest.Secrets.DigestKeyProtected is { } key
                ? bundleSecrets.Unprotect(Convert.FromBase64String(key), DigestKeyPurpose)
                : null;

            var tables = new List<TableVerification>();
            var applied = new Dictionary<string, TransferChunkRecord>(StringComparer.Ordinal);
            foreach (TransferPart part in Enum.GetValues<TransferPart>().Where(transfer.HasPart))
            {
                foreach (TransferChunkRecord r in await transfer.GetAppliedChunksAsync(state.SwitchId, part, ct).ConfigureAwait(false))
                {
                    applied[r.ChunkId] = r;
                }
            }

            // Core tables: row counts and checksums recomputed from the target's own tables (not possible once the target is live and changing).
            if (!active)
            {
                foreach (BundleFile f in RowFiles(manifest, history: false).Select(x => x.File))
                {
                    if (!applied.TryGetValue(f.Path, out TransferChunkRecord? record) || !string.Equals(record.Checksum, f.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        problems.Add($"{f.Path}: not imported (or imported with another checksum)");
                    }
                }

                foreach (BundleTable expected in manifest.Tables.Where(t => TransferTables.ByName(t.Name).Part != TransferPart.History))
                {
                    TransferTable table = TransferTables.ByName(expected.Name);
                    if (!transfer.HasPart(table.Part))
                    {
                        continue;
                    }

                    TableChecksum actual = await RecomputeAsync(table, digestKey, ct).ConfigureAwait(false);
                    bool sumOk = actual.Rows == expected.Rows && string.Equals(actual.Checksum, expected.Checksum, StringComparison.Ordinal);
                    bool? secretsOk = expected.SecretDigest is null ? null : string.Equals(actual.SecretDigest, expected.SecretDigest, StringComparison.Ordinal);
                    tables.Add(new TableVerification(expected.Name, expected.Rows, actual.Rows, sumOk, secretsOk));
                    if (!sumOk)
                    {
                        problems.Add($"{expected.Name}: {actual.Rows} rows with checksum {actual.Checksum} in the target, {expected.Rows} rows with {expected.Checksum} in the bundle");
                    }

                    if (secretsOk == false)
                    {
                        problems.Add($"{expected.Name}: the secrets in the target do not match the bundle's secret digest (re-protection changed a secret)");
                    }

                    Report(progress, "verify", expected.Name, tables.Count, manifest.Tables.Count, $"{expected.Name}: {actual.Rows} rows");
                }
            }

            // Queue rows must all still be held by this switch until activation.
            long held = await transfer.CountHeldQueueRowsAsync(state.SwitchId, ct).ConfigureAwait(false);
            if (!active)
            {
                long expectedHeld = manifest.Tables.Where(t => TransferTables.ByName(t.Name) is { HasHold: true }).Sum(t => t.HeldRows ?? t.Rows);
                if (held != expectedHeld)
                {
                    problems.Add($"queue: {held} rows are held in the target, the bundle has {expectedHeld}");
                }
            }

            // History: chunk by chunk (progress records), and the whole-table checksum when the target holds nothing else.
            long historyApplied = 0, historyTotal = 0;
            if (manifest.Switch.HistoryIncluded && transfer.HasPart(TransferPart.History))
            {
                var historyFiles = RowFiles(manifest, history: true);
                historyTotal = historyFiles.Count;
                foreach ((BundleFile f, _) in historyFiles)
                {
                    if (applied.TryGetValue(f.Path, out TransferChunkRecord? record))
                    {
                        if (!string.Equals(record.Checksum, f.Sha256, StringComparison.OrdinalIgnoreCase) || record.Rows != f.Rows)
                        {
                            problems.Add($"{f.Path}: the applied chunk differs from the bundle");
                        }
                        else
                        {
                            historyApplied++;
                        }
                    }
                }

                if (historyApplied < historyTotal || !manifest.Switch.HistoryComplete)
                {
                    notes.Add($"History is not complete yet: {historyApplied} of {historyTotal} chunks applied{(manifest.Switch.HistoryComplete ? string.Empty : ", and the export is still incomplete")}.");
                }
                else if (!active)
                {
                    foreach (BundleTable expected in manifest.Tables.Where(t => TransferTables.ByName(t.Name).Part == TransferPart.History))
                    {
                        TransferTable table = TransferTables.ByName(expected.Name);
                        TableChecksum actual = await RecomputeAsync(table, null, ct).ConfigureAwait(false);
                        bool ok = actual.Rows == expected.Rows && string.Equals(actual.Checksum, expected.Checksum, StringComparison.Ordinal);
                        tables.Add(new TableVerification(expected.Name, expected.Rows, actual.Rows, ok, null));
                        if (!ok)
                        {
                            problems.Add($"{expected.Name}: {actual.Rows} rows in the target, {expected.Rows} in the bundle (or the checksum differs)");
                        }
                    }
                }
            }
            else if (manifest.Switch.HistoryIncluded)
            {
                notes.Add("The target records no per-message history: history stays in the read-only source.");
            }

            var report = new VerifyReport
            {
                Ok = problems.Count == 0,
                Tables = tables,
                Problems = problems,
                FilesChecked = files.FilesChecked,
                BytesChecked = files.BytesChecked,
                QueueRowsHeld = held,
                HistoryChunksApplied = historyApplied,
                HistoryChunksTotal = historyTotal,
                SecretsChecked = digestKey is not null && !active,
                Notes = notes,
            };

            if (report.Ok && state.State == SwitchStates.Importing)
            {
                await transfer.SetStateAsync(state with { State = SwitchStates.Verified, UpdatedAt = Truncate(_clock.UtcNow) }, ct).ConfigureAwait(false);
            }

            Report(progress, "verify", null, 1, 1, report.Ok ? "Verified" : "Verification found problems");
            return report;
        }).ConfigureAwait(false);
    }

    /// <summary>Recomputes a table's row count, checksum and (with the digest key) secret digest from the target.</summary>
    private async Task<TableChecksum> RecomputeAsync(TransferTable table, byte[]? digestKey, CancellationToken ct)
    {
        var sum = new TableChecksum();
        await foreach (object row in TargetTransfer.ReadAsync(table, TransferRange.All, ct).ConfigureAwait(false))
        {
            string canonical = table.Canonical(row);
            sum.AddRow(canonical);
            if (digestKey is null)
            {
                continue;
            }

            foreach (ITransferSecret secret in table.Secrets)
            {
                byte[]? stored = secret.Get(row);
                if (stored is not { Length: > 0 })
                {
                    continue;
                }

                byte[] plain;
                try
                {
                    plain = Target.Secrets.Unprotect(stored, secret.Purpose);
                }
                catch (CryptographicException)
                {
                    // Counted as a mismatch: the digest differs because this secret contributes nothing.
                    continue;
                }

                try
                {
                    sum.AddSecret(digestKey, canonical, secret.Column, plain);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plain);
                }
            }
        }

        return sum;
    }
}
