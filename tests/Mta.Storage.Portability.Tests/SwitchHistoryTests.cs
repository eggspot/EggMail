using Mta.Core;
using Mta.Storage.Model;
using Mta.Storage.Transfer;

namespace Mta.Storage.Portability.Tests;

/// <summary>Per-message history moves in per-day, checksummed chunks, resumably (design §4.6).</summary>
public class SwitchHistoryTests : SwitchTestBase
{
    private async Task<(TestStore Source, TestStore Target, StorageSwitchEngine Engine)> SeededAsync(StoreKind from = StoreKind.Sqlite, StoreKind to = StoreKind.Sqlite)
    {
        TestStore source = await NewStoreAsync(from, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(to, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 2, deliveredPerDay: 3, days: 5);
        return (source, target, NewEngine(source, target, activator: new RecordingActivator()));
    }

    private static SwitchRequest Quiesce(string bundle) => new() { Mode = SwitchMode.Quiesce, BundlePath = bundle, Passphrase = Pass, QuiesceTimeout = TimeSpan.FromMilliseconds(50) };

    [Fact]
    public async Task History_is_exported_in_per_day_chunks_that_the_manifest_lists_with_their_day()
    {
        var (source, _, engine) = await SeededAsync();
        await engine.StartAsync(Quiesce(BundleDir()), null, default);
        ExportResult export = await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.True(export.HistoryComplete);

        BundleReader reader = await BundleReader.OpenAsync(BundleDir(), default);
        Assert.True((await reader.VerifyAsync(default)).Ok);
        var historyFiles = reader.Manifest.Files.Where(f => f.Path.StartsWith("history/", StringComparison.Ordinal) && f.Kind == "rows").ToList();
        Assert.NotEmpty(historyFiles);
        Assert.All(historyFiles, f =>
        {
            Assert.Matches(@"^\d{4}-\d{2}-\d{2}$", f.ChunkFrom!);
            Assert.Equal(f.ChunkFrom, f.ChunkTo);
            Assert.Contains(f.ChunkFrom!, f.Path);
        });
        Assert.True(historyFiles.Select(f => f.ChunkFrom).Distinct().Count() >= 5);
        Assert.Equal((await ReadAsync<MessageEventEntity>(source, TransferTables.MessageEvents)).Count, reader.Manifest.Tables.Single(t => t.Name == "message_event").Rows);
        // Retained raw travels in body packs, not in the rows.
        Assert.Contains(reader.Manifest.Files, f => f.Kind == "bodies" && f.Path.StartsWith("history/message_raw_retained/", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_killed_history_export_resumes_after_the_last_complete_day_and_drops_half_written_files()
    {
        var (source, target, engine) = await SeededAsync();
        await engine.StartAsync(Quiesce(BundleDir()), null, default);
        using var cts = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => engine.ExportAsync(
            new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, new CancelOnProgress(cts, p => p.Phase == "export-history" && p.Done == 2), cts.Token));

        // The manifest on disk is consistent and says how far it got.
        BundleReader partial = await BundleReader.OpenAsync(BundleDir(), default);
        Assert.False(partial.Manifest.Switch.HistoryComplete);
        Assert.NotNull(partial.Manifest.Switch.LastHistoryDay);
        Assert.True((await partial.VerifyAsync(default)).Ok);
        int exportedDays = partial.Manifest.Files.Where(f => f.Path.StartsWith("history/message_index/", StringComparison.Ordinal)).Select(f => f.ChunkFrom).Distinct().Count();
        Assert.Equal(2, exportedDays);

        // A crash in the middle of a day leaves files the manifest does not list.
        string orphan = Path.Combine(BundleDir(), "history", "message_event", "2999-01-01.00001.ndjson");
        File.WriteAllText(orphan, "{\"half\":\"written\"}\n");

        // A fresh engine (a new process) resumes.
        StorageSwitchEngine resumed = NewEngine(source, target, activator: new RecordingActivator());
        ExportResult export = await resumed.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.True(export.HistoryComplete);
        Assert.False(File.Exists(orphan));
        Assert.Contains(export.Notes, n => n.Contains("Resumed"));
        BundleReader done = await BundleReader.OpenAsync(BundleDir(), default);
        Assert.True((await done.VerifyAsync(default)).Ok);
        Assert.True(done.Manifest.Switch.HistoryComplete);

        await resumed.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        VerifyReport report = await resumed.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.True(report.Ok, string.Join("; ", report.Problems));
        await AssertSameAsync(source, target);
    }

    [Fact]
    public async Task A_killed_history_import_continues_after_the_last_applied_chunk_and_re_sending_a_chunk_is_harmless()
    {
        var (source, target, engine) = await SeededAsync(StoreKind.InMemory, StoreKind.Sqlite);
        await engine.StartAsync(Quiesce(BundleDir()), null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        BundleManifest manifest = (await BundleReader.OpenAsync(BundleDir(), default)).Manifest;
        int historyChunks = manifest.Files.Count(f => f.Kind == "rows" && f.Path.StartsWith("history/", StringComparison.Ordinal));
        Assert.True(historyChunks > 6);

        using var cts = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => engine.ImportAsync(
            new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, new CancelOnProgress(cts, p => p.Phase == "import-history" && p.Done >= 4), cts.Token));

        var appliedSoFar = await target.Transfer.GetAppliedChunksAsync(manifest.SwitchId, TransferPart.History, default);
        Assert.InRange(appliedSoFar.Count, 1, historyChunks - 1);
        long indexRowsSoFar = await target.Transfer.CountAsync(TransferTables.MessageIndex, TransferRange.All, default);
        Assert.True(indexRowsSoFar < (await source.Transfer.CountAsync(TransferTables.MessageIndex, TransferRange.All, default)));

        // Verify sees an incomplete history and says so, without failing the core.
        VerifyReport partial = await engine.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.True(partial.Ok, string.Join("; ", partial.Problems));
        Assert.Equal(appliedSoFar.Count, partial.HistoryChunksApplied);
        Assert.Contains(partial.Notes, n => n.Contains("History is not complete"));

        // Resume: only the missing chunks are applied.
        ImportResult resumed = await NewEngine(source, target).ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.Equal(historyChunks - appliedSoFar.Count, resumed.ChunksApplied);
        Assert.True(resumed.ChunksAlreadyApplied >= appliedSoFar.Count);

        // Re-sending everything again changes nothing.
        ImportResult again = await NewEngine(source, target).ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.Equal(0, again.ChunksApplied);
        Assert.Equal(0, again.RowsApplied);

        VerifyReport full = await engine.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.True(full.Ok, string.Join("; ", full.Problems));
        Assert.Equal(historyChunks, full.HistoryChunksApplied);
        await AssertSameAsync(source, target);
    }

    [Fact]
    public async Task A_chunk_applied_by_a_process_that_died_before_it_reported_is_not_applied_twice()
    {
        var (source, target, engine) = await SeededAsync();
        await engine.StartAsync(Quiesce(BundleDir()), null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        await engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass, Scope = ImportScope.Core }, null, default);
        BundleReader reader = await BundleReader.OpenAsync(BundleDir(), default);

        // The first history chunk went into the target (rows and progress record) but the process died before it moved on.
        BundleFile first = reader.Manifest.Files.Where(f => f.Kind == "rows" && f.Path.StartsWith("history/message_index/", StringComparison.Ordinal)).OrderBy(f => f.Path, StringComparer.Ordinal).First();
        var rows = new List<object>();
        await foreach (string line in reader.ReadLinesAsync(first.Path, default))
        {
            rows.Add(TransferTables.MessageIndex.Deserialize(line));
        }

        await target.Transfer.ApplyChunkAsync(new TransferChunk(reader.Manifest.SwitchId, TransferTables.MessageIndex, first.Path, first.Sha256, false), rows, default);
        long before = await target.Transfer.CountAsync(TransferTables.MessageIndex, TransferRange.All, default);

        ImportResult result = await engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass, Scope = ImportScope.HistoryOnly }, null, default);
        Assert.True(result.ChunksAlreadyApplied >= 1);
        Assert.True(await target.Transfer.CountAsync(TransferTables.MessageIndex, TransferRange.All, default) >= before);
        Assert.True((await engine.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default)).Ok);
        await AssertSameAsync(source, target);
    }

    [Fact]
    public async Task A_corrupted_history_chunk_stops_the_import_after_the_earlier_chunks_and_a_repaired_bundle_resumes()
    {
        var (source, target, engine) = await SeededAsync();
        await engine.StartAsync(Quiesce(BundleDir()), null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        BundleReader reader = await BundleReader.OpenAsync(BundleDir(), default);
        BundleFile victim = reader.Manifest.Files.Where(f => f.Kind == "rows" && f.Path.StartsWith("history/message_event/", StringComparison.Ordinal)).OrderBy(f => f.Path, StringComparer.Ordinal).Last();
        string path = Path.Combine(BundleDir(), victim.Path);
        string original = await File.ReadAllTextAsync(path);
        await File.WriteAllTextAsync(path, original.Replace("\"type\"", "\"tyqe\"", StringComparison.Ordinal));

        BundleException ex = await Assert.ThrowsAsync<BundleException>(() => engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default));
        Assert.Contains(victim.Path, ex.Message);
        var applied = await target.Transfer.GetAppliedChunksAsync(reader.Manifest.SwitchId, TransferPart.History, default);
        Assert.DoesNotContain(applied, a => a.ChunkId == victim.Path);
        Assert.NotEmpty(applied);

        await File.WriteAllTextAsync(path, original);
        await engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.True((await engine.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default)).Ok);
        await AssertSameAsync(source, target);
    }

    [Fact]
    public async Task History_can_be_backfilled_after_activation_without_touching_what_the_target_recorded_meanwhile()
    {
        var (source, target, engine) = await SeededAsync(StoreKind.Sqlite, StoreKind.InMemory);
        await engine.StartAsync(Quiesce(BundleDir()), null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        await engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass, Scope = ImportScope.Core }, null, default);
        Assert.Empty(await ReadAsync<MessageIndexEntity>(target, TransferTables.MessageIndex));
        VerifyReport core = await engine.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.True(core.Ok, string.Join("; ", core.Problems));
        Assert.Contains(core.Notes, n => n.Contains("History is not complete"));
        await engine.ConfirmAsync(default);
        await engine.ActivateAsync(default);
        await TargetActivation.ActivateAsync(target.Transfer, SystemClock.Instance, default);

        // The target works and records history of its own.
        Guid fresh = await SwitchFlowTests.EnqueueAsync(target.Storage, "fresh@example.org");
        Assert.NotEmpty(await target.Storage.History.GetEventsAsync(Seed.TenantA, fresh, default));

        // Finalize waits for the backfill.
        var early = await Assert.ThrowsAsync<SwitchException>(() => engine.FinalizeAsync(false, null, default));
        Assert.Contains("History is not fully copied", early.Message);

        ImportResult backfill = await engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass, Scope = ImportScope.HistoryOnly }, null, default);
        Assert.True(backfill.HistoryChunksApplied > 0);
        VerifyReport report = await engine.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.True(report.Ok, string.Join("; ", report.Problems));
        Assert.Equal(report.HistoryChunksTotal, report.HistoryChunksApplied);

        Assert.NotEmpty(await target.Storage.History.GetEventsAsync(Seed.TenantA, fresh, default)); // still there
        var sourceIndex = await ReadAsync<MessageIndexEntity>(source, TransferTables.MessageIndex);
        var targetIndex = await ReadAsync<MessageIndexEntity>(target, TransferTables.MessageIndex);
        Assert.Equal(sourceIndex.Count + 1, targetIndex.Count);
        Assert.All(sourceIndex, s => Assert.Contains(targetIndex, t => t.MessageId == s.MessageId));

        SwitchStatus final = await engine.FinalizeAsync(false, null, default);
        Assert.Equal(SwitchStates.Finalized, final.SourceState);
    }

    [Fact]
    public async Task Skipping_history_leaves_it_in_the_read_only_source_and_the_bundle_says_so()
    {
        var (source, target, engine) = await SeededAsync();
        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass, SkipHistory = true, QuiesceTimeout = TimeSpan.FromMilliseconds(50) }, null, default);
        ExportResult export = await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass, SkipHistory = true }, null, default);
        Assert.Contains(export.Notes, n => n.Contains("History was not exported"));
        BundleReader reader = await BundleReader.OpenAsync(BundleDir(), default);
        Assert.False(reader.Manifest.Switch.HistoryIncluded);
        Assert.DoesNotContain(reader.Manifest.Files, f => f.Path.StartsWith("history/", StringComparison.Ordinal));

        ImportResult import = await engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.Contains(import.Notes, n => n.Contains("no history"));
        Assert.True((await engine.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default)).Ok);
        Assert.Empty(await ReadAsync<MessageIndexEntity>(target, TransferTables.MessageIndex));
        Assert.NotEmpty(await ReadAsync<MessageIndexEntity>(source, TransferTables.MessageIndex));
    }

    [Fact]
    public async Task Cancelling_an_import_leaves_the_target_in_Importing_and_the_next_import_continues()
    {
        var (source, target, engine) = await SeededAsync(StoreKind.InMemory, StoreKind.Sqlite);
        await engine.StartAsync(Quiesce(BundleDir()), null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);

        using var cts = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => engine.ImportAsync(
            new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, new CancelOnProgress(cts, p => p.Phase == "import" && p.Table == "domain"), cts.Token));
        Assert.Equal(SwitchStates.Importing, (await target.Transfer.GetStateAsync(default))!.State);
        Assert.NotEmpty(await ReadAsync<TenantEntity>(target, TransferTables.Tenants));
        Assert.Empty(await ReadAsync<QueuedDeliveryEntity>(target, TransferTables.Deliveries));

        await NewEngine(source, target).ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.True((await engine.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default)).Ok);
        await AssertSameAsync(source, target);
    }

    [Fact]
    public async Task The_cancel_method_stops_the_running_operation()
    {
        var (_, _, engine) = await SeededAsync();
        await engine.StartAsync(Quiesce(BundleDir()), null, default);
        var cancelling = new CancelViaEngine(engine);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, cancelling, default));
    }

    private sealed class CancelViaEngine(StorageSwitchEngine engine) : IProgress<SwitchProgress>
    {
        public void Report(SwitchProgress value)
        {
            if (value.Phase == "export-history")
            {
                engine.Cancel();
            }
        }
    }

    [Fact]
    public async Task A_bundle_of_format_1_2_without_inbound_tables_imports_and_the_target_starts_with_no_inbound_mail()
    {
        var (source, target, engine) = await SeededAsync();
        await engine.StartAsync(Quiesce(BundleDir()), null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.NotEmpty((await source.Storage.Inbound.SearchAsync(new InboundMessageQuery(TenantId: Seed.TenantA), default)).Items);   // the source has inbound mail: it was seeded

        // What an older exporter wrote: format 1.2.0, no inbound files, no inbound entries in the manifest.
        string manifestPath = Path.Combine(BundleDir(), "manifest.json");
        var manifest = System.Text.Json.Nodes.JsonNode.Parse(await File.ReadAllTextAsync(manifestPath))!.AsObject();
        manifest["formatVersion"] = "1.2.0";
        var files = manifest["files"]!.AsArray();
        foreach (var file in files.ToList())
        {
            string path = file!["path"]!.GetValue<string>();
            if (path.Contains("inbound", StringComparison.Ordinal))
            {
                files.Remove(file);
                File.Delete(Path.Combine(BundleDir(), path));
            }
        }

        var tables = manifest["tables"]!.AsArray();
        foreach (var table in tables.ToList())
        {
            if (table!["name"]!.GetValue<string>().StartsWith("inbound", StringComparison.Ordinal))
            {
                tables.Remove(table);
            }
        }

        await File.WriteAllTextAsync(manifestPath, manifest.ToJsonString());

        ImportResult import = await engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.NotNull(import);
        Assert.Empty((await target.Storage.Inbound.SearchAsync(new InboundMessageQuery(TenantId: Seed.TenantA), default)).Items);
        Assert.Empty(await target.Storage.Inbound.GetRoutesAsync((await target.Storage.Config.GetDomainsAsync(Seed.TenantA, default)).First().Id, default));
        Assert.NotEmpty(await target.Storage.Config.GetDomainsAsync(Seed.TenantA, default));   // everything else came along
    }

    [Fact]
    public async Task A_manifest_without_heldRows_is_a_problem_for_received_mail_and_still_fine_for_tables_that_hold_every_row()
    {
        var (_, _, engine) = await SeededAsync();
        await engine.StartAsync(Quiesce(BundleDir()), null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        await engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        var request = new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass };

        VerifyReport good = await engine.VerifyAsync(request, null, default);
        Assert.True(good.Ok, string.Join("; ", good.Problems));
        string manifestPath = Path.Combine(BundleDir(), "manifest.json");
        var manifest = System.Text.Json.Nodes.JsonNode.Parse(await File.ReadAllTextAsync(manifestPath))!.AsObject();
        var inbound = manifest["tables"]!.AsArray().Single(t => t!["name"]!.GetValue<string>() == "inbound_message")!.AsObject();
        Assert.True(inbound["heldRows"]!.GetValue<long>() < inbound["rows"]!.GetValue<long>());   // only the pending action is held

        // A manifest from before heldRows existed says nothing: tables that hold every row fall back to their row count, received mail cannot be guessed.
        foreach (var table in manifest["tables"]!.AsArray())
        {
            table!.AsObject().Remove("heldRows");
        }

        await File.WriteAllTextAsync(manifestPath, manifest.ToJsonString());
        VerifyReport bad = await engine.VerifyAsync(request, null, default);
        string problem = Assert.Single(bad.Problems);
        Assert.Contains("inbound_message", problem);
        Assert.Contains("heldRows", problem);
    }
}

