using System.Text;
using Mta.Core;
using Mta.Storage.Model;
using Mta.Storage.Transfer;

namespace Mta.Storage.Portability.Tests;

/// <summary>The guarantees around the switch: the fence, the activation gate, rollback, tamper detection, resumability, refusals.</summary>
public class SwitchSafetyTests : SwitchTestBase
{
    private static readonly string[] SecretWords = ["cert-private-key", "whsec_123", "relay-pass", "acme-account-key"];

    [Fact]
    public async Task A_fenced_source_refuses_to_accept_and_dispatch_after_a_restart()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 3);
        await SwitchToConfirmedAsync(NewEngine(source, target, activator: new RecordingActivator()), BundleDir());

        await source.ReopenAsync(); // an old pod, or an instance restarted with the old configuration

        Assert.True(source.Transfer.Gate.IsClosed);
        await Assert.ThrowsAsync<StorageFencedException>(async () => await source.Storage.Intake.AcceptAsync(Seed.Message(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(5), ["a@example.org"]), default));
        Assert.Empty(await source.Storage.Deliveries.ClaimAsync("restarted", 100, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default));
        Assert.Empty(await source.Storage.Webhooks.ClaimDueAsync("restarted", 100, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default));

        // Even a real delivery engine on the restarted source sends nothing.
        await using var remote = new RemoteMta();
        await using var rig = new DeliveryRig(source.Storage, remote, "forgotten-pod");
        await Task.Delay(500);
        Assert.Empty(remote.Received);
        Assert.Equal(6, (await ReadAsync<QueuedDeliveryEntity>(source, TransferTables.Deliveries)).Count);
    }

    [Fact]
    public async Task The_target_does_not_dispatch_imported_mail_until_it_is_activated()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 3);
        await SwitchToConfirmedAsync(NewEngine(source, target, activator: new RecordingActivator()), BundleDir());

        await using var remote = new RemoteMta();
        await using (var rig = new DeliveryRig(target.Storage, remote, "target-rig"))
        {
            await Task.Delay(600);
            Assert.Empty(remote.Received); // Confirmed is not Active
        }

        // A restart of the target keeps it closed too (state Confirmed is persisted).
        await target.ReopenAsync();
        Assert.True(target.Transfer.Gate.IsClosed);

        Assert.True(await TargetActivation.ActivateAsync(target.Transfer, SystemClock.Instance, default));
        Assert.False(target.Transfer.Gate.IsClosed);
        await using var liveRig = new DeliveryRig(target.Storage, remote, "target-live");
        await DeliveryRig.WaitAsync(() => remote.Received.Count >= 5);
        Assert.False(await TargetActivation.ActivateAsync(target.Transfer, SystemClock.Instance, default)); // already active: a no-op
    }

    [Fact]
    public async Task Rollback_before_activation_discards_the_target_clears_marks_and_the_fence_and_resumes_the_source()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 3);
        var activator = new RecordingActivator();
        var host = new RecordingHost();
        StorageSwitchEngine engine = NewEngine(source, target, host, activator);
        await SwitchToConfirmedAsync(engine, BundleDir());
        await engine.ActivateAsync(default);
        Assert.False(host.Accepting);

        SwitchStatus status = await engine.RollbackAsync(sourceOnly: false, default);

        Assert.Equal(SwitchStates.Active, status.SourceState);
        Assert.Null(status.TargetState);
        Assert.True(activator.Restored); // the bootstrap pointer is put back
        Assert.True(host.Accepting);
        Assert.False(host.DispatchPaused);
        Assert.Empty(await target.Transfer.GetNonEmptyTablesAsync(default));
        Assert.Null(await target.Transfer.GetStateAsync(default));
        Assert.Empty(await target.Transfer.GetAppliedChunksAsync(Guid.NewGuid(), TransferPart.Queue, default));

        // The source works as before: nothing sent from the target, so nothing can have been duplicated.
        Assert.False(source.Transfer.Gate.IsClosed);
        await source.Storage.Intake.AcceptAsync(Seed.Message(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(5), ["back@example.org"]), default);
        Assert.Equal(7, (await source.Storage.Deliveries.ClaimAsync("w", 100, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default)).Count);

        // And the switch can be started again against the same, now empty, target.
        PreflightReport again = await engine.PreflightAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir("second"), Passphrase = Pass }, default);
        Assert.True(again.CanProceed, string.Join("; ", again.Errors.Select(e => e.Message)));
    }

    [Fact]
    public async Task Rollback_after_the_target_is_active_is_refused_and_the_source_stays_fenced()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 3);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());
        await SwitchToConfirmedAsync(engine, BundleDir());
        await TargetActivation.ActivateAsync(target.Transfer, SystemClock.Instance, default);

        var ex = await Assert.ThrowsAsync<SwitchException>(() => engine.RollbackAsync(false, default));
        Assert.Contains("already active", ex.Message);
        Assert.Equal(SwitchStates.Fenced, (await source.Transfer.GetStateAsync(default))!.State);
        Assert.True(source.Transfer.Gate.IsClosed);
        Assert.Equal(6, (await ReadAsync<QueuedDeliveryEntity>(target, TransferTables.Deliveries)).Count);
    }

    [Fact]
    public async Task Rollback_without_a_target_needs_the_explicit_source_only_choice()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        StorageSwitchEngine engine = NewEngine(source, null);
        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass, QuiesceTimeout = TimeSpan.FromMilliseconds(50) }, null, default);
        Assert.True(source.Transfer.Gate.IsClosed);

        await Assert.ThrowsAsync<SwitchException>(() => engine.RollbackAsync(false, default));
        SwitchStatus status = await engine.RollbackAsync(sourceOnly: true, default);
        Assert.Equal(SwitchStates.Active, status.SourceState);
        Assert.False(source.Transfer.Gate.IsClosed);
    }

    [Fact]
    public async Task A_corrupted_chunk_is_refused_and_nothing_of_it_is_applied()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 3);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());
        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass, QuiesceTimeout = TimeSpan.FromMilliseconds(50) }, null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);

        string chunk = Path.Combine(BundleDir(), "queue", "message_spool.00001.ndjson");
        string text = await File.ReadAllTextAsync(chunk);
        await File.WriteAllTextAsync(chunk, text.Replace("\"tenantId\"", "\"tenantld\"", StringComparison.Ordinal));

        BundleException ex = await Assert.ThrowsAsync<BundleException>(() => engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default));
        Assert.Contains("SHA-256", ex.Message);
        Assert.Empty(await target.Transfer.GetNonEmptyTablesAsync(default)); // refused before the first row was written
        Assert.Null(await target.Transfer.GetStateAsync(default));
    }

    [Fact]
    public async Task A_corrupted_body_pack_a_missing_file_and_a_modified_manifest_are_refused()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 3);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());
        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass, QuiesceTimeout = TimeSpan.FromMilliseconds(50) }, null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);

        string bodies = Path.Combine(BundleDir(), "queue", "message_spool.00001.bodies");
        byte[] original = await File.ReadAllBytesAsync(bodies);
        byte[] flipped = (byte[])original.Clone();
        flipped[flipped.Length / 2] ^= 0x01;
        await File.WriteAllBytesAsync(bodies, flipped);
        await Assert.ThrowsAsync<BundleException>(() => engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default));

        await File.WriteAllBytesAsync(bodies, original);
        File.Delete(Path.Combine(BundleDir(), "config", "tenant.00001.ndjson"));
        await Assert.ThrowsAsync<BundleException>(() => engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default));
        Assert.Empty(await target.Transfer.GetNonEmptyTablesAsync(default));
    }

    [Fact]
    public async Task A_chunk_changed_after_it_was_imported_is_found_by_verify_and_the_target_is_not_marked_verified()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 3);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());
        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass, QuiesceTimeout = TimeSpan.FromMilliseconds(50) }, null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        await engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);

        File.AppendAllText(Path.Combine(BundleDir(), "config", "tenant.00001.ndjson"), " ");
        VerifyReport report = await engine.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.False(report.Ok);
        Assert.Contains(report.Problems, p => p.Contains("tenant.00001.ndjson") && p.Contains("SHA-256"));
        Assert.Equal(SwitchStates.Importing, (await target.Transfer.GetStateAsync(default))!.State);
        await Assert.ThrowsAsync<SwitchException>(() => engine.ConfirmAsync(default));
    }

    [Fact]
    public async Task A_target_that_was_changed_after_the_import_fails_the_checksum()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 3);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());
        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass, QuiesceTimeout = TimeSpan.FromMilliseconds(50) }, null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        await engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);

        // Someone edits the target behind the import's back: a suppression disappears, a DKIM key is replaced.
        await target.Storage.Config.RemoveSuppressionAsync(Seed.TenantA, "gone3@example.org", default);
        DkimKeyRecord key = (await target.Storage.Config.GetDkimKeysAsync((await target.Storage.Config.GetDomainsAsync(null, default))[0].Id, default))[0];
        await target.Storage.Config.AddDkimKeyAsync(key with { Id = Ids.New(), PrivateKeyProtected = target.Protector.Protect("other key"u8, SecretPurposes.DkimKey) }, default);

        VerifyReport report = await engine.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.False(report.Ok);
        Assert.Contains(report.Problems, p => p.StartsWith("suppression:", StringComparison.Ordinal));
        Assert.Contains(report.Problems, p => p.StartsWith("dkim_key:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_secret_swapped_for_another_one_is_caught_by_the_secret_digest()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 0);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());
        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass, QuiesceTimeout = TimeSpan.FromMilliseconds(50) }, null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        await engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);

        // Same row, same shape, different plaintext (protected correctly with the target's ring): only the digest can tell.
        var endpoints = await target.Storage.Config.GetWebhookEndpointsAsync(null, default);
        await target.Storage.Config.UpsertWebhookEndpointAsync(endpoints[0] with { SecretProtected = target.Protector.Protect("whsec_EVIL"u8, SecretPurposes.WebhookSecret) }, default);

        VerifyReport report = await engine.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.False(report.Ok);
        Assert.Contains(report.Problems, p => p.StartsWith("webhook_endpoint:", StringComparison.Ordinal) && p.Contains("secret"));
        Assert.Contains(report.Tables, t => t.Table == "webhook_endpoint" && t.ChecksumMatches && t.SecretsMatch == false);
    }

    [Fact]
    public async Task No_secret_is_ever_written_in_clear_and_the_wrong_passphrase_is_refused_before_anything_is_written()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target", certificateRing: true);
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 3);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());
        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass, QuiesceTimeout = TimeSpan.FromMilliseconds(50) }, null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);

        foreach (string file in Directory.EnumerateFiles(BundleDir(), "*", SearchOption.AllDirectories))
        {
            string text = File.ReadAllText(file, Encoding.Latin1);
            foreach (string word in SecretWords)
            {
                Assert.DoesNotContain(word, text);
            }

            Assert.DoesNotContain(Convert.ToBase64String(Seed.DkimPlain), text);
            Assert.DoesNotContain(Convert.ToBase64String(Seed.VerpPlain), text);
        }

        await Assert.ThrowsAsync<BundleException>(() => engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = "not the right passphrase" }, null, default));
        Assert.Empty(await target.Transfer.GetNonEmptyTablesAsync(default));
        Assert.Null(await target.Transfer.GetStateAsync(default));
        await Assert.ThrowsAsync<SwitchException>(() => engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = "short" }, null, default));

        await engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        await AssertSecretsAsync(source, target);
    }

    [Fact]
    public async Task Different_key_protection_on_each_side_works_because_secrets_are_re_protected()
    {
        // The source ring is protected by a certificate, the target ring is not (Secrets:KeyProtection=None).
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source", certificateRing: true);
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target", certificateRing: false);
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 3);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());

        PreflightReport pre = await engine.PreflightAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass }, default);
        Assert.False(pre.CanProceed);
        Assert.Contains(pre.Errors, e => e.Name == "key-protection");

        // Without the acknowledgement the import refuses; with it the secrets are re-protected under the target's own ring.
        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass, QuiesceTimeout = TimeSpan.FromMilliseconds(50), AcceptUnprotectedTarget = true }, null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        await Assert.ThrowsAsync<SwitchException>(() => engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default));
        await engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass, AcceptUnprotectedTarget = true }, null, default);

        Assert.NotEqual(
            (await ReadAsync<DkimKeyEntity>(source, TransferTables.DkimKeys))[0].PrivateKeyProtected,
            (await ReadAsync<DkimKeyEntity>(target, TransferTables.DkimKeys))[0].PrivateKeyProtected);
        Assert.Equal(Seed.DkimPlain, target.Protector.Unprotect((await ReadAsync<DkimKeyEntity>(target, TransferTables.DkimKeys))[0].PrivateKeyProtected, SecretPurposes.DkimKey));
        Assert.Equal(Seed.VerpPlain, target.Protector.Unprotect((await ReadAsync<VerpKeyEntity>(target, TransferTables.VerpKeys))[0].KeyProtected, SecretPurposes.VerpKey));
        // The source's ring cannot open what the target holds, and vice versa: two independent rings.
        byte[] targetKey = (await ReadAsync<DkimKeyEntity>(target, TransferTables.DkimKeys))[0].PrivateKeyProtected;
        Assert.ThrowsAny<Exception>(() => source.Protector.Unprotect(targetKey, SecretPurposes.DkimKey));
        VerifyReport report = await engine.VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.True(report.Ok, string.Join("; ", report.Problems));
    }

    [Fact]
    public async Task A_source_secret_that_cannot_be_unprotected_fails_the_export_with_a_clear_message()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore other = await NewStoreAsync(StoreKind.InMemory, HistoryMode.Full, "other");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 0);
        // The engine is given a protector that is not the source's ring (its certificate or KMS is not reachable).
        var engine = new StorageSwitchEngine(new SwitchEndpoint { Storage = source.Storage, Secrets = other.Protector, Options = source.Endpoint.Options }, null);
        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass, QuiesceTimeout = TimeSpan.FromMilliseconds(50) }, null, default);

        SwitchException ex = await Assert.ThrowsAsync<SwitchException>(() => engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default));
        Assert.Contains("cannot be unprotected", ex.Message);
    }

    [Fact]
    public async Task Preflight_refuses_a_non_empty_target_and_the_import_does_too()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 2);
        await target.Storage.Config.UpsertTenantAsync(new Tenant(Ids.New(), "Existing", "existing", true, DateTimeOffset.UtcNow, false), default);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());

        PreflightReport pre = await engine.PreflightAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass }, default);
        Assert.False(pre.CanProceed);
        PreflightCheck check = Assert.Single(pre.Errors);
        Assert.Equal("target-empty", check.Name);
        Assert.Contains("tenant", check.Message);

        var ex = await Assert.ThrowsAsync<SwitchException>(() => engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass }, null, default));
        Assert.NotNull(ex.Report);
        Assert.Equal(SwitchStates.Active, (await engine.GetStatusAsync(default)).SourceState ?? SwitchStates.Active); // nothing was started

        // The importer refuses to merge into it as well (a bundle made elsewhere).
        TestStore clean = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "clean");
        StorageSwitchEngine exporter = NewEngine(source, clean, activator: new RecordingActivator());
        await exporter.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir("b2"), Passphrase = Pass, QuiesceTimeout = TimeSpan.FromMilliseconds(50) }, null, default);
        await exporter.ExportAsync(new BundleRequest { BundlePath = BundleDir("b2"), Passphrase = Pass }, null, default);
        var refused = await Assert.ThrowsAsync<SwitchException>(() => engine.ImportAsync(new ImportRequest { BundlePath = BundleDir("b2"), Passphrase = Pass }, null, default));
        Assert.Contains("not empty", refused.Message);
    }

    [Fact]
    public async Task Preflight_reports_the_other_refusals_and_warnings()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target", tweak: o => new StorageOptions
        {
            Backend = o.Backend, History = o.History, Sqlite = o.Sqlite, Content = o.Content, Queue = o.Queue,
            Retention = new RetentionOptions { MetadataDays = 14 },
        });
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 2);
        StorageSwitchEngine engine = NewEngine(source, target);

        Directory.CreateDirectory(BundleDir());
        File.WriteAllText(Path.Combine(BundleDir(), "leftover.txt"), "x");
        PreflightReport pre = await engine.PreflightAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = "short" }, default);
        Assert.Contains(pre.Errors, e => e.Name == "bundle");
        Assert.Contains(pre.Errors, e => e.Name == "passphrase");
        Assert.Contains(pre.Checks, c => c.Name == "sync-mode" && c.Status == CheckStatus.Warning); // SQLite target with SyncMode=Off
        Assert.Contains(pre.Checks, c => c.Name == "effective-settings" && c.Message.Contains("Retention:MetadataDays 30 to 14"));
        Assert.Contains(pre.WillNotCarryOver, w => w.Contains("Data Protection key ring"));

        // Source and target in the same SQLite directory.
        var same = new StorageSwitchEngine(source.Endpoint, source.Endpoint);
        Assert.Contains((await same.PreflightAsync(new SwitchRequest(), default)).Errors, e => e.Name == "target-distinct");

        // A target with a switch record of its own.
        await target.Transfer.SetStateAsync(new SwitchStateRecord(Guid.NewGuid(), SwitchRoles.Target, SwitchStates.Importing, DateTimeOffset.UtcNow, null), default);
        Assert.Contains((await engine.PreflightAsync(new SwitchRequest { BundlePath = BundleDir("fresh"), Passphrase = Pass }, default)).Errors, e => e.Name == "target-state");
    }

    [Fact]
    public async Task Export_and_import_need_the_right_state()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 1);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());

        var notStarted = await Assert.ThrowsAsync<SwitchException>(() => engine.ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default));
        Assert.Contains("not part of a switch", notStarted.Message);
        await Assert.ThrowsAsync<SwitchException>(() => engine.ConfirmAsync(default));
        await Assert.ThrowsAsync<SwitchException>(() => engine.ActivateAsync(default));
        await Assert.ThrowsAsync<SwitchException>(() => engine.FinalizeAsync(false, null, default));
        await Assert.ThrowsAsync<SwitchException>(() => engine.RollbackAsync(false, default));

        await SwitchToConfirmedAsync(engine, BundleDir());
        var tooEarly = await Assert.ThrowsAsync<SwitchException>(() => engine.FinalizeAsync(false, null, default));
        Assert.Contains("Confirmed", tooEarly.Message);
        await TargetActivation.ActivateAsync(target.Transfer, SystemClock.Instance, default);
        var importActive = await Assert.ThrowsAsync<SwitchException>(() => engine.ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default));
        Assert.Contains("already active", importActive.Message);
    }

    [Fact]
    public async Task Draining_fences_the_source_by_itself_once_the_queue_is_empty()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 2);
        StorageSwitchEngine engine = NewEngine(source, target, activator: new RecordingActivator());
        SwitchStatus started = await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Drain, BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.Equal(SwitchStates.Draining, started.SourceState);
        Assert.Equal(SwitchMode.Drain, started.Mode);

        await Task.Delay(300);
        Assert.Equal(SwitchStates.Draining, (await engine.AdvanceAsync(default)).SourceState); // still queued

        await DeliverEverythingAsync(source.Storage);
        await DeliveryRig.WaitAsync(() => source.Transfer.GetStateAsync(default).AsTask().Result!.State == SwitchStates.Fenced);
        Assert.True(source.Transfer.Gate.IsClosed);
        SwitchStatus advanced = await engine.AdvanceAsync(default);
        Assert.Equal(SwitchStates.Fenced, advanced.SourceState);
    }

    [Fact]
    public async Task A_second_engine_in_another_process_can_continue_the_switch_from_the_stored_states()
    {
        TestStore source = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "source");
        TestStore target = await NewStoreAsync(StoreKind.Sqlite, HistoryMode.Full, "target");
        await Seed.PopulateAsync(source.Storage, source.Protector, queued: 2);
        await NewEngine(source, target).StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = BundleDir(), Passphrase = Pass, QuiesceTimeout = TimeSpan.FromMilliseconds(50) }, null, default);
        await NewEngine(source, null).ExportAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        await NewEngine(null, target).ImportAsync(new ImportRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default);
        Assert.True((await NewEngine(null, target).VerifyAsync(new BundleRequest { BundlePath = BundleDir(), Passphrase = Pass }, null, default)).Ok);
        await NewEngine(null, target).ConfirmAsync(default);
        SwitchStatus status = await NewEngine(source, target).GetStatusAsync(default);
        Assert.Equal(SwitchStates.Fenced, status.SourceState);
        Assert.Equal(SwitchStates.Confirmed, status.TargetState);
        Assert.Equal(SwitchMode.Quiesce, status.Mode);
    }

    private sealed class RecordingHost : ISwitchHostControl
    {
        public bool Accepting { get; private set; } = true;

        public bool DispatchPaused { get; private set; }

        public ValueTask StopAcceptingAsync(CancellationToken cancellationToken)
        {
            Accepting = false;
            return default;
        }

        public ValueTask ResumeAcceptingAsync(CancellationToken cancellationToken)
        {
            Accepting = true;
            return default;
        }

        public ValueTask PauseDispatchAsync(CancellationToken cancellationToken)
        {
            DispatchPaused = true;
            return default;
        }

        public ValueTask ResumeDispatchAsync(CancellationToken cancellationToken)
        {
            DispatchPaused = false;
            return default;
        }

        public ValueTask QuiesceDeliveriesAsync(TimeSpan timeout, CancellationToken cancellationToken) => default;
    }
}
