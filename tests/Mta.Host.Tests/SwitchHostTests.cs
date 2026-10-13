using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Secrets;
using Mta.Host.Switching;
using Mta.Storage;
using Mta.Storage.InMemory;
using Mta.Storage.Portability;
using Mta.Storage.Sqlite;
using Mta.Storage.Transfer;

namespace Mta.Host.Tests;

public class StartupGateTests
{
    private static async Task<InMemoryStorage> StorageAsync()
    {
        var s = new InMemoryStorage(new StorageOptions());
        await s.InitializeAsync(default);
        return s;
    }

    private static readonly Guid SwitchId = Guid.Parse("01900000-0000-7000-8000-0000000000cc");

    private static SwitchStateRecord State(string role, string state) => new(SwitchId, role, state, DateTimeOffset.UtcNow, null);

    [Fact]
    public async Task Without_a_switch_record_or_when_active_the_application_runs_normally()
    {
        await using var storage = await StorageAsync();
        Assert.Equal(StartupMode.Normal, (await StartupGate.EvaluateAsync(storage, SystemClock.Instance, NullMtaLog.Instance, default)).Mode);
        await storage.Transfer!.SetStateAsync(State(SwitchRoles.Source, SwitchStates.Active), default);
        Assert.Equal(StartupMode.Normal, (await StartupGate.EvaluateAsync(storage, SystemClock.Instance, NullMtaLog.Instance, default)).Mode);
        await storage.Transfer.SetStateAsync(State(SwitchRoles.Target, SwitchStates.Active), default);
        Assert.Equal(StartupMode.Normal, (await StartupGate.EvaluateAsync(storage, SystemClock.Instance, NullMtaLog.Instance, default)).Mode);
    }

    [Theory]
    [InlineData(SwitchRoles.Source, SwitchStates.Draining, StartupMode.Draining, false, true)]
    [InlineData(SwitchRoles.Source, SwitchStates.Quiescing, StartupMode.Restricted, false, false)]
    [InlineData(SwitchRoles.Source, SwitchStates.Fenced, StartupMode.Fenced, false, false)]
    [InlineData(SwitchRoles.Source, SwitchStates.Finalized, StartupMode.Fenced, false, false)]
    [InlineData(SwitchRoles.Target, SwitchStates.Importing, StartupMode.Restricted, false, false)]
    [InlineData(SwitchRoles.Target, SwitchStates.Verified, StartupMode.Restricted, false, false)]
    public async Task A_fenced_source_or_an_unactivated_target_refuses_to_accept_and_dispatch_and_names_the_switch(string role, string state, StartupMode mode, bool accept, bool dispatch)
    {
        await using var storage = await StorageAsync();
        await storage.Transfer!.SetStateAsync(State(role, state), default);

        StartupDecision decision = await StartupGate.EvaluateAsync(storage, SystemClock.Instance, NullMtaLog.Instance, default);

        Assert.Equal(mode, decision.Mode);
        Assert.Equal(accept, decision.AcceptMail);
        Assert.Equal(dispatch, decision.Dispatch);
        Assert.Contains(SwitchId.ToString(), decision.Banner);
        Assert.Equal(SwitchId, decision.SwitchId);
    }

    [Fact]
    public async Task A_confirmed_target_becomes_active_atomically_and_its_imported_mail_is_released()
    {
        await using var storage = await StorageAsync();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var delivery = new Mta.Storage.Model.QueuedDeliveryEntity
        {
            Id = Ids.New(), MessageId = Ids.New(), TenantId = Guid.NewGuid(), EnvelopeFrom = "a@example.com", Recipient = "b@example.org", RecipientDomain = "example.org",
            DueAt = now, CreatedAt = now, ExpiresAt = now.AddDays(5), LeaseUntil = DateTimeOffset.UnixEpoch,
        };
        await storage.Transfer!.ApplyChunkAsync(new TransferChunk(SwitchId, TransferTables.Deliveries, "queue/delivery_queue.00001.ndjson", "x", HoldRows: true), [delivery], default);
        await storage.Transfer.SetStateAsync(State(SwitchRoles.Target, SwitchStates.Confirmed), default);
        Assert.Empty(await storage.Deliveries.ClaimAsync("w", 10, now.AddMinutes(1), TimeSpan.FromMinutes(1), default));

        StartupDecision decision = await StartupGate.EvaluateAsync(storage, SystemClock.Instance, NullMtaLog.Instance, default);

        Assert.Equal(StartupMode.Normal, decision.Mode);
        Assert.True(decision.TargetActivated);
        Assert.Equal(SwitchStates.Active, decision.State);
        Assert.Equal(SwitchStates.Active, (await storage.Transfer.GetStateAsync(default))!.State);
        Assert.Single(await storage.Deliveries.ClaimAsync("w", 10, now.AddMinutes(1), TimeSpan.FromMinutes(1), default));

        // The next start finds an active target: nothing more to do.
        Assert.False((await StartupGate.EvaluateAsync(storage, SystemClock.Instance, NullMtaLog.Instance, default)).TargetActivated);
    }
}

public class SwitchActivatorTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-activator-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static StorageOptions Postgres(string runtime) => new() { Backend = StorageBackend.Postgres, Postgres = new PostgresOptions { RuntimeConnectionString = runtime, OwnerConnectionString = runtime + ";owner" } };

    private static StorageOptions Sqlite(string dir) => new() { Sqlite = new SqliteOptions { DataDirectory = dir } };

    private SwitchActivationRequest Request(StorageOptions source, StorageOptions target) =>
        new(Guid.NewGuid(), source, target, EffectiveSettings.Describe(source));

    [Fact]
    public async Task A_bootstrap_managed_pointer_is_written_to_the_bootstrap_file_and_the_old_file_is_kept_for_rollback()
    {
        string bootstrap = Path.Combine(_dir, "bootstrap.json");
        await File.WriteAllTextAsync(bootstrap, "{\"Sqlite\":{\"DataDirectory\":\"/data\"},\"Hostname\":\"mx.example.org\"}");
        IConfigurationRoot root = ConfigLoader.Build([], _dir);
        var activator = new SwitchActivator(root, bootstrap);
        SwitchActivationRequest request = Request(Sqlite("/data"), Postgres("Host=db;Database=egg;Password=hunter2"));

        SwitchActivation result = await activator.ActivateAsync(request, default);

        Assert.Equal(ActivationKind.BootstrapFileWritten, result.Kind);
        Assert.Equal(bootstrap, result.File);
        Assert.Null(result.Patch);
        JsonNode written = JsonNode.Parse(await File.ReadAllTextAsync(bootstrap))!;
        Assert.Equal("Postgres", (string?)written["Storage"]!["Backend"]);
        Assert.Equal("Host=db;Database=egg;Password=hunter2", (string?)written["Storage"]!["Postgres"]!["RuntimeConnectionString"]);
        Assert.Equal("mx.example.org", (string?)written["Hostname"]); // unrelated settings stay
        Assert.Equal("Full", (string?)written["History"]!["Mode"]);

        // The next start reads the new pointer.
        Assert.Equal("Postgres", ConfigLoader.Build([], _dir)["Storage:Backend"]);
        Assert.Equal(bootstrap + ".pre-" + request.SwitchId.ToString("N"), SwitchActivator.PendingOriginalBootstrap(bootstrap));

        await activator.RestoreAsync(request.SwitchId, default);
        Assert.Equal("/data", ConfigLoader.Build([], _dir)["Sqlite:DataDirectory"]);
        Assert.Null(ConfigLoader.Build([], _dir)["Storage:Backend"]);
        Assert.Null(SwitchActivator.PendingOriginalBootstrap(bootstrap));
    }

    [Fact]
    public async Task Without_a_bootstrap_file_rollback_removes_the_one_that_was_written()
    {
        string bootstrap = Path.Combine(_dir, "bootstrap.json");
        var activator = new SwitchActivator(ConfigLoader.Build([], _dir), bootstrap);
        SwitchActivationRequest request = Request(Sqlite(_dir), Sqlite(Path.Combine(_dir, "new")));

        await activator.ActivateAsync(request, default);
        Assert.True(File.Exists(bootstrap));
        Assert.Equal(string.Empty, SwitchActivator.PendingOriginalBootstrap(bootstrap));

        await activator.RestoreAsync(request.SwitchId, default);
        Assert.False(File.Exists(bootstrap));
        Assert.Null(SwitchActivator.PendingOriginalBootstrap(bootstrap));
    }

    [Fact]
    public async Task An_orchestrator_managed_pointer_is_never_rewritten_and_the_patch_prints_no_secret()
    {
        string bootstrap = Path.Combine(_dir, "bootstrap.json");
        IConfigurationRoot root = ConfigLoader.Build(["--Storage:Backend=Sqlite", "--Sqlite:DataDirectory=/data"], _dir);
        var activator = new SwitchActivator(root, bootstrap);
        SwitchActivationRequest request = Request(Sqlite("/data"), Postgres("Host=db;Database=egg;Password=hunter2"));

        SwitchActivation result = await activator.ActivateAsync(request, default);

        Assert.Equal(ActivationKind.CutoverPatch, result.Kind);
        Assert.False(File.Exists(bootstrap)); // not touched
        Assert.NotNull(result.Patch);
        Assert.DoesNotContain("hunter2", result.Patch);
        Assert.DoesNotContain("Host=db", result.Patch);
        Assert.Contains("Storage__Backend=Postgres", result.Patch);
        Assert.Contains("was: Sqlite", result.Patch);
        Assert.Contains("Storage__Postgres__RuntimeConnectionString", result.Patch);
        Assert.Contains("secretKeyRef", result.Patch);
        Assert.Contains("kubectl patch configmap", result.Patch);
        Assert.Contains("docker-compose.override.yml", result.Patch);
        Assert.Contains("the command line", result.Summary);
    }

    [Fact]
    public async Task Carried_settings_keep_the_behavior_unchanged()
    {
        string bootstrap = Path.Combine(_dir, "bootstrap.json");
        var source = new StorageOptions { Retention = new RetentionOptions { MetadataDays = 14 }, Sqlite = new SqliteOptions { DataDirectory = _dir } };
        var activator = new SwitchActivator(ConfigLoader.Build([], _dir), bootstrap);
        await activator.ActivateAsync(Request(source, Postgres("Host=db")), default);
        JsonNode written = JsonNode.Parse(await File.ReadAllTextAsync(bootstrap))!;
        Assert.Equal("14", (string?)written["Retention"]!["MetadataDays"]);
        Assert.Null(written["Stats"]); // defaults are not repeated
    }

    [Fact]
    public async Task Pending_activation_markers_are_found_and_forgotten()
    {
        string bootstrap = Path.Combine(_dir, "bootstrap.json");
        Guid id = Guid.NewGuid();
        File.WriteAllText(bootstrap + ".pre-" + id.ToString("N"), "{}");
        Assert.NotNull(SwitchActivator.PendingOriginalBootstrap(bootstrap));
        await new SwitchActivator(ConfigLoader.Build([], _dir), bootstrap).ForgetAsync(id, default);
        Assert.Null(SwitchActivator.PendingOriginalBootstrap(bootstrap));
    }
}

public class DataDirectoryLockTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-lock-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void Only_one_owner_at_a_time()
    {
        using (DataDirectoryLock.Acquire(_dir))
        {
            var ex = Assert.Throws<IOException>(() => DataDirectoryLock.Acquire(_dir));
            Assert.Contains("Another process is using the data directory", ex.Message);
        }

        using (DataDirectoryLock.Acquire(_dir))
        {
        }
    }
}

/// <summary>The <c>mta migrate-storage</c> command end to end over two SQLite directories.</summary>
[Collection("CpuHeavy")]
public class MigrateStorageCommandTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("eggmail-cli-").FullName;
    private string Source => Path.Combine(_root, "source");
    private string Target => Path.Combine(_root, "target");
    private string Bundle => Path.Combine(_root, "bundle");
    private string Bootstrap => Path.Combine(_root, "bootstrap.json");
    private string PassphraseFile => Path.Combine(_root, "passphrase.txt");

    public MigrateStorageCommandTests()
    {
        File.WriteAllText(PassphraseFile, "correct horse battery staple\n");
        File.WriteAllText(Bootstrap, JsonNode.Parse("{}")!.ToJsonString());
        var bootstrap = new JsonObject { ["Sqlite"] = new JsonObject { ["DataDirectory"] = Source } };
        File.WriteAllText(Bootstrap, bootstrap.ToJsonString());
    }

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private async Task SeedSourceAsync()
    {
        var storage = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = Source, StatsFlushInterval = TimeSpan.Zero } });
        await storage.InitializeAsync(default);
        var secrets = SecretsFactory.Create(new SecretsSection(), storage.Config);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Guid tenant = Ids.New();
        Guid domain = Ids.New();
        await storage.Config.UpsertTenantAsync(new Tenant(tenant, "Acme", "acme", true, now, false), default);
        await storage.Config.UpsertDomainAsync(new DomainRecord(domain, tenant, "example.com", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        await storage.Config.AddDkimKeyAsync(new DkimKeyRecord(Ids.New(), domain, "egg1", secrets.Protect("dkim-private-key"u8, SecretPurposes.DkimKey), "PUB", now, true, null), default);
        for (int i = 0; i < 3; i++)
        {
            await storage.Intake.AcceptAsync(new AcceptedMessage
            {
                MessageId = Ids.New(now), TenantId = tenant, Source = MessageSource.Api, EnvelopeFrom = EmailAddress.Parse("a@example.com"),
                Recipients = [new AcceptedRecipient(Ids.New(now), EmailAddress.Parse($"r{i}@example.org"))],
                Raw = System.Text.Encoding.ASCII.GetBytes($"Subject: {i}\r\n\r\nbody {i}\r\n"), ReceivedAt = now, ExpiresAt = now.AddDays(5), Content = new MessageContent("s", "t", null, [], false),
            }, default);
        }

        await storage.DisposeAsync();
    }

    private async Task<(int Code, string Out, string Err)> RunAsync(params string[] args)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        int code = await MigrateStorageCommand.RunAsync(args, o, e, name => name == "EGGMAIL_TEST_PASS" ? "correct horse battery staple" : null);
        return (code, o.ToString(), e.ToString());
    }

    private string[] ToTarget(params string[] more) => ["--to", "sqlite", "--target-dir", Target, "--bootstrap-file", Bootstrap, .. more];

    [Fact]
    public async Task The_whole_flow_runs_from_the_command_line_and_the_target_starts_active()
    {
        await SeedSourceAsync();

        // Preflight refuses the default Secrets:KeyProtection=None target until it is acknowledged.
        var pre = await RunAsync(["preflight", .. ToTarget("--bundle", Bundle)]);
        Assert.Equal(MigrateStorageCommand.Refused, pre.Code);
        Assert.Contains("key-protection", pre.Out);

        // A dry run changes nothing.
        var dry = await RunAsync(["export", .. ToTarget("--bundle", Bundle, "--quiesce", "--dry-run", "--accept-unprotected-keys")]);
        Assert.Equal(0, dry.Code);
        Assert.Contains("Dry run", dry.Out);
        Assert.False(Directory.Exists(Bundle));

        var export = await RunAsync(["export", .. ToTarget("--bundle", Bundle, "--quiesce", "--passphrase-file", PassphraseFile, "--accept-unprotected-keys")]);
        Assert.True(export.Code == 0, export.Out + export.Err);
        Assert.Contains("fenced", export.Out);
        Assert.True(File.Exists(Path.Combine(Bundle, "manifest.json")));

        var import = await RunAsync(["import", .. ToTarget("--bundle", Bundle, "--passphrase-env", "EGGMAIL_TEST_PASS", "--accept-unprotected-keys")]);
        Assert.True(import.Code == 0, import.Out + import.Err);

        var verify = await RunAsync(["verify", .. ToTarget("--bundle", Bundle, "--passphrase-file", PassphraseFile)]);
        Assert.True(verify.Code == 0, verify.Out + verify.Err);
        Assert.Contains("Verified", verify.Out);

        var confirm = await RunAsync(["confirm", .. ToTarget()]);
        Assert.True(confirm.Code == 0, confirm.Out + confirm.Err);

        var activate = await RunAsync(["activate", .. ToTarget()]);
        Assert.True(activate.Code == 0, activate.Out + activate.Err);
        Assert.Contains("bootstrap file", activate.Out);
        Assert.Equal(Target, (string?)JsonNode.Parse(File.ReadAllText(Bootstrap))!["Sqlite"]!["DataDirectory"]);

        var status = await RunAsync(["status", .. ToTarget()]);
        Assert.Contains("Target: Confirmed", status.Out);

        // The application starts with the rewritten pointer: the startup gate activates the target.
        var config = ConfigLoader.Load(ConfigLoader.Build([], _root));
        Assert.True(config.IsValid);
        Assert.Equal(Target, config.Config.Storage.Sqlite.DataDirectory);
        var started = StorageFactory.Create(config.Config.Storage, SystemClock.Instance, NullMtaLog.Instance);
        await started.InitializeAsync(default);
        StartupDecision decision = await StartupGate.EvaluateAsync(started, SystemClock.Instance, NullMtaLog.Instance, default);
        Assert.True(decision.TargetActivated);
        Assert.Equal(3, (await started.Deliveries.ClaimAsync("w", 10, DateTimeOffset.UtcNow.AddMinutes(1), TimeSpan.FromMinutes(1), default)).Count);
        var protector = SecretsFactory.Create(new SecretsSection(), started.Config);
        var keys = await started.Config.GetDkimKeysAsync((await started.Config.GetDomainsAsync(null, default))[0].Id, default);
        Assert.Equal("dkim-private-key"u8.ToArray(), protector.Unprotect(keys[0].PrivateKeyProtected, SecretPurposes.DkimKey));
        await started.DisposeAsync();

        // The source stays fenced and untouched until finalized; the pointer of the old configuration is read for that.
        var finalize = await RunAsync(["finalize", .. ToTarget("--delete-bundle")]);
        Assert.True(finalize.Code == 0, finalize.Out + finalize.Err);
        Assert.False(Directory.Exists(Bundle));
        Assert.Null(SwitchActivator.PendingOriginalBootstrap(Bootstrap));
        var source = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = Source } });
        await source.InitializeAsync(default);
        Assert.Equal(SwitchStates.Finalized, (await source.Transfer.GetStateAsync(default))!.State);
        await source.DisposeAsync();
    }

    [Fact]
    public async Task Rollback_before_the_target_started_restores_the_pointer_and_resumes_the_source()
    {
        await SeedSourceAsync();
        Assert.Equal(0, (await RunAsync(["export", .. ToTarget("--bundle", Bundle, "--quiesce", "--passphrase-file", PassphraseFile, "--accept-unprotected-keys")])).Code);
        Assert.Equal(0, (await RunAsync(["import", .. ToTarget("--bundle", Bundle, "--passphrase-file", PassphraseFile, "--accept-unprotected-keys")])).Code);
        Assert.Equal(0, (await RunAsync(["verify", .. ToTarget("--bundle", Bundle, "--passphrase-file", PassphraseFile)])).Code);
        Assert.Equal(0, (await RunAsync(["confirm", .. ToTarget()])).Code);
        Assert.Equal(0, (await RunAsync(["activate", .. ToTarget()])).Code);

        var rollback = await RunAsync(["rollback", .. ToTarget()]);
        Assert.True(rollback.Code == 0, rollback.Out + rollback.Err);

        Assert.Equal(Source, (string?)JsonNode.Parse(File.ReadAllText(Bootstrap))!["Sqlite"]!["DataDirectory"]);
        var source = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = Source } });
        await source.InitializeAsync(default);
        Assert.False(source.Transfer.Gate.IsClosed);
        Assert.Equal(3, (await source.Deliveries.ClaimAsync("w", 10, DateTimeOffset.UtcNow.AddMinutes(1), TimeSpan.FromMinutes(1), default)).Count);
        await source.DisposeAsync();
    }

    [Fact]
    public async Task A_passphrase_on_the_command_line_is_refused_and_a_missing_one_is_a_usage_error()
    {
        await SeedSourceAsync();
        var onCommandLine = await RunAsync(["export", .. ToTarget("--bundle", Bundle, "--passphrase", "hunter2hunter2")]);
        Assert.Equal(MigrateStorageCommand.UsageError, onCommandLine.Code);
        Assert.Contains("never accepted on the command line", onCommandLine.Err);

        var missing = await RunAsync(["export", .. ToTarget("--bundle", Bundle, "--quiesce", "--accept-unprotected-keys")]);
        Assert.Equal(MigrateStorageCommand.UsageError, missing.Code);
        Assert.Contains("EGGMAIL_BUNDLE_PASSPHRASE", missing.Err);
        Assert.False(Directory.Exists(Bundle));
    }

    [Fact]
    public async Task A_data_directory_in_use_by_a_running_server_is_refused()
    {
        await SeedSourceAsync();
        using var running = DataDirectoryLock.Acquire(Source);
        var result = await RunAsync(["export", .. ToTarget("--bundle", Bundle, "--quiesce", "--passphrase-file", PassphraseFile, "--accept-unprotected-keys")]);
        Assert.Equal(MigrateStorageCommand.Refused, result.Code);
        Assert.Contains("Another process is using the data directory", result.Err);
    }

    [Fact]
    public async Task A_drain_with_mail_in_the_queue_waits_for_the_application_and_a_tampered_bundle_is_reported()
    {
        await SeedSourceAsync();
        var drain = await RunAsync(["export", .. ToTarget("--bundle", Bundle, "--drain", "--passphrase-file", PassphraseFile, "--accept-unprotected-keys")]);
        Assert.Equal(MigrateStorageCommand.NotReady, drain.Code);
        Assert.Contains("draining", drain.Out);
        Assert.False(Directory.Exists(Bundle));

        // Quiesce instead (rolls into the same switch? no: the switch is draining; roll it back first).
        var rollback = await RunAsync(["rollback", .. ToTarget("--source-only")]);
        Assert.True(rollback.Code == 0, rollback.Out + rollback.Err);
        Assert.Equal(0, (await RunAsync(["export", .. ToTarget("--bundle", Bundle, "--quiesce", "--passphrase-file", PassphraseFile, "--accept-unprotected-keys")])).Code);
        File.AppendAllText(Path.Combine(Bundle, "config", "tenant.00001.ndjson"), " ");
        var import = await RunAsync(["import", .. ToTarget("--bundle", Bundle, "--passphrase-file", PassphraseFile, "--accept-unprotected-keys")]);
        Assert.Equal(MigrateStorageCommand.IntegrityFailure, import.Code);
        Assert.Contains("differs from the manifest", import.Err);
    }

    [Fact]
    public async Task Usage_errors_have_their_own_exit_code()
    {
        Assert.Equal(MigrateStorageCommand.UsageError, (await RunAsync(["bogus"])).Code);
        Assert.Equal(MigrateStorageCommand.UsageError, (await RunAsync(["export", "--nonsense"])).Code);
        Assert.Equal(MigrateStorageCommand.UsageError, (await RunAsync(["export", "--to", "mysql", "--bootstrap-file", Bootstrap])).Code);
        Assert.Equal(0, (await RunAsync(["--help"])).Code);
    }
}
