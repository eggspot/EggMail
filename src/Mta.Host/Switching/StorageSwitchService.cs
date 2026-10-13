using Microsoft.Extensions.Configuration;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Secrets;
using Mta.Storage;
using Mta.Storage.Portability;
using Mta.Storage.Transfer;
using ApiProgress = Mta.Host.Api.SwitchProgress;
using EngineProgress = Mta.Storage.Portability.SwitchProgress;

namespace Mta.Host.Switching;

/// <summary>The store a switch moves to: its storage options and how it protects secrets.</summary>
public sealed record ResolvedSwitchTarget(StorageOptions Storage, SecretsSection Secrets);

/// <summary>Turns the target of an API request into storage options. Deployment configuration decides what is reachable; the API never carries secrets.</summary>
public interface ISwitchTargetResolver
{
    /// <summary>Throws <see cref="StorageSwitchException"/> (<see cref="StorageSwitchError.Invalid"/>) when the target cannot be described.</summary>
    ResolvedSwitchTarget Resolve(SwitchRequestModel request);

    /// <summary>The store the running instance was switched away from (after a restart on the target), or null when it is not described.</summary>
    ResolvedSwitchTarget? ResolveFormerSource(StorageBackend formerBackend);
}

/// <summary>
/// Resolves targets from the deployment configuration: the settings under <c>SwitchTarget:</c> (and <c>SwitchSource:</c> for the former
/// source) overlay the instance's own configuration. A PostgreSQL target is a named connection (<c>SwitchTarget:Connections:&lt;name&gt;</c>)
/// or host, port and database applied to the connection string in <c>SwitchTarget:Storage:Postgres:RuntimeConnectionString</c> (which carries
/// the credentials); a SQLite target is a data directory.
/// </summary>
public sealed class ConfiguredSwitchTargetResolver(IConfiguration main) : ISwitchTargetResolver
{
    public ResolvedSwitchTarget Resolve(SwitchRequestModel request)
    {
        if (!SwitchTargetConfiguration.TryParseBackend(request.To, out StorageBackend backend))
        {
            throw new StorageSwitchException(StorageSwitchError.Invalid, "Unknown target backend.", "to");
        }

        SwitchTargetModel target = request.Target ?? throw new StorageSwitchException(StorageSwitchError.Invalid, "Required.", "target");
        IConfiguration overlay = SwitchTargetConfiguration.Build(main, backend, backend == StorageBackend.Sqlite ? target.Path : null);
        var values = new Dictionary<string, string?>();
        if (backend == StorageBackend.Postgres)
        {
            string? connection;
            if (!string.IsNullOrWhiteSpace(target.ConnectionName))
            {
                connection = main[$"SwitchTarget:Connections:{target.ConnectionName}"];
                if (string.IsNullOrWhiteSpace(connection))
                {
                    throw new StorageSwitchException(StorageSwitchError.Invalid, $"No connection named '{target.ConnectionName}' is configured (SwitchTarget:Connections:{target.ConnectionName}).", "target.connectionName");
                }
            }
            else
            {
                var builder = new Npgsql.NpgsqlConnectionStringBuilder(overlay["Storage:Postgres:RuntimeConnectionString"] ?? string.Empty) { Host = target.Host };
                if (target.Port is { } port)
                {
                    builder.Port = port;
                }

                builder.Database = target.Database;
                connection = builder.ConnectionString;
            }

            values["Storage:Postgres:RuntimeConnectionString"] = connection;
        }

        return Load(Overlay(overlay, values));
    }

    public ResolvedSwitchTarget? ResolveFormerSource(StorageBackend formerBackend)
    {
        if (!main.GetSection("SwitchSource").GetChildren().Any())
        {
            return null;
        }

        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (KeyValuePair<string, string?> kv in main.AsEnumerable())
        {
            if (kv.Value is not null && !kv.Key.StartsWith(SwitchTargetConfiguration.Prefix, StringComparison.OrdinalIgnoreCase) && !kv.Key.StartsWith("SwitchSource:", StringComparison.OrdinalIgnoreCase))
            {
                values[kv.Key] = kv.Value;
            }
        }

        foreach (KeyValuePair<string, string?> kv in main.AsEnumerable())
        {
            if (kv.Value is not null && kv.Key.StartsWith("SwitchSource:", StringComparison.OrdinalIgnoreCase))
            {
                values[kv.Key["SwitchSource:".Length..]] = kv.Value;
            }
        }

        values["Storage:Backend"] = formerBackend.ToString();
        return Load(new ConfigurationBuilder().AddInMemoryCollection(values).Build());
    }

    private static IConfiguration Overlay(IConfiguration configuration, Dictionary<string, string?> values)
    {
        var all = configuration.AsEnumerable().Where(kv => kv.Value is not null).ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase);
        foreach (KeyValuePair<string, string?> kv in values)
        {
            all[kv.Key] = kv.Value;
        }

        return new ConfigurationBuilder().AddInMemoryCollection(all).Build();
    }

    private static ResolvedSwitchTarget Load(IConfiguration configuration)
    {
        LoadedConfig loaded = ConfigLoader.Load(configuration);
        if (!loaded.IsValid)
        {
            throw new StorageSwitchException(StorageSwitchError.Invalid, "The target configuration is invalid: " + string.Join(" ", loaded.Errors), "target");
        }

        return new ResolvedSwitchTarget(loaded.Config.Storage, loaded.Config.Secrets);
    }
}

/// <summary>Options of the API-side switch service.</summary>
public sealed class StorageSwitchServiceOptions
{
    /// <summary>Where bundles are written (a directory per switch). Defaults to a folder in the temp directory; deployments should point it at a volume with space.</summary>
    public string? BundleDirectory { get; init; }

    /// <summary>Whether the instance protects its Data Protection key ring (<c>Secrets:KeyProtection</c> is not <c>None</c>). A target without protection is only accepted when this is false too.</summary>
    public bool SourceKeysProtectedAtRest { get; init; } = true;

    public TimeSpan QuiesceTimeout { get; init; } = TimeSpan.FromSeconds(30);

    public TimeSpan DrainPollInterval { get; init; } = TimeSpan.FromSeconds(1);
}

/// <summary>
/// <see cref="IStorageSwitchService"/> over <see cref="IStorageSwitchEngine"/> (design §4.6): the admin API starts a switch for the storage this
/// process runs on. <c>start</c> returns at once; a background job quiesces or drains, exports, imports and verifies, and the status reports its
/// progress. The export passphrase lives in memory for the duration of that job only. <c>confirm</c>, <c>activate</c>, <c>rollback</c> and
/// <c>finalize</c> are single engine steps. The persisted switch states in the stores are the truth; this service only keeps the handle to the
/// target it opened and the report of the last verification.
/// </summary>
public sealed class StorageSwitchService(
    IStorage storage,
    StorageOptions storageOptions,
    ISecretProtector secrets,
    IClock clock,
    ISwitchTargetResolver resolver,
    ISwitchActivator? activator = null,
    ISwitchHostControl? host = null,
    StorageSwitchServiceOptions? options = null) : IStorageSwitchService, IAsyncDisposable
{
    private readonly StorageSwitchServiceOptions _options = options ?? new StorageSwitchServiceOptions();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Session? _session;

    private sealed class Session
    {
        public required Guid Id { get; init; }
        public required string To { get; init; }
        public required SwitchMode Mode { get; init; }
        public required List<string> Include { get; init; }
        public required DateTimeOffset StartedAt { get; init; }
        public required IStorage Target { get; init; }
        public required StorageSwitchEngine Engine { get; init; }
        public required string BundleDirectory { get; init; }
        public required CancellationTokenSource Cancel { get; init; }
        public Task Job { get; set; } = Task.CompletedTask;
        public string Phase { get; set; } = "starting";
        public EngineProgress? Progress { get; set; }
        public VerifyReport? Verify { get; set; }
        public DateTimeOffset? VerifiedAt { get; set; }
        public SwitchActivation? Activation { get; set; }
        public string? Error { get; set; }
        public string? Terminal { get; set; }
        public DateTimeOffset UpdatedAt { get; set; }
    }

    private static StorageSwitchException NotReady(string message) => new(StorageSwitchError.NotReady, message);

    private static StorageSwitchException Conflict(string message) => new(StorageSwitchError.InvalidState, message);

    private async Task<(IStorage Storage, StorageSwitchEngine Engine, ResolvedSwitchTarget Resolved)> OpenTargetAsync(SwitchRequestModel request, CancellationToken ct)
    {
        ResolvedSwitchTarget target = resolver.Resolve(request);
        IStorage targetStorage;
        try
        {
            targetStorage = StorageFactory.Create(target.Storage, clock, NullMtaLog.Instance);
            await targetStorage.InitializeAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not StorageSwitchException)
        {
            throw NotReady("The target storage cannot be opened: " + ex.Message);
        }

        try
        {
            bool targetProtected = target.Secrets.KeyProtection != KeyProtectionMode.None;
            var targetEndpoint = new SwitchEndpoint
            {
                Storage = targetStorage,
                Secrets = SecretsFactory.Create(target.Secrets, targetStorage.Config),
                Options = target.Storage,
                KeysProtectedAtRest = targetProtected,
            };
            var engine = new StorageSwitchEngine(SourceEndpoint(), targetEndpoint, host, activator, clock, NullMtaLog.Instance,
                new SwitchOptions { DrainPollInterval = _options.DrainPollInterval });
            return (targetStorage, engine, target);
        }
        catch
        {
            await targetStorage.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private SwitchEndpoint SourceEndpoint() => new() { Storage = storage, Secrets = secrets, Options = storageOptions, KeysProtectedAtRest = _options.SourceKeysProtectedAtRest };

    private SwitchRequest EngineRequest(SwitchRequestModel model, string? bundle, string? passphrase) => new()
    {
        Mode = model.Mode == "quiesce" ? SwitchMode.Quiesce : SwitchMode.Drain,
        QuiesceTimeout = _options.QuiesceTimeout,
        SkipHistory = model.Include is null || !model.Include.Contains("history"),
        BundlePath = bundle,
        Passphrase = passphrase,
        // A target that does not protect its key ring is accepted only when this instance does not either: nothing gets weaker.
        AcceptUnprotectedTarget = !_options.SourceKeysProtectedAtRest,
    };

    private string BundleDirectoryFor(Guid id) =>
        Path.Combine(_options.BundleDirectory ?? Path.Combine(storageOptions.Backend == StorageBackend.Sqlite ? storageOptions.Sqlite.DataDirectory : Path.GetTempPath(), "switch"), id.ToString("N"));

    public async ValueTask<SwitchPreflightReport> PreflightAsync(SwitchRequestModel request, CancellationToken cancellationToken)
    {
        if (storage.Transfer is null)
        {
            throw NotReady("This storage backend does not support switching yet.");
        }

        (IStorage target, StorageSwitchEngine engine, ResolvedSwitchTarget resolved) = await OpenTargetAsync(request, cancellationToken).ConfigureAwait(false);
        try
        {
            PreflightReport report = await engine.PreflightAsync(EngineRequest(request, Path.Combine(BundleDirectoryFor(Guid.NewGuid()), "preflight"), null), cancellationToken).ConfigureAwait(false);
            long Sum(IEnumerable<string> tables) => tables.Sum(t => report.SourceRows.GetValueOrDefault(t));
            IEnumerable<string> history = TransferTables.Of(TransferPart.History).Select(t => t.Name);
            IEnumerable<string> stats = TransferTables.Of(TransferPart.Stats).Select(t => t.Name);
            long bytes = report.SourceRows.Values.Sum() * 400 + report.SpoolBytes;
            return new SwitchPreflightReport(
                report.CanProceed,
                report.Checks.Select(c => new PreflightCheckModel(c.Name, c.Status != CheckStatus.Error, c.Message, c.Status switch { CheckStatus.Ok => "info", CheckStatus.Warning => "warning", _ => "error" })).ToList(),
                new PreflightCountsModel(Sum(["delivery_queue"]), Sum(history), 0, Sum(stats)),
                new PreflightEstimateModel(null, bytes, Unverified: true),
                report.WillNotCarryOver,
                OrchestratorManaged: activator is SwitchActivator a && SwitchActivator.PointerFor(resolved.Storage).Any(p => a.DeploymentSupplier(p.Key) is not null));
        }
        finally
        {
            await target.DisposeAsync().ConfigureAwait(false);
        }
    }

    public async ValueTask<SwitchStatusReport> StartAsync(SwitchStartModel request, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_session is { Terminal: null })
            {
                throw Conflict("A backend switch is already in progress; finish or roll it back first.");
            }

            if (storage.Transfer is null)
            {
                throw NotReady("This storage backend does not support switching yet.");
            }

            (IStorage target, StorageSwitchEngine engine, _) = await OpenTargetAsync(request, cancellationToken).ConfigureAwait(false);
            Guid id = Ids.New(clock.UtcNow);
            string bundle = BundleDirectoryFor(id);
            SwitchRequest engineRequest = EngineRequest(request, bundle, request.ExportPassphrase);
            PreflightReport pre = await engine.PreflightAsync(engineRequest, cancellationToken).ConfigureAwait(false);
            if (!pre.CanProceed)
            {
                await target.DisposeAsync().ConfigureAwait(false);
                throw new StorageSwitchException(StorageSwitchError.Invalid, "Preflight failed: " + string.Join(" ", pre.Errors.Select(e => e.Message)), "target");
            }

            var session = new Session
            {
                Id = id,
                To = request.To!,
                Mode = engineRequest.Mode,
                Include = request.Include ?? [],
                StartedAt = clock.UtcNow,
                UpdatedAt = clock.UtcNow,
                Target = target,
                Engine = engine,
                BundleDirectory = bundle,
                Cancel = new CancellationTokenSource(),
                Phase = engineRequest.Mode == SwitchMode.Quiesce ? "quiescing" : "draining",
            };
            _session = session;
            string passphrase = request.ExportPassphrase!;
            bool history = request.Include?.Contains("history") == true;
            session.Job = Task.Run(() => RunJobAsync(session, engineRequest, passphrase, history));
            return Report(session, null);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task RunJobAsync(Session s, SwitchRequest request, string passphrase, bool history)
    {
        CancellationToken ct = s.Cancel.Token;
        var progress = new Progress<EngineProgress>(p =>
        {
            s.Progress = p;
            s.UpdatedAt = clock.UtcNow;
        });
        try
        {
            SwitchStatus started = await s.Engine.StartAsync(request, progress, ct).ConfigureAwait(false);
            while (started.SourceState == SwitchStates.Draining)
            {
                await Task.Delay(_options.DrainPollInterval, ct).ConfigureAwait(false);
                started = await s.Engine.AdvanceAsync(ct).ConfigureAwait(false);
            }

            s.Phase = "exporting";
            await s.Engine.ExportAsync(new BundleRequest { BundlePath = s.BundleDirectory, Passphrase = passphrase, SkipHistory = !history }, progress, ct).ConfigureAwait(false);
            s.Phase = "importing";
            await s.Engine.ImportAsync(new ImportRequest { BundlePath = s.BundleDirectory, Passphrase = passphrase, Scope = history ? ImportScope.All : ImportScope.Core, AcceptUnprotectedTarget = request.AcceptUnprotectedTarget }, progress, ct).ConfigureAwait(false);
            s.Phase = "verifying";
            VerifyReport verify = await s.Engine.VerifyAsync(new BundleRequest { BundlePath = s.BundleDirectory, Passphrase = passphrase }, progress, ct).ConfigureAwait(false);
            s.Verify = verify;
            s.VerifiedAt = clock.UtcNow;
            if (!verify.Ok)
            {
                s.Error = "Verification found problems: " + string.Join("; ", verify.Problems.Take(5));
                s.Phase = "failed";
            }
            else
            {
                s.Phase = "verified";
            }
        }
        catch (OperationCanceledException)
        {
            s.Phase = "failed";
            s.Error ??= "The switch was cancelled.";
        }
        catch (Exception ex)
        {
            s.Phase = "failed";
            s.Error = ex.Message;
        }
        finally
        {
            s.UpdatedAt = clock.UtcNow;
        }
    }

    public async ValueTask<SwitchStatusReport> GetStatusAsync(CancellationToken cancellationToken)
    {
        if (_session is { } s)
        {
            return Report(s, await PersistedAsync(cancellationToken).ConfigureAwait(false));
        }

        SwitchStateRecord? record = await PersistedAsync(cancellationToken).ConfigureAwait(false);
        return record is null || record.State == SwitchStates.Active && record.Role == SwitchRoles.Source
            ? new SwitchStatusReport("none")
            : FromRecord(record);
    }

    private async Task<SwitchStateRecord?> PersistedAsync(CancellationToken ct) => storage.Transfer is null ? null : await storage.Transfer.GetStateAsync(ct).ConfigureAwait(false);

    private SwitchStatusReport FromRecord(SwitchStateRecord r) => new(
        (r.Role, r.State) switch
        {
            (SwitchRoles.Source, SwitchStates.Draining) => "draining",
            (SwitchRoles.Source, SwitchStates.Quiescing) => "quiescing",
            (SwitchRoles.Source, SwitchStates.Fenced) => "fenced",
            (SwitchRoles.Source, SwitchStates.Finalized) => "finalized",
            (SwitchRoles.Target, SwitchStates.Importing) => "importing",
            (SwitchRoles.Target, SwitchStates.Verified) => "verified",
            (SwitchRoles.Target, SwitchStates.Confirmed) => "confirmed",
            (SwitchRoles.Target, SwitchStates.Active) => "active",
            _ => "none",
        },
        r.SwitchId,
        UpdatedAt: r.UpdatedAt,
        OrchestratorManaged: false);

    private SwitchStatusReport Report(Session s, SwitchStateRecord? local)
    {
        string state = s.Terminal ?? s.Phase;
        if (s.Terminal is null && s.Phase == "verified")
        {
            state = s.Activation is not null ? "active" : "verified";
        }

        ApiProgress? progress = s.Progress is { } p
            ? new ApiProgress(s.Phase, p.Total > 0 ? (int)Math.Clamp(p.Done * 100 / p.Total, 0, 100) : 0, p.Total > 0 ? p.Done : null, p.Total > 0 ? p.Total : null)
            : null;
        SwitchVerifyReport? verify = s.Verify is { } v
            ? new SwitchVerifyReport(v.Ok, v.Tables.Select(t => new SwitchVerifyTable(t.Table, t.ExpectedRows, t.ActualRows)).ToList(), v.Tables.All(t => t.ChecksumMatches && t.SecretsMatch != false), s.VerifiedAt)
            : null;
        SwitchCutoverPatch? patch = s.Activation is { } a ? new SwitchCutoverPatch(a.Kind == ActivationKind.CutoverPatch ? "patch" : "bootstrap", a.Patch ?? a.Summary) : null;
        _ = local;
        return new SwitchStatusReport(
            state, s.Id, new SwitchDirection(ApiMap.Backend(storage.Backend), s.To), s.Mode == SwitchMode.Quiesce ? "quiesce" : "drain", s.Include, progress, verify, patch,
            s.Activation?.Kind == ActivationKind.CutoverPatch, s.StartedAt, s.UpdatedAt, s.Error);
    }

    private Session RequireIdle(string step)
    {
        Session s = _session ?? throw Conflict($"Cannot {step}: no backend switch is in progress on this instance.");
        if (s.Terminal is not null)
        {
            throw Conflict($"Cannot {step}: the switch is {s.Terminal}.");
        }

        if (!s.Job.IsCompleted)
        {
            throw Conflict($"Cannot {step}: the switch is still {s.Phase}.");
        }

        return s;
    }

    private async ValueTask<SwitchStatusReport> StepAsync(string step, Func<Session, CancellationToken, Task> action, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Session s = RequireIdle(step);
            try
            {
                await action(s, ct).ConfigureAwait(false);
            }
            catch (SwitchException ex)
            {
                throw Conflict(ex.Message);
            }

            s.UpdatedAt = clock.UtcNow;
            return Report(s, null);
        }
        finally
        {
            _gate.Release();
        }
    }

    public ValueTask<SwitchStatusReport> ConfirmAsync(CancellationToken cancellationToken) =>
        StepAsync("confirm", async (s, ct) =>
        {
            if (s.Phase != "verified")
            {
                throw Conflict($"Cannot confirm: the switch is {s.Phase}, not verified.");
            }

            await s.Engine.ConfirmAsync(ct).ConfigureAwait(false);
            s.Phase = "confirmed";
        }, cancellationToken);

    public ValueTask<SwitchStatusReport> ActivateAsync(CancellationToken cancellationToken) =>
        StepAsync("activate", async (s, ct) =>
        {
            if (s.Phase != "confirmed")
            {
                throw Conflict($"Cannot activate: the switch is {s.Phase}, not confirmed.");
            }

            if (activator is null)
            {
                throw NotReady("Activation is not available on this instance.");
            }

            s.Activation = await s.Engine.ActivateAsync(ct).ConfigureAwait(false);
            s.Phase = "verified"; // reported as "active" through the activation (the target becomes Active when the application restarts)
        }, cancellationToken);

    public async ValueTask<SwitchStatusReport> RollbackAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Session s = _session ?? throw Conflict("Cannot roll back: no backend switch is in progress on this instance. After a restart use 'mta migrate-storage rollback'.");
            if (s.Terminal is not null)
            {
                throw Conflict($"Cannot roll back: the switch is {s.Terminal}.");
            }

            if (!s.Job.IsCompleted)
            {
                s.Cancel.Cancel();
                s.Engine.Cancel();
                try
                {
                    await s.Job.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
            }

            try
            {
                await s.Engine.RollbackAsync(sourceOnly: false, cancellationToken).ConfigureAwait(false);
            }
            catch (SwitchException ex)
            {
                throw Conflict(ex.Message);
            }

            s.Terminal = "rolled_back";
            s.Error = null;
            s.UpdatedAt = clock.UtcNow;
            await s.Target.DisposeAsync().ConfigureAwait(false);
            return Report(s, null);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<SwitchStatusReport> FinalizeAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_session is { Terminal: null } s)
            {
                // Still the old instance: the target only becomes Active when the application runs on it.
                throw Conflict($"Cannot finalize: the switch is {s.Phase}; finalize is only possible once the application runs on the new backend and the target is active.");
            }

            SwitchStateRecord? local = await PersistedAsync(cancellationToken).ConfigureAwait(false);
            if (local is not { Role: SwitchRoles.Target, State: SwitchStates.Active })
            {
                throw Conflict("Cannot finalize: this instance is not running on the target of a completed switch.");
            }

            StorageBackend former = storage.Backend == StorageBackend.Postgres ? StorageBackend.Sqlite : StorageBackend.Postgres;
            ResolvedSwitchTarget? old = resolver.ResolveFormerSource(former);
            if (old is null)
            {
                throw NotReady("The former source is not described (SwitchSource:*). Finalize with 'mta migrate-storage finalize' instead.");
            }

            IStorage oldStorage;
            try
            {
                oldStorage = StorageFactory.Create(old.Storage, clock, NullMtaLog.Instance);
                await oldStorage.InitializeAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                throw NotReady("The former source cannot be opened: " + ex.Message);
            }

            try
            {
                var engine = new StorageSwitchEngine(
                    new SwitchEndpoint { Storage = oldStorage, Secrets = SecretsFactory.Create(old.Secrets, oldStorage.Config), Options = old.Storage },
                    SourceEndpoint(), host, activator, clock, NullMtaLog.Instance);
                try
                {
                    SwitchStatus status = await engine.FinalizeAsync(deleteBundle: false, null, cancellationToken).ConfigureAwait(false);
                    return new SwitchStatusReport("finalized", status.SwitchId, UpdatedAt: clock.UtcNow);
                }
                catch (SwitchException ex)
                {
                    throw Conflict(ex.Message);
                }
            }
            finally
            {
                await oldStorage.DisposeAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_session is { } s)
        {
            s.Cancel.Cancel();
            try
            {
                await s.Job.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }

            if (s.Terminal is null)
            {
                await s.Target.DisposeAsync().ConfigureAwait(false);
            }
        }
    }
}
