using System.Text.Json;
using Mta.Core;
using Mta.Storage.Transfer;

namespace Mta.Storage.Portability;

/// <summary>Tuning knobs of the engine (chunk sizes, drain polling). The defaults suit production; tests shrink them.</summary>
public sealed class SwitchOptions
{
    /// <summary>Rows per bundle chunk file (and per import transaction).</summary>
    public int ChunkRows { get; init; } = 5000;

    /// <summary>Bytes per bundle chunk (rows plus bodies); a chunk is closed after the row that passes it.</summary>
    public long ChunkBytes { get; init; } = 32L * 1024 * 1024;

    /// <summary>How often a drain looks at the queue.</summary>
    public TimeSpan DrainPollInterval { get; init; } = TimeSpan.FromMilliseconds(500);

    /// <summary>Recorded in the bundle manifest (<c>createdBy</c>).</summary>
    public string AppVersion { get; init; } = "0.0.0";
}

/// <summary>The persisted detail of a switch state: what the later steps need to know (never a secret).</summary>
internal sealed class SwitchDetail
{
    public string Mode { get; set; } = "drain";
    public string? Bundle { get; set; }
    public bool SkipHistory { get; set; }
    public bool HistoryAfterActivation { get; set; }
    public bool Activated { get; set; }
    public string? Note { get; set; }

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static SwitchDetail Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return new SwitchDetail();
        }

        try
        {
            return JsonSerializer.Deserialize<SwitchDetail>(json, Json) ?? new SwitchDetail();
        }
        catch (JsonException)
        {
            return new SwitchDetail { Note = json };
        }
    }
}

/// <summary>
/// The storage switch engine (design §4.6): orchestrates preflight, drain or quiesce, export, import, verify, confirm,
/// activate, rollback and finalize between a source and a target store. All durable state lives in the stores (the
/// <c>switch_state</c> records, the fence, the transfer marks and the chunk progress records), so a new engine instance, in a
/// new process, picks up where the last one stopped. Within one instance operations do not overlap.
/// </summary>
public sealed partial class StorageSwitchEngine : IStorageSwitchEngine
{
    private readonly SwitchEndpoint? _source;
    private readonly SwitchEndpoint? _target;
    private readonly ISwitchHostControl _host;
    private readonly ISwitchActivator? _activator;
    private readonly IClock _clock;
    private readonly IMtaLog _log;
    private readonly SwitchOptions _options;
    private readonly SemaphoreSlim _operation = new(1, 1);
    private readonly SemaphoreSlim _fenceLock = new(1, 1);
    private readonly object _sync = new();
    private CancellationTokenSource? _current;
    private CancellationTokenSource? _drainMonitor;
    private SwitchProgress? _lastProgress;

    public StorageSwitchEngine(SwitchEndpoint? source, SwitchEndpoint? target, ISwitchHostControl? host = null, ISwitchActivator? activator = null, IClock? clock = null, IMtaLog? log = null, SwitchOptions? options = null)
    {
        _source = source;
        _target = target;
        _host = host ?? OfflineHostControl.Instance;
        _activator = activator;
        _clock = clock ?? SystemClock.Instance;
        _log = log ?? NullMtaLog.Instance;
        _options = options ?? new SwitchOptions();
    }

    private SwitchEndpoint Source => _source ?? throw new SwitchException("This operation needs the source store, which is not configured.");

    private SwitchEndpoint Target => _target ?? throw new SwitchException("This operation needs the target store, which is not configured (give --to and the target settings).");

    private static IStorageTransfer TransferOf(SwitchEndpoint endpoint, string role) =>
        endpoint.Storage.Transfer ?? throw new SwitchException($"The {role} backend ({endpoint.Storage.Backend}) does not support switching yet.");

    private IStorageTransfer SourceTransfer => TransferOf(Source, "source");

    private IStorageTransfer TargetTransfer => TransferOf(Target, "target");

    private async Task<T> RunAsync<T>(string name, CancellationToken cancellationToken, Func<CancellationToken, Task<T>> body)
    {
        if (!await _operation.WaitAsync(0, CancellationToken.None).ConfigureAwait(false))
        {
            throw new SwitchException("Another switch operation is still running in this process; wait for it or cancel it first.");
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        lock (_sync)
        {
            _current = cts;
        }

        try
        {
            _log.Write(MtaLogLevel.Information, "switch", $"{name} started");
            T result = await body(cts.Token).ConfigureAwait(false);
            _log.Write(MtaLogLevel.Information, "switch", $"{name} finished");
            return result;
        }
        catch (OperationCanceledException)
        {
            _log.Write(MtaLogLevel.Warning, "switch", $"{name} was cancelled; run it again to resume");
            throw;
        }
        finally
        {
            lock (_sync)
            {
                _current = null;
            }

            _operation.Release();
        }
    }

    public void Cancel()
    {
        lock (_sync)
        {
            _current?.Cancel();
        }
    }

    private void Report(IProgress<SwitchProgress>? progress, string phase, string? table, long done, long total, string message)
    {
        var p = new SwitchProgress(phase, table, done, total, message);
        _lastProgress = p;
        progress?.Report(p);
    }

    private SwitchStateRecord NewState(Guid switchId, string role, string state, SwitchDetail detail) =>
        new(switchId, role, state, Truncate(_clock.UtcNow), detail.ToJson());

    private static DateTimeOffset Truncate(DateTimeOffset value) => DateTimeOffset.FromUnixTimeMilliseconds(value.ToUnixTimeMilliseconds());

    // ---- Start: drain or quiesce, ending Fenced

    public async Task<SwitchStatus> StartAsync(SwitchRequest request, IProgress<SwitchProgress>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return await RunAsync("start", cancellationToken, async ct =>
        {
            PreflightReport report = await PreflightCoreAsync(request, ct).ConfigureAwait(false);
            if (!report.CanProceed)
            {
                throw new SwitchException("Preflight failed: " + string.Join(" ", report.Errors.Select(e => e.Message)), null) { Report = report };
            }

            IStorageTransfer source = SourceTransfer;
            Guid switchId = Ids.New(_clock.UtcNow);
            var detail = new SwitchDetail
            {
                Mode = request.Mode == SwitchMode.Quiesce ? "quiesce" : "drain",
                Bundle = request.BundlePath,
                SkipHistory = request.SkipHistory,
                HistoryAfterActivation = request.HistoryAfterActivation,
            };

            string intermediate = request.Mode == SwitchMode.Quiesce ? SwitchStates.Quiescing : SwitchStates.Draining;
            await source.SetStateAsync(NewState(switchId, SwitchRoles.Source, intermediate, detail), ct).ConfigureAwait(false);
            await _host.StopAcceptingAsync(ct).ConfigureAwait(false);
            Report(progress, "start", null, 0, 1, request.Mode == SwitchMode.Quiesce ? "Stopped accepting; quiescing deliveries" : "Stopped accepting; draining the queue");

            if (request.Mode == SwitchMode.Quiesce)
            {
                await _host.PauseDispatchAsync(ct).ConfigureAwait(false);
                await _host.QuiesceDeliveriesAsync(request.QuiesceTimeout, ct).ConfigureAwait(false);
                await FenceAsync(switchId, detail, ct).ConfigureAwait(false);
            }
            else
            {
                StartDrainMonitor();
            }

            Report(progress, "start", null, 1, 1, request.Mode == SwitchMode.Quiesce ? "Fenced" : "Draining");
            return await StatusCoreAsync(ct).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }

    private void StartDrainMonitor()
    {
        lock (_sync)
        {
            _drainMonitor?.Cancel();
            _drainMonitor = new CancellationTokenSource();
            CancellationToken token = _drainMonitor.Token;
            _ = Task.Run(async () =>
            {
                try
                {
                    while (!token.IsCancellationRequested)
                    {
                        await Task.Delay(_options.DrainPollInterval, token).ConfigureAwait(false);
                        if (await TryFenceWhenDrainedAsync(token).ConfigureAwait(false))
                        {
                            return;
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                }
                catch (Exception ex)
                {
                    _log.Write(MtaLogLevel.Error, "switch", "waiting for the queue to drain failed; call advance again", ex);
                }
            }, CancellationToken.None);
        }
    }

    private void StopDrainMonitor()
    {
        lock (_sync)
        {
            _drainMonitor?.Cancel();
            _drainMonitor = null;
        }
    }

    public async Task<SwitchStatus> AdvanceAsync(CancellationToken cancellationToken)
    {
        await TryFenceWhenDrainedAsync(cancellationToken).ConfigureAwait(false);
        return await StatusCoreAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Fences the source when it is draining and its delivery queue is empty. Returns true once the source is fenced.</summary>
    private async Task<bool> TryFenceWhenDrainedAsync(CancellationToken ct)
    {
        await _fenceLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            SwitchStateRecord? state = await SourceTransfer.GetStateAsync(ct).ConfigureAwait(false);
            if (state is not { Role: SwitchRoles.Source })
            {
                return false;
            }

            if (state.State == SwitchStates.Fenced)
            {
                return true;
            }

            if (state.State != SwitchStates.Draining)
            {
                return false;
            }

            QueueStats stats = await Source.Storage.Deliveries.GetQueueStatsAsync(ct).ConfigureAwait(false);
            if (stats.Queued + stats.Leased + stats.Deferred > 0)
            {
                return false;
            }

            await FenceAsync(state.SwitchId, SwitchDetail.Parse(state.Detail), ct).ConfigureAwait(false);
            return true;
        }
        finally
        {
            _fenceLock.Release();
        }
    }

    private async Task FenceAsync(Guid switchId, SwitchDetail detail, CancellationToken ct)
    {
        // Counters of the last seconds must be in stats.db before it is exported.
        await Source.Storage.Stats.FlushAsync(ct).ConfigureAwait(false);
        await SourceTransfer.SetStateAsync(NewState(switchId, SwitchRoles.Source, SwitchStates.Fenced, detail), ct).ConfigureAwait(false);
        await _host.PauseDispatchAsync(ct).ConfigureAwait(false);
        StopDrainMonitor();
        _log.Write(MtaLogLevel.Warning, "switch", $"source fenced for backend switch {switchId}: it neither accepts nor dispatches until the switch is rolled back or finalized");
    }

    // ---- Confirm, activate

    public async Task<SwitchStatus> ConfirmAsync(CancellationToken cancellationToken) =>
        await RunAsync("confirm", cancellationToken, async ct =>
        {
            SwitchStateRecord state = await RequireTargetStateAsync(ct, SwitchStates.Verified).ConfigureAwait(false);
            await TargetTransfer.SetStateAsync(state with { State = SwitchStates.Confirmed, UpdatedAt = Truncate(_clock.UtcNow) }, ct).ConfigureAwait(false);
            return await StatusCoreAsync(ct).ConfigureAwait(false);
        }).ConfigureAwait(false);

    public async Task<SwitchActivation> ActivateAsync(CancellationToken cancellationToken) =>
        await RunAsync("activate", cancellationToken, async ct =>
        {
            SwitchStateRecord target = await RequireTargetStateAsync(ct, SwitchStates.Confirmed).ConfigureAwait(false);
            SwitchStateRecord source = await RequireSourceStateAsync(ct, target.SwitchId, SwitchStates.Fenced).ConfigureAwait(false);
            if (_activator is null)
            {
                throw new SwitchException("No activator is configured: the host must supply one to write the bootstrap file or produce the cutover patch.");
            }

            var detail = SwitchDetail.Parse(source.Detail);
            SwitchActivation activation = await _activator.ActivateAsync(
                new SwitchActivationRequest(source.SwitchId, Source.Options, Target.Options, EffectiveSettings.Describe(Source.Options)), ct).ConfigureAwait(false);
            detail.Activated = true;
            await SourceTransfer.SetStateAsync(source with { Detail = detail.ToJson(), UpdatedAt = Truncate(_clock.UtcNow) }, ct).ConfigureAwait(false);
            _log.Write(MtaLogLevel.Warning, "switch", activation.Summary);
            return activation;
        }).ConfigureAwait(false);

    // ---- Rollback, finalize

    public async Task<SwitchStatus> RollbackAsync(bool sourceOnly, CancellationToken cancellationToken) =>
        await RunAsync("rollback", cancellationToken, async ct =>
        {
            SwitchStateRecord? source = await SourceTransfer.GetStateAsync(ct).ConfigureAwait(false);
            if (source is not { Role: SwitchRoles.Source } || source.State is SwitchStates.Active)
            {
                throw new SwitchException("There is no switch in progress on the source; nothing to roll back.");
            }

            if (source.State == SwitchStates.Finalized)
            {
                throw new SwitchException("The switch was finalized; the source is retired. To go back, run the same flow in reverse (new backend to old backend).");
            }

            if (!sourceOnly)
            {
                if (_target is null)
                {
                    throw new SwitchException("The target store is not configured, so its imported data cannot be discarded. Give the target settings, or roll back with sourceOnly to clear only the source (the target's data is then left for manual cleanup).");
                }

                SwitchStateRecord? target = await TargetTransfer.GetStateAsync(ct).ConfigureAwait(false);
                if (target is not null && target.SwitchId != source.SwitchId)
                {
                    throw new SwitchException($"The target belongs to a different switch ({target.SwitchId}); it is not touched.");
                }

                if (target is { State: SwitchStates.Active })
                {
                    throw new SwitchException("The target is already active and may have delivered the imported mail, so the source cannot be un-fenced (that could double-send). Go back by running the same flow in reverse: the target is fenced and what is still queued is transferred back.");
                }

                if (target is not null)
                {
                    await TargetTransfer.DiscardImportedAsync(source.SwitchId, ct).ConfigureAwait(false);
                    await TargetTransfer.ClearStateAsync(ct).ConfigureAwait(false);
                    _log.Write(MtaLogLevel.Warning, "switch", "the target's imported data was discarded");
                }
            }

            StopDrainMonitor();
            var detail = SwitchDetail.Parse(source.Detail);
            if (detail.Activated && _activator is not null)
            {
                await _activator.RestoreAsync(source.SwitchId, ct).ConfigureAwait(false);
            }

            long released = await SourceTransfer.ReleaseQueueAsync(source.SwitchId, ct).ConfigureAwait(false);
            await SourceTransfer.SetStateAsync(NewState(source.SwitchId, SwitchRoles.Source, SwitchStates.Active, new SwitchDetail { Note = "rolled back" }), ct).ConfigureAwait(false);
            await _host.ResumeAcceptingAsync(ct).ConfigureAwait(false);
            await _host.ResumeDispatchAsync(ct).ConfigureAwait(false);
            _log.Write(MtaLogLevel.Warning, "switch", $"switch {source.SwitchId} rolled back: {released} queued rows released, the source accepts and dispatches again");
            return await StatusCoreAsync(ct).ConfigureAwait(false);
        }).ConfigureAwait(false);

    public async Task<SwitchStatus> FinalizeAsync(bool deleteBundle, string? bundlePath, CancellationToken cancellationToken) =>
        await RunAsync("finalize", cancellationToken, async ct =>
        {
            SwitchStateRecord source = await RequireSourceStateAsync(ct, null, SwitchStates.Fenced).ConfigureAwait(false);
            SwitchStateRecord target = await TargetTransfer.GetStateAsync(ct).ConfigureAwait(false) ?? throw new SwitchException("The target has no switch record; it was never imported into, or was rolled back.");
            if (target.SwitchId != source.SwitchId || target.State != SwitchStates.Active)
            {
                throw new SwitchException($"The target is {target.State} (switch {target.SwitchId}); finalize is only allowed once the application runs on the new backend and the target is Active.");
            }

            var detail = SwitchDetail.Parse(source.Detail);
            string? bundle = bundlePath ?? detail.Bundle;
            if (bundle is not null && Directory.Exists(bundle) && File.Exists(Path.Combine(bundle, "manifest.json")))
            {
                BundleReader reader = await BundleReader.OpenAsync(bundle, ct).ConfigureAwait(false);
                if (reader.Manifest.Switch.HistoryIncluded && TargetTransfer.HasPart(TransferPart.History))
                {
                    int expected = reader.Manifest.Files.Count(f => f.Kind == "rows" && f.Path.StartsWith("history/", StringComparison.Ordinal));
                    int applied = (await TargetTransfer.GetAppliedChunksAsync(source.SwitchId, TransferPart.History, ct).ConfigureAwait(false)).Count;
                    if (!reader.Manifest.Switch.HistoryComplete || applied < expected)
                    {
                        throw new SwitchException($"History is not fully copied to the target yet ({applied} of {expected} chunks applied{(reader.Manifest.Switch.HistoryComplete ? string.Empty : ", and the export is incomplete")}). The source is kept until the backfill is verified.");
                    }
                }
            }

            await SourceTransfer.SetStateAsync(NewState(source.SwitchId, SwitchRoles.Source, SwitchStates.Finalized, detail), ct).ConfigureAwait(false);
            if (_activator is not null)
            {
                await _activator.ForgetAsync(source.SwitchId, ct).ConfigureAwait(false);
            }

            if (deleteBundle && bundle is not null && Directory.Exists(bundle))
            {
                Directory.Delete(bundle, recursive: true);
            }

            _log.Write(MtaLogLevel.Warning, "switch", $"switch {source.SwitchId} finalized; the old data is untouched and can now be removed by the owner");
            return await StatusCoreAsync(ct).ConfigureAwait(false);
        }).ConfigureAwait(false);

    // ---- Status

    public async Task<SwitchStatus> GetStatusAsync(CancellationToken cancellationToken) => await StatusCoreAsync(cancellationToken).ConfigureAwait(false);

    private async Task<SwitchStatus> StatusCoreAsync(CancellationToken ct)
    {
        SwitchStateRecord? source = _source is null ? null : await TransferOf(_source, "source").GetStateAsync(ct).ConfigureAwait(false);
        SwitchStateRecord? target = _target is null ? null : await TransferOf(_target, "target").GetStateAsync(ct).ConfigureAwait(false);
        var detail = SwitchDetail.Parse(source?.Detail ?? target?.Detail);
        SwitchMode? mode = detail.Mode switch
        {
            "quiesce" => SwitchMode.Quiesce,
            "drain" when source is not null || target is not null => SwitchMode.Drain,
            _ => null,
        };
        Guid? id = source?.SwitchId ?? target?.SwitchId;
        string summary = (source?.State, target?.State) switch
        {
            (null or SwitchStates.Active, null) => "No switch in progress.",
            (SwitchStates.Draining, _) => "Source draining: not accepting; waiting for the queue to empty.",
            (SwitchStates.Quiescing, _) => "Source quiescing in-flight deliveries.",
            (SwitchStates.Fenced, null) => "Source fenced; export the bundle next.",
            (SwitchStates.Fenced, SwitchStates.Importing) => "Target importing.",
            (SwitchStates.Fenced, SwitchStates.Verified) => "Target verified; confirm next.",
            (SwitchStates.Fenced, SwitchStates.Confirmed) => detail.Activated ? "Activated: restart the application on the new backend." : "Target confirmed; activate next.",
            (SwitchStates.Fenced, SwitchStates.Active) => "Target active; finalize when satisfied.",
            (SwitchStates.Finalized, _) => "Finalized: the source is retired.",
            _ => $"Source {source?.State ?? "none"}, target {target?.State ?? "none"}.",
        };

        return new SwitchStatus(id, source?.State, target?.State, mode, detail.Bundle, detail.Activated, summary, _lastProgress);
    }

    private async Task<SwitchStateRecord> RequireTargetStateAsync(CancellationToken ct, params string[] allowed)
    {
        SwitchStateRecord? state = await TargetTransfer.GetStateAsync(ct).ConfigureAwait(false);
        if (state is not { Role: SwitchRoles.Target } || !allowed.Contains(state.State))
        {
            throw new SwitchException($"The target is {(state is null ? "not part of a switch" : state.State)}; this step needs it to be {string.Join(" or ", allowed)}.");
        }

        return state;
    }

    private async Task<SwitchStateRecord> RequireSourceStateAsync(CancellationToken ct, Guid? switchId, params string[] allowed)
    {
        SwitchStateRecord? state = await SourceTransfer.GetStateAsync(ct).ConfigureAwait(false);
        if (state is not { Role: SwitchRoles.Source } || !allowed.Contains(state.State))
        {
            throw new SwitchException($"The source is {(state is null ? "not part of a switch" : state.State)}; this step needs it to be {string.Join(" or ", allowed)}.");
        }

        if (switchId is { } id && state.SwitchId != id)
        {
            throw new SwitchException($"The source belongs to switch {state.SwitchId}, the target to {id}.");
        }

        return state;
    }
}

/// <summary>The target's activation: what the startup gate does when the application starts on a confirmed target (design §4.6).</summary>
public static class TargetActivation
{
    /// <summary>
    /// If the store is the target of a switch in state <see cref="SwitchStates.Confirmed"/>, releases the imported queue rows and moves
    /// it to <see cref="SwitchStates.Active"/>, in that order, so a crash in between is repeated by the next start and a row is never
    /// left held under an Active store. Returns true when the store was activated by this call.
    /// </summary>
    public static async Task<bool> ActivateAsync(IStorageTransfer transfer, IClock clock, CancellationToken cancellationToken)
    {
        SwitchStateRecord? state = await transfer.GetStateAsync(cancellationToken).ConfigureAwait(false);
        if (state is not { Role: SwitchRoles.Target, State: SwitchStates.Confirmed })
        {
            return false;
        }

        await transfer.ReleaseQueueAsync(state.SwitchId, cancellationToken).ConfigureAwait(false);
        await transfer.SetStateAsync(state with { State = SwitchStates.Active, UpdatedAt = DateTimeOffset.FromUnixTimeMilliseconds(clock.UtcNow.ToUnixTimeMilliseconds()) }, cancellationToken).ConfigureAwait(false);
        return true;
    }
}
