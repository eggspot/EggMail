using Mta.Core;
using Mta.Host.Hosting;
using Mta.Storage;
using Mta.Storage.Portability;
using Mta.Storage.Transfer;

namespace Mta.Host.Switching;

/// <summary>
/// What the running process currently allows, for the parts that are not the storage: whether the SMTP listeners and the HTTP
/// API take new mail. The API layer reads <see cref="AcceptingApi"/> and answers <c>503</c> with <c>Retry-After</c> while it is
/// false, and shows <see cref="Banner"/>.
/// </summary>
public sealed class SwitchRuntimeState
{
    private volatile bool _acceptingApi = true;
    private volatile string? _banner;

    public SwitchRuntimeState(StartupDecision decision)
    {
        Decision = decision;
        _acceptingApi = decision.AcceptMail;
        _banner = decision.Banner;
    }

    public StartupDecision Decision { get; }

    /// <summary>False while the instance is draining, quiescing, fenced or a target that is not active: the API answers 503 with Retry-After.</summary>
    public bool AcceptingApi
    {
        get => _acceptingApi;
        set => _acceptingApi = value;
    }

    /// <summary>The message naming the switch; null in normal operation.</summary>
    public string? Banner
    {
        get => _banner;
        set => _banner = value;
    }
}

/// <summary>
/// The process side of a switch: stops the SMTP listeners and the API from taking mail, pauses and quiesces the delivery
/// scheduler. The engine (in-process, behind the admin API) calls it step by step; the <see cref="SwitchStateWatcher"/> calls
/// <see cref="ReactAsync"/> when another process (the CLI) changed the persisted state.
/// </summary>
public sealed class HostSwitchControl(EggMailRuntime runtime, SwitchRuntimeState state) : ISwitchHostControl
{
    private readonly SemaphoreSlim _quiesce = new(1, 1);
    private (Guid Id, string State)? _reactedTo;

    public ValueTask StopAcceptingAsync(CancellationToken cancellationToken)
    {
        runtime.SmtpServer.AcceptingMail = false;
        state.AcceptingApi = false;
        return default;
    }

    public ValueTask ResumeAcceptingAsync(CancellationToken cancellationToken)
    {
        if (state.Decision.AcceptMail)
        {
            runtime.SmtpServer.AcceptingMail = true;
            state.AcceptingApi = true;
            state.Banner = null;
        }

        return default;
    }

    public ValueTask PauseDispatchAsync(CancellationToken cancellationToken)
    {
        runtime.Delivery.Pause();
        runtime.InboundActions.Pause();   // the route actions of received mail are held with the rest of the queue
        return default;
    }

    public ValueTask ResumeDispatchAsync(CancellationToken cancellationToken)
    {
        if (state.Decision.Dispatch)
        {
            runtime.Delivery.Resume();
            runtime.InboundActions.Resume();
        }

        return default;
    }

    public async ValueTask QuiesceDeliveriesAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        await _quiesce.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await runtime.Delivery.QuiesceAsync(timeout, cancellationToken).ConfigureAwait(false);
            await runtime.InboundActions.QuiesceAsync(timeout, cancellationToken).ConfigureAwait(false);
            await runtime.FlushRuntimeStateAsync(cancellationToken).ConfigureAwait(false);   // the sending and TLS-RPT counters of the last seconds belong in the bundle
        }
        finally
        {
            _quiesce.Release();
        }
    }

    /// <summary>
    /// Applies a persisted source state written by another process: Draining stops accepting, Quiescing and Fenced also stop
    /// dispatching (and quiesce what is in flight); back to Active (a rollback) resumes. Idempotent.
    /// </summary>
    public async Task ReactAsync(SwitchStateRecord? record, TimeSpan quiesceTimeout, CancellationToken cancellationToken)
    {
        (Guid, string)? key = record is { Role: SwitchRoles.Source } ? (record.SwitchId, record.State) : null;
        if (key == _reactedTo)
        {
            return;
        }

        switch (record)
        {
            case { Role: SwitchRoles.Source, State: SwitchStates.Draining }:
                await StopAcceptingAsync(cancellationToken).ConfigureAwait(false);
                state.Banner = $"Backend switch {record.SwitchId} is draining this instance: not accepting mail.";
                break;
            case { Role: SwitchRoles.Source, State: SwitchStates.Quiescing or SwitchStates.Fenced or SwitchStates.Finalized }:
                await StopAcceptingAsync(cancellationToken).ConfigureAwait(false);
                await PauseDispatchAsync(cancellationToken).ConfigureAwait(false);
                await QuiesceDeliveriesAsync(quiesceTimeout, cancellationToken).ConfigureAwait(false);
                state.Banner = $"Backend switch {record.SwitchId}: this instance is {record.State.ToLowerInvariant()} and neither accepts nor dispatches mail.";
                break;
            default:
                if (_reactedTo is not null)
                {
                    // The switch was rolled back (or cleared): resume.
                    await ResumeAcceptingAsync(cancellationToken).ConfigureAwait(false);
                    await ResumeDispatchAsync(cancellationToken).ConfigureAwait(false);
                    state.Banner = state.Decision.Banner;
                }

                break;
        }

        _reactedTo = key;
    }
}

/// <summary>
/// Polls the switch state of the store: when another process (the <c>mta migrate-storage</c> command, or another replica's admin
/// API) drains, quiesces, fences or rolls back this store, this process follows, and completes a drain (fences the source) once
/// the queue is empty. This is what makes a fence hold for replicas on a shared store.
/// </summary>
internal sealed class SwitchStateWatcher(EggMailRuntime runtime, HostSwitchControl control, TimeSpan interval) : Microsoft.Extensions.Hosting.BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (runtime.Storage.Transfer is not { } transfer)
        {
            return;
        }

        var engine = new StorageSwitchEngine(
            new SwitchEndpoint { Storage = runtime.Storage, Secrets = runtime.Secrets, Options = runtime.Config.Storage },
            null, control, null, runtime.Clock, runtime.Log);
        var quiesceTimeout = TimeSpan.FromSeconds(Math.Max(1, runtime.Config.Switch.QuiesceTimeoutSeconds));
        using var timer = new PeriodicTimer(interval);
        try
        {
            do
            {
                try
                {
                    SwitchStateRecord? record = await transfer.GetStateAsync(stoppingToken).ConfigureAwait(false);
                    await control.ReactAsync(record, quiesceTimeout, stoppingToken).ConfigureAwait(false);
                    if (record is { Role: SwitchRoles.Source, State: SwitchStates.Draining })
                    {
                        await engine.AdvanceAsync(stoppingToken).ConfigureAwait(false);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    runtime.Log.Write(MtaLogLevel.Error, "switch", "reading the backend switch state failed", ex);
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
        }
    }
}
