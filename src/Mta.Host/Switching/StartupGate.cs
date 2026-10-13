using Mta.Core;
using Mta.Storage;
using Mta.Storage.Portability;
using Mta.Storage.Transfer;

namespace Mta.Host.Switching;

/// <summary>What the process may do after reading the switch state of its storage at startup (design §4.6).</summary>
public enum StartupMode : byte
{
    /// <summary>No switch, or the switch is complete here: run normally.</summary>
    Normal = 0,

    /// <summary>A drain is in progress: do not accept mail, keep delivering until the queue is empty.</summary>
    Draining,

    /// <summary>The store is the target of a switch that is not activated yet, or a quiesce was interrupted: dashboard and API read-only, no accepting, no dispatching.</summary>
    Restricted,

    /// <summary>A fenced (or finalized) source: a banner, and neither accepting nor dispatching, so a forgotten replica cannot double-send.</summary>
    Fenced,
}

/// <summary>The outcome of the startup gate.</summary>
/// <param name="Mode">What the process may do.</param>
/// <param name="Banner">A message naming the switch, shown on the dashboard and logged; null in normal operation.</param>
/// <param name="SwitchId">The switch the store belongs to, if any.</param>
/// <param name="Role">Source or Target, if the store is part of a switch.</param>
/// <param name="State">The state in the switch record, after any transition made by the gate.</param>
/// <param name="TargetActivated">True when this start moved a confirmed target to Active.</param>
public sealed record StartupDecision(StartupMode Mode, string? Banner, Guid? SwitchId, string? Role, string? State, bool TargetActivated)
{
    public static StartupDecision Normal { get; } = new(StartupMode.Normal, null, null, null, null, false);

    public bool AcceptMail => Mode == StartupMode.Normal;

    public bool Dispatch => Mode is StartupMode.Normal or StartupMode.Draining;
}

/// <summary>
/// On start, reads the <c>switch_state</c> of the store the application is pointed at (design §4.6). No record, or Active: run.
/// A confirmed target is atomically moved to Active and only then runs. An importing or verified target starts restricted.
/// A fenced source shows a banner and refuses to accept or dispatch. The same rule applies whether the pointer was changed by the
/// bootstrap file or by an orchestrator, which is why the order of operations is safe whatever the orchestrator does.
/// </summary>
public static class StartupGate
{
    public static async Task<StartupDecision> EvaluateAsync(IStorage storage, IClock clock, IMtaLog log, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(storage);
        if (storage.Transfer is not { } transfer)
        {
            return StartupDecision.Normal;
        }

        SwitchStateRecord? state = await transfer.GetStateAsync(cancellationToken).ConfigureAwait(false);
        if (state is null)
        {
            return StartupDecision.Normal;
        }

        StartupDecision decision = (state.Role, state.State) switch
        {
            (SwitchRoles.Source, SwitchStates.Active) => StartupDecision.Normal,
            (SwitchRoles.Target, SwitchStates.Active) => StartupDecision.Normal,
            (SwitchRoles.Source, SwitchStates.Draining) => Describe(StartupMode.Draining, state, $"Backend switch {state.SwitchId} is draining this instance: it does not accept mail and delivers what is queued; it is fenced when the queue is empty."),
            (SwitchRoles.Source, SwitchStates.Quiescing) => Describe(StartupMode.Restricted, state, $"Backend switch {state.SwitchId} was quiescing this instance when it stopped: it neither accepts nor dispatches. Continue the switch or roll it back (mta migrate-storage rollback)."),
            (SwitchRoles.Source, SwitchStates.Fenced) => Describe(StartupMode.Fenced, state, $"This instance is the fenced source of backend switch {state.SwitchId}: it is read-only and neither accepts nor dispatches mail, so nothing is sent twice. Mail is handled by the new backend. Roll the switch back (mta migrate-storage rollback) to resume this instance, or finalize it."),
            (SwitchRoles.Source, SwitchStates.Finalized) => Describe(StartupMode.Fenced, state, $"This instance is the finalized source of backend switch {state.SwitchId}: the old data is kept but mail is handled by the new backend. Point the deployment at the new backend."),
            (SwitchRoles.Target, SwitchStates.Importing or SwitchStates.Verified) => Describe(StartupMode.Restricted, state, $"Backend switch {state.SwitchId}: this storage is the target and is {state.State}. It neither accepts nor dispatches mail until the switch is confirmed and activated."),
            (SwitchRoles.Target, SwitchStates.Confirmed) => StartupDecision.Normal, // activated below
            _ => Describe(StartupMode.Restricted, state, $"Backend switch {state.SwitchId}: unknown state {state.Role}/{state.State}; starting restricted."),
        };

        if (state is { Role: SwitchRoles.Target, State: SwitchStates.Confirmed })
        {
            if (await TargetActivation.ActivateAsync(transfer, clock, cancellationToken).ConfigureAwait(false))
            {
                log.Write(MtaLogLevel.Warning, "switch", $"backend switch {state.SwitchId}: the target was confirmed; it is now Active and starts accepting and dispatching (queued mail that moved with the switch is dispatched now)");
                return new StartupDecision(StartupMode.Normal, null, state.SwitchId, SwitchRoles.Target, SwitchStates.Active, TargetActivated: true);
            }

            // Another replica activated it between our read and our write: it is Active now.
            return new StartupDecision(StartupMode.Normal, null, state.SwitchId, SwitchRoles.Target, SwitchStates.Active, false);
        }

        if (decision.Banner is not null)
        {
            log.Write(MtaLogLevel.Warning, "switch", decision.Banner);
        }

        return decision;
    }

    private static StartupDecision Describe(StartupMode mode, SwitchStateRecord state, string banner) => new(mode, banner, state.SwitchId, state.Role, state.State, false);
}
