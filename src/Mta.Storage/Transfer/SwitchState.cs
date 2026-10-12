namespace Mta.Storage.Transfer;

/// <summary>The roles a store can have in a backend switch (design §4.6). Stored in <see cref="SwitchStateRecord.Role"/>.</summary>
public static class SwitchRoles
{
    public const string Source = "Source";
    public const string Target = "Target";
}

/// <summary>
/// The states of a backend switch. Source: <see cref="Active"/>, <see cref="Quiescing"/> or <see cref="Draining"/>, <see cref="Fenced"/>,
/// then <see cref="Finalized"/> (or back to Active on rollback). Target: <see cref="Importing"/>, <see cref="Verified"/>,
/// <see cref="Confirmed"/>, <see cref="Active"/>.
/// </summary>
public static class SwitchStates
{
    public const string Active = "Active";
    public const string Quiescing = "Quiescing";
    public const string Draining = "Draining";
    public const string Fenced = "Fenced";
    public const string Finalized = "Finalized";
    public const string Importing = "Importing";
    public const string Verified = "Verified";
    public const string Confirmed = "Confirmed";
}

/// <summary>Thrown when mail is accepted by, or a delivery claimed from, a store that a backend switch has closed.</summary>
public sealed class StorageFencedException(string message) : InvalidOperationException(message);

/// <summary>A failure of the transfer machinery itself (a re-sent chunk that differs from the applied one, a missing part).</summary>
public sealed class StorageTransferException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// What a store currently allows while a backend switch is in progress. It is derived from the persisted switch state, so
/// it survives a restart: a fenced source never accepts or dispatches again until the fence is cleared by rollback, and a
/// target does not accept or dispatch until it is activated (design §4.6).
/// </summary>
public sealed class SwitchGate
{
    private volatile string? _reason;
    private Guid _switchId;

    /// <summary>True when the store refuses to accept mail and to hand out deliveries.</summary>
    public bool IsClosed => _reason is not null;

    /// <summary>Why the store is closed, for logs and banners (null when open).</summary>
    public string? Reason => _reason;

    /// <summary>The switch that closed the gate (<see cref="Guid.Empty"/> when open).</summary>
    public Guid SwitchId => _switchId;

    /// <summary>Re-evaluates the gate from a persisted state (null means no switch record).</summary>
    public void Apply(SwitchStateRecord? state)
    {
        string? reason = Evaluate(state);
        _switchId = reason is null || state is null ? Guid.Empty : state.SwitchId;
        _reason = reason;
    }

    /// <summary>The reason a state closes the store, or null when it leaves the store open.</summary>
    public static string? Evaluate(SwitchStateRecord? state)
    {
        if (state is null)
        {
            return null;
        }

        return (state.Role, state.State) switch
        {
            (SwitchRoles.Source, SwitchStates.Fenced) => $"This store is the fenced source of backend switch {state.SwitchId}; it neither accepts nor dispatches mail. Finish the switch, or roll it back to resume this store.",
            (SwitchRoles.Source, SwitchStates.Finalized) => $"This store is the finalized source of backend switch {state.SwitchId}; mail is handled by the new backend.",
            (SwitchRoles.Target, SwitchStates.Importing or SwitchStates.Verified or SwitchStates.Confirmed) => $"This store is the target of backend switch {state.SwitchId} ({state.State}); it neither accepts nor dispatches mail until the switch is activated.",
            _ => null,
        };
    }

    public void ThrowIfClosed()
    {
        if (_reason is { } reason)
        {
            throw new StorageFencedException(reason);
        }
    }
}
