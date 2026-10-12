using System.Text.Json.Serialization;

namespace Mta.Host.Api;

/// <summary>Why the switch engine refused a request.</summary>
public enum StorageSwitchError : byte
{
    /// <summary>The engine (or the target it was pointed at) is not available. Answered as 503 <c>not_ready</c>.</summary>
    NotReady,

    /// <summary>The operation is not allowed in the current switch state. Answered as 409 <c>conflict</c>.</summary>
    InvalidState,

    /// <summary>The request itself is wrong (named field). Answered as 400 <c>validation_failed</c>.</summary>
    Invalid,
}

public sealed class StorageSwitchException(StorageSwitchError kind, string message, string? field = null) : Exception(message)
{
    public StorageSwitchError Kind { get; } = kind;

    public string? Field { get; } = field;
}

/// <summary>Where to switch to. Secrets are never sent: a PostgreSQL target is a named connection (deployment configuration) or host fields.</summary>
public sealed class SwitchTargetModel
{
    public string? ConnectionName { get; set; }
    public string? Host { get; set; }
    public int? Port { get; set; }
    public string? Database { get; set; }

    /// <summary>SQLite data directory.</summary>
    public string? Path { get; set; }
}

public class SwitchRequestModel
{
    /// <summary><c>postgres</c> or <c>sqlite</c>.</summary>
    public string? To { get; set; }

    public SwitchTargetModel? Target { get; set; }

    /// <summary><c>queue</c> and/or <c>history</c>.</summary>
    public List<string>? Include { get; set; }

    /// <summary><c>drain</c> or <c>quiesce</c>.</summary>
    public string? Mode { get; set; }
}

public sealed class SwitchStartModel : SwitchRequestModel
{
    /// <summary>Protects the secrets in the export bundle (at least 12 characters, design section 4.6).</summary>
    public string? ExportPassphrase { get; set; }

    /// <summary>The typed phrase <c>switch to &lt;postgres|sqlite&gt;</c>.</summary>
    public string? Confirmation { get; set; }
}

public sealed record PreflightCheckModel(string Name, bool Ok, string Message, string Severity);

public sealed record PreflightCountsModel(long QueuedMessages, long HistoryRows, long HistoryBytes, long StatsRows);

public sealed record PreflightEstimateModel(long? Seconds, long? Bytes, bool Unverified);

public sealed record SwitchPreflightReport(
    bool Ok,
    IReadOnlyList<PreflightCheckModel> Checks,
    PreflightCountsModel Counts,
    PreflightEstimateModel? Estimate,
    IReadOnlyList<string> NotCarried,
    bool OrchestratorManaged);

public sealed record SwitchDirection(string From, string To);

public sealed record SwitchProgress(string Phase, int Percent, long? RowsDone, long? RowsTotal);

public sealed record SwitchVerifyTable(string Table, long Expected, long Actual);

public sealed record SwitchVerifyReport(bool Ok, IReadOnlyList<SwitchVerifyTable> Tables, bool ChecksumsOk, DateTimeOffset? CheckedAt);

public sealed record SwitchCutoverPatch(string Kind, string Text);

/// <summary>
/// The state of the backend switch. <c>State</c> is one of <c>none, draining, quiescing, fenced, exporting, importing, verified, confirmed, active,
/// finalized, rolled_back, failed</c>. <c>Available</c> is false when this build has no switch engine.
/// </summary>
public sealed record SwitchStatusReport(
    string State,
    Guid? SwitchId = null,
    SwitchDirection? Direction = null,
    string? Mode = null,
    IReadOnlyList<string>? Include = null,
    SwitchProgress? Progress = null,
    SwitchVerifyReport? VerifyReport = null,
    SwitchCutoverPatch? CutoverPatch = null,
    bool OrchestratorManaged = false,
    DateTimeOffset? StartedAt = null,
    DateTimeOffset? UpdatedAt = null,
    string? Error = null,
    [property: JsonPropertyName("available")] bool Available = true);

/// <summary>
/// The backend-switch engine (design section 4.6; decision 14: manual, symmetric, never automatic). The HTTP API is a thin layer over this interface and
/// the CLI (<c>mta migrate-storage</c>) uses the same engine. Implementations throw <see cref="StorageSwitchException"/> for refusals.
/// </summary>
public interface IStorageSwitchService
{
    ValueTask<SwitchPreflightReport> PreflightAsync(SwitchRequestModel request, CancellationToken cancellationToken);

    ValueTask<SwitchStatusReport> StartAsync(SwitchStartModel request, CancellationToken cancellationToken);

    ValueTask<SwitchStatusReport> GetStatusAsync(CancellationToken cancellationToken);

    ValueTask<SwitchStatusReport> ConfirmAsync(CancellationToken cancellationToken);

    ValueTask<SwitchStatusReport> ActivateAsync(CancellationToken cancellationToken);

    ValueTask<SwitchStatusReport> RollbackAsync(CancellationToken cancellationToken);

    ValueTask<SwitchStatusReport> FinalizeAsync(CancellationToken cancellationToken);
}

/// <summary>The engine does not exist yet: status reads <c>none</c> and every operation answers <c>not_ready</c>.</summary>
public sealed class UnavailableStorageSwitchService : IStorageSwitchService
{
    private static StorageSwitchException NotAvailable() => new(StorageSwitchError.NotReady, "The storage switch engine is not available in this build.");

    public ValueTask<SwitchPreflightReport> PreflightAsync(SwitchRequestModel request, CancellationToken cancellationToken) => throw NotAvailable();

    public ValueTask<SwitchStatusReport> StartAsync(SwitchStartModel request, CancellationToken cancellationToken) => throw NotAvailable();

    public ValueTask<SwitchStatusReport> GetStatusAsync(CancellationToken cancellationToken) => ValueTask.FromResult(new SwitchStatusReport("none", Available: false));

    public ValueTask<SwitchStatusReport> ConfirmAsync(CancellationToken cancellationToken) => throw NotAvailable();

    public ValueTask<SwitchStatusReport> ActivateAsync(CancellationToken cancellationToken) => throw NotAvailable();

    public ValueTask<SwitchStatusReport> RollbackAsync(CancellationToken cancellationToken) => throw NotAvailable();

    public ValueTask<SwitchStatusReport> FinalizeAsync(CancellationToken cancellationToken) => throw NotAvailable();
}
