using Mta.Core;

namespace Mta.Storage.Portability;

/// <summary>How the source hands over its queued mail (design §4.6).</summary>
public enum SwitchMode : byte
{
    /// <summary>Stop accepting, let the queue empty, nothing queued moves.</summary>
    Drain = 0,

    /// <summary>Stop accepting, finish what is in flight (up to a timeout), fence, transfer what remains.</summary>
    Quiesce,
}

/// <summary>What an import covers.</summary>
public enum ImportScope : byte
{
    /// <summary>Config, stats and queue, then history when the bundle has it.</summary>
    All = 0,

    /// <summary>Config, stats and queue only (history is skipped or backfilled later).</summary>
    Core,

    /// <summary>History only: the backfill after activation, or the history that a core import left out.</summary>
    HistoryOnly,
}

/// <summary>One side of a switch: its storage, how it protects secrets at rest, and the options it runs with.</summary>
public sealed class SwitchEndpoint
{
    public required IStorage Storage { get; init; }

    /// <summary>Protects and unprotects the secrets of this deployment (the host's Data Protection key ring).</summary>
    public required ISecretProtector Secrets { get; init; }

    /// <summary>The options this storage runs with (history mode, retention, SQLite settings, …).</summary>
    public required StorageOptions Options { get; init; }

    /// <summary>False when <c>Secrets:KeyProtection=None</c>: the re-protected keys are then only as safe as the database (design §4.6, point d).</summary>
    public bool KeysProtectedAtRest { get; init; } = true;

    public string Describe() => Storage.Backend switch
    {
        StorageBackend.Sqlite => $"SQLite ({Options.Sqlite.DataDirectory})",
        StorageBackend.Postgres => "PostgreSQL",
        _ => Storage.Backend.ToString(),
    };
}

/// <summary>The parameters of a switch that stay the same from preflight to finalize.</summary>
public sealed class SwitchRequest
{
    public SwitchMode Mode { get; init; } = SwitchMode.Drain;

    /// <summary>How long in-flight deliveries may finish when quiescing (<c>Switch:QuiesceTimeoutSeconds</c>, default 30, decision R).</summary>
    public TimeSpan QuiesceTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Do not move per-message history (it stays in the read-only source).</summary>
    public bool SkipHistory { get; init; }

    /// <summary>Copy history after activation instead of before (for large histories); the source is kept until the backfill is verified.</summary>
    public bool HistoryAfterActivation { get; init; }

    public string? BundlePath { get; init; }

    /// <summary>The export passphrase (checked for length in preflight). Never logged, never stored.</summary>
    public string? Passphrase { get; init; }

    /// <summary>Acknowledge that the target runs with <c>Secrets:KeyProtection=None</c>.</summary>
    public bool AcceptUnprotectedTarget { get; init; }
}

public sealed class BundleRequest
{
    public required string BundlePath { get; init; }

    public required string Passphrase { get; init; }

    /// <summary>Export only: leave per-message history out of the bundle.</summary>
    public bool SkipHistory { get; init; }
}

public sealed class ImportRequest
{
    public required string BundlePath { get; init; }

    public required string Passphrase { get; init; }

    public ImportScope Scope { get; init; } = ImportScope.All;

    public bool AcceptUnprotectedTarget { get; init; }
}

public enum CheckStatus : byte
{
    Ok = 0,
    Warning,
    Error,
}

public sealed record PreflightCheck(string Name, CheckStatus Status, string Message);

/// <summary>What preflight found (design §4.6, step 1). <see cref="CanProceed"/> is false when any check is an error.</summary>
public sealed class PreflightReport
{
    public required IReadOnlyList<PreflightCheck> Checks { get; init; }

    /// <summary>Row counts per table of the source (what would move).</summary>
    public required IReadOnlyDictionary<string, long> SourceRows { get; init; }

    /// <summary>Bytes of queued raw messages in the source spool.</summary>
    public long SpoolBytes { get; init; }

    /// <summary>Statements about what will not carry over.</summary>
    public required IReadOnlyList<string> WillNotCarryOver { get; init; }

    public bool CanProceed => Checks.All(c => c.Status != CheckStatus.Error);

    public IEnumerable<PreflightCheck> Errors => Checks.Where(c => c.Status == CheckStatus.Error);
}

/// <summary>A progress notification of a running operation.</summary>
public sealed record SwitchProgress(string Phase, string? Table, long Done, long Total, string Message);

/// <summary>The summary of an export.</summary>
public sealed record ExportResult(Guid SwitchId, string BundlePath, long Rows, long Bytes, long QueueRowsMarked, bool HistoryComplete, IReadOnlyList<string> Notes);

/// <summary>The summary of an import.</summary>
public sealed record ImportResult(Guid SwitchId, long RowsApplied, long ChunksApplied, long ChunksAlreadyApplied, long HistoryChunksApplied, long HistoryChunksTotal, IReadOnlyList<string> Notes);

public sealed record TableVerification(string Table, long ExpectedRows, long ActualRows, bool ChecksumMatches, bool? SecretsMatch);

/// <summary>The verification report shown to the owner (design §4.6, step 5).</summary>
public sealed class VerifyReport
{
    public required bool Ok { get; init; }

    public required IReadOnlyList<TableVerification> Tables { get; init; }

    public required IReadOnlyList<string> Problems { get; init; }

    public long FilesChecked { get; init; }

    public long BytesChecked { get; init; }

    public long QueueRowsHeld { get; init; }

    public long HistoryChunksApplied { get; init; }

    public long HistoryChunksTotal { get; init; }

    /// <summary>True when the secret digests were checked (needs the passphrase).</summary>
    public bool SecretsChecked { get; init; }

    public IReadOnlyList<string> Notes { get; init; } = [];
}

public enum ActivationKind : byte
{
    /// <summary>The bootstrap file on the data volume now points at the target; restart the application.</summary>
    BootstrapFileWritten = 0,

    /// <summary>The storage pointer comes from the orchestrator: apply the patch and restart.</summary>
    CutoverPatch,
}

/// <summary>The outcome of the activation step.</summary>
/// <param name="Kind">How the storage pointer is managed in this deployment.</param>
/// <param name="Summary">What was done or what the operator must do.</param>
/// <param name="Patch">For <see cref="ActivationKind.CutoverPatch"/>: the environment diff, ConfigMap patch and compose override (secrets are referenced by name, never printed).</param>
/// <param name="File">For <see cref="ActivationKind.BootstrapFileWritten"/>: the file that was written.</param>
public sealed record SwitchActivation(ActivationKind Kind, string Summary, string? Patch, string? File)
{
    public bool RestartRequired => true;
}

public sealed record SwitchActivationRequest(Guid SwitchId, StorageOptions Source, StorageOptions Target, IReadOnlyDictionary<string, string> EffectiveSettings);

/// <summary>Implemented by the host: writes the new storage pointer or produces the cutover patch (design §4.6, "Activation").</summary>
public interface ISwitchActivator
{
    Task<SwitchActivation> ActivateAsync(SwitchActivationRequest request, CancellationToken cancellationToken);

    /// <summary>Undoes what <see cref="ActivateAsync"/> did (restores the previous bootstrap file) when a switch is rolled back.</summary>
    Task RestoreAsync(Guid switchId, CancellationToken cancellationToken);
}

/// <summary>
/// What the running process does while it is the source of a switch. The engine decides when; the host knows how: the SMTP
/// listeners reply <c>421</c>, the API replies <c>503</c> with <c>Retry-After</c>, the delivery scheduler stops claiming.
/// </summary>
public interface ISwitchHostControl
{
    ValueTask StopAcceptingAsync(CancellationToken cancellationToken);

    ValueTask ResumeAcceptingAsync(CancellationToken cancellationToken);

    ValueTask PauseDispatchAsync(CancellationToken cancellationToken);

    ValueTask ResumeDispatchAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Waits up to <paramref name="timeout"/> for in-flight deliveries, aborts what is left and requeues it with its retry state
    /// (decision R), flagged <c>possible_duplicate</c> when the end of data had been sent.
    /// </summary>
    ValueTask QuiesceDeliveriesAsync(TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>The control of an offline tool (the CLI with the server stopped): nothing is running, so there is nothing to stop.</summary>
public sealed class OfflineHostControl : ISwitchHostControl
{
    public static readonly OfflineHostControl Instance = new();

    public ValueTask StopAcceptingAsync(CancellationToken cancellationToken) => default;

    public ValueTask ResumeAcceptingAsync(CancellationToken cancellationToken) => default;

    public ValueTask PauseDispatchAsync(CancellationToken cancellationToken) => default;

    public ValueTask ResumeDispatchAsync(CancellationToken cancellationToken) => default;

    public ValueTask QuiesceDeliveriesAsync(TimeSpan timeout, CancellationToken cancellationToken) => default;
}

/// <summary>Where a switch stands, from the persisted states of both stores.</summary>
public sealed record SwitchStatus(
    Guid? SwitchId,
    string? SourceState,
    string? TargetState,
    SwitchMode? Mode,
    string? BundlePath,
    bool Activated,
    string Summary,
    SwitchProgress? Progress);

/// <summary>An operation was refused because the switch is not in the state it needs (or a check failed). The message says what to do.</summary>
public sealed class SwitchException(string message, Exception? inner = null) : Exception(message, inner)
{
    public PreflightReport? Report { get; init; }
}

/// <summary>
/// The engine the HTTP API layer (<c>/admin/storage/switch</c>) and the <c>mta migrate-storage</c> command both call
/// (design §4.6: "two entry points, one engine"). Every operation is idempotent where it can be and resumable where it is long.
/// </summary>
public interface IStorageSwitchEngine
{
    /// <summary>Step 1: checks everything that can be checked without changing anything.</summary>
    Task<PreflightReport> PreflightAsync(SwitchRequest request, CancellationToken cancellationToken);

    /// <summary>Step 2: stops accepting, then drains (returns while draining; call <see cref="AdvanceAsync"/> or export) or quiesces (returns fenced).</summary>
    Task<SwitchStatus> StartAsync(SwitchRequest request, IProgress<SwitchProgress>? progress, CancellationToken cancellationToken);

    /// <summary>Completes a drain once the queue is empty (fences the source). Safe to call repeatedly.</summary>
    Task<SwitchStatus> AdvanceAsync(CancellationToken cancellationToken);

    /// <summary>Step 3: writes the bundle from the fenced source and marks the exported queue rows.</summary>
    Task<ExportResult> ExportAsync(BundleRequest request, IProgress<SwitchProgress>? progress, CancellationToken cancellationToken);

    /// <summary>Step 4: imports the bundle into the empty target (resumable, idempotent per chunk).</summary>
    Task<ImportResult> ImportAsync(ImportRequest request, IProgress<SwitchProgress>? progress, CancellationToken cancellationToken);

    /// <summary>Step 5: re-checks the bundle and the target against the manifest; moves the target to Verified when everything matches.</summary>
    Task<VerifyReport> VerifyAsync(BundleRequest request, IProgress<SwitchProgress>? progress, CancellationToken cancellationToken);

    /// <summary>Step 6: the owner's explicit confirmation (Verified to Confirmed).</summary>
    Task<SwitchStatus> ConfirmAsync(CancellationToken cancellationToken);

    /// <summary>Step 7: writes the new storage pointer or produces the cutover patch; the target becomes Active when it starts (the startup gate).</summary>
    Task<SwitchActivation> ActivateAsync(CancellationToken cancellationToken);

    /// <summary>Before activation: discards the target's imported data, clears the marks and the fence and resumes the source.</summary>
    Task<SwitchStatus> RollbackAsync(bool sourceOnly, CancellationToken cancellationToken);

    /// <summary>Step 8: only after the target is Active; marks the source Finalized. The tool never deletes the source.</summary>
    Task<SwitchStatus> FinalizeAsync(bool deleteBundle, string? bundlePath, CancellationToken cancellationToken);

    Task<SwitchStatus> GetStatusAsync(CancellationToken cancellationToken);

    /// <summary>Cancels the operation that is running (export, import, verify, drain wait). The next call resumes.</summary>
    void Cancel();
}
