namespace Mta.Storage.Transfer;

/// <summary>One chunk of a bundle as the importer hands it to a store (a file of at most a few thousand rows of one table).</summary>
/// <param name="SwitchId">The backend switch the chunk belongs to; import is idempotent per switch and chunk.</param>
/// <param name="Table">The table the rows belong to.</param>
/// <param name="ChunkId">The bundle-relative path of the chunk file; unique within the switch.</param>
/// <param name="Checksum">SHA-256 (hex) of the chunk file, from the manifest.</param>
/// <param name="HoldRows">Store the switch id in the hold column of the rows so they cannot be claimed until activation.</param>
public sealed record TransferChunk(Guid SwitchId, TransferTable Table, string ChunkId, string Checksum, bool HoldRows);

/// <summary>The progress record of an applied chunk.</summary>
public sealed record TransferChunkRecord(Guid SwitchId, string ChunkId, string Table, long Rows, string Checksum, DateTimeOffset AppliedAt);

public enum ChunkApplyOutcome : byte
{
    Applied = 0,

    /// <summary>The chunk was applied before (same switch, same id, same checksum): nothing was written.</summary>
    AlreadyApplied,
}

/// <summary>
/// The provider-neutral transfer contract of a store (design §4.6): streaming export of every table as entity rows, idempotent
/// chunked import with progress records, the persisted switch state with the fence behind it, and the transfer marks and
/// activation holds on queued rows. Every backend implements it; the relational providers share
/// <see cref="EfStorageTransfer"/>. The portable engine (<c>Mta.Storage.Portability</c>) only talks to this interface.
/// </summary>
public interface IStorageTransfer
{
    /// <summary>
    /// What the store currently allows: closed on a fenced source and on a target that is not activated yet. A closed store
    /// refuses to accept mail (<see cref="StorageFencedException"/>), hands out no deliveries and no webhook events, and
    /// runs no maintenance, whatever else is configured, including after a restart.
    /// </summary>
    SwitchGate Gate { get; }

    /// <summary>Whether the store has the part (the history part is absent under <see cref="HistoryMode.StatsOnly"/>).</summary>
    bool HasPart(TransferPart part);

    // ---- Export: streaming, bounded memory

    /// <summary>
    /// Streams the rows of a table in key order. The enumeration may read a consistent snapshot while writers continue, but a
    /// fenced source has no writers. Rows are provider-neutral entities; the caller must not modify them.
    /// </summary>
    IAsyncEnumerable<object> ReadAsync(TransferTable table, TransferRange range, CancellationToken cancellationToken);

    ValueTask<long> CountAsync(TransferTable table, TransferRange range, CancellationToken cancellationToken);

    /// <summary>The distinct history days that have rows, ascending (empty without a history part).</summary>
    ValueTask<IReadOnlyList<int>> GetHistoryDaysAsync(CancellationToken cancellationToken);

    // ---- Import: idempotent per switch id and chunk

    /// <summary>The tables that hold rows that would move (the importer refuses to merge into a non-empty target).</summary>
    ValueTask<IReadOnlyList<string>> GetNonEmptyTablesAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Applies the rows of one chunk and its progress record in one transaction. A chunk that was applied before is skipped
    /// (<see cref="ChunkApplyOutcome.AlreadyApplied"/>); the same chunk id with a different checksum throws
    /// <see cref="StorageTransferException"/>.
    /// </summary>
    ValueTask<ChunkApplyOutcome> ApplyChunkAsync(TransferChunk chunk, IReadOnlyList<object> rows, CancellationToken cancellationToken);

    ValueTask<IReadOnlyList<TransferChunkRecord>> GetAppliedChunksAsync(Guid switchId, TransferPart part, CancellationToken cancellationToken);

    /// <summary>Deletes every row that moves, in every part, and the progress records of the switch (rollback of a target).</summary>
    ValueTask DiscardImportedAsync(Guid switchId, CancellationToken cancellationToken);

    // ---- Switch state, fence, marks

    ValueTask<SwitchStateRecord?> GetStateAsync(CancellationToken cancellationToken);

    /// <summary>Persists the switch state and re-evaluates <see cref="Gate"/> from it, so state and fence always agree.</summary>
    ValueTask SetStateAsync(SwitchStateRecord state, CancellationToken cancellationToken);

    /// <summary>Removes the switch record (an empty target after rollback) and opens the gate.</summary>
    ValueTask ClearStateAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Marks every queued delivery and webhook outbox row <c>transferred(switchId)</c>: a marked row cannot be claimed even if
    /// the fence were cleared by mistake. Returns the number of rows marked.
    /// </summary>
    ValueTask<long> MarkQueueTransferredAsync(Guid switchId, CancellationToken cancellationToken);

    /// <summary>Clears the marks or activation holds of the switch (rollback of the source, activation of the target). Returns the number of rows released.</summary>
    ValueTask<long> ReleaseQueueAsync(Guid switchId, CancellationToken cancellationToken);

    /// <summary>The number of queued rows held by the switch (marked on the source, held on the target).</summary>
    ValueTask<long> CountHeldQueueRowsAsync(Guid switchId, CancellationToken cancellationToken);
}
