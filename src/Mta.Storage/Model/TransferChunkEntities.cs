namespace Mta.Storage.Model;

/// <summary>
/// Progress record of the backend switch (design §4.6): one row per bundle chunk applied to this store. The chunk rows and
/// this record commit together, so re-sending a chunk is detected and skipped, and a killed import resumes after the last
/// applied chunk. One table per model part (a part is one SQLite file, and a transaction cannot span files).
/// </summary>
public abstract class TransferChunkEntity
{
    public Guid SwitchId { get; set; }

    /// <summary>The bundle-relative file path of the chunk, for example <c>queue/delivery_queue.00001.ndjson</c>.</summary>
    public string ChunkId { get; set; } = "";

    public string TableName { get; set; } = "";
    public long Rows { get; set; }

    /// <summary>SHA-256 (hex) of the chunk file as listed in the bundle manifest.</summary>
    public string Checksum { get; set; } = "";
    public DateTimeOffset AppliedAt { get; set; }
}

public sealed class ConfigTransferChunkEntity : TransferChunkEntity;

public sealed class QueueTransferChunkEntity : TransferChunkEntity;

public sealed class StatsTransferChunkEntity : TransferChunkEntity;

public sealed class HistoryTransferChunkEntity : TransferChunkEntity;
