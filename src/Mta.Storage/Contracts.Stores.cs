using Mta.Core;

namespace Mta.Storage;

/// <summary>
/// The storage facade. Both backends implement it with identical behavior (decision E); only characteristics differ.
/// All methods are safe for concurrent use.
/// </summary>
public interface IStorage : IAsyncDisposable
{
    StorageBackend Backend { get; }
    HistoryMode HistoryMode { get; }
    IMessageIntake Intake { get; }
    IDeliveryStore Deliveries { get; }
    IConfigStore Config { get; }
    IStatsStore Stats { get; }
    IHistoryStore History { get; }
    IWebhookOutbox Webhooks { get; }
    IStorageMaintenance Maintenance { get; }

    /// <summary>Creates or migrates the schema, runs startup integrity checks (SQLite) and prepares writers.</summary>
    Task InitializeAsync(CancellationToken cancellationToken);
}

/// <summary>Durable acceptance of a message (decision 13): returns after the data is committed according to the configured sync mode.</summary>
public interface IMessageIntake
{
    /// <summary>
    /// Atomically (per backend semantics) stores the raw message in the spool, creates one queued delivery per recipient,
    /// records history content when <see cref="HistoryMode.Full"/>, updates the idempotency table and counts "accepted" statistics.
    /// </summary>
    ValueTask<IntakeResult> AcceptAsync(AcceptedMessage message, CancellationToken cancellationToken);
}

/// <summary>Queue operations used by the delivery engine.</summary>
public interface IDeliveryStore
{
    /// <summary>
    /// Leases up to <paramref name="max"/> due deliveries to <paramref name="owner"/> (single statement on PostgreSQL:
    /// <c>FOR UPDATE SKIP LOCKED … RETURNING</c>; single-process claim on SQLite).
    /// </summary>
    ValueTask<IReadOnlyList<ClaimedDelivery>> ClaimAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken);

    /// <summary>Reads the raw message of a claimed delivery from the spool (null if gone).</summary>
    ValueTask<byte[]?> GetRawAsync(Guid messageId, CancellationToken cancellationToken);

    /// <summary>
    /// Records one attempt and its consequences in the order that keeps crashes harmless (suppression first, then the
    /// queue row, event, statistics, webhook outbox rows): deletes or reschedules the row, writes the event, counts
    /// statistics, fans out webhook events, frees the spool when the last recipient is final (moving raw to retention
    /// when requested).
    /// </summary>
    ValueTask RecordAttemptAsync(DeliveryAttempt attempt, CancellationToken cancellationToken);

    /// <summary>Extends a lease for a long-running attempt.</summary>
    ValueTask<bool> ExtendLeaseAsync(Guid deliveryId, string owner, DateTimeOffset until, CancellationToken cancellationToken);

    /// <summary>Clears every lease (startup of a single-process backend, or reclaiming leases of dead workers).</summary>
    ValueTask<int> ReleaseExpiredLeasesAsync(DateTimeOffset now, CancellationToken cancellationToken);

    /// <summary>Releases the leases held by <paramref name="owner"/> without counting an attempt (graceful shutdown, quiesce).</summary>
    ValueTask<int> ReleaseOwnedLeasesAsync(string owner, CancellationToken cancellationToken);

    ValueTask<QueueStats> GetQueueStatsAsync(CancellationToken cancellationToken);

    /// <summary>Expires deliveries older than their <c>ExpiresAt</c> that are not leased; returns the claimed rows to bounce.</summary>
    ValueTask<IReadOnlyList<ClaimedDelivery>> ClaimExpiredAsync(string owner, int max, DateTimeOffset now, CancellationToken cancellationToken);
}

public sealed record QueueStats(long Queued, long Leased, long Deferred, DateTimeOffset? OldestDueAt, long SpoolBytes);

public sealed record StatKey(DateTimeOffset HourStart, Guid TenantId, string SendingDomain, string RecipientDomain);

[Flags]
public enum StatCounter : byte
{
    Accepted = 0,
    Delivered = 1,
    Deferred = 2,
    HardBounce = 3,
    SoftBounce = 4,
    Expired = 5,
    Complained = 6,
    Rejected = 7,
    Suppressed = 8,
}

public sealed class StatRow
{
    public required DateTimeOffset PeriodStart { get; init; }
    public required bool Daily { get; init; }
    public required Guid TenantId { get; init; }
    public required string SendingDomain { get; init; }
    public required string RecipientDomain { get; init; }
    public long Accepted { get; init; }
    public long Delivered { get; init; }
    public long Deferred { get; init; }
    public long HardBounce { get; init; }
    public long SoftBounce { get; init; }
    public long Expired { get; init; }
    public long Complained { get; init; }
    public long Rejected { get; init; }
    public long Suppressed { get; init; }
}

public interface IStatsStore
{
    /// <summary>Adds to an in-memory aggregate that is flushed periodically (about every 10 s) and on shutdown.</summary>
    void Add(in StatKey key, StatCounter counter, long count = 1);

    ValueTask FlushAsync(CancellationToken cancellationToken);

    ValueTask<IReadOnlyList<StatRow>> QueryAsync(Guid? tenantId, DateTimeOffset from, DateTimeOffset to, bool daily, CancellationToken cancellationToken);

    /// <summary>Latest events (content-free ring, always kept).</summary>
    ValueTask<IReadOnlyList<RecentEvent>> GetRecentEventsAsync(Guid? tenantId, int max, CancellationToken cancellationToken);
}

public sealed record RecentEvent(DateTimeOffset At, Guid TenantId, string EventType, string RecipientDomain, string? Detail);

public enum MessageEventType : byte
{
    Queued = 0,
    Delivered,
    Deferred,
    Bounced,
    Expired,
    Suppressed,
    Cancelled,
    Complained,
    AbortedBySwitch,
    PossibleDuplicate,
    Opened,
}

public sealed record MessageEvent(
    Guid EventId,
    Guid MessageId,
    Guid? DeliveryId,
    Guid TenantId,
    MessageEventType Type,
    DateTimeOffset At,
    string? Recipient,
    int? SmtpCode,
    string? EnhancedCode,
    string? Message,
    string? MxHost,
    string? Route,
    TlsInfo? Tls);

public sealed record MessageSummary(
    Guid MessageId,
    Guid TenantId,
    DateTimeOffset ReceivedAt,
    string? Subject,
    string EnvelopeFrom,
    int RecipientCount,
    string? Status,
    long Size);

public sealed record MessageDetail(MessageSummary Summary, MessageContent? Content, ContentState ContentState, IReadOnlyList<string> Recipients, bool RawRetained);

/// <summary>Whether stored content is available (reuses the earlier body_expired state).</summary>
public enum ContentState : byte
{
    Available = 0,
    Expired,
    NotRecorded,
}

public sealed record MessageQuery(
    Guid? TenantId = null,
    string? Recipient = null,
    string? Sender = null,
    string? SubjectContains = null,
    string? Status = null,
    DateTimeOffset? From = null,
    DateTimeOffset? To = null,
    int Limit = 50,
    string? Cursor = null);

public sealed record Page<T>(IReadOnlyList<T> Items, string? NextCursor);

/// <summary>Per-message history; only meaningful when <see cref="HistoryMode.Full"/>.</summary>
public interface IHistoryStore
{
    ValueTask<Page<MessageSummary>> SearchAsync(MessageQuery query, CancellationToken cancellationToken);

    /// <summary>Returns null when the message is unknown or past <c>Retention:MetadataDays</c>.</summary>
    ValueTask<MessageDetail?> GetAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken);

    ValueTask<IReadOnlyList<MessageEvent>> GetEventsAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken);

    /// <summary>Raw message for resend/download when attachment storage retained it; null otherwise.</summary>
    ValueTask<byte[]?> GetRetainedRawAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken);
}

public enum WebhookOutboxState : byte
{
    Pending = 0,
    Delivered,
    Failed,
}

public sealed class WebhookOutboxItem
{
    public required Guid Id { get; init; }
    public required Guid EndpointId { get; init; }
    public required Guid TenantId { get; init; }
    public required string EventType { get; init; }
    public required Guid EventId { get; init; }
    public required string PayloadJson { get; init; }
    public required int Attempt { get; init; }
    public required DateTimeOffset NextAttemptAt { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
}

public sealed record WebhookAttemptRecord(
    Guid OutboxId,
    DateTimeOffset At,
    int? StatusCode,
    TimeSpan Duration,
    string? ErrorClass,
    string? ResponseSnippet);

public interface IWebhookOutbox
{
    ValueTask<IReadOnlyList<WebhookOutboxItem>> ClaimDueAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken);

    /// <summary>Records the attempt and either schedules the next one, marks the item delivered, or marks it failed (state change in the same commit).</summary>
    ValueTask CompleteAsync(Guid outboxId, WebhookAttemptRecord attempt, WebhookOutboxState newState, DateTimeOffset? nextAttemptAt, CancellationToken cancellationToken);

    ValueTask<IReadOnlyList<WebhookAttemptRecord>> GetAttemptsAsync(Guid tenantId, Guid endpointId, int max, CancellationToken cancellationToken);

    /// <summary>Re-queues a finished or failed outbox item for manual replay.</summary>
    ValueTask<bool> ReplayAsync(Guid tenantId, Guid outboxId, DateTimeOffset now, CancellationToken cancellationToken);
}

public sealed record MaintenanceReport(string Job, TimeSpan Duration, long RowsAffected, string? Detail);

public sealed record StorageHealth(
    bool Ready,
    IReadOnlyList<string> Warnings,
    IReadOnlyDictionary<string, string> Details);

/// <summary>Background upkeep: retention, partitions or batched deletes, rollups, vacuum, backups, integrity.</summary>
public interface IStorageMaintenance
{
    /// <summary>Runs every due job once (retention, rollup, partition creation, checkpoint…). Idempotent; safe to call from several replicas.</summary>
    ValueTask<IReadOnlyList<MaintenanceReport>> RunAsync(DateTimeOffset now, CancellationToken cancellationToken);

    ValueTask<StorageHealth> GetHealthAsync(CancellationToken cancellationToken);

    /// <summary>Consistent online backup (SQLite: <c>VACUUM INTO</c> per file; PostgreSQL: not supported, use pg_dump).</summary>
    ValueTask<string?> BackupAsync(string directory, CancellationToken cancellationToken);
}
