namespace Mta.Storage.Model;

// Entities of the "queue" model part (queue.db on SQLite): the live work set. Rows are short-lived.

/// <summary>One row per recipient delivery (<c>delivery_queue</c>). Deleted when the delivery reaches a final state.</summary>
public sealed class QueuedDeliveryEntity
{
    public Guid Id { get; set; }
    public Guid MessageId { get; set; }
    public Guid TenantId { get; set; }

    /// <summary>Envelope sender as <c>local@domain</c>; empty for the null reverse-path.</summary>
    public string EnvelopeFrom { get; set; } = "";
    public string Recipient { get; set; } = "";
    public string RecipientDomain { get; set; } = "";
    public string? SendingDomain { get; set; }
    public MessageSource Source { get; set; }

    /// <summary>Attempts already made (incremented when a deferral is recorded).</summary>
    public int Attempt { get; set; }

    /// <summary>Earliest time the next attempt may start.</summary>
    public DateTimeOffset DueAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>Null when not leased.</summary>
    public string? LeaseOwner { get; set; }

    /// <summary>Unix epoch (0) when not leased; a row is claimable when this is not after "now".</summary>
    public DateTimeOffset LeaseUntil { get; set; }
    public string? LastError { get; set; }
    public bool PossibleDuplicate { get; set; }
}

/// <summary>The verbatim message (<c>message_spool</c>), kept until every recipient is final.</summary>
public sealed class SpoolMessageEntity
{
    public Guid MessageId { get; set; }
    public Guid TenantId { get; set; }
    public byte[] Raw { get; set; } = [];
    public long Size { get; set; }

    /// <summary>Deliveries not yet final. The spool row is freed when this reaches zero.</summary>
    public int PendingRecipients { get; set; }

    /// <summary>Move the raw message to history.db when the last recipient is final.</summary>
    public bool RetainRaw { get; set; }

    /// <summary>
    /// All recipients are final and the raw message must be copied to retained storage first. The row stays until the
    /// copy is committed (history before spool delete, design §4.4); a reconcile job finishes interrupted hand-overs.
    /// </summary>
    public bool AwaitingRetention { get; set; }
    public DateTimeOffset ReceivedAt { get; set; }
}

/// <summary>Webhook outbox (<c>webhook_outbox</c>), in the queue store so fan-out commits with the delivery completion.</summary>
public sealed class WebhookOutboxEntity
{
    public Guid Id { get; set; }
    public Guid EndpointId { get; set; }
    public Guid TenantId { get; set; }
    public string EventType { get; set; } = "";
    public Guid EventId { get; set; }
    public string PayloadJson { get; set; } = "";

    /// <summary>Attempts already made.</summary>
    public int Attempt { get; set; }
    public DateTimeOffset NextAttemptAt { get; set; }
    public WebhookOutboxState State { get; set; }
    public string? LeaseOwner { get; set; }
    public DateTimeOffset LeaseUntil { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Set when the item reached Delivered or Failed (retention clock).</summary>
    public DateTimeOffset? FinishedAt { get; set; }
}

/// <summary>
/// API idempotency key (<c>api_idempotency_key</c>), unique per tenant. Logically configuration (the switch bundle
/// exports it with config), but on SQLite it lives in queue.db so the duplicate check is atomic with the spool insert.
/// </summary>
public sealed class IdempotencyKeyEntity
{
    public Guid TenantId { get; set; }
    public string IdempotencyKey { get; set; } = "";
    public Guid MessageId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>Digest of the request that used the key (addition); null when the caller did not supply one.</summary>
    public string? Fingerprint { get; set; }
}
