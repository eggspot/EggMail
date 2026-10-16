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

    /// <summary>
    /// The message's header section is internationalized (RFC 6532 UTF-8 header fields), so every transaction that carries it needs
    /// SMTPUTF8 whatever the addresses. Decided once at intake (<see cref="AcceptedMessage.HeadersUtf8"/>) and copied to each recipient's row.
    /// </summary>
    public bool HeadersUtf8 { get; set; }

    /// <summary>
    /// Backend switch hold (design §4.6): when set, the row cannot be claimed. On the source it is the transfer mark
    /// <c>transferred(switch_id)</c>, on the target it keeps imported rows from being dispatched until activation.
    /// </summary>
    public Guid? TransferSwitchId { get; set; }
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

    /// <summary>Backend switch hold, see <see cref="QueuedDeliveryEntity.TransferSwitchId"/>.</summary>
    public Guid? TransferSwitchId { get; set; }
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

/// <summary>
/// One received message for one recipient (<c>inbound_message</c>, queue part): the metadata, the verification results and the state of the route
/// action. The body is in <see cref="InboundMessageRawEntity"/>. Queue-like: pending actions are claimed with a lease, and the switch holds rows
/// with <see cref="TransferSwitchId"/> like deliveries.
/// </summary>
public sealed class InboundMessageEntity
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid DomainId { get; set; }
    public string Domain { get; set; } = "";
    public DateTimeOffset ReceivedAt { get; set; }
    public string RemoteAddress { get; set; } = "";
    public string? Helo { get; set; }
    public bool TlsUsed { get; set; }

    /// <summary>Lower-case <c>local@domain</c>; empty for the null reverse-path.</summary>
    public string EnvelopeFrom { get; set; } = "";

    /// <summary>Lower-case <c>local@domain</c>.</summary>
    public string EnvelopeTo { get; set; } = "";
    public string? Subject { get; set; }
    public long Size { get; set; }
    public InboundVerdict Spf { get; set; }
    public string? SpfDomain { get; set; }
    public InboundVerdict SpfHelo { get; set; }
    public InboundVerdict Dkim { get; set; }
    public string? DkimDomain { get; set; }
    public InboundVerdict Dmarc { get; set; }
    public string? DmarcPolicy { get; set; }
    public InboundVerdict Arc { get; set; }
    public InboundDmarcDisposition Disposition { get; set; }
    public Guid? RouteId { get; set; }
    public InboundActionKind ActionKind { get; set; }
    public InboundActionState ActionState { get; set; }
    public int ActionAttempts { get; set; }

    /// <summary>Incremented by every manual retry; part of the webhook id.</summary>
    public int RetryGeneration { get; set; }
    public DateTimeOffset? ActionNextAttemptAt { get; set; }
    public DateTimeOffset? ActionFinishedAt { get; set; }
    public string? ActionLastError { get; set; }

    /// <summary>A short code for a completion the tenant should know about (see <see cref="InboundActionOutcome.Note"/>).</summary>
    public string? ActionNote { get; set; }
    public Guid? ForwardMessageId { get; set; }

    /// <summary>The body row exists.</summary>
    public bool HasRaw { get; set; }
    public string? LeaseOwner { get; set; }

    /// <summary>Grows with every claim and never goes down (a release and a retry leave it alone): the token a completion has to present.</summary>
    public long ClaimSequence { get; set; }

    /// <summary>Unix epoch when not leased; an action is claimable when this is not after "now".</summary>
    public DateTimeOffset LeaseUntil { get; set; }

    /// <summary>Backend switch hold, see <see cref="QueuedDeliveryEntity.TransferSwitchId"/>.</summary>
    public Guid? TransferSwitchId { get; set; }
}

/// <summary>The stored message of an <see cref="InboundMessageEntity"/> (<c>inbound_message_raw</c>), separate so lists and claims never read it.</summary>
public sealed class InboundMessageRawEntity
{
    public Guid MessageId { get; set; }
    public Guid TenantId { get; set; }
    public byte[] Raw { get; set; } = [];
}

