namespace Mta.Storage.Model;

// Entities of the "history" model part (history.db on SQLite; empty under History:Mode=StatsOnly).
//
// Every table is keyed with a leading Day = the UTC day embedded in the message's UUIDv7 id (days since 1970-01-01), so
// retention is a range delete over a key prefix (decision L). All rows of one message share one day, which keeps
// metadata retention consistent and lets the day be derived from the id without a lookup.

/// <summary>One row per message (<c>message_index</c>): the summary used by search and the detail view.</summary>
public sealed class MessageIndexEntity
{
    public int Day { get; set; }
    public Guid MessageId { get; set; }
    public Guid TenantId { get; set; }
    public DateTimeOffset ReceivedAt { get; set; }

    /// <summary>Null when subjects are not stored (<c>Content:StoreSubject=false</c>) or the message had none.</summary>
    public string? Subject { get; set; }
    public string EnvelopeFrom { get; set; } = "";
    public int RecipientCount { get; set; }
    public int FinalCount { get; set; }
    public int DeliveredCount { get; set; }
    public int FailedCount { get; set; }
    public string Status { get; set; } = "queued";
    public long Size { get; set; }

    /// <summary>Content was recorded at accept time (distinguishes Expired from NotRecorded).</summary>
    public bool ContentRecorded { get; set; }
    public bool RawRetained { get; set; }

    /// <summary>The Message-ID header of the message, normalized by <c>MessageIdKey</c> (no angle brackets, lower case): how an asynchronous bounce finds its message. Null for messages stored before schema version 4.</summary>
    public string? MessageIdHeader { get; set; }

    /// <summary>The tags of the API send as a JSON array of strings; null when there are none.</summary>
    public string? Tags { get; set; }
}

public sealed class MessageRecipientEntity
{
    public int Day { get; set; }
    public Guid MessageId { get; set; }

    /// <summary>Recipient address as <c>local@domain</c>, lower-cased for matching.</summary>
    public string Recipient { get; set; } = "";
}

public sealed class MessageEventEntity
{
    public int Day { get; set; }
    public Guid MessageId { get; set; }
    public Guid EventId { get; set; }
    public Guid? DeliveryId { get; set; }
    public Guid TenantId { get; set; }
    public MessageEventType Type { get; set; }
    public DateTimeOffset At { get; set; }
    public string? Recipient { get; set; }
    public int? SmtpCode { get; set; }
    public string? EnhancedCode { get; set; }
    public string? Message { get; set; }
    public string? MxHost { get; set; }
    public string? Route { get; set; }
    public string? TlsJson { get; set; }
}

public sealed class MessageContentEntity
{
    public int Day { get; set; }
    public Guid MessageId { get; set; }
    public Guid TenantId { get; set; }
    public string? Subject { get; set; }
    public string? Text { get; set; }
    public string? Html { get; set; }
    public string AttachmentsJson { get; set; } = "[]";
    public bool Truncated { get; set; }
}

/// <summary>Raw message kept after delivery when attachment storage is enabled (<c>message_raw_retained</c>).</summary>
public sealed class RetainedRawEntity
{
    public int Day { get; set; }
    public Guid MessageId { get; set; }
    public Guid TenantId { get; set; }
    public byte[] Raw { get; set; } = [];
    public DateTimeOffset RetainedAt { get; set; }
}
