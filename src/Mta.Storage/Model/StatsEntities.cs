namespace Mta.Storage.Model;

// Entities of the "stats" model part (stats.db on SQLite).

/// <summary>Hourly and daily counters (<c>stat_aggregate</c>); one table, <see cref="Daily"/> is the first key column.</summary>
public sealed class StatAggregateEntity
{
    public bool Daily { get; set; }

    /// <summary>UTC hour start (hourly) or UTC midnight (daily).</summary>
    public DateTimeOffset PeriodStart { get; set; }
    public Guid TenantId { get; set; }
    public string SendingDomain { get; set; } = "";
    public string RecipientDomain { get; set; } = "";
    public long Accepted { get; set; }
    public long Delivered { get; set; }
    public long Deferred { get; set; }
    public long HardBounce { get; set; }
    public long SoftBounce { get; set; }
    public long Expired { get; set; }
    public long Complained { get; set; }
    public long Rejected { get; set; }
    public long Suppressed { get; set; }
}

/// <summary>Small key/value state of the stats store (e.g. the rollup watermark).</summary>
public sealed class StatMetaEntity
{
    public string Key { get; set; } = "";
    public long Value { get; set; }
}

/// <summary>The content-free recent-events ring (<c>recent_event</c>), bounded by <c>History:RecentEvents</c>.</summary>
public sealed class RecentEventEntity
{
    /// <summary>Monotonic sequence; the ring keeps the highest <c>RecentEvents</c> values.</summary>
    public long Seq { get; set; }
    public DateTimeOffset At { get; set; }
    public Guid TenantId { get; set; }
    public string EventType { get; set; } = "";
    public string RecipientDomain { get; set; } = "";
    public string? Detail { get; set; }
}

/// <summary>One webhook delivery attempt (<c>webhook_attempt</c>). Losing a few rows in a crash is acceptable.</summary>
public sealed class WebhookAttemptEntity
{
    public long Seq { get; set; }
    public Guid OutboxId { get; set; }
    public Guid EndpointId { get; set; }
    public Guid TenantId { get; set; }
    public DateTimeOffset At { get; set; }
    public int? StatusCode { get; set; }
    public long DurationMs { get; set; }
    public string? ErrorClass { get; set; }
    public string? ResponseSnippet { get; set; }
}
