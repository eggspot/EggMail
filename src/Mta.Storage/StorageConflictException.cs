namespace Mta.Storage;

/// <summary>Raised when a write violates a uniqueness or key constraint (for example a duplicate tenant slug) or a rule the store keeps in place of a foreign key.</summary>
public sealed class StorageConflictException : InvalidOperationException
{
    public StorageConflictException(string message, Exception? inner = null)
        : base(message, inner)
    {
    }

    /// <summary>A conflict a caller tells apart from the others: one of <see cref="StorageConflictReasons"/>.</summary>
    public StorageConflictException(string message, string reason)
        : base(message)
    {
        Reason = reason;
    }

    /// <summary>Null for a plain constraint violation.</summary>
    public string? Reason { get; }
}

/// <summary>The reasons a <see cref="StorageConflictException"/> can carry, so callers branch on a value and not on message text.</summary>
public static class StorageConflictReasons
{
    /// <summary>A webhook route names an endpoint that does not exist for its tenant.</summary>
    public const string WebhookEndpointMissing = "webhook_endpoint_missing";

    /// <summary>A webhook endpoint cannot be deleted while an inbound route targets it.</summary>
    public const string WebhookEndpointInUse = "webhook_endpoint_in_use";
}
