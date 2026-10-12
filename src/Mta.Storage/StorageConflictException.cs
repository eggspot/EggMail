namespace Mta.Storage;

/// <summary>Raised when a write violates a uniqueness or key constraint (for example a duplicate tenant slug).</summary>
public sealed class StorageConflictException(string message, Exception? inner = null) : InvalidOperationException(message, inner);
