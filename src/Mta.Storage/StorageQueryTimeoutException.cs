namespace Mta.Storage;

/// <summary>
/// A read took longer than the database allows for it (PostgreSQL <c>statement_timeout</c> on the read-only role, design section 4.3). The database is reachable, so
/// this is not <see cref="StorageUnavailableException"/>: retrying the same query will time out again, the caller should narrow it (a smaller time range, more filters).
/// </summary>
public sealed class StorageQueryTimeoutException(string message, Exception? inner = null) : InvalidOperationException(message, inner);
