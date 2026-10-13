namespace Mta.Storage;

/// <summary>
/// The storage backend cannot be reached right now (for example PostgreSQL is down, restarting, out of connections or
/// the network failed). The condition is expected to be transient: the SMTP layer answers <c>451</c> and the caller may
/// retry. It is distinct from a programming or data error, which keeps its own exception type. The SQLite backend is
/// in-process and never raises it.
/// </summary>
public sealed class StorageUnavailableException(string message, Exception? inner = null) : InvalidOperationException(message, inner);
