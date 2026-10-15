namespace Mta.Storage;

/// <summary>
/// The storage backend cannot be reached right now (for example PostgreSQL is down, restarting, out of connections or
/// the network failed). The condition is expected to be transient: the SMTP layer answers <c>451</c> and the caller may
/// retry. It is distinct from a programming or data error, which keeps its own exception type. The SQLite backend is
/// in-process and raises only its subclass <see cref="StorageFullException"/>.
/// </summary>
public class StorageUnavailableException(string message, Exception? inner = null) : InvalidOperationException(message, inner);

/// <summary>
/// The disk holding the database is full (SQLite <c>SQLITE_FULL</c>). Transient like any unavailability, but the SMTP layer says so with
/// <c>452 4.3.1</c> (insufficient system storage) so that an operator reading the client's log knows what to free.
/// </summary>
public sealed class StorageFullException(string message, Exception? inner = null) : StorageUnavailableException(message, inner);
