using System.Collections.Concurrent;
using Microsoft.Data.Sqlite;

namespace Mta.Storage.Sqlite;

/// <summary>
/// A read connection that stays open together with the statements prepared on it (see <see cref="PreparedCommand"/>). The hot reads of the
/// delivery path (the raw message, the suppression check) run on these instead of opening a pooled connection, building a command and a
/// data reader for every call, which cost several KB and, through EF Core, registered the SQL functions of the provider again on every open.
/// </summary>
internal sealed class SqliteReadSession : IDisposable
{
    private readonly Dictionary<Stmt, PreparedCommand> _commands = [];

    internal SqliteReadSession(SqliteConnection connection, int generation)
    {
        Connection = connection;
        Generation = generation;
    }

    internal SqliteConnection Connection { get; }

    internal int Generation { get; }

    /// <summary>The statement prepared on this session's connection (cached per statement).</summary>
    public PreparedCommand Command(Stmt stmt)
    {
        if (!_commands.TryGetValue(stmt, out PreparedCommand? command))
        {
            command = new PreparedCommand(Connection.Handle ?? throw new InvalidOperationException("The read connection is not open."), stmt);
            _commands[stmt] = command;
        }

        return command;
    }

    public void Dispose()
    {
        foreach (PreparedCommand c in _commands.Values)
        {
            c.Dispose();
        }

        _commands.Clear();
        Connection.Dispose();
    }
}

/// <summary>
/// The idle read sessions of one file. A session is rented for one read and returned; at most <see cref="MaxIdle"/> are kept, the others
/// are closed. <see cref="Clear"/> closes the idle ones and retires the rented ones (they close when returned), which is what releasing the
/// file for a move, a backup or a delete needs.
/// </summary>
internal sealed class SqliteReadSessionPool(SqliteFile file)
{
    private const int MaxIdle = 64;

    private readonly ConcurrentBag<SqliteReadSession> _idle = [];
    private int _idleCount;
    private int _generation;

    public ReadLease Rent()
    {
        while (_idle.TryTake(out SqliteReadSession? session))
        {
            Interlocked.Decrement(ref _idleCount);
            if (session.Generation == Volatile.Read(ref _generation))
            {
                return new ReadLease(this, session);
            }

            session.Dispose();
        }

        return new ReadLease(this, new SqliteReadSession(file.OpenReader(), Volatile.Read(ref _generation)));
    }

    internal void Return(SqliteReadSession session)
    {
        if (session.Generation != Volatile.Read(ref _generation) || Volatile.Read(ref _idleCount) >= MaxIdle)
        {
            session.Dispose();
            return;
        }

        _idle.Add(session);
        Interlocked.Increment(ref _idleCount);
    }

    /// <summary>Closes every idle session; sessions in use are closed when they come back.</summary>
    public void Clear()
    {
        Interlocked.Increment(ref _generation);
        while (_idle.TryTake(out SqliteReadSession? session))
        {
            Interlocked.Decrement(ref _idleCount);
            session.Dispose();
        }
    }
}

/// <summary>A rented <see cref="SqliteReadSession"/>; dispose it to give the session back.</summary>
internal readonly struct ReadLease : IDisposable
{
    private readonly SqliteReadSessionPool _pool;

    internal ReadLease(SqliteReadSessionPool pool, SqliteReadSession session)
    {
        _pool = pool;
        Session = session;
    }

    public SqliteReadSession Session { get; }

    public void Dispose() => _pool.Return(Session);
}
