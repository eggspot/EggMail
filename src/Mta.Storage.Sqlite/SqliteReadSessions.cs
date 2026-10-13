using System.Collections.Concurrent;
using System.Diagnostics;
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

    /// <summary>The pool generation current when the session was rented or opened (read before the connection was opened, see <see cref="SqliteReadSessionPool.Rent"/>).</summary>
    internal int Generation { get; }

    /// <summary>When the session was last given back (<see cref="Stopwatch.GetTimestamp"/>).</summary>
    internal long IdleSince { get; set; }

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
/// The idle read sessions of one file. A session is rented for one read and returned. At most <see cref="MaxIdle"/> are kept and a session
/// idle for longer than <see cref="IdleLifetime"/> is closed. <see cref="Clear"/> closes the idle ones and retires the rented ones (they close
/// when returned), which is what releasing the file for a move or a quarantine needs; <see cref="Close"/> does that for good (the storage
/// was disposed): afterwards a read still works but its session is never kept.
/// </summary>
internal sealed class SqliteReadSessionPool
{
    internal const int MaxIdle = 64;

    internal static readonly TimeSpan DefaultIdleLifetime = TimeSpan.FromSeconds(60);

    private readonly Func<SqliteConnection> _open;
    private readonly ConcurrentBag<SqliteReadSession> _idle = [];
    private int _idleCount;
    private int _generation;
    private volatile bool _closed;
    private long _lastPrune = long.MinValue;   // when idle sessions were last looked at; MinValue until the first return

    public SqliteReadSessionPool(SqliteFile file)
        : this(file.OpenReader)
    {
    }

    /// <summary>A pool over any way of opening a connection (tests use it to interleave a release with an open).</summary>
    internal SqliteReadSessionPool(Func<SqliteConnection> open)
    {
        _open = open;
    }

    /// <summary>How long a session may sit idle before it is closed.</summary>
    internal TimeSpan IdleLifetime { get; set; } = DefaultIdleLifetime;

    /// <summary>The clock (<see cref="Stopwatch.GetTimestamp"/>); tests replace it instead of waiting.</summary>
    internal Func<long> Timestamp { get; set; } = Stopwatch.GetTimestamp;

    /// <summary>Test hook: runs inside <see cref="Return"/> after the checks and before the session is put away.</summary>
    internal Action? BeforeKeep { get; set; }

    /// <summary>Sessions waiting for a read.</summary>
    internal int IdleCount => Volatile.Read(ref _idleCount);

    public ReadLease Rent()
    {
        // The generation is read BEFORE anything else: a Clear that runs while the connection below is being opened must leave this session
        // marked as belonging to the older generation, so that Return closes it instead of keeping a connection that was meant to be released.
        int generation = Volatile.Read(ref _generation);
        while (_idle.TryTake(out SqliteReadSession? session))
        {
            Interlocked.Decrement(ref _idleCount);
            if (session.Generation == generation)
            {
                return new ReadLease(this, session);
            }

            session.Dispose();
        }

        return new ReadLease(this, new SqliteReadSession(_open(), generation));
    }

    internal void Return(SqliteReadSession session)
    {
        if (_closed || session.Generation != Volatile.Read(ref _generation) || Volatile.Read(ref _idleCount) >= MaxIdle)
        {
            session.Dispose();
            return;
        }

        session.IdleSince = Timestamp();
        BeforeKeep?.Invoke();
        _idle.Add(session);
        Interlocked.Increment(ref _idleCount);

        // A Clear (or Close) that ran after the check above and before the Add did not see this session: look again, and drain what is stale.
        if (_closed || session.Generation != Volatile.Read(ref _generation))
        {
            DrainStale();
        }
        else
        {
            PruneIdle();
        }
    }

    /// <summary>Closes every idle session; sessions in use are closed when they come back.</summary>
    public void Clear()
    {
        Interlocked.Increment(ref _generation);
        DrainStale();
    }

    /// <summary>The storage was disposed: closes the idle sessions and keeps no session from now on.</summary>
    public void Close()
    {
        _closed = true;
        Clear();
    }

    private void DrainStale()
    {
        int generation = Volatile.Read(ref _generation);
        var keep = new List<SqliteReadSession>();
        while (_idle.TryTake(out SqliteReadSession? session))
        {
            Interlocked.Decrement(ref _idleCount);
            if (!_closed && session.Generation == generation)
            {
                keep.Add(session);
            }
            else
            {
                session.Dispose();
            }
        }

        foreach (SqliteReadSession session in keep)
        {
            _idle.Add(session);
            Interlocked.Increment(ref _idleCount);
        }
    }

    /// <summary>Closes sessions that have been idle for longer than <see cref="IdleLifetime"/>; looks at most once per half lifetime.</summary>
    private void PruneIdle()
    {
        long now = Timestamp();
        long last = Volatile.Read(ref _lastPrune);
        if (last == long.MinValue)
        {
            Interlocked.CompareExchange(ref _lastPrune, now, long.MinValue);
            return;
        }

        if (Stopwatch.GetElapsedTime(last, now) < IdleLifetime / 2 || Interlocked.CompareExchange(ref _lastPrune, now, last) != last)
        {
            return;
        }

        var keep = new List<SqliteReadSession>();
        while (_idle.TryTake(out SqliteReadSession? session))
        {
            Interlocked.Decrement(ref _idleCount);
            if (Stopwatch.GetElapsedTime(session.IdleSince, now) > IdleLifetime)
            {
                session.Dispose();
            }
            else
            {
                keep.Add(session);
            }
        }

        foreach (SqliteReadSession session in keep)
        {
            _idle.Add(session);
            Interlocked.Increment(ref _idleCount);
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
