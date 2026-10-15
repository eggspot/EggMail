using System.Diagnostics;
using System.Threading.Channels;
using System.Threading.Tasks.Sources;
using Microsoft.Data.Sqlite;
using Mta.Core;

namespace Mta.Storage.Sqlite;

/// <summary>A SQL statement with ordered parameter names; prepared once per writer and reused (design §3: no per-call parsing).</summary>
internal sealed class Stmt(string sql, params string[] parameters)
{
    public string Sql { get; } = sql;

    public string[] Parameters { get; } = parameters;
}

/// <summary>What a command can touch while it runs on the writer thread.</summary>
internal sealed class WriterContext(SqliteConnection connection)
{
    private readonly Dictionary<Stmt, PreparedCommand> _commands = [];

    public SqliteConnection Connection { get; } = connection;

    /// <summary>True while a transaction is open on the connection (SQLite's own answer: the connection is not in autocommit mode).</summary>
    public bool InTransaction => SQLitePCL.raw.sqlite3_get_autocommit(Connection.Handle) == 0;

    /// <summary>The open batch transaction, or null for an exclusive (non-transactional) command.</summary>
    public SqliteTransaction? Transaction { get; set; }

    /// <summary>
    /// Returns the statement prepared on the writer's connection (cached per statement). It runs on that connection, so it takes part in the
    /// open batch transaction by itself.
    /// </summary>
    public PreparedCommand Command(Stmt stmt)
    {
        if (!_commands.TryGetValue(stmt, out PreparedCommand? cmd))
        {
            cmd = new PreparedCommand(Connection.Handle ?? throw new InvalidOperationException("The writer connection is not open."), stmt);
            _commands[stmt] = cmd;
        }

        return cmd;
    }

    public void Dispose()
    {
        foreach (PreparedCommand c in _commands.Values)
        {
            c.Dispose();
        }

        _commands.Clear();
    }
}

/// <summary>Counters for the dashboard's advisory storage-pressure indicator and for tests.</summary>
public sealed class WriterMetrics
{
    private long _batches;
    private long _commands;
    private long _failedBatches;
    private long _maxBatch;
    private long _lastBatch;
    private long _lastCommitTicks;
    private long _totalCommitTicks;
    private long _maxCommitTicks;
    private int _queueDepth;

    public string File { get; init; } = "";

    /// <summary>Committed transactions.</summary>
    public long Batches => Interlocked.Read(ref _batches);

    /// <summary>Commands executed (committed or individually failed).</summary>
    public long Commands => Interlocked.Read(ref _commands);

    /// <summary>Batches that failed as a whole and were replayed one command at a time.</summary>
    public long FailedBatches => Interlocked.Read(ref _failedBatches);

    public long MaxBatchSize => Interlocked.Read(ref _maxBatch);

    public long LastBatchSize => Interlocked.Read(ref _lastBatch);

    public double AverageBatchSize => Batches == 0 ? 0 : (double)Commands / Batches;

    public TimeSpan LastCommit => TimeSpan.FromTicks(Interlocked.Read(ref _lastCommitTicks) * TimeSpan.TicksPerSecond / Stopwatch.Frequency);

    public TimeSpan MaxCommit => TimeSpan.FromTicks(Interlocked.Read(ref _maxCommitTicks) * TimeSpan.TicksPerSecond / Stopwatch.Frequency);

    /// <summary>Commands waiting for the writer (sampled).</summary>
    public int QueueDepth => Volatile.Read(ref _queueDepth);

    internal void SetQueueDepth(int depth) => Volatile.Write(ref _queueDepth, depth);

    internal void RecordBatch(int size, long commitTicks)
    {
        SqliteMetrics.CommitDuration.Record((double)commitTicks / Stopwatch.Frequency, new KeyValuePair<string, object?>("file", File));
        SqliteMetrics.WriterBatchSize.Record(size, new KeyValuePair<string, object?>("file", File));
        Interlocked.Increment(ref _batches);
        Interlocked.Add(ref _commands, size);
        Interlocked.Exchange(ref _lastBatch, size);
        Interlocked.Exchange(ref _lastCommitTicks, commitTicks);
        Interlocked.Add(ref _totalCommitTicks, commitTicks);
        long max;
        while ((max = Interlocked.Read(ref _maxBatch)) < size && Interlocked.CompareExchange(ref _maxBatch, size, max) != max)
        {
        }

        while ((max = Interlocked.Read(ref _maxCommitTicks)) < commitTicks && Interlocked.CompareExchange(ref _maxCommitTicks, commitTicks, max) != max)
        {
        }
    }

    internal void RecordFailedBatch()
    {
        SqliteMetrics.WriterBatchFailures.Add(1, new KeyValuePair<string, object?>("file", File));
        Interlocked.Increment(ref _failedBatches);
    }

    internal void RecordIndividual() => Interlocked.Increment(ref _commands);
}

/// <summary>The statements that open and end a batch, run through the native API like the commands themselves (no driver transaction object per batch).</summary>
internal static class BatchSql
{
    public static readonly Stmt Begin = new("BEGIN IMMEDIATE");

    public static readonly Stmt Commit = new("COMMIT");

    public static readonly Stmt Rollback = new("ROLLBACK");
}

internal abstract class WriterCommand
{
    /// <summary>Runs alone, outside any transaction (checkpoint, incremental_vacuum).</summary>
    internal bool Exclusive;

    /// <summary>
    /// The command hands <see cref="WriterContext.Transaction"/> to a library (Entity Framework) and so needs the batch to run in a driver
    /// transaction. Every other command only uses the native statements, which take part in whatever transaction is open on the connection.
    /// </summary>
    internal bool NeedsDriverTransaction;

    internal abstract void Execute(WriterContext context);

    internal abstract void Succeed();

    internal abstract void Fail(Exception exception);
}

/// <summary>
/// One unit of work for the writer. It doubles as the awaitable, and it is reused: after the caller has taken the result (or the exception) with
/// <c>GetResult</c>, the object goes back to a small pool of its closed generic type, so a submission allocates nothing in the steady state.
/// <para>
/// Like every <see cref="ValueTask{TResult}"/> over an <see cref="IValueTaskSource{TResult}"/>, the task of a command must be awaited (or
/// <c>AsTask</c>ed) exactly once and not touched afterwards; a second <c>GetResult</c> with the old token is refused by the version check and does not
/// recycle anything. Nothing here is used by the writer after it has called <see cref="Succeed"/> or <see cref="Fail"/>, which is when the caller may
/// take the object back, and the state and result are cleared when it is recycled so a pooled command keeps no message alive.
/// </para>
/// </summary>
internal sealed class WriterCommand<TState, TResult> : WriterCommand, IValueTaskSource<TResult>
{
    private const int MaxPooled = 1024;

    private static readonly System.Collections.Concurrent.ConcurrentQueue<WriterCommand<TState, TResult>> Pool = new();
    private static int _pooled;

    private ManualResetValueTaskSourceCore<TResult> _core = new() { RunContinuationsAsynchronously = true };
    private TState _state = default!;
    private Func<WriterContext, TState, TResult> _work = null!;
    private TResult _result = default!;

    private WriterCommand()
    {
    }

    /// <summary>A command for <paramref name="work"/> over <paramref name="state"/>, from the pool when it has one.</summary>
    internal static WriterCommand<TState, TResult> Rent(TState state, Func<WriterContext, TState, TResult> work, bool exclusive, bool needsDriverTransaction)
    {
        if (!Pool.TryDequeue(out WriterCommand<TState, TResult>? command))
        {
            command = new WriterCommand<TState, TResult>();
        }
        else
        {
            Interlocked.Decrement(ref _pooled);
        }

        command._state = state;
        command._work = work;
        command.Exclusive = exclusive;
        command.NeedsDriverTransaction = needsDriverTransaction;
        return command;
    }

    internal short Version => _core.Version;

    internal override void Execute(WriterContext context) => _result = _work(context, _state);

    internal override void Succeed() => _core.SetResult(_result);

    internal override void Fail(Exception exception) => _core.SetException(exception);

    TResult IValueTaskSource<TResult>.GetResult(short token)
    {
        if (token != _core.Version)
        {
            return _core.GetResult(token);   // throws: a stale or repeated await must not recycle the command that now belongs to someone else
        }

        try
        {
            return _core.GetResult(token);
        }
        finally
        {
            Recycle();
        }
    }

    ValueTaskSourceStatus IValueTaskSource<TResult>.GetStatus(short token) => _core.GetStatus(token);

    void IValueTaskSource<TResult>.OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags) =>
        _core.OnCompleted(continuation, state, token, flags);

    private void Recycle()
    {
        _core.Reset();
        _state = default!;
        _work = null!;
        _result = default!;
        Exclusive = false;
        NeedsDriverTransaction = false;
        if (Interlocked.Increment(ref _pooled) <= MaxPooled)
        {
            Pool.Enqueue(this);
        }
        else
        {
            Interlocked.Decrement(ref _pooled);
        }
    }
}

/// <summary>
/// The single writer of one database file (design §4.4): callers submit commands through a bounded channel and await the
/// result; a dedicated thread drains up to <c>WriterMaxBatch</c> commands into one <c>BEGIN IMMEDIATE … COMMIT</c> (group
/// commit) and completes them after the commit returned. With <c>synchronous=FULL</c> the thread also lingers up to
/// <c>WriterBatchWindow</c> for more commands, because there one fsync per commit is what group commit amortizes; under
/// <c>OFF</c>/<c>NORMAL</c> a commit does no fsync, so it commits as soon as the queue is momentarily empty and batches
/// still grow whenever commands arrive faster than commits finish.
/// <para>
/// If any command of a batch throws, the whole batch is rolled back and its commands are replayed one by one, each in its
/// own transaction, so one bad command (a constraint violation) fails alone. Commands must therefore be repeatable and
/// keep side effects outside the database out of <c>Execute</c>.
/// </para>
/// </summary>
internal sealed class SqliteFileWriter : IAsyncDisposable
{
    private readonly SqliteFile _file;
    private readonly SqliteOptions _options;
    private readonly Channel<WriterCommand> _channel;
    private readonly Thread _thread;
    private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Action? _onRollback;
    private readonly bool _linger;
    private int _disposed;
    private SqliteConnection? _connection;

    public SqliteFileWriter(SqliteFile file, SqliteOptions options, Action? onRollback = null)
    {
        _file = file;
        _options = options;
        _onRollback = onRollback;
        _linger = file.Sync == SqliteSyncMode.Full && options.WriterBatchWindow > TimeSpan.Zero;
        Metrics = new WriterMetrics { File = file.FileName };
        _channel = Channel.CreateBounded<WriterCommand>(new BoundedChannelOptions(options.WriterQueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false,
        });
        _thread = new Thread(Run) { IsBackground = true, Name = "eggmail-sqlite-" + file.Name };
    }

    public WriterMetrics Metrics { get; }

    /// <summary>Commands waiting in the queue right now (a live read, unlike the sampled <see cref="WriterMetrics.QueueDepth"/>).</summary>
    public int PendingCommands => _channel.Reader.Count;

    public SqliteFile File => _file;

    /// <summary>Starts the thread and waits until the connection is open and the schema exists.</summary>
    public async Task StartAsync()
    {
        _thread.Start();
        await _ready.Task.ConfigureAwait(false);
    }

    /// <summary>
    /// Queues <paramref name="work"/> and returns when its batch has committed. The token only cancels the wait for queue
    /// space (back-pressure); a command already queued is always executed.
    /// </summary>
    public ValueTask<TResult> SubmitAsync<TState, TResult>(TState state, Func<WriterContext, TState, TResult> work, CancellationToken cancellationToken = default, bool exclusive = false, bool needsDriverTransaction = false)
    {
        var command = WriterCommand<TState, TResult>.Rent(state, work, exclusive, needsDriverTransaction);
        ValueTask<TResult> awaitable = new(command, command.Version);
        if (_channel.Writer.TryWrite(command))
        {
            return awaitable;
        }

        return SubmitSlowAsync(command, awaitable, cancellationToken);
    }

    private async ValueTask<TResult> SubmitSlowAsync<TState, TResult>(WriterCommand<TState, TResult> command, ValueTask<TResult> awaitable, CancellationToken cancellationToken)
    {
        try
        {
            await _channel.Writer.WriteAsync(command, cancellationToken).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            throw new ObjectDisposedException(nameof(SqliteFileWriter), $"The {_file.FileName} writer is closed.");
        }

        return await awaitable.ConfigureAwait(false);
    }

    private void Run()
    {
        WriterContext context;
        try
        {
            _connection = _file.OpenWriter();
            context = new WriterContext(_connection);
            _ready.SetResult();
        }
        catch (Exception ex)
        {
            _ready.SetException(ex);
            return;
        }

        var batch = new List<WriterCommand>(_options.WriterMaxBatch);
        ChannelReader<WriterCommand> reader = _channel.Reader;
        WriterCommand? carried = null;
        try
        {
            while (true)
            {
                WriterCommand? first = carried;
                carried = null;
                if (first is null && !reader.TryRead(out first))
                {
                    if (!reader.WaitToReadAsync().AsTask().GetAwaiter().GetResult())
                    {
                        break;
                    }

                    continue;
                }

                if (first.Exclusive)
                {
                    RunExclusive(context, first);
                    continue;
                }

                batch.Clear();
                batch.Add(first);
                long deadline = _linger ? Stopwatch.GetTimestamp() + (long)(_options.WriterBatchWindow.TotalSeconds * Stopwatch.Frequency) : 0;
                while (batch.Count < _options.WriterMaxBatch)
                {
                    if (reader.TryRead(out WriterCommand? next))
                    {
                        if (next.Exclusive)
                        {
                            carried = next;
                            break;
                        }

                        batch.Add(next);
                        continue;
                    }

                    if (!_linger || !WaitForMore(reader, deadline))
                    {
                        break;
                    }
                }

                Metrics.SetQueueDepth(reader.Count);
                ExecuteBatch(context, batch);
            }
        }
        finally
        {
            context.Dispose();
            _connection.Dispose();
        }
    }

    /// <summary>Waits until more commands arrive or the linger window ends. Returns true when a command may be available.</summary>
    private static bool WaitForMore(ChannelReader<WriterCommand> reader, long deadline)
    {
        long remaining = deadline - Stopwatch.GetTimestamp();
        if (remaining <= 0)
        {
            return false;
        }

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds((double)remaining / Stopwatch.Frequency));
        try
        {
            return reader.WaitToReadAsync(cts.Token).AsTask().GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private void ExecuteBatch(WriterContext context, List<WriterCommand> batch)
    {
        bool driverTransaction = false;
        for (int i = 0; i < batch.Count; i++)
        {
            if (batch[i].NeedsDriverTransaction)
            {
                driverTransaction = true;
                break;
            }
        }

        bool failed = false;
        long commitStart = 0;
        long commitTicks = 0;
        try
        {
            using SqliteTransaction? tx = Begin(context, driverTransaction);
            context.Transaction = tx;
            try
            {
                foreach (WriterCommand c in batch)
                {
                    c.Execute(context);
                }

                commitStart = Stopwatch.GetTimestamp();
                Commit(context, tx);
                commitTicks = Stopwatch.GetTimestamp() - commitStart;
            }
            catch
            {
                failed = true;
                TryRollback(context, tx);
            }
            finally
            {
                context.Transaction = null;
            }
        }
        catch
        {
            failed = true;
        }

        if (!failed)
        {
            Metrics.RecordBatch(batch.Count, commitTicks);
            foreach (WriterCommand c in batch)
            {
                c.Succeed();
            }

            return;
        }

        Metrics.RecordFailedBatch();
        _onRollback?.Invoke();
        foreach (WriterCommand c in batch)
        {
            RunIndividually(context, c);
        }
    }

    /// <summary>
    /// Opens the batch transaction (<c>BEGIN IMMEDIATE</c>). A batch of native commands uses the prepared statements <see cref="BatchSql"/> and allocates
    /// nothing; only a batch that holds a command for a library that wants a transaction object (<see cref="WriterCommand.NeedsDriverTransaction"/>)
    /// goes through the driver's <c>BeginTransaction</c>, which builds a command, a reader and a rollback hook for it.
    /// </summary>
    private static SqliteTransaction? Begin(WriterContext context, bool driverTransaction)
    {
        if (driverTransaction)
        {
            return context.Connection.BeginTransaction(deferred: false);
        }

        if (context.InTransaction)
        {
            // A transaction left open by a rollback that did not take (it must not be, but a BEGIN inside it would fail every batch from here on): end it first.
            TryRollback(context, null);
        }

        context.Command(BatchSql.Begin).ExecuteNonQuery();
        return null;
    }

    private static void Commit(WriterContext context, SqliteTransaction? tx)
    {
        if (tx is not null)
        {
            tx.Commit();
            return;
        }

        context.Command(BatchSql.Commit).ExecuteNonQuery();
    }

    private void RunIndividually(WriterContext context, WriterCommand command)
    {
        try
        {
            using SqliteTransaction? tx = Begin(context, command.NeedsDriverTransaction);
            context.Transaction = tx;
            try
            {
                command.Execute(context);
                long start = Stopwatch.GetTimestamp();
                Commit(context, tx);
                Metrics.RecordBatch(1, Stopwatch.GetTimestamp() - start);
            }
            catch
            {
                TryRollback(context, tx);
                throw;
            }
            finally
            {
                context.Transaction = null;
            }
        }
        catch (Exception ex)
        {
            _onRollback?.Invoke();
            Metrics.RecordIndividual();
            command.Fail(Translate(ex));
            return;
        }

        command.Succeed();
    }

    /// <summary>
    /// SQLITE_FULL (13, whatever its extended code) becomes <see cref="StorageFullException"/> so the SMTP layer can answer 452 4.3.1; everything else
    /// is passed on as it is. The unix file system layer of SQLite already reports ENOSPC on a write as SQLITE_FULL, so there is no separate
    /// SQLITE_IOERR variant to map.
    /// </summary>
    internal static Exception Translate(Exception ex) =>
        ex is SqliteException { SqliteErrorCode: var code } && (code & 0xFF) == 13 ? new StorageFullException("The disk holding the SQLite files is full (SQLITE_FULL).", ex) : ex;

    private void RunExclusive(WriterContext context, WriterCommand command)
    {
        try
        {
            context.Transaction = null;
            command.Execute(context);
        }
        catch (Exception ex)
        {
            Metrics.RecordIndividual();
            command.Fail(Translate(ex));
            return;
        }

        Metrics.RecordIndividual();
        command.Succeed();
    }

    private static void TryRollback(WriterContext context, SqliteTransaction? tx)
    {
        try
        {
            if (tx is not null)
            {
                tx.Rollback();
            }
            else
            {
                context.Command(BatchSql.Rollback).ExecuteNonQuery();
            }
        }
        catch (Exception)
        {
            // The connection may already have rolled back (for example after SQLITE_FULL); the batch is replayed anyway.
        }

        if (tx is null && context.InTransaction)
        {
            // A native ROLLBACK that failed while the transaction is still open (a statement of the batch had not finished, say): once more, so no batch ever starts inside it.
            try
            {
                context.Command(BatchSql.Rollback).ExecuteNonQuery();
            }
            catch (Exception)
            {
                // Nothing more can be done here; the next Begin tries again before it opens a transaction.
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _channel.Writer.TryComplete();
        if (_thread.IsAlive)
        {
            await Task.Run(() => _thread.Join()).ConfigureAwait(false);
        }
    }
}
