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
    private readonly Dictionary<Stmt, SqliteCommand> _commands = [];

    public SqliteConnection Connection { get; } = connection;

    /// <summary>The open batch transaction, or null for an exclusive (non-transactional) command.</summary>
    public SqliteTransaction? Transaction { get; set; }

    /// <summary>Returns the cached prepared command for a statement, joined to the current transaction.</summary>
    public SqliteCommand Command(Stmt stmt)
    {
        if (!_commands.TryGetValue(stmt, out SqliteCommand? cmd))
        {
            cmd = Connection.CreateCommand();
            cmd.CommandText = stmt.Sql;
            foreach (string p in stmt.Parameters)
            {
                cmd.Parameters.Add(new SqliteParameter(p, null));
            }

            _commands[stmt] = cmd;
        }

        cmd.Transaction = Transaction;
        return cmd;
    }

    public void Dispose()
    {
        foreach (SqliteCommand c in _commands.Values)
        {
            c.Dispose();
        }

        _commands.Clear();
    }
}

internal static class SqliteCommandExtensions
{
    /// <summary>Sets parameter <paramref name="index"/> (null becomes SQL NULL) and returns the command for chaining.</summary>
    public static SqliteCommand Set(this SqliteCommand command, int index, object? value)
    {
        command.Parameters[index].Value = value ?? DBNull.Value;
        return command;
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

    internal void RecordFailedBatch() => Interlocked.Increment(ref _failedBatches);

    internal void RecordIndividual() => Interlocked.Increment(ref _commands);
}

internal abstract class WriterCommand
{
    /// <summary>Runs alone, outside any transaction (checkpoint, incremental_vacuum).</summary>
    internal bool Exclusive;

    internal abstract void Execute(WriterContext context);

    internal abstract void Succeed();

    internal abstract void Fail(Exception exception);
}

/// <summary>One unit of work for the writer. It doubles as the awaitable so a submission costs one allocation.</summary>
internal sealed class WriterCommand<TState, TResult>(TState state, Func<WriterContext, TState, TResult> work) : WriterCommand, IValueTaskSource<TResult>
{
    private ManualResetValueTaskSourceCore<TResult> _core = new() { RunContinuationsAsynchronously = true };
    private TResult _result = default!;

    internal short Version => _core.Version;

    internal override void Execute(WriterContext context) => _result = work(context, state);

    internal override void Succeed() => _core.SetResult(_result);

    internal override void Fail(Exception exception) => _core.SetException(exception);

    TResult IValueTaskSource<TResult>.GetResult(short token) => _core.GetResult(token);

    ValueTaskSourceStatus IValueTaskSource<TResult>.GetStatus(short token) => _core.GetStatus(token);

    void IValueTaskSource<TResult>.OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags) =>
        _core.OnCompleted(continuation, state, token, flags);
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
    public ValueTask<TResult> SubmitAsync<TState, TResult>(TState state, Func<WriterContext, TState, TResult> work, CancellationToken cancellationToken = default, bool exclusive = false)
    {
        var command = new WriterCommand<TState, TResult>(state, work) { Exclusive = exclusive };
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
        SqliteConnection connection = context.Connection;
        bool failed = false;
        long commitStart = 0;
        long commitTicks = 0;
        try
        {
            using SqliteTransaction tx = connection.BeginTransaction(deferred: false);
            context.Transaction = tx;
            try
            {
                foreach (WriterCommand c in batch)
                {
                    c.Execute(context);
                }

                commitStart = Stopwatch.GetTimestamp();
                tx.Commit();
                commitTicks = Stopwatch.GetTimestamp() - commitStart;
            }
            catch
            {
                failed = true;
                TryRollback(tx);
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

    private void RunIndividually(WriterContext context, WriterCommand command)
    {
        try
        {
            using SqliteTransaction tx = context.Connection.BeginTransaction(deferred: false);
            context.Transaction = tx;
            try
            {
                command.Execute(context);
                long start = Stopwatch.GetTimestamp();
                tx.Commit();
                Metrics.RecordBatch(1, Stopwatch.GetTimestamp() - start);
            }
            catch
            {
                TryRollback(tx);
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
            command.Fail(ex);
            return;
        }

        command.Succeed();
    }

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
            command.Fail(ex);
            return;
        }

        Metrics.RecordIndividual();
        command.Succeed();
    }

    private static void TryRollback(SqliteTransaction tx)
    {
        try
        {
            tx.Rollback();
        }
        catch (Exception)
        {
            // The connection may already have rolled back (for example after SQLITE_FULL); the batch is replayed anyway.
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
