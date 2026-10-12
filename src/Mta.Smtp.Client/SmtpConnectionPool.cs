using System.Collections.Concurrent;
using Mta.Core;

namespace Mta.Smtp.Client;

/// <summary>
/// Keeps a few idle connections per remote target so consecutive deliveries to the same MX skip the connect, banner,
/// EHLO and TLS handshake. Concurrency limits per destination are the delivery scheduler's job, not the pool's.
/// </summary>
public sealed class SmtpConnectionPool : IAsyncDisposable
{
    private readonly SmtpClientOptions _options;
    private readonly IClock _clock;
    private readonly int _maxIdlePerTarget;
    private readonly int _maxIdleTotal;
    private readonly TimeSpan _idleTimeout;
    private readonly int _maxTransactionsPerConnection;
    private readonly ConcurrentDictionary<string, ConcurrentStack<SmtpClientConnection>> _idle = new();
    private readonly Timer _reaper;
    private int _idleCount;
    private bool _disposed;

    public SmtpConnectionPool(SmtpClientOptions options, IClock? clock = null, int maxIdlePerTarget = 2, int maxIdleTotal = 256,
        TimeSpan? idleTimeout = null, int maxTransactionsPerConnection = 100)
    {
        _options = options;
        _clock = clock ?? SystemClock.Instance;
        _maxIdlePerTarget = maxIdlePerTarget;
        _maxIdleTotal = maxIdleTotal;
        _idleTimeout = idleTimeout ?? TimeSpan.FromSeconds(30);
        _maxTransactionsPerConnection = maxTransactionsPerConnection;
        _reaper = new Timer(_ => _ = ReapAsync(), null, _idleTimeout, _idleTimeout);
    }

    public int IdleConnections => Volatile.Read(ref _idleCount);

    /// <summary>Gets a ready connection (idle reuse or a fresh connect). Dispose the lease to return or discard it.</summary>
    public async ValueTask<PooledConnection> RentAsync(SmtpRemoteTarget target, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_idle.TryGetValue(target.PoolKey, out var stack))
        {
            while (stack.TryPop(out var candidate))
            {
                Interlocked.Decrement(ref _idleCount);
                if (candidate.IsReusable && _clock.UtcNow - candidate.LastUsedAt < _idleTimeout && await candidate.CheckAliveAsync(ct).ConfigureAwait(false))
                {
                    SmtpClientMetrics.PoolHits.Add(1);
                    return new PooledConnection(this, target.PoolKey, candidate);
                }

                await candidate.DisposeAsync().ConfigureAwait(false);
            }
        }

        var fresh = await SmtpClientConnection.ConnectAsync(target, _options, _clock, ct).ConfigureAwait(false);
        return new PooledConnection(this, target.PoolKey, fresh);
    }

    internal async ValueTask ReturnAsync(string key, SmtpClientConnection connection, bool discard)
    {
        if (discard || _disposed || !connection.IsReusable || connection.TransactionsCompleted >= _maxTransactionsPerConnection ||
            Volatile.Read(ref _idleCount) >= _maxIdleTotal)
        {
            await CloseAsync(connection).ConfigureAwait(false);
            return;
        }

        var stack = _idle.GetOrAdd(key, _ => new ConcurrentStack<SmtpClientConnection>());
        if (stack.Count >= _maxIdlePerTarget)
        {
            await CloseAsync(connection).ConfigureAwait(false);
            return;
        }

        try
        {
            await connection.ResetAsync().ConfigureAwait(false);
        }
        catch (SmtpClientException)
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            return;
        }

        if (!connection.IsReusable)
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            return;
        }

        stack.Push(connection);
        Interlocked.Increment(ref _idleCount);
    }

    private static async ValueTask CloseAsync(SmtpClientConnection c)
    {
        await c.QuitAsync().ConfigureAwait(false);
        await c.DisposeAsync().ConfigureAwait(false);
    }

    private async Task ReapAsync()
    {
        foreach (var (key, stack) in _idle)
        {
            var keep = new List<SmtpClientConnection>();
            while (stack.TryPop(out var c))
            {
                Interlocked.Decrement(ref _idleCount);
                if (c.IsReusable && _clock.UtcNow - c.LastUsedAt < _idleTimeout)
                {
                    keep.Add(c);
                }
                else
                {
                    await CloseAsync(c).ConfigureAwait(false);
                }
            }

            foreach (var c in keep)
            {
                stack.Push(c);
                Interlocked.Increment(ref _idleCount);
            }

            if (stack.IsEmpty)
            {
                _idle.TryRemove(key, out _);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) { return; }
        _disposed = true;
        await _reaper.DisposeAsync().ConfigureAwait(false);
        foreach (var stack in _idle.Values)
        {
            while (stack.TryPop(out var c))
            {
                await CloseAsync(c).ConfigureAwait(false);
            }
        }
    }
}

/// <summary>A connection on loan from the pool.</summary>
public sealed class PooledConnection : IAsyncDisposable
{
    private readonly SmtpConnectionPool _pool;
    private readonly string _key;
    private bool _discard;
    private bool _returned;

    internal PooledConnection(SmtpConnectionPool pool, string key, SmtpClientConnection connection)
    {
        _pool = pool;
        _key = key;
        Connection = connection;
    }

    public SmtpClientConnection Connection { get; }

    /// <summary>Do not return this connection to the pool (after an error or a surprising reply).</summary>
    public void Discard() => _discard = true;

    public async ValueTask DisposeAsync()
    {
        if (_returned) { return; }
        _returned = true;
        await _pool.ReturnAsync(_key, Connection, _discard).ConfigureAwait(false);
    }
}
