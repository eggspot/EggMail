using Microsoft.Data.Sqlite;
using System.Data;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>The pool of open read connections: the two races between renting, returning and releasing, the cap, the idle lifetime and the closed state.</summary>
public class ReadSessionPoolTests
{
    private static SqliteConnection Open()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        return connection;
    }

    [Fact]
    public void A_release_while_a_connection_is_being_opened_does_not_let_that_session_be_kept()
    {
        // Clear runs inside the open: the session being built belongs to the generation that was current when Rent started, so it is stale.
        SqliteReadSessionPool pool = null!;
        pool = new SqliteReadSessionPool(() =>
        {
            pool.Clear();
            return Open();
        });

        var lease = pool.Rent();
        SqliteConnection connection = lease.Session.Connection;
        lease.Dispose();

        Assert.Equal(0, pool.IdleCount);
        Assert.Equal(ConnectionState.Closed, connection.State);
    }

    [Fact]
    public void A_release_between_the_check_in_return_and_putting_the_session_away_is_noticed()
    {
        var pool = new SqliteReadSessionPool(Open);
        var lease = pool.Rent();
        SqliteConnection connection = lease.Session.Connection;
        pool.BeforeKeep = pool.Clear;   // the release lands after Return decided to keep the session and before it is added

        lease.Dispose();

        Assert.Equal(0, pool.IdleCount);
        Assert.Equal(ConnectionState.Closed, connection.State);
    }

    [Fact]
    public void A_session_returned_after_a_release_is_closed_and_one_returned_before_it_is_closed_by_it()
    {
        var pool = new SqliteReadSessionPool(Open);
        var kept = pool.Rent();
        var inUse = pool.Rent();
        SqliteConnection keptConnection = kept.Session.Connection;
        SqliteConnection inUseConnection = inUse.Session.Connection;
        kept.Dispose();
        Assert.Equal(1, pool.IdleCount);
        Assert.Equal(ConnectionState.Open, keptConnection.State);

        pool.Clear();
        Assert.Equal(0, pool.IdleCount);
        Assert.Equal(ConnectionState.Closed, keptConnection.State);
        Assert.Equal(ConnectionState.Open, inUseConnection.State);   // still in use: closed when it comes back

        inUse.Dispose();
        Assert.Equal(0, pool.IdleCount);
        Assert.Equal(ConnectionState.Closed, inUseConnection.State);

        var again = pool.Rent();   // the pool is usable after a release
        again.Dispose();
        Assert.Equal(1, pool.IdleCount);
    }

    [Fact]
    public void At_most_the_cap_is_kept_idle()
    {
        var pool = new SqliteReadSessionPool(Open);
        var leases = Enumerable.Range(0, SqliteReadSessionPool.MaxIdle + 6).Select(_ => pool.Rent()).ToList();
        foreach (var lease in leases)
        {
            lease.Dispose();
        }

        Assert.Equal(SqliteReadSessionPool.MaxIdle, pool.IdleCount);
        Assert.Equal(6, leases.Count(l => l.Session.Connection.State == ConnectionState.Closed));
    }

    [Fact]
    public void A_closed_pool_keeps_nothing_but_still_serves_a_read()
    {
        var pool = new SqliteReadSessionPool(Open);
        pool.Rent().Dispose();
        Assert.Equal(1, pool.IdleCount);

        pool.Close();
        Assert.Equal(0, pool.IdleCount);

        var lease = pool.Rent();
        SqliteConnection connection = lease.Session.Connection;
        Assert.Equal(ConnectionState.Open, connection.State);
        lease.Dispose();
        Assert.Equal(0, pool.IdleCount);
        Assert.Equal(ConnectionState.Closed, connection.State);
    }

    [Fact]
    public void A_session_idle_for_longer_than_the_lifetime_is_closed_by_the_next_return()
    {
        long second = System.Diagnostics.Stopwatch.Frequency;
        long now = 0;
        var pool = new SqliteReadSessionPool(Open) { IdleLifetime = TimeSpan.FromSeconds(60), Timestamp = () => now };
        var old = pool.Rent();
        SqliteConnection oldConnection = old.Session.Connection;
        old.Dispose();   // idle since t = 0

        now = 100 * second;
        var fresh = pool.Rent();   // a rent reuses the idle session; only a return prunes
        Assert.Same(oldConnection, fresh.Session.Connection);
        var other = pool.Rent();
        SqliteConnection otherConnection = other.Session.Connection;
        other.Dispose();                      // idle since t = 100
        now = 200 * second;
        fresh.Dispose();                      // returned at t = 200: prunes what has been idle for more than 60 s
        Assert.Equal(ConnectionState.Closed, otherConnection.State);
        Assert.Equal(1, pool.IdleCount);
        Assert.Equal(ConnectionState.Open, oldConnection.State);   // the one just returned is fresh
    }
}
