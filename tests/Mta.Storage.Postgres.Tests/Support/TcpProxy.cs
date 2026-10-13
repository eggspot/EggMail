using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Mta.Storage.Postgres.Tests;

/// <summary>
/// A minimal TCP forwarder between the storage and the test PostgreSQL, so a test can cut the "network" (close the listener and
/// every open connection) and bring it back on the same port. This is how an outage is simulated without touching the shared server.
/// </summary>
internal sealed class TcpProxy : IAsyncDisposable
{
    private readonly IPEndPoint _target;
    private readonly ConcurrentDictionary<TcpClient, byte> _open = new();
    private TcpListener? _listener;
    private CancellationTokenSource _cts = new();

    public TcpProxy(string targetHost, int targetPort)
    {
        _target = new IPEndPoint(IPAddress.Parse(targetHost), targetPort);
        Port = Start(0);
    }

    public int Port { get; private set; }

    private int Start(int port)
    {
        _cts = new CancellationTokenSource();
        _listener = new TcpListener(IPAddress.Loopback, port);
        _listener.Start();
        _ = AcceptLoopAsync(_listener, _cts.Token);
        return ((IPEndPoint)_listener.LocalEndpoint).Port;
    }

    /// <summary>The server becomes unreachable: refuses new connections and drops the open ones.</summary>
    public void Cut()
    {
        _cts.Cancel();
        _listener?.Stop();
        foreach (TcpClient c in _open.Keys)
        {
            c.Close();
        }

        _open.Clear();
    }

    /// <summary>The server is reachable again on the same port.</summary>
    public void Restore() => Start(Port);

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client = await listener.AcceptTcpClientAsync(ct);
                _ = PumpAsync(client, ct);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException or InvalidOperationException)
        {
        }
    }

    private async Task PumpAsync(TcpClient client, CancellationToken ct)
    {
        var upstream = new TcpClient();
        try
        {
            await upstream.ConnectAsync(_target, ct);
            _open[client] = 0;
            _open[upstream] = 0;
            Task a = client.GetStream().CopyToAsync(upstream.GetStream(), ct);
            Task b = upstream.GetStream().CopyToAsync(client.GetStream(), ct);
            await Task.WhenAny(a, b);
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException or InvalidOperationException)
        {
        }
        finally
        {
            client.Close();
            upstream.Close();
            _open.TryRemove(client, out _);
            _open.TryRemove(upstream, out _);
        }
    }

    public ValueTask DisposeAsync()
    {
        Cut();
        return ValueTask.CompletedTask;
    }
}
