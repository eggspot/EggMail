using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Mta.Dns.Tests;

internal sealed record ServerQuery(byte[] Bytes, bool IsTcp, int Sequence, IPEndPoint Remote);

/// <summary>A hand-written loopback DNS server (UDP and TCP on one port) whose behavior is a delegate: return the datagrams to send back (none = stay silent).</summary>
internal sealed class LoopbackDnsServer : IDisposable
{
    private readonly Socket _udp;
    private readonly Socket _tcp;
    private readonly Socket _spoofSocket;
    private readonly CancellationTokenSource _cts = new();
    private readonly Func<ServerQuery, Task<byte[][]>> _handler;
    private int _udpCount;
    private int _tcpCount;
    private int _sequence;

    public LoopbackDnsServer(Func<ServerQuery, Task<byte[][]>> handler, IPAddress? address = null)
    {
        _handler = handler;
        address ??= IPAddress.Loopback;
        Socket udp;
        Socket tcp;
        for (int attempt = 0; ; attempt++)
        {
            udp = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(address, 0));
            int port = ((IPEndPoint)udp.LocalEndPoint!).Port;
            tcp = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                tcp.Bind(new IPEndPoint(address, port));
                break;
            }
            catch (SocketException) when (attempt < 20)
            {
                udp.Dispose();
                tcp.Dispose();
            }
        }

        _udp = udp;
        _tcp = tcp;
        _tcp.Listen(16);
        Endpoint = (IPEndPoint)_udp.LocalEndPoint!;
        _spoofSocket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        _spoofSocket.Bind(new IPEndPoint(address, 0));
        _ = Task.Run(UdpLoopAsync);
        _ = Task.Run(TcpLoopAsync);
    }

    public IPEndPoint Endpoint { get; }

    public int UdpQueries => Volatile.Read(ref _udpCount);

    public int TcpQueries => Volatile.Read(ref _tcpCount);

    public static Task<byte[][]> Reply(params byte[][] datagrams) => Task.FromResult(datagrams);

    public static Task<byte[][]> Silent() => Task.FromResult(Array.Empty<byte[]>());

    /// <summary>Sends a datagram to <paramref name="to"/> from a different source port than the server's own (a spoofing attempt).</summary>
    public void SendFromOtherPort(IPEndPoint to, byte[] data) => _spoofSocket.SendTo(data, to);

    private async Task UdpLoopAsync()
    {
        byte[] buffer = new byte[65535];
        EndPoint any = new IPEndPoint(Endpoint.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                var result = await _udp.ReceiveFromAsync(buffer, SocketFlags.None, any, _cts.Token);
                byte[] query = buffer.AsSpan(0, result.ReceivedBytes).ToArray();
                var remote = (IPEndPoint)result.RemoteEndPoint;
                Interlocked.Increment(ref _udpCount);
                int seq = Interlocked.Increment(ref _sequence);
                _ = Task.Run(async () =>
                {
                    try
                    {
                        foreach (var datagram in await _handler(new ServerQuery(query, false, seq, remote)))
                        {
                            await _udp.SendToAsync(datagram, SocketFlags.None, remote, _cts.Token);
                        }
                    }
                    catch (Exception) when (_cts.IsCancellationRequested)
                    {
                    }
                });
            }
            catch (Exception) when (_cts.IsCancellationRequested)
            {
                return;
            }
            catch (SocketException)
            {
                // ICMP-induced errors on the shared socket; keep serving.
            }
        }
    }

    private async Task TcpLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await _tcp.AcceptAsync(_cts.Token);
            }
            catch (Exception) when (_cts.IsCancellationRequested)
            {
                return;
            }

            _ = Task.Run(() => ServeTcpAsync(client));
        }
    }

    private async Task ServeTcpAsync(Socket client)
    {
        using (client)
        {
            try
            {
                while (true)
                {
                    byte[] prefix = new byte[2];
                    if (!await ReadAsync(client, prefix))
                    {
                        return;
                    }

                    byte[] query = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)];
                    if (!await ReadAsync(client, query))
                    {
                        return;
                    }

                    Interlocked.Increment(ref _tcpCount);
                    int seq = Interlocked.Increment(ref _sequence);
                    foreach (var message in await _handler(new ServerQuery(query, true, seq, (IPEndPoint)client.RemoteEndPoint!)))
                    {
                        byte[] framed = new byte[message.Length + 2];
                        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)message.Length);
                        message.CopyTo(framed, 2);
                        await client.SendAsync(framed, SocketFlags.None, _cts.Token);
                    }
                }
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
            {
            }
        }
    }

    private async Task<bool> ReadAsync(Socket socket, byte[] buffer)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = await socket.ReceiveAsync(buffer.AsMemory(read), SocketFlags.None, _cts.Token);
            if (n == 0)
            {
                return false;
            }

            read += n;
        }

        return true;
    }

    public void Dispose()
    {
        _cts.Cancel();
        _udp.Dispose();
        _tcp.Dispose();
        _spoofSocket.Dispose();
        _cts.Dispose();
    }
}
