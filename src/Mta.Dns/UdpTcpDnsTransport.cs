using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Mta.Dns;

/// <summary>
/// The production <see cref="IDnsTransport"/>: sends each query over UDP from a fresh socket (so every query uses a
/// new random ephemeral source port chosen by the OS), switches to TCP when the answer is truncated, and fails over
/// across the configured servers.
/// </summary>
/// <remarks>
/// <para>
/// Anti-spoofing: the UDP socket is connected to the server, so the kernel drops datagrams from any other address
/// or port; every datagram must additionally match the query's ID and question section (<see cref="DnsWire.IsResponseTo"/>,
/// exact case when 0x20 is on). Non-matching datagrams are ignored, not treated as the answer, so a spoofing
/// attempt cannot force an error (it can only race the real answer, and would need ID plus source port).
/// </para>
/// <para>
/// Failover: for each of up to <see cref="DnsResolverOptions.Attempts"/> rounds every server that has not failed
/// definitively is tried in order, with the per-attempt timeout growing by <see cref="DnsResolverOptions.BackoffMultiplier"/>
/// each round. A server that answers SERVFAIL, REFUSED, NOTIMP or FORMERR, or whose socket fails (connection
/// refused, unreachable), is not asked again for this query. The server that last produced a usable answer is asked
/// first on the next query. If every server gave a definitive failure the last such response is returned (so the
/// caller sees the rcode); if nothing answered at all a <see cref="DnsException"/> is thrown.
/// </para>
/// Thread-safe; holds no sockets between queries.
/// </remarks>
public sealed class UdpTcpDnsTransport : IDnsTransport
{
    private const int UdpReceiveBufferSize = DnsWire.MaxMessageLength;

    private readonly IPEndPoint[] _servers;
    private readonly DnsResolverOptions _options;
    private int _preferredServer;

    public UdpTcpDnsTransport(DnsResolverOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        if (options.Servers.Count == 0)
        {
            throw new ArgumentException("At least one DNS server must be configured.", nameof(options));
        }

        _options = options;
        _servers = [.. options.Servers];
    }

    public async ValueTask<ReadOnlyMemory<byte>> ExchangeAsync(ReadOnlyMemory<byte> query, CancellationToken cancellationToken)
    {
        if (!DnsWire.TryReadHeader(query.Span, out var header) || header.QuestionCount != 1
            || !DnsWire.TryGetQuestionLength(query.Span, out _) || query.Length > DnsWire.MaxMessageLength)
        {
            throw new ArgumentException("The query is not a well-formed single-question DNS message.", nameof(query));
        }

        cancellationToken.ThrowIfCancellationRequested();

        int serverCount = _servers.Length;
        var finished = new bool[serverCount];
        int live = serverCount;
        int first = Volatile.Read(ref _preferredServer) % serverCount;
        byte[]? softFailure = null;
        DnsException? last = null;
        var timeout = _options.AttemptTimeout;

        for (int round = 0; round < _options.Attempts && live > 0; round++)
        {
            for (int k = 0; k < serverCount && !cancellationToken.IsCancellationRequested; k++)
            {
                int index = (first + k) % serverCount;
                if (finished[index])
                {
                    continue;
                }

                try
                {
                    byte[] response = await QueryServerAsync(_servers[index], query, timeout, cancellationToken).ConfigureAwait(false);
                    var rcode = DnsWire.TryReadHeader(response, out var rh) ? rh.Rcode : DnsRcode.ServerFailure;
                    if (rcode is DnsRcode.ServerFailure or DnsRcode.Refused or DnsRcode.NotImplemented or DnsRcode.FormatError)
                    {
                        softFailure = response;
                        finished[index] = true;
                        live--;
                        continue;
                    }

                    Volatile.Write(ref _preferredServer, index);
                    return response;
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    last = new DnsException($"DNS server {_servers[index]} did not answer within {timeout.TotalMilliseconds:0} ms.", DnsFailureReason.Timeout);
                }
                catch (SocketException ex)
                {
                    last = new DnsException($"DNS server {_servers[index]} is unreachable: {ex.SocketErrorCode}.", DnsFailureReason.Network, ex);
                    finished[index] = true;
                    live--;
                }
                catch (IOException ex)
                {
                    last = new DnsException($"I/O error talking to DNS server {_servers[index]}: {ex.Message}", DnsFailureReason.Network, ex);
                }
                catch (DnsException ex)
                {
                    last = ex;
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
            timeout = TimeSpan.FromTicks((long)Math.Min(timeout.Ticks * _options.BackoffMultiplier, _options.MaxAttemptTimeout.Ticks));
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (softFailure is not null)
        {
            return softFailure;
        }

        throw last ?? new DnsException("No DNS server answered.", DnsFailureReason.Timeout);
    }

    private async Task<byte[]> QueryServerAsync(IPEndPoint server, ReadOnlyMemory<byte> query, TimeSpan timeout, CancellationToken cancellationToken)
    {
        byte[] response = await QueryUdpAsync(server, query, timeout, cancellationToken).ConfigureAwait(false);
        if (!DnsWire.TryReadHeader(response, out var header) || !header.Truncated)
        {
            return response;
        }

        if (!_options.EnableTcpFallback)
        {
            throw new DnsException($"DNS server {server} truncated the response and TCP fallback is disabled.", DnsFailureReason.ResponseMismatch);
        }

        return await QueryTcpAsync(server, query, timeout, cancellationToken).ConfigureAwait(false);
    }

    private async Task<byte[]> QueryUdpAsync(IPEndPoint server, ReadOnlyMemory<byte> query, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);

        // A new socket per query: connect() binds an OS-chosen ephemeral port, different for every query.
        using var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        await socket.ConnectAsync(server, cts.Token).ConfigureAwait(false);
        await socket.SendAsync(query, SocketFlags.None, cts.Token).ConfigureAwait(false);

        byte[] buffer = ArrayPool<byte>.Shared.Rent(UdpReceiveBufferSize);
        try
        {
            while (true)
            {
                int received = await socket.ReceiveAsync(buffer.AsMemory(), SocketFlags.None, cts.Token).ConfigureAwait(false);
                if (received >= DnsWire.HeaderLength && DnsWire.IsResponseTo(query.Span, buffer.AsSpan(0, received), _options.Use0x20))
                {
                    return buffer.AsSpan(0, received).ToArray();
                }

                // Anything else (wrong ID or question, garbage) is ignored: keep waiting for the real answer until the timeout.
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async Task<byte[]> QueryTcpAsync(IPEndPoint server, ReadOnlyMemory<byte> query, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);

        using var socket = new Socket(server.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        await socket.ConnectAsync(server, cts.Token).ConfigureAwait(false);

        byte[] framed = ArrayPool<byte>.Shared.Rent(query.Length + 2);
        try
        {
            BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
            query.CopyTo(framed.AsMemory(2));
            await SendAllAsync(socket, framed.AsMemory(0, query.Length + 2), cts.Token).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(framed);
        }

        byte[] prefix = new byte[2];
        await ReceiveExactlyAsync(socket, prefix, cts.Token).ConfigureAwait(false);
        int length = BinaryPrimitives.ReadUInt16BigEndian(prefix);
        if (length < DnsWire.HeaderLength)
        {
            throw new DnsException($"DNS server {server} sent a TCP response of {length} bytes.", DnsFailureReason.MalformedResponse);
        }

        byte[] response = new byte[length];
        await ReceiveExactlyAsync(socket, response, cts.Token).ConfigureAwait(false);
        if (!DnsWire.IsResponseTo(query.Span, response, _options.Use0x20))
        {
            throw new DnsException($"DNS server {server} sent a TCP response that does not match the query.", DnsFailureReason.ResponseMismatch);
        }

        return response;
    }

    private static async Task SendAllAsync(Socket socket, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        while (!data.IsEmpty)
        {
            int sent = await socket.SendAsync(data, SocketFlags.None, cancellationToken).ConfigureAwait(false);
            data = data[sent..];
        }
    }

    private static async Task ReceiveExactlyAsync(Socket socket, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        while (!buffer.IsEmpty)
        {
            int n = await socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false);
            if (n == 0)
            {
                throw new DnsException("The DNS server closed the TCP connection before sending a full response.", DnsFailureReason.Network);
            }

            buffer = buffer[n..];
        }
    }
}
