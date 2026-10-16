using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace Mta.RemoteMta.Tests.Harness;

/// <summary>A message the fake peer accepted (or, for a peer that accepts and then loses the connection, kept).</summary>
public sealed record ReceivedMessage(
    string Sender,
    IReadOnlyList<string> Recipients,
    byte[] Body,
    bool Tls,
    string? BodyParameter,
    bool SmtpUtf8,
    int ConnectionIndex,
    bool Chunked)
{
    public string Text => Encoding.Latin1.GetString(Body);
}

/// <summary>One connection to a fake peer: its protocol state and a transcript of both directions.</summary>
public sealed class FakeSession
{
    private readonly ConcurrentQueue<string> _transcript = new();

    internal FakeSession(FakeMta server, int index)
    {
        Server = server;
        Index = index;
    }

    public FakeMta Server { get; }

    /// <summary>Zero for the first connection the peer ever accepted.</summary>
    public int Index { get; }

    public bool TlsActive { get; internal set; }

    public string? ClientName { get; internal set; }

    public string? MailFrom { get; internal set; }

    public List<string> Recipients { get; } = [];

    public int AcceptedMessages { get; internal set; }

    /// <summary>Commands that arrived before the reply to the previous command was sent: the peer saw pipelined input.</summary>
    public int PipelinedCommands { get; internal set; }

    /// <summary>Bytes that were already buffered in plaintext when STARTTLS was answered (the injection check).</summary>
    public int PlainBytesBufferedAtStartTls { get; internal set; }

    public IReadOnlyCollection<string> Transcript => _transcript.ToArray();

    /// <summary>The commands the client sent, upper-cased verbs only (<c>EHLO</c>, <c>MAIL</c>, <c>RSET</c> ...), in order.</summary>
    public IReadOnlyList<string> Verbs => _transcript.Where(l => l.StartsWith("C: ", StringComparison.Ordinal)).Select(l => l[3..].Split(' ', 2)[0].ToUpperInvariant()).ToArray();

    internal void Log(string line) => _transcript.Enqueue(line);
}

/// <summary>
/// A fake remote MTA on a loopback port (ephemeral, so tests run in parallel and on shared CI machines). It is a small hand written SMTP
/// server driven by a <see cref="MtaPersonality"/>; it does not use the project's own SMTP server, so a bug in the server code cannot hide a bug in the client.
/// </summary>
public sealed class FakeMta : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _acceptLoop;
    private readonly ConcurrentDictionary<int, (FakeSession Session, Socket Socket)> _open = new();
    private readonly ConcurrentQueue<ReceivedMessage> _messages = new();
    private readonly ConcurrentQueue<FakeSession> _sessions = new();
    private int _connections;
    private int _active;
    private int _maxActive;
    private int _tlsHandshakeFailures;
    private int _tlsHandshakes;

    public FakeMta(MtaPersonality personality, IPAddress? bindTo = null, int port = 0)
    {
        Personality = personality;
        Address = bindTo ?? IPAddress.Loopback;
        _listener = new TcpListener(Address, port);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _acceptLoop = Task.Run(AcceptLoopAsync);
    }

    public MtaPersonality Personality { get; }

    public IPAddress Address { get; }

    public int Port { get; }

    public int ConnectionCount => Volatile.Read(ref _connections);

    public int ActiveConnections => Volatile.Read(ref _active);

    /// <summary>The most connections that were ever open at the same time.</summary>
    public int MaxConcurrentConnectionsSeen => Volatile.Read(ref _maxActive);

    public int TlsHandshakes => Volatile.Read(ref _tlsHandshakes);

    public int TlsHandshakeFailures => Volatile.Read(ref _tlsHandshakeFailures);

    public IReadOnlyList<ReceivedMessage> Messages => _messages.ToArray();

    public IReadOnlyList<FakeSession> Sessions => _sessions.ToArray();

    /// <summary>Waits (polling, with a generous deadline) until the peer has stored <paramref name="count"/> messages.</summary>
    public Task WaitForMessagesAsync(int count) => Wait.UntilAsync(() => _messages.Count >= count, $"{Personality.Name} to hold {count} message(s), has {_messages.Count}");

    /// <summary>Closes every open connection from the server side: a peer that times its idle clients out.</summary>
    public void DropOpenConnections()
    {
        foreach (var (_, socket) in _open.Values)
        {
            try
            {
                socket.Shutdown(SocketShutdown.Both);
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
            }
        }
    }

    private async Task AcceptLoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await _listener.AcceptSocketAsync(_stop.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            socket.NoDelay = true;
            int index = Interlocked.Increment(ref _connections) - 1;
            int active = Interlocked.Increment(ref _active);
            int seen;
            while (active > (seen = Volatile.Read(ref _maxActive)) && Interlocked.CompareExchange(ref _maxActive, active, seen) != seen)
            {
            }

            var session = new FakeSession(this, index);
            _sessions.Enqueue(session);
            _open[index] = (session, socket);
            _ = Task.Run(async () =>
            {
                try
                {
                    await new Connection(this, session, socket, active).RunAsync().ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException or OperationCanceledException or System.Security.Authentication.AuthenticationException)
                {
                    // the peer (the engine under test) went away; that is part of the scenarios
                }
                finally
                {
                    Interlocked.Decrement(ref _active);
                    _open.TryRemove(index, out _);
                    socket.Dispose();
                }
            });
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        _listener.Stop();
        DropOpenConnections();
        try
        {
            await _acceptLoop.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        _stop.Dispose();
    }

    // ---------------------------------------------------------------------------------------------------------------

    private sealed class Connection
    {
        private readonly FakeMta _mta;
        private readonly FakeSession _session;
        private readonly Socket _socket;
        private readonly int _activeAtStart;
        private Stream _stream;
        private readonly byte[] _buffer = new byte[16 * 1024];
        private int _pos;
        private int _len;
        private string? _bodyParameter;
        private bool _smtpUtf8;
        private long _declaredSize = -1;

        public Connection(FakeMta mta, FakeSession session, Socket socket, int activeAtStart)
        {
            _mta = mta;
            _session = session;
            _socket = socket;
            _activeAtStart = activeAtStart;
            _stream = new NetworkStream(socket, ownsSocket: false);
        }

        private MtaPersonality P => _mta.Personality;

        private CancellationToken Stopping => _mta._stop.Token;

        public async Task RunAsync()
        {
            Step greeting = P.MaxConcurrentConnections is { } max && _activeAtStart > max
                ? Step.Reply(421, "4.7.0", "Too many connections from your IP address, try again later").Then(Step.Close())
                : P.Greeting?.Invoke(_session) ?? Step.Reply(220, null, $"{P.Hostname} ESMTP ready");
            if (!await PerformAsync(greeting))
            {
                return;
            }

            while (!Stopping.IsCancellationRequested)
            {
                string? line = await ReadLineAsync();
                if (line is null)
                {
                    return;
                }

                _session.Log("C: " + line);
                if (_pos < _len)
                {
                    _session.PipelinedCommands++;
                }

                if (P.OnCommand?.Invoke(_session, line) is { } scripted)
                {
                    if (!await PerformAsync(scripted))
                    {
                        return;
                    }

                    continue;
                }

                string verb = line.Split(' ', 2)[0].ToUpperInvariant();
                string rest = line.Length > verb.Length ? line[(verb.Length + 1)..] : string.Empty;
                bool keepGoing = verb switch
                {
                    "EHLO" => await HandleHelloAsync(rest, extended: true),
                    "HELO" => await HandleHelloAsync(rest, extended: false),
                    "STARTTLS" => await HandleStartTlsAsync(),
                    "MAIL" => await HandleMailAsync(rest),
                    "RCPT" => await HandleRcptAsync(rest),
                    "DATA" => await HandleDataAsync(),
                    "BDAT" => await HandleBdatAsync(rest),
                    "RSET" => await HandleHousekeepingAsync(line, reset: true),
                    "NOOP" => await HandleHousekeepingAsync(line, reset: false),
                    "QUIT" => await PerformAsync(Step.Reply(221, "2.0.0", $"{P.Hostname} closing connection").Then(Step.Close())) && false,
                    _ => await PerformAsync(Step.Reply(502, "5.5.2", "Error: command not recognized")),
                };
                if (!keepGoing)
                {
                    return;
                }
            }
        }

        // ------------------------------------------------------------------------------------------------ commands

        private async Task<bool> HandleHelloAsync(string clientName, bool extended)
        {
            _session.ClientName = clientName;
            Reset();
            if (!extended)
            {
                return await PerformAsync(Step.Reply(250, null, $"{P.Hostname} Hello {clientName}"));
            }

            if (!P.Esmtp)
            {
                return await PerformAsync(Step.Reply(500, "5.5.1", "Error: unknown command"));
            }

            var lines = new List<string> { $"{P.Hostname} Hello {clientName}" };
            if (P.Pipelining)
            {
                lines.Add("PIPELINING");
            }

            if (P.SizeAdvertised is { } size)
            {
                lines.Add(size == 0 ? "SIZE" : "SIZE " + size);
            }

            if (OffersStartTls())
            {
                lines.Add("STARTTLS");
            }

            if (P.EnhancedStatusCodes)
            {
                lines.Add("ENHANCEDSTATUSCODES");
            }

            if (P.EightBitMime)
            {
                lines.Add("8BITMIME");
            }

            if (P.SmtpUtf8)
            {
                lines.Add("SMTPUTF8");
            }

            if (P.Chunking)
            {
                lines.Add("CHUNKING");
            }

            if (P.Dsn)
            {
                lines.Add("DSN");
            }

            lines.AddRange(P.ExtraCapabilities);
            return await PerformAsync(Step.Reply(250, null, [.. lines]));
        }

        private bool OffersStartTls() => !_session.TlsActive && P.Certificate is not null && (P.OffersStartTls?.Invoke(_session) ?? true);

        private async Task<bool> HandleStartTlsAsync()
        {
            if (_session.TlsActive || P.Certificate is null)
            {
                return await PerformAsync(Step.Reply(503, "5.5.1", "Error: TLS not available"));
            }

            switch (P.StartTls)
            {
                case StartTlsBehaviour.Refuses454:
                    return await PerformAsync(Step.Reply(454, "4.7.0", "TLS not available due to temporary reason"));
                case StartTlsBehaviour.ClosesAfter220:
                    await PerformAsync(Step.Reply(220, "2.0.0", "Ready to start TLS"));
                    return false;
                case StartTlsBehaviour.PlainTextAfter220:
                    await PerformAsync(Step.Reply(220, "2.0.0", "Ready to start TLS"));
                    await PerformAsync(Step.Raw("SSH-2.0-this is not a TLS server\r\n"));
                    return false;
                case StartTlsBehaviour.InjectsAfter220:
                    // 220 and, in the same segment, a plaintext line the client would read as a reply once TLS is up (CVE-2011-0411 and friends).
                    await PerformAsync(Step.Raw("220 2.0.0 Ready to start TLS\r\n250 2.0.0 injected before the handshake\r\n"));
                    return false;
                case StartTlsBehaviour.ResetsMidHandshake:
                    await PerformAsync(Step.Reply(220, "2.0.0", "Ready to start TLS"));
                    await FillAsync();
                    return false;
            }

            await PerformAsync(Step.Reply(220, "2.0.0", "Ready to start TLS"));
            _session.PlainBytesBufferedAtStartTls = _len - _pos;
            _pos = _len = 0;
            var ssl = new SslStream(_stream, leaveInnerStreamOpen: false);
            try
            {
                await ssl.AuthenticateAsServerAsync(
                    new SslServerAuthenticationOptions
                    {
                        ServerCertificateSelectionCallback = (_, sni) => P.Certificate(sni),
                        EnabledSslProtocols = P.TlsProtocols,
                    },
                    Stopping);
            }
            catch (Exception ex) when (ex is System.Security.Authentication.AuthenticationException or IOException)
            {
                Interlocked.Increment(ref _mta._tlsHandshakeFailures);
                await ssl.DisposeAsync();
                return false;
            }

            Interlocked.Increment(ref _mta._tlsHandshakes);
            _stream = ssl;
            _session.TlsActive = true;
            return true;
        }

        private async Task<bool> HandleMailAsync(string rest)
        {
            if (P.MaxMessagesPerConnection is { } cap && _session.AcceptedMessages >= cap)
            {
                return await PerformAsync(Step.Reply(421, "4.7.0", "Too many messages on this connection, closing").Then(Step.Close())) && false;
            }

            string path = ExtractPath(rest, "FROM:");
            var parameters = ParseParameters(rest);
            _bodyParameter = parameters.GetValueOrDefault("BODY");
            _smtpUtf8 = parameters.ContainsKey("SMTPUTF8");
            _declaredSize = parameters.TryGetValue("SIZE", out string? sz) && long.TryParse(sz, out long n) ? n : -1;
            if (P.SizeEnforced is { } limit && _declaredSize > limit)
            {
                return await PerformAsync(Step.Reply(552, "5.3.4", "Message size exceeds fixed maximum message size"));
            }

            var step = P.OnMail?.Invoke(_session, path, parameters) ?? Step.Reply(250, "2.1.0", "Ok");
            if (step.IsPositive)
            {
                _session.MailFrom = path;
                _session.Recipients.Clear();
            }

            return await PerformAsync(step);
        }

        private async Task<bool> HandleRcptAsync(string rest)
        {
            if (_session.MailFrom is null)
            {
                return await PerformAsync(Step.Reply(503, "5.5.1", "Error: need MAIL command"));
            }

            string path = ExtractPath(rest, "TO:");
            if (P.MaxRecipientsPerTransaction is { } max && _session.Recipients.Count >= max)
            {
                return await PerformAsync(Step.Reply(452, "4.5.3", "Error: too many recipients"));
            }

            var step = P.OnRcpt?.Invoke(_session, path) ?? Step.Reply(250, "2.1.5", "Ok");
            if (step.IsPositive)
            {
                _session.Recipients.Add(path);
            }

            return await PerformAsync(step);
        }

        private async Task<bool> HandleDataAsync()
        {
            if (_session.MailFrom is null || _session.Recipients.Count == 0)
            {
                return await PerformAsync(Step.Reply(503, "5.5.1", "Error: need RCPT command"));
            }

            Step go = P.OnData?.Invoke(_session) ?? Step.Reply(354, null, "End data with <CR><LF>.<CR><LF>");
            if (!go.IsIntermediate())
            {
                return await PerformAsync(go);
            }

            if (!await PerformAsync(go))
            {
                return false;
            }

            var body = new MemoryStream();
            while (true)
            {
                string? line = await ReadLineAsync();
                if (line is null)
                {
                    return false;
                }

                if (line == ".")
                {
                    break;
                }

                if (line.StartsWith("..", StringComparison.Ordinal))
                {
                    line = line[1..];
                }

                body.Write(Encoding.Latin1.GetBytes(line));
                body.Write("\r\n"u8);
            }

            return await FinishMessageAsync(body.ToArray(), chunked: false);
        }

        private readonly MemoryStream _bdat = new();

        private async Task<bool> HandleBdatAsync(string rest)
        {
            string[] parts = rest.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (!P.Chunking || parts.Length == 0 || !int.TryParse(parts[0], out int size) || size < 0)
            {
                return await PerformAsync(Step.Reply(503, "5.5.1", "Error: BDAT not available"));
            }

            bool last = parts.Length > 1 && parts[1].Equals("LAST", StringComparison.OrdinalIgnoreCase);
            var chunk = new byte[size];
            if (!await ReadExactAsync(chunk))
            {
                return false;
            }

            _bdat.Write(chunk);
            if (!last)
            {
                return await PerformAsync(Step.Reply(250, "2.0.0", $"{size} octets received"));
            }

            byte[] all = _bdat.ToArray();
            _bdat.SetLength(0);
            return await FinishMessageAsync(all, chunked: true);
        }

        private async Task<bool> FinishMessageAsync(byte[] body, bool chunked)
        {
            var message = new ReceivedMessage(_session.MailFrom ?? string.Empty, _session.Recipients.ToArray(), body, _session.TlsActive, _bodyParameter, _smtpUtf8, _session.Index, chunked);
            Step verdict;
            var context = new EndOfDataContext(message);
            if (P.SizeEnforced is { } limit && body.Length > limit)
            {
                verdict = Step.Reply(552, "5.3.4", "Message size exceeds fixed maximum message size");
            }
            else
            {
                verdict = P.OnEndOfData?.Invoke(_session, context) ?? Step.Reply(250, "2.0.0", $"Ok: queued as {Guid.NewGuid().ToString("N")[..10].ToUpperInvariant()}");
            }

            if (verdict.IsPositive || context.Keep)
            {
                _mta._messages.Enqueue(message);
                _session.AcceptedMessages++;
            }

            Reset();
            return await PerformAsync(verdict);
        }

        private async Task<bool> HandleHousekeepingAsync(string line, bool reset)
        {
            if (reset)
            {
                Reset();
            }

            return await PerformAsync(P.OnHousekeeping?.Invoke(_session, line) ?? Step.Reply(250, "2.0.0", "Ok"));
        }

        private void Reset()
        {
            _session.MailFrom = null;
            _session.Recipients.Clear();
            _bdat.SetLength(0);
        }

        // --------------------------------------------------------------------------------------------------- I/O

        /// <summary>Does a step; false when the connection is over.</summary>
        private async Task<bool> PerformAsync(Step step)
        {
            switch (step.What)
            {
                case Step.Kind.Reply:
                    string text = step.Format(P.EnhancedStatusCodes);
                    _session.Log("S: " + text.TrimEnd().Replace("\r\n", " | "));
                    await WriteAsync(Encoding.Latin1.GetBytes(text));
                    return true;
                case Step.Kind.Raw:
                    _session.Log("S: <raw " + step.Bytes.Length + " bytes>");
                    await WriteAsync(step.Bytes);
                    return true;
                case Step.Kind.Drip:
                    _session.Log("S: <dripped " + step.Bytes.Length + " bytes>");
                    for (int i = 0; i < step.Bytes.Length; i += step.ChunkSize)
                    {
                        await WriteAsync(step.Bytes.AsMemory(i, Math.Min(step.ChunkSize, step.Bytes.Length - i)));
                        await Task.Delay(1, Stopping);
                    }

                    return true;
                case Step.Kind.Close:
                    _session.Log("S: <close>");
                    try
                    {
                        _socket.Shutdown(SocketShutdown.Both);
                    }
                    catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                    {
                    }

                    return false;
                case Step.Kind.Abort:
                    _session.Log("S: <reset>");
                    _socket.LingerState = new LingerOption(true, 0);
                    _socket.Close();
                    return false;
                case Step.Kind.Hang:
                    _session.Log("S: <silence>");
                    try
                    {
                        await Task.Delay(Timeout.Infinite, Stopping);
                    }
                    catch (OperationCanceledException)
                    {
                    }

                    return false;
                case Step.Kind.Gated:
                    await step.Gate!.WaitAsync(Stopping);
                    return await PerformAsync(step.Steps[0]);
                default:
                    foreach (var inner in step.Steps)
                    {
                        if (!await PerformAsync(inner))
                        {
                            return false;
                        }
                    }

                    return true;
            }
        }

        private async Task WriteAsync(ReadOnlyMemory<byte> bytes)
        {
            await _stream.WriteAsync(bytes, Stopping);
            await _stream.FlushAsync(Stopping);
        }

        private async Task<bool> FillAsync()
        {
            if (_pos < _len)
            {
                return true;
            }

            _pos = _len = 0;
            int read = await _stream.ReadAsync(_buffer, Stopping);
            if (read <= 0)
            {
                return false;
            }

            _len = read;
            return true;
        }

        private async Task<string?> ReadLineAsync()
        {
            var line = new List<byte>();
            while (true)
            {
                if (!await FillAsync())
                {
                    return null;
                }

                while (_pos < _len)
                {
                    byte b = _buffer[_pos++];
                    if (b == (byte)'\n')
                    {
                        if (line.Count > 0 && line[^1] == (byte)'\r')
                        {
                            line.RemoveAt(line.Count - 1);
                        }

                        return Encoding.Latin1.GetString(line.ToArray());
                    }

                    line.Add(b);
                    if (line.Count > 1_000_000)
                    {
                        return null;
                    }
                }
            }
        }

        private async Task<bool> ReadExactAsync(byte[] target)
        {
            int got = 0;
            while (got < target.Length)
            {
                if (!await FillAsync())
                {
                    return false;
                }

                int take = Math.Min(_len - _pos, target.Length - got);
                Buffer.BlockCopy(_buffer, _pos, target, got, take);
                _pos += take;
                got += take;
            }

            return true;
        }

        private static string ExtractPath(string rest, string keyword)
        {
            int start = rest.IndexOf('<');
            int end = rest.IndexOf('>');
            if (start >= 0 && end > start)
            {
                return rest[(start + 1)..end];
            }

            return rest.StartsWith(keyword, StringComparison.OrdinalIgnoreCase) ? rest[keyword.Length..].Trim() : rest;
        }

        private static Dictionary<string, string> ParseParameters(string rest)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            int end = rest.IndexOf('>');
            string tail = end >= 0 ? rest[(end + 1)..] : string.Empty;
            foreach (string token in tail.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = token.IndexOf('=');
                if (eq > 0)
                {
                    result[token[..eq]] = token[(eq + 1)..];
                }
                else
                {
                    result[token] = string.Empty;
                }
            }

            return result;
        }
    }
}

internal static class StepExtensions
{
    /// <summary>True for a 3xx reply (what DATA wants before the body).</summary>
    public static bool IsIntermediate(this Step step) => step.What == Step.Kind.Reply && step.Code is >= 300 and < 400;
}
