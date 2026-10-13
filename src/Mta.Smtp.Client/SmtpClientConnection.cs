using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Mta.Core;
using Mta.Smtp.Protocol;

namespace Mta.Smtp.Client;

/// <summary>
/// One outbound SMTP connection to one remote address: banner, EHLO, optional STARTTLS (policy driven), optional AUTH,
/// then any number of mail transactions. Not thread-safe; use one transaction at a time.
/// </summary>
public sealed class SmtpClientConnection : IAsyncDisposable
{
    private readonly SmtpClientOptions _options;
    private readonly SmtpRemoteTarget _target;
    private readonly IClock _clock;
    private Socket? _socket;
    private Stream _stream = null!;
    private PipeReader _reader = null!;
    private PipeWriter _writer = null!;
    private bool _broken;
    private bool _quit;

    /// <summary>Capabilities from the latest EHLO (after STARTTLS the post-TLS list).</summary>
    public SmtpCapabilities Capabilities { get; private set; } = SmtpCapabilities.None;

    /// <summary>The server's banner reply.</summary>
    public SmtpReply Banner { get; private set; } = null!;

    public SmtpTlsSession TlsSession { get; private set; } = new(false, null, null, null, null, null, SslPolicyErrors.None, false, false, false);

    public SmtpRemoteTarget Target => _target;

    public DateTimeOffset LastUsedAt { get; private set; }

    public int TransactionsCompleted { get; private set; }

    /// <summary>
    /// True once the end of the message data of the current (or last) transaction has begun to be written: the <c>.</c> line after
    /// <c>DATA</c>, or the <c>BDAT … LAST</c> chunk. From then on the server may accept the message even though we never see its reply,
    /// so a transaction cancelled or lost in that state may be a duplicate when retried; before it, nothing can have been accepted.
    /// Reset at the start of every transaction.
    /// </summary>
    public bool EndOfDataStarted { get; private set; }

    /// <summary>False once an I/O error or protocol violation occurred, or after QUIT.</summary>
    public bool IsReusable => !_broken && !_quit && _socket is { Connected: true };

    private SmtpClientConnection(SmtpRemoteTarget target, SmtpClientOptions options, IClock clock)
    {
        _target = target;
        _options = options;
        _clock = clock;
    }

    /// <summary>
    /// Connects and negotiates up to the point where mail can be sent. Throws <see cref="SmtpConnectionException"/>,
    /// <see cref="SmtpGreetingRejectedException"/>, <see cref="SmtpTlsException"/> or <see cref="SmtpProtocolException"/>.
    /// </summary>
    public static async ValueTask<SmtpClientConnection> ConnectAsync(SmtpRemoteTarget target, SmtpClientOptions options, IClock? clock = null, CancellationToken cancellationToken = default)
    {
        var c = new SmtpClientConnection(target, options, clock ?? SystemClock.Instance);
        try
        {
            await c.OpenAsync(cancellationToken).ConfigureAwait(false);
            SmtpClientMetrics.Connections.Add(1);
            return c;
        }
        catch
        {
            await c.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async ValueTask OpenAsync(CancellationToken ct)
    {
        _socket = new Socket(_target.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            if (_target.LocalAddress is not null)
            {
                _socket.Bind(new IPEndPoint(_target.LocalAddress, 0));
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(_options.ConnectTimeout);
            await _socket.ConnectAsync(new IPEndPoint(_target.Address, _target.Port), cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new SmtpConnectionException(SmtpStage.Connect, $"Connect to {_target.Host} ({_target.Address}:{_target.Port}) timed out", timedOut: true);
        }
        catch (SocketException ex)
        {
            throw new SmtpConnectionException(SmtpStage.Connect, $"Connect to {_target.Host} ({_target.Address}:{_target.Port}) failed: {ex.SocketErrorCode}", ex);
        }

        var network = new NetworkStream(_socket, ownsSocket: false);
        AttachStream(network);

        if (_target.Tls.Mode == SmtpTlsMode.Implicit)
        {
            await HandshakeAsync(network, startTlsAdvertised: false, ct).ConfigureAwait(false);
        }

        Banner = await ReadReplyAsync(SmtpStage.Banner, _options.BannerTimeout, ct).ConfigureAwait(false);
        if (!Banner.IsPositiveCompletion)
        {
            throw new SmtpGreetingRejectedException(SmtpStage.Banner, Banner);
        }

        await EhloAsync(ct).ConfigureAwait(false);

        if (_target.Tls.Mode == SmtpTlsMode.StartTls)
        {
            if (Capabilities.StartTls)
            {
                await StartTlsAsync(ct).ConfigureAwait(false);
            }
            else if (_target.Tls.Require)
            {
                throw new SmtpTlsException(TlsFailure.NotAdvertised, $"{_target.Host} did not offer STARTTLS but TLS is required",
                    TlsSession with { StartTlsAdvertised = false });
            }
            else
            {
                TlsSession = TlsSession with { StartTlsAdvertised = false, PlaintextFallback = true };
            }
        }

        if (_target.Credentials is not null)
        {
            await AuthenticateAsync(_target.Credentials, ct).ConfigureAwait(false);
        }

        LastUsedAt = _clock.UtcNow;
    }

    private void AttachStream(Stream stream)
    {
        _stream = stream;
        _reader = PipeReader.Create(stream, new StreamPipeReaderOptions(leaveOpen: true, bufferSize: 4096, minimumReadSize: 1024));
        _writer = PipeWriter.Create(stream, new StreamPipeWriterOptions(leaveOpen: true, minimumBufferSize: 1024));
    }

    // ------------------------------------------------------------ low-level I/O

    private async ValueTask<SmtpReply> ReadReplyAsync(SmtpStage stage, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            while (true)
            {
                var result = await _reader.ReadAsync(cts.Token).ConfigureAwait(false);
                var buffer = result.Buffer;
                var status = SmtpReplyParser.TryParse(buffer, out var reply, out var consumed);
                if (status == ReplyParseStatus.Ok)
                {
                    _reader.AdvanceTo(consumed);
                    return reply!;
                }

                if (status == ReplyParseStatus.Invalid)
                {
                    _broken = true;
                    throw new SmtpProtocolException($"Invalid reply from {_target.Host} at {stage}");
                }

                if (result.IsCompleted)
                {
                    _broken = true;
                    throw new SmtpConnectionException(stage, $"{_target.Host} closed the connection at {stage}");
                }

                _reader.AdvanceTo(buffer.Start, buffer.End);
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            _broken = true;
            throw new SmtpConnectionException(stage, $"Timeout waiting for reply from {_target.Host} at {stage}", timedOut: true);
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            _broken = true;
            throw new SmtpConnectionException(stage, $"Connection to {_target.Host} lost at {stage}: {ex.Message}", ex);
        }
    }

    private async ValueTask FlushAsync(SmtpStage stage, CancellationToken ct)
    {
        try
        {
            var r = await _writer.FlushAsync(ct).ConfigureAwait(false);
            if (r.IsCompleted)
            {
                _broken = true;
                throw new SmtpConnectionException(stage, $"{_target.Host} closed the connection while sending at {stage}");
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            _broken = true;
            throw new SmtpConnectionException(stage, $"Connection to {_target.Host} lost while sending at {stage}: {ex.Message}", ex);
        }
    }

    private void WriteLine(ReadOnlySpan<char> text)
    {
        var span = _writer.GetSpan(Encoding.UTF8.GetMaxByteCount(text.Length) + 2);
        int n = Encoding.UTF8.GetBytes(text, span);
        span[n++] = (byte)'\r';
        span[n++] = (byte)'\n';
        _writer.Advance(n);
    }

    private async ValueTask<SmtpReply> CommandAsync(SmtpStage stage, string command, TimeSpan timeout, CancellationToken ct)
    {
        WriteLine(command);
        await FlushAsync(stage, ct).ConfigureAwait(false);
        return await ReadReplyAsync(stage, timeout, ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------ session setup

    private async ValueTask EhloAsync(CancellationToken ct)
    {
        var reply = await CommandAsync(SmtpStage.Ehlo, $"EHLO {_options.HeloName}", _options.CommandTimeout, ct).ConfigureAwait(false);
        if (!reply.IsPositiveCompletion && reply.Code is 500 or 501 or 502 or 504)
        {
            // Pre-ESMTP server: fall back to HELO with no extensions.
            reply = await CommandAsync(SmtpStage.Ehlo, $"HELO {_options.HeloName}", _options.CommandTimeout, ct).ConfigureAwait(false);
            if (reply.IsPositiveCompletion)
            {
                Capabilities = SmtpCapabilities.None;
                return;
            }
        }

        if (!reply.IsPositiveCompletion)
        {
            throw new SmtpGreetingRejectedException(SmtpStage.Ehlo, reply);
        }

        Capabilities = SmtpCapabilities.Parse(reply.Lines.Skip(1));
    }

    private async ValueTask StartTlsAsync(CancellationToken ct)
    {
        var reply = await CommandAsync(SmtpStage.StartTls, "STARTTLS", _options.CommandTimeout, ct).ConfigureAwait(false);
        if (!reply.IsPositiveCompletion)
        {
            if (_target.Tls.Require)
            {
                throw new SmtpTlsException(TlsFailure.Refused, $"{_target.Host} refused STARTTLS: {reply}", TlsSession with { StartTlsAdvertised = true });
            }

            TlsSession = TlsSession with { StartTlsAdvertised = true, PlaintextFallback = true };
            return;
        }

        // Anything the server sent after its 220 would be a plaintext injection (RFC 3207 §4.2): the reader must be empty.
        if (_reader.TryRead(out var pending) && !pending.Buffer.IsEmpty)
        {
            _broken = true;
            throw new SmtpTlsException(TlsFailure.HandshakeFailed, $"{_target.Host} sent data after STARTTLS before the handshake (possible injection)");
        }

        await _reader.CompleteAsync().ConfigureAwait(false);
        await _writer.CompleteAsync().ConfigureAwait(false);
        var network = (NetworkStream)_stream;
        await HandshakeAsync(network, startTlsAdvertised: true, ct).ConfigureAwait(false);

        // The pre-TLS capability list must be discarded and EHLO re-issued.
        Capabilities = SmtpCapabilities.None;
        await EhloAsync(ct).ConfigureAwait(false);
    }

    private async ValueTask HandshakeAsync(NetworkStream network, bool startTlsAdvertised, CancellationToken ct)
    {
        var tls = _target.Tls;
        var errors = SslPolicyErrors.None;
        bool verified = false;
        X509Certificate? peer = null;
        var ssl = new SslStream(network, leaveInnerStreamOpen: true, (sender, cert, chain, e) =>
        {
            errors = e;
            peer = cert is null ? null : new X509Certificate2(cert);
            bool ok = tls.ValidationCallback is null || tls.ValidationCallback(sender, cert, chain, e);
            verified = e == SslPolicyErrors.None && ok;
            return ok;
        });

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_options.TlsHandshakeTimeout);
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = tls.TargetHost ?? _target.Host,
                EnabledSslProtocols = tls.Protocols,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            }, cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is System.Security.Authentication.AuthenticationException or IOException or OperationCanceledException or SocketException)
        {
            await ssl.DisposeAsync().ConfigureAwait(false);
            _broken = true;
            var failed = new SmtpTlsSession(false, null, null, DescribeSubject(peer), null, null, errors, false, startTlsAdvertised, false);
            SmtpClientMetrics.TlsFailures.Add(1);
            throw new SmtpTlsException(TlsFailure.HandshakeFailed, $"TLS handshake with {_target.Host} failed: {ex.Message}", failed, ex);
        }

        SmtpClientMetrics.TlsHandshakes.Add(1);
        TlsSession = new SmtpTlsSession(
            true,
            ssl.SslProtocol.ToString(),
            ssl.NegotiatedCipherSuite.ToString(),
            DescribeSubject(peer),
            (peer as X509Certificate2)?.Issuer ?? peer?.Issuer,
            peer is X509Certificate2 x ? Convert.ToHexString(SHA256.HashData(x.RawData)) : null,
            errors,
            verified,
            startTlsAdvertised,
            false);
        AttachStream(ssl);
    }

    private static string? DescribeSubject(X509Certificate? c) => c?.Subject;

    private async ValueTask AuthenticateAsync(SmtpCredentials cred, CancellationToken ct)
    {
        if (TlsSession.Used is false && _target.Tls.Mode != SmtpTlsMode.None)
        {
            throw new SmtpTlsException(TlsFailure.NotAdvertised, "Refusing to send credentials without TLS");
        }

        var mechs = Capabilities.AuthMechanisms;
        SmtpReply reply;
        if (mechs.Contains("PLAIN"))
        {
            string ir = Convert.ToBase64String(Encoding.UTF8.GetBytes($"\0{cred.UserName}\0{cred.Password}"));
            reply = await CommandAsync(SmtpStage.Auth, "AUTH PLAIN " + ir, _options.CommandTimeout, ct).ConfigureAwait(false);
        }
        else if (mechs.Contains("LOGIN"))
        {
            reply = await CommandAsync(SmtpStage.Auth, "AUTH LOGIN", _options.CommandTimeout, ct).ConfigureAwait(false);
            if (reply.Code == 334)
            {
                reply = await CommandAsync(SmtpStage.Auth, Sasl.EncodeBase64(cred.UserName), _options.CommandTimeout, ct).ConfigureAwait(false);
            }

            if (reply.Code == 334)
            {
                reply = await CommandAsync(SmtpStage.Auth, Sasl.EncodeBase64(cred.Password), _options.CommandTimeout, ct).ConfigureAwait(false);
            }
        }
        else
        {
            throw new SmtpGreetingRejectedException(SmtpStage.Auth, SmtpReply.Create(504, "5.5.4", "No supported AUTH mechanism offered"));
        }

        if (!reply.IsPositiveCompletion)
        {
            throw new SmtpGreetingRejectedException(SmtpStage.Auth, reply);
        }

        // Capabilities may change after AUTH; refresh.
        await EhloAsync(ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------ transaction

    /// <summary>Sends one message. Network failures throw <see cref="SmtpConnectionException"/>; SMTP-level refusals are reported in the result.</summary>
    public async ValueTask<SmtpSendResult> SendAsync(SmtpEnvelope envelope, ReadOnlyMemory<byte> message, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfZero(envelope.Recipients.Count);
        EndOfDataStarted = false;
        var caps = Capabilities;

        if (caps.Size is > 0 && message.Length > caps.Size)
        {
            return new SmtpSendResult { LocalFailure = LocalFailure.MessageTooLarge, Stage = SmtpStage.MailFrom };
        }

        if (envelope.SmtpUtf8 && !caps.SmtpUtf8)
        {
            return new SmtpSendResult { LocalFailure = LocalFailure.Smtputf8NotSupported, Stage = SmtpStage.MailFrom };
        }

        if (envelope.EightBit && !caps.EightBitMime)
        {
            return new SmtpSendResult { LocalFailure = LocalFailure.EightBitNotSupported, Stage = SmtpStage.MailFrom };
        }

        bool pipelining = _options.Pipelining && caps.Pipelining;
        bool chunking = _options.PreferChunking && caps.Chunking;

        // MAIL FROM
        var mail = new StringBuilder("MAIL FROM:", 64).Append(envelope.From.ToPath());
        if (caps.Size is not null)
        {
            mail.Append(" SIZE=").Append(message.Length);
        }

        if (envelope.SmtpUtf8)
        {
            mail.Append(" SMTPUTF8");
        }

        if (envelope.EightBit)
        {
            mail.Append(" BODY=8BITMIME");
        }

        var results = new List<SmtpRecipientResult>(envelope.Recipients.Count);
        SmtpReply mailReply;
        if (pipelining)
        {
            WriteLine(mail.ToString());
            foreach (var rcpt in envelope.Recipients)
            {
                WriteLine($"RCPT TO:{rcpt.ToPath()}");
            }

            // DATA/BDAT cannot be pipelined blindly with BDAT; with DATA we may send it right behind the last RCPT.
            if (!chunking)
            {
                WriteLine("DATA");
            }

            await FlushAsync(SmtpStage.MailFrom, cancellationToken).ConfigureAwait(false);
            mailReply = await ReadReplyAsync(SmtpStage.MailFrom, _options.CommandTimeout, cancellationToken).ConfigureAwait(false);
            for (int i = 0; i < envelope.Recipients.Count; i++)
            {
                var r = await ReadReplyAsync(SmtpStage.RcptTo, _options.CommandTimeout, cancellationToken).ConfigureAwait(false);
                results.Add(new SmtpRecipientResult { Address = envelope.Recipients[i], Reply = r });
            }

            SmtpReply? dataReply = chunking ? null : await ReadReplyAsync(SmtpStage.Data, _options.DataInitiationTimeout, cancellationToken).ConfigureAwait(false);
            if (!mailReply.IsPositiveCompletion)
            {
                // Server rejected the sender; the pipelined RCPT/DATA were answered 503. Resynchronized, nothing to reset.
                return new SmtpSendResult { Stage = SmtpStage.MailFrom, SenderRejection = mailReply, Recipients = results };
            }

            if (!results.Any(r => r.Accepted))
            {
                if (dataReply is { IsIntermediate: true })
                {
                    // No recipient accepted yet the server opened DATA: we cannot RSET inside DATA, drop the connection.
                    _broken = true;
                }
                else
                {
                    // The MAIL transaction is still open at the server; clear it so the connection can be reused.
                    await ResetAsync(cancellationToken).ConfigureAwait(false);
                }

                return new SmtpSendResult { Stage = SmtpStage.RcptTo, Recipients = results };
            }

            if (!chunking)
            {
                if (!dataReply!.IsIntermediate)
                {
                    return new SmtpSendResult { Stage = SmtpStage.Data, Recipients = results, DataRejection = dataReply };
                }

                return await SendDataAsync(results, message, cancellationToken).ConfigureAwait(false);
            }

            return await SendBdatAsync(results, message, cancellationToken).ConfigureAwait(false);
        }

        mailReply = await CommandAsync(SmtpStage.MailFrom, mail.ToString(), _options.CommandTimeout, cancellationToken).ConfigureAwait(false);
        if (!mailReply.IsPositiveCompletion)
        {
            return new SmtpSendResult { Stage = SmtpStage.MailFrom, SenderRejection = mailReply };
        }

        foreach (var rcpt in envelope.Recipients)
        {
            var r = await CommandAsync(SmtpStage.RcptTo, $"RCPT TO:{rcpt.ToPath()}", _options.CommandTimeout, cancellationToken).ConfigureAwait(false);
            results.Add(new SmtpRecipientResult { Address = rcpt, Reply = r });
        }

        if (!results.Any(r => r.Accepted))
        {
            await ResetAsync(cancellationToken).ConfigureAwait(false);
            return new SmtpSendResult { Stage = SmtpStage.RcptTo, Recipients = results };
        }

        if (chunking)
        {
            return await SendBdatAsync(results, message, cancellationToken).ConfigureAwait(false);
        }

        var data = await CommandAsync(SmtpStage.Data, "DATA", _options.DataInitiationTimeout, cancellationToken).ConfigureAwait(false);
        if (!data.IsIntermediate)
        {
            return new SmtpSendResult { Stage = SmtpStage.Data, Recipients = results, DataRejection = data };
        }

        return await SendDataAsync(results, message, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<SmtpSendResult> SendDataAsync(List<SmtpRecipientResult> results, ReadOnlyMemory<byte> message, CancellationToken ct)
    {
        var stuffer = new DotStuffer();
        const int block = 64 * 1024;
        for (int offset = 0; offset < message.Length; offset += block)
        {
            var chunk = message.Slice(offset, Math.Min(block, message.Length - offset));
            if (!stuffer.Write(chunk.Span, _writer))
            {
                // Cannot transmit faithfully. The server is waiting for data; cut the connection so no partial message is accepted.
                _broken = true;
                return new SmtpSendResult { LocalFailure = LocalFailure.MalformedMessage, Stage = SmtpStage.Data, Recipients = results };
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(_options.DataBlockTimeout);
            try
            {
                await FlushAsync(SmtpStage.Data, cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                _broken = true;
                throw new SmtpConnectionException(SmtpStage.Data, $"Timeout sending data to {_target.Host}", timedOut: true);
            }
        }

        EndOfDataStarted = true;
        stuffer.Complete(_writer);
        try
        {
            await FlushAsync(SmtpStage.EndOfData, ct).ConfigureAwait(false);
        }
        catch (SmtpConnectionException ex)
        {
            throw new SmtpConnectionException(ex.Stage, ex.Message, ex.InnerException, endOfDataSent: true, ex.TimedOut);
        }

        SmtpReply final;
        try
        {
            final = await ReadReplyAsync(SmtpStage.EndOfData, _options.EndOfDataTimeout, ct).ConfigureAwait(false);
        }
        catch (SmtpConnectionException ex)
        {
            // The dot was written but we never saw the verdict: the server may have accepted the message.
            throw new SmtpConnectionException(ex.Stage, ex.Message, ex.InnerException, endOfDataSent: true, ex.TimedOut);
        }

        TransactionsCompleted++;
        LastUsedAt = _clock.UtcNow;
        return new SmtpSendResult { Stage = SmtpStage.EndOfData, Recipients = results, FinalReply = final, EndOfDataSent = true };
    }

    private async ValueTask<SmtpSendResult> SendBdatAsync(List<SmtpRecipientResult> results, ReadOnlyMemory<byte> message, CancellationToken ct)
    {
        if (!BdatSafe(message.Span))
        {
            return new SmtpSendResult { LocalFailure = LocalFailure.MalformedMessage, Stage = SmtpStage.Data, Recipients = results };
        }

        int chunk = Math.Max(1024, _options.BdatChunkSize);
        int offset = 0;
        SmtpReply reply;
        do
        {
            int take = Math.Min(chunk, message.Length - offset);
            bool last = offset + take >= message.Length;
            EndOfDataStarted |= last;
            WriteLine($"BDAT {take}{(last ? " LAST" : "")}");
            _writer.Write(message.Span.Slice(offset, take));
            try
            {
                await FlushAsync(last ? SmtpStage.EndOfData : SmtpStage.Data, ct).ConfigureAwait(false);
                reply = await ReadReplyAsync(last ? SmtpStage.EndOfData : SmtpStage.Data, last ? _options.EndOfDataTimeout : _options.DataBlockTimeout, ct).ConfigureAwait(false);
            }
            catch (SmtpConnectionException ex) when (last)
            {
                throw new SmtpConnectionException(ex.Stage, ex.Message, ex.InnerException, endOfDataSent: true, ex.TimedOut);
            }

            offset += take;
            if (!reply.IsPositiveCompletion)
            {
                // A failed chunk aborts the transfer; resync by waiting for the rest is impossible, so drop the connection.
                _broken = true;
                return last
                    ? new SmtpSendResult { Stage = SmtpStage.EndOfData, Recipients = results, FinalReply = reply, EndOfDataSent = true }
                    : new SmtpSendResult { Stage = SmtpStage.Data, Recipients = results, DataRejection = reply };
            }
        }
        while (offset < message.Length);

        TransactionsCompleted++;
        LastUsedAt = _clock.UtcNow;
        return new SmtpSendResult { Stage = SmtpStage.EndOfData, Recipients = results, FinalReply = reply, EndOfDataSent = true };
    }

    /// <summary>Bare CR/LF cannot be allowed through BDAT either (the receiver may normalize or reject).</summary>
    private static bool BdatSafe(ReadOnlySpan<byte> m)
    {
        int i = 0;
        while (i < m.Length)
        {
            int j = m[i..].IndexOfAny((byte)'\r', (byte)'\n', (byte)0);
            if (j < 0) { return true; }
            i += j;
            byte b = m[i];
            if (b == 0 || b == '\n') { return false; }
            if (i + 1 >= m.Length || m[i + 1] != '\n') { return false; }
            i += 2;
        }

        return true;
    }

    /// <summary>RSET; used between transactions on a reused connection and after aborted ones.</summary>
    public async ValueTask ResetAsync(CancellationToken ct = default)
    {
        var r = await CommandAsync(SmtpStage.Rset, "RSET", _options.CommandTimeout, ct).ConfigureAwait(false);
        if (!r.IsPositiveCompletion)
        {
            _broken = true;
        }
    }

    /// <summary>Checks the idle connection is still usable (NOOP).</summary>
    public async ValueTask<bool> CheckAliveAsync(CancellationToken ct = default)
    {
        if (!IsReusable) { return false; }
        try
        {
            var r = await CommandAsync(SmtpStage.Rset, "NOOP", TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
            return r.IsPositiveCompletion;
        }
        catch (SmtpClientException)
        {
            _broken = true;
            return false;
        }
    }

    public async ValueTask QuitAsync(CancellationToken ct = default)
    {
        if (_quit || _broken || _socket is null) { return; }
        _quit = true;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            WriteLine("QUIT");
            await _writer.FlushAsync(cts.Token).ConfigureAwait(false);
            await ReadReplyAsync(SmtpStage.Rset, TimeSpan.FromSeconds(5), cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SmtpClientException or IOException or OperationCanceledException or SocketException or ObjectDisposedException)
        {
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_socket is null)
        {
            return;
        }

        try { if (_writer is not null) { await _writer.CompleteAsync().ConfigureAwait(false); } } catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException) { }
        try { if (_reader is not null) { await _reader.CompleteAsync().ConfigureAwait(false); } } catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException) { }
        try { if (_stream is not null) { await _stream.DisposeAsync().ConfigureAwait(false); } } catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
        _socket.Dispose();
        _socket = null;
    }
}
