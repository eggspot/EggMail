using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using Mta.Core;
using Mta.Smtp.Protocol;

namespace Mta.Smtp.Server;

/// <summary>One client connection: the protocol loop of the SMTP server (RFC 5321, 3207, 4954, 3030, 6531, 2920, 6152, 2034).</summary>
internal sealed class SmtpSession
{
    private readonly SmtpServer _server;
    private readonly SmtpServerOptions _options;
    private readonly ISmtpServerHandler _handler;
    private readonly SmtpListenerOptions _listener;
    private readonly SocketTransport _transport;
    private readonly SmtpSessionContext _ctx;
    private readonly SmtpSessionState _state;
    private readonly SmtpParseOptions _parseOptions;
    private readonly IMtaLog _log;
    private readonly CancellationTokenSource _readCts;
    private readonly CancellationToken _stopping;
    private byte[]? _scratch;
    private int _errors;
    private int _messages;
    private bool _close;

    // Open transaction.
    private MailFromInfo? _mail;
    private readonly List<EmailAddress> _recipients = [];

    public SmtpSession(SmtpServer server, Socket socket, SmtpListenerOptions listener, CancellationToken stopping)
    {
        _server = server;
        _options = server.Options;
        _handler = server.Handler;
        _listener = listener;
        _log = server.Log;
        _stopping = stopping;
        _transport = new SocketTransport(socket, startPlain: listener.Mode != ListenerMode.Implicit);
        _readCts = CancellationTokenSource.CreateLinkedTokenSource(stopping);
        _parseOptions = new SmtpParseOptions { MaxLineLength = _options.MaxLineLength, AllowSmtpUtf8 = _options.SmtpUtf8 };
        var remote = (IPEndPoint)socket.RemoteEndPoint!;
        var local = (IPEndPoint)socket.LocalEndPoint!;
        _ctx = new SmtpSessionContext
        {
            RemoteEndPoint = remote,
            LocalEndPoint = local,
            ListenerName = listener.Name,
            Role = listener.Role,
        };
        _state = new SmtpSessionState
        {
            StartTlsAvailable = listener.Mode == ListenerMode.StartTls && _options.Certificates is not null,
            AuthAvailable = listener.Role == ListenerRole.Submission,
            AllowInsecureAuth = listener.AllowInsecureAuth,
            RequireAuthForMail = listener.AuthRequired,
            MaxRecipients = _options.MaxRecipients,
        };
    }

    public async Task RunAsync()
    {
        SmtpMetrics.Connections.Add(1);
        SmtpMetrics.ActiveSessions.Add(1);
        try
        {
            if (_listener.Mode == ListenerMode.Implicit)
            {
                if (!await UpgradeTlsAsync(startTls: false).ConfigureAwait(false))
                {
                    return;
                }
            }

            SmtpReply? refusal = _server.AcceptingMail
                ? await _handler.OnConnectedAsync(_ctx, _stopping).ConfigureAwait(false)
                : SmtpReply.Create(421, "4.3.2", $"{_options.Hostname} service not available, try again later");
            if (refusal is not null)
            {
                Write(refusal);
                await FlushAsync().ConfigureAwait(false);
                SmtpMetrics.RefusedConnections.Add(1);
                return;
            }

            Write(SmtpReplies.Greeting(_options.Hostname, _options.ProductName));
            await FlushAsync().ConfigureAwait(false);
            await CommandLoopAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Server stopping or timeout already answered.
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException or InvalidOperationException)
        {
            if (_log.IsEnabled(MtaLogLevel.Debug))
            {
                _log.Write(MtaLogLevel.Debug, "smtp.server", $"session {_ctx.SessionId} from {_ctx.RemoteEndPoint}: {ex.GetType().Name}: {ex.Message}");
            }
        }
        catch (Exception ex)
        {
            _log.Write(MtaLogLevel.Error, "smtp.server", $"session {_ctx.SessionId} from {_ctx.RemoteEndPoint}: unexpected error", ex);
        }
        finally
        {
            try
            {
                _handler.OnDisconnected(_ctx);
            }
            catch (Exception ex)
            {
                _log.Write(MtaLogLevel.Error, "smtp.server", "handler OnDisconnected failed", ex);
            }

            await _transport.DisposeAsync().ConfigureAwait(false);
            _readCts.Dispose();
            SmtpMetrics.ActiveSessions.Add(-1);
        }
    }

    // ---------------------------------------------------------------- output helpers

    private bool Enhanced => _options.EnhancedStatusCodes && _state.UsedEhlo;

    private void Write(SmtpReply reply) => reply.WriteTo(_transport.Output, Enhanced);

    private async ValueTask FlushAsync()
    {
        var result = await _transport.Output.FlushAsync(CancellationToken.None).ConfigureAwait(false);
        if (result.IsCompleted || result.IsCanceled)
        {
            _close = true;
        }
    }

    private async ValueTask ReplyAsync(SmtpReply reply)
    {
        Write(reply);
        await FlushAsync().ConfigureAwait(false);
    }

    // ---------------------------------------------------------------- reading helpers

    /// <summary>Reads more data from the client; throws <see cref="TimeoutException"/> if nothing arrives in time.</summary>
    private async ValueTask<ReadResult> ReadAsync(TimeSpan timeout)
    {
        var reader = _transport.Input;
        if (reader.TryRead(out var immediate))
        {
            return immediate;
        }

        // About to block: push out pipelined replies first.
        await FlushAsync().ConfigureAwait(false);
        _readCts.CancelAfter(timeout);
        try
        {
            return await reader.ReadAsync(_readCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!_stopping.IsCancellationRequested)
        {
            throw new TimeoutException();
        }
        finally
        {
            _readCts.CancelAfter(Timeout.InfiniteTimeSpan);
        }
    }

    // ---------------------------------------------------------------- main loop

    private async Task CommandLoopAsync()
    {
        bool first = true;
        while (!_close)
        {
            ReadResult read;
            try
            {
                read = await ReadAsync(first ? _options.GreetingTimeout : _options.CommandTimeout).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                await ReplyAsync(SmtpReplies.Timeout).ConfigureAwait(false);
                return;
            }
            catch (OperationCanceledException)
            {
                await ReplyAsync(SmtpReplies.ShuttingDown).ConfigureAwait(false);
                return;
            }

            first = false;
            var buffer = read.Buffer;
            if (buffer.IsEmpty && read.IsCompleted)
            {
                return; // client went away
            }

            var status = TryReadCommand(buffer, out var cmd, out var parseError, out int consumed);
            switch (status)
            {
                case LineStatus.Incomplete:
                    if (read.IsCompleted)
                    {
                        return;
                    }

                    _transport.Input.AdvanceTo(buffer.Start, buffer.End);
                    continue;

                case LineStatus.TooLong:
                    SmtpMetrics.ProtocolErrors.Add(1);
                    await ReplyAsync(SmtpReplies.LineTooLong).ConfigureAwait(false);
                    return;

                case LineStatus.BareLf:
                case LineStatus.BareCr:
                    SmtpMetrics.ProtocolErrors.Add(1);
                    _log.Write(MtaLogLevel.Warning, "smtp.server", $"session {_ctx.SessionId} from {_ctx.RemoteEndPoint}: bare CR/LF in command line");
                    await ReplyAsync(SmtpReplies.BareLineEnding).ConfigureAwait(false);
                    return;
            }

            _transport.Input.AdvanceTo(buffer.GetPosition(consumed));
            SmtpMetrics.Commands.Add(1);

            if (parseError != SmtpParseError.None)
            {
                if (await ErrorAsync(ParseErrorReply(parseError)).ConfigureAwait(false))
                {
                    return;
                }

                continue;
            }

            if (!_server.AcceptingMail && cmd.Verb == SmtpVerb.Mail)
            {
                await ReplyAsync(SmtpReply.Create(421, "4.3.2", "Service not available, closing connection")).ConfigureAwait(false);
                return;
            }

            var refusal = _state.Check(cmd.Verb);
            if (refusal is not null)
            {
                if (await ErrorAsync(refusal).ConfigureAwait(false))
                {
                    return;
                }

                continue;
            }

            await DispatchAsync(cmd).ConfigureAwait(false);
        }
    }

    private LineStatus TryReadCommand(in ReadOnlySequence<byte> buffer, out SmtpCommand cmd, out SmtpParseError error, out int consumed)
    {
        cmd = default;
        error = SmtpParseError.None;
        if (!buffer.IsSingleSegment)
        {
            _scratch ??= new byte[_options.MaxLineLength + 2];
        }

        var status = SmtpLineScanner.TryGetLine(buffer, _options.MaxLineLength, _scratch ?? [], out var line, out consumed);
        if (status == LineStatus.Ok)
        {
            error = SmtpCommandParser.TryParse(line, _parseOptions, out cmd);
        }

        return status;
    }

    private static SmtpReply ParseErrorReply(SmtpParseError e) => e switch
    {
        SmtpParseError.UnknownCommand => SmtpReplies.SyntaxError,
        SmtpParseError.ParameterNotImplemented => SmtpReplies.ParameterNotImplemented,
        SmtpParseError.LineTooLong => SmtpReplies.LineTooLong,
        _ => SmtpReplies.ArgumentSyntaxError,
    };

    /// <summary>Sends an error reply and counts it. Returns true if the session must close (too many errors).</summary>
    private async ValueTask<bool> ErrorAsync(SmtpReply reply)
    {
        SmtpMetrics.ProtocolErrors.Add(1);
        Write(reply);
        if (++_errors >= _options.MaxErrorsPerSession)
        {
            Write(SmtpReplies.TooManyErrors);
            await FlushAsync().ConfigureAwait(false);
            return true;
        }

        return false;
    }

    private async ValueTask DispatchAsync(SmtpCommand cmd)
    {
        switch (cmd.Verb)
        {
            case SmtpVerb.Helo:
            case SmtpVerb.Ehlo:
                HandleGreeting(cmd);
                break;

            case SmtpVerb.Noop:
                Write(SmtpReplies.Ok);
                break;

            case SmtpVerb.Quit:
                Write(SmtpReplies.Bye);
                await FlushAsync().ConfigureAwait(false);
                _close = true;
                break;

            case SmtpVerb.Rset:
                ResetTransaction();
                Write(SmtpReplies.ResetOk);
                break;

            case SmtpVerb.Vrfy:
                Write(SmtpReplies.VrfyDisabled);
                break;

            case SmtpVerb.Expn:
                Write(SmtpReplies.NotImplemented);
                break;

            case SmtpVerb.Help:
                Write(SmtpReply.Create(214, "2.0.0", "https://github.com/eggspot/EggMail"));
                break;

            case SmtpVerb.StartTls:
                await HandleStartTlsAsync().ConfigureAwait(false);
                break;

            case SmtpVerb.Auth:
                await HandleAuthAsync(cmd).ConfigureAwait(false);
                break;

            case SmtpVerb.Mail:
                await HandleMailAsync(cmd).ConfigureAwait(false);
                break;

            case SmtpVerb.Rcpt:
                await HandleRcptAsync(cmd).ConfigureAwait(false);
                break;

            case SmtpVerb.Data:
                await HandleDataAsync().ConfigureAwait(false);
                break;

            case SmtpVerb.Bdat:
                await HandleBdatAsync(cmd).ConfigureAwait(false);
                break;
        }
    }

    // ---------------------------------------------------------------- verbs

    private void ResetTransaction()
    {
        _state.ResetTransaction();
        _mail = null;
        _recipients.Clear();
    }

    private SmtpCapabilities BuildCapabilities()
    {
        bool offerAuth = _state.AuthAvailable && (_state.TlsActive || _listener.AllowInsecureAuth);
        return new SmtpCapabilities
        {
            Pipelining = _options.Pipelining,
            EightBitMime = _options.EightBitMime,
            SmtpUtf8 = _options.SmtpUtf8,
            Chunking = _options.Chunking,
            EnhancedStatusCodes = _options.EnhancedStatusCodes,
            StartTls = _state.StartTlsAvailable && !_state.TlsActive,
            Size = _options.MaxMessageSize,
            AuthMechanisms = offerAuth ? ["PLAIN", "LOGIN"] : [],
        };
    }

    private void HandleGreeting(SmtpCommand cmd)
    {
        _ctx.HeloName = cmd.Argument;
        bool ehlo = cmd.Verb == SmtpVerb.Ehlo;
        _ctx.UsedEhlo = ehlo;
        ResetTransaction();
        _state.OnGreeted(ehlo);
        string greeting = $"{_options.Hostname} greets {cmd.Argument}";
        if (!ehlo)
        {
            Write(SmtpReply.Create(250, null, greeting));
            return;
        }

        Write(new SmtpReply(250, null, BuildCapabilities().ToEhloLines(greeting)));
    }

    private async ValueTask HandleStartTlsAsync()
    {
        if (_options.Certificates is null)
        {
            await ReplyAsync(SmtpReplies.TlsNotAvailable).ConfigureAwait(false);
            return;
        }

        // Stop the plaintext reader before the reply goes out, so a ClientHello that follows 220 at once cannot be read as plaintext.
        if (!await _transport.StopPlaintextReadingAsync().ConfigureAwait(false))
        {
            _close = true;
            return;
        }

        Write(SmtpReplies.ReadyForTls);
        await FlushAsync().ConfigureAwait(false);
        if (!await UpgradeTlsAsync(startTls: true).ConfigureAwait(false))
        {
            _close = true;
            return;
        }

        _state.OnTlsEstablished();
        ResetTransaction();
        _ctx.HeloName = null;
    }

    private async Task<bool> UpgradeTlsAsync(bool startTls)
    {
        if (_options.Certificates is null)
        {
            return false;
        }

        bool ok = await _transport.UpgradeToTlsAsync(_server.ServerOptionsCallback, _options.TlsHandshakeTimeout, _stopping).ConfigureAwait(false);
        if (!ok)
        {
            SmtpMetrics.TlsFailures.Add(1);
            _log.Write(MtaLogLevel.Debug, "smtp.server", $"session {_ctx.SessionId} from {_ctx.RemoteEndPoint}: TLS {(startTls ? "upgrade" : "handshake")} failed");
            return false;
        }

        SmtpMetrics.TlsHandshakes.Add(1);
        var ssl = _transport.Ssl!;
        _ctx.TlsActive = true;
        _ctx.TlsProtocol = ssl.SslProtocol.ToString();
        _ctx.TlsCipherSuite = ssl.NegotiatedCipherSuite.ToString();
        if (!startTls)
        {
            _state.MarkImplicitTls();
        }

        return true;
    }

    private async ValueTask HandleMailAsync(SmtpCommand cmd)
    {
        if (cmd.Mail.Size is long declared && declared > _options.MaxMessageSize)
        {
            if (await ErrorAsync(SmtpReplies.MessageTooLarge).ConfigureAwait(false)) { _close = true; }
            return;
        }

        if (cmd.Mail.BodyType == SmtpBodyType.BinaryMime || (cmd.Mail.BodyType == SmtpBodyType.EightBitMime && !_options.EightBitMime))
        {
            if (await ErrorAsync(SmtpReply.Create(555, "5.5.4", "BODY type not supported")).ConfigureAwait(false)) { _close = true; }
            return;
        }

        if (_messages >= _options.MaxMessagesPerSession)
        {
            Write(SmtpReply.Create(421, "4.7.0", "Too many messages in this session, closing connection"));
            await FlushAsync().ConfigureAwait(false);
            _close = true;
            return;
        }

        var info = new MailFromInfo { Sender = cmd.Path, Parameters = cmd.Mail };
        var reply = await _handler.OnMailFromAsync(_ctx, info, _stopping).ConfigureAwait(false);
        if (reply.IsPositiveCompletion)
        {
            _mail = info;
            _recipients.Clear();
            _state.OnMailAccepted();
            _ctx.SmtpUtf8 = cmd.Mail.SmtpUtf8;
            Write(reply);
        }
        else
        {
            if (await ErrorAsync(reply).ConfigureAwait(false)) { _close = true; }
        }
    }

    private async ValueTask HandleRcptAsync(SmtpCommand cmd)
    {
        var reply = await _handler.OnRcptToAsync(_ctx, _mail!, cmd.Path, cmd.Rcpt, _stopping).ConfigureAwait(false);
        if (reply.IsPositiveCompletion)
        {
            _recipients.Add(cmd.Path);
            _state.OnRecipientAccepted();
            Write(reply);
        }
        else
        {
            if (await ErrorAsync(reply).ConfigureAwait(false)) { _close = true; }
        }
    }

    private async ValueTask HandleAuthAsync(SmtpCommand cmd)
    {
        string mech = cmd.Argument!;
        if (mech is not ("PLAIN" or "LOGIN"))
        {
            if (await ErrorAsync(SmtpReplies.ParameterNotImplemented).ConfigureAwait(false)) { _close = true; }
            return;
        }

        string? user = null, password = null, authzid = "";
        if (mech == "PLAIN")
        {
            string? response = cmd.InitialResponse;
            if (response is null)
            {
                response = await ChallengeAsync("").ConfigureAwait(false);
                if (response is null) { return; }
            }

            if (response == "=") { response = ""; }
            if (!Sasl.TryDecodeBase64(response, out byte[] raw) || !Sasl.TryParsePlain(raw, out authzid, out user, out password))
            {
                await AuthFailedAsync(SmtpReplies.ArgumentSyntaxError, count: false).ConfigureAwait(false);
                return;
            }
        }
        else
        {
            string? u = cmd.InitialResponse;
            if (u is null)
            {
                u = await ChallengeAsync(Sasl.EncodeBase64("Username:")).ConfigureAwait(false);
                if (u is null) { return; }
            }

            string? p = await ChallengeAsync(Sasl.EncodeBase64("Password:")).ConfigureAwait(false);
            if (p is null) { return; }
            if (!Sasl.TryDecodeBase64(u, out byte[] ub) || !Sasl.TryDecodeBase64(p, out byte[] pb))
            {
                await AuthFailedAsync(SmtpReplies.ArgumentSyntaxError, count: false).ConfigureAwait(false);
                return;
            }

            try
            {
                var strict = new UTF8Encoding(false, true);
                user = strict.GetString(ub);
                password = strict.GetString(pb);
            }
            catch (ArgumentException)
            {
                await AuthFailedAsync(SmtpReplies.ArgumentSyntaxError, count: false).ConfigureAwait(false);
                return;
            }

            authzid = "";
        }

        var result = await _handler.AuthenticateAsync(_ctx, authzid, user!, password!, _stopping).ConfigureAwait(false);
        if (result.Success)
        {
            _ctx.AuthenticatedUser = result.UserName ?? user;
            _state.OnAuthenticated();
            Write(SmtpReplies.AuthOk);
        }
        else
        {
            await AuthFailedAsync(result.Reply ?? SmtpReplies.AuthFailed, count: true).ConfigureAwait(false);
        }
    }

    private async ValueTask AuthFailedAsync(SmtpReply reply, bool count)
    {
        if (count)
        {
            SmtpMetrics.AuthFailures.Add(1);
            if (_options.AuthFailureDelay > TimeSpan.Zero)
            {
                await Task.Delay(_options.AuthFailureDelay, _stopping).ConfigureAwait(false);
            }
        }

        if (await ErrorAsync(reply).ConfigureAwait(false)) { _close = true; }
    }

    /// <summary>Sends a 334 challenge and reads the client's response line. Returns null (after replying) on cancel/errors.</summary>
    private async ValueTask<string?> ChallengeAsync(string challenge)
    {
        Write(SmtpReply.Create(334, null, challenge));
        await FlushAsync().ConfigureAwait(false);
        ReadResult read;
        while (true)
        {
            try
            {
                read = await ReadAsync(_options.CommandTimeout).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                await ReplyAsync(SmtpReplies.Timeout).ConfigureAwait(false);
                _close = true;
                return null;
            }

            var buffer = read.Buffer;
            if (!buffer.IsSingleSegment)
            {
                _scratch ??= new byte[_options.MaxLineLength + 2];
            }

            var status = SmtpLineScanner.TryGetLine(buffer, 4096, _scratch ?? [], out var line, out int consumed);
            if (status == LineStatus.Incomplete)
            {
                if (read.IsCompleted) { _close = true; return null; }
                _transport.Input.AdvanceTo(buffer.Start, buffer.End);
                continue;
            }

            if (status != LineStatus.Ok)
            {
                await ReplyAsync(status == LineStatus.TooLong ? SmtpReplies.LineTooLong : SmtpReplies.BareLineEnding).ConfigureAwait(false);
                _close = true;
                return null;
            }

            string text = Encoding.ASCII.GetString(line);
            _transport.Input.AdvanceTo(buffer.GetPosition(consumed));
            if (text == "*")
            {
                if (await ErrorAsync(SmtpReply.Create(501, "5.0.0", "Authentication cancelled")).ConfigureAwait(false)) { _close = true; }
                return null;
            }

            return text;
        }
    }

    // ---------------------------------------------------------------- message data

    private async ValueTask HandleDataAsync()
    {
        Write(SmtpReplies.StartData);
        await FlushAsync().ConfigureAwait(false);

        var scanner = new DataScanner(_options.RejectNulInData);
        using var message = new MessageBuffer();
        var discard = new CountingNullWriter();
        long reserved = 0;
        bool tooLarge = false, noMemory = false;
        long started = _server.Clock.Timestamp;

        while (true)
        {
            ReadResult read;
            try
            {
                if (_server.Clock.GetElapsedTime(started) > _options.MaxDataDuration)
                {
                    throw new TimeoutException();
                }

                read = await ReadAsync(_options.DataTimeout).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                _server.Budget.Release(reserved);
                await ReplyAsync(SmtpReplies.Timeout).ConfigureAwait(false);
                _close = true;
                return;
            }
            catch (OperationCanceledException)
            {
                _server.Budget.Release(reserved);
                await ReplyAsync(SmtpReplies.ShuttingDown).ConfigureAwait(false);
                _close = true;
                return;
            }

            var buffer = read.Buffer;
            DataScanStatus status = DataScanStatus.NeedMoreData;
            long consumedTotal = 0;
            foreach (var segment in buffer)
            {
                IBufferWriter<byte> sink = (tooLarge || noMemory) ? discard : message;
                status = scanner.Scan(segment.Span, sink, out int used);
                consumedTotal += used;
                if (!(tooLarge || noMemory))
                {
                    if (scanner.BytesWritten > _options.MaxMessageSize)
                    {
                        tooLarge = true;
                    }
                    else if (message.Capacity > reserved)
                    {
                        long need = message.Capacity - reserved;
                        if (_server.Budget.TryReserve(need))
                        {
                            reserved += need;
                        }
                        else
                        {
                            noMemory = true;
                        }
                    }

                    if (tooLarge || noMemory)
                    {
                        message.Dispose();
                        _server.Budget.Release(reserved);
                        reserved = 0;
                    }
                }

                if (status != DataScanStatus.NeedMoreData)
                {
                    break;
                }
            }

            var consumedPos = buffer.GetPosition(consumedTotal);
            _transport.Input.AdvanceTo(consumedPos);

            switch (status)
            {
                case DataScanStatus.NeedMoreData:
                    if (read.IsCompleted)
                    {
                        _server.Budget.Release(reserved);
                        _close = true;
                        return;
                    }

                    continue;

                case DataScanStatus.BareLf:
                case DataScanStatus.BareCr:
                case DataScanStatus.Nul:
                    _server.Budget.Release(reserved);
                    SmtpMetrics.ProtocolErrors.Add(1);
                    _log.Write(MtaLogLevel.Warning, "smtp.server", $"session {_ctx.SessionId} from {_ctx.RemoteEndPoint}: {status} in message data (possible smuggling attempt)");
                    await ReplyAsync(SmtpReplies.BareLineEnding).ConfigureAwait(false);
                    _close = true;
                    return;

                case DataScanStatus.Complete:
                    break;
            }

            break;
        }

        try
        {
            if (tooLarge)
            {
                SmtpMetrics.MessagesRejected.Add(1);
                ResetTransaction();
                Write(SmtpReplies.MessageTooLarge);
                return;
            }

            if (noMemory)
            {
                SmtpMetrics.MessagesRejected.Add(1);
                ResetTransaction();
                Write(SmtpReplies.InsufficientStorage);
                return;
            }

            await CompleteMessageAsync(message).ConfigureAwait(false);
        }
        finally
        {
            _server.Budget.Release(reserved);
        }
    }

    private async ValueTask HandleBdatAsync(SmtpCommand cmd)
    {
        _state.OnChunkingStarted();
        using var message = new MessageBuffer();
        long reserved = 0;
        long total = 0;
        bool failed = false;
        SmtpReply? failure = null;
        var chunk = cmd;
        long started = _server.Clock.Timestamp;

        try
        {
            while (true)
            {
                long remaining = chunk.ChunkSize;
                total += chunk.ChunkSize;
                if (!failed && total > _options.MaxMessageSize)
                {
                    failed = true;
                    failure = SmtpReplies.MessageTooLarge;
                    message.Dispose();
                    _server.Budget.Release(reserved);
                    reserved = 0;
                }

                // Read the chunk payload (binary; no scanning, so commands inside it are inert).
                while (remaining > 0)
                {
                    ReadResult read;
                    try
                    {
                        if (_server.Clock.GetElapsedTime(started) > _options.MaxDataDuration) { throw new TimeoutException(); }
                        read = await ReadAsync(_options.DataTimeout).ConfigureAwait(false);
                    }
                    catch (TimeoutException)
                    {
                        await ReplyAsync(SmtpReplies.Timeout).ConfigureAwait(false);
                        _close = true;
                        return;
                    }
                    catch (OperationCanceledException)
                    {
                        await ReplyAsync(SmtpReplies.ShuttingDown).ConfigureAwait(false);
                        _close = true;
                        return;
                    }

                    var buffer = read.Buffer;
                    if (buffer.IsEmpty && read.IsCompleted)
                    {
                        _close = true;
                        return;
                    }

                    long take = Math.Min(remaining, buffer.Length);
                    if (!failed && take > 0)
                    {
                        foreach (var seg in buffer.Slice(0, take))
                        {
                            message.Write(seg.Span);
                        }

                        if (message.Capacity > reserved)
                        {
                            long need = message.Capacity - reserved;
                            if (_server.Budget.TryReserve(need))
                            {
                                reserved += need;
                            }
                            else
                            {
                                failed = true;
                                failure = SmtpReplies.InsufficientStorage;
                                message.Dispose();
                                _server.Budget.Release(reserved);
                                reserved = 0;
                            }
                        }
                    }

                    remaining -= take;
                    _transport.Input.AdvanceTo(buffer.GetPosition(take));
                }

                if (failed)
                {
                    SmtpMetrics.MessagesRejected.Add(1);
                    if (chunk.LastChunk)
                    {
                        ResetTransaction();
                        Write(failure!);
                        return;
                    }

                    Write(failure!);
                }
                else if (chunk.LastChunk)
                {
                    await CompleteMessageAsync(message).ConfigureAwait(false);
                    return;
                }
                else
                {
                    Write(SmtpReply.Create(250, "2.0.0", $"{chunk.ChunkSize} octets received"));
                }

                // Wait for the next BDAT (only BDAT, RSET, NOOP, QUIT are valid while chunking).
                var next = await ReadNextBdatAsync().ConfigureAwait(false);
                if (next is null)
                {
                    return;
                }

                chunk = next.Value;
            }
        }
        finally
        {
            _server.Budget.Release(reserved);
        }
    }

    /// <summary>Reads the next command during a BDAT sequence. Returns the BDAT command, or null if the sequence ended (RSET/QUIT/error).</summary>
    private async ValueTask<SmtpCommand?> ReadNextBdatAsync()
    {
        while (true)
        {
            ReadResult read;
            try
            {
                read = await ReadAsync(_options.CommandTimeout).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                await ReplyAsync(SmtpReplies.Timeout).ConfigureAwait(false);
                _close = true;
                return null;
            }

            var buffer = read.Buffer;
            if (buffer.IsEmpty && read.IsCompleted) { _close = true; return null; }
            var status = TryReadCommand(buffer, out var cmd, out var err, out int consumed);
            if (status == LineStatus.Incomplete)
            {
                if (read.IsCompleted) { _close = true; return null; }
                _transport.Input.AdvanceTo(buffer.Start, buffer.End);
                continue;
            }

            if (status != LineStatus.Ok)
            {
                await ReplyAsync(status == LineStatus.TooLong ? SmtpReplies.LineTooLong : SmtpReplies.BareLineEnding).ConfigureAwait(false);
                _close = true;
                return null;
            }

            _transport.Input.AdvanceTo(buffer.GetPosition(consumed));
            if (err == SmtpParseError.None && cmd.Verb == SmtpVerb.Bdat)
            {
                return cmd;
            }

            if (err == SmtpParseError.None && cmd.Verb is SmtpVerb.Rset)
            {
                ResetTransaction();
                Write(SmtpReplies.ResetOk);
                return null;
            }

            if (err == SmtpParseError.None && cmd.Verb is SmtpVerb.Noop)
            {
                Write(SmtpReplies.Ok);
                continue;
            }

            if (err == SmtpParseError.None && cmd.Verb is SmtpVerb.Quit)
            {
                Write(SmtpReplies.Bye);
                await FlushAsync().ConfigureAwait(false);
                _close = true;
                return null;
            }

            // Anything else aborts the chunked transfer (RFC 3030 §4.1).
            ResetTransaction();
            await ErrorAsync(SmtpReplies.BadSequence).ConfigureAwait(false);
            return null;
        }
    }

    private async ValueTask CompleteMessageAsync(MessageBuffer body)
    {
        long t0 = _server.Clock.Timestamp;
        var mail = _mail!;
        var now = _server.Clock.UtcNow;
        string tag = Ids.ToCompact(Ids.New())[..16];
        byte[] received = ReceivedHeader.Build(_ctx, _options.Hostname, _recipients.Count == 1 ? _recipients[0].ToString() : null, tag, now);
        var message = new SmtpMessage
        {
            Session = _ctx,
            Sender = mail.Sender,
            Parameters = mail.Parameters,
            Recipients = _recipients.ToArray(),
            Body = body.AsSequence(),
            ReceivedHeader = received,
            ReceivedAt = now,
        };

        SmtpReply reply;
        try
        {
            reply = await _handler.OnMessageAsync(message, _stopping).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_stopping.IsCancellationRequested)
        {
            reply = SmtpReplies.ShuttingDown;
            _close = true;
        }
        catch (Exception ex)
        {
            _log.Write(MtaLogLevel.Error, "smtp.server", $"session {_ctx.SessionId}: handler failed for message", ex);
            reply = SmtpReplies.LocalError;
        }

        if (reply.IsPositiveCompletion)
        {
            SmtpMetrics.Messages.Add(1);
            SmtpMetrics.Bytes.Add(body.Length);
            _messages++;
        }
        else
        {
            SmtpMetrics.MessagesRejected.Add(1);
        }

        ResetTransaction();
        Write(reply);
        await FlushAsync().ConfigureAwait(false);
        SmtpMetrics.TransactionSeconds.Record(_server.Clock.GetElapsedTime(t0).TotalSeconds);
    }

    private sealed class CountingNullWriter : IBufferWriter<byte>
    {
        private byte[] _scratch = [];

        public void Advance(int count)
        {
        }

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            if (_scratch.Length < Math.Max(sizeHint, 4096)) { _scratch = new byte[Math.Max(sizeHint, 4096)]; }
            return _scratch;
        }

        public Span<byte> GetSpan(int sizeHint = 0) => GetMemory(sizeHint).Span;
    }
}
