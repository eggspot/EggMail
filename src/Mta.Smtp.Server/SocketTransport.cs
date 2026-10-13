using System.IO.Pipelines;
using System.Net.Security;
using System.Net.Sockets;

namespace Mta.Smtp.Server;

/// <summary>
/// Moves bytes between a socket and a pair of pipes. Idle connections hold no read buffer: each pump first waits
/// with a zero-byte read and rents memory only when data is actually available (decision 24). The same transport
/// can be upgraded to TLS in place for STARTTLS, with the injection guard of RFC 3207 §4.2 (any byte buffered
/// after the STARTTLS command aborts the upgrade).
/// </summary>
internal sealed class SocketTransport : IAsyncDisposable
{
    private static readonly PipeOptions InputOptions = new(
        pool: System.Buffers.MemoryPool<byte>.Shared,
        pauseWriterThreshold: 128 * 1024,
        resumeWriterThreshold: 64 * 1024,
        minimumSegmentSize: 4096,
        useSynchronizationContext: false);

    private static readonly PipeOptions OutputOptions = new(
        pool: System.Buffers.MemoryPool<byte>.Shared,
        pauseWriterThreshold: 256 * 1024,
        resumeWriterThreshold: 128 * 1024,
        minimumSegmentSize: 2048,
        useSynchronizationContext: false);

    private readonly Socket _socket;
    private readonly NetworkStream _network;
    private Stream _stream;
    private Pipe? _input;
    private Pipe? _output;
    private Task _inputPump = Task.CompletedTask;
    private Task _outputPump = Task.CompletedTask;
    private CancellationTokenSource _pumpCts = new();
    private bool _disposed;

    public SslStream? Ssl { get; private set; }

    public PipeReader Input => _input!.Reader;

    public PipeWriter Output => _output!.Writer;

    /// <param name="startPlain">Start plaintext pumps immediately. Implicit-TLS connections pass false so the
    /// ClientHello is never read into the plaintext pipe.</param>
    public SocketTransport(Socket socket, bool startPlain)
    {
        _socket = socket;
        _network = new NetworkStream(socket, ownsSocket: false);
        _stream = _network;
        if (startPlain)
        {
            StartPumps();
        }
    }

    private void StartPumps()
    {
        _input = new Pipe(InputOptions);
        _output = new Pipe(OutputOptions);
        _pumpCts = new CancellationTokenSource();
        _inputPump = PumpInputAsync(_stream, _input.Writer, _pumpCts.Token);
        _outputPump = PumpOutputAsync(_output.Reader, _stream);
    }

    private static async Task PumpInputAsync(Stream stream, PipeWriter writer, CancellationToken ct)
    {
        Exception? error = null;
        try
        {
            while (true)
            {
                // Zero-byte read: completes when data is available, without holding a buffer meanwhile.
                await stream.ReadAsync(Memory<byte>.Empty, ct).ConfigureAwait(false);
                var memory = writer.GetMemory(1);
                int read = await stream.ReadAsync(memory, ct).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                writer.Advance(read);
                var flush = await writer.FlushAsync(CancellationToken.None).ConfigureAwait(false);
                if (flush.IsCompleted || flush.IsCanceled)
                {
                    break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Pump stopped on purpose (TLS upgrade or shutdown).
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException or System.Security.Authentication.AuthenticationException or InvalidOperationException)
        {
            error = ex;
        }

        await writer.CompleteAsync(error).ConfigureAwait(false);
    }

    private static async Task PumpOutputAsync(PipeReader reader, Stream stream)
    {
        Exception? error = null;
        try
        {
            while (true)
            {
                var result = await reader.ReadAsync().ConfigureAwait(false);
                var buffer = result.Buffer;
                foreach (var segment in buffer)
                {
                    await stream.WriteAsync(segment).ConfigureAwait(false);
                }

                reader.AdvanceTo(buffer.End);
                if (result.IsCompleted)
                {
                    break;
                }
            }

            await stream.FlushAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException or System.Security.Authentication.AuthenticationException or InvalidOperationException)
        {
            error = ex;
        }

        await reader.CompleteAsync(error).ConfigureAwait(false);
    }

    private bool _plaintextStopped;

    /// <summary>
    /// Stops reading plaintext from the socket and reports whether any bytes had already arrived behind the STARTTLS line. Call this BEFORE
    /// sending "220 Ready to start TLS": a client may start its handshake the instant it sees that reply, and a plaintext reader that is
    /// still running would swallow the ClientHello (and the injection guard would then refuse the connection). Bytes present at this point
    /// were sent before the reply existed, so they are pipelined plaintext (CVE-2011-0411 family). Returns false in that case.
    /// </summary>
    public async ValueTask<bool> StopPlaintextReadingAsync()
    {
        if (_input is null || _plaintextStopped)
        {
            return true;
        }

        _plaintextStopped = true;
        await _pumpCts.CancelAsync().ConfigureAwait(false);
        await _inputPump.ConfigureAwait(false);
        bool leftover = _input.Reader.TryRead(out var pending) && !pending.Buffer.IsEmpty;
        await _input.Reader.CompleteAsync().ConfigureAwait(false);
        return !leftover;
    }

    /// <summary>Performs the server-side TLS handshake on a fresh connection (implicit TLS) or after STARTTLS (after <see cref="StopPlaintextReadingAsync"/> and the 220 reply).</summary>
    public async Task<bool> UpgradeToTlsAsync(ServerOptionsSelectionCallback optionsCallback, TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (_input is not null && _output is not null)
        {
            if (!await StopPlaintextReadingAsync().ConfigureAwait(false))
            {
                return false;
            }

            // Flush the pending output (the 220 reply) and stop the output pump.
            await _output.Writer.CompleteAsync().ConfigureAwait(false);
            await _outputPump.ConfigureAwait(false);
        }

        var ssl = new SslStream(_network, leaveInnerStreamOpen: true);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        try
        {
            await ssl.AuthenticateAsServerAsync(optionsCallback, null, cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or System.Security.Authentication.AuthenticationException or OperationCanceledException or SocketException or ObjectDisposedException)
        {
            await ssl.DisposeAsync().ConfigureAwait(false);
            return false;
        }

        Ssl = ssl;
        _stream = ssl;
        StartPumps();
        return true;
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try
        {
            if (_output is not null)
            {
                await _output.Writer.CompleteAsync().ConfigureAwait(false);
                await Task.WhenAny(_outputPump, Task.Delay(TimeSpan.FromSeconds(2))).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
        {
        }

        try
        {
            _socket.Shutdown(SocketShutdown.Both);
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
        }

        await _pumpCts.CancelAsync().ConfigureAwait(false);
        try
        {
            await _inputPump.ConfigureAwait(false);
            if (_input is not null)
            {
                await _input.Reader.CompleteAsync().ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
        {
        }

        if (Ssl is not null)
        {
            await Ssl.DisposeAsync().ConfigureAwait(false);
        }

        await _network.DisposeAsync().ConfigureAwait(false);
        _socket.Dispose();
        _pumpCts.Dispose();
    }
}
