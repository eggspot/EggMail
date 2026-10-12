using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace Mta.Tools;

/// <summary>
/// Closed-loop SMTP ingest benchmark. Measures accepted messages per second (when the final reply arrives) and the
/// transaction latency distribution. Written for our own harness because no maintained load tool covers TLS and
/// pipelining (docs/benchmarks.md).
/// </summary>
internal static class LoadCommand
{
    public static async Task<int> RunAsync(ArgParser args, CancellationToken ct)
    {
        var cfg = new LoadConfig
        {
            Host = args.Get("host") ?? "127.0.0.1",
            Port = args.GetInt("port", 2525),
            Connections = args.GetInt("connections", 16),
            Messages = args.GetInt("messages", 100_000),
            Size = args.GetInt("size", 2048),
            Recipients = args.GetInt("rcpt", 1),
            Pipelining = args.Flag("pipelining"),
            StartTls = args.Flag("starttls"),
            ImplicitTls = args.Flag("implicit-tls"),
            DurationSeconds = args.GetDouble("duration-s", 0),
            Auth = args.Get("auth"),
            Label = args.Get("label") ?? "",
            ServerPid = args.GetInt("server-pid", 0),
        };
        if (cfg.Connections < 1 || cfg.Size < 200 || cfg.Recipients < 1)
        {
            throw new ArgumentException("--connections >= 1, --size >= 200, --rcpt >= 1");
        }

        Console.WriteLine($"load: {cfg.Connections} connections -> {cfg.Host}:{cfg.Port}, size {cfg.Size} B, rcpt {cfg.Recipients}, pipelining={cfg.Pipelining}, tls={(cfg.ImplicitTls ? "implicit" : cfg.StartTls ? "starttls" : "none")}, {(cfg.DurationSeconds > 0 ? cfg.DurationSeconds + " s" : cfg.Messages + " messages")}");

        TimeSpan? serverCpuBefore = null;
        Process? server = null;
        if (cfg.ServerPid > 0)
        {
            try { server = Process.GetProcessById(cfg.ServerPid); serverCpuBefore = server.TotalProcessorTime; }
            catch (ArgumentException) { Console.Error.WriteLine("server pid not found; skipping server CPU"); }
        }

        long remaining = cfg.Messages;
        var deadline = cfg.DurationSeconds > 0 ? Stopwatch.GetTimestamp() + (long)(cfg.DurationSeconds * Stopwatch.Frequency) : long.MaxValue;
        var workers = new Worker[cfg.Connections];
        var sw = Stopwatch.StartNew();
        var tasks = new Task[cfg.Connections];
        for (int i = 0; i < workers.Length; i++)
        {
            workers[i] = new Worker(cfg, i);
            var w = workers[i];
            tasks[i] = Task.Run(() => w.RunAsync(() => Interlocked.Decrement(ref remaining) >= 0 || cfg.DurationSeconds > 0, deadline, ct), ct);
        }

        var progress = Task.Run(async () =>
        {
            long last = 0;
            while (!ct.IsCancellationRequested && tasks.Any(t => !t.IsCompleted))
            {
                await Task.Delay(1000, CancellationToken.None);
                long now = workers.Sum(w => Interlocked.Read(ref w.Accepted));
                Console.WriteLine($"  {sw.Elapsed.TotalSeconds,6:F1}s accepted={now} rate={now - last}/s");
                last = now;
            }
        }, CancellationToken.None);

        await Task.WhenAll(tasks);
        sw.Stop();
        await progress;

        var latencies = workers.SelectMany(w => w.Latencies).ToArray();
        Array.Sort(latencies);
        long accepted = workers.Sum(w => w.Accepted);
        long failed = workers.Sum(w => w.Failed);
        double seconds = sw.Elapsed.TotalSeconds;
        double Pct(double p) => latencies.Length == 0 ? 0 : latencies[Math.Min(latencies.Length - 1, (int)(latencies.Length * p))] * 1000.0 / Stopwatch.Frequency;
        double? cpuPerK = null;
        if (server is not null && serverCpuBefore is not null && accepted > 0)
        {
            server.Refresh();
            cpuPerK = (server.TotalProcessorTime - serverCpuBefore.Value).TotalMilliseconds / accepted * 1000.0;
        }

        var result = new
        {
            cfg.Label,
            Config = new { cfg.Host, cfg.Port, cfg.Connections, cfg.Size, cfg.Recipients, cfg.Pipelining, cfg.StartTls, cfg.ImplicitTls },
            Machine = new { Environment.ProcessorCount, OS = System.Runtime.InteropServices.RuntimeInformation.OSDescription, Runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription },
            Seconds = Math.Round(seconds, 3),
            Accepted = accepted,
            Failed = failed,
            MessagesPerSecond = Math.Round(accepted / seconds, 1),
            MegabytesPerSecond = Math.Round(accepted * (double)cfg.Size / seconds / 1_000_000, 2),
            LatencyMs = new { P50 = Math.Round(Pct(0.50), 3), P95 = Math.Round(Pct(0.95), 3), P99 = Math.Round(Pct(0.99), 3), Max = Math.Round(Pct(1.0), 3) },
            ServerCpuMsPer1000Messages = cpuPerK is null ? (double?)null : Math.Round(cpuPerK.Value, 1),
        };
        string json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
        Console.WriteLine(json);
        if (args.Get("json") is { } path)
        {
            await File.WriteAllTextAsync(path, json, CancellationToken.None);
        }

        return failed == 0 && accepted > 0 ? 0 : 1;
    }

    private sealed class LoadConfig
    {
        public required string Host { get; init; }
        public required int Port { get; init; }
        public required int Connections { get; init; }
        public required int Messages { get; init; }
        public required int Size { get; init; }
        public required int Recipients { get; init; }
        public required bool Pipelining { get; init; }
        public required bool StartTls { get; init; }
        public required bool ImplicitTls { get; init; }
        public required double DurationSeconds { get; init; }
        public string? Auth { get; init; }
        public required string Label { get; init; }
        public int ServerPid { get; init; }
    }

    private sealed class Worker(LoadConfig cfg, int index)
    {
        public long Accepted;
        public long Failed;
        public readonly List<long> Latencies = new(1 << 16);
        private Stream _stream = null!;
        private readonly byte[] _readBuf = new byte[8192];
        private int _readPos;
        private int _readLen;

        public async Task RunAsync(Func<bool> next, long deadline, CancellationToken ct)
        {
            try
            {
                await ConnectAsync(ct);
                byte[] message = BuildMessage(cfg.Size, index);
                int counterOffset = Encoding.ASCII.GetString(message).IndexOf("Message-ID: <", StringComparison.Ordinal) + "Message-ID: <".Length;
                long n = 0;
                byte[] mail = Encoding.ASCII.GetBytes($"MAIL FROM:<load{index}@bench.test>\r\n");
                byte[] rcpts = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, cfg.Recipients).Select(r => $"RCPT TO:<rcpt{r}@dest.test>\r\n")));
                byte[] data = "DATA\r\n"u8.ToArray();
                byte[] dot = ".\r\n"u8.ToArray();
                while (!ct.IsCancellationRequested && Stopwatch.GetTimestamp() < deadline && next())
                {
                    PatchCounter(message, counterOffset, n++);
                    long t0 = Stopwatch.GetTimestamp();
                    bool ok;
                    if (cfg.Pipelining)
                    {
                        await _stream.WriteAsync(Concat(mail, rcpts, data), ct);
                        ok = await ExpectAsync(250, ct);
                        for (int r = 0; r < cfg.Recipients && ok; r++) { ok = await ExpectAsync(250, ct); }
                        ok = ok && await ExpectAsync(354, ct);
                    }
                    else
                    {
                        await _stream.WriteAsync(mail, ct);
                        ok = await ExpectAsync(250, ct);
                        for (int r = 0; r < cfg.Recipients && ok; r++)
                        {
                            await _stream.WriteAsync(Encoding.ASCII.GetBytes($"RCPT TO:<rcpt{r}@dest.test>\r\n"), ct);
                            ok = await ExpectAsync(250, ct);
                        }

                        if (ok)
                        {
                            await _stream.WriteAsync(data, ct);
                            ok = await ExpectAsync(354, ct);
                        }
                    }

                    if (!ok) { Failed++; break; }
                    await _stream.WriteAsync(message, ct);
                    await _stream.WriteAsync(dot, ct);
                    ok = await ExpectAsync(250, ct);
                    long dt = Stopwatch.GetTimestamp() - t0;
                    if (ok)
                    {
                        Interlocked.Increment(ref Accepted);
                        Latencies.Add(dt);
                    }
                    else
                    {
                        Failed++;
                        break;
                    }
                }

                await _stream.WriteAsync("QUIT\r\n"u8.ToArray(), ct);
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or System.Security.Authentication.AuthenticationException)
            {
                Interlocked.Increment(ref Failed);
            }
        }

        private async Task ConnectAsync(CancellationToken ct)
        {
            var tcp = new TcpClient { NoDelay = true };
            await tcp.ConnectAsync(cfg.Host, cfg.Port, ct);
            _stream = tcp.GetStream();
            if (cfg.ImplicitTls)
            {
                _stream = await TlsAsync(_stream, ct);
            }

            if (!await ExpectAsync(220, ct)) { throw new IOException("bad banner"); }
            await _stream.WriteAsync("EHLO load.test\r\n"u8.ToArray(), ct);
            if (!await ExpectAsync(250, ct)) { throw new IOException("bad ehlo"); }
            if (cfg.StartTls && !cfg.ImplicitTls)
            {
                await _stream.WriteAsync("STARTTLS\r\n"u8.ToArray(), ct);
                if (!await ExpectAsync(220, ct)) { throw new IOException("starttls refused"); }
                _readPos = _readLen = 0;
                _stream = await TlsAsync(_stream, ct);
                await _stream.WriteAsync("EHLO load.test\r\n"u8.ToArray(), ct);
                if (!await ExpectAsync(250, ct)) { throw new IOException("bad ehlo"); }
            }

            if (cfg.Auth is { } auth)
            {
                string[] up = auth.Split(':', 2);
                string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes($"\0{up[0]}\0{up[1]}"));
                await _stream.WriteAsync(Encoding.ASCII.GetBytes($"AUTH PLAIN {b64}\r\n"), ct);
                if (!await ExpectAsync(235, ct)) { throw new IOException("auth failed"); }
            }
        }

        private static async Task<Stream> TlsAsync(Stream inner, CancellationToken ct)
        {
            var ssl = new SslStream(inner, false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "load.test" }, ct);
            return ssl;
        }

        /// <summary>Reads one (possibly multi-line) reply and checks the code.</summary>
        private async Task<bool> ExpectAsync(int code, CancellationToken ct)
        {
            while (true)
            {
                string? line = await ReadLineAsync(ct);
                if (line is null) { return false; }
                if (line.Length < 4) { return false; }
                if (line[3] == ' ')
                {
                    return int.Parse(line.AsSpan(0, 3), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture) == code;
                }
            }
        }

        private async Task<string?> ReadLineAsync(CancellationToken ct)
        {
            var sb = new StringBuilder(64);
            while (true)
            {
                if (_readPos == _readLen)
                {
                    _readLen = await _stream.ReadAsync(_readBuf, ct);
                    _readPos = 0;
                    if (_readLen == 0) { return null; }
                }

                byte b = _readBuf[_readPos++];
                if (b == '\n') { return sb.ToString().TrimEnd('\r'); }
                sb.Append((char)b);
            }
        }

        private static byte[] Concat(byte[] a, byte[] b, byte[] c)
        {
            byte[] r = new byte[a.Length + b.Length + c.Length];
            a.CopyTo(r, 0);
            b.CopyTo(r, a.Length);
            c.CopyTo(r, a.Length + b.Length);
            return r;
        }

        private static byte[] BuildMessage(int size, int worker)
        {
            var sb = new StringBuilder(size + 256);
            sb.Append("From: load").Append(worker).Append("@bench.test\r\nTo: rcpt0@dest.test\r\nSubject: load test\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n");
            sb.Append("Message-ID: <000000000000.").Append(worker.ToString("D4")).Append("@bench.test>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n");
            string line = new string('x', 74) + "\r\n";
            while (sb.Length + line.Length < size)
            {
                sb.Append(line);
            }

            return Encoding.ASCII.GetBytes(sb.ToString());
        }

        private static void PatchCounter(byte[] message, int offset, long counter)
        {
            for (int i = 11; i >= 0; i--)
            {
                message[offset + i] = (byte)('0' + counter % 10);
                counter /= 10;
            }
        }
    }
}
