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
/// <para>
/// The same generator drives the soak harness (<c>bench/soak</c>, docs/soak.md) with the options <c>--persist</c> (reconnect through server
/// outages instead of giving up), <c>--rate</c> (paced, open-ish load), <c>--size-mix</c>, <c>--id-prefix</c> (every message gets a unique,
/// numbered Message-ID), <c>--ack-log</c> (one line per message the server acknowledged: the proof the soak checks delivery against) and
/// <c>--stats-jsonl</c> (a counter and latency line per interval).
/// </para>
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
            Persist = args.Flag("persist"),
            Rate = args.GetDouble("rate", 0),
            SizeMix = ParseSizeMix(args.Get("size-mix"), args.GetInt("size", 2048)),
            IdPrefix = args.Get("id-prefix"),
            SeqStart = args.GetInt("seq-start", 0),
            FromAddress = args.Get("from") ?? "load@bench.test",
            RcptDomains = (args.Get("rcpt-domain") ?? "dest.test").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            IoTimeoutSeconds = args.GetDouble("io-timeout-s", 0),
            AckLog = args.Get("ack-log"),
            StatsJsonl = args.Get("stats-jsonl"),
            StatsIntervalSeconds = args.GetDouble("stats-interval-s", 10),
        };
        if (cfg.Connections < 1 || cfg.Size < 200 || cfg.Recipients < 1 || cfg.SizeMix.Any(m => m.Size < 200) || cfg.RcptDomains.Length == 0 || cfg.Rate < 0)
        {
            throw new ArgumentException("--connections >= 1, --size >= 200 (also in --size-mix), --rcpt >= 1, --rcpt-domain not empty, --rate >= 0");
        }

        if (cfg.Persist && cfg.DurationSeconds <= 0)
        {
            throw new ArgumentException("--persist needs --duration-s");
        }

        if (cfg.AckLog is not null && cfg.IdPrefix is null)
        {
            throw new ArgumentException("--ack-log needs --id-prefix (the log names messages by their sequence number)");
        }

        string sizes = cfg.SizeMix.Length > 1 ? string.Join(",", cfg.SizeMix.Select(m => $"{m.Size}:{m.Weight}")) : cfg.SizeMix[0].Size.ToString();
        Console.WriteLine($"load: {cfg.Connections} connections -> {cfg.Host}:{cfg.Port}, size {sizes} B, rcpt {cfg.Recipients}, pipelining={cfg.Pipelining}, tls={(cfg.ImplicitTls ? "implicit" : cfg.StartTls ? "starttls" : "none")}, {(cfg.DurationSeconds > 0 ? cfg.DurationSeconds + " s" : cfg.Messages + " messages")}{(cfg.Rate > 0 ? ", " + cfg.Rate + " msg/s" : "")}{(cfg.Persist ? ", persistent" : "")}");

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
        await using var shared = new SharedState(cfg);
        for (int i = 0; i < workers.Length; i++)
        {
            workers[i] = new Worker(cfg, i, shared);
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

        using var statsStop = new CancellationTokenSource();
        Task stats = cfg.StatsJsonl is null ? Task.CompletedTask : Task.Run(() => WriteStatsAsync(cfg, workers, sw, statsStop.Token), CancellationToken.None);
        await Task.WhenAll(tasks);
        sw.Stop();
        await progress;
        statsStop.Cancel();
        await stats;

        var latencies = workers.SelectMany(w => w.Latencies).ToArray();
        Array.Sort(latencies);
        long accepted = workers.Sum(w => w.Accepted);
        long failed = workers.Sum(w => w.Failed);
        long rejected = workers.Sum(w => Interlocked.Read(ref w.Rejected));
        long connectErrors = workers.Sum(w => Interlocked.Read(ref w.ConnectErrors));
        long bytesAccepted = workers.Sum(w => Interlocked.Read(ref w.BytesAccepted));
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
            Rejected = rejected,
            ConnectErrors = connectErrors,
            SessionLimitCloses = workers.Sum(w => Interlocked.Read(ref w.SessionLimitCloses)),
            MessagesPerSecond = Math.Round(accepted / seconds, 1),
            MegabytesPerSecond = Math.Round(bytesAccepted / seconds / 1_000_000, 2),
            LatencyMs = new { P50 = Math.Round(Pct(0.50), 3), P95 = Math.Round(Pct(0.95), 3), P99 = Math.Round(Pct(0.99), 3), Max = Math.Round(Pct(1.0), 3) },
            ServerCpuMsPer1000Messages = cpuPerK is null ? (double?)null : Math.Round(cpuPerK.Value, 1),
        };
        string json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
        Console.WriteLine(json);
        if (args.Get("json") is { } path)
        {
            await File.WriteAllTextAsync(path, json, CancellationToken.None);
        }

        // A persistent run goes through outages on purpose (crash drills): its verdict is the caller's, from the stats and the ack log.
        return (failed == 0 || cfg.Persist) && accepted > 0 ? 0 : 1;
    }

    /// <summary>"512:60,4096:30,65536:10": message sizes in bytes with relative weights. Without a mix, the single --size.</summary>
    private static (int Size, int Weight)[] ParseSizeMix(string? text, int fallbackSize)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return [(fallbackSize, 1)];
        }

        var mix = new List<(int, int)>();
        foreach (string part in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string[] bits = part.Split(':');
            if (bits.Length != 2 || !int.TryParse(bits[0], out int size) || !int.TryParse(bits[1], out int weight) || weight < 1)
            {
                throw new ArgumentException($"--size-mix entry '{part}' is not <bytes>:<weight>.");
            }

            mix.Add((size, weight));
        }

        return mix.Count == 0 ? [(fallbackSize, 1)] : [.. mix];
    }

    /// <summary>One JSON line per interval: the cumulative counters and the latency percentiles of that interval (the soak harness reads them).</summary>
    private static async Task WriteStatsAsync(LoadConfig cfg, Worker[] workers, Stopwatch clock, CancellationToken stop)
    {
        await using var writer = new StreamWriter(cfg.StatsJsonl!, append: true) { AutoFlush = true };
        var interval = TimeSpan.FromSeconds(Math.Max(1, cfg.StatsIntervalSeconds));
        while (true)
        {
            bool last = false;
            try { await Task.Delay(interval, stop); } catch (OperationCanceledException) { last = true; }
            var samples = new List<long>();
            foreach (var w in workers)
            {
                samples.AddRange(w.TakeIntervalLatencies());
            }

            samples.Sort();
            double Ms(double p) => samples.Count == 0 ? 0 : Math.Round(samples[Math.Min(samples.Count - 1, (int)(samples.Count * p))] * 1000.0 / Stopwatch.Frequency, 3);
            await writer.WriteLineAsync(JsonSerializer.Serialize(new
            {
                t = DateTime.UtcNow.ToString("O"),
                elapsed_s = Math.Round(clock.Elapsed.TotalSeconds, 1),
                accepted = workers.Sum(w => Interlocked.Read(ref w.Accepted)),
                rejected = workers.Sum(w => Interlocked.Read(ref w.Rejected)),
                connect_errors = workers.Sum(w => Interlocked.Read(ref w.ConnectErrors)),
                session_limit_closes = workers.Sum(w => Interlocked.Read(ref w.SessionLimitCloses)),
                interval_accepted = samples.Count,
                p50_ms = Ms(0.50),
                p95_ms = Ms(0.95),
                p99_ms = Ms(0.99),
                max_ms = Ms(1.0),
                final = last,
            }));
            if (last)
            {
                return;
            }
        }
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
        public bool Persist { get; init; }
        public double Rate { get; init; }
        public required (int Size, int Weight)[] SizeMix { get; init; }
        public string? IdPrefix { get; init; }
        public int SeqStart { get; init; }
        public required string FromAddress { get; init; }
        public required string[] RcptDomains { get; init; }
        public double IoTimeoutSeconds { get; init; }
        public string? AckLog { get; init; }
        public string? StatsJsonl { get; init; }
        public double StatsIntervalSeconds { get; init; }
    }

    /// <summary>State shared by the workers: the message sequence number (numbered runs give every message one) and the acknowledgement log.</summary>
    private sealed class SharedState : IAsyncDisposable
    {
        private readonly StreamWriter? _ackLog;
        private readonly object _ackLock = new();
        private readonly Timer? _flush;
        private long _next;

        public SharedState(LoadConfig cfg)
        {
            _next = cfg.SeqStart;
            if (cfg.AckLog is not null)
            {
                _ackLog = new StreamWriter(new FileStream(cfg.AckLog, FileMode.Append, FileAccess.Write, FileShare.ReadWrite), Encoding.ASCII);
                _flush = new Timer(_ => { lock (_ackLock) { _ackLog.Flush(); } }, null, 1000, 1000);
            }
        }

        public long NextSequence() => Interlocked.Increment(ref _next) - 1;

        /// <summary>One line per message the server acknowledged with 250: sequence number, size in bytes, the reply text (which carries the server's message id).</summary>
        public void Acknowledged(long sequence, int size, string reply)
        {
            if (_ackLog is null)
            {
                return;
            }

            lock (_ackLock)
            {
                _ackLog.Write(sequence);
                _ackLog.Write('\t');
                _ackLog.Write(size);
                _ackLog.Write('\t');
                _ackLog.WriteLine(reply);
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (_flush is not null) { await _flush.DisposeAsync(); }
            if (_ackLog is not null)
            {
                lock (_ackLock) { _ackLog.Flush(); }
                await _ackLog.DisposeAsync();
            }
        }
    }

    private sealed class Worker(LoadConfig cfg, int index, SharedState shared)
    {
        private static long s_rejectionsLogged;

        public long Accepted;
        public long Failed;
        public long Rejected;
        public long ConnectErrors;
        public long SessionLimitCloses;
        public long BytesAccepted;
        public readonly List<long> Latencies = new(1 << 16);
        private readonly object _intervalLock = new();
        private List<long> _interval = new(1 << 10);
        private readonly Random _random = new(index * 7919 + 17);
        private Stream _stream = null!;
        private readonly byte[] _readBuf = new byte[8192];
        private int _readPos;
        private int _readLen;
        private int _replyCode;
        private string _replyText = "";
        private long _nextDue;

        public List<long> TakeIntervalLatencies()
        {
            lock (_intervalLock)
            {
                var taken = _interval;
                _interval = new List<long>(taken.Capacity);
                return taken;
            }
        }

        /// <summary>Runs sessions until the work or time is used up. A server that ends a session (message limit per session, a refusal) is reconnected to; twenty sessions in a row without an accepted message stop the worker, unless the run is persistent (then it backs off up to two seconds and keeps trying until the time is up).</summary>
        public async Task RunAsync(Func<bool> next, long deadline, CancellationToken ct)
        {
            int idleSessions = 0;
            int backoffMs = 250;
            while (!ct.IsCancellationRequested && Stopwatch.GetTimestamp() < deadline && (cfg.Persist || idleSessions < 20))
            {
                long before = Interlocked.Read(ref Accepted);
                if (!await RunSessionAsync(next, deadline, ct))
                {
                    return;
                }

                if (cfg.Persist)
                {
                    backoffMs = Interlocked.Read(ref Accepted) > before ? 250 : Math.Min(backoffMs * 2, 2000);
                    try { await Task.Delay(backoffMs, ct); } catch (OperationCanceledException) { return; }
                }
                else
                {
                    idleSessions = Interlocked.Read(ref Accepted) > before ? 0 : idleSessions + 1;
                }
            }
        }

        /// <summary>One connection. Returns true when it ended abnormally (the caller may reconnect), false when the work is done.</summary>
        private async Task<bool> RunSessionAsync(Func<bool> next, long deadline, CancellationToken ct)
        {
            bool abnormal = false;
            // Persistent runs bound every network operation: a server that stops answering must show up as errors, not as a stuck worker.
            using var operation = CancellationTokenSource.CreateLinkedTokenSource(ct);
            CancellationToken io = cfg.IoTimeoutSeconds > 0 ? operation.Token : ct;
            TimeSpan ioTimeout = TimeSpan.FromSeconds(cfg.IoTimeoutSeconds);
            if (cfg.IoTimeoutSeconds > 0) { operation.CancelAfter(ioTimeout); }
            try
            {
                await ConnectAsync(io);
                var templates = cfg.SizeMix.Select(m => BuildMessage(m.Size, index, cfg)).ToArray();
                int totalWeight = cfg.SizeMix.Sum(m => m.Weight);
                long legacyCounter = 0;
                byte[] mail = Encoding.ASCII.GetBytes($"MAIL FROM:<{cfg.FromAddress}>\r\n");
                byte[][] rcptsByDomain = cfg.RcptDomains.Select(d => Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, cfg.Recipients).Select(r => $"RCPT TO:<rcpt{r}@{d}>\r\n")))).ToArray();
                byte[] data = "DATA\r\n"u8.ToArray();
                byte[] dot = ".\r\n"u8.ToArray();
                long interval = cfg.Rate > 0 ? (long)(cfg.Connections / cfg.Rate * Stopwatch.Frequency) : 0;
                if (interval > 0 && _nextDue == 0)
                {
                    _nextDue = Stopwatch.GetTimestamp() + interval * index / cfg.Connections;   // staggered start
                }

                while (!ct.IsCancellationRequested && Stopwatch.GetTimestamp() < deadline && next())
                {
                    if (interval > 0)
                    {
                        if (cfg.IoTimeoutSeconds > 0) { operation.CancelAfter(Timeout.InfiniteTimeSpan); }   // waiting for the next slot is not network time
                        long wait = _nextDue - Stopwatch.GetTimestamp();
                        if (wait > 0)
                        {
                            await Task.Delay(TimeSpan.FromSeconds((double)wait / Stopwatch.Frequency), ct);
                        }

                        // Never try to catch up more than a second of backlog (after an outage): a burst would be a different load.
                        _nextDue = Math.Max(_nextDue + interval, Stopwatch.GetTimestamp() - Stopwatch.Frequency);
                    }

                    if (cfg.IoTimeoutSeconds > 0) { operation.CancelAfter(ioTimeout); }
                    int pick = 0;
                    if (templates.Length > 1)
                    {
                        int roll = _random.Next(totalWeight);
                        while (roll >= cfg.SizeMix[pick].Weight) { roll -= cfg.SizeMix[pick++].Weight; }
                    }

                    var (message, counterOffset) = templates[pick];
                    long n = cfg.IdPrefix is null ? legacyCounter++ : shared.NextSequence();
                    PatchCounter(message, counterOffset, n);
                    int domain = (int)(n % cfg.RcptDomains.Length);
                    byte[] rcpts = rcptsByDomain[domain];
                    long t0 = Stopwatch.GetTimestamp();
                    bool ok;
                    if (cfg.Pipelining)
                    {
                        await _stream.WriteAsync(Concat(mail, rcpts, data), io);
                        ok = await ExpectAsync(250, io);
                        for (int r = 0; r < cfg.Recipients && ok; r++) { ok = await ExpectAsync(250, io); }
                        ok = ok && await ExpectAsync(354, io);
                    }
                    else
                    {
                        await _stream.WriteAsync(mail, io);
                        ok = await ExpectAsync(250, io);
                        for (int r = 0; r < cfg.Recipients && ok; r++)
                        {
                            await _stream.WriteAsync(Encoding.ASCII.GetBytes($"RCPT TO:<rcpt{r}@{cfg.RcptDomains[domain]}>\r\n"), io);
                            ok = await ExpectAsync(250, io);
                        }

                        if (ok)
                        {
                            await _stream.WriteAsync(data, io);
                            ok = await ExpectAsync(354, io);
                        }
                    }

                    if (!ok)
                    {
                        // The server's own limit on messages per session (Smtp:MaxMessagesPerSession) ends a session politely with 421 at the next
                        // MAIL FROM: a client reconnects, it has not been refused. Counted on its own, so it neither hides a real 421 nor looks like an error.
                        if (_replyCode == 421 && _replyText.Contains("Too many messages", StringComparison.OrdinalIgnoreCase))
                        {
                            Interlocked.Increment(ref SessionLimitCloses);
                        }
                        else
                        {
                            CountFailure();
                        }

                        abnormal = true;
                        break;
                    }

                    await _stream.WriteAsync(message, io);
                    await _stream.WriteAsync(dot, io);
                    ok = await ExpectAsync(250, io);
                    long dt = Stopwatch.GetTimestamp() - t0;
                    if (ok)
                    {
                        Interlocked.Increment(ref Accepted);
                        Interlocked.Add(ref BytesAccepted, message.Length);
                        Latencies.Add(dt);
                        lock (_intervalLock) { _interval.Add(dt); }
                        shared.Acknowledged(n, message.Length, _replyText);
                    }
                    else
                    {
                        CountFailure();
                        abnormal = true;
                        break;
                    }
                }

                if (!abnormal)
                {
                    await _stream.WriteAsync("QUIT\r\n"u8.ToArray(), io);
                }
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or System.Security.Authentication.AuthenticationException)
            {
                Interlocked.Increment(ref Failed);
                if (!ct.IsCancellationRequested)
                {
                    Interlocked.Increment(ref ConnectErrors);   // a stop requested by the caller is not a server problem
                }

                abnormal = true;
            }

            try { _stream?.Dispose(); } catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
            return abnormal;
        }

        /// <summary>A reply with a failure code means a live server said no (counted as rejected); no reply at all means the connection broke (counted as a connection error).</summary>
        private void CountFailure()
        {
            if (_replyCode >= 400 && Interlocked.Increment(ref s_rejectionsLogged) <= 40)
            {
                Console.Error.WriteLine($"{DateTime.UtcNow:HH:mm:ss} refused by the server: {_replyText}");   // what a live server said, for the first few
            }

            Interlocked.Increment(ref Failed);
            Interlocked.Increment(ref _replyCode >= 400 ? ref Rejected : ref ConnectErrors);
        }

        private async Task ConnectAsync(CancellationToken ct)
        {
            _readPos = 0;
            _readLen = 0;
            _replyCode = 0;
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

            _replyCode = 0;
        }

        private static async Task<Stream> TlsAsync(Stream inner, CancellationToken ct)
        {
            var ssl = new SslStream(inner, false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "load.test" }, ct);
            return ssl;
        }

        /// <summary>Reads one (possibly multi-line) reply and checks the code; remembers the code and the text of its last line.</summary>
        private async Task<bool> ExpectAsync(int code, CancellationToken ct)
        {
            _replyCode = 0;
            while (true)
            {
                string? line = await ReadLineAsync(ct);
                if (line is null) { return false; }
                if (line.Length < 4) { return false; }
                if (line[3] == ' ')
                {
                    _replyCode = int.Parse(line.AsSpan(0, 3), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture);
                    _replyText = line;
                    return _replyCode == code;
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

        /// <summary>The message and the offset of its 12 counter digits. Without --id-prefix the id is "counter.worker@bench.test" (the original form); with it "prefix.counter@from-domain".</summary>
        private static (byte[] Message, int CounterOffset) BuildMessage(int size, int worker, LoadConfig cfg)
        {
            var sb = new StringBuilder(size + 256);
            string fromDomain = cfg.FromAddress[(cfg.FromAddress.IndexOf('@') + 1)..];
            sb.Append("From: ").Append(cfg.FromAddress).Append("\r\nTo: rcpt0@").Append(cfg.RcptDomains[0]).Append("\r\nSubject: load test\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n");
            sb.Append("Message-ID: <");
            int counterOffset;
            if (cfg.IdPrefix is null)
            {
                counterOffset = sb.Length;
                sb.Append("000000000000.").Append(worker.ToString("D4")).Append("@bench.test>");
            }
            else
            {
                sb.Append(cfg.IdPrefix).Append('.');
                counterOffset = sb.Length;
                sb.Append("000000000000@").Append(fromDomain).Append('>');
            }

            sb.Append("\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n");
            string line = new string('x', 74) + "\r\n";
            while (sb.Length + line.Length < size)
            {
                sb.Append(line);
            }

            // The first character of the id is at a known offset in the ASCII text (no multi-byte characters), so it is also the byte offset.
            return (Encoding.ASCII.GetBytes(sb.ToString()), counterOffset);
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
