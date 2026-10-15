using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Mta.Core;
using Mta.Dkim;
using Mta.Dns;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Security;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.Postgres;
using Mta.Storage.Sqlite;

// Whole-pipeline benchmark: the real runtime (SMTP ingest, storage, DKIM signing at delivery, delivery engine) in this process, a counting
// sink as the remote MTA, and the separate-process load generator (mta-tools load) as the client. Reports ingest throughput (accepted
// at the final 250), end-to-end throughput (until the sink has received everything), allocations and CPU of this process.
//
//   dotnet run -c Release --project bench/Mta.Bench.Pipeline -- --sync off --messages 50000 --connections 32 --size 2048
//   options: --backend sqlite|postgres (postgres needs EGGMAIL_BENCH_POSTGRES=<connection string of an empty database>)
//            --sync off|normal|full   --history full|statsonly   --messages N   --connections N   --size BYTES   --rcpt N
//            --micro true [--only TEXT] [--alloc-profile true] [--json FILE (byte counts, read by the CI allocation gate)]: per-step allocation of the ingest path;  --micro-delivery true: per-step allocation of the delivery path;  --sink-only true: the SMTP server alone
//            --idle N (Delivery:MaxIdleConnectionsPerTarget, default 2: the production default)   --tls true|false (default true: STARTTLS; false measures the server without TLS)   --deliver true|false (default true: also drain the queue to the sink)   --split true (start delivery after ingest so each phase is measured alone)   --label TEXT   --json out.json
var opt = Args.Parse(args);
if (opt.Get("micro-delivery", "false") == "true")
{
    await MicroDelivery.RunAsync();
    return 0;
}

if (opt.Get("micro", "false") == "true")
{
    await Micro.RunAsync(opt.Get("alloc-profile", "false") == "true", opt.Get("only", ""), opt.Get("json", ""));
    return 0;
}

using var allocProfile = opt.Get("alloc-profile", "false") == "true" ? new AllocationSampler() : null;
if (opt.Get("sink-only", "false") == "true")
{
    return await SinkOnly.RunAsync(opt, allocProfile);
}

// --metrics true attaches the Prometheus exporter (what a production process always has, so every instrument records) and a queue sampler;
// --trace true also attaches a trace listener that records every span (the upper bound of tracing; production samples a fraction). Both
// default to off: no listener, the way the library benchmarks run.
using var prometheus = opt.Get("metrics", "false") == "true" ? new Mta.Observability.PrometheusTextExporter() : null;
using var traceListener = opt.Get("trace", "false") == "true" ? AttachTraceListener() : null;
static System.Diagnostics.ActivityListener AttachTraceListener()
{
    var listener = new System.Diagnostics.ActivityListener
    {
        ShouldListenTo = s => s.Name == MessageTrace.SourceName,
        Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> _) => System.Diagnostics.ActivitySamplingResult.AllDataAndRecorded,
    };
    System.Diagnostics.ActivitySource.AddActivityListener(listener);
    return listener;
}

string backend = opt.Get("backend", "sqlite");
var sync = Enum.Parse<SqliteSyncMode>(opt.Get("sync", "off"), ignoreCase: true);
var history = Enum.Parse<HistoryMode>(opt.Get("history", "full"), ignoreCase: true);
int messages = int.Parse(opt.Get("messages", "50000"));
int connections = int.Parse(opt.Get("connections", "32"));
int size = int.Parse(opt.Get("size", "2048"));
int rcpt = int.Parse(opt.Get("rcpt", "1"));
bool deliver = bool.Parse(opt.Get("deliver", "true"));
bool tls = opt.Get("tls", "true") == "true";   // false: the submission listener is plain text with AUTH allowed, to measure the server without the TLS stack
bool split = opt.Get("split", "false") == "true";   // start the delivery engine only after ingest finished, so each phase is measured on its own
string label = opt.Get("label", $"{backend}-{(backend == "sqlite" ? sync.ToString() : "pg")}-{history}");

string dir = Directory.CreateTempSubdirectory("eggmail-bench-").FullName;
var sink = new CountingSink();
var sinkServer = new SmtpServer(new SmtpServerOptions
{
    Hostname = "sink.bench",
    MaxMessageSize = 64L * 1024 * 1024,
    MaxRecipients = 1000,
    Listeners = [new SmtpListenerOptions { Name = "sink", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce }],
}, sink);
sinkServer.Start();

var dns = new StaticDnsResolver().AddMx("dest.test", 10, "mx.dest.test").AddA("mx.dest.test", "127.0.0.1");
var storageOptions = new StorageOptions
{
    Backend = backend == "postgres" ? StorageBackend.Postgres : StorageBackend.Sqlite,
    History = new HistoryOptions { Mode = history },
    Content = new ContentOptions { Retain = opt.Get("content", "true") == "true" },
    Sqlite = new SqliteOptions { DataDirectory = dir, SyncMode = sync },
    Postgres = new PostgresOptions
    {
        OwnerConnectionString = Environment.GetEnvironmentVariable("EGGMAIL_BENCH_POSTGRES"),
        RuntimeConnectionString = Environment.GetEnvironmentVariable("EGGMAIL_BENCH_POSTGRES"),
    },
};
var config = new MtaConfig
{
    Hostname = "bench.local",
    Storage = storageOptions,
    Smtp = new SmtpSection
    {
        MaxConnections = 4096, MaxConnectionsPerIp = 4096,
        Listeners = new Dictionary<string, ListenerSection> { ["submission"] = new() { Port = 0, BindAddress = "127.0.0.1", Mode = tls ? ListenerMode.StartTls : ListenerMode.Plain, AuthRequired = true, AllowInsecureAuth = !tls } },
    },
    Delivery = new DeliverySection
    {
        RemotePort = sinkServer.LocalEndPoints["sink"].Port, AllowPrivateMxAddresses = true, Workers = 64, BounceDomain = "bounces.bench.local",
        MaxIdleConnectionsPerTarget = int.Parse(opt.Get("idle", "2")),
        Throttle = new ThrottleSection { MaxConnections = 64, InitialConnections = 64, MaxMessagesPerMinute = 100_000_000, InitialMessagesPerMinute = 100_000_000, MaxMessagesPerConnection = 10_000 },
    },
    Backup = new BackupSection { Enabled = false },
};
IStorage storage = backend == "postgres" ? PostgresStorage.Create(storageOptions) : SqliteStorage.Create(storageOptions);
await storage.InitializeAsync(default);
await using var runtime = await EggMailRuntime.CreateAsync(config, storage, SystemClock.Instance, NullMtaLog.Instance, default, dns);

var tenant = Guid.NewGuid();
var now = DateTimeOffset.UtcNow;
var domainId = Ids.New();
using var dkim = DkimKeyTools.GenerateRsa2048();
await storage.Config.UpsertTenantAsync(new Tenant(tenant, "Bench", "bench", true, now, false), default);
await storage.Config.UpsertDomainAsync(new DomainRecord(domainId, tenant, "bench.test", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
await storage.Config.AddDkimKeyAsync(new Mta.Storage.DkimKeyRecord(Ids.New(), domainId, "bench1", runtime.Secrets.Protect(dkim.ExportPkcs8PrivateKey(), SecretPurposes.DkimKey), DkimKeyTools.ExportPublicKeyBase64(dkim), now, true, null), default);
await storage.Config.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), tenant, "bench", PasswordHasher.Hash("bench-pass", 2000), true, now), default);

runtime.SmtpServer.Start();
int port = runtime.SmtpServer.LocalEndPoints["submission"].Port;
using var stop = new CancellationTokenSource();
Task? engine = null;
if (deliver && !split)
{
    engine = Task.Run(() => runtime.Delivery.RunAsync(stop.Token));
}

string tools = Environment.GetEnvironmentVariable("EGGMAIL_BENCH_TOOLS") ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "Mta.Tools", "bin", "Release", "net10.0", "mta-tools.dll"));
if (!File.Exists(tools))
{
    Console.Error.WriteLine("Build the load generator first: dotnet build -c Release src/Mta.Tools   (expected " + tools + ")");
    return 2;
}

string loadJson = Path.Combine(dir, "load.json");
long allocBefore = GC.GetTotalAllocatedBytes(precise: true);
var cpuBefore = Process.GetCurrentProcess().TotalProcessorTime;
var wall = Stopwatch.StartNew();
var psi = new ProcessStartInfo("dotnet", $"\"{tools}\" load --port {port} {(tls ? "--starttls " : "")}--auth bench:bench-pass --connections {connections} --messages {messages} --size {size} --rcpt {rcpt} --json \"{loadJson}\" --label \"{label}\"")
{
    RedirectStandardOutput = true,
    RedirectStandardError = true,
};
psi.Environment.Remove("DOTNET_EnableEventPipe");   // a trace of this process (see docs/benchmarks.md) must not be started in the load generator too
using (var load = Process.Start(psi)!)
{
    await load.StandardOutput.ReadToEndAsync();
    await load.WaitForExitAsync();
    if (load.ExitCode != 0)
    {
        Console.Error.WriteLine("load generator failed: " + await load.StandardError.ReadToEndAsync());
    }
}

double ingestSeconds = wall.Elapsed.TotalSeconds;
long allocAfterIngest = GC.GetTotalAllocatedBytes(precise: true);
var cpuAfterIngest = Process.GetCurrentProcess().TotalProcessorTime;

double endToEndSeconds = ingestSeconds;
long expected = (long)messages * rcpt;
double deliverySeconds = 0;
if (deliver && split)
{
    if (allocProfile is not null)
    {
        Console.WriteLine("ingest phase:");
        allocProfile.Print(25);
        allocProfile.Reset();
    }

    GC.Collect();
    allocAfterIngest = GC.GetTotalAllocatedBytes(precise: true);
    cpuAfterIngest = Process.GetCurrentProcess().TotalProcessorTime;
    wall.Restart();
    engine = Task.Run(() => runtime.Delivery.RunAsync(stop.Token));
}

if (deliver)
{
    var deadline = DateTime.UtcNow.AddMinutes(10);
    while (Interlocked.Read(ref sink.Recipients) < expected && DateTime.UtcNow < deadline)
    {
        await Task.Delay(50);
    }

    endToEndSeconds = wall.Elapsed.TotalSeconds;
    deliverySeconds = endToEndSeconds;
}

long allocAfterDelivery = GC.GetTotalAllocatedBytes(precise: true);
var cpuAfterDelivery = Process.GetCurrentProcess().TotalProcessorTime;

using var loadDoc = JsonDocument.Parse(File.ReadAllText(loadJson));
var l = loadDoc.RootElement;
long accepted = l.GetProperty("Accepted").GetInt64();
var result = new
{
    Label = label,
    Backend = backend,
    SqliteSync = backend == "sqlite" ? sync.ToString() : null,
    History = history.ToString(),
    Messages = messages,
    Recipients = rcpt,
    Connections = connections,
    SizeBytes = size,
    Machine = new { Environment.ProcessorCount, OS = System.Runtime.InteropServices.RuntimeInformation.OSDescription, Runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription },
    Ingest = new
    {
        Accepted = accepted,
        MessagesPerSecond = l.GetProperty("MessagesPerSecond").GetDouble(),
        LatencyMs = new { P50 = l.GetProperty("LatencyMs").GetProperty("P50").GetDouble(), P99 = l.GetProperty("LatencyMs").GetProperty("P99").GetDouble() },
        ServerAllocatedBytesPerMessage = accepted == 0 ? 0 : (allocAfterIngest - allocBefore) / accepted,
        ServerCpuMsPer1000Messages = accepted == 0 ? 0 : Math.Round((cpuAfterIngest - cpuBefore).TotalMilliseconds / accepted * 1000, 1),
    },
    EndToEnd = deliver ? new
    {
        DeliveredRecipients = Interlocked.Read(ref sink.Recipients),
        Seconds = Math.Round(endToEndSeconds, 2),
        RecipientsPerSecond = Math.Round(Interlocked.Read(ref sink.Recipients) / endToEndSeconds, 1),
        ServerAllocatedBytesPerMessage = split ? 0 : accepted == 0 ? 0 : (allocAfterDelivery - allocBefore) / accepted,
        ServerCpuMsPer1000Messages = split ? 0 : accepted == 0 ? 0 : Math.Round((cpuAfterDelivery - cpuBefore).TotalMilliseconds / accepted * 1000, 1),
        DeliveryPhaseOnly = split ? new
        {
            Seconds = Math.Round(deliverySeconds, 2),
            RecipientsPerSecond = Math.Round(Interlocked.Read(ref sink.Recipients) / deliverySeconds, 1),
            ServerAllocatedBytesPerMessage = accepted == 0 ? 0 : (allocAfterDelivery - allocAfterIngest) / accepted,
            ServerCpuMsPer1000Messages = accepted == 0 ? 0 : Math.Round((cpuAfterDelivery - cpuAfterIngest).TotalMilliseconds / accepted * 1000, 1),
        } : null,
    } : null,
    Gen2Collections = GC.CollectionCount(2),
};
string json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
Console.WriteLine(json);
if (opt.Get("json", "") is { Length: > 0 } outPath)
{
    File.WriteAllText(outPath, json);
}

allocProfile?.Print();
await stop.CancelAsync();
if (engine is not null)
{
    try { await engine; } catch (OperationCanceledException) { }
}

await runtime.SmtpServer.StopAsync(TimeSpan.FromSeconds(2));
await sinkServer.DisposeAsync();
await storage.DisposeAsync();
try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
return 0;

internal sealed class CountingSink : ISmtpServerHandler
{
    public long Recipients;

    public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken ct) => ValueTask.FromResult<SmtpReply?>(null);

    public ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct) => ValueTask.FromResult(SmtpAuthResult.Failed);

    public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.SenderOk);

    public ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters p, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.RecipientOk);

    public ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
    {
        Interlocked.Add(ref Recipients, message.Recipients.Count);
        return ValueTask.FromResult(SmtpReply.Create(250, "2.0.0", "OK"));
    }

    public void OnDisconnected(SmtpSessionContext session)
    {
    }
}

internal sealed class Args
{
    private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);

    public static Args Parse(string[] args)
    {
        var a = new Args();
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].StartsWith("--", StringComparison.Ordinal))
            {
                a._values[args[i][2..]] = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal) ? args[++i] : "true";
            }
        }

        return a;
    }

    public string Get(string key, string fallback) => _values.TryGetValue(key, out var v) ? v : fallback;
}

/// <summary>Samples allocations by type through the runtime's GCAllocationTick events (one event per about 100 KB allocated).</summary>
internal sealed class AllocationSampler : System.Diagnostics.Tracing.EventListener
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, long> _bytes = new();

    protected override void OnEventSourceCreated(System.Diagnostics.Tracing.EventSource source)
    {
        if (source.Name == "Microsoft-Windows-DotNETRuntime")
        {
            EnableEvents(source, System.Diagnostics.Tracing.EventLevel.Verbose, (System.Diagnostics.Tracing.EventKeywords)0x1);   // GC
        }
    }

    protected override void OnEventWritten(System.Diagnostics.Tracing.EventWrittenEventArgs e)
    {
        if (e.EventName?.StartsWith("GCAllocationTick", StringComparison.Ordinal) != true || e.Payload is null || e.PayloadNames is null)
        {
            return;
        }

        int typeIndex = e.PayloadNames.IndexOf("TypeName");
        int amountIndex = e.PayloadNames.IndexOf("AllocationAmount64");
        if (typeIndex < 0 || amountIndex < 0)
        {
            return;
        }

        _bytes.AddOrUpdate(e.Payload[typeIndex]?.ToString() ?? "?", Convert.ToInt64(e.Payload[amountIndex]), (_, old) => old + Convert.ToInt64(e.Payload[amountIndex]));
    }

    public void Reset() => _bytes.Clear();

    public void Print(int top = 25)
    {
        long total = _bytes.Values.Sum();
        Console.WriteLine($"allocation sample (about 100 KB granularity), total {total / 1_000_000.0:F1} MB:");
        foreach (var (type, bytes) in _bytes.OrderByDescending(kv => kv.Value).Take(top))
        {
            Console.WriteLine($"  {bytes * 100.0 / total,5:F1}%  {type}");
        }
    }
}

/// <summary>Allocation per call of the ingest steps in isolation (bytes per operation, all threads, measured while nothing else runs).</summary>
internal static class Micro
{
    private const string Head = "From: Tester <news@bench.test>\r\nTo: rcpt0@dest.test\r\nSubject: load test\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\nMessage-ID: <abcdef@bench.test>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n";

    private static AllocationSampler? _sampler;

    private static string _only = "";

    private static bool Wanted(string name) => _only.Length == 0 || name.Contains(_only, StringComparison.OrdinalIgnoreCase);

    private static readonly Dictionary<string, long> Results = new(StringComparer.Ordinal);

    public static async Task RunAsync(bool profile, string only = "", string jsonPath = "")
    {
        _only = only;
        using var allocProfile = profile ? new AllocationSampler() : null;
        _sampler = allocProfile;
        byte[] raw = System.Text.Encoding.ASCII.GetBytes(Head + new string('x', 1800) + "\r\n");
        byte[] tiny = System.Text.Encoding.ASCII.GetBytes(Head + "hello\r\n");
        byte[] received = System.Text.Encoding.ASCII.GetBytes("Received: from client.test (127.0.0.1) by egg.local with ESMTPSA id abc; Mon, 12 Oct 2026 08:00:00 +0000\r\n");

        Console.WriteLine($"message of {raw.Length} bytes (2 KB) and of {tiny.Length} bytes (headers only, 'tiny'); B/op = bytes allocated per operation");
        Measure("MimeMessage.Parse", () => { Mta.Mime.MimeMessage.Parse(raw); });
        Measure("MessageHeaderEditor (Received only, ToArray)", () =>
        {
            var e = new Mta.Mime.MessageHeaderEditor(raw);
            e.PrependRawWithoutCopy(received);
            e.ToArray();
        });
        Measure("MessageHeaderEditor (remove Bcc, 2 prepends, Received, ToArray)", () =>
        {
            var e = new Mta.Mime.MessageHeaderEditor(raw);
            e.Remove("Bcc");
            e.Prepend("Message-ID", "<x@y>");
            e.Prepend("Date", "Mon, 12 Oct 2026 08:00:00 +0000");
            e.PrependRawWithoutCopy(received);
            e.ToArray();
        });
        var parsedOnce = Mta.Mime.MimeMessage.Parse(raw);
        Measure("MessageContentExtractor.Extract(raw) (parses itself)", () => { Mta.Mime.MessageContentExtractor.Extract(raw, 262144); });
        Measure("MessageContentExtractor.Extract(parsed message)", () => { Mta.Mime.MessageContentExtractor.Extract(parsedOnce, 262144); });
        Measure("AddressList.Parse(From) + GetCommonDomain (the full parser, as before)", () => { Mta.Mime.AddressList.Parse("Tester <news@bench.test>").GetCommonDomain(out _); });
        Measure("AddressList.GetCommonDomain(From header) (the simple-address shortcut)", () => { Mta.Mime.AddressList.GetCommonDomain(parsedOnce.Headers[0], null, out _); });
        Measure("Ids.New + EmailAddress.Parse x2", () => { Mta.Core.Ids.New(); Mta.Core.EmailAddress.Parse("rcpt0@dest.test"); Mta.Core.EmailAddress.Parse("load0@bench.test"); });

        var tenant = new Mta.Storage.Tenant(Guid.NewGuid(), "T", "t", true, DateTimeOffset.UtcNow, false);
        string dir = Directory.CreateTempSubdirectory("eggmail-micro-").FullName;
        try
        {
            foreach (var (label, storage) in new (string, Mta.Storage.IStorage)[]
            {
                ("InMemory", new Mta.Storage.InMemory.InMemoryStorage(new Mta.Storage.StorageOptions())),
                ("SQLite (sync off)", Mta.Storage.Sqlite.SqliteStorage.Create(new Mta.Storage.StorageOptions { Sqlite = new Mta.Storage.SqliteOptions { DataDirectory = dir, SyncMode = Mta.Storage.SqliteSyncMode.Off } })),
            })
            {
                await storage.InitializeAsync(default);
                await storage.Config.UpsertDomainAsync(new Mta.Storage.DomainRecord(Guid.NewGuid(), tenant.Id, "bench.test", Mta.Storage.DomainStatus.Verified, null, false, DateTimeOffset.UtcNow, null, null, 0, null, false, null), default);
                var options = new Mta.Storage.StorageOptions();
                var submission = new Mta.Host.Submission.SubmissionService(storage, Mta.Core.SystemClock.Instance, new Mta.Policy.SenderPolicy(), options);
                foreach (var (size, message) in new[] { ("2 KB", raw), ("tiny", tiny) })
                {
                    var request = new Mta.Host.Submission.SubmissionRequest { Tenant = tenant, Source = Mta.Storage.MessageSource.Smtp, EnvelopeFrom = Mta.Core.EmailAddress.Parse("load0@bench.test"), Recipients = [Mta.Core.EmailAddress.Parse("rcpt0@dest.test")], Message = message, ReceivedHeader = received };
                    await MeasureAsync($"SubmissionService.SubmitAsync, {label}, history Full, {size}", async () => { await submission.SubmitAsync(request, default); });
                    if (label != "InMemory")
                    {
                        await MeasureConcurrentAsync($"SubmissionService.SubmitAsync, {label}, history Full, {size}, 32 concurrent", () => submission.SubmitAsync(request, default).AsTask());
                    }
                }

                await storage.DisposeAsync();
            }
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }

        if (jsonPath.Length > 0)
        {
            // Read by bench/compare-allocations.py (the allocation gate).
            File.WriteAllText(jsonPath, JsonSerializer.Serialize(new { Kind = "micro", BytesPerOperation = Results }, new JsonSerializerOptions { WriteIndented = true }));
        }
    }

    private static void Measure(string name, Action action)
    {
        if (!Wanted(name))
        {
            return;
        }

        for (int i = 0; i < 200; i++) { action(); }
        const int n = 10000;
        long bytes = 0;
        double best = double.MaxValue;
        for (int pass = 0; pass < 3; pass++)   // the fastest of three passes: the machine is shared and noisy
        {
            long before = GC.GetAllocatedBytesForCurrentThread();
            long started = Stopwatch.GetTimestamp();
            for (int i = 0; i < n; i++) { action(); }
            best = Math.Min(best, Stopwatch.GetElapsedTime(started).TotalMicroseconds / n);
            bytes = (GC.GetAllocatedBytesForCurrentThread() - before) / n;
        }

        Results[name] = bytes;
        Console.WriteLine($"{name,-80} {bytes,8} B/op {best,8:F2} us/op");
    }

    /// <summary>The same operation from 32 concurrent callers, so a writer can group commit (the per-batch cost is shared by the batch).</summary>
    private static async Task MeasureConcurrentAsync(string name, Func<Task> action)
    {
        if (!Wanted(name))
        {
            return;
        }

        const int callers = 32;
        async Task Run(int each) { for (int i = 0; i < each; i++) { await action(); } }
        await Task.WhenAll(Enumerable.Range(0, callers).Select(_ => Run(20)));
        GC.Collect();
        _sampler?.Reset();
        long before = GC.GetTotalAllocatedBytes(precise: true);
        const int each = 400;
        double best = double.MaxValue;
        long bytes = 0;
        for (int pass = 0; pass < 3; pass++)
        {
            GC.Collect();
            before = GC.GetTotalAllocatedBytes(precise: true);
            long started = Stopwatch.GetTimestamp();
            await Task.WhenAll(Enumerable.Range(0, callers).Select(_ => Run(each)));
            best = Math.Min(best, Stopwatch.GetElapsedTime(started).TotalMicroseconds / (callers * each));
            bytes = (GC.GetTotalAllocatedBytes(precise: true) - before) / (callers * each);
        }

        Results[name] = bytes;
        Console.WriteLine($"{name,-80} {bytes,8} B/op {best,8:F2} us/op (wall time per message)");
        _sampler?.Print(14);
    }

    private static async Task MeasureAsync(string name, Func<Task> action)
    {
        if (!Wanted(name))
        {
            return;
        }

        for (int i = 0; i < 300; i++) { await action(); }
        const int n = 20000;
        long bytes = 0;
        double best = double.MaxValue;
        for (int pass = 0; pass < 3; pass++)   // the fastest of three passes: the machine is shared and noisy
        {
            GC.Collect();
            _sampler?.Reset();
            long before = GC.GetTotalAllocatedBytes(precise: true);
            long started = Stopwatch.GetTimestamp();
            for (int i = 0; i < n; i++) { await action(); }
            best = Math.Min(best, Stopwatch.GetElapsedTime(started).TotalMicroseconds / n);
            bytes = (GC.GetTotalAllocatedBytes(precise: true) - before) / n;
        }

        Results[name] = bytes;
        Console.WriteLine($"{name,-80} {bytes,8} B/op {best,8:F2} us/op");
        _sampler?.Print(14);
    }
}

/// <summary>
/// The SMTP server protocol path alone: the load generator talks plain SMTP to the counting sink, so the allocation per message is that of
/// the session, the DATA reader and the reply (no storage, no authentication, no TLS). Run with <c>--sink-only true</c>.
/// </summary>
internal static class SinkOnly
{
    public static async Task<int> RunAsync(Args opt, AllocationSampler? allocProfile)
    {
        int messages = int.Parse(opt.Get("messages", "50000"));
        int connections = int.Parse(opt.Get("connections", "32"));
        int size = int.Parse(opt.Get("size", "2048"));
        var sink = new CountingSink();
        await using var server = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "sink.bench",
            MaxMessageSize = 64L * 1024 * 1024,
            MaxRecipients = 1000,
            Listeners = [new SmtpListenerOptions { Name = "sink", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce }],
        }, sink);
        server.Start();
        string tools = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "Mta.Tools", "bin", "Release", "net10.0", "mta-tools.dll"));
        string loadJson = Path.Combine(Path.GetTempPath(), "eggmail-sink-load-" + Guid.NewGuid().ToString("N") + ".json");
        GC.Collect();
        allocProfile?.Reset();
        long before = GC.GetTotalAllocatedBytes(precise: true);
        var cpuBefore = Process.GetCurrentProcess().TotalProcessorTime;
        var psi = new ProcessStartInfo("dotnet", $"\"{tools}\" load --port {server.LocalEndPoints["sink"].Port} --connections {connections} --messages {messages} --size {size} --json \"{loadJson}\" --label sink-only") { RedirectStandardOutput = true, RedirectStandardError = true };
        psi.Environment.Remove("DOTNET_EnableEventPipe");
        using (var load = Process.Start(psi)!)
        {
            await load.StandardOutput.ReadToEndAsync();
            await load.WaitForExitAsync();
        }

        long bytes = GC.GetTotalAllocatedBytes(precise: true) - before;
        var cpu = Process.GetCurrentProcess().TotalProcessorTime - cpuBefore;
        using var doc = JsonDocument.Parse(File.ReadAllText(loadJson));
        long accepted = doc.RootElement.GetProperty("Accepted").GetInt64();
        Console.WriteLine($"SMTP server protocol path (plain, no storage): {accepted} messages of {size} bytes, {doc.RootElement.GetProperty("MessagesPerSecond").GetDouble():F0} msg/s, {bytes / Math.Max(1, accepted)} B/message, {cpu.TotalMilliseconds / Math.Max(1, accepted) * 1000:F1} cpu-ms/1000 messages");
        allocProfile?.Print(20);
        File.Delete(loadJson);
        return 0;
    }
}
