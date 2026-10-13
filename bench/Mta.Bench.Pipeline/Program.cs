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
//            --deliver true|false (default true: also drain the queue to the sink)   --label TEXT   --json out.json
var opt = Args.Parse(args);
if (opt.Get("micro", "false") == "true")
{
    await Micro.RunAsync();
    return 0;
}

using var allocProfile = opt.Get("alloc-profile", "false") == "true" ? new AllocationSampler() : null;

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
        Listeners = new Dictionary<string, ListenerSection> { ["submission"] = new() { Port = 0, BindAddress = "127.0.0.1", Mode = ListenerMode.StartTls, AuthRequired = true } },
    },
    Delivery = new DeliverySection
    {
        RemotePort = sinkServer.LocalEndPoints["sink"].Port, AllowPrivateMxAddresses = true, Workers = 64, BounceDomain = "bounces.bench.local",
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
if (deliver)
{
    engine = Task.Run(() => runtime.Delivery.RunAsync(stop.Token));
}

string tools = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "Mta.Tools", "bin", "Release", "net10.0", "mta-tools.dll"));
if (!File.Exists(tools))
{
    Console.Error.WriteLine("Build the load generator first: dotnet build -c Release src/Mta.Tools   (expected " + tools + ")");
    return 2;
}

string loadJson = Path.Combine(dir, "load.json");
long allocBefore = GC.GetTotalAllocatedBytes(precise: true);
var cpuBefore = Process.GetCurrentProcess().TotalProcessorTime;
var wall = Stopwatch.StartNew();
var psi = new ProcessStartInfo("dotnet", $"\"{tools}\" load --port {port} --starttls --auth bench:bench-pass --connections {connections} --messages {messages} --size {size} --rcpt {rcpt} --json \"{loadJson}\" --label \"{label}\"")
{
    RedirectStandardOutput = true,
    RedirectStandardError = true,
};
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
if (deliver)
{
    var deadline = DateTime.UtcNow.AddMinutes(10);
    while (Interlocked.Read(ref sink.Recipients) < expected && DateTime.UtcNow < deadline)
    {
        await Task.Delay(50);
    }

    endToEndSeconds = wall.Elapsed.TotalSeconds;
}

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
    EndToEnd = deliver ? new { DeliveredRecipients = Interlocked.Read(ref sink.Recipients), Seconds = Math.Round(endToEndSeconds, 2), RecipientsPerSecond = Math.Round(Interlocked.Read(ref sink.Recipients) / endToEndSeconds, 1) } : null,
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

    public void Print()
    {
        long total = _bytes.Values.Sum();
        Console.WriteLine($"allocation sample (about 100 KB granularity), total {total / 1_000_000.0:F1} MB:");
        foreach (var (type, bytes) in _bytes.OrderByDescending(kv => kv.Value).Take(25))
        {
            Console.WriteLine($"  {bytes * 100.0 / total,5:F1}%  {type}");
        }
    }
}

/// <summary>Allocation per call of the ingest steps in isolation (bytes per operation on the calling thread).</summary>
internal static class Micro
{
    public static async Task RunAsync()
    {
        string head = "From: Tester <news@bench.test>\r\nTo: rcpt0@dest.test\r\nSubject: load test\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\nMessage-ID: <abcdef@bench.test>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n";
        byte[] raw = System.Text.Encoding.ASCII.GetBytes(head + new string('x', 1800) + "\r\n");
        byte[] received = System.Text.Encoding.ASCII.GetBytes("Received: from client.test (127.0.0.1) by egg.local with ESMTPSA id abc; Mon, 12 Oct 2026 08:00:00 +0000\r\n");

        Measure("MimeMessage.Parse", () => { Mta.Mime.MimeMessage.Parse(raw); });
        Measure("MessageHeaderEditor (remove Bcc, 2 prepends, Received, ToArray)", () =>
        {
            var e = new Mta.Mime.MessageHeaderEditor(raw);
            e.Remove("Bcc");
            e.Prepend("Message-ID", "<x@y>");
            e.Prepend("Date", "Mon, 12 Oct 2026 08:00:00 +0000");
            e.PrependRaw(received);
            e.ToArray();
        });
        Measure("MessageContentExtractor.Extract", () => { Mta.Mime.MessageContentExtractor.Extract(raw, 262144); });
        Measure("AddressList.Parse(From)", () => { Mta.Mime.AddressList.Parse("Tester <news@bench.test>").Mailboxes.ToList(); });
        Measure("Ids.New + EmailAddress.Parse x2", () => { Mta.Core.Ids.New(); Mta.Core.EmailAddress.Parse("rcpt0@dest.test"); Mta.Core.EmailAddress.Parse("load0@bench.test"); });

        var storage = new Mta.Storage.InMemory.InMemoryStorage(new Mta.Storage.StorageOptions());
        await storage.InitializeAsync(default);
        var tenant = new Mta.Storage.Tenant(Guid.NewGuid(), "T", "t", true, DateTimeOffset.UtcNow, false);
        await storage.Config.UpsertDomainAsync(new Mta.Storage.DomainRecord(Guid.NewGuid(), tenant.Id, "bench.test", Mta.Storage.DomainStatus.Verified, null, false, DateTimeOffset.UtcNow, null, null, 0, null, false, null), default);
        var submission = new Mta.Host.Submission.SubmissionService(storage, Mta.Core.SystemClock.Instance, new Mta.Policy.SenderPolicy(), new Mta.Storage.StorageOptions());
        var request = new Mta.Host.Submission.SubmissionRequest { Tenant = tenant, Source = Mta.Storage.MessageSource.Smtp, EnvelopeFrom = Mta.Core.EmailAddress.Parse("load0@bench.test"), Recipients = [Mta.Core.EmailAddress.Parse("rcpt0@dest.test")], Message = raw, ReceivedHeader = received };
        await submission.SubmitAsync(request, default);
        long before = GC.GetAllocatedBytesForCurrentThread();
        const int n = 5000;
        for (int i = 0; i < n; i++) { await submission.SubmitAsync(request, default); }
        Console.WriteLine($"{"SubmissionService.SubmitAsync (InMemory storage, history Full)",-70} {(GC.GetAllocatedBytesForCurrentThread() - before) / n,8} B/op");
    }

    private static void Measure(string name, Action action)
    {
        for (int i = 0; i < 100; i++) { action(); }
        long before = GC.GetAllocatedBytesForCurrentThread();
        const int n = 10000;
        for (int i = 0; i < n; i++) { action(); }
        Console.WriteLine($"{name,-70} {(GC.GetAllocatedBytesForCurrentThread() - before) / n,8} B/op");
    }
}
