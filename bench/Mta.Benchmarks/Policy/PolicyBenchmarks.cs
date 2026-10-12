using BenchmarkDotNet.Attributes;
using Mta.Core;
using Mta.Policy;

namespace Mta.Benchmarks.Policy;

/// <summary>Reply classification throughput. Run: <c>dotnet run -c Release --project bench/Mta.Benchmarks -- --filter "*ReplyClassifier*"</c>.</summary>
[MemoryDiagnoser]
public class ReplyClassifierBenchmarks
{
    private readonly ReplyClassifier _classifier = ReplyClassifier.Default;

    private readonly RemoteReply _delivered = new(250, "2.0.0", "Ok: queued as ABC123");
    private readonly RemoteReply _enhancedHit = new(550, "5.1.1", "The email account that you tried to reach does not exist. Please try double-checking the recipient's email address.");
    private readonly RemoteReply _textHeuristic = new(550, null, "Message rejected because it looks like spam (score 12.3)");
    private readonly RemoteReply _throttle = new(421, "4.7.0", "[TSS04] Messages from 203.0.113.5 temporarily deferred due to unexpected volume or user complaints");
    private readonly RemoteReply _fallthrough = new(554, null, "Transaction failed");

    [Benchmark(Baseline = true)]
    public DeliveryClass Delivered() => _classifier.Classify(_delivered, SmtpStage.EndOfData).Class;

    [Benchmark]
    public DeliveryClass EnhancedCodeRule() => _classifier.Classify(_enhancedHit, SmtpStage.RcptTo).Class;

    [Benchmark]
    public DeliveryClass TextHeuristic() => _classifier.Classify(_textHeuristic, SmtpStage.EndOfData).Class;

    [Benchmark]
    public DeliveryClass ThrottleText() => _classifier.Classify(_throttle, SmtpStage.RcptTo).Class;

    [Benchmark]
    public DeliveryClass FullTableScan() => _classifier.Classify(_fallthrough, SmtpStage.EndOfData).Class;
}

/// <summary>Per-destination throttle hot path (acquire plus release of a connection slot).</summary>
[MemoryDiagnoser]
public class DestinationThrottleBenchmarks
{
    private DestinationThrottle _throttle = null!;
    private ThrottleKey[] _keys = null!;
    private int _next;

    [GlobalSetup]
    public void Setup()
    {
        _throttle = new DestinationThrottle(SystemClock.Instance, new DestinationThrottleOptions
        {
            Defaults = new ThrottleLimits(1024, 100_000_000, 1000),
            InitialConcurrentConnections = 1024,
            InitialMessagesPerMinute = 100_000_000,
            BurstSeconds = 3600,
        });
        _keys = [.. Enumerable.Range(0, 1000).Select(i => new ThrottleKey($"domain{i}.example"))];
        foreach (ThrottleKey k in _keys)
        {
            _throttle.TryAcquire(k).Lease!.Dispose();
        }
    }

    [Benchmark(Baseline = true)]
    public bool AcquireRelease_SingleKey()
    {
        ThrottleResult r = _throttle.TryAcquire(_keys[0]);
        r.Lease?.Dispose();
        return r.Acquired;
    }

    [Benchmark]
    public bool AcquireRelease_ThousandKeys()
    {
        ThrottleResult r = _throttle.TryAcquire(_keys[_next++ % _keys.Length]);
        r.Lease?.Dispose();
        return r.Acquired;
    }

    [Benchmark]
    public void Report_Success() => _throttle.Report(_keys[0], ThrottleSignal.Success);
}

/// <summary>Retry schedule and sending-limit checks, which the scheduler consults for every delivery.</summary>
[MemoryDiagnoser]
public class SchedulerPolicyBenchmarks
{
    private readonly RetrySchedule _retry = new(random: new SeededRandomSource(1));
    private readonly DateTimeOffset _now = new(2026, 10, 12, 8, 30, 0, TimeSpan.Zero);
    private readonly RemoteReply _reply = new(451, "4.3.0", "Temporary local problem");
    private readonly Guid _tenant = Guid.NewGuid();
    private SendingLimits _limits = null!;

    [GlobalSetup]
    public void Setup() => _limits = new SendingLimits(SystemClock.Instance);

    [Benchmark]
    public RetryDecision NextAttemptAt() => _retry.NextAttemptAt(3, _now, _now.AddDays(5), _reply);

    [Benchmark]
    public SendingDecision ReserveSendingCapacity() => _limits.TryReserve(_tenant, "example.com");
}
