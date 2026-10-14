using System.Diagnostics;
using Mta.Core;
using Mta.Smtp.Protocol;
using Mta.Storage;

namespace Mta.Delivery.Tests;

/// <summary>Counts how often the queue is read and can be told to fail, around a real store.</summary>
internal sealed class CountingQueueStore(IDeliveryStore inner) : IDeliveryStore
{
    public int StatsReads;
    public bool FailStats;

    /// <summary>Fail like a store whose own command timeout expired: an OperationCanceledException that is not the caller's cancellation.</summary>
    public bool TimeOut;

    public ValueTask<QueueStats> GetQueueStatsAsync(CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref StatsReads);
        if (TimeOut)
        {
            throw new OperationCanceledException("the store's command timeout expired");
        }

        return FailStats ? throw new StorageUnavailableException("queue store is down") : inner.GetQueueStatsAsync(cancellationToken);
    }

    public ValueTask<IReadOnlyList<ClaimedDelivery>> ClaimAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken) => inner.ClaimAsync(owner, max, now, lease, cancellationToken);

    public ValueTask<byte[]?> GetRawAsync(Guid messageId, CancellationToken cancellationToken) => inner.GetRawAsync(messageId, cancellationToken);

    public ValueTask RecordAttemptAsync(DeliveryAttempt attempt, CancellationToken cancellationToken) => inner.RecordAttemptAsync(attempt, cancellationToken);

    public ValueTask<bool> ExtendLeaseAsync(Guid deliveryId, string owner, DateTimeOffset until, CancellationToken cancellationToken) => inner.ExtendLeaseAsync(deliveryId, owner, until, cancellationToken);

    public ValueTask<int> ReleaseExpiredLeasesAsync(DateTimeOffset now, CancellationToken cancellationToken) => inner.ReleaseExpiredLeasesAsync(now, cancellationToken);

    public ValueTask<int> ReleaseOwnedLeasesAsync(string owner, CancellationToken cancellationToken) => inner.ReleaseOwnedLeasesAsync(owner, cancellationToken);

    public ValueTask<IReadOnlyList<ClaimedDelivery>> ClaimExpiredAsync(string owner, int max, DateTimeOffset now, CancellationToken cancellationToken) => inner.ClaimExpiredAsync(owner, max, now, cancellationToken);

    public ValueTask<CancelResult> CancelAsync(Guid tenantId, Guid messageId, IReadOnlyList<string>? recipients, DateTimeOffset now, Func<CancelledDeliveryInfo, WebhookEventDraft?>? webhookEvent, CancellationToken cancellationToken) => inner.CancelAsync(tenantId, messageId, recipients, now, webhookEvent, cancellationToken);
}

internal sealed class ShiftedClock(TimeSpan shift) : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow + shift;

    public long Timestamp => Stopwatch.GetTimestamp();
}

/// <summary>The queue gauges read a sample taken in the background; they are process-wide, so these tests run one after the other.</summary>
[Collection("queue-gauges")]
public class QueueGaugeTests
{
    private static MeterCapture Capture() => new(m => m.Name == "Mta.Delivery");

    [Fact]
    public async Task Gauges_report_the_last_sample_by_state_and_a_pull_never_reads_the_queue()
    {
        await using var f = new DeliveryFixture(startEngine: false);
        await f.EnqueueAsync(["a@dest.example", "b@dest.example"]);
        await f.EnqueueAsync(["c@dest.example"]);
        var store = new CountingQueueStore(f.Storage.Deliveries);
        var gauges = new QueueGauges(store, new ShiftedClock(TimeSpan.FromMinutes(10)), NullMtaLog.Instance, TimeSpan.FromSeconds(15));
        using IDisposable attached = DeliveryMetrics.AttachQueueGauges(gauges);
        using var capture = Capture();

        capture.Pull();
        Assert.Empty(capture.Of("mta.delivery.queue.depth"));   // no sample yet: no numbers, not zeros

        await gauges.SampleOnceAsync(default);
        for (int i = 0; i < 5; i++)
        {
            capture.Pull();
        }

        Assert.Equal(1, store.StatsReads);
        Assert.Equal(3, capture.Last("mta.delivery.queue.depth", ("state", "queued")));
        Assert.Equal(0, capture.Last("mta.delivery.queue.depth", ("state", "deferred")));
        Assert.Equal(0, capture.Last("mta.delivery.queue.depth", ("state", "leased")));
        Assert.True(capture.Last("mta.delivery.queue.spool.size") > 0);

        // The oldest delivery became due when it was accepted; the gauge's clock runs ten minutes ahead.
        double age = capture.Last("mta.delivery.queue.oldest_due_age")!.Value;
        Assert.InRange(age, 590, 700);
        Assert.InRange(capture.Last("mta.delivery.queue.sample_age")!.Value, 0, 60);
    }

    [Fact]
    public async Task An_empty_queue_reports_zeros()
    {
        await using var f = new DeliveryFixture(startEngine: false);
        var gauges = new QueueGauges(f.Storage.Deliveries, SystemClock.Instance, NullMtaLog.Instance, TimeSpan.FromSeconds(15));
        using IDisposable attached = DeliveryMetrics.AttachQueueGauges(gauges);
        using var capture = Capture();

        await gauges.SampleOnceAsync(default);
        capture.Pull();

        Assert.Equal(0, capture.Last("mta.delivery.queue.depth", ("state", "queued")));
        Assert.Equal(0, capture.Last("mta.delivery.queue.oldest_due_age"));
        Assert.Equal(0, capture.Last("mta.delivery.queue.spool.size"));
    }

    [Fact]
    public async Task A_failed_sample_keeps_the_previous_numbers_and_is_counted()
    {
        await using var f = new DeliveryFixture(startEngine: false);
        await f.EnqueueAsync(["a@dest.example"]);
        var store = new CountingQueueStore(f.Storage.Deliveries);
        var gauges = new QueueGauges(store, SystemClock.Instance, NullMtaLog.Instance, TimeSpan.FromSeconds(15));
        using IDisposable attached = DeliveryMetrics.AttachQueueGauges(gauges);
        using var capture = Capture();

        await gauges.SampleOnceAsync(default);
        store.FailStats = true;
        await gauges.SampleOnceAsync(default);   // does not throw
        capture.Pull();

        Assert.Equal(1, capture.Last("mta.delivery.queue.depth", ("state", "queued")));
        Assert.True(capture.Sum("mta.delivery.queue.sample.failures") >= 1);
        Assert.NotNull(gauges.Latest);
    }

    [Fact]
    public async Task A_store_timeout_is_a_failed_sample_not_a_cancellation()
    {
        await using var f = new DeliveryFixture(startEngine: false);
        var store = new CountingQueueStore(f.Storage.Deliveries) { TimeOut = true };
        var gauges = new QueueGauges(store, SystemClock.Instance, NullMtaLog.Instance, TimeSpan.FromSeconds(15));
        using var capture = Capture();

        await gauges.SampleOnceAsync(default);   // an OperationCanceledException of the store's own makes no difference to the caller

        Assert.Null(gauges.Latest);
        Assert.True(capture.Sum("mta.delivery.queue.sample.failures") >= 1);
    }

    [Fact]
    public async Task Our_own_cancellation_still_propagates_from_a_sample()
    {
        await using var f = new DeliveryFixture(startEngine: false);
        var store = new CountingQueueStore(f.Storage.Deliveries) { TimeOut = true };
        var gauges = new QueueGauges(store, SystemClock.Instance, NullMtaLog.Instance, TimeSpan.FromSeconds(15));
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => gauges.SampleOnceAsync(cancelled.Token));
    }

    [Fact]
    public async Task A_store_timeout_does_not_end_the_sampling_loop()
    {
        await using var f = new DeliveryFixture(startEngine: false);
        await f.EnqueueAsync(["a@dest.example"]);
        var store = new CountingQueueStore(f.Storage.Deliveries) { TimeOut = true };
        var gauges = new QueueGauges(store, SystemClock.Instance, NullMtaLog.Instance, TimeSpan.FromMilliseconds(20));
        using var stop = new CancellationTokenSource();
        Task run = gauges.RunAsync(stop.Token);

        await DeliveryFixture.WaitAsync(() => store.StatsReads >= 3);   // it keeps trying while every sample times out
        Assert.False(run.IsCompleted);

        store.TimeOut = false;   // the store recovers: the next sample lands
        await DeliveryFixture.WaitAsync(() => gauges.Latest is not null);
        Assert.Equal(1, gauges.Latest!.Stats.Queued);

        await stop.CancelAsync();
        await run;
    }

    [Fact]
    public async Task Detaching_stops_the_gauges()
    {
        await using var f = new DeliveryFixture(startEngine: false);
        var gauges = new QueueGauges(f.Storage.Deliveries, SystemClock.Instance, NullMtaLog.Instance, TimeSpan.FromSeconds(15));
        IDisposable attached = DeliveryMetrics.AttachQueueGauges(gauges);
        await gauges.SampleOnceAsync(default);
        attached.Dispose();
        using var capture = Capture();

        capture.Pull();

        Assert.Empty(capture.Of("mta.delivery.queue.depth"));
    }

    [Fact]
    public async Task Run_samples_immediately_and_attaches_while_running()
    {
        await using var f = new DeliveryFixture(startEngine: false);
        await f.EnqueueAsync(["a@dest.example"]);
        var gauges = new QueueGauges(f.Storage.Deliveries, SystemClock.Instance, NullMtaLog.Instance, TimeSpan.FromMilliseconds(50));
        using var stop = new CancellationTokenSource();
        Task run = gauges.RunAsync(stop.Token);

        await DeliveryFixture.WaitAsync(() => gauges.Latest is not null);
        using (var capture = Capture())
        {
            capture.Pull();
            Assert.Equal(1, capture.Last("mta.delivery.queue.depth", ("state", "queued")));
        }

        await stop.CancelAsync();
        await run;   // cancellation ends the loop quietly
        using var after = Capture();
        after.Pull();
        Assert.Empty(after.Of("mta.delivery.queue.depth"));
    }
}

/// <summary>Runs deliveries and watches the process-wide meters, so every class that runs a delivery engine shares the "delivery-pipeline" collection and counts are exact.</summary>
[Collection("delivery-pipeline")]
public class DeliveryObservabilityTests
{
    private static ActivityListener Listen(Guid messageId, List<Activity> stopped)
    {
        var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == MessageTrace.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = a =>
            {
                if (a.TraceId.ToHexString() == Ids.ToCompact(messageId))
                {
                    lock (stopped) { stopped.Add(a); }
                }
            },
        };
        ActivitySource.AddActivityListener(listener);
        return listener;
    }

    [Fact]
    public async Task A_delivery_emits_a_queue_wait_span_and_an_attempt_span_in_the_trace_of_the_message()
    {
        await using var f = new DeliveryFixture(startEngine: false);
        var stopped = new List<Activity>();
        var message = Ids.New();
        using ActivityListener listener = Listen(message, stopped);   // other tests deliver in parallel: only this message's spans are kept
        await EnqueueWithIdAsync(f, message, ["rcpt@dest.example"]);
        f.StartEngine();

        await f.WaitForEventAsync(message, MessageEventType.Delivered);
        await DeliveryFixture.WaitAsync(() => { lock (stopped) { return stopped.Any(a => a.OperationName == MessageTrace.DeliveryAttemptSpan); } });

        Activity wait, attempt;
        lock (stopped)
        {
            wait = Assert.Single(stopped, a => a.OperationName == MessageTrace.QueueWaitSpan);
            attempt = Assert.Single(stopped, a => a.OperationName == MessageTrace.DeliveryAttemptSpan);
        }

        Assert.Equal(MessageTrace.RootContextOf(message).SpanId, attempt.ParentSpanId);
        Assert.Equal(wait.ParentSpanId, attempt.ParentSpanId);
        Assert.Equal(1, attempt.GetTagItem("mta.delivery.attempt"));
        Assert.Equal("dest.example", attempt.GetTagItem("mta.recipient.domain"));
        ActivityEvent result = Assert.Single(attempt.Events);
        Assert.Equal("recipient.result", result.Name);
        Assert.Contains(result.Tags, t => t.Key == "mta.delivery.outcome" && (string?)t.Value == "delivered");
        Assert.Contains(result.Tags, t => t.Key == "mta.smtp.code" && (int?)t.Value == 250);
        Assert.NotEqual(ActivityStatusCode.Error, attempt.Status);
    }

    [Fact]
    public async Task A_permanent_failure_marks_the_attempt_span_as_an_error()
    {
        await using var f = new DeliveryFixture(startEngine: false);
        f.Dns.AddMx("example.org", 10, "mx.example.org").AddA("mx.example.org", "127.0.0.1");
        f.Remote.OnRecipient = _ => SmtpReplyFor550();
        var stopped = new List<Activity>();
        var message = Ids.New();
        using ActivityListener listener = Listen(message, stopped);
        await EnqueueWithIdAsync(f, message, ["gone@dest.example"]);
        f.StartEngine();

        await f.WaitForEventAsync(message, MessageEventType.Bounced);
        await DeliveryFixture.WaitAsync(() => { lock (stopped) { return stopped.Any(a => a.OperationName == MessageTrace.DeliveryAttemptSpan); } });

        Activity attempt;
        lock (stopped)
        {
            attempt = Assert.Single(stopped, a => a.OperationName == MessageTrace.DeliveryAttemptSpan);
        }

        Assert.Equal(ActivityStatusCode.Error, attempt.Status);
        // The status carries codes only: the server's reply text echoes recipient addresses and must not leave the box with the span.
        Assert.Equal("5.1.1", attempt.StatusDescription);
        Assert.DoesNotContain("No such user", attempt.StatusDescription);
        Assert.DoesNotContain(attempt.Events.SelectMany(e => e.Tags), t => t.Value is string text && text.Contains("No such user", StringComparison.Ordinal));
        Assert.Contains(attempt.Events.Single().Tags, t => t.Key == "mta.delivery.outcome" && (string?)t.Value == "failed");
    }

    [Fact]
    public async Task Claim_and_record_durations_and_outcomes_are_measured()
    {
        await using var f = new DeliveryFixture();
        using var capture = new MeterCapture(m => m.Name == "Mta.Delivery");
        var id = await f.EnqueueAsync(["rcpt@dest.example"]);
        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        // Every class that runs an engine is in the same collection, so nothing else records into these meters meanwhile.
        Assert.Single(capture.Of("mta.delivery.claim.duration", ("result", "claimed")));
        Assert.Equal(1, capture.Sum("mta.delivery.claimed"));
        Assert.Single(capture.Of("mta.delivery.record.duration"));
        Assert.Equal(1, capture.Sum("mta.delivery.attempts", ("outcome", "delivered")));
        Assert.Single(capture.Of("mta.delivery.group.duration"));
        Assert.All(capture.Of("mta.delivery.record.duration"), m => Assert.InRange(m.Value, 0, 30));
    }

    private static SmtpReply SmtpReplyFor550() => SmtpReply.Create(550, "5.1.1", "No such user");

    /// <summary>Like <see cref="DeliveryFixture.EnqueueAsync"/> but with the message id chosen by the test, so spans can be matched to it.</summary>
    private static async Task EnqueueWithIdAsync(DeliveryFixture f, Guid id, string[] to)
    {
        var now = DateTimeOffset.UtcNow;
        string raw = $"From: sender@example.org\r\nTo: {string.Join(", ", to)}\r\nSubject: Hello\r\nMessage-ID: <{Guid.NewGuid():N}@example.org>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n\r\nBody line\r\n";
        await f.Storage.Intake.AcceptAsync(new AcceptedMessage
        {
            MessageId = id,
            TenantId = DeliveryFixture.Tenant,
            Source = MessageSource.Smtp,
            EnvelopeFrom = EmailAddress.Parse("sender@example.org"),
            Recipients = to.Select(t => new AcceptedRecipient(Ids.New(now), EmailAddress.Parse(t))).ToList(),
            Raw = System.Text.Encoding.ASCII.GetBytes(raw),
            ReceivedAt = now,
            ExpiresAt = now + TimeSpan.FromDays(5),
            SendingDomain = "example.org",
        }, CancellationToken.None);
    }
}
