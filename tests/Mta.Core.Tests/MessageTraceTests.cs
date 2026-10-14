using System.Diagnostics;
using Mta.Core;

namespace Mta.Core.Tests;

[Collection("activity-source")]
public class MessageTraceTests
{
    private static ActivityListener Listen(List<Activity> stopped, ActivitySamplingResult result = ActivitySamplingResult.AllDataAndRecorded)
    {
        var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == MessageTrace.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => result,
            ActivityStopped = a => { lock (stopped) { stopped.Add(a); } },
        };
        ActivitySource.AddActivityListener(listener);
        return listener;
    }

    [Fact]
    public void Nothing_is_created_when_no_one_listens()
    {
        Assert.False(MessageTrace.IsEnabled);
        Assert.Null(MessageTrace.Start(MessageTrace.SubmitSpan, Guid.NewGuid()));
        Assert.Null(MessageTrace.StartUnattached(MessageTrace.WebhookDeliverSpan));
    }

    [Fact]
    public void The_trace_id_is_the_message_id_and_every_span_of_a_message_shares_one_parent()
    {
        var stopped = new List<Activity>();
        using ActivityListener listener = Listen(stopped);
        Guid message = Ids.New();

        using (Activity? submit = MessageTrace.Start(MessageTrace.SubmitSpan, message))
        using (Activity? attempt = MessageTrace.Start(MessageTrace.DeliveryAttemptSpan, message, ActivityKind.Client))
        {
            Assert.NotNull(submit);
            Assert.NotNull(attempt);
            Assert.Equal(Ids.ToCompact(message), submit.TraceId.ToHexString());
            Assert.Equal(submit.TraceId, attempt.TraceId);
            Assert.Equal(submit.ParentSpanId, attempt.ParentSpanId);
            Assert.NotEqual(default, submit.ParentSpanId);
            Assert.NotEqual(submit.SpanId, attempt.SpanId);
            Assert.Equal(Ids.ToCompact(message), submit.GetTagItem(MessageTrace.MessageIdTag));
        }

        // The context is a pure function of the id, which is what lets a retry days later (or another replica) join the same trace.
        Assert.Equal(MessageTrace.RootContextOf(message), MessageTrace.RootContextOf(message));
        Assert.NotEqual(MessageTrace.RootContextOf(message).TraceId, MessageTrace.RootContextOf(Ids.New()).TraceId);
        Assert.NotEqual(default, MessageTrace.RootContextOf(Guid.Empty).SpanId);
    }

    [Fact]
    public void The_queue_wait_span_can_start_in_the_past()
    {
        var stopped = new List<Activity>();
        using ActivityListener listener = Listen(stopped);
        DateTimeOffset accepted = DateTimeOffset.UtcNow.AddMinutes(-3);

        using (MessageTrace.Start(MessageTrace.QueueWaitSpan, Ids.New(), ActivityKind.Internal, accepted))
        {
        }

        Activity wait = Assert.Single(stopped, a => a.OperationName == MessageTrace.QueueWaitSpan);
        Assert.True(wait.Duration >= TimeSpan.FromMinutes(2.9));
        Assert.Equal(accepted.UtcDateTime, wait.StartTimeUtc, TimeSpan.FromMilliseconds(5));
    }

    [Fact]
    public void An_empty_message_id_starts_no_span_and_a_dropping_sampler_yields_none()
    {
        var stopped = new List<Activity>();
        using (Listen(stopped))
        {
            Assert.Null(MessageTrace.Start(MessageTrace.SubmitSpan, Guid.Empty));
        }

        using (Listen(stopped, ActivitySamplingResult.None))
        {
            Assert.Null(MessageTrace.Start(MessageTrace.SubmitSpan, Ids.New()));
        }

        Assert.Empty(stopped);
    }

    [Fact]
    public void The_sample_decision_comes_from_the_message_id_and_follows_the_ratio()
    {
        double before = MessageTrace.SampleRatio;
        try
        {
            var ids = Enumerable.Range(0, 20_000).Select(_ => Ids.New()).ToList();

            MessageTrace.SampleRatio = 1;
            Assert.All(ids.Take(100), id => Assert.True(MessageTrace.IsSampled(id)));
            MessageTrace.SampleRatio = 0;
            Assert.All(ids.Take(100), id => Assert.False(MessageTrace.IsSampled(id)));

            MessageTrace.SampleRatio = 0.1;
            int sampled = ids.Count(MessageTrace.IsSampled);
            Assert.InRange(sampled, 1700, 2300);   // 10 % of 20 000, well inside the binomial spread
            Assert.Equal(sampled, ids.Count(MessageTrace.IsSampled));   // the same ids every time: a message is in all of its spans or in none

            MessageTrace.SampleRatio = 7;   // out of range is clamped, not an error
            Assert.Equal(1, MessageTrace.SampleRatio);
        }
        finally
        {
            MessageTrace.SampleRatio = before;
        }
    }

    [Fact]
    public void An_unsampled_message_creates_no_activity_even_with_a_listener()
    {
        var stopped = new List<Activity>();
        double before = MessageTrace.SampleRatio;
        MessageTrace.SampleRatio = 0;
        try
        {
            using ActivityListener listener = Listen(stopped);
            Assert.Null(MessageTrace.Start(MessageTrace.SubmitSpan, Ids.New()));
        }
        finally
        {
            MessageTrace.SampleRatio = before;
        }

        Assert.Empty(stopped);
    }

    [Fact]
    public void A_span_without_a_message_follows_the_ratio_too()
    {
        var stopped = new List<Activity>();
        double before = MessageTrace.SampleRatio;
        try
        {
            using ActivityListener listener = Listen(stopped);

            MessageTrace.SampleRatio = 0;
            for (int i = 0; i < 200; i++) { Assert.Null(MessageTrace.StartUnattached(MessageTrace.WebhookDeliverSpan)); }

            MessageTrace.SampleRatio = 1;
            using (Activity? all = MessageTrace.StartUnattached(MessageTrace.WebhookDeliverSpan)) { Assert.NotNull(all); }

            MessageTrace.SampleRatio = 0.5;
            int started = 0;
            for (int i = 0; i < 4000; i++)
            {
                using Activity? maybe = MessageTrace.StartUnattached(MessageTrace.WebhookDeliverSpan);
                if (maybe is not null) { started++; }
            }

            Assert.InRange(started, 1700, 2300);
        }
        finally
        {
            MessageTrace.SampleRatio = before;
        }
    }
}
