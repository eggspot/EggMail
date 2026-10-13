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
}
