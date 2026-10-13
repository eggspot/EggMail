using System.Diagnostics;

namespace Mta.Core;

/// <summary>
/// Distributed tracing of a message's life: submission, wait in the queue, every delivery attempt and every webhook about it
/// (<see cref="ActivitySource"/> <c>Mta.Message</c>; BCL only, so any assembly may emit spans).
/// <para><b>One trace per message, without storing anything.</b> The trace id of every span about a message is the message id itself (the same 32
/// hex digits as the id in the SMTP <c>250 Queued as</c> reply, the API and the dashboard), and all spans share one deterministic parent span id
/// (<see cref="RootContextOf"/>). A span emitted days later by a retry, or by another replica, therefore lands in the same trace as the submission
/// even though the queue and the webhook outbox carry no trace context. Searching a tracing backend for the message id finds everything.</para>
/// <para><b>Free when nobody listens, nearly free when the message is not sampled.</b> Every entry point first asks
/// <see cref="ActivitySource.HasListeners"/>; without an exporter (no <c>Observability:OtlpEndpoint</c>) nothing is computed and nothing is
/// allocated. With one, <see cref="SampleRatio"/> decides from the message id, a few arithmetic operations and no allocation, so the same message
/// is sampled or dropped in all of its spans and an unsampled message creates no <see cref="Activity"/> at all.</para>
/// </summary>
public static class MessageTrace
{
    public const string SourceName = "Mta.Message";

    public const string SubmitSpan = "mta.submit";
    public const string QueueWaitSpan = "mta.queue.wait";
    public const string DeliveryAttemptSpan = "mta.delivery.attempt";
    public const string WebhookDeliverSpan = "mta.webhook.deliver";

    public const string MessageIdTag = "mta.message.id";

    public static readonly ActivitySource Source = new(SourceName, "1.0.0");

    private static double s_sampleRatio = 1;

    /// <summary>
    /// Share of messages that are traced (0 to 1), decided by the message id alone. The host sets it from <c>Observability:TraceSampleRatio</c>;
    /// the exporter's own sampler then keeps everything it is given.
    /// </summary>
    public static double SampleRatio
    {
        get => Volatile.Read(ref s_sampleRatio);
        set => Volatile.Write(ref s_sampleRatio, Math.Clamp(value, 0, 1));
    }

    /// <summary>True when the trace of <paramref name="messageId"/> is part of the sampled share: the 62 random bits of the id (the low half, without the variant bits) against the ratio.</summary>
    public static bool IsSampled(Guid messageId)
    {
        double ratio = SampleRatio;
        if (ratio >= 1)
        {
            return true;
        }

        if (ratio <= 0)
        {
            return false;
        }

        Span<byte> bytes = stackalloc byte[16];
        messageId.TryWriteBytes(bytes, bigEndian: true, out _);
        ulong random = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(bytes[8..]) & 0x3FFF_FFFF_FFFF_FFFFUL;
        return random < (ulong)(ratio * 0x4000_0000_0000_0000UL);
    }

    /// <summary>True while a trace exporter (or any other listener) is attached.</summary>
    public static bool IsEnabled => Source.HasListeners();

    /// <summary>
    /// The context every span of <paramref name="messageId"/> hangs under: trace id = the message id, span id derived from it (never zero).
    /// It marks the context as remote and recorded so that parent-based samplers keep the whole trace.
    /// </summary>
    public static ActivityContext RootContextOf(Guid messageId)
    {
        Span<byte> bytes = stackalloc byte[16];
        messageId.TryWriteBytes(bytes, bigEndian: true, out _);
        Span<byte> span = stackalloc byte[8];
        for (int i = 0; i < 8; i++)
        {
            span[i] = (byte)(bytes[i] ^ bytes[i + 8] ^ 0x5A);
        }

        span[7] |= 1;
        return new ActivityContext(ActivityTraceId.CreateFromBytes(bytes), ActivitySpanId.CreateFromBytes(span), ActivityTraceFlags.Recorded, isRemote: true);
    }

    /// <summary>Starts a span in the trace of <paramref name="messageId"/>; null when nothing listens, the id is empty or the sampler dropped the trace.</summary>
    public static Activity? Start(string name, Guid messageId, ActivityKind kind = ActivityKind.Internal, DateTimeOffset startTime = default)
    {
        if (messageId == Guid.Empty || !Source.HasListeners() || !IsSampled(messageId))
        {
            return null;
        }

        Activity? activity = Source.StartActivity(name, kind, RootContextOf(messageId), tags: null, links: null, startTime);
        if (activity is null)
        {
            return null;
        }

        if (!activity.IsAllDataRequested)
        {
            // A sampler that drops the trace (OpenTelemetry's does) still gets an activity back, only to propagate the context. Nothing here
            // propagates, so end it at once: callers see null and skip their tags, and the rest of the work is the same as for a message
            // nobody listens for.
            activity.Dispose();
            return null;
        }

        activity.SetTag(MessageIdTag, Ids.ToCompact(messageId));
        return activity;
    }

    /// <summary>Starts a span that is not tied to a message (an event without one): a new root trace, or a child of the ambient activity.</summary>
    public static Activity? StartUnattached(string name, ActivityKind kind = ActivityKind.Internal)
    {
        if (!Source.HasListeners() || (SampleRatio < 1 && Random.Shared.NextDouble() >= SampleRatio))
        {
            return null;   // not about a message, so there is no id to decide by: the ratio is applied per span
        }

        Activity? activity = Source.StartActivity(name, kind);
        if (activity is { IsAllDataRequested: false })
        {
            activity.Dispose();
            return null;
        }

        return activity;
    }
}
