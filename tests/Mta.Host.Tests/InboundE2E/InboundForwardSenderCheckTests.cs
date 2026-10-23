using System.Diagnostics.Metrics;
using Mta.Host.Inbound;
using Mta.Storage;

namespace Mta.Host.Tests.InboundE2E;

public abstract class InboundForwardSenderCheckTests(LabBackend backend)
{
    private static async Task<InboundMessage> ActedOnAsync(InboundLab lab, Guid id)
    {
        DateTime deadline = DateTime.UtcNow.AddSeconds(30);
        while (true)
        {
            InboundMessage m = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, id, default))!;
            if (m.ActionState != InboundActionState.Pending)
            {
                return m;
            }

            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException($"the action of message {id:N} never ran; {m.ActionAttempts} attempts, error {m.ActionLastError}");
            }

            await lab.Runtime.InboundActions.RunOnceAsync(default);
        }
    }

    [Fact]
    public async Task A_from_the_receive_path_judged_unusable_is_not_forwarded_and_is_counted_and_an_ordinary_foreign_from_is_still_forwarded()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        long refused = 0;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter == InboundActionMetrics.Meter && instrument.Name == "mta.inbound.forward.refused")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
        {
            foreach (KeyValuePair<string, object?> tag in tags)
            {
                if (tag is { Key: "reason", Value: "unusable_from" })
                {
                    Interlocked.Add(ref refused, value);
                }
            }
        });
        listener.Start();

        lab.PublishSpf("evil.test");
        lab.PublishDmarc("evil.test", "none");
        lab.PublishSpf("sender.test");
        lab.PublishDmarc("sender.test", "none");
        Assert.Equal(250, (await lab.SendAsync("x@evil.test", "billing-1@example.org", InboundLab.Message(from: "ceo@example.org <x@evil.test>", to: "billing-1@example.org"))).Code);
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "billing-2@example.org", InboundLab.Message(to: "billing-2@example.org"))).Code);
        IReadOnlyList<InboundMessage> stored = await lab.MessagesAsync(InboundLab.Acme);
        InboundMessage ambiguous = Assert.Single(stored, m => m.EnvelopeTo == "billing-1@example.org");
        InboundMessage ordinary = Assert.Single(stored, m => m.EnvelopeTo == "billing-2@example.org");
        Assert.Equal(InboundVerdict.PermError, ambiguous.Auth.Dmarc);

        InboundMessage refusedMessage = await ActedOnAsync(lab, ambiguous.Id);
        InboundMessage forwarded = await ActedOnAsync(lab, ordinary.Id);

        Assert.Equal((InboundActionState.Failed, "unusable_from", (Guid?)null), (refusedMessage.ActionState, refusedMessage.ActionLastError, refusedMessage.ForwardMessageId));
        Assert.Equal(InboundActionState.Done, forwarded.ActionState);
        Assert.NotNull(forwarded.ForwardMessageId);
        var queued = await lab.Storage.Deliveries.ClaimAsync("oracle", 100, lab.Clock.UtcNow.AddMinutes(1), TimeSpan.FromMinutes(1), default);
        ClaimedDelivery copy = Assert.Single(queued);
        Assert.Equal((forwarded.ForwardMessageId, "archive@elsewhere.test", MessageSource.Forward), (copy.MessageId, copy.Recipient.ToString(), copy.Source));
        Assert.True(Interlocked.Read(ref refused) >= 1, "the refusal is counted under its reason");
    }
}

public sealed class SqliteInboundForwardSenderCheckTests() : InboundForwardSenderCheckTests(LabBackend.Sqlite);

public sealed class PostgresInboundForwardSenderCheckTests() : InboundForwardSenderCheckTests(LabBackend.Postgres);
