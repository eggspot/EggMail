using Mta.Core;
using Mta.Dsn;
using Mta.Mime;
using Mta.Storage;

namespace Mta.Delivery;

/// <summary>A delivery that ended as a permanent failure or expired, with the recorded attempt.</summary>
public sealed record BounceItem(ClaimedDelivery Delivery, DeliveryAttempt Attempt);

/// <summary>
/// Sends a delivery status notification (RFC 3464) to the sender of a message that could not be delivered, by queueing a
/// new message with the null reverse-path. Bounces are never generated for bounces, for null senders, or for sources that are
/// switched off in <see cref="DeliveryOptions"/>.
/// </summary>
public sealed class DsnService
{
    private readonly IStorage _storage;
    private readonly IClock _clock;
    private readonly DeliveryOptions _options;

    public DsnService(IStorage storage, IClock clock, DeliveryOptions options)
    {
        _storage = storage;
        _clock = clock;
        _options = options;
    }

    /// <summary>True when a bounce message would be generated for this delivery.</summary>
    public bool Applies(ClaimedDelivery d) =>
        !d.EnvelopeFrom.IsNull && d.Source switch
        {
            MessageSource.Smtp => _options.GenerateDsnForSmtpSubmissions,
            MessageSource.Api => _options.GenerateDsnForApiSubmissions,
            _ => false,
        };

    /// <summary>Queues one bounce message per original message. Call before the attempt is recorded, because recording the last recipient frees the stored message.</summary>
    public async ValueTask ReportAsync(IReadOnlyList<BounceItem> items, CancellationToken ct)
    {
        foreach (var message in items.Where(i => Applies(i.Delivery)).GroupBy(i => i.Delivery.MessageId))
        {
            var list = message.ToList();
            var first = list[0].Delivery;
            byte[]? original = await _storage.Deliveries.GetRawAsync(first.MessageId, ct).ConfigureAwait(false);
            var now = _clock.UtcNow;
            byte[] dsn = DsnBuilder.Build(new DsnRequest
            {
                ReportingMta = _options.Hostname,
                To = first.EnvelopeFrom,
                Action = DsnAction.Failed,
                ArrivalDate = first.CreatedAt,
                Now = now,
                OriginalMessage = original ?? [],
                ReturnContent = _options.DsnReturnContent,
                Recipients = list.Select(i => new DsnRecipient(
                    i.Delivery.Recipient,
                    i.Attempt.EnhancedCode ?? (i.Attempt.Outcome == DeliveryOutcome.Expired ? "4.4.7" : "5.0.0"),
                    i.Attempt.Message,
                    i.Attempt.MxHost,
                    i.Attempt.At)).ToList(),
            });

            var accepted = await _storage.Intake.AcceptAsync(new AcceptedMessage
            {
                MessageId = Ids.New(now),
                TenantId = first.TenantId,
                Source = MessageSource.Bounce,
                EnvelopeFrom = EmailAddress.Null,
                Recipients = [new AcceptedRecipient(Ids.New(now), first.EnvelopeFrom)],
                Raw = dsn,
                ReceivedAt = now,
                ExpiresAt = now + _options.DsnLifetime,
                HeadersUtf8 = MessageInspector.HasValidUtf8Headers(dsn),   // the sender's address is in the To field
                IdempotencyKey = IdempotencyKeyFor(list),
            }, ct).ConfigureAwait(false);
            if (accepted.Status == IntakeStatus.Accepted)
            {
                DeliveryMetrics.Bounces.Add(1);
            }
        }
    }

    /// <summary>
    /// The notice is queued before the result of the attempt it reports is recorded (a notice must never be lost). A process that dies between the two writes leaves a delivery whose lease runs out and which is
    /// then attempted, and fails or expires, again: the same recipients, so the same key, and the second notice is recognised as a duplicate instead of being sent to the sender a second time.
    /// </summary>
    internal static string IdempotencyKeyFor(IReadOnlyList<BounceItem> items)
    {
        var ids = items.Select(i => i.Delivery.DeliveryId).OrderBy(id => id).ToList();
        byte[] bytes = new byte[ids.Count * 16];
        for (int i = 0; i < ids.Count; i++)
        {
            ids[i].TryWriteBytes(bytes.AsSpan(i * 16, 16));
        }

        return "eggmail-dsn:" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes))[..32].ToLowerInvariant();
    }
}
