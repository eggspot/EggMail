using Mta.Core;

namespace Mta.Storage.Tests;

/// <summary>Accepting a message: spool, deliveries, idempotency, history content, statistics.</summary>
public abstract class IntakeConformance : StorageTestBase
{
    [Fact]
    public async Task Accept_creates_one_delivery_per_recipient_with_all_fields()
    {
        AcceptedMessage m = await AcceptAsync(Msg(to: ["a@example.org", "b@example.net"], from: "Sender.Name@example.com", lifetime: TimeSpan.FromHours(3)));

        var claimed = await ClaimAsync();
        Assert.Equal(2, claimed.Count);
        Assert.Equal(m.Recipients.Select(r => r.DeliveryId).Order(), claimed.Select(c => c.DeliveryId).Order());
        foreach (var c in claimed)
        {
            Assert.Equal(m.MessageId, c.MessageId);
            Assert.Equal(TenantA, c.TenantId);
            Assert.Equal("Sender.Name@example.com", c.EnvelopeFrom.LocalPart + "@" + c.EnvelopeFrom.Domain);
            Assert.Equal(0, c.Attempt);
            Assert.Equal(Start, c.CreatedAt);
            Assert.Equal(Start.AddHours(3), c.ExpiresAt);
            Assert.Equal("example.com", c.SendingDomain);
            Assert.Equal(MessageSource.Api, c.Source);
            Assert.False(c.PossibleDuplicate);
            Assert.Null(c.LastError);
            Assert.Equal(c.Recipient.Domain, c.RecipientDomain);
        }

        Assert.Contains(claimed, c => c.Recipient.LocalPart == "a" && c.RecipientDomain == "example.org");
        Assert.Contains(claimed, c => c.Recipient.LocalPart == "b" && c.RecipientDomain == "example.net");
    }

    [Fact]
    public async Task Accept_stores_the_raw_message_byte_for_byte()
    {
        AcceptedMessage m = await AcceptAsync(Msg(size: 300_000));
        byte[]? raw = await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None);
        Assert.NotNull(raw);
        Assert.True(m.Raw.Span.SequenceEqual(raw));
    }

    [Fact]
    public async Task GetRaw_of_unknown_message_is_null()
    {
        Assert.Null(await Storage.Deliveries.GetRawAsync(Ids.New(), CancellationToken.None));
    }

    [Fact]
    public async Task Null_reverse_path_round_trips()
    {
        await AcceptAsync(Msg(from: ""));
        var claimed = await ClaimAsync();
        Assert.True(claimed.Single().EnvelopeFrom.IsNull);
    }

    [Fact]
    public async Task Internationalized_addresses_round_trip()
    {
        await AcceptAsync(Msg(to: ["пользователь@example.org"]));
        var claimed = await ClaimAsync();
        Assert.Equal("пользователь", claimed.Single().Recipient.LocalPart);
    }

    [Fact]
    public async Task Accept_requires_a_recipient_and_a_uuidv7_id()
    {
        AcceptedMessage noRecipients = Msg();
        var bad = new AcceptedMessage
        {
            MessageId = noRecipients.MessageId,
            TenantId = noRecipients.TenantId,
            Source = noRecipients.Source,
            EnvelopeFrom = noRecipients.EnvelopeFrom,
            Recipients = [],
            Raw = noRecipients.Raw,
            ReceivedAt = noRecipients.ReceivedAt,
            ExpiresAt = noRecipients.ExpiresAt,
        };
        await Assert.ThrowsAnyAsync<ArgumentException>(async () => await Storage.Intake.AcceptAsync(bad, CancellationToken.None));

        AcceptedMessage v4 = Msg();
        var notV7 = new AcceptedMessage
        {
            MessageId = Guid.NewGuid(),
            TenantId = v4.TenantId,
            Source = v4.Source,
            EnvelopeFrom = v4.EnvelopeFrom,
            Recipients = v4.Recipients,
            Raw = v4.Raw,
            ReceivedAt = v4.ReceivedAt,
            ExpiresAt = v4.ExpiresAt,
        };
        await Assert.ThrowsAnyAsync<ArgumentException>(async () => await Storage.Intake.AcceptAsync(notV7, CancellationToken.None));
    }

    [Fact]
    public async Task Idempotency_key_returns_the_original_message_and_creates_nothing()
    {
        AcceptedMessage first = Msg(idempotencyKey: "key-1");
        IntakeResult r1 = await Storage.Intake.AcceptAsync(first, CancellationToken.None);
        Assert.Equal(IntakeStatus.Accepted, r1.Status);

        AcceptedMessage second = Msg(idempotencyKey: "key-1", to: ["other@example.org", "other2@example.org"]);
        IntakeResult r2 = await Storage.Intake.AcceptAsync(second, CancellationToken.None);
        Assert.Equal(IntakeStatus.DuplicateIdempotencyKey, r2.Status);
        Assert.Equal(first.MessageId, r2.MessageId);

        Assert.Null(await Storage.Deliveries.GetRawAsync(second.MessageId, CancellationToken.None));
        Assert.Single(await ClaimAsync());
        QueueStats stats = await Storage.Deliveries.GetQueueStatsAsync(CancellationToken.None);
        Assert.Equal(first.Raw.Length, stats.SpoolBytes);
    }

    [Fact]
    public async Task Idempotency_duplicate_reports_the_fingerprint_stored_with_the_original_request()
    {
        AcceptedMessage first = WithFingerprint(Msg(idempotencyKey: "fp"), "sha256:aaa");
        Assert.Equal(IntakeStatus.Accepted, (await Storage.Intake.AcceptAsync(first, CancellationToken.None)).Status);

        IntakeResult same = await Storage.Intake.AcceptAsync(WithFingerprint(Msg(idempotencyKey: "fp"), "sha256:aaa"), CancellationToken.None);
        Assert.Equal(IntakeStatus.DuplicateIdempotencyKey, same.Status);
        Assert.Equal("sha256:aaa", same.IdempotencyFingerprint);

        // Key reuse with another body: still a duplicate that creates nothing, and the caller sees the original fingerprint to compare.
        IntakeResult other = await Storage.Intake.AcceptAsync(WithFingerprint(Msg(idempotencyKey: "fp"), "sha256:bbb"), CancellationToken.None);
        Assert.Equal(IntakeStatus.DuplicateIdempotencyKey, other.Status);
        Assert.Equal(first.MessageId, other.MessageId);
        Assert.Equal("sha256:aaa", other.IdempotencyFingerprint);
        Assert.Single(await ClaimAsync());
    }

    [Fact]
    public async Task Idempotency_duplicate_without_a_stored_fingerprint_reports_null()
    {
        await AcceptAsync(Msg(idempotencyKey: "nofp"));
        IntakeResult dup = await Storage.Intake.AcceptAsync(WithFingerprint(Msg(idempotencyKey: "nofp"), "sha256:ccc"), CancellationToken.None);
        Assert.Equal(IntakeStatus.DuplicateIdempotencyKey, dup.Status);
        Assert.Null(dup.IdempotencyFingerprint);
    }

    [Fact]
    public async Task Idempotency_fingerprint_is_replaced_when_an_expired_key_is_reused()
    {
        await AcceptAsync(WithFingerprint(Msg(idempotencyKey: "old"), "sha256:old"));
        Clock.Advance(TimeSpan.FromHours(25));
        await AcceptAsync(WithFingerprint(Msg(idempotencyKey: "old"), "sha256:new"));
        IntakeResult dup = await Storage.Intake.AcceptAsync(Msg(idempotencyKey: "old"), CancellationToken.None);
        Assert.Equal("sha256:new", dup.IdempotencyFingerprint);
    }

    private static AcceptedMessage WithFingerprint(AcceptedMessage m, string fingerprint) => new()
    {
        MessageId = m.MessageId,
        TenantId = m.TenantId,
        Source = m.Source,
        EnvelopeFrom = m.EnvelopeFrom,
        Recipients = m.Recipients,
        Raw = m.Raw,
        ReceivedAt = m.ReceivedAt,
        ExpiresAt = m.ExpiresAt,
        IdempotencyKey = m.IdempotencyKey,
        IdempotencyFingerprint = fingerprint,
        Content = m.Content,
        SendingDomain = m.SendingDomain,
    };

    [Fact]
    public async Task Idempotency_keys_are_unique_per_tenant()
    {
        Assert.Equal(IntakeStatus.Accepted, (await Storage.Intake.AcceptAsync(Msg(tenant: TenantA, idempotencyKey: "same"), CancellationToken.None)).Status);
        Assert.Equal(IntakeStatus.Accepted, (await Storage.Intake.AcceptAsync(Msg(tenant: TenantB, idempotencyKey: "same"), CancellationToken.None)).Status);
        Assert.Equal(IntakeStatus.DuplicateIdempotencyKey, (await Storage.Intake.AcceptAsync(Msg(tenant: TenantA, idempotencyKey: "same"), CancellationToken.None)).Status);
    }

    [Fact]
    public async Task Idempotency_key_expires_after_its_lifetime()
    {
        await AcceptAsync(Msg(idempotencyKey: "k"));
        Clock.Advance(TimeSpan.FromHours(23));
        Assert.Equal(IntakeStatus.DuplicateIdempotencyKey, (await Storage.Intake.AcceptAsync(Msg(idempotencyKey: "k"), CancellationToken.None)).Status);
        Clock.Advance(TimeSpan.FromHours(2));
        Assert.Equal(IntakeStatus.Accepted, (await Storage.Intake.AcceptAsync(Msg(idempotencyKey: "k"), CancellationToken.None)).Status);
    }

    [Fact]
    public async Task Concurrent_accepts_all_land()
    {
        const int count = 150;
        var messages = Enumerable.Range(0, count).Select(i => Msg(to: [$"r{i}@example.org"], size: 1024)).ToList();
        await Task.WhenAll(messages.Select(m => Storage.Intake.AcceptAsync(m, CancellationToken.None).AsTask()));

        QueueStats stats = await Storage.Deliveries.GetQueueStatsAsync(CancellationToken.None);
        Assert.Equal(count, stats.Queued);
        Assert.Equal(count * 1024L, stats.SpoolBytes);
    }

    [Fact]
    public async Task Concurrent_accepts_with_the_same_idempotency_key_create_exactly_one_message()
    {
        var attempts = Enumerable.Range(0, 20).Select(_ => Msg(idempotencyKey: "race")).ToList();
        var results = await Task.WhenAll(attempts.Select(m => Storage.Intake.AcceptAsync(m, CancellationToken.None).AsTask()));
        Assert.Single(results, r => r.Status == IntakeStatus.Accepted);
        Guid winner = results.Single(r => r.Status == IntakeStatus.Accepted).MessageId;
        Assert.All(results, r => Assert.Equal(winner, r.MessageId));
        Assert.Single(await ClaimAsync());
    }

    [Fact]
    public async Task Accepted_statistics_are_counted_per_recipient_domain()
    {
        await AcceptAsync(Msg(to: ["a@one.example", "b@one.example", "c@two.example"], sendingDomain: "s.example"));
        await FlushStatsAsync();

        var rows = await Storage.Stats.QueryAsync(TenantA, Start.AddHours(-2), Start.AddHours(2), daily: false, CancellationToken.None);
        Assert.Equal(2, rows.Count);
        var one = rows.Single(r => r.RecipientDomain == "one.example");
        Assert.Equal(2, one.Accepted);
        Assert.Equal("s.example", one.SendingDomain);
        Assert.Equal(new DateTimeOffset(2026, 10, 12, 12, 0, 0, TimeSpan.Zero), one.PeriodStart);
        Assert.Equal(1, rows.Single(r => r.RecipientDomain == "two.example").Accepted);
    }

    [Fact]
    public async Task History_content_is_recorded_when_full_and_absent_when_stats_only()
    {
        AcceptedMessage m = await AcceptAsync(Msg(subject: "Quarterly report", to: ["a@example.org", "b@example.org"]));

        MessageDetail? detail = await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None);
        Page<MessageSummary> page = await Storage.History.SearchAsync(new MessageQuery(TenantId: TenantA), CancellationToken.None);
        if (IsFull)
        {
            Assert.NotNull(detail);
            Assert.Equal(ContentState.Available, detail.ContentState);
            Assert.Equal("Quarterly report", detail.Content!.Subject);
            Assert.Equal("plain body text", detail.Content.Text);
            Assert.Equal("<p>html body</p>", detail.Content.Html);
            Assert.Equal("a.pdf", detail.Content.Attachments.Single().FileName);
            Assert.Equal(2, detail.Summary.RecipientCount);
            Assert.Equal(["a@example.org", "b@example.org"], detail.Recipients.Order());
            Assert.Equal("queued", detail.Summary.Status);
            Assert.Equal(m.Raw.Length, detail.Summary.Size);
            Assert.Single(page.Items);
        }
        else
        {
            Assert.Null(detail);
            Assert.Empty(page.Items);
            Assert.Null(page.NextCursor);
            Assert.Empty(await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None));
        }
    }

    [Fact]
    public async Task Message_without_extracted_content_is_recorded_as_not_recorded()
    {
        if (!IsFull)
        {
            return;
        }

        AcceptedMessage m = await AcceptAsync(Msg(noContent: true));
        MessageDetail? detail = await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None);
        Assert.NotNull(detail);
        Assert.Equal(ContentState.NotRecorded, detail.ContentState);
        Assert.Null(detail.Content);
    }

    [Fact]
    public async Task Duplicate_message_id_is_rejected()
    {
        AcceptedMessage m = await AcceptAsync();
        await Assert.ThrowsAnyAsync<Exception>(async () => await Storage.Intake.AcceptAsync(m, CancellationToken.None));
    }
}
