using Mta.Core;

namespace Mta.Storage.Tests;

/// <summary>Per-message history with <see cref="HistoryMode.Full"/>: search, detail, events, content lifetime.</summary>
public abstract class HistoryConformance : StorageTestBase
{
    protected override HistoryMode Mode => HistoryMode.Full;

    private async Task<List<AcceptedMessage>> AcceptManyAsync(int count, Guid? tenant = null, TimeSpan? spacing = null)
    {
        var list = new List<AcceptedMessage>();
        for (int i = 0; i < count; i++)
        {
            list.Add(await AcceptAsync(Msg(tenant: tenant, received: Start.AddSeconds(i) + (spacing ?? TimeSpan.Zero) * i, to: [$"user{i}@example.org"], subject: $"Subject {i}")));
        }

        return list;
    }

    [Fact]
    public async Task Search_pages_newest_first_without_gaps_or_duplicates()
    {
        // 25 messages spread over three days.
        var all = new List<AcceptedMessage>();
        for (int i = 0; i < 25; i++)
        {
            all.Add(await AcceptAsync(Msg(received: Start.AddHours(-30 + i * 2.5), to: [$"u{i}@example.org"])));
        }

        var seen = new List<Guid>();
        string? cursor = null;
        int pages = 0;
        do
        {
            Page<MessageSummary> page = await Storage.History.SearchAsync(new MessageQuery(Limit: 10, Cursor: cursor), CancellationToken.None);
            seen.AddRange(page.Items.Select(i => i.MessageId));
            cursor = page.NextCursor;
            pages++;
            Assert.True(pages <= 3);
        }
        while (cursor is not null);

        Assert.Equal(3, pages);
        Assert.Equal(all.AsEnumerable().Reverse().Select(m => m.MessageId), seen);
    }

    [Fact]
    public async Task Recipient_lookup_returns_sorted_recipients_of_the_tenants_messages_only()
    {
        Assert.True(Storage.History is IMessageRecipientLookup, "every provider in this repository implements the optional lookup");
        var lookup = (IMessageRecipientLookup)Storage.History;
        var mine = await AcceptAsync(Msg(tenant: TenantA, to: ["zed@example.org", "amy@example.org", "bob@example.org"]));
        var theirs = await AcceptAsync(Msg(tenant: TenantB, to: ["other@example.org"]));

        var found = await lookup.GetRecipientsAsync(TenantA, [mine.MessageId, theirs.MessageId, Ids.New()], 10, CancellationToken.None);
        Assert.Equal(["amy@example.org", "bob@example.org", "zed@example.org"], found[mine.MessageId]);
        Assert.False(found.ContainsKey(theirs.MessageId), "another tenant's message must not be disclosed");
        Assert.Single(found);

        var capped = await lookup.GetRecipientsAsync(TenantA, [mine.MessageId], 2, CancellationToken.None);
        Assert.Equal(["amy@example.org", "bob@example.org"], capped[mine.MessageId]);
        Assert.Empty(await lookup.GetRecipientsAsync(TenantA, [], 5, CancellationToken.None));
    }

    [Fact]
    public async Task Search_limit_is_respected_and_reports_more_pages()
    {
        await AcceptManyAsync(3);
        Page<MessageSummary> page = await Storage.History.SearchAsync(new MessageQuery(Limit: 1), CancellationToken.None);
        Assert.Single(page.Items);
        Assert.NotNull(page.NextCursor);
        Page<MessageSummary> exact = await Storage.History.SearchAsync(new MessageQuery(Limit: 3), CancellationToken.None);
        Assert.Equal(3, exact.Items.Count);
        Assert.Null(exact.NextCursor);
    }

    [Fact]
    public async Task Search_rejects_a_garbage_cursor()
    {
        await Assert.ThrowsAnyAsync<ArgumentException>(async () => await Storage.History.SearchAsync(new MessageQuery(Cursor: "!!not-a-cursor!!"), CancellationToken.None));
    }

    [Fact]
    public async Task Search_filters_by_tenant_recipient_sender_subject_status_and_time()
    {
        var a1 = await AcceptAsync(Msg(tenant: TenantA, to: ["Alice@example.org", "bob@example.net"], from: "news@sender.example", subject: "Weekly Digest", received: Start));
        var a2 = await AcceptAsync(Msg(tenant: TenantA, to: ["carol@example.org"], from: "billing@sender.example", subject: "Invoice 42", received: Start.AddMinutes(10)));
        var b1 = await AcceptAsync(Msg(tenant: TenantB, to: ["alice@example.org"], from: "news@sender.example", subject: "Welcome", received: Start.AddMinutes(20)));
        Clock.Advance(TimeSpan.FromMinutes(30));

        async Task<List<Guid>> Search(MessageQuery q) => (await Storage.History.SearchAsync(q, CancellationToken.None)).Items.Select(i => i.MessageId).ToList();

        Assert.Equal([a2.MessageId, a1.MessageId], await Search(new MessageQuery(TenantId: TenantA)));
        Assert.Equal([b1.MessageId], await Search(new MessageQuery(TenantId: TenantB)));
        Assert.Equal([b1.MessageId, a2.MessageId, a1.MessageId], await Search(new MessageQuery()));

        Assert.Equal([b1.MessageId, a1.MessageId], await Search(new MessageQuery(Recipient: "ALICE@example.org")));
        Assert.Equal([a1.MessageId], await Search(new MessageQuery(TenantId: TenantA, Recipient: "alice@example.org")));
        Assert.Equal([a1.MessageId], await Search(new MessageQuery(Recipient: "bob@example.net")));
        Assert.Empty(await Search(new MessageQuery(Recipient: "nobody@example.net")));

        Assert.Equal([b1.MessageId, a1.MessageId], await Search(new MessageQuery(Sender: "news@sender.example")));
        Assert.Equal([a2.MessageId], await Search(new MessageQuery(Sender: "BILLING@sender.example")));

        Assert.Equal([a2.MessageId], await Search(new MessageQuery(SubjectContains: "invoice")));
        Assert.Equal([a1.MessageId], await Search(new MessageQuery(SubjectContains: "ekly Dig")));
        Assert.Empty(await Search(new MessageQuery(SubjectContains: "zzz")));

        Assert.Equal([b1.MessageId, a2.MessageId, a1.MessageId], await Search(new MessageQuery(Status: "queued")));
        Assert.Empty(await Search(new MessageQuery(Status: "delivered")));

        Assert.Equal([a2.MessageId], await Search(new MessageQuery(From: Start.AddMinutes(5), To: Start.AddMinutes(15))));
        Assert.Equal([b1.MessageId, a2.MessageId], await Search(new MessageQuery(From: Start.AddMinutes(10))));
        Assert.Equal([a2.MessageId, a1.MessageId], await Search(new MessageQuery(To: Start.AddMinutes(20))));
    }

    [Fact]
    public async Task Subject_search_treats_wildcards_literally()
    {
        var a = await AcceptAsync(Msg(subject: "100% sure_thing", received: Start));
        await AcceptAsync(Msg(subject: "100 sureXthing", received: Start.AddSeconds(1)));
        async Task<List<Guid>> Find(string text) => (await Storage.History.SearchAsync(new MessageQuery(SubjectContains: text), CancellationToken.None)).Items.Select(i => i.MessageId).ToList();
        Assert.Equal([a.MessageId], await Find("100% sure"));
        Assert.Equal([a.MessageId], await Find("sure_thing"));
        Assert.Equal([a.MessageId], await Find("e_t"));
        Assert.Empty(await Find("100\\"));
    }

    [Fact]
    public async Task Search_by_status_follows_the_delivery_outcome()
    {
        var ok = await AcceptAsync(Msg(to: ["ok@example.org"], received: Start));
        var bad = await AcceptAsync(Msg(to: ["bad@example.org"], received: Start.AddSeconds(1)));
        Clock.Advance(TimeSpan.FromMinutes(1));
        var claimed = await ClaimAsync();
        await RecordAsync(claimed.Single(c => c.MessageId == ok.MessageId), DeliveryOutcome.Delivered);
        await RecordAsync(claimed.Single(c => c.MessageId == bad.MessageId), DeliveryOutcome.Failed, smtp: 550);

        var delivered = await Storage.History.SearchAsync(new MessageQuery(Status: "delivered"), CancellationToken.None);
        var bounced = await Storage.History.SearchAsync(new MessageQuery(Status: "Bounced"), CancellationToken.None);
        Assert.Equal(ok.MessageId, delivered.Items.Single().MessageId);
        Assert.Equal(bad.MessageId, bounced.Items.Single().MessageId);
    }

    [Fact]
    public async Task Get_is_scoped_to_the_tenant()
    {
        var m = await AcceptAsync(Msg(tenant: TenantA));
        Assert.NotNull(await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None));
        Assert.Null(await Storage.History.GetAsync(TenantB, m.MessageId, CancellationToken.None));
        Assert.Empty(await Storage.History.GetEventsAsync(TenantB, m.MessageId, CancellationToken.None));
        Assert.Null(await Storage.History.GetAsync(TenantA, Ids.New(), CancellationToken.None));
    }

    [Fact]
    public async Task Summary_has_the_envelope_subject_recipients_and_size()
    {
        var m = await AcceptAsync(Msg(from: "Boss@example.com", to: ["a@example.org", "b@example.org"], subject: "Plan", size: 4321));
        MessageDetail d = (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!;
        Assert.Equal("Boss@example.com", d.Summary.EnvelopeFrom);
        Assert.Equal("Plan", d.Summary.Subject);
        Assert.Equal(2, d.Summary.RecipientCount);
        Assert.Equal(4321, d.Summary.Size);
        Assert.Equal(Start, d.Summary.ReceivedAt);
        Assert.Equal(TenantA, d.Summary.TenantId);
    }

    // Tags (API sends)

    [Fact]
    public async Task Tags_are_stored_with_the_message_and_returned_by_search_and_detail()
    {
        var tagged = await AcceptAsync(Msg(tags: ["welcome", "autumn \"2026\"", "über"], received: Start));
        var plain = await AcceptAsync(Msg(received: Start.AddSeconds(1)));

        MessageDetail detail = (await Storage.History.GetAsync(TenantA, tagged.MessageId, CancellationToken.None))!;
        Assert.Equal(["welcome", "autumn \"2026\"", "über"], detail.Summary.Tags);
        Assert.Null((await Storage.History.GetAsync(TenantA, plain.MessageId, CancellationToken.None))!.Summary.Tags);

        Page<MessageSummary> all = await Storage.History.SearchAsync(new MessageQuery(), CancellationToken.None);
        Assert.Null(all.Items.Single(i => i.MessageId == plain.MessageId).Tags);
        Assert.Equal(["welcome", "autumn \"2026\"", "über"], all.Items.Single(i => i.MessageId == tagged.MessageId).Tags);
    }

    [Fact]
    public async Task Search_by_tag_matches_a_whole_tag_exactly()
    {
        var a = await AcceptAsync(Msg(tags: ["welcome", "vip"], received: Start));
        var b = await AcceptAsync(Msg(tags: ["welcome-back", "bar\"vip"], received: Start.AddSeconds(1)));
        await AcceptAsync(Msg(received: Start.AddSeconds(2)));
        async Task<List<Guid>> Find(string tag, Guid? tenant = null) => (await Storage.History.SearchAsync(new MessageQuery(TenantId: tenant, Tag: tag), CancellationToken.None)).Items.Select(i => i.MessageId).ToList();

        Assert.Equal([a.MessageId], await Find("welcome"));
        Assert.Equal([b.MessageId], await Find("welcome-back"));
        Assert.Equal([a.MessageId], await Find("vip"));      // not the tag bar"vip
        Assert.Equal([b.MessageId], await Find("bar\"vip"));
        Assert.Empty(await Find("wel"));
        Assert.Empty(await Find("WELCOME"));
        Assert.Empty(await Find("welcome", TenantB));
    }

    // Asynchronous bounces and complaints attached to a message's history

    private static AsyncReport Bounce(DateTimeOffset at, string recipient = "alice@example.org") =>
        new(MessageEventType.Bounced, at, recipient, 550, "5.1.1", "mailbox unavailable");

    [Fact]
    public async Task An_async_bounce_is_attached_to_the_message_found_by_its_message_id_header()
    {
        var m = await AcceptAsync(Msg(messageIdHeader: "<Abc.123@mail.Example.com>", to: ["alice@example.org"]));
        var d = (await ClaimAsync()).Single();
        await RecordAsync(d, DeliveryOutcome.Delivered);
        Clock.Advance(TimeSpan.FromMinutes(5));

        Guid? found = await Storage.History.AttachReportAsync(TenantA, " abc.123@MAIL.example.com ", Bounce(Clock.UtcNow), CancellationToken.None);
        Assert.Equal(m.MessageId, found);

        var events = await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None);
        Assert.Equal([MessageEventType.Queued, MessageEventType.Delivered, MessageEventType.Bounced], events.Select(e => e.Type));
        MessageEvent bounce = events[^1];
        Assert.Equal(("alice@example.org", 550, "5.1.1", "mailbox unavailable", null), (bounce.Recipient, bounce.SmtpCode, bounce.EnhancedCode, bounce.Message, bounce.DeliveryId));
        Assert.Equal(Clock.UtcNow, bounce.At);
        Assert.Equal("bounced", (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.Summary.Status);
    }

    [Fact]
    public async Task An_async_bounce_of_one_recipient_of_several_makes_a_delivered_message_partial_and_a_complaint_makes_it_complained()
    {
        var m = await AcceptAsync(Msg(messageIdHeader: "multi@x", to: ["a@example.org", "b@example.org"]));
        foreach (var d in await ClaimAsync())
        {
            await RecordAsync(d, DeliveryOutcome.Delivered);
        }

        Assert.Equal("delivered", (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.Summary.Status);
        await Storage.History.AttachReportAsync(TenantA, "<multi@x>", Bounce(Clock.UtcNow, "b@example.org"), CancellationToken.None);
        Assert.Equal("partial", (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.Summary.Status);

        await Storage.History.AttachReportAsync(TenantA, "<multi@x>", new AsyncReport(MessageEventType.Complained, Clock.UtcNow, "a@example.org", null, null, "abuse"), CancellationToken.None);
        Assert.Equal("complained", (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.Summary.Status);
        var types = (await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None)).Select(e => e.Type).ToList();
        Assert.Equal(1, types.Count(t => t == MessageEventType.Bounced));
        Assert.Equal(1, types.Count(t => t == MessageEventType.Complained));
    }

    [Fact]
    public async Task An_async_report_changes_nothing_for_another_tenant_an_unknown_id_or_an_expired_message()
    {
        var m = await AcceptAsync(Msg(tenant: TenantA, messageIdHeader: "<mine@x>"));
        Assert.Null(await Storage.History.AttachReportAsync(TenantB, "<mine@x>", Bounce(Clock.UtcNow), CancellationToken.None));
        Assert.Null(await Storage.History.AttachReportAsync(TenantA, "<unknown@x>", Bounce(Clock.UtcNow), CancellationToken.None));
        Assert.Null(await Storage.History.AttachReportAsync(TenantA, "  ", Bounce(Clock.UtcNow), CancellationToken.None));
        Assert.Equal([MessageEventType.Queued], (await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None)).Select(e => e.Type));

        Clock.Advance(TimeSpan.FromDays(21)); // past Retention:MetadataDays = 20
        Assert.Null(await Storage.History.AttachReportAsync(TenantA, "<mine@x>", Bounce(Clock.UtcNow), CancellationToken.None));
    }

    [Fact]
    public async Task A_reused_message_id_header_attaches_to_the_newest_message()
    {
        await AcceptAsync(Msg(messageIdHeader: "<same@x>", received: Start));
        var newer = await AcceptAsync(Msg(messageIdHeader: "<same@x>", received: Start.AddMinutes(1)));
        Assert.Equal(newer.MessageId, await Storage.History.AttachReportAsync(TenantA, "<same@x>", Bounce(Clock.UtcNow), CancellationToken.None));
    }

    // Content lifetime

    protected override StorageOptions BuildOptions() => new()
    {
        Content = new ContentOptions { RetentionDays = 6 },
        Retention = new RetentionOptions { MetadataDays = 20 },
    };

    [Fact]
    public async Task Content_expires_after_the_content_retention_but_metadata_remains()
    {
        var m = await AcceptAsync(Msg(retainRaw: true));
        var d = (await ClaimAsync()).Single();
        await RecordAsync(d, DeliveryOutcome.Delivered);

        Clock.Advance(TimeSpan.FromDays(5));
        MessageDetail before = (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!;
        Assert.Equal(ContentState.Available, before.ContentState);
        Assert.NotNull(await Storage.History.GetRetainedRawAsync(TenantA, m.MessageId, CancellationToken.None));

        Clock.Advance(TimeSpan.FromDays(1.5));
        MessageDetail after = (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!;
        Assert.Equal(ContentState.Expired, after.ContentState);
        Assert.Null(after.Content);
        Assert.Equal("delivered", after.Summary.Status);
        Assert.Null(await Storage.History.GetRetainedRawAsync(TenantA, m.MessageId, CancellationToken.None));

        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        MessageDetail afterMaintenance = (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!;
        Assert.Equal(ContentState.Expired, afterMaintenance.ContentState);
        Assert.Equal(2, (await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None)).Count);
        Assert.NotEmpty(await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None));
        Assert.Single((await Storage.History.SearchAsync(new MessageQuery(), CancellationToken.None)).Items);
    }

    [Fact]
    public async Task Metadata_disappears_after_the_metadata_retention_once_maintenance_ran()
    {
        var m = await AcceptAsync();
        Clock.Advance(TimeSpan.FromDays(21));
        Assert.Null(await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None));
        Assert.Empty((await Storage.History.SearchAsync(new MessageQuery(), CancellationToken.None)).Items);

        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        Assert.Null(await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None));
        Assert.Empty(await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None));
    }

    [Fact]
    public async Task Zero_metadata_retention_keeps_history_forever()
    {
        await OpenAsync(Opts(retention: new RetentionOptions { MetadataDays = 0 }, content: new ContentOptions { RetentionDays = 6 }));
        var m = await AcceptAsync();
        Clock.Advance(TimeSpan.FromDays(800));
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);

        MessageDetail? d = await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None);
        Assert.NotNull(d);
        Assert.Equal(ContentState.Expired, d.ContentState);
        Assert.Single((await Storage.History.SearchAsync(new MessageQuery(), CancellationToken.None)).Items);
    }

    [Fact]
    public async Task Content_mode_none_drops_the_content_when_the_message_is_final()
    {
        await OpenAsync(Opts(content: new ContentOptions { Retain = false, RetentionDays = 7 }));
        var m = await AcceptAsync();
        Assert.Equal(ContentState.Available, (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!.ContentState);

        var d = (await ClaimAsync()).Single();
        await RecordAsync(d, DeliveryOutcome.Delivered);
        MessageDetail after = (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!;
        Assert.Equal(ContentState.NotRecorded, after.ContentState);
        Assert.Null(after.Content);
    }

    [Fact]
    public async Task Subject_is_not_stored_when_disabled()
    {
        await OpenAsync(Opts(content: new ContentOptions { StoreSubject = false, RetentionDays = 7 }));
        var m = await AcceptAsync(Msg(subject: "Private subject"));
        MessageDetail d = (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!;
        Assert.Null(d.Summary.Subject);
        Assert.Null(d.Content!.Subject);
        Assert.Equal("plain body text", d.Content.Text);
        Assert.Empty((await Storage.History.SearchAsync(new MessageQuery(SubjectContains: "Private"), CancellationToken.None)).Items);
    }

    [Fact]
    public async Task Stored_bodies_are_truncated_to_the_configured_size_and_flagged()
    {
        await OpenAsync(Opts(content: new ContentOptions { MaxStoredBodyBytes = 100, RetentionDays = 7 }));
        string big = new('é', 500);
        var m = await AcceptAsync(Msg(content: new MessageContent("s", big, big, [], false)));
        MessageDetail d = (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!;
        Assert.True(d.Content!.Truncated);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(d.Content.Text!) <= 100);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(d.Content.Html!) <= 100);
        Assert.StartsWith("éé", d.Content.Text);
    }

    [Fact]
    public async Task Bodies_given_as_utf8_bytes_are_stored_and_read_back_like_strings()
    {
        // The intake path hands over a body that is already UTF-8 in the message as those bytes; every backend must store exactly what it would for the string.
        await OpenAsync(Opts(content: new ContentOptions { RetentionDays = 7 }));
        string text = "Café über € 😀 line two\r\n" + new string('x', 3000);
        string html = "<p>Héllo</p>";
        byte[] textBytes = System.Text.Encoding.UTF8.GetBytes(text);
        byte[] htmlBytes = System.Text.Encoding.UTF8.GetBytes(html);
        var viaBytes = await AcceptAsync(Msg(content: new MessageContent("Subj é", null, null, textBytes, htmlBytes, [], false)));
        var viaStrings = await AcceptAsync(Msg(content: new MessageContent("Subj é", text, html, [], false)));

        foreach (var m in new[] { viaBytes, viaStrings })
        {
            MessageDetail d = (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!;
            Assert.Equal("Subj é", d.Content!.Subject);
            Assert.Equal(text, d.Content.Text);
            Assert.Equal(html, d.Content.Html);
            Assert.False(d.Content.Truncated);
        }
    }

    [Fact]
    public async Task Bodies_given_as_utf8_bytes_are_cut_at_the_configured_size_like_strings()
    {
        await OpenAsync(Opts(content: new ContentOptions { MaxStoredBodyBytes = 100, RetentionDays = 7 }));
        string big = new string('é', 500);
        var viaBytes = await AcceptAsync(Msg(content: new MessageContent("s", null, null, System.Text.Encoding.UTF8.GetBytes(big), System.Text.Encoding.UTF8.GetBytes("<p>short</p>"), [], false)));
        MessageDetail d = (await Storage.History.GetAsync(TenantA, viaBytes.MessageId, CancellationToken.None))!;
        Assert.True(d.Content!.Truncated);
        Assert.Equal(new string('é', 50), d.Content.Text);
        Assert.Equal("<p>short</p>", d.Content.Html);
    }

    [Fact]
    public async Task An_empty_body_given_as_bytes_is_the_empty_string_and_not_null()
    {
        await OpenAsync(Opts(content: new ContentOptions { RetentionDays = 7 }));
        var m = await AcceptAsync(Msg(content: new MessageContent("s", null, null, Array.Empty<byte>(), null, [], false)));
        MessageDetail d = (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!;
        Assert.Equal(string.Empty, d.Content!.Text);
        Assert.Null(d.Content.Html);
    }

    [Fact]
    public async Task Event_tls_details_survive_a_round_trip()
    {
        var m = await AcceptAsync();
        var d = (await ClaimAsync()).Single();
        await RecordAsync(d, DeliveryOutcome.Delivered);
        var delivered = (await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None)).Single(e => e.Type == MessageEventType.Delivered);
        Assert.Equal(new TlsInfo(true, "TLS1.3", "TLS_AES_256_GCM_SHA384", "CN=mx.example.org", "CN=Test CA", "ABCD", null, true, "may", null, true, false), delivered.Tls);
    }
}

/// <summary>With <see cref="HistoryMode.StatsOnly"/> no per-message data is recorded; reads return nothing.</summary>
public abstract class StatsOnlyHistoryConformance : StorageTestBase
{
    protected override HistoryMode Mode => HistoryMode.StatsOnly;

    [Fact]
    public async Task Nothing_is_recorded_and_every_history_read_comes_back_empty()
    {
        var m = await AcceptAsync(Msg(retainRaw: true));
        var d = (await ClaimAsync()).Single();
        await RecordAsync(d, DeliveryOutcome.Delivered);

        Assert.Equal(HistoryMode.StatsOnly, Storage.HistoryMode);
        Assert.Empty((await Storage.History.SearchAsync(new MessageQuery(), CancellationToken.None)).Items);
        Assert.Null(await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None));
        Assert.Empty(await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None));
        Assert.Null(await Storage.History.GetRetainedRawAsync(TenantA, m.MessageId, CancellationToken.None));
    }

    [Fact]
    public async Task Tags_and_asynchronous_reports_store_no_per_message_record()
    {
        var m = await AcceptAsync(Msg(messageIdHeader: "<a@x>", tags: ["welcome"]));
        Assert.Null(await Storage.History.AttachReportAsync(TenantA, "<a@x>", new AsyncReport(MessageEventType.Bounced, Clock.UtcNow, "alice@example.org", 550, "5.1.1", "no"), CancellationToken.None));
        Assert.Empty((await Storage.History.SearchAsync(new MessageQuery(Tag: "welcome"), CancellationToken.None)).Items);
        Assert.Empty(await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None));
    }

    [Fact]
    public async Task Statistics_and_the_recent_ring_work_exactly_as_in_full_mode()
    {
        await AcceptAsync();
        var d = (await ClaimAsync()).Single();
        await RecordAsync(d, DeliveryOutcome.Delivered);
        await FlushStatsAsync();

        var rows = await Storage.Stats.QueryAsync(TenantA, Start.AddHours(-1), Start.AddHours(1), daily: false, CancellationToken.None);
        Assert.Equal(1, rows.Single().Accepted);
        Assert.Equal(1, rows.Single().Delivered);
        Assert.Single(await Storage.Stats.GetRecentEventsAsync(null, 10, CancellationToken.None));
    }

    [Fact]
    public async Task Maintenance_runs_cleanly_without_history()
    {
        await AcceptAsync();
        var reports = await Storage.Maintenance.RunAsync(Clock.UtcNow.AddDays(100), CancellationToken.None);
        Assert.NotEmpty(reports);
    }
}
