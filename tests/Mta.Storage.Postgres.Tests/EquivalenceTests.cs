using System.Globalization;
using Mta.Core;
using Mta.Storage.InMemory;
using Mta.Storage.Logic;
using Mta.Storage.Sqlite;
using Mta.Storage.Tests;

namespace Mta.Storage.Postgres.Tests;

/// <summary>
/// Decision E in one place: the same scenario runs on the in-memory, SQLite and PostgreSQL backends and the observable results
/// (queue state, history, statistics, outbox, retention) are compared line by line. Ids are replaced by symbolic names, so the
/// transcript only contains what a caller can see.
/// </summary>
public class EquivalenceTests : PgTestBase
{
    private static readonly Guid Tenant1 = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    private static readonly Guid Tenant2 = Guid.Parse("b0000000-0000-7000-8000-000000000002");

    [Fact]
    public async Task The_same_scenario_gives_the_same_observable_results_on_all_three_backends()
    {
        List<string> memory = await RunOnAsync(StorageBackend.InMemory);
        List<string> sqlite = await RunOnAsync(StorageBackend.Sqlite);
        List<string> postgres = await RunOnAsync(StorageBackend.Postgres);

        Assert.True(memory.Count > 90, "the scenario is substantial: " + memory.Count);
        Assert.Equal(memory, sqlite);
        Assert.Equal(memory, postgres);
    }

    [Fact]
    public async Task The_same_scenario_in_stats_only_mode_gives_the_same_results_on_all_three_backends()
    {
        List<string> memory = await RunOnAsync(StorageBackend.InMemory, HistoryMode.StatsOnly);
        List<string> sqlite = await RunOnAsync(StorageBackend.Sqlite, HistoryMode.StatsOnly);
        List<string> postgres = await RunOnAsync(StorageBackend.Postgres, HistoryMode.StatsOnly);

        Assert.Equal(memory, sqlite);
        Assert.Equal(memory, postgres);
    }

    [Fact]
    public async Task History_cursors_page_identically_on_sqlite_and_postgres()
    {
        string dir = Path.Combine(Path.GetTempPath(), "eggmail-equiv-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        await using SqliteStorage sqlite = SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = dir, StatsFlushInterval = TimeSpan.Zero } }, Clock);
        await sqlite.InitializeAsync(CancellationToken.None);
        try
        {
            // 60 messages over 5 days, several in the very same millisecond so the id breaks the tie, two tenants.
            var messages = new List<AcceptedMessage>();
            for (int i = 0; i < 60; i++)
            {
                DateTimeOffset at = Start.AddHours(-24 * (i / 12)).AddMilliseconds(i % 3 == 0 ? 0 : i * 997);
                messages.Add(Msg(tenant: i % 4 == 0 ? TenantB : TenantA, to: [$"user{i % 7}@example.org"], subject: $"Subject {i}", received: at));
            }

            foreach (AcceptedMessage m in messages)
            {
                await sqlite.Intake.AcceptAsync(m, CancellationToken.None);
                await Storage.Intake.AcceptAsync(m, CancellationToken.None);
            }

            MessageQuery[] queries =
            [
                new(Limit: 7),
                new(Limit: 10, TenantId: TenantA),
                new(Limit: 4, Recipient: "USER3@example.org"),
                new(Limit: 9, SubjectContains: "subject 1"),
                new(Limit: 5, From: Start.AddDays(-2), To: Start.AddHours(-3)),
                new(Limit: 6, Status: "queued", TenantId: TenantB),
            ];
            foreach (MessageQuery query in queries)
            {
                string? cursorA = null, cursorB = null;
                int pages = 0;
                do
                {
                    var a = await sqlite.History.SearchAsync(query with { Cursor = cursorA }, CancellationToken.None);
                    var b = await Storage.History.SearchAsync(query with { Cursor = cursorB }, CancellationToken.None);
                    Assert.Equal(a.Items.Select(i => i.MessageId), b.Items.Select(i => i.MessageId));
                    Assert.Equal(a.Items, b.Items);
                    Assert.Equal(a.NextCursor, b.NextCursor);
                    cursorA = a.NextCursor;
                    cursorB = b.NextCursor;
                    pages++;
                }
                while (cursorA is not null && pages < 50);

                Assert.True(pages >= 1);
            }

            // A cursor produced by one backend continues correctly on the other (they are the same opaque (day, id) pair).
            var firstPage = await sqlite.History.SearchAsync(new MessageQuery(Limit: 11), CancellationToken.None);
            var viaSqlite = await sqlite.History.SearchAsync(new MessageQuery(Limit: 11, Cursor: firstPage.NextCursor), CancellationToken.None);
            var viaPostgres = await Storage.History.SearchAsync(new MessageQuery(Limit: 11, Cursor: firstPage.NextCursor), CancellationToken.None);
            Assert.Equal(viaSqlite.Items.Select(i => i.MessageId), viaPostgres.Items.Select(i => i.MessageId));
        }
        finally
        {
            await sqlite.DisposeAsync();
            try
            {
                Directory.Delete(dir, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }

    private async Task<List<string>> RunOnAsync(StorageBackend backend, HistoryMode mode = HistoryMode.Full)
    {
        var clock = new TestClock(Start);
        StorageOptions options = new() { History = new HistoryOptions { Mode = mode }, Content = new ContentOptions { RetentionDays = 7 }, Retention = new RetentionOptions { MetadataDays = 30 } };
        string? dir = null;
        PgHarness? harness = null;
        IStorage storage;
        switch (backend)
        {
            case StorageBackend.InMemory:
                storage = new InMemoryStorage(options, clock, null, TimeSpan.Zero);
                break;
            case StorageBackend.Sqlite:
                dir = Path.Combine(Path.GetTempPath(), "eggmail-equiv-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(dir);
                storage = SqliteStorage.Create(new StorageOptions
                {
                    History = options.History,
                    Content = options.Content,
                    Retention = options.Retention,
                    Sqlite = new SqliteOptions { DataDirectory = dir, StatsFlushInterval = TimeSpan.Zero, SyncMode = SqliteSyncMode.Off },
                }, clock);
                break;
            default:
                harness = new PgHarness();
                storage = await harness.CreateAsync(options, clock);
                break;
        }

        try
        {
            await storage.InitializeAsync(CancellationToken.None);
            return await new Scenario(storage, clock).RunAsync();
        }
        finally
        {
            await storage.DisposeAsync();
            if (harness is not null)
            {
                await harness.DisposeAsync();
            }

            if (dir is not null)
            {
                try
                {
                    Directory.Delete(dir, recursive: true);
                }
                catch (IOException)
                {
                }
            }
        }
    }

    private sealed class Scenario(IStorage s, TestClock clock)
    {
        private readonly List<string> _log = [];
        private readonly Dictionary<Guid, string> _names = [];

        private string Name(Guid id) => _names.TryGetValue(id, out string? n) ? n : "?" + id.ToString("N")[..4];

        private void Log(string line) => _log.Add(line);

        private static string T(DateTimeOffset? t) => t is null ? "-" : t.Value.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);

        private static string Q(string? v) => v is null ? "~" : "'" + v + "'";

        private AcceptedMessage Message(string label, Guid tenant, string[] to, string subject, TimeSpan at, bool retain = false, bool content = true, string? key = null, string from = "sender@example.com")
        {
            DateTimeOffset when = clock.UtcNow + at;
            Guid id = Ids.New(when);
            var m = new AcceptedMessage
            {
                MessageId = id,
                TenantId = tenant,
                Source = MessageSource.Smtp,
                EnvelopeFrom = from.Length == 0 ? EmailAddress.Null : EmailAddress.Parse(from),
                Recipients = to.Select(r => new AcceptedRecipient(Ids.New(when), EmailAddress.Parse(r))).ToList(),
                Raw = Enumerable.Range(0, 700 + label.Length).Select(i => (byte)(i * 7 + label[0])).ToArray(),
                ReceivedAt = when,
                ExpiresAt = when.AddDays(5),
                IdempotencyKey = key,
                SendingDomain = "sender.example",
                RetainRaw = retain,
                Content = content ? new MessageContent(subject, "text of " + label, "<p>" + label + "</p>", [new AttachmentInfo("f.pdf", "application/pdf", 10, null)], false) : null,
            };
            _names[id] = label;
            foreach (AcceptedRecipient r in m.Recipients)
            {
                _names[r.DeliveryId] = label + ":" + r.Address.LocalPart;
            }

            return m;
        }

        private async Task<IntakeResult> AcceptAsync(AcceptedMessage m)
        {
            IntakeResult r = await s.Intake.AcceptAsync(m, CancellationToken.None);
            Log($"accept {Name(m.MessageId)} -> {r.Status} {Name(r.MessageId)}");
            return r;
        }

        private async Task<List<ClaimedDelivery>> ClaimAsync(string owner, int max, TimeSpan lease)
        {
            var claimed = (await s.Deliveries.ClaimAsync(owner, max, clock.UtcNow, lease, CancellationToken.None)).ToList();
            Log($"claim {owner} max={max} -> {claimed.Count}");
            foreach (ClaimedDelivery d in claimed.OrderBy(d => Name(d.DeliveryId), StringComparer.Ordinal))
            {
                Log($"  {Name(d.DeliveryId)} msg={Name(d.MessageId)} attempt={d.Attempt} rd={d.RecipientDomain} lease={T(d.LeaseUntil)} err={Q(d.LastError)} dup={d.PossibleDuplicate} created={T(d.CreatedAt)} exp={T(d.ExpiresAt)} src={d.Source} from={AddressText.Format(d.EnvelopeFrom)}");
            }

            return claimed;
        }

        private async Task RecordAsync(ClaimedDelivery d, DeliveryOutcome outcome, DateTimeOffset? next = null, SuppressionReason? suppress = null, string? message = null, int? smtp = null, string? enhanced = null,
            IReadOnlyList<WebhookEventDraft>? events = null, bool dup = false, bool count = true)
        {
            await s.Deliveries.RecordAttemptAsync(new DeliveryAttempt
            {
                DeliveryId = d.DeliveryId,
                Outcome = outcome,
                At = clock.UtcNow,
                SmtpCode = smtp,
                EnhancedCode = enhanced,
                Message = message,
                MxHost = "mx.example.net",
                Route = "direct",
                Tls = new TlsInfo(true, "TLS1.3", "TLS_AES_256_GCM_SHA384", "CN=mx", "CN=ca", "AB", null, true, "may", null, true, false),
                NextAttemptAt = next,
                PossibleDuplicate = dup,
                CountAttempt = count,
                Suppress = suppress,
                WebhookEvents = events ?? [],
            }, CancellationToken.None);
            Log($"record {Name(d.DeliveryId)} {outcome}{(count ? "" : " hold")}");
        }

        private async Task QueueAsync(string label)
        {
            QueueStats q = await s.Deliveries.GetQueueStatsAsync(CancellationToken.None);
            Log($"queue {label}: queued={q.Queued} leased={q.Leased} deferred={q.Deferred} oldest={T(q.OldestDueAt)} spool={q.SpoolBytes}");
        }

        private async Task HistoryAsync(string label, Guid tenant, params AcceptedMessage[] messages)
        {
            Log($"history {label}");
            foreach (AcceptedMessage m in messages)
            {
                MessageDetail? d = await s.History.GetAsync(tenant, m.MessageId, CancellationToken.None);
                if (d is null)
                {
                    Log($"  {Name(m.MessageId)}: none");
                }
                else
                {
                    MessageSummary x = d.Summary;
                    Log($"  {Name(m.MessageId)}: status={x.Status} rcpt={x.RecipientCount} size={x.Size} subj={Q(x.Subject)} from={x.EnvelopeFrom} at={T(x.ReceivedAt)} content={d.ContentState} text={Q(d.Content?.Text)} html={Q(d.Content?.Html)} att={d.Content?.Attachments.Count} recipients={string.Join(',', d.Recipients)} raw={d.RawRetained}");
                }

                var events = await s.History.GetEventsAsync(tenant, m.MessageId, CancellationToken.None);
                Log($"  events: {string.Join(" | ", events.Select(e => $"{e.Type}/{(e.DeliveryId is { } id ? Name(id) : "-")}/{e.SmtpCode}/{e.EnhancedCode}/{Q(e.Message)}/{e.MxHost}/{e.Route}/{e.Tls?.Version}/{e.Recipient}/{T(e.At)}"))}");
                Log($"  retained: {(await s.History.GetRetainedRawAsync(tenant, m.MessageId, CancellationToken.None))?.Length}");
            }
        }

        private async Task SearchAsync(string label, MessageQuery q)
        {
            var seen = new List<string>();
            string? cursor = q.Cursor;
            int pages = 0;
            do
            {
                Page<MessageSummary> p = await s.History.SearchAsync(q with { Cursor = cursor }, CancellationToken.None);
                seen.AddRange(p.Items.Select(i => Name(i.MessageId)));
                string? decoded = null;
                if (p.NextCursor is not null && Cursors.TryDecodeHistory(p.NextCursor, out int day, out Guid id))
                {
                    decoded = day.ToString(CultureInfo.InvariantCulture) + ":" + Name(id);
                }

                seen.Add("|" + decoded);
                cursor = p.NextCursor;
                pages++;
            }
            while (cursor is not null && pages < 20);

            Log($"search {label}: {string.Join(',', seen)}");
        }

        private async Task StatsAsync(string label, bool daily, DateTimeOffset from, DateTimeOffset to)
        {
            var rows = await s.Stats.QueryAsync(null, from, to, daily, CancellationToken.None);
            Log($"stats {label}: {rows.Count}");
            foreach (StatRow r in rows)
            {
                Log($"  {T(r.PeriodStart)} {(r.TenantId == Tenant1 ? "T1" : "T2")} {r.SendingDomain} {r.RecipientDomain} a={r.Accepted} d={r.Delivered} df={r.Deferred} hb={r.HardBounce} sb={r.SoftBounce} ex={r.Expired} c={r.Complained} r={r.Rejected} s={r.Suppressed}");
            }
        }

        public async Task<List<string>> RunAsync()
        {
            Guid ep1 = Ids.New(), ep2 = Ids.New(), ep3 = Ids.New();
            _names[ep1] = "ep1";
            _names[ep2] = "ep2";
            _names[ep3] = "ep3";
            foreach ((Guid id, Guid tenant, bool enabled, string[] types) in new[] { (ep1, Tenant1, true, new[] { "*" }), (ep2, Tenant1, true, new[] { "message.bounced" }), (ep3, Tenant2, true, new[] { "message.delivered" }) })
            {
                await s.Config.UpsertWebhookEndpointAsync(new WebhookEndpointRecord(id, tenant, "https://hooks.example.com/" + _names[id], [1, 2], types, enabled, null, null, clock.UtcNow, null), CancellationToken.None);
            }

            // 1. Intake
            AcceptedMessage m1 = Message("m1", Tenant1, ["a@one.example", "b@two.example", "c@one.example"], "Quarterly report", TimeSpan.Zero, retain: true);
            AcceptedMessage m2 = Message("m2", Tenant2, ["x@one.example"], "Welcome", TimeSpan.FromSeconds(30), key: "key-1");
            AcceptedMessage m3 = Message("m3", Tenant1, ["Y@Three.example"], "No content here", TimeSpan.FromMinutes(1), content: false, from: "");
            AcceptedMessage m2dup = Message("m2dup", Tenant2, ["other@one.example"], "Duplicate", TimeSpan.FromMinutes(2), key: "key-1");
            AcceptedMessage m4 = Message("m4", Tenant1, ["p@one.example", "q@one.example"], "Weekly digest 100% real_ok", TimeSpan.FromMinutes(3));
            foreach (AcceptedMessage m in new[] { m1, m2, m3, m2dup, m4 })
            {
                await AcceptAsync(m);
            }

            await QueueAsync("after intake");
            Log($"raw m1 = {(await s.Deliveries.GetRawAsync(m1.MessageId, CancellationToken.None))?.Length}, m2dup = {(await s.Deliveries.GetRawAsync(m2dup.MessageId, CancellationToken.None))?.Length}");

            // 2. Claim and record outcomes
            clock.Advance(TimeSpan.FromMinutes(5));
            List<ClaimedDelivery> first = await ClaimAsync("w1", 4, TimeSpan.FromMinutes(10));
            await QueueAsync("after first claim");
            List<ClaimedDelivery> rest = await ClaimAsync("w2", 10, TimeSpan.FromMinutes(1));
            ClaimedDelivery Find(string name) => first.Concat(rest).Single(d => Name(d.DeliveryId) == name);

            WebhookEventDraft Draft(string type, string payload) => new(Ids.New(), type, payload);
            await RecordAsync(Find("m1:a"), DeliveryOutcome.Delivered, smtp: 250, enhanced: "2.0.0", message: "ok", events: [Draft("message.delivered", "{\"m\":1}")]);
            await RecordAsync(Find("m1:b"), DeliveryOutcome.Deferred, next: clock.UtcNow.AddMinutes(10), smtp: 451, enhanced: "4.7.1", message: "greylisted", events: [Draft("message.deferred", "{\"m\":2}")]);
            await RecordAsync(Find("m1:c"), DeliveryOutcome.Failed, suppress: SuppressionReason.HardBounce, smtp: 550, enhanced: "5.1.1", message: "no such user", events: [Draft("message.bounced", "{\"m\":3}")]);
            await RecordAsync(Find("m2:x"), DeliveryOutcome.Delivered, smtp: 250, events: [Draft("message.delivered", "{\"m\":4}")]);
            await RecordAsync(Find("m3:Y"), DeliveryOutcome.Suppressed);
            await RecordAsync(Find("m4:p"), DeliveryOutcome.Failed, suppress: SuppressionReason.Complaint, smtp: 554, message: "spam");
            await RecordAsync(Find("m4:q"), DeliveryOutcome.AbortedBySwitch, dup: true);
            await RecordAsync(Find("m4:q"), DeliveryOutcome.AbortedBySwitch, dup: true);
            await QueueAsync("after outcomes");
            Log($"suppressed: {await s.Config.IsSuppressedAsync(Tenant1, "c@one.example", CancellationToken.None)} {await s.Config.IsSuppressedAsync(Tenant2, "c@one.example", CancellationToken.None)} {await s.Config.IsSuppressedAsync(Tenant1, "p@one.example", CancellationToken.None)}");
            Log($"raw m1 = {(await s.Deliveries.GetRawAsync(m1.MessageId, CancellationToken.None))?.Length}, m2 = {(await s.Deliveries.GetRawAsync(m2.MessageId, CancellationToken.None))?.Length}");

            // 3. Second round: retry, hold, expiry
            clock.Advance(TimeSpan.FromMinutes(11));
            List<ClaimedDelivery> second = await ClaimAsync("w3", 10, TimeSpan.FromMinutes(5));
            ClaimedDelivery b = second.Single(d => Name(d.DeliveryId) == "m1:b");
            ClaimedDelivery q = second.Single(d => Name(d.DeliveryId) == "m4:q");
            await RecordAsync(q, DeliveryOutcome.Deferred, next: clock.UtcNow.AddMinutes(1), count: false, message: "local limit");
            await RecordAsync(b, DeliveryOutcome.Deferred, next: clock.UtcNow.AddMinutes(30), smtp: 451, message: "again");
            clock.Advance(TimeSpan.FromMinutes(2));
            List<ClaimedDelivery> third = await ClaimAsync("w4", 10, TimeSpan.FromMinutes(5));
            await RecordAsync(third.Single(d => Name(d.DeliveryId) == "m4:q"), DeliveryOutcome.Delivered, smtp: 250);
            await QueueAsync("before expiry");
            clock.Advance(TimeSpan.FromDays(6));
            var reaped = await s.Deliveries.ClaimExpiredAsync("reaper", 10, clock.UtcNow, CancellationToken.None);
            Log($"expired: {string.Join(',', reaped.Select(d => Name(d.DeliveryId)))}");
            foreach (ClaimedDelivery d in reaped)
            {
                await RecordAsync(d, DeliveryOutcome.Expired, message: "lifetime exceeded");
            }

            await QueueAsync("after expiry");
            Log($"released: {await s.Deliveries.ReleaseOwnedLeasesAsync("nobody", CancellationToken.None)} {await s.Deliveries.ReleaseExpiredLeasesAsync(clock.UtcNow, CancellationToken.None)}");

            // 4. History reads
            clock.Set(StorageTestBase.Start.AddDays(2));
            await HistoryAsync("tenant 1", Tenant1, m1, m3, m4);
            await HistoryAsync("tenant 2", Tenant2, m2, m2dup);
            await HistoryAsync("wrong tenant", Tenant2, m1);
            await SearchAsync("all", new MessageQuery(Limit: 2));
            await SearchAsync("tenant1", new MessageQuery(TenantId: Tenant1, Limit: 10));
            await SearchAsync("recipient", new MessageQuery(Recipient: "B@TWO.example"));
            await SearchAsync("sender", new MessageQuery(Sender: "SENDER@example.com", Limit: 1));
            await SearchAsync("subject", new MessageQuery(SubjectContains: "100% real_"));
            await SearchAsync("status partial", new MessageQuery(Status: "partial"));
            await SearchAsync("status expired", new MessageQuery(Status: "expired"));
            await SearchAsync("range", new MessageQuery(From: StorageTestBase.Start.AddMinutes(1), To: StorageTestBase.Start.AddMinutes(2)));

            // 5. Webhooks
            var due = (await s.Webhooks.ClaimDueAsync("dispatcher", 20, clock.UtcNow, TimeSpan.FromMinutes(1), CancellationToken.None))
                .OrderBy(i => i.PayloadJson, StringComparer.Ordinal).ThenBy(i => Name(i.EndpointId), StringComparer.Ordinal).ToList();
            Log($"outbox: {string.Join(" | ", due.Select(i => $"{Name(i.EndpointId)}/{i.EventType}/{i.PayloadJson}/{i.Attempt}"))}");
            await s.Webhooks.CompleteAsync(due[0].Id, new WebhookAttemptRecord(due[0].Id, clock.UtcNow, 200, TimeSpan.FromMilliseconds(12), null, "ok"), WebhookOutboxState.Delivered, null, CancellationToken.None);
            await s.Webhooks.CompleteAsync(due[1].Id, new WebhookAttemptRecord(due[1].Id, clock.UtcNow, 503, TimeSpan.FromMilliseconds(40), "http_5xx", "down"), WebhookOutboxState.Pending, clock.UtcNow.AddMinutes(5), CancellationToken.None);
            Log($"enqueue: {await s.Webhooks.EnqueueAsync(Tenant1, Draft("message.bounced", "{\"async\":1}"), clock.UtcNow, CancellationToken.None)} {await s.Webhooks.EnqueueAsync(Tenant2, Draft("message.bounced", "{}"), clock.UtcNow, CancellationToken.None)}");
            Log($"replay: {await s.Webhooks.ReplayAsync(Tenant1, due[0].Id, clock.UtcNow, CancellationToken.None)} {await s.Webhooks.ReplayAsync(Tenant1, due[1].Id, clock.UtcNow, CancellationToken.None)}");
            foreach (Guid ep in new[] { ep1, ep2, ep3 })
            {
                var attempts = await s.Webhooks.GetAttemptsAsync(ep == ep3 ? Tenant2 : Tenant1, ep, 10, CancellationToken.None);
                Log($"attempts {Name(ep)}: {string.Join(" | ", attempts.Select(a => $"{T(a.At)}/{a.StatusCode}/{a.Duration.TotalMilliseconds}/{a.ErrorClass}/{a.ResponseSnippet}"))}");
            }

            // 6. Statistics, ring, rollup
            await s.Stats.FlushAsync(CancellationToken.None);
            await StatsAsync("hourly", false, StorageTestBase.Start.AddHours(-2), StorageTestBase.Start.AddDays(8));
            var ring = await s.Stats.GetRecentEventsAsync(null, 50, CancellationToken.None);
            Log($"ring: {string.Join(" | ", ring.Select(e => $"{T(e.At)}/{(e.TenantId == Tenant1 ? "T1" : "T2")}/{e.EventType}/{e.RecipientDomain}/{e.Detail}"))}");
            await s.Maintenance.RunAsync(clock.UtcNow, CancellationToken.None);
            await StatsAsync("daily", true, StorageTestBase.Start.AddDays(-1), StorageTestBase.Start.AddDays(8));

            // 7. Retention
            clock.Set(StorageTestBase.Start.AddDays(10));
            await HistoryAsync("content expired", Tenant1, m1);
            await SearchAsync("after content retention", new MessageQuery(TenantId: Tenant1));
            clock.Set(StorageTestBase.Start.AddDays(45));
            await s.Maintenance.RunAsync(clock.UtcNow, CancellationToken.None);
            await HistoryAsync("metadata expired", Tenant1, m1);
            await SearchAsync("after metadata retention", new MessageQuery());
            await StatsAsync("hourly after retention", false, StorageTestBase.Start.AddHours(-2), StorageTestBase.Start.AddDays(8));
            await StatsAsync("daily after retention", true, StorageTestBase.Start.AddDays(-1), StorageTestBase.Start.AddDays(8));
            StorageHealth health = await s.Maintenance.GetHealthAsync(CancellationToken.None);
            Log($"health ready={health.Ready}");
            return _log;
        }
    }
}
