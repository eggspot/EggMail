using Mta.Core;
using Mta.Storage.Tests;
using Mta.TestSupport;
using Npgsql;
using Xunit.Abstractions;

namespace Mta.Storage.Postgres.Tests;

/// <summary>
/// Connection loss as the crash of a PostgreSQL deployment: the database connection is cut (through <see cref="TcpProxy"/>) while one operation is in flight, with a seeded delay that lands
/// the cut before the statement, in the middle of the transaction or after the commit, the "network" stays down for a virtual hour, comes back, and sometimes the storage object is closed
/// and reopened (a fresh connection pool). Whatever the timing, the contract holds:
/// <list type="bullet">
/// <item>every call fails with <see cref="StorageUnavailableException"/> (the SMTP layer's 451), promptly, never with another exception and never by hanging;</item>
/// <item>an operation that threw was <b>all or nothing</b>: a message is either whole (every recipient queued, history entry present) or absent; a delivery report is either applied (the
/// delivery gone, exactly one final event, its webhook event in the outbox) or not applied (the delivery still queued, no final event, no outbox row), never half;</item>
/// <item>nothing acknowledged is lost, and the leases an interrupted claim took run out so the deliveries are handed out again;</item>
/// <item>statistics are write-behind and at-least-once: a flush whose acknowledgement was lost may count its batch twice, but an acknowledged increment is never lost.</item>
/// </list>
/// </summary>
public class CrashLoopLifecycleOutageTests(ITestOutputHelper output) : StorageTestBase
{
    private readonly PgHarness _pg = new();
    private TcpProxy? _proxy;
    private string? _viaProxy;
    private bool _reopening;

    protected override async Task<IStorage> CreateAsync(StorageOptions options)
    {
        if (_viaProxy is null || !_reopening)
        {
            await DisposeProxyAsync();
            await _pg.DisposeAsync();
            TestDatabase db = await PostgresTestServer.Instance.CreateDatabaseAsync();
            var direct = new NpgsqlConnectionStringBuilder(db.ConnectionString);
            _proxy = new TcpProxy(direct.Host!, direct.Port);
            _viaProxy = new NpgsqlConnectionStringBuilder(db.ConnectionString) { Host = "127.0.0.1", Port = _proxy.Port, Timeout = 30, Pooling = true }.ConnectionString;
            _pg.Adopt(db);
        }

        return PostgresStorage.Create(PgHarness.WithDatabase(options, _viaProxy), Clock);
    }

    private async Task DisposeProxyAsync()
    {
        if (_proxy is not null)
        {
            await _proxy.DisposeAsync();
            _proxy = null;
        }
    }

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await DisposeProxyAsync();
        await _pg.DisposeAsync();
    }

    private sealed class Row
    {
        public required Guid DeliveryId { get; init; }
        public required Guid MessageId { get; init; }
        public required string Address { get; init; }
        public bool Final { get; set; }
        public ClaimedDelivery? Claim { get; set; }
    }

    private sealed record Mdl(Guid Id, List<Row> Rows);

    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(60);

    [Fact]
    public async Task Cutting_the_connection_at_random_points_never_leaves_an_operation_half_applied()
    {
        int seed = Accelerated.Seed(31337);
        int cycles = Accelerated.Scaled(24);
        output.WriteLine($"outage crash loop: seed {seed}, {cycles} cycles (replay: EGGMAIL_ACCEL_SEED={seed})");
        var rng = new Random(seed);
        var trace = new List<string>();
        var model = new List<Mdl>();
        var expectedOutbox = new HashSet<Guid>();
        await AddEndpointAsync(TenantA, true, "*");
        long acceptedRecipients = 0;
        long lostAccepted = 0;
        long duplicatedAccepted = 0;
        long pendingAcceptedSinceFlush = 0;
        int cuts = 0;
        int appliedDespiteError = 0;
        int notApplied = 0;

        try
        {
            for (int cycle = 0; cycle < cycles; cycle++)
            {
                void Log(string text) => trace.Add($"#{cycle} {Clock.UtcNow:MM-dd HH:mm} {text}");

                // a) normal traffic while the database is up
                for (int i = rng.Next(1, 4); i > 0; i--)
                {
                    string[] to = Enumerable.Range(0, rng.Next(1, 4)).Select(k => $"u{k}@dest{rng.Next(3)}.example").Distinct().ToArray();
                    AcceptedMessage m = Msg(to: to);
                    Assert.Equal(IntakeStatus.Accepted, (await Storage.Intake.AcceptAsync(m, default)).Status);
                    model.Add(new Mdl(m.MessageId, m.Recipients.Select((r, k) => new Row { DeliveryId = r.DeliveryId, MessageId = m.MessageId, Address = to[k] }).ToList()));
                    acceptedRecipients += to.Length;
                    pendingAcceptedSinceFlush += to.Length;
                    Log($"accept {m.MessageId:N} x{to.Length}");
                }

                // b) a worker holds everything that is open, and reports some of it
                Clock.Advance(TimeSpan.FromMinutes(6));
                IReadOnlyList<ClaimedDelivery> claimed = await ClaimAsync(100_000, TimeSpan.FromMinutes(5));
                var open = model.SelectMany(m => m.Rows).Where(r => !r.Final).ToDictionary(r => r.DeliveryId);
                Assert.True(claimed.Select(c => c.DeliveryId).ToHashSet().SetEquals(open.Keys), $"(seed {seed}, cycle {cycle}) the open deliveries are not exactly the claimable ones: {claimed.Count} claimed, {open.Count} open\n{string.Join('\n', trace.TakeLast(40))}");
                foreach (ClaimedDelivery c in claimed)
                {
                    open[c.DeliveryId].Claim = c;
                }

                foreach (Row r in open.Values.Where(_ => rng.NextDouble() < 0.4).ToList())
                {
                    WebhookEventDraft draft = Draft("message.delivered");
                    await RecordAsync(r.Claim!, DeliveryOutcome.Delivered, events: [draft]);
                    r.Final = true;
                    expectedOutbox.Add(draft.EventId);
                }

                // c) one operation meets the outage
                var heldRows = model.SelectMany(m => m.Rows).Where(r => !r.Final).ToList();
                int kind = heldRows.Count == 0 ? 0 : rng.Next(6);
                Row? victimRow = kind is 1 or 2 ? heldRows[rng.Next(heldRows.Count)] : null;
                WebhookEventDraft victimDraft = Draft("message.delivered");
                AcceptedMessage? victimMessage = null;
                string[]? victimTo = null;
                long flushBatch = pendingAcceptedSinceFlush;
                Func<Task> operation;
                switch (kind)
                {
                    case 0:
                        victimTo = [$"v{rng.Next(100)}@dest0.example", $"w{rng.Next(100)}@dest1.example"];
                        victimMessage = Msg(to: victimTo);
                        operation = async () => await Storage.Intake.AcceptAsync(victimMessage, default);
                        Log($"victim: accept {victimMessage.MessageId:N}");
                        break;
                    case 1:
                        operation = async () => await Storage.Deliveries.RecordAttemptAsync(Attempt(victimRow!.Claim!, DeliveryOutcome.Delivered, events: [victimDraft]), default);
                        Log($"victim: record delivered {victimRow!.Address} of {victimRow.MessageId:N}");
                        break;
                    case 2:
                        operation = async () => await Storage.Deliveries.RecordAttemptAsync(Attempt(victimRow!.Claim!, DeliveryOutcome.Deferred, next: Clock.UtcNow.AddMinutes(30), events: [victimDraft]), default);
                        Log($"victim: record deferred {victimRow!.Address} of {victimRow.MessageId:N}");
                        break;
                    case 3:
                        operation = async () => await Storage.Deliveries.ClaimAsync("w2", 100, Clock.UtcNow, TimeSpan.FromMinutes(5), default);
                        Log("victim: claim");
                        break;
                    case 4:
                        operation = async () => await Storage.Stats.FlushAsync(default);
                        Log("victim: statistics flush");
                        break;
                    default:
                        operation = async () => await Storage.Maintenance.RunAsync(Clock.UtcNow, default);
                        Log("victim: maintenance");
                        break;
                }

                Exception? failure = null;
                Task victim = Task.Run(async () =>
                {
                    try
                    {
                        await operation();
                    }
                    catch (Exception ex)
                    {
                        failure = ex;
                    }
                });
                int spins = rng.Next(0, 120);
                for (int i = 0; i < spins && !victim.IsCompleted; i++)
                {
                    await Task.Yield();
                }

                _proxy!.Cut();
                cuts++;
                Task finished = await Task.WhenAny(victim, Task.Delay(Generous));
                Assert.True(finished == victim, $"(seed {seed}, cycle {cycle}) an operation hung after the connection was cut\n{string.Join('\n', trace.TakeLast(40))}");
                Log(failure is null ? "  -> the operation had completed before the cut" : $"  -> {failure.GetType().Name}");
                if (failure is not null)
                {
                    Assert.True(failure is StorageUnavailableException, $"(seed {seed}, cycle {cycle}) a lost connection surfaced as {failure.GetType().Name}: {failure.Message}\n{string.Join('\n', trace.TakeLast(40))}");
                }

                // d) while it is down every call is refused promptly
                await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.Intake.AcceptAsync(Msg(), default).AsTask().WaitAsync(Generous));
                await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.Deliveries.ClaimAsync("w", 5, Clock.UtcNow, TimeSpan.FromMinutes(1), default).AsTask().WaitAsync(Generous));
                await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.Config.GetTenantsAsync(default).AsTask().WaitAsync(Generous));
                Clock.Advance(rng.NextDouble() < 0.5 ? TimeSpan.FromHours(1) : TimeSpan.FromMinutes(10));   // the outage lasts a virtual hour
                _proxy.Restore();
                if (rng.NextDouble() < 0.5)
                {
                    _reopening = true;
                    try
                    {
                        await OpenAsync(Options);
                    }
                    finally
                    {
                        _reopening = false;
                    }

                    Log("storage object reopened (fresh pool)");
                }

                // e) all or nothing
                Clock.Advance(TimeSpan.FromMinutes(6));   // any lease taken by the interrupted operation or by the held claims ran out
                switch (kind)
                {
                    case 0 when failure is not null:
                    {
                        bool exists = await Retry(() => Storage.Deliveries.GetRawAsync(victimMessage!.MessageId, default).AsTask()) is not null;
                        if (exists)
                        {
                            appliedDespiteError++;
                            Log("  the failed accept was applied; it must be whole");
                            model.Add(new Mdl(victimMessage!.MessageId, victimMessage.Recipients.Select((r, k) => new Row { DeliveryId = r.DeliveryId, MessageId = victimMessage.MessageId, Address = victimTo![k] }).ToList()));
                            acceptedRecipients += victimTo!.Length;
                            lostAccepted += victimTo.Length;   // the acknowledged statistics increment of an intake whose answer was lost may be missing
                            MessageDetail? detail = await Retry(() => Storage.History.GetAsync(TenantA, victimMessage.MessageId, default).AsTask());
                            Assert.True(detail is not null && detail.Recipients.Count == victimTo.Length, $"(seed {seed}, cycle {cycle}) a message is half accepted: history has {detail?.Recipients.Count.ToString() ?? "no entry"} of {victimTo.Length} recipients\n{string.Join('\n', trace.TakeLast(40))}");
                        }
                        else
                        {
                            notApplied++;
                        }

                        break;
                    }

                    case 0:
                        model.Add(new Mdl(victimMessage!.MessageId, victimMessage.Recipients.Select((r, k) => new Row { DeliveryId = r.DeliveryId, MessageId = victimMessage.MessageId, Address = victimTo![k] }).ToList()));
                        acceptedRecipients += victimTo!.Length;
                        pendingAcceptedSinceFlush += victimTo.Length;
                        break;
                    case 1 or 2 when failure is not null:
                    {
                        IReadOnlyList<MessageEvent> events = await Retry(() => Storage.History.GetEventsAsync(TenantA, victimRow!.MessageId, default).AsTask());
                        int finals = events.Count(e => e.Recipient == victimRow!.Address && e.Type is MessageEventType.Delivered);
                        int deferrals = events.Count(e => e.Recipient == victimRow!.Address && e.Type is MessageEventType.Deferred);
                        int applied = kind == 1 ? finals : deferrals;
                        Assert.True(applied is 0 or 1, $"(seed {seed}, cycle {cycle}) one report produced {applied} events");
                        if (applied == 1)
                        {
                            appliedDespiteError++;
                            expectedOutbox.Add(victimDraft.EventId);
                            if (kind == 1)
                            {
                                victimRow!.Final = true;
                            }
                        }
                        else
                        {
                            notApplied++;
                        }

                        Log($"  the failed report was {(applied == 1 ? "applied" : "not applied")}");
                        break;
                    }

                    case 1:
                        victimRow!.Final = true;
                        expectedOutbox.Add(victimDraft.EventId);
                        break;
                    case 2:
                        expectedOutbox.Add(victimDraft.EventId);
                        break;
                    case 4 when failure is not null:
                        duplicatedAccepted += flushBatch;   // the flush may have committed although its answer was lost; its batch is then counted again by the retry
                        break;
                    case 4:
                        pendingAcceptedSinceFlush = 0;
                        break;
                }

                // f) the whole truth: the open deliveries are exactly the claimable ones, every report has its event and outbox row or neither
                Clock.Advance(TimeSpan.FromMinutes(6));
                var openAfter = model.SelectMany(m => m.Rows).Where(r => !r.Final).Select(r => r.DeliveryId).ToHashSet();
                IReadOnlyList<ClaimedDelivery> reclaimed = await Retry(() => ClaimAsync(100_000, TimeSpan.FromMinutes(5)));
                Assert.True(reclaimed.Select(c => c.DeliveryId).ToHashSet().SetEquals(openAfter) && reclaimed.Count == openAfter.Count,
                    $"(seed {seed}, cycle {cycle}) after the outage the queue holds {reclaimed.Count} claimable deliveries, the model {openAfter.Count}: an acknowledged delivery was lost or a reported one came back\n{string.Join('\n', trace.TakeLast(40))}");
                foreach (ClaimedDelivery c in reclaimed)
                {
                    model.SelectMany(m => m.Rows).Single(r => r.DeliveryId == c.DeliveryId).Claim = c;
                }

                IReadOnlyList<WebhookOutboxItem> outbox = await Retry(() => Storage.Webhooks.ClaimDueAsync("d", 100_000, Clock.UtcNow, TimeSpan.FromMinutes(1), default).AsTask());
                Assert.True(outbox.Select(i => i.EventId).ToHashSet().SetEquals(expectedOutbox) && outbox.Count == expectedOutbox.Count,
                    $"(seed {seed}, cycle {cycle}) the webhook outbox holds {outbox.Count} events, expected {expectedOutbox.Count}: a report and its webhook event were applied separately\n{string.Join('\n', trace.TakeLast(40))}");
                Clock.Advance(TimeSpan.FromMinutes(2));
            }

            // Finish: report everything, flush, and compare the statistics with what was acknowledged.
            Clock.Advance(TimeSpan.FromMinutes(6));
            foreach (ClaimedDelivery c in await ClaimAsync(100_000, TimeSpan.FromMinutes(5)))
            {
                await RecordAsync(c, DeliveryOutcome.Delivered);
            }

            QueueStats q = await Storage.Deliveries.GetQueueStatsAsync(default);
            Assert.True(q is { Queued: 0, Leased: 0, Deferred: 0 }, $"the drained queue is not empty: {q}");
            await FlushStatsAsync();
            var rows = await Storage.Stats.QueryAsync(null, Start.AddDays(-1), Start.AddDays(30), false, default);
            long accepted = rows.Sum(r => r.Accepted);
            Assert.True(accepted >= acceptedRecipients - lostAccepted && accepted <= acceptedRecipients + duplicatedAccepted,
                $"(seed {seed}) accepted statistics {accepted}, expected between {acceptedRecipients - lostAccepted} and {acceptedRecipients + duplicatedAccepted}");
            output.WriteLine($"outage crash loop: {cuts} cuts; of the operations that failed {appliedDespiteError} had been applied and {notApplied} had not; accepted statistics {accepted} for {acceptedRecipients} acknowledged recipients");
            Assert.True(appliedDespiteError + notApplied >= 3, "the cuts never interrupted an operation, so atomicity was not exercised");
        }
        catch (Exception ex) when (ex is not Xunit.Sdk.XunitException)
        {
            throw new InvalidOperationException($"outage crash loop failed (seed {seed}): {ex.Message}\n{string.Join('\n', trace.TakeLast(40))}", ex);
        }
    }

    /// <summary>The first call after the connection came back may meet a pooled connection the cut killed; the product's callers retry (451), so does the test.</summary>
    private async Task<T> Retry<T>(Func<Task<T>> call)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                return await call().WaitAsync(Generous);
            }
            catch (StorageUnavailableException) when (attempt < 3)
            {
            }
        }
    }
}
