using System.Collections.Concurrent;
using Mta.Core;
using Npgsql;

namespace Mta.Storage.Postgres.Tests;

/// <summary>Several application instances (replicas) on one database: the claim never hands a row out twice (design §4.3, SKIP LOCKED).</summary>
public class ConcurrencyTests : PgTestBase
{
    [Fact]
    public async Task Workers_on_several_replicas_never_claim_the_same_delivery()
    {
        const int messages = 150;
        const int recipientsPerMessage = 8;
        PostgresStorage[] replicas = [Pg, await OpenReplicaAsync(), await OpenReplicaAsync()];
        var accepted = Enumerable.Range(0, messages)
            .Select(i => Msg(to: Enumerable.Range(0, recipientsPerMessage).Select(r => $"r{i}x{r}@example.org").ToArray(), size: 128, received: Start.AddMilliseconds(i)))
            .ToList();
        await Task.WhenAll(accepted.Select((m, i) => replicas[i % 3].Intake.AcceptAsync(m, CancellationToken.None).AsTask()));

        Clock.Advance(TimeSpan.FromMinutes(1));
        var claimed = new ConcurrentBag<Guid>();
        int batches = 0;
        var workers = Enumerable.Range(0, 12).Select(w => Task.Run(async () =>
        {
            PostgresStorage replica = replicas[w % 3];
            while (true)
            {
                var batch = await replica.Deliveries.ClaimAsync("worker-" + w, 17, Clock.UtcNow, TimeSpan.FromMinutes(5), CancellationToken.None);
                if (batch.Count == 0)
                {
                    return;
                }

                Interlocked.Increment(ref batches);
                foreach (var d in batch)
                {
                    claimed.Add(d.DeliveryId);
                }
            }
        }));
        await Task.WhenAll(workers);

        Assert.Equal(messages * recipientsPerMessage, claimed.Count);
        Assert.Equal(claimed.Count, claimed.Distinct().Count());
        Assert.True(batches > 12, "the work was actually shared between several claims");
        Assert.Equal(accepted.SelectMany(m => m.Recipients).Select(r => r.DeliveryId).Order(), claimed.Order());
    }

    [Fact]
    public async Task A_claim_skips_rows_locked_by_an_open_transaction_instead_of_waiting()
    {
        await AcceptAsync(Msg(to: ["a@example.org", "b@example.org", "c@example.org"]));
        Clock.Advance(TimeSpan.FromMinutes(1));

        // Another session holds one row locked (as a worker in the middle of its claim transaction would).
        await using var holder = new NpgsqlConnection(Db.ConnectionString);
        await holder.OpenAsync();
        await using NpgsqlTransaction tx = await holder.BeginTransactionAsync();
        await using (var lockRow = new NpgsqlCommand("SELECT id FROM delivery_queue ORDER BY due_at, id LIMIT 1 FOR UPDATE", holder, tx))
        {
            await lockRow.ExecuteScalarAsync();
        }

        // A claim that waited for the locked row would never return (the lock is held until this test releases it), so a
        // generous wait is a hang guard, not a time assertion.
        var claimed = await ClaimAsync().WaitAsync(TimeSpan.FromSeconds(60));

        Assert.Equal(2, claimed.Count);
        await tx.RollbackAsync();
        Assert.Single(await ClaimAsync(owner: "worker-2"));
    }

    [Fact]
    public async Task Webhook_outbox_claims_are_disjoint_across_replicas()
    {
        PostgresStorage[] replicas = [Pg, await OpenReplicaAsync(), await OpenReplicaAsync()];
        await AddEndpointAsync(TenantA, true, "*");
        for (int i = 0; i < 40; i++)
        {
            await replicas[0].Webhooks.EnqueueAsync(TenantA, Draft("message.delivered", $"{{\"n\":{i}}}"), Clock.UtcNow, CancellationToken.None);
        }

        Clock.Advance(TimeSpan.FromSeconds(1));
        var ids = new ConcurrentBag<Guid>();
        await Task.WhenAll(Enumerable.Range(0, 9).Select(w => Task.Run(async () =>
        {
            while (true)
            {
                var items = await replicas[w % 3].Webhooks.ClaimDueAsync("d" + w, 3, Clock.UtcNow, TimeSpan.FromMinutes(1), CancellationToken.None);
                if (items.Count == 0)
                {
                    return;
                }

                foreach (var item in items)
                {
                    ids.Add(item.Id);
                }
            }
        })));

        Assert.Equal(40, ids.Count);
        Assert.Equal(40, ids.Distinct().Count());
    }

    [Fact]
    public async Task Recording_the_same_attempt_from_two_replicas_at_once_completes_it_once()
    {
        PostgresStorage other = await OpenReplicaAsync();
        var m = await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"]));
        var claimed = await ClaimAsync();

        await Task.WhenAll(
            Pg.Deliveries.RecordAttemptAsync(Attempt(claimed[0], DeliveryOutcome.Delivered), CancellationToken.None).AsTask(),
            other.Deliveries.RecordAttemptAsync(Attempt(claimed[0], DeliveryOutcome.Delivered), CancellationToken.None).AsTask());

        Assert.NotNull(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None)); // the second recipient still needs it
        await RecordAsync(claimed[1], DeliveryOutcome.Delivered);
        Assert.Null(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));
        var events = await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None);
        Assert.Equal(2, events.Count(e => e.Type == MessageEventType.Delivered));
    }

    [Fact]
    public async Task Concurrent_recipients_of_one_message_end_with_the_right_final_status()
    {
        PostgresStorage other = await OpenReplicaAsync();
        string[] to = Enumerable.Range(0, 12).Select(i => $"u{i}@example.org").ToArray();
        var m = await AcceptAsync(Msg(to: to, retainRaw: true));
        var claimed = await ClaimAsync();
        Assert.Equal(12, claimed.Count);

        await Task.WhenAll(claimed.Select((d, i) => (i % 2 == 0 ? Pg : other).Deliveries.RecordAttemptAsync(Attempt(d, DeliveryOutcome.Delivered), CancellationToken.None).AsTask()));

        var detail = (await Storage.History.GetAsync(TenantA, m.MessageId, CancellationToken.None))!;
        Assert.Equal("delivered", detail.Summary.Status);
        Assert.True(detail.RawRetained);
        Assert.Null(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));
        Assert.Equal(12 + 1, (await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None)).Count);
    }

    [Fact]
    public async Task Statistics_flushed_by_two_replicas_add_up()
    {
        PostgresStorage other = await OpenReplicaAsync();
        var key = new StatKey(new DateTimeOffset(2026, 10, 12, 9, 0, 0, TimeSpan.Zero), TenantA, "s.example", "a.example");
        await Task.WhenAll(Enumerable.Range(0, 4).Select(i => Task.Run(async () =>
        {
            PostgresStorage s = i % 2 == 0 ? Pg : other;
            for (int n = 0; n < 50; n++)
            {
                s.Stats.Add(key, StatCounter.Accepted, 1);
                if (n % 10 == 0)
                {
                    await s.Stats.FlushAsync(CancellationToken.None);
                }
            }

            await s.Stats.FlushAsync(CancellationToken.None);
        })));

        var rows = await Storage.Stats.QueryAsync(TenantA, key.HourStart.AddHours(-1), key.HourStart.AddHours(1), false, CancellationToken.None);
        Assert.Equal(200, rows.Single().Accepted);
    }

    [Fact]
    public async Task A_lease_is_granted_to_exactly_one_replica_even_when_both_ask_at_once()
    {
        PostgresStorage other = await OpenReplicaAsync();
        for (int round = 0; round < 10; round++)
        {
            string name = "renewal-" + round;
            var results = await Task.WhenAll(
                Task.Run(async () => await Pg.Config.TryAcquireLeaseAsync(name, "node-a", TimeSpan.FromMinutes(1), Clock.UtcNow, CancellationToken.None)),
                Task.Run(async () => await other.Config.TryAcquireLeaseAsync(name, "node-b", TimeSpan.FromMinutes(1), Clock.UtcNow, CancellationToken.None)));
            Assert.Single(results, r => r is not null);
        }
    }

    [Fact]
    public async Task Intake_from_several_replicas_with_one_idempotency_key_creates_one_message()
    {
        PostgresStorage[] replicas = [Pg, await OpenReplicaAsync(), await OpenReplicaAsync()];
        var attempts = Enumerable.Range(0, 24).Select(_ => Msg(idempotencyKey: "same-key")).ToList();
        var results = await Task.WhenAll(attempts.Select((m, i) => replicas[i % 3].Intake.AcceptAsync(m, CancellationToken.None).AsTask()));

        Assert.Single(results, r => r.Status == IntakeStatus.Accepted);
        Assert.Single(await ClaimAsync());
    }
}
