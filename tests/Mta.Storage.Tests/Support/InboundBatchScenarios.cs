using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Mta.Core;
using Mta.Storage.Model;

namespace Mta.Storage.Tests;

/// <summary>
/// The scenarios that pin how the relational inbound store deletes in batches (erasure and retention): the write-side guard, the row and byte caps and the pause. They need the store
/// itself (its test seams are internal), so the SQLite and PostgreSQL test projects call them with their own store; the in-memory store has no batches.
/// </summary>
public static class InboundBatchScenarios
{
    private static readonly Guid Tenant = Guid.Parse("a0000000-0000-7000-8000-0000000000a1");

    private static async Task<(DomainRecord Domain, Guid Route)> DomainAsync(IStorage storage, DateTimeOffset now)
    {
        await storage.Config.UpsertTenantAsync(new Tenant(Tenant, "A", "a", true, now, false), default);
        var domain = new DomainRecord(Ids.New(), Tenant, "example.com", DomainStatus.Verified, null, false, now, null, null, 0, null, false, null);
        await storage.Config.UpsertDomainAsync(domain, default);
        return (domain, Ids.New());
    }

    private static InboundMessageDraft Draft(DomainRecord domain, Guid route, InboundActionKind kind, DateTimeOffset at, int size, string from = "a@sender.test") => new()
    {
        Id = Ids.New(at), TenantId = domain.TenantId, DomainId = domain.Id, Domain = domain.Name, ReceivedAt = at, RemoteAddress = "203.0.113.9", EnvelopeFrom = from,
        EnvelopeTo = "x@" + domain.Name, Auth = InboundAuthResults.NotChecked, RouteId = route, ActionKind = kind, Raw = new byte[size],
    };

    /// <summary>
    /// A message the retention job found expired, and that is made pending again by a retry in the window between the read of the batch and its write, keeps its row and its body. Removing
    /// the pending guard from the delete (or deleting the body first) makes this fail.
    /// </summary>
    public static async Task Retention_keeps_a_message_that_a_retry_made_pending_between_the_read_and_the_write<TContext>(IStorage storage, EfInboundMessageStore<TContext> store, IClock clock)
        where TContext : DbContext, IQueueDbSets
    {
        (DomainRecord domain, Guid route) = await DomainAsync(storage, clock.UtcNow);
        InboundMessageDraft expired = Draft(domain, route, InboundActionKind.Webhook, clock.UtcNow.AddDays(-30), 400);
        InboundMessageDraft settled = Draft(domain, route, InboundActionKind.Store, clock.UtcNow.AddDays(-30).AddSeconds(1), 400);
        await storage.Inbound.AcceptAsync([expired, settled], default);
        Assert.Single(await storage.Inbound.ClaimActionsAsync("w", 5, clock.UtcNow, TimeSpan.FromMinutes(1), default));
        Assert.True(await storage.Inbound.CompleteActionAsync(expired.Id, "w", new InboundActionOutcome(InboundActionState.Failed, clock.UtcNow, null, "x"), default));

        int hookRuns = 0;
        store.BetweenReadAndWrite = async () =>
        {
            hookRuns++;
            Assert.Equal(InboundRetryResult.Queued, await storage.Inbound.RetryActionAsync(Tenant, expired.Id, clock.UtcNow, default));
        };
        try
        {
            var reports = await storage.Maintenance.RunAsync(clock.UtcNow, default);

            Assert.True(hookRuns >= 1);
            Assert.Equal(1, Assert.Single(reports, r => r.Job == "inbound_retention").RowsAffected);   // the settled one only
            InboundMessage survivor = (await storage.Inbound.GetAsync(Tenant, expired.Id, default))!;
            Assert.Equal(InboundActionState.Pending, survivor.ActionState);
            Assert.True(survivor.HasRaw);
            Assert.Equal(400, (await storage.Inbound.GetRawAsync(Tenant, expired.Id, default))!.Length);
            Assert.Null(await storage.Inbound.GetAsync(Tenant, settled.Id, default));
        }
        finally
        {
            store.BetweenReadAndWrite = null;
        }
    }

    /// <summary>The batch caps: no more than the row cap and, by body bytes, no more than the byte cap (but always at least one message) go in one write, with a pause between batches.</summary>
    public static async Task An_erasure_deletes_in_batches_bounded_by_rows_and_bytes_with_a_pause<TContext>(IStorage storage, EfInboundMessageStore<TContext> store, IClock clock)
        where TContext : DbContext, IQueueDbSets
    {
        (DomainRecord domain, Guid route) = await DomainAsync(storage, clock.UtcNow);
        for (int i = 0; i < 10; i++)
        {
            await storage.Inbound.AcceptAsync([Draft(domain, route, InboundActionKind.Store, clock.UtcNow.AddMilliseconds(i), 100, "bulk@sender.test")], default);
        }

        await storage.Inbound.AcceptAsync([Draft(domain, route, InboundActionKind.Store, clock.UtcNow.AddSeconds(1), 100, "friend@sender.test")], default);
        var query = new InboundMessageQuery(Tenant, Sender: "bulk@sender.test");

        // Rows: 10 messages, 3 per write, so 4 writes (3 + 3 + 3 + 1).
        store.MaxBatchRows = 3;
        store.MaxBatchBytes = long.MaxValue;
        store.ErasePause = TimeSpan.Zero;
        int before = store.BatchesWritten;
        Assert.Equal(10, await storage.Inbound.DeleteMatchingAsync(query, default));
        Assert.Equal(4, store.BatchesWritten - before);

        // Bytes: 100-byte bodies against a 250-byte cap are 2 per write, so 5 writes for 10 messages; the pause is taken between them.
        for (int i = 0; i < 10; i++)
        {
            await storage.Inbound.AcceptAsync([Draft(domain, route, InboundActionKind.Store, clock.UtcNow.AddMinutes(1).AddMilliseconds(i), 100, "bulk@sender.test")], default);
        }

        store.MaxBatchRows = 100;
        store.MaxBatchBytes = 250;
        store.ErasePause = TimeSpan.FromMilliseconds(60);
        before = store.BatchesWritten;
        var clockWatch = Stopwatch.StartNew();
        Assert.Equal(10, await storage.Inbound.DeleteMatchingAsync(query, default));
        clockWatch.Stop();
        Assert.Equal(5, store.BatchesWritten - before);
        Assert.True(clockWatch.ElapsedMilliseconds >= 4 * 60 - 20, $"the pause between batches was not taken ({clockWatch.ElapsedMilliseconds} ms)");

        // A body larger than the byte cap still goes, alone.
        await storage.Inbound.AcceptAsync([Draft(domain, route, InboundActionKind.Store, clock.UtcNow.AddMinutes(2), 5_000, "bulk@sender.test"), Draft(domain, route, InboundActionKind.Store, clock.UtcNow.AddMinutes(2).AddMilliseconds(1), 5_000, "bulk@sender.test")], default);
        before = store.BatchesWritten;
        store.ErasePause = TimeSpan.Zero;
        Assert.Equal(2, await storage.Inbound.DeleteMatchingAsync(query, default));
        Assert.Equal(2, store.BatchesWritten - before);

        Assert.Equal(1, (await storage.Inbound.GetUsageAsync(Tenant, null, default)).Messages);   // the friend's mail
    }
}
