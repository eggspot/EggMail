using Mta.Core;
using Mta.Policy;
using Mta.Storage;
using Mta.Storage.Sqlite;
using Mta.Webhooks;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>
/// The delivery engine over days of virtual time, on a real storage backend (SQLite files or PostgreSQL), the same scenarios on both. The engine, the SMTP client, the retry schedule, the DSN service,
/// the webhook fan-out and the storage are the production ones; the remote MTA is a scripted loopback server and time is a <see cref="Mta.TestSupport.VirtualClock"/> the test moves to the next due instant.
/// This is accelerated: it proves the schedule, the exactly-once bookkeeping and the state carried across restarts, not how the process behaves in 5 real days.
/// </summary>
public abstract partial class EngineLifecycleTests(LifecycleBackend backend) : IAsyncLifetime
{
    private readonly List<LifecycleHarness> _harnesses = [];

    private bool Unavailable => backend.Unavailable;

    public async Task InitializeAsync() => await backend.PrepareAsync();

    public async Task DisposeAsync()
    {
        foreach (LifecycleHarness h in _harnesses)
        {
            await h.DisposeAsync();
        }

        await backend.CleanupAsync();
    }

    internal async Task<LifecycleHarness> NewHarnessAsync(Action<MtaConfigBuilder>? tune = null, Func<IStorage, IStorage>? wrap = null, bool startRemote = true, bool flakyProxy = false)
    {
        var h = new LifecycleHarness(backend.NewStorageOptions(), backend.CreateStorage, wrap, flakyProxy) { Tune = tune };
        _harnesses.Add(h);
        if (startRemote)
        {
            h.StartRemote();
        }

        await h.StartRuntimeAsync();
        return h;
    }

    // The documented ladder (docs/components/delivery.md, Mta.Policy.RetryScheduleOptions): the oracle for every test below.
    private static readonly TimeSpan[] DocumentedLadder = [TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(30), TimeSpan.FromHours(1), TimeSpan.FromHours(2), TimeSpan.FromHours(4)];
    private static readonly TimeSpan DocumentedRepeat = TimeSpan.FromHours(4);
    private static readonly TimeSpan DocumentedJitter = TimeSpan.FromMilliseconds(1);

    private static TimeSpan BaseDelay(int attemptsMade) => attemptsMade <= DocumentedLadder.Length ? DocumentedLadder[attemptsMade - 1] : DocumentedRepeat;

    /// <summary>How many attempts the ladder makes before the lifetime ends, if every delay is the base delay times <paramref name="factor"/> (the schedule jitters each delay by +-10 %).</summary>
    private static int AttemptsUntilExpiry(TimeSpan lifetime, double factor)
    {
        TimeSpan margin = TimeSpan.FromMinutes(1);
        TimeSpan at = TimeSpan.Zero;
        int attempts = 1;
        while (true)
        {
            TimeSpan next = at + (BaseDelay(attempts) * factor);
            if (next < lifetime)
            {
                at = next;
                attempts++;
            }
            else
            {
                return lifetime - at >= margin + margin ? attempts + 1 : attempts;
            }
        }
    }

    [Fact]
    public void The_default_ladder_is_the_documented_one()
    {
        var options = new RetryScheduleOptions();
        Assert.Equal(DocumentedLadder, options.Delays);
        Assert.Equal(DocumentedRepeat, options.RepeatInterval);
        Assert.Equal(0.10, options.JitterFraction);
        Assert.Equal(TimeSpan.FromDays(5), new QueueOptions().MaxLifetime);
    }

    [Fact]
    public async Task A_message_that_is_always_deferred_follows_the_ladder_for_five_days_then_expires_with_one_notice_to_the_sender()
    {
        if (Unavailable)
        {
            return;
        }

        var h = await NewHarnessAsync();
        h.Remote.Message = (_, rcpts) => rcpts.Any(r => r.EndsWith("@dest.example", StringComparison.Ordinal)) ? LifecycleHarness.Temporary() : null;
        var endpointId = await AddEndpointAsync(h, WebhookEventFactory.Expired, WebhookEventFactory.Deferred);

        Guid id = await h.SubmitAsync(["rcpt@dest.example"]);
        DateTimeOffset expires = h.Started + TimeSpan.FromDays(5);
        await h.RunUntilQuietAsync();

        var events = await h.EventsAsync(id);
        var attempts = events.Where(e => e.Type is MessageEventType.Deferred or MessageEventType.Expired).ToList();
        Assert.Equal(MessageEventType.Expired, attempts[^1].Type);
        Assert.All(attempts.Take(attempts.Count - 1), e => Assert.Equal(MessageEventType.Deferred, e.Type));

        // The first attempt is immediate; every later gap is the base delay of the attempts made so far, jittered by at most 10 %.
        Assert.Equal(h.Started, attempts[0].At);
        for (int i = 1; i < attempts.Count; i++)
        {
            TimeSpan gap = attempts[i].At - attempts[i - 1].At;
            TimeSpan baseDelay = BaseDelay(i);
            bool finalAttempt = i == attempts.Count - 1 && attempts[i].At == expires - TimeSpan.FromMinutes(1);
            if (finalAttempt)
            {
                Assert.True(gap <= baseDelay * 1.1 + DocumentedJitter, $"the final attempt before expiry comes after {gap}, later than the ladder's {baseDelay}");
            }
            else
            {
                Assert.InRange(gap, baseDelay * 0.9 - DocumentedJitter, baseDelay * 1.1 + DocumentedJitter);
            }
        }

        // The number of attempts is what the ladder makes in the lifetime, within the jitter's bounds, and the lifetime is never exceeded.
        Assert.InRange(attempts.Count, AttemptsUntilExpiry(TimeSpan.FromDays(5), 1.1), AttemptsUntilExpiry(TimeSpan.FromDays(5), 0.9));
        Assert.True(attempts[^1].At < expires);
        Assert.True(expires - attempts[^1].At <= TimeSpan.FromHours(4) * 1.1, "the last attempt is within one repeat interval of the expiry");
        Assert.Equal(attempts.Count, h.Remote.DataCommands - h.Bounces.Count);   // every attempt reached the remote once; the notice is the only other message

        // One final state, one notice.
        Assert.Equal(MessageEventType.Expired, Assert.Single(LifecycleHarness.FinalStates(events)).Value);
        var notice = Assert.Single(h.Bounces);
        Assert.Contains("rcpt@dest.example", System.Text.Encoding.UTF8.GetString(notice.Body));
        Assert.Equal("expired", (await h.AllMessagesAsync()).Single(m => m.MessageId == id).Status);
        Assert.DoesNotContain(events, e => e.Type == MessageEventType.PossibleDuplicate);   // a clean 4xx never flags

        // More days with repeated sweeps change nothing: no new attempt, no second notice, the counters stay.
        await h.RunUntilAsync(h.Clock.UtcNow + TimeSpan.FromDays(3));
        await h.Storage.Deliveries.ReleaseExpiredLeasesAsync(h.Clock.UtcNow, default);
        Assert.Single(h.Bounces);
        Assert.Equal(attempts.Count, (await h.EventsAsync(id)).Count(e => e.Type is MessageEventType.Deferred or MessageEventType.Expired));
        Assert.Equal(1, await h.StatAsync(r => r.Expired));
        Assert.Equal(attempts.Count - 1, await h.StatAsync(r => r.Deferred));

        // One webhook event per attempt outcome: the deferrals and exactly one message.expired.
        var outbox = await ClaimAllOutboxAsync(h);
        Assert.Equal(1, outbox.Count(i => i.EventType == WebhookEventFactory.Expired));
        Assert.Equal(attempts.Count - 1, outbox.Count(i => i.EventType == WebhookEventFactory.Deferred));
        Assert.All(outbox, i => Assert.Equal(endpointId, i.EndpointId));
    }

    private static async Task<Guid> AddEndpointAsync(LifecycleHarness h, params string[] types)
    {
        var endpoint = new WebhookEndpointRecord(Ids.New(), LifecycleHarness.TenantId, "http://hooks.example/" + Guid.NewGuid().ToString("N"), [1, 2, 3], types, true, null, null, h.Clock.UtcNow, null);
        await h.Storage.Config.UpsertWebhookEndpointAsync(endpoint, default);
        return endpoint.Id;
    }

    private static async Task<List<WebhookOutboxItem>> ClaimAllOutboxAsync(LifecycleHarness h)
    {
        var all = new List<WebhookOutboxItem>();
        while (true)
        {
            var batch = await h.Storage.Webhooks.ClaimDueAsync("test", 500, h.Clock.UtcNow + TimeSpan.FromDays(365), TimeSpan.FromMinutes(1), default);
            if (batch.Count == 0)
            {
                return all;
            }

            all.AddRange(batch);
        }
    }
}

public sealed class EngineLifecycleOnSqlite() : EngineLifecycleTests(new SqliteLifecycleBackend());

public sealed class EngineLifecycleOnPostgres() : EngineLifecycleTests(new PostgresLifecycleBackend());
