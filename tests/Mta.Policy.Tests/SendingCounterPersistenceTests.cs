using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Policy.Tests;

/// <summary>The sending counters survive a restart and are shared between replicas through the stored totals (the stored side is the in-memory config store; the SQL backends run the same contract in their conformance suites).</summary>
public class SendingCounterPersistenceTests
{
    private static readonly Guid Tenant = Guid.Parse("00000000-0000-0000-0000-00000000000a");
    private static readonly DateTimeOffset Start = new(2026, 10, 12, 8, 30, 0, TimeSpan.Zero);

    private sealed class Process
    {
        public Process(IRuntimeStateStore state, FakeClock clock, SendingLimitsOptions options)
        {
            Counters = new InMemorySendingCounterStore();
            Limits = new SendingLimits(clock, Counters, options);
            Persistence = new SendingCounterPersistence(Counters, state, clock);
        }

        public InMemorySendingCounterStore Counters { get; }

        public SendingLimits Limits { get; }

        public SendingCounterPersistence Persistence { get; }
    }

    private static SendingLimitsOptions Caps(long perHour, long perDay) => new() { DefaultTenant = new LimitSet(perHour, perDay) };

    private static InMemoryStorage NewStorage(FakeClock clock) => new(new StorageOptions(), clock);

    private static long Used(Process p, CounterScope scope, CounterWindow window) => p.Limits.GetUsage(Tenant, null).Single(u => u.Scope == scope && u.Window == window).Used;

    [Fact]
    public async Task A_restart_does_not_reset_the_current_hour_and_day_window()
    {
        var clock = new FakeClock(Start);
        await using var storage = NewStorage(clock);
        var before = new Process(storage.Config, clock, Caps(3, 5));
        for (int i = 0; i < 3; i++)
        {
            Assert.True(before.Limits.TryReserve(Tenant, null).IsAllowed);
        }

        Assert.Equal(4, await before.Persistence.FlushAsync(default));   // global and tenant, hour and day
        // The process is gone; a new one starts over the same storage and loads the windows before it takes mail.
        var after = new Process(storage.Config, clock, Caps(3, 5));
        await after.Persistence.LoadAsync(default);

        Assert.Equal(3, Used(after, CounterScope.Tenant, CounterWindow.Hour));
        Assert.Equal(3, Used(after, CounterScope.Tenant, CounterWindow.Day));
        SendingDecision decision = after.Limits.TryReserve(Tenant, null);
        Assert.Equal(SendingDecisionKind.Deferred, decision.Kind);
        Assert.Equal("tenant hourly limit reached", decision.Reason);

        // The next hour has its own window: the daily total carried over, the hourly count is fresh.
        clock.Advance(TimeSpan.FromHours(1));
        Assert.True(after.Limits.TryReserve(Tenant, null).IsAllowed);
        Assert.True(after.Limits.TryReserve(Tenant, null).IsAllowed);
        Assert.Equal(SendingDecisionKind.Deferred, after.Limits.TryReserve(Tenant, null).Kind);   // 5 per day reached
        Assert.Equal(5, Used(after, CounterScope.Tenant, CounterWindow.Day));
    }

    [Fact]
    public async Task Only_the_change_since_the_last_flush_is_written_so_a_flush_never_counts_twice()
    {
        var clock = new FakeClock(Start);
        await using var storage = NewStorage(clock);
        var p = new Process(storage.Config, clock, Caps(100, 100));
        p.Limits.TryReserve(Tenant, "example.com", 4);
        Assert.Equal(6, await p.Persistence.FlushAsync(default));   // global, tenant and sending domain, hour and day
        Assert.Equal(0, await p.Persistence.FlushAsync(default));   // nothing changed
        p.Limits.TryReserve(Tenant, "example.com", 2);
        await p.Persistence.FlushAsync(default);
        await p.Persistence.FlushAsync(default);

        long hour = Start.ToUnixTimeSeconds() / 3600;
        var stored = await storage.Config.GetSendingCountersAsync(hour, hour / 24, default);
        Assert.All(stored, c => Assert.Equal(6, c.Count));
        Assert.Equal(6, stored.Count);   // global, tenant and domain, hour and day
        Assert.Equal(6, Used(p, CounterScope.Tenant, CounterWindow.Hour));
    }

    [Fact]
    public async Task A_released_reservation_is_taken_off_the_stored_total()
    {
        var clock = new FakeClock(Start);
        await using var storage = NewStorage(clock);
        var p = new Process(storage.Config, clock, Caps(100, 100));
        SendingDecision d = p.Limits.TryReserve(Tenant, null, 3);
        await p.Persistence.FlushAsync(default);
        p.Limits.Release(Tenant, null, 2, d.At);
        await p.Persistence.FlushAsync(default);

        var restarted = new Process(storage.Config, clock, Caps(100, 100));
        await restarted.Persistence.LoadAsync(default);
        Assert.Equal(1, Used(restarted, CounterScope.Tenant, CounterWindow.Hour));
    }

    [Fact]
    public async Task Replicas_learn_what_the_others_sent_at_their_next_flush()
    {
        var clock = new FakeClock(Start);
        await using var storage = NewStorage(clock);
        var a = new Process(storage.Config, clock, Caps(10, 100));
        var b = new Process(storage.Config, clock, Caps(10, 100));

        a.Limits.TryReserve(Tenant, null, 4);
        b.Limits.TryReserve(Tenant, null, 3);
        await a.Persistence.FlushAsync(default);
        await b.Persistence.FlushAsync(default);   // b writes its 3 and reads back a's 4
        Assert.Equal(7, Used(b, CounterScope.Tenant, CounterWindow.Hour));
        Assert.Equal(4, Used(a, CounterScope.Tenant, CounterWindow.Hour));   // a has not flushed since

        await a.Persistence.FlushAsync(default);
        Assert.Equal(7, Used(a, CounterScope.Tenant, CounterWindow.Hour));

        // b's own unflushed reservations stay on top of what it learned.
        b.Limits.TryReserve(Tenant, null, 2);
        await a.Persistence.FlushAsync(default);
        Assert.Equal(9, Used(b, CounterScope.Tenant, CounterWindow.Hour));
        await b.Persistence.FlushAsync(default);
        await a.Persistence.FlushAsync(default);
        Assert.Equal(9, Used(a, CounterScope.Tenant, CounterWindow.Hour));
        Assert.Equal(9, Used(b, CounterScope.Tenant, CounterWindow.Hour));
        Assert.Equal(SendingDecisionKind.Allowed, a.Limits.TryReserve(Tenant, null, 1).Kind);
        Assert.Equal(SendingDecisionKind.Deferred, a.Limits.TryReserve(Tenant, null, 1).Kind);
    }

    [Fact]
    public async Task A_failed_flush_keeps_its_change_for_the_next_one()
    {
        var clock = new FakeClock(Start);
        await using var storage = NewStorage(clock);
        var flaky = new FlakyState(storage.Config);
        var p = new Process(flaky, clock, Caps(100, 100));
        p.Limits.TryReserve(Tenant, null, 5);

        flaky.FailNextWrite = true;
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await p.Persistence.FlushAsync(default));
        Assert.Empty(await storage.Config.GetSendingCountersAsync(0, 0, default));

        await p.Persistence.FlushAsync(default);
        var restarted = new Process(storage.Config, clock, Caps(100, 100));
        await restarted.Persistence.LoadAsync(default);
        Assert.Equal(5, Used(restarted, CounterScope.Tenant, CounterWindow.Hour));
    }

    [Fact]
    public async Task Windows_older_than_the_previous_hour_and_day_are_pruned_from_the_store()
    {
        var clock = new FakeClock(Start);
        await using var storage = NewStorage(clock);
        var p = new Process(storage.Config, clock, Caps(100, 100));
        p.Limits.TryReserve(Tenant, null);
        await p.Persistence.FlushAsync(default);
        Assert.Equal(4, (await storage.Config.GetSendingCountersAsync(0, 0, default)).Count);

        clock.Advance(TimeSpan.FromDays(3));
        await p.Persistence.FlushAsync(default);
        Assert.Empty(await storage.Config.GetSendingCountersAsync(0, 0, default));
    }

    private sealed class FlakyState(IRuntimeStateStore inner) : IRuntimeStateStore
    {
        public bool FailNextWrite { get; set; }

        public ValueTask AddSendingCountersAsync(IReadOnlyList<SendingCounterRecord> deltas, long pruneBeforeHour, long pruneBeforeDay, CancellationToken ct)
        {
            if (FailNextWrite)
            {
                FailNextWrite = false;
                throw new InvalidOperationException("storage unavailable");
            }

            return inner.AddSendingCountersAsync(deltas, pruneBeforeHour, pruneBeforeDay, ct);
        }

        public ValueTask<IReadOnlyList<SendingCounterRecord>> GetSendingCountersAsync(long minHourIndex, long minDayIndex, CancellationToken ct) => inner.GetSendingCountersAsync(minHourIndex, minDayIndex, ct);

        public ValueTask<IReadOnlyList<DomainRecordCheckRecord>> GetDomainRecordChecksAsync(Guid domainId, CancellationToken ct) => inner.GetDomainRecordChecksAsync(domainId, ct);

        public ValueTask ReplaceDomainRecordChecksAsync(Guid domainId, IReadOnlyList<DomainRecordCheckRecord> checks, CancellationToken ct) => inner.ReplaceDomainRecordChecksAsync(domainId, checks, ct);

        public ValueTask AddTlsRptBucketsAsync(IReadOnlyList<TlsRptBucketRecord> buckets, CancellationToken ct) => inner.AddTlsRptBucketsAsync(buckets, ct);

        public ValueTask<IReadOnlyList<TlsRptBucketRecord>> GetTlsRptBucketsAsync(int beforeDay, int max, CancellationToken ct) => inner.GetTlsRptBucketsAsync(beforeDay, max, ct);

        public ValueTask ReplaceTlsRptBucketsAsync(IReadOnlyCollection<Guid> removeIds, TlsRptBucketRecord? replacement, CancellationToken ct) => inner.ReplaceTlsRptBucketsAsync(removeIds, replacement, ct);
    }
}
