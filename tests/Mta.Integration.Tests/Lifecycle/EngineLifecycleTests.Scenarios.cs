using Mta.Smtp.Protocol;
using Mta.Storage;

namespace Mta.Integration.Tests.Lifecycle;

public abstract partial class EngineLifecycleTests
{
    private static List<MessageEvent> Attempts(IEnumerable<MessageEvent> events) =>
        events.Where(e => e.Type is MessageEventType.Deferred or MessageEventType.Expired or MessageEventType.Delivered or MessageEventType.Bounced).OrderBy(e => e.At).ToList();

    private static void AssertGap(TimeSpan gap, TimeSpan expectedBase, string what) =>
        Assert.True(gap >= expectedBase * 0.9 - DocumentedJitter && gap <= expectedBase * 1.1 + DocumentedJitter, $"{what}: the gap was {gap}, the ladder says {expectedBase} +-10 %");

    private static string Text(ScriptedRemote.Mail mail) => System.Text.Encoding.UTF8.GetString(mail.Body);

    [Fact]
    public async Task A_remote_that_is_refusing_connections_for_days_gets_the_message_when_it_returns_inside_the_lifetime()
    {
        if (Unavailable)
        {
            return;
        }

        var h = await NewHarnessAsync(startRemote: false);
        Guid id = await h.SubmitAsync(["rcpt@dest.example"]);
        await h.RunUntilAsync(h.Started + TimeSpan.FromDays(3));
        Assert.False(h.RemoteIsUp);
        Assert.Equal(0, h.Remote.Connections);   // refused: nobody was listening

        var before = Attempts(await h.EventsAsync(id));
        Assert.All(before, e => Assert.Equal(MessageEventType.Deferred, e.Type));
        // A connection problem at the first attempt retries early (a minute), the rest follows the ladder.
        AssertGap(before[1].At - before[0].At, TimeSpan.FromMinutes(1), "first retry after a refused connection");
        for (int i = 2; i < before.Count; i++)
        {
            AssertGap(before[i].At - before[i - 1].At, BaseDelay(i), $"retry {i}");
        }

        h.StartRemote();
        await h.RunUntilQuietAsync();
        var events = await h.EventsAsync(id);
        Assert.Equal(MessageEventType.Delivered, Assert.Single(LifecycleHarness.FinalStates(events)).Value);
        var delivered = Assert.Single(h.Remote.Accepted);
        Assert.Equal(["rcpt@dest.example"], delivered.Recipients);
        Assert.Empty(h.Bounces);
        Assert.Equal(0, await h.StatAsync(r => r.Expired));
    }

    [Fact]
    public async Task A_remote_that_stays_away_past_the_lifetime_expires_the_message_once_and_the_notice_is_sent_when_it_returns()
    {
        if (Unavailable)
        {
            return;
        }

        var h = await NewHarnessAsync(startRemote: false);
        Guid id = await h.SubmitAsync(["rcpt@dest.example"]);
        await h.RunUntilAsync(h.Started + TimeSpan.FromDays(5) + TimeSpan.FromHours(6));
        Assert.Equal(MessageEventType.Expired, Assert.Single(LifecycleHarness.FinalStates(await h.EventsAsync(id))).Value);
        Assert.Equal(1, await h.StatAsync(r => r.Expired));
        Assert.Empty(h.Remote.Accepted);

        // The notice is a message of its own, queued for the sender (it has its own, shorter lifetime); it goes out when the remote returns.
        h.StartRemote();
        await h.RunUntilQuietAsync();
        var notice = Assert.Single(h.Bounces);
        Assert.Contains("rcpt@dest.example", Text(notice));
        Assert.Equal(2, (await h.AllMessagesAsync()).Count);
        Assert.Equal(1, await h.StatAsync(r => r.Expired));
    }

    [Fact]
    public async Task A_notice_that_cannot_be_delivered_within_its_own_lifetime_expires_quietly_and_is_never_bounced_again()
    {
        if (Unavailable)
        {
            return;
        }

        var h = await NewHarnessAsync(startRemote: false);
        Guid id = await h.SubmitAsync(["rcpt@dest.example"]);
        await h.RunUntilAsync(h.Started + TimeSpan.FromDays(5) + TimeSpan.FromDays(3));
        await h.RunUntilQuietAsync();

        var messages = await h.AllMessagesAsync();
        Assert.Equal(2, messages.Count);   // the message and its notice; the notice has the null sender, so its expiry produces nothing
        var notice = messages.Single(m => m.MessageId != id);
        Assert.Equal("expired", notice.Status);
        Assert.Equal(2, await h.StatAsync(r => r.Expired));
        h.StartRemote();
        await h.RunUntilAsync(h.Clock.UtcNow + TimeSpan.FromDays(2));
        Assert.Empty(h.Remote.Accepted);
    }

    [Fact]
    public async Task A_greylisted_recipient_is_retried_after_the_greylist_delay_and_delivered_once()
    {
        if (Unavailable)
        {
            return;
        }

        var h = await NewHarnessAsync();
        int seen = 0;
        h.Remote.Message = (_, _) => Interlocked.Increment(ref seen) == 1 ? LifecycleHarness.Greylisted() : null;
        Guid id = await h.SubmitAsync(["rcpt@dest.example"]);
        await h.RunUntilQuietAsync();

        var attempts = Attempts(await h.EventsAsync(id));
        Assert.Equal([MessageEventType.Deferred, MessageEventType.Delivered], attempts.Select(a => a.Type));
        // Greylisting: the delay is clamped to 5..15 minutes (the ladder's first 2 minutes would be too early to pass the greylist).
        TimeSpan gap = attempts[1].At - attempts[0].At;
        Assert.InRange(gap, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5.5));
        Assert.Single(h.Remote.Accepted);
        Assert.Empty(h.Bounces);
    }

    [Fact]
    public async Task One_message_with_a_delivered_a_refused_and_a_deferred_recipient_ends_each_recipient_in_exactly_one_state()
    {
        if (Unavailable)
        {
            return;
        }

        var h = await NewHarnessAsync();
        h.Remote.Rcpt = r => r.StartsWith("gone@", StringComparison.Ordinal) ? LifecycleHarness.NoSuchUser() : r.StartsWith("busy@", StringComparison.Ordinal) ? SmtpReply.Create(451, "4.2.1", "Mailbox busy") : null;
        Guid id = await h.SubmitAsync(["ok@dest.example", "gone@dest.example", "busy@dest.example"]);
        await h.RunUntilQuietAsync();

        var finals = LifecycleHarness.FinalStates(await h.EventsAsync(id));
        Assert.Equal(MessageEventType.Delivered, finals["ok@dest.example"]);
        Assert.Equal(MessageEventType.Bounced, finals["gone@dest.example"]);
        Assert.Equal(MessageEventType.Expired, finals["busy@dest.example"]);
        Assert.Equal(3, finals.Count);

        // The remote got the message for the one recipient it accepted, once; the sender got one notice per final failure (the refusal at once, the expiry five days later).
        Assert.Equal(["ok@dest.example"], h.Remote.Accepted.Where(m => m.Sender.Length > 0).SelectMany(m => m.Recipients).Distinct());
        Assert.Equal(1, h.Remote.Accepted.Count(m => m.Recipients.Contains("ok@dest.example")));
        Assert.Equal(2, h.Bounces.Count);
        Assert.Single(h.Bounces, b => Text(b).Contains("Final-Recipient: rfc822; gone@dest.example", StringComparison.Ordinal));
        Assert.Single(h.Bounces, b => Text(b).Contains("Final-Recipient: rfc822; busy@dest.example", StringComparison.Ordinal));
        Assert.True(await h.Storage.Config.IsSuppressedAsync(LifecycleHarness.TenantId, "gone@dest.example", default));
        Assert.False(await h.Storage.Config.IsSuppressedAsync(LifecycleHarness.TenantId, "busy@dest.example", default));

        // A later message to the refused address is suppressed without a connection; the bounced address stays suppressed for the rest of the run.
        long connections = h.Remote.Connections;
        Guid second = await h.SubmitAsync(["gone@dest.example"], subject: "again");
        await h.RunUntilQuietAsync();
        Assert.Equal(MessageEventType.Suppressed, Assert.Single(LifecycleHarness.FinalStates(await h.EventsAsync(second))).Value);
        Assert.Equal(connections, h.Remote.Connections);
    }

    [Fact]
    public async Task A_connection_cut_after_the_data_flags_possible_duplicate_a_clean_refusal_never_does_and_the_flag_stays()
    {
        if (Unavailable)
        {
            return;
        }

        var h = await NewHarnessAsync(flakyProxy: true);
        h.Proxy!.DropProbability = 1;
        Guid cut = await h.SubmitAsync(["cut@dest.example"], subject: "cut");
        await h.SettleAsync();
        Assert.True(h.Proxy.Drops >= 1);
        var afterCut = await h.EventsAsync(cut);
        Assert.Contains(afterCut, e => e.Type == MessageEventType.PossibleDuplicate && e.Recipient == "cut@dest.example");
        Assert.Single(h.Remote.Accepted, m => m.Subject == "cut");   // the remote has the message although the sender never saw the 250

        h.Proxy.DropProbability = 0;
        h.Remote.Message = (subject, _) => subject == "refused" ? LifecycleHarness.Temporary() : null;
        Guid refused = await h.SubmitAsync(["refused@dest.example"], subject: "refused");
        await h.RunUntilAsync(h.Clock.UtcNow + TimeSpan.FromHours(2));

        var events = await h.EventsAsync(cut);
        Assert.Equal(MessageEventType.Delivered, Assert.Single(LifecycleHarness.FinalStates(events)).Value);
        Assert.Equal(2, h.Remote.Accepted.Count(m => m.Subject == "cut"));   // delivered twice: allowed only because it is flagged
        Assert.Contains(events, e => e.Type == MessageEventType.PossibleDuplicate);   // and the flag is still in the history after the delivery
        Assert.DoesNotContain(await h.EventsAsync(refused), e => e.Type == MessageEventType.PossibleDuplicate);
    }

    [Fact]
    public async Task A_delivery_claimed_by_a_worker_that_vanished_is_retried_after_its_lease_and_flagged_possible_duplicate()
    {
        if (Unavailable)
        {
            return;
        }

        var h = await NewHarnessAsync();
        await h.StopRuntimeAsync();
        await h.StartRuntimeAsync(startEngine: false);
        Guid id = await h.SubmitAsync(["rcpt@dest.example"]);
        var claimed = await h.Storage.Deliveries.ClaimAsync("worker-that-died", 10, h.Clock.UtcNow, TimeSpan.FromMinutes(15), default);
        Assert.Single(claimed);

        // The engine of the next process starts while the lease still holds: nothing may be sent yet.
        h.StartEngine();
        h.Clock.Advance(TimeSpan.FromMinutes(14));
        h.Runtime.Delivery.Wake();
        await Task.Delay(100);
        Assert.Equal(0, h.Remote.DataCommands);

        h.Clock.Advance(TimeSpan.FromMinutes(2));
        h.Runtime.Delivery.Wake();
        await h.WaitForFinalStateAsync(id);
        await h.RunUntilQuietAsync();
        var events = await h.EventsAsync(id);
        Assert.Equal(MessageEventType.Delivered, Assert.Single(LifecycleHarness.FinalStates(events)).Value);
        Assert.Single(events, e => e.Type == MessageEventType.PossibleDuplicate);
        Assert.Single(h.Remote.Accepted);
    }

    [Fact]
    public async Task Quiesce_aborts_the_attempt_in_flight_keeps_the_ladder_position_and_resume_goes_on_from_there()
    {
        if (Unavailable)
        {
            return;
        }

        var h = await NewHarnessAsync();
        bool defer = true;
        h.Remote.Message = (_, rcpts) => defer && rcpts.Any(r => r.EndsWith("@dest.example", StringComparison.Ordinal)) ? LifecycleHarness.Temporary() : null;
        Guid id = await h.SubmitAsync(["rcpt@dest.example"]);
        for (int i = 0; i < 3; i++)
        {
            await h.SettleAsync();
            if (i < 2)
            {
                Assert.True(await h.StepAsync());
            }
        }

        await h.SettleAsync();
        Assert.Equal(3, Attempts(await h.EventsAsync(id)).Count);

        // The fourth attempt reaches the remote and hangs there.
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        long dataBefore = h.Remote.DataCommands;
        defer = false;
        h.Remote.BeforeReply = ct => gate.Task.WaitAsync(ct);
        Assert.True(await h.StepAsync());
        var deadline = DateTime.UtcNow.AddSeconds(60);
        while (h.Remote.DataCommands == dataBefore)
        {
            Assert.True(DateTime.UtcNow < deadline, "the attempt never reached the remote");
            await Task.Delay(5);
        }

        await h.Runtime.Delivery.QuiesceAsync(TimeSpan.FromMilliseconds(200), default);
        gate.SetResult();   // the remote answers now, to a connection nobody holds any more
        Assert.Equal(0, h.Runtime.Delivery.PendingGroups);

        // Nothing was counted: still three attempts, the delivery is waiting and flagged (the data had been sent when the connection was aborted).
        var afterQuiesce = await h.EventsAsync(id);
        Assert.Equal(3, Attempts(afterQuiesce).Count);
        Assert.Contains(afterQuiesce, e => e.Type == MessageEventType.PossibleDuplicate);
        Assert.DoesNotContain(afterQuiesce, e => e.Type == MessageEventType.Delivered);

        // While paused nothing is claimed, however much time passes.
        h.Remote.BeforeReply = null;
        defer = true;
        long paused = h.Remote.DataCommands;
        h.Clock.Advance(TimeSpan.FromHours(3));
        h.Runtime.Delivery.Wake();
        await Task.Delay(100);
        Assert.Equal(paused, h.Remote.DataCommands);

        // Resumed: the aborted attempt is made again at once, and its deferral is the ladder's fourth step (30 minutes), not the first (2 minutes) and not a later one.
        h.Runtime.Delivery.Resume();
        await h.SettleAsync();
        var events = Attempts(await h.EventsAsync(id));
        Assert.Equal(4, events.Count);
        Assert.Equal(h.Clock.UtcNow, events[3].At);
        Assert.True(await h.StepAsync());
        await h.SettleAsync();
        events = Attempts(await h.EventsAsync(id));
        Assert.Equal(5, events.Count);
        AssertGap(events[4].At - events[3].At, BaseDelay(4), "the first retry after a quiesce");
    }

    [Fact]
    public async Task A_restart_in_the_middle_of_the_ladder_carries_on_with_the_same_schedule_and_still_sends_one_notice()
    {
        if (Unavailable)
        {
            return;
        }

        var h = await NewHarnessAsync();
        h.Remote.Message = (_, rcpts) => rcpts.Any(r => r.EndsWith("@dest.example", StringComparison.Ordinal)) ? LifecycleHarness.Temporary() : null;
        Guid id = await h.SubmitAsync(["rcpt@dest.example"]);
        int restarts = 0;
        for (int i = 0; i < 5000; i++)
        {
            if (!await h.StepAsync())
            {
                break;
            }

            // A graceful restart of the whole process after every fifth step, while the delivery is waiting.
            if (i % 5 == 4)
            {
                await h.SettleAsync();
                await h.StopRuntimeAsync();
                await h.StartRuntimeAsync();
                restarts++;
            }
        }

        Assert.True(restarts >= 5);
        var attempts = Attempts(await h.EventsAsync(id));
        Assert.Equal(MessageEventType.Expired, attempts[^1].Type);
        for (int i = 1; i < attempts.Count - 1; i++)
        {
            AssertGap(attempts[i].At - attempts[i - 1].At, BaseDelay(i), $"retry {i} (restarts: {restarts})");
        }

        Assert.InRange(attempts.Count, AttemptsUntilExpiry(TimeSpan.FromDays(5), 1.1), AttemptsUntilExpiry(TimeSpan.FromDays(5), 0.9));
        Assert.Single(h.Bounces);
        Assert.Equal(2, (await h.AllMessagesAsync()).Count);
    }

    [Fact]
    public async Task A_process_that_dies_after_the_notice_was_queued_but_before_the_expiry_was_recorded_does_not_send_a_second_notice()
    {
        if (Unavailable)
        {
            return;
        }

        FaultInjectingStorage? faulty = null;
        var h = await NewHarnessAsync(wrap: s => faulty = new FaultInjectingStorage(s));
        h.Remote.Message = (_, rcpts) => rcpts.Any(r => r.EndsWith("@dest.example", StringComparison.Ordinal)) ? LifecycleHarness.Temporary() : null;
        int failures = 1;
        faulty!.FailRecording = a => a.Outcome == DeliveryOutcome.Expired && Interlocked.Decrement(ref failures) >= 0;
        Guid id = await h.SubmitAsync(["rcpt@dest.example"]);

        // Walk the ladder until the final attempt: the worker dies right after it queued the notice, so its lease stays.
        var deadline = DateTime.UtcNow.AddSeconds(90);
        while (faulty.FailedRecordings == 0)
        {
            Assert.True(DateTime.UtcNow < deadline, "the expiry was never reached");
            if (await h.IsIdleAsync())
            {
                Assert.True(await h.StepAsync());
            }
            else
            {
                await Task.Delay(5);
            }
        }

        // The next process takes over when the lease has run out.
        h.Clock.Advance(TimeSpan.FromMinutes(16));
        h.Runtime.Delivery.Wake();
        await h.WaitForFinalStateAsync(id);
        await h.RunUntilQuietAsync();

        Assert.Equal(1, faulty.FailedRecordings);
        var events = await h.EventsAsync(id);
        Assert.Equal(MessageEventType.Expired, Assert.Single(LifecycleHarness.FinalStates(events)).Value);
        var notice = Assert.Single(h.Bounces);
        Assert.Contains("rcpt@dest.example", Text(notice));
        Assert.Equal(2, (await h.AllMessagesAsync()).Count);
        Assert.Equal(1, await h.StatAsync(r => r.Expired));
    }
}
