using Mta.Smtp.Protocol;
using Mta.Storage;
using Mta.TestSupport;

namespace Mta.Integration.Tests.Lifecycle;

public abstract partial class EngineLifecycleTests
{
    [Fact]
    public async Task Two_processes_on_one_database_expire_every_message_once_and_send_every_notice_once()
    {
        if (Unavailable || !backend.SupportsSeveralProcesses)
        {
            return;   // SQLite is one process on a local volume
        }

        var first = await NewHarnessAsync();
        var second = new LifecycleHarness(backend.NewStorageOptions(), backend.CreateStorage, sharedWith: first);
        _harnesses.Add(second);
        await second.StartRuntimeAsync();
        first.Remote.Message = (_, rcpts) => rcpts.Any(r => r.EndsWith("@dest.example", StringComparison.Ordinal)) ? LifecycleHarness.Temporary() : null;

        var ids = new List<Guid>();
        for (int i = 0; i < 6; i++)
        {
            ids.Add(await first.SubmitAsync([$"rcpt{i}@dest.example"], subject: $"replica-{i}"));
        }

        for (int step = 0; step < 5000; step++)
        {
            if (!await first.StepAsync())
            {
                break;
            }

            second.Runtime.Delivery.Wake();
        }

        await first.SettleAsync();
        foreach (Guid id in ids)
        {
            var events = await first.EventsAsync(id);
            Assert.Equal(MessageEventType.Expired, Assert.Single(LifecycleHarness.FinalStates(events)).Value);
            var attempts = Attempts(events);
            // One attempt per step of the ladder: two processes never attempt the same delivery at the same instant.
            Assert.Equal(attempts.Count, attempts.Select(a => a.At).Distinct().Count());
            Assert.InRange(attempts.Count, AttemptsUntilExpiry(TimeSpan.FromDays(5), 1.1), AttemptsUntilExpiry(TimeSpan.FromDays(5), 0.9));
        }

        Assert.Equal(6, first.Bounces.Count);
        for (int i = 0; i < 6; i++)
        {
            Assert.Single(first.Bounces, b => Text(b).Contains($"Final-Recipient: rfc822; rcpt{i}@dest.example", StringComparison.Ordinal));
        }

        await second.Storage.Stats.FlushAsync(default);   // each process counts what it recorded in memory and writes it behind
        Assert.Equal(6, await first.StatAsync(r => r.Expired));
    }

    /// <summary>The recipient's local part says what the remote does with it: delivered at once, greylisted once, deferred a number of times, deferred for good, refused.</summary>
    private sealed class FateScript
    {
        private readonly Dictionary<string, int> _seen = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _gate = new();

        public SmtpReply? Rcpt(string recipient)
        {
            string local = recipient[..recipient.IndexOf('@')];
            if (!recipient.EndsWith("@dest.example", StringComparison.Ordinal))
            {
                return null;
            }

            int times;
            lock (_gate)
            {
                _seen[recipient] = times = _seen.GetValueOrDefault(recipient) + 1;
            }

            if (local.StartsWith("gone", StringComparison.Ordinal))
            {
                return LifecycleHarness.NoSuchUser();
            }

            if (local.StartsWith("grey", StringComparison.Ordinal))
            {
                return times == 1 ? LifecycleHarness.Greylisted() : null;
            }

            if (local.StartsWith("never", StringComparison.Ordinal))
            {
                return SmtpReply.Create(451, "4.2.1", "Mailbox busy");
            }

            if (local.StartsWith("flaky", StringComparison.Ordinal))
            {
                int deferrals = int.Parse(local[5..local.IndexOf('-')], System.Globalization.CultureInfo.InvariantCulture);
                return times <= deferrals ? SmtpReply.Create(451, "4.2.1", "Mailbox busy") : null;
            }

            return null;
        }
    }

    [Fact]
    public async Task Many_messages_with_mixed_fates_each_end_every_recipient_in_exactly_one_state_and_every_failure_is_reported_once()
    {
        if (Unavailable)
        {
            return;
        }

        int seed = Accelerated.Seed(20261012);
        int messages = Accelerated.Scaled(24);
        var rng = new Random(seed);
        var h = await NewHarnessAsync();
        var script = new FateScript();
        h.Remote.Rcpt = script.Rcpt;

        // Each message has one to three recipients with a fate each; the plan is remembered to check the outcome against.
        var plan = new List<(Guid Id, string Recipient, string Fate)>();
        for (int i = 0; i < messages; i++)
        {
            int count = rng.Next(1, 4);
            var recipients = new List<string>();
            for (int r = 0; r < count; r++)
            {
                string fate = rng.Next(10) switch { < 4 => "ok", < 5 => "grey", < 7 => $"flaky{rng.Next(1, 12)}", < 8 => "never", _ => "gone" };
                recipients.Add($"{fate}-{i}-{r}@dest.example");
            }

            Guid id = await h.SubmitAsync(recipients.ToArray(), subject: $"mixed-{i}");
            plan.AddRange(recipients.Select(r => (id, r, r[..r.IndexOf('-')])));

            // Spread the submissions over the first two days (the engine finishes what is due before time moves on: an attempt still in flight when the virtual clock jumps past its lease would be claimed again).
            await h.SettleAsync();
            h.Clock.Advance(TimeSpan.FromMinutes(rng.Next(1, 120)));
            h.Runtime.Delivery.Wake();
        }

        string context = $" (seed {seed}, {messages} messages; EGGMAIL_ACCEL_SEED replays it)";
        await h.RunUntilQuietAsync();
        await h.RunUntilAsync(h.Clock.UtcNow + TimeSpan.FromDays(3));
        await h.RunUntilQuietAsync();

        foreach (var group in plan.GroupBy(p => p.Id))
        {
            var finals = LifecycleHarness.FinalStates(await h.EventsAsync(group.Key));
            Assert.Equal(group.Count(), finals.Count);
            foreach (var (_, recipient, fate) in group)
            {
                var expected = fate switch
                {
                    "gone" => MessageEventType.Bounced,
                    "never" => MessageEventType.Expired,
                    _ => MessageEventType.Delivered,
                };
                Assert.True(finals.TryGetValue(recipient, out var actual) && actual == expected, $"{recipient}: expected {expected}, got {(finals.TryGetValue(recipient, out var a) ? a.ToString() : "nothing")}{context}");
            }
        }

        // The remote has each delivered recipient exactly once (no connection was cut, so no duplicate is allowed) and no failed one.
        var received = h.Remote.Accepted.Where(m => m.Sender.Length > 0).SelectMany(m => m.Recipients).GroupBy(r => r).ToDictionary(g => g.Key, g => g.Count());
        foreach (var (_, recipient, fate) in plan)
        {
            int times = received.GetValueOrDefault(recipient);
            Assert.True(times == (fate is "gone" or "never" ? 0 : 1), $"{recipient} ({fate}) was accepted {times} times{context}");
        }

        // Every failed recipient appears in exactly one notice, and nothing else is reported.
        foreach (var (_, recipient, fate) in plan)
        {
            int notices = h.Bounces.Count(b => Text(b).Contains($"Final-Recipient: rfc822; {recipient}", StringComparison.Ordinal));
            Assert.True(notices == (fate is "gone" or "never" ? 1 : 0), $"{recipient} ({fate}) is in {notices} notices{context}");
        }

        Assert.Equal(plan.Count(p => p.Fate == "gone"), await h.StatAsync(r => r.HardBounce));
        Assert.Equal(plan.Count(p => p.Fate == "never"), await h.StatAsync(r => r.Expired));
    }
}
