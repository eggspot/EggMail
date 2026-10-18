using Mta.Host.Api;
using Mta.Host.Domains;
using Mta.Policy;
using Mta.Storage;
using Mta.TestSupport;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>
/// Domain re-verification over virtual months with the real <see cref="DomainVerificationService"/> (design section 8): a verified domain is re-checked every 24 hours, a record that goes
/// missing is confirmed after 15 minutes, the domain is then in temporary failure (hourly checks, sending continues) and after 72 hours it is failed and sending is paused; it recovers
/// at the first check that finds the records again. A DNS outage changes nothing. Virtual time jumps from check to check, so the instants are exact, and the number of DNS checks over
/// the whole period is bounded (no re-check storm).
/// </summary>
public class DomainReverificationLifecycleTests
{
    private static readonly TimeSpan Day = TimeSpan.FromDays(1);

    [Fact]
    public async Task Ninety_days_of_failures_and_recoveries_on_sqlite()
    {
        var clock = new VirtualClock();
        await using HostBackend backend = await HostBackend.SqliteAsync(clock);
        await RunAsync(backend, clock);
    }

    [PostgresFact]
    public async Task Ninety_days_of_failures_and_recoveries_on_postgres()
    {
        var clock = new VirtualClock();
        await using HostBackend backend = await HostBackend.PostgresAsync(clock);
        await RunAsync(backend, clock);
    }

    private sealed record Sample(DateTimeOffset At, DomainStatus Status, int Failures, bool Paused, DateTimeOffset? Since, DateTimeOffset? Next);

    private static async Task RunAsync(HostBackend backend, VirtualClock clock)
    {
        DomainHarness h = await DomainHarness.CreateAsync(backend, clock);
        DateTimeOffset start = clock.UtcNow;
        var samples = new List<Sample>();
        DateTimeOffset lastSeen = DateTimeOffset.MinValue;

        // A second domain, added on day 86, whose customer never publishes anything: it stays "verifying" with the documented fast, medium and hourly cadences and is never failed or paused.
        RegisteredDomain? neverPublished = null;
        var neverChecks = new List<DateTimeOffset>();
        DateTimeOffset neverLastSeen = DateTimeOffset.MinValue;

        async Task AfterTick()
        {
            DomainRecord row = await h.DomainAsync();
            if (row.LastCheckedAt is { } at && at != lastSeen)
            {
                lastSeen = at;
                samples.Add(new Sample(at, row.Status, row.ConsecutiveFailures, row.SendingPaused, row.TemporaryFailureSince, row.NextCheckAt));
            }

            DomainRecord? other = neverPublished is null ? null : await h.Config.GetDomainAsync(neverPublished.Domain.Id, default);
            if (other?.LastCheckedAt is { } at2 && at2 != neverLastSeen)
            {
                neverLastSeen = at2;
                neverChecks.Add(at2);
                Assert.Equal(DomainStatus.Verifying, other.Status);
                Assert.False(other.SendingPaused);
            }
        }

        // The customer's actions at virtual days since the start.
        var actions = new SortedList<DateTimeOffset, Func<Task>>
        {
            // Day 0: everything is published at once.
            [start] = async () => await h.PublishAsync(),
            // Day 10: the DKIM record disappears (a zone change gone wrong). Day 17: it is back.
            [start + 10 * Day + TimeSpan.FromHours(3)] = () => { h.Dns.Remove((h.PlanAsync().Result).First(r => r.Purpose == DomainRecordPurpose.Dkim).Host); return Task.CompletedTask; },
            [start + 17 * Day + TimeSpan.FromHours(5)] = async () => await h.PublishAsync(),
            // Day 30: gone again, back after 30 hours: inside the 72 hour grace, so the domain never becomes failed.
            [start + 30 * Day + TimeSpan.FromHours(1)] = () => { h.Dns.Remove((h.PlanAsync().Result).First(r => r.Purpose == DomainRecordPurpose.Dkim).Host); return Task.CompletedTask; },
            [start + 31 * Day + TimeSpan.FromHours(7)] = async () => await h.PublishAsync(),
            // Day 45: a DNS outage of six hours, across the daily check (07:31 by then), changes nothing.
            [start + 45 * Day + TimeSpan.FromHours(6)] = () => { h.Dns.ServerFailure = true; return Task.CompletedTask; },
            [start + 45 * Day + TimeSpan.FromHours(12)] = () => { h.Dns.ServerFailure = false; return Task.CompletedTask; },
            [start + 86 * Day] = async () =>
                neverPublished = await DomainRegistration.RegisterAsync(h.Config, h.Protector, h.Service.Schedule, new DomainRecordOptions { BounceDomain = "bounces.egg.test" }, DomainHarness.TenantId, "never.example", clock.UtcNow, default),
        };

        DateTimeOffset end = start + 90 * Day;
        var pending = new Queue<KeyValuePair<DateTimeOffset, Func<Task>>>(actions);
        int guard = 0;
        while (clock.UtcNow < end)
        {
            Assert.True(++guard < 20_000, "the scheduler is looping");
            IReadOnlyList<DomainRecord> all = await h.Config.GetDomainsAsync(null, default);
            DateTimeOffset nextCheck = all.Where(d => d.NextCheckAt is not null).Min(d => d.NextCheckAt!.Value);
            DateTimeOffset nextAction = pending.Count > 0 ? pending.Peek().Key : DateTimeOffset.MaxValue;
            DateTimeOffset next = nextCheck < nextAction ? nextCheck : nextAction;
            if (next > clock.UtcNow)
            {
                clock.Set(next);
            }

            while (pending.Count > 0 && pending.Peek().Key <= clock.UtcNow)
            {
                await pending.Dequeue().Value();
            }

            await h.TickAsync();
            await AfterTick();
        }

        // --- the first verification
        Sample verified = samples.First(s => s.Status == DomainStatus.Verified);
        Assert.Equal(start + TimeSpan.FromSeconds(90), verified.At);   // the first check is due 90 seconds after the domain was added
        Assert.Equal(0, verified.Failures);

        // A verified domain is checked every 24 hours exactly while nothing is wrong.
        var firstQuiet = samples.TakeWhile(s => s.At < start + 10 * Day).ToList();
        for (int i = 1; i < firstQuiet.Count; i++)
        {
            Assert.Equal(Day, firstQuiet[i].At - firstQuiet[i - 1].At);
        }

        // --- the failure on day 10: confirmed after 15 minutes, temporary failure, failed after 72 hours, sending paused only then
        Sample firstFail = samples.First(s => s.At > start + 10 * Day && s.Failures == 1);
        Assert.Equal(DomainStatus.Verified, firstFail.Status);
        Assert.Equal(firstFail.At + TimeSpan.FromMinutes(15), firstFail.Next);
        Sample temporary = samples.First(s => s.At > firstFail.At && s.Status == DomainStatus.TemporaryFailure);
        Assert.Equal(firstFail.At + TimeSpan.FromMinutes(15), temporary.At);
        Assert.Equal(2, temporary.Failures);
        Assert.Equal(temporary.At, temporary.Since);
        Assert.False(temporary.Paused);   // temporary failure keeps sending
        Assert.True(VerificationSchedule.AllowsSending(temporary.Status, temporary.Paused));
        var duringGrace = samples.Where(s => s.Status == DomainStatus.TemporaryFailure && s.At <= temporary.At + TimeSpan.FromHours(72) && s.At >= temporary.At).ToList();
        Assert.All(duringGrace.Skip(1), s => Assert.False(s.Paused));
        for (int i = 1; i < duringGrace.Count; i++)
        {
            Assert.Equal(TimeSpan.FromHours(1), duringGrace[i].At - duringGrace[i - 1].At);   // hourly while in temporary failure
        }

        Sample failed = samples.First(s => s.Status == DomainStatus.Failed);
        Assert.Equal(temporary.At + TimeSpan.FromHours(72), failed.At);   // not a check earlier, not a check later
        Assert.True(failed.Paused);
        Assert.False(VerificationSchedule.AllowsSending(failed.Status, failed.Paused));
        Assert.Equal(failed.At + Day, failed.Next);   // a failed domain is checked daily

        // --- recovery after the records are back on day 17
        Sample recovered = samples.First(s => s.At > failed.At && s.Status == DomainStatus.Verified);
        Assert.True(recovered.At <= start + 17 * Day + TimeSpan.FromHours(5) + Day, "the first check after the records returned recovers the domain");
        Assert.False(recovered.Paused);
        Assert.Equal(0, recovered.Failures);
        Assert.Null(recovered.Since);
        Assert.Equal(recovered.At + Day, recovered.Next);

        // --- day 30: temporary failure that heals inside the grace: never failed, never paused
        var episode2 = samples.Where(s => s.At > start + 30 * Day && s.At < start + 33 * Day).ToList();
        Assert.Contains(episode2, s => s.Status == DomainStatus.TemporaryFailure);
        Assert.DoesNotContain(episode2, s => s.Status == DomainStatus.Failed || s.Paused);
        Assert.Equal(DomainStatus.Verified, episode2[^1].Status);

        // --- day 45: a DNS outage does not change status, counters or the pause flag
        var outage = samples.Where(s => s.At > start + 45 * Day + TimeSpan.FromHours(6) && s.At < start + 45 * Day + TimeSpan.FromHours(12)).ToList();
        Assert.InRange(outage.Count, 50, 60);   // the daily check at 07:31 and then one every 5 minutes
        Assert.All(outage, s =>
        {
            Assert.Equal(DomainStatus.Verified, s.Status);
            Assert.Equal(0, s.Failures);
            Assert.False(s.Paused);
            Assert.Equal(s.At + TimeSpan.FromMinutes(5), s.Next);   // looked at again in 5 minutes, not sooner
        });
        Assert.Equal(DomainStatus.Verified, samples.Last(x => x.At < start + 46 * Day).Status);

        // --- no storm: the checks of the whole period are bounded by what the schedule allows
        // Verified days: about 1/day. Episode 1: 1 + 1 + 72 hourly + the failed phase (daily) + recovery. Episode 2: a handful. Outage: 6 h / 5 min = 72.
        // The never-verified domain is bounded separately below.
        int checksOfMainDomain = samples.Count;
        Assert.InRange(checksOfMainDomain, 85, 90 + 2 + 76 + 10 + 40 + 80);

        // --- the domain nobody publishes for: 10 checks at 90 s, then every 15 minutes through the first day, then hourly; never failed
        Assert.NotNull(neverPublished);
        DateTimeOffset created = neverPublished.Domain.CreatedAt;
        var fast = neverChecks.Where(t => t - created <= TimeSpan.FromMinutes(15)).ToList();
        Assert.Equal(10, fast.Count);
        var medium = neverChecks.Where(t => t - created > TimeSpan.FromMinutes(15) && t - created <= TimeSpan.FromMinutes(15) + Day).ToList();
        Assert.InRange(medium.Count, 95, 97);
        var slow = neverChecks.Where(t => t - created > TimeSpan.FromMinutes(15) + Day + TimeSpan.FromMinutes(15)).ToList();
        for (int i = 1; i < slow.Count; i++)
        {
            Assert.Equal(TimeSpan.FromHours(1), slow[i] - slow[i - 1]);
        }

        Assert.InRange(neverChecks.Count, 10 + 95 + 68, 10 + 97 + 74);
    }
}
