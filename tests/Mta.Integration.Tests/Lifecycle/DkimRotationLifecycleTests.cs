using Mta.Dkim;
using Mta.Host.Api;
using Mta.Host.Domains;
using Mta.Storage;
using Mta.TestSupport;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>
/// DKIM key rotation over a virtual year with the real verification service, signer provider and storage (design section 8: publish N+1, verify, switch, keep N published for the
/// retirement grace). The test plays the customer: it publishes the records the dashboard lists and removes the ones that are no longer listed. Invariants at every step: exactly one
/// key is active, the signer is that key, and mail signed right now verifies against the DNS as it is right now (so the new key never signs before its record is published and the
/// old record is never taken away while mail signed with it can still be in flight).
/// </summary>
public class DkimRotationLifecycleTests
{
    private static readonly TimeSpan Step = TimeSpan.FromHours(12);

    [Fact]
    public async Task A_year_of_rotations_on_sqlite_keeps_signing_valid_and_overlaps_selectors()
    {
        var clock = new VirtualClock();
        await using HostBackend backend = await HostBackend.SqliteAsync(clock);
        await RunAsync(backend, clock);
    }

    [PostgresFact]
    public async Task A_year_of_rotations_on_postgres_keeps_signing_valid_and_overlaps_selectors()
    {
        var clock = new VirtualClock();
        await using HostBackend backend = await HostBackend.PostgresAsync(clock);
        await RunAsync(backend, clock);
    }

    private static async Task RunAsync(HostBackend backend, VirtualClock clock)
    {
        int seed = Accelerated.Seed(20261012);
        var random = new Random(seed);
        int rotations = Accelerated.Scaled(4);
        TimeSpan spacing = TimeSpan.FromDays(365.0 / rotations);
        var api = new ApiOptions { VerificationPollInterval = TimeSpan.FromHours(1) };
        TimeSpan grace = api.DkimRetirementGrace;
        Assert.True(spacing > grace + TimeSpan.FromDays(5), "the rotations must not overlap each other for this scenario (seed " + seed + ")");

        DomainHarness h = await DomainHarness.CreateAsync(backend, clock, api);
        var everPublished = new HashSet<string>(StringComparer.Ordinal);

        async Task PublishAndRemember(string? onlySelector = null)
        {
            await h.PublishAsync(onlySelector: onlySelector);
            foreach (var r in await h.PlanAsync())
            {
                if (r.Purpose == DomainRecordPurpose.Dkim)
                {
                    everPublished.Add(r.Host);
                }
            }
        }

        // The first key: registered active, the customer publishes the plan, the domain verifies.
        await PublishAndRemember();
        Assert.NotNull(await h.SignAsync("at-registration"));   // the first key is active from registration on
        await h.AdvanceAsync(TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(1));
        Assert.Equal(DomainStatus.Verified, (await h.DomainAsync()).Status);

        long checksBeforeYear = h.Checks;
        DateTimeOffset yearStart = clock.UtcNow;
        int switches = 0;
        DateTimeOffset? lastSwitch = null;

        async Task Invariants()
        {
            var keys = await h.KeysAsync();
            Assert.Single(keys, k => k.Active);
            Assert.True(h.Service.PublishedKeys(keys, clock.UtcNow).Count <= 3);
            byte[]? mail = await h.SignAsync("tick");
            Assert.NotNull(mail);
            Assert.Equal(DkimStatus.Pass, await h.VerifyAsync(mail!));
            DkimSigner signer = (await h.Signers.GetSignerAsync(DomainHarness.DomainName, default))!;
            Assert.Equal(keys.Single(k => k.Active).Selector, signer.Selector);
        }

        for (int i = 0; i < rotations; i++)
        {
            // Quiet time until the next rotation, with the daily verification check running.
            DateTimeOffset rotateAt = yearStart + spacing * (i + 1) - spacing / 2 + TimeSpan.FromHours(random.Next(0, 24));
            await h.AdvanceAsync(rotateAt - clock.UtcNow, Step, Invariants);

            // Rotation (the steps of POST /domains/{id}/dkim/rotate).
            var keysBefore = await h.KeysAsync();
            Mta.Storage.DkimKeyRecord old = keysBefore.Single(k => k.Active);
            Assert.DoesNotContain(keysBefore, k => !k.Active && k.RetiredAt is null);
            Mta.Storage.DkimKeyRecord pending = await DomainVerificationService.CreateKeyAsync(h.DomainId, DomainVerificationService.NextSelector(keysBefore, clock.UtcNow), h.Protector, clock.UtcNow, active: false);
            await h.Config.AddDkimKeyAsync(pending, default);
            DomainRecord row = await h.DomainAsync();
            await h.Config.UpsertDomainAsync(row with { NextCheckAt = h.Service.Schedule.FirstCheckAt(clock.UtcNow) }, default);

            // The new record is advice only until it is published: a check finds it missing and must change nothing. A DNS outage and a wrong value at the new
            // selector are no reason to switch either.
            byte[] signedBeforeSwitch = (await h.SignAsync("before-switch-" + i))!;
            await h.AdvanceAsync(TimeSpan.FromHours(6), TimeSpan.FromMinutes(30), async () =>
            {
                Assert.Equal(old.Selector, (await h.Signers.GetSignerAsync(DomainHarness.DomainName, default))!.Selector);
                Assert.Single(await h.KeysAsync(), k => k.Active && k.Id == old.Id);
            });
            h.Dns.ServerFailure = true;
            await h.AdvanceAsync(TimeSpan.FromHours(30), TimeSpan.FromHours(1));
            h.Dns.ServerFailure = false;
            Assert.Equal(old.Id, (await h.KeysAsync()).Single(k => k.Active).Id);

            string pendingHost = (await h.PlanAsync()).Single(r => r.Purpose == DomainRecordPurpose.Dkim && r.Host.StartsWith(pending.Selector + ".", StringComparison.Ordinal)).Host;
            using (var other = DkimKeyTools.GenerateRsa2048())
            {
                h.Dns.SetTxt(pendingHost, "v=DKIM1; k=rsa; p=" + DkimKeyTools.ExportPublicKeyBase64(other));
            }

            await h.AdvanceAsync(TimeSpan.FromDays(2), TimeSpan.FromHours(6));
            Assert.Equal(old.Id, (await h.KeysAsync()).Single(k => k.Active).Id);
            h.Dns.Remove(pendingHost);

            // Rotation while mail is being signed: the customer publishes the new record, and signing runs concurrently with the check that switches. Every message
            // verifies, whichever key signed it.
            await PublishAndRemember();
            DateTimeOffset publishedAt = clock.UtcNow;
            var signing = Task.Run(async () =>
            {
                for (int n = 0; n < 60; n++)
                {
                    byte[] mail = (await h.SignAsync("race-" + i + "-" + n))!;
                    Assert.Equal(DkimStatus.Pass, await h.VerifyAsync(mail));
                }
            });
            DateTimeOffset switchedAt = DateTimeOffset.MinValue;
            await h.AdvanceAsync(TimeSpan.FromDays(2), TimeSpan.FromHours(1), async () =>
            {
                if (switchedAt == DateTimeOffset.MinValue && (await h.KeysAsync()).Single(k => k.Active).Id == pending.Id)
                {
                    switchedAt = clock.UtcNow;
                }
            });
            await signing;
            Assert.NotEqual(DateTimeOffset.MinValue, switchedAt);
            switches++;
            lastSwitch = switchedAt;

            // The switch happens at the first check after the record is published, at the latest one verified-domain interval later.
            Assert.True(switchedAt - publishedAt <= TimeSpan.FromHours(25), $"switched {switchedAt - publishedAt} after the record was published");

            var keysAfter = await h.KeysAsync();
            Mta.Storage.DkimKeyRecord retired = keysAfter.Single(k => k.Id == old.Id);
            Assert.False(retired.Active);
            Assert.Equal(switchedAt, retired.RetiredAt);
            Assert.True(keysAfter.Single(k => k.Id == pending.Id).Active);
            Assert.Null(keysAfter.Single(k => k.Id == pending.Id).RetiredAt);

            // Mail signed before the switch still verifies for the whole grace (the retired record stays listed and published), and the old selector is not listed one
            // moment longer than the grace.
            string oldHost = (await h.PlanAsync()).Single(r => r.Host.StartsWith(old.Selector + ".", StringComparison.Ordinal)).Host;
            Assert.Equal(DkimStatus.Pass, await h.VerifyAsync(signedBeforeSwitch));
            if (i == 0)
            {
                // A restart in the middle of the grace changes nothing.
                await backend.RestartAsync();
                h.Rebind();
            }

            DateTimeOffset graceEnd = switchedAt + grace;
            await h.AdvanceAsync(graceEnd - clock.UtcNow - TimeSpan.FromMinutes(1), Step, async () =>
            {
                Assert.Contains(await h.PlanAsync(), r => r.Host == oldHost);
                Assert.Equal(DkimStatus.Pass, await h.VerifyAsync(signedBeforeSwitch));
                await Invariants();
            });
            Assert.Contains(await h.PlanAsync(), r => r.Host == oldHost);
            clock.Advance(TimeSpan.FromMinutes(1));   // exactly the end of the grace
            Assert.DoesNotContain(await h.PlanAsync(), r => r.Host == oldHost);
            await h.RemoveUnlistedDkimAsync(everPublished);
            await h.TickAsync();
            Assert.NotEqual(DkimStatus.Pass, await h.VerifyAsync(signedBeforeSwitch));
            Assert.Equal(DomainStatus.Verified, (await h.DomainAsync()).Status);
            Assert.False((await h.DomainAsync()).SendingPaused);
        }

        await h.AdvanceAsync(yearStart + TimeSpan.FromDays(365) - clock.UtcNow, Step, Invariants);

        Assert.Equal(rotations, switches);
        Assert.NotNull(lastSwitch);
        var finalKeys = await h.KeysAsync();
        Assert.Equal(rotations + 1, finalKeys.Count);
        Assert.Equal(rotations + 1, finalKeys.Select(k => k.Selector).Distinct(StringComparer.OrdinalIgnoreCase).Count());   // selector names are never reused
        Assert.Single(finalKeys, k => k.Active);
        Assert.Equal(rotations, finalKeys.Count(k => k.RetiredAt is not null));
        // Nothing in the plan after the last grace but the active key, and the scheduler checked the domain about once a day (not in a storm).
        Assert.Single(await h.PlanAsync(), r => r.Purpose == DomainRecordPurpose.Dkim);
        long checksInYear = h.Checks - checksBeforeYear;
        Assert.InRange(checksInYear, 300, 365 + rotations * 100);
    }
}
