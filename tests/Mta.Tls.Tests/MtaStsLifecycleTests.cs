using Mta.Tls.MtaSts;
using Mta.Tls.Tests.Support;
using Mta.TestSupport;

namespace Mta.Tls.Tests;

/// <summary>
/// The MTA-STS policy cache over virtual months (RFC 8461): a fetched policy applies until its <c>max_age</c> and not a second longer, also when the policy host or the TXT record is gone; it is
/// revalidated daily, immediately when the TXT <c>id</c> changes; failures are not retried in a storm; and with thousands of domains the cache stays within its size, never serves a policy that
/// has expired, and drops expired entries.
/// </summary>
public class MtaStsLifecycleTests
{
    private const string Domain = "example.com";
    private const string TxtName = "_mta-sts.example.com";

    private static string Body(string mode = "enforce", long maxAge = 86400, string mx = "mail.example.com") =>
        $"version: STSv1\nmode: {mode}\nmx: {mx}\nmax_age: {maxAge}\n";

    [Fact]
    public async Task A_policy_applies_for_exactly_its_max_age_when_the_policy_host_goes_away_and_is_revalidated_daily_while_it_stays()
    {
        var clock = new TestClock(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var dns = new ScriptedDnsResolver();
        var fetcher = new FakePolicyFetcher();
        var cache = new InMemoryMtaStsCache(clock);
        var store = new MtaStsPolicyStore(dns, fetcher, cache, clock);
        TimeSpan maxAge = TimeSpan.FromDays(30);
        dns.SetTxt(TxtName, "v=STSv1; id=v1");
        fetcher.OnFetch = _ => FakePolicyFetcher.Ok(Body(maxAge: (long)maxAge.TotalSeconds));

        // 60 days with a lookup every hour (a busy destination) while the policy host keeps answering: one fetch a day, never one per lookup, and a policy at every lookup.
        int hours = 60 * 24;
        for (int h = 0; h < hours; h++)
        {
            MtaStsLookupResult r = await store.GetPolicyAsync(Domain);
            Assert.True(r.HasActivePolicy);
            Assert.Equal(MtaStsMode.Enforce, r.Policy!.Mode);
            clock.Advance(TimeSpan.FromHours(1));
        }

        Assert.InRange(fetcher.Calls, 60, 61);   // the policy is revalidated after 24 hours (RevalidateAfter), not at every lookup

        // The policy host stops answering for good (the domain moved its web server) and the TXT record stays. The last good fetch was at most a day ago; the policy goes on applying until
        // its max_age since that fetch and then there is none. The cached enforce policy is not downgraded earlier.
        fetcher.OnFetch = _ => new MtaStsFetchResult(null, MtaStsFetchFailure.ConnectionFailed, "gone");
        MtaStsCacheEntry entry = (await cache.GetAsync(Domain))!;
        DateTimeOffset expiresAt = entry.ExpiresAt;
        Assert.Equal(entry.FetchedAt + maxAge, expiresAt);
        foreach (int daysLater in new[] { 1, 10, 25 })
        {
            clock.Set(entry.FetchedAt + TimeSpan.FromDays(daysLater));
            MtaStsLookupResult stillThere = await store.GetPolicyAsync(Domain);
            Assert.Equal(MtaStsPolicySource.Cache, stillThere.Source);
            Assert.Equal(MtaStsMode.Enforce, stillThere.Policy!.Mode);
            Assert.Equal(TlsResultType.StsPolicyFetchError, stillThere.Failure);   // the failure is reported, the policy still applies
        }

        clock.Set(expiresAt - TimeSpan.FromSeconds(1));
        Assert.Equal(MtaStsPolicySource.Cache, (await store.GetPolicyAsync(Domain)).Source);   // the last second
        clock.Set(expiresAt);
        MtaStsLookupResult gone = await store.GetPolicyAsync(Domain);
        Assert.Equal(MtaStsPolicySource.None, gone.Source);   // exactly at max_age
        Assert.Null(gone.Policy);
        Assert.Null(await cache.GetAsync(Domain));            // and it is removed
    }

    [Fact]
    public async Task A_changed_txt_id_refetches_at_once_and_a_vanished_txt_keeps_the_cached_policy_until_it_expires()
    {
        var clock = new TestClock(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var dns = new ScriptedDnsResolver();
        var fetcher = new FakePolicyFetcher();
        var store = new MtaStsPolicyStore(dns, fetcher, new InMemoryMtaStsCache(clock), clock);
        dns.SetTxt(TxtName, "v=STSv1; id=v1");
        fetcher.OnFetch = _ => FakePolicyFetcher.Ok(Body(mx: "mail.example.com", maxAge: 7 * 86400));
        await store.GetPolicyAsync(Domain);

        // Every few days the domain publishes a new policy and a new id; the new mx list applies at the very next lookup, not at the next daily revalidation.
        for (int version = 2; version <= 20; version++)
        {
            clock.Advance(TimeSpan.FromHours(7 + version));
            string mx = $"mx{version}.example.com";
            dns.SetTxt(TxtName, $"v=STSv1; id=v{version}");
            fetcher.OnFetch = _ => FakePolicyFetcher.Ok(Body(mx: mx, maxAge: 7 * 86400));
            MtaStsLookupResult r = await store.GetPolicyAsync(Domain);
            Assert.Equal(MtaStsPolicySource.Fetched, r.Source);
            Assert.Equal($"v{version}", r.PolicyId);
            Assert.Equal([mx], r.Policy!.MxPatterns);
        }

        // The TXT record disappears (a DNS change gone wrong): the cached policy still protects mail for its max_age, counted from the last fetch (which was at the last id change).
        dns.Remove(TxtName, Mta.Dns.DnsRecordType.TXT);
        int fetchesBefore = fetcher.Calls;
        DateTimeOffset lastFetch = clock.UtcNow;
        for (int day = 1; day <= 6; day++)
        {
            clock.Advance(TimeSpan.FromDays(1) - TimeSpan.FromSeconds(day == 6 ? 1 : 0));   // 6 days less one second at the end
            Assert.Equal(MtaStsPolicySource.Cache, (await store.GetPolicyAsync(Domain)).Source);
        }

        clock.Set(lastFetch + TimeSpan.FromDays(7) - TimeSpan.FromSeconds(1));
        Assert.Equal(MtaStsPolicySource.Cache, (await store.GetPolicyAsync(Domain)).Source);
        clock.Set(lastFetch + TimeSpan.FromDays(7));
        Assert.Equal(MtaStsPolicySource.None, (await store.GetPolicyAsync(Domain)).Source);
        Assert.Equal(fetchesBefore, fetcher.Calls);   // nothing was fetched without a TXT record
    }

    [Fact]
    public async Task A_failing_policy_host_is_not_hammered_and_a_policy_with_max_age_zero_removes_the_cache()
    {
        var clock = new TestClock(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var dns = new ScriptedDnsResolver();
        var fetcher = new FakePolicyFetcher { OnFetch = _ => new MtaStsFetchResult(null, MtaStsFetchFailure.HttpStatus, "503") };
        var cache = new InMemoryMtaStsCache(clock);
        var store = new MtaStsPolicyStore(dns, fetcher, cache, clock);
        dns.SetTxt(TxtName, "v=STSv1; id=v1");

        // Mail for the domain is sent every minute for two days while its policy host answers 503: the policy host is asked at most once per backoff (5 minutes).
        for (int minute = 0; minute < 2 * 24 * 60; minute++)
        {
            Assert.False((await store.GetPolicyAsync(Domain)).HasActivePolicy);
            clock.Advance(TimeSpan.FromMinutes(1));
        }

        Assert.InRange(fetcher.Calls, 2 * 24 * 60 / 5 - 2, 2 * 24 * 60 / 5 + 2);

        // It recovers with a policy of max_age 0 ("forget the policy"): there is no cache entry afterwards, whatever there was.
        clock.Advance(TimeSpan.FromMinutes(6));
        fetcher.OnFetch = _ => FakePolicyFetcher.Ok(Body(mode: "none", maxAge: 0));
        MtaStsLookupResult none = await store.GetPolicyAsync(Domain);
        Assert.False(none.HasActivePolicy);
        Assert.Null(await cache.GetAsync(Domain));
    }

    [Fact]
    public async Task Thousands_of_domains_over_a_virtual_month_never_exceed_the_cache_size_or_serve_an_expired_policy()
    {
        int seed = Accelerated.Seed(8461);
        var random = new Random(seed);
        var clock = new TestClock(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var dns = new ScriptedDnsResolver();
        var fetcher = new FakePolicyFetcher();
        int capacity = 500;
        var cache = new InMemoryMtaStsCache(clock, capacity);
        var store = new MtaStsPolicyStore(dns, fetcher, cache, clock);

        int domains = 2000;
        long[] maxAges = [3600, 86_400, 7 * 86_400, 30 * 86_400];
        long MaxAgeOf(int d) => maxAges[d % maxAges.Length];
        for (int d = 0; d < domains; d++)
        {
            dns.SetTxt($"_mta-sts.d{d}.example", "v=STSv1; id=v1");
        }

        var fetchedAt = new Dictionary<int, DateTimeOffset>();
        fetcher.OnFetch = name =>
        {
            int d = int.Parse(name[1..name.IndexOf('.')]);
            fetchedAt[d] = clock.UtcNow;
            return FakePolicyFetcher.Ok(Body(maxAge: MaxAgeOf(d), mx: $"mail.d{d}.example"));
        };

        long cacheHits = 0, lookups = 0;
        int steps = Accelerated.Scaled(24 * 30);   // an hour at a time for 30 days
        for (int step = 0; step < steps; step++)
        {
            clock.Advance(TimeSpan.FromHours(1));
            for (int n = 0; n < 40; n++)
            {
                int d = random.NextDouble() < 0.5 ? random.Next(0, 100) : random.Next(0, domains);
                MtaStsLookupResult r = await store.GetPolicyAsync($"d{d}.example");
                lookups++;
                Assert.True(r.HasActivePolicy);
                Assert.Equal([$"mail.d{d}.example"], r.Policy!.MxPatterns);
                if (r.Source == MtaStsPolicySource.Cache)
                {
                    cacheHits++;
                    Assert.True(clock.UtcNow < fetchedAt[d] + TimeSpan.FromSeconds(MaxAgeOf(d)), $"domain {d}: a policy past its max_age was served from the cache (seed {seed})");
                    Assert.True(clock.UtcNow - fetchedAt[d] < TimeSpan.FromHours(24) + TimeSpan.FromSeconds(1), "a cached policy older than the revalidation interval was served");
                }
            }

            Assert.True(cache.Count <= capacity + 1, $"the cache holds {cache.Count} policies (limit {capacity})");
        }

        Assert.True(cacheHits > lookups / 10, $"the cache was used: {cacheHits} hits of {lookups}");

        // After a long quiet time everything has expired; the next lookups find room by dropping what expired, and the size stays within the limit.
        clock.Advance(TimeSpan.FromDays(60));
        for (int d = 0; d < domains; d++)
        {
            await store.GetPolicyAsync($"d{d}.example");
            Assert.True(cache.Count <= capacity + 1);
        }
    }
}
