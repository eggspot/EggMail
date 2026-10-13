using Mta.Dns;
using Mta.Tls.MtaSts;
using Mta.Tls.Tests.Support;

namespace Mta.Tls.Tests;

public class MtaStsPolicyStoreTests
{
    private const string Domain = "example.com";
    private const string TxtName = "_mta-sts.example.com";

    private static string Body(string mode = "enforce", int maxAge = 86400, string mx = "mail.example.com") =>
        $"version: STSv1\nmode: {mode}\nmx: {mx}\nmax_age: {maxAge}\n";

    private sealed class Rig
    {
        public TestClock Clock { get; } = new();
        public ScriptedDnsResolver Dns { get; } = new();
        public FakePolicyFetcher Fetcher { get; } = new();
        public InMemoryMtaStsCache Cache { get; }
        public MtaStsPolicyStore Store { get; }

        public Rig(MtaStsStoreOptions? options = null)
        {
            Cache = new InMemoryMtaStsCache(Clock);
            Store = new MtaStsPolicyStore(Dns, Fetcher, Cache, Clock, options);
        }

        public void Txt(string id) => Dns.SetTxt(TxtName, $"v=STSv1; id={id}");

        public void Serve(string body) => Fetcher.OnFetch = _ => FakePolicyFetcher.Ok(body);

        public void FailFetch(MtaStsFetchFailure failure = MtaStsFetchFailure.HttpStatus) =>
            Fetcher.OnFetch = _ => new MtaStsFetchResult(null, failure, "boom");
    }

    [Fact]
    public async Task No_txt_record_means_no_policy_and_no_fetch()
    {
        var rig = new Rig();
        var result = await rig.Store.GetPolicyAsync(Domain);

        Assert.Equal(MtaStsPolicySource.None, result.Source);
        Assert.Null(result.Policy);
        Assert.False(result.HasActivePolicy);
        Assert.Equal(0, rig.Fetcher.Calls);
    }

    [Fact]
    public async Task Fetches_and_caches_when_txt_is_present()
    {
        var rig = new Rig();
        rig.Txt("v1");
        rig.Serve(Body());

        var first = await rig.Store.GetPolicyAsync(Domain);
        var second = await rig.Store.GetPolicyAsync(Domain);

        Assert.Equal(MtaStsPolicySource.Fetched, first.Source);
        Assert.Equal(MtaStsPolicySource.Cache, second.Source);
        Assert.Equal("v1", second.PolicyId);
        Assert.True(first.HasActivePolicy);
        Assert.Equal(1, rig.Fetcher.Calls);
        var entry = await rig.Cache.GetAsync(Domain);
        Assert.Equal(rig.Clock.UtcNow.AddSeconds(86400), entry!.ExpiresAt);
    }

    [Fact]
    public async Task A_changed_txt_id_triggers_a_refetch()
    {
        var rig = new Rig();
        rig.Txt("v1");
        rig.Serve(Body(mx: "mail.example.com"));
        await rig.Store.GetPolicyAsync(Domain);

        rig.Txt("v2");
        rig.Serve(Body(mx: "new.example.com"));
        var result = await rig.Store.GetPolicyAsync(Domain);

        Assert.Equal(MtaStsPolicySource.Fetched, result.Source);
        Assert.Equal("v2", result.PolicyId);
        Assert.Equal(["new.example.com"], result.Policy!.MxPatterns);
        Assert.Equal(2, rig.Fetcher.Calls);
    }

    [Fact]
    public async Task Fetch_failure_keeps_the_cached_policy_and_reports_the_error()
    {
        var rig = new Rig();
        rig.Txt("v1");
        rig.Serve(Body());
        await rig.Store.GetPolicyAsync(Domain);

        rig.Txt("v2");
        rig.FailFetch();
        var result = await rig.Store.GetPolicyAsync(Domain);

        Assert.Equal(MtaStsPolicySource.Cache, result.Source);
        Assert.Equal("v1", result.PolicyId);
        Assert.Equal(MtaStsMode.Enforce, result.Policy!.Mode);
        Assert.Equal(TlsResultType.StsPolicyFetchError, result.Failure);
    }

    [Fact]
    public async Task Disappearing_txt_does_not_downgrade_a_cached_enforce_policy()
    {
        var rig = new Rig();
        rig.Txt("v1");
        rig.Serve(Body());
        await rig.Store.GetPolicyAsync(Domain);

        rig.Dns.Remove(TxtName, DnsRecordType.TXT); // NXDOMAIN now
        rig.Clock.Advance(TimeSpan.FromHours(2));
        var result = await rig.Store.GetPolicyAsync(Domain);

        Assert.Equal(MtaStsPolicySource.Cache, result.Source);
        Assert.Equal(MtaStsMode.Enforce, result.Policy!.Mode);
        Assert.Equal(1, rig.Fetcher.Calls);
    }

    [Theory]
    [InlineData("servfail")]
    [InlineData("exception")]
    [InlineData("garbage")]
    [InlineData("duplicate")]
    public async Task Dns_trouble_does_not_downgrade_a_cached_enforce_policy(string trouble)
    {
        var rig = new Rig();
        rig.Txt("v1");
        rig.Serve(Body());
        await rig.Store.GetPolicyAsync(Domain);

        switch (trouble)
        {
            case "servfail":
                rig.Dns.Set(TxtName, DnsRecordType.TXT, new DnsResponse { Rcode = DnsRcode.ServerFailure });
                break;
            case "exception":
                rig.Dns.Set(TxtName, DnsRecordType.TXT, () => throw new DnsException("timeout"));
                break;
            case "garbage":
                rig.Dns.SetTxt(TxtName, "v=STSv1; id=not valid!");
                break;
            default:
                rig.Dns.SetTxt(TxtName, "v=STSv1; id=a", "v=STSv1; id=b");
                break;
        }

        var result = await rig.Store.GetPolicyAsync(Domain);
        Assert.Equal(MtaStsPolicySource.Cache, result.Source);
        Assert.Equal(MtaStsMode.Enforce, result.Policy!.Mode);
    }

    [Fact]
    public async Task Cached_policy_expires_after_max_age_and_then_dns_absence_means_no_policy()
    {
        var rig = new Rig();
        rig.Txt("v1");
        rig.Serve(Body(maxAge: 3600));
        await rig.Store.GetPolicyAsync(Domain);

        rig.Dns.Remove(TxtName, DnsRecordType.TXT);
        rig.Clock.Advance(TimeSpan.FromSeconds(3599));
        Assert.Equal(MtaStsPolicySource.Cache, (await rig.Store.GetPolicyAsync(Domain)).Source);

        rig.Clock.Advance(TimeSpan.FromSeconds(2));
        var result = await rig.Store.GetPolicyAsync(Domain);
        Assert.Equal(MtaStsPolicySource.None, result.Source);
        Assert.Null(await rig.Cache.GetAsync(Domain));
    }

    [Fact]
    public async Task Fetch_failure_with_nothing_cached_yields_no_policy_with_the_failure_for_reporting()
    {
        var rig = new Rig();
        rig.Txt("v1");
        rig.FailFetch(MtaStsFetchFailure.TlsValidationFailed);
        var result = await rig.Store.GetPolicyAsync(Domain);

        Assert.Equal(MtaStsPolicySource.None, result.Source);
        Assert.Null(result.Policy);
        Assert.Equal(TlsResultType.StsWebpkiInvalid, result.Failure);
    }

    [Fact]
    public async Task Failed_fetches_back_off_and_then_retry()
    {
        var rig = new Rig(new MtaStsStoreOptions { FailureBackoff = TimeSpan.FromMinutes(5) });
        rig.Txt("v1");
        rig.FailFetch();

        await rig.Store.GetPolicyAsync(Domain);
        await rig.Store.GetPolicyAsync(Domain);
        Assert.Equal(1, rig.Fetcher.Calls);

        rig.Clock.Advance(TimeSpan.FromMinutes(6));
        rig.Serve(Body());
        var result = await rig.Store.GetPolicyAsync(Domain);
        Assert.Equal(2, rig.Fetcher.Calls);
        Assert.Equal(MtaStsPolicySource.Fetched, result.Source);
    }

    [Fact]
    public async Task Unchanged_id_is_revalidated_after_the_revalidate_interval_and_extends_the_lifetime()
    {
        var rig = new Rig(new MtaStsStoreOptions { RevalidateAfter = TimeSpan.FromHours(24) });
        rig.Txt("v1");
        rig.Serve(Body(maxAge: 7 * 86400));
        await rig.Store.GetPolicyAsync(Domain);

        rig.Clock.Advance(TimeSpan.FromHours(23));
        await rig.Store.GetPolicyAsync(Domain);
        Assert.Equal(1, rig.Fetcher.Calls);

        rig.Clock.Advance(TimeSpan.FromHours(2));
        var result = await rig.Store.GetPolicyAsync(Domain);
        Assert.Equal(2, rig.Fetcher.Calls);
        Assert.Equal(MtaStsPolicySource.Fetched, result.Source);
        var entry = await rig.Cache.GetAsync(Domain);
        Assert.Equal(rig.Clock.UtcNow.AddDays(7), entry!.ExpiresAt);
    }

    [Fact]
    public async Task Failed_revalidation_keeps_the_policy()
    {
        var rig = new Rig();
        rig.Txt("v1");
        rig.Serve(Body(maxAge: 7 * 86400));
        await rig.Store.GetPolicyAsync(Domain);

        rig.Clock.Advance(TimeSpan.FromHours(25));
        rig.FailFetch();
        var result = await rig.Store.GetPolicyAsync(Domain);
        Assert.Equal(MtaStsPolicySource.Cache, result.Source);
        Assert.Equal(TlsResultType.StsPolicyFetchError, result.Failure);
    }

    [Fact]
    public async Task Mode_none_policy_replaces_an_enforce_policy_when_the_id_changes()
    {
        var rig = new Rig();
        rig.Txt("v1");
        rig.Serve(Body());
        await rig.Store.GetPolicyAsync(Domain);

        rig.Txt("v2");
        rig.Serve("version: STSv1\nmode: none\nmax_age: 86400\n");
        var result = await rig.Store.GetPolicyAsync(Domain);

        Assert.Equal(MtaStsMode.None, result.Policy!.Mode);
        Assert.False(result.HasActivePolicy);
    }

    [Fact]
    public async Task Max_age_zero_policy_is_not_cached()
    {
        var rig = new Rig();
        rig.Txt("v1");
        rig.Serve(Body(maxAge: 0));
        var result = await rig.Store.GetPolicyAsync(Domain);

        Assert.Equal(MtaStsPolicySource.Fetched, result.Source);
        Assert.Null(await rig.Cache.GetAsync(Domain));
    }

    [Fact]
    public async Task Invalid_domain_is_no_policy_without_dns()
    {
        var rig = new Rig();
        var result = await rig.Store.GetPolicyAsync("not a domain");
        Assert.Equal(MtaStsPolicySource.None, result.Source);
        Assert.Equal(0, rig.Dns.Queries);
    }

    [Fact]
    public async Task Domain_names_are_normalised()
    {
        var rig = new Rig();
        rig.Txt("v1");
        rig.Serve(Body());
        await rig.Store.GetPolicyAsync("EXAMPLE.com.");
        Assert.NotNull(await rig.Cache.GetAsync(Domain));
    }

    [Fact]
    public async Task Concurrent_lookups_share_one_fetch()
    {
        var rig = new Rig();
        rig.Txt("v1");
        var gate = new TaskCompletionSource();
        var entered = new TaskCompletionSource();
        int calls = 0;
        var parsed = FakePolicyFetcher.Ok(Body());
        var slow = new SlowFetcher(async () =>
        {
            Interlocked.Increment(ref calls);
            entered.TrySetResult();
            await gate.Task;
            return parsed;
        });
        var store = new MtaStsPolicyStore(rig.Dns, slow, new InMemoryMtaStsCache(rig.Clock), rig.Clock);

        var tasks = Enumerable.Range(0, 10).Select(_ => store.GetPolicyAsync(Domain).AsTask()).ToArray();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(60));   // the one shared fetch is under way and holds the gate
        gate.SetResult();
        var results = await Task.WhenAll(tasks);

        Assert.Equal(1, calls);
        Assert.All(results, r => Assert.NotNull(r.Policy));
    }

    [Fact]
    public async Task A_cancelled_caller_does_not_poison_later_lookups()
    {
        var rig = new Rig();
        rig.Txt("v1");
        var gate = new TaskCompletionSource();
        var parsed = FakePolicyFetcher.Ok(Body());
        var entered = new TaskCompletionSource();
        var slow = new SlowFetcher(async () =>
        {
            entered.TrySetResult();
            await gate.Task;
            return parsed;
        });
        var store = new MtaStsPolicyStore(rig.Dns, slow, new InMemoryMtaStsCache(rig.Clock), rig.Clock);

        using var cts = new CancellationTokenSource();
        var cancelled = store.GetPolicyAsync(Domain, cts.Token).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(60));
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);

        gate.SetResult();
        var result = await store.GetPolicyAsync(Domain);
        Assert.NotNull(result.Policy);
    }

    [Fact]
    public async Task In_memory_cache_is_bounded_and_evicts_expired_then_oldest()
    {
        var clock = new TestClock();
        var cache = new InMemoryMtaStsCache(clock, maxEntries: 3);
        var policy = FakePolicyFetcher.Ok(Body()).Policy!;

        async Task Add(string d, TimeSpan age, TimeSpan ttl) =>
            await cache.SetAsync(new MtaStsCacheEntry(d, "i", policy, clock.UtcNow - age, clock.UtcNow - age + ttl));

        await Add("a.example", TimeSpan.FromHours(3), TimeSpan.FromHours(1)); // expired
        await Add("b.example", TimeSpan.FromHours(2), TimeSpan.FromDays(1));
        await Add("c.example", TimeSpan.FromHours(1), TimeSpan.FromDays(1));
        await Add("d.example", TimeSpan.Zero, TimeSpan.FromDays(1));
        Assert.Equal(3, cache.Count);
        Assert.Null(await cache.GetAsync("a.example"));

        await Add("e.example", TimeSpan.Zero, TimeSpan.FromDays(1));
        Assert.Equal(3, cache.Count);
        Assert.Null(await cache.GetAsync("b.example")); // oldest fetch evicted
        Assert.NotNull(await cache.GetAsync("e.example"));

        await cache.RemoveAsync("e.example");
        Assert.Null(await cache.GetAsync("e.example"));
        Assert.Throws<ArgumentOutOfRangeException>(() => new InMemoryMtaStsCache(clock, 0));
    }

    [Fact]
    public async Task Custom_cache_implementations_are_used()
    {
        var rig = new Rig();
        var spy = new SpyCache();
        var store = new MtaStsPolicyStore(rig.Dns, rig.Fetcher, spy, rig.Clock);
        rig.Txt("v1");
        rig.Serve(Body());
        await store.GetPolicyAsync(Domain);
        Assert.Equal(1, spy.Sets);
    }

    private sealed class SlowFetcher(Func<Task<MtaStsFetchResult>> work) : IMtaStsPolicyFetcher
    {
        public async ValueTask<MtaStsFetchResult> FetchAsync(string domain, CancellationToken cancellationToken = default) => await work();
    }

    private sealed class SpyCache : IMtaStsCache
    {
        private readonly InMemoryMtaStsCache _inner = new();
        public int Sets;

        public ValueTask<MtaStsCacheEntry?> GetAsync(string domain, CancellationToken cancellationToken = default) => _inner.GetAsync(domain, cancellationToken);

        public ValueTask SetAsync(MtaStsCacheEntry entry, CancellationToken cancellationToken = default)
        {
            Sets++;
            return _inner.SetAsync(entry, cancellationToken);
        }

        public ValueTask RemoveAsync(string domain, CancellationToken cancellationToken = default) => _inner.RemoveAsync(domain, cancellationToken);
    }
}
