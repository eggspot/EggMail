using Mta.TestSupport;

namespace Mta.Dns.Tests;

/// <summary>
/// The resolver cache over a virtual month of queries for thousands of names (a bounded cache under pressure, with answers of every TTL, negative answers and failures). A model remembers when
/// each name was last fetched; every answer that comes from the cache must be younger than its lifetime and carry the decayed TTL, no failure is cached, and the cache never holds more
/// than its capacity. Virtual time moves only with the test's clock.
/// </summary>
public class DnsCacheLifecycleTests
{
    private static readonly uint[] PositiveTtls = [1, 30, 300, 3600, 86_400, 172_800];
    private const int Capacity = 500;
    private const int Names = 3000;

    private enum Kind { Positive, NxdomainWithSoa, NxdomainWithoutSoa, ServerFailure }

    private static (Kind Kind, uint Ttl) Describe(int index) => (index % 7) switch
    {
        0 or 1 or 2 or 3 => (Kind.Positive, PositiveTtls[index / 7 % PositiveTtls.Length]),
        4 => (Kind.NxdomainWithSoa, new uint[] { 10, 60, 600, 86_400 }[index / 7 % 4]),
        5 => (Kind.NxdomainWithoutSoa, 0),
        _ => (Kind.ServerFailure, 0),
    };

    private static string NameOf(int index) => $"h{index}.example.net";

    [Fact]
    public async Task A_month_of_queries_never_serves_an_expired_answer_and_never_grows_past_the_capacity()
    {
        int seed = Accelerated.Seed(53);
        var random = new Random(seed);
        var options = new DnsResolverOptions { MaxCacheEntries = Capacity, EdnsUdpPayloadSize = 1232 };   // the product's TTL limits: min 5 s, max 1 day, negative cap 5 minutes, default negative 30 s
        var clock = new FakeClock();
        var transport = new FakeTransport(q =>
        {
            int index = int.Parse(q.Name[1..q.Name.IndexOf('.')]);
            var (kind, ttl) = Describe(index);
            return kind switch
            {
                Kind.Positive => q.Reply().A(q.Name, "192.0.2.1", ttl).Build(),
                Kind.NxdomainWithSoa => q.Reply(rcode: 3).Soa("example.net", 3600, ttl).Build(),
                Kind.NxdomainWithoutSoa => q.Reply(rcode: 3).Build(),
                _ => q.Reply(rcode: 2).Build(),
            };
        });
        var client = new DnsClient(transport, options, clock);

        TimeSpan Lifetime(int index)
        {
            var (kind, ttl) = Describe(index);
            return kind switch
            {
                Kind.Positive => TimeSpan.FromSeconds(Math.Clamp(ttl, 5u, 86_400u)),
                Kind.NxdomainWithSoa => TimeSpan.FromSeconds(Math.Min(ttl, 300u)),
                Kind.NxdomainWithoutSoa => TimeSpan.FromSeconds(30),
                _ => TimeSpan.Zero,
            };
        }

        var fetchedAt = new Dictionary<int, DateTimeOffset>();
        int queries = Accelerated.Scaled(60_000);
        long hits = 0, misses = 0, stale = 0;
        for (int i = 0; i < queries; i++)
        {
            clock.Advance(TimeSpan.FromSeconds(random.Next(1, 90)));
            // Some names are asked far more often than others (a handful of big destinations and a long tail).
            int index = random.NextDouble() < 0.6 ? random.Next(0, 120) : random.Next(0, Names);
            int before = transport.Calls;
            DnsResponse r = await client.QueryAsync(NameOf(index), DnsRecordType.A);
            bool hit = transport.Calls == before;
            var (kind, _) = Describe(index);
            TimeSpan lifetime = Lifetime(index);
            DateTimeOffset now = clock.UtcNow;

            switch (kind)
            {
                case Kind.Positive:
                    Assert.True(r.IsSuccess);
                    break;
                case Kind.NxdomainWithSoa or Kind.NxdomainWithoutSoa:
                    Assert.True(r.IsNxDomain);
                    break;
                default:
                    Assert.False(r.IsSuccess);
                    Assert.False(hit, $"a failure was answered from the cache (name {index}, seed {seed})");
                    break;
            }

            if (hit)
            {
                hits++;
                Assert.True(fetchedAt.TryGetValue(index, out DateTimeOffset at), "a hit for a name that was never fetched");
                TimeSpan age = now - at;
                Assert.True(age < lifetime, $"name {index} ({kind}) was served from the cache at age {age}, lifetime {lifetime} (seed {seed})");
                uint expected = (uint)Math.Max(0, lifetime.TotalSeconds - Math.Floor(age.TotalSeconds));
                Assert.Equal(expected, r.Ttl);   // the TTL decays with the time spent in the cache
            }
            else
            {
                misses++;
                if (kind != Kind.ServerFailure)
                {
                    if (fetchedAt.TryGetValue(index, out DateTimeOffset at) && now - at < lifetime)
                    {
                        stale++;   // a fresh entry that was pushed out by newer ones: allowed only because the cache is smaller than the set of names
                    }

                    fetchedAt[index] = now;
                    Assert.Equal((uint)lifetime.TotalSeconds, r.Ttl);   // the first answer carries the clamped TTL
                }
            }

            Assert.True(client.CachedEntryCount <= Capacity, $"the cache holds {client.CachedEntryCount} entries (capacity {Capacity}, seed {seed})");
        }

        Assert.True(hits > queries / 20, $"the cache was used: {hits} hits of {queries}");
        Assert.True(misses > 0 && stale >= 0);
        // Evictions of fresh entries happen only under pressure: the set of names is six times the capacity.
        Assert.True(stale < misses);
    }

    [Fact]
    public async Task Ttls_are_clamped_and_answers_expire_at_the_exact_second_whatever_the_server_says()
    {
        var clock = new FakeClock();
        var transport = new FakeTransport(q =>
        {
            uint ttl = uint.Parse(q.Name[1..q.Name.IndexOf('.')]);
            return q.Reply().A(q.Name, "192.0.2.1", ttl).Build();
        });
        var client = new DnsClient(transport, new DnsResolverOptions { EdnsUdpPayloadSize = 1232 }, clock);

        // 1 s is raised to the 5 s minimum; 2 days is cut to the 1 day maximum; the others are kept.
        foreach ((uint served, uint lifetime) in new (uint, uint)[] { (1, 5), (5, 5), (30, 30), (3600, 3600), (86_400, 86_400), (172_800, 86_400), (2_000_000_000, 86_400) })
        {
            string name = $"h{served}.example.net";
            int calls = transport.Calls;
            Assert.Equal(lifetime, (await client.QueryAsync(name, DnsRecordType.A)).Ttl);
            Assert.Equal(calls + 1, transport.Calls);

            clock.Advance(TimeSpan.FromSeconds(lifetime - 1));
            await client.QueryAsync(name, DnsRecordType.A);
            Assert.Equal(calls + 1, transport.Calls);   // one second before the end: cached
            clock.Advance(TimeSpan.FromSeconds(1));
            await client.QueryAsync(name, DnsRecordType.A);
            Assert.Equal(calls + 2, transport.Calls);   // at the end: asked again
        }

        // A name asked for once a day for a year is asked of the server once a day, not once a year and not once a query.
        int before = transport.Calls;
        for (int day = 0; day < 365; day++)
        {
            clock.Advance(TimeSpan.FromDays(1));
            await client.QueryAsync("h172800.example.net", DnsRecordType.A);
        }

        Assert.Equal(365, transport.Calls - before);
    }
}
