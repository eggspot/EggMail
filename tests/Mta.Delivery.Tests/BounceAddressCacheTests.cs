using Mta.Core;
using Mta.Dsn;

namespace Mta.Delivery.Tests;

/// <summary>The signed bounce address is made once per key, tenant, sending domain and hour; these tests count how often it is made.</summary>
public class BounceAddressCacheTests
{
    private static readonly Guid TenantA = Guid.Parse("a0000000-0000-7000-8000-00000000000a");
    private static readonly Guid TenantB = Guid.Parse("b0000000-0000-7000-8000-00000000000b");
    private static readonly Guid DomainOne = Guid.Parse("d1000000-0000-7000-8000-000000000001");
    private static readonly Guid DomainTwo = Guid.Parse("d2000000-0000-7000-8000-000000000002");

    private static readonly VerpCodec Codec = new(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey(), [2] = VerpCodec.GenerateKey() }, 1);

    private sealed class Counting
    {
        public int Runs;

        public EmailAddress? Make(VerpCodec codec, Guid tenant, Guid domain, DateTimeOffset now)
        {
            Runs++;
            return EmailAddress.Parse(codec.CreateAddress(tenant, domain, "bounces.egg.test", now));
        }
    }

    private static EmailAddress? Get(BounceAddressCache cache, Counting counter, VerpCodec codec, Guid tenant, Guid domain, DateTimeOffset now) =>
        cache.GetOrCreate(codec.ActiveKeyId, tenant, domain, VerpCodec.HourStamp(now), (counter, codec, tenant, domain, now), static s => s.counter.Make(s.codec, s.tenant, s.domain, s.now));

    [Fact]
    public void An_address_is_made_once_per_tenant_domain_and_hour_and_each_combination_has_its_own()
    {
        var cache = new BounceAddressCache();
        var counter = new Counting();
        var hour = new DateTimeOffset(2026, 10, 15, 10, 0, 0, TimeSpan.Zero);

        var a1 = Get(cache, counter, Codec, TenantA, DomainOne, hour.AddMinutes(1));
        var a2 = Get(cache, counter, Codec, TenantA, DomainOne, hour.AddMinutes(59));   // same hour
        Assert.Equal(1, counter.Runs);
        Assert.Equal(a1, a2);

        var otherDomain = Get(cache, counter, Codec, TenantA, DomainTwo, hour.AddMinutes(5));
        var otherTenant = Get(cache, counter, Codec, TenantB, DomainOne, hour.AddMinutes(5));
        Assert.Equal(3, counter.Runs);
        Assert.NotEqual(a1, otherDomain);
        Assert.NotEqual(a1, otherTenant);
        Assert.NotEqual(otherDomain, otherTenant);

        // Asked again, none of the three is made again, and each still decodes to its own tenant and domain.
        Assert.Equal(otherDomain, Get(cache, counter, Codec, TenantA, DomainTwo, hour.AddMinutes(30)));
        Assert.Equal(otherTenant, Get(cache, counter, Codec, TenantB, DomainOne, hour.AddMinutes(30)));
        Assert.Equal(3, counter.Runs);
        foreach (var (address, tenant, domain) in new[] { (a1, TenantA, DomainOne), (otherDomain, TenantA, DomainTwo), (otherTenant, TenantB, DomainOne) })
        {
            Assert.True(Codec.TryDecode(address!.Value.LocalPart, hour.AddMinutes(10), TimeSpan.FromHours(1), out var token));
            Assert.Equal(tenant, token.TenantId);
            Assert.True(VerpCodec.MatchesDomain(token, domain));
        }
    }

    [Fact]
    public void The_next_hour_gets_a_new_address_because_the_token_carries_the_hour()
    {
        var cache = new BounceAddressCache();
        var counter = new Counting();
        var lastMinute = new DateTimeOffset(2026, 10, 15, 10, 59, 59, TimeSpan.Zero);
        var before = Get(cache, counter, Codec, TenantA, DomainOne, lastMinute);
        var after = Get(cache, counter, Codec, TenantA, DomainOne, lastMinute.AddSeconds(1));
        Assert.Equal(2, counter.Runs);
        Assert.NotEqual(before, after);
        Assert.True(Codec.TryDecode(after!.Value.LocalPart, lastMinute.AddSeconds(1), TimeSpan.FromHours(1), out var token));
        Assert.Equal(VerpCodec.HourStamp(lastMinute.AddSeconds(1)), (long)(token.IssuedAt - new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalHours);

        // The earlier hour is still served from the table (a delivery that started before the turn of the hour).
        Assert.Equal(before, Get(cache, counter, Codec, TenantA, DomainOne, lastMinute.AddSeconds(-30)));
        Assert.Equal(2, counter.Runs);
    }

    [Fact]
    public void A_codec_with_another_active_key_never_gets_an_address_signed_by_the_first()
    {
        var cache = new BounceAddressCache();
        var counter = new Counting();
        var at = new DateTimeOffset(2026, 10, 15, 10, 5, 0, TimeSpan.Zero);
        var rotated = new VerpCodec(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey(), [2] = VerpCodec.GenerateKey() }, 2);
        var first = Get(cache, counter, Codec, TenantA, DomainOne, at);
        var second = Get(cache, counter, rotated, TenantA, DomainOne, at);
        Assert.Equal(2, counter.Runs);
        Assert.NotEqual(first, second);
        Assert.False(rotated.TryDecode(first!.Value.LocalPart, at, TimeSpan.FromHours(1), out _));   // signed with a key the other codec does not have
        Assert.True(rotated.TryDecode(second!.Value.LocalPart, at, TimeSpan.FromHours(1), out _));
    }

    [Fact]
    public void An_address_that_could_not_be_made_is_not_kept_and_the_table_stays_bounded()
    {
        var cache = new BounceAddressCache(maxEntries: 3);
        int runs = 0;
        Assert.Null(cache.GetOrCreate(1, TenantA, DomainOne, 5, 0, _ => { runs++; return null; }));
        Assert.Null(cache.GetOrCreate(1, TenantA, DomainOne, 5, 0, _ => { runs++; return null; }));
        Assert.Equal(2, runs);
        Assert.Equal(0, cache.Count);

        for (int hour = 0; hour < 20; hour++)
        {
            var made = cache.GetOrCreate(1, TenantA, DomainOne, hour, hour, h => EmailAddress.Parse($"b+h{h}@bounces.egg.test"));
            Assert.Equal($"b+h{hour}@bounces.egg.test", made!.Value.ToString());
            Assert.True(cache.Count <= 3);
        }
    }
}
