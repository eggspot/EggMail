using System.Net;

namespace Mta.Dns.Tests;

public class MxResolverTests
{
    private static MxResolver Resolver(StaticDnsResolver dns, MxResolverOptions? options = null, int seed = 1) =>
        new(dns, options, new Random(seed));

    [Fact]
    public async Task Orders_by_preference_and_resolves_addresses()
    {
        var dns = new StaticDnsResolver()
            .AddMx("example.com", 20, "backup.example.com")
            .AddMx("example.com", 10, "mail.example.com")
            .AddA("mail.example.com", "192.0.2.10")
            .AddAaaa("mail.example.com", "2001:db8::10")
            .AddA("backup.example.com", "192.0.2.20");

        var result = await Resolver(dns).ResolveAsync("Example.COM");

        Assert.Equal(MxResolutionStatus.Ok, result.Status);
        Assert.True(result.IsOk);
        Assert.False(result.UsedImplicitMx);
        Assert.Equal(["mail.example.com", "backup.example.com"], result.Exchangers.Select(e => e.Host));
        Assert.Equal<ushort>([10, 20], result.Exchangers.Select(e => e.Preference));
        Assert.Equal([IPAddress.Parse("192.0.2.10"), IPAddress.Parse("2001:db8::10")], result.Exchangers[0].Addresses);
    }

    [Fact]
    public async Task Equal_preferences_are_shuffled_deterministically_with_a_seeded_random()
    {
        StaticDnsResolver Build()
        {
            var d = new StaticDnsResolver();
            for (int i = 0; i < 5; i++)
            {
                d.AddMx("example.com", 10, $"mx{i}.example.com").AddA($"mx{i}.example.com", $"192.0.2.{i + 1}");
            }

            return d.AddMx("example.com", 5, "first.example.com").AddA("first.example.com", "192.0.2.99");
        }

        var a = await Resolver(Build(), seed: 42).ResolveAsync("example.com");
        var b = await Resolver(Build(), seed: 42).ResolveAsync("example.com");
        Assert.Equal(a.Exchangers.Select(e => e.Host), b.Exchangers.Select(e => e.Host));
        Assert.Equal("first.example.com", a.Exchangers[0].Host);
        Assert.Equal(6, a.Exchangers.Count);

        // Different seeds produce different orders eventually (and always the same set).
        var orders = new HashSet<string>();
        for (int seed = 0; seed < 30; seed++)
        {
            var r = await Resolver(Build(), seed: seed).ResolveAsync("example.com");
            orders.Add(string.Join(",", r.Exchangers.Select(e => e.Host)));
            Assert.Equal(["first.example.com", "mx0.example.com", "mx1.example.com", "mx2.example.com", "mx3.example.com", "mx4.example.com"], r.Exchangers.Select(e => e.Host).Order());
        }

        Assert.True(orders.Count > 5);
    }

    [Fact]
    public async Task Ties_are_spread_roughly_evenly()
    {
        var dns = new StaticDnsResolver().AddMx("example.com", 10, "a.example.com").AddMx("example.com", 10, "b.example.com")
            .AddA("a.example.com", "192.0.2.1").AddA("b.example.com", "192.0.2.2");
        var resolver = new MxResolver(dns, null, new Random(7));
        int aFirst = 0;
        for (int i = 0; i < 400; i++)
        {
            if ((await resolver.ResolveAsync("example.com")).Exchangers[0].Host == "a.example.com")
            {
                aFirst++;
            }
        }

        Assert.InRange(aFirst, 140, 260);
    }

    [Fact]
    public async Task Null_mx_means_the_domain_does_not_accept_mail()
    {
        var dns = new StaticDnsResolver().AddMx("example.com", 0, ".").AddA("example.com", "192.0.2.1");
        var result = await Resolver(dns).ResolveAsync("example.com");
        Assert.Equal(MxResolutionStatus.NullMx, result.Status);
        Assert.Empty(result.Exchangers);
        Assert.NotNull(result.Detail);
        Assert.Equal(0, dns.GetQueryCount("example.com", DnsRecordType.A));   // the implicit MX must not be consulted
    }

    [Fact]
    public async Task A_null_mx_next_to_real_ones_is_ignored()
    {
        var dns = new StaticDnsResolver().AddMx("example.com", 0, ".").AddMx("example.com", 10, "mail.example.com").AddA("mail.example.com", "192.0.2.1");
        var result = await Resolver(dns).ResolveAsync("example.com");
        Assert.Equal(MxResolutionStatus.Ok, result.Status);
        Assert.Equal("mail.example.com", Assert.Single(result.Exchangers).Host);
    }

    [Fact]
    public async Task Without_mx_the_domain_itself_is_the_mail_host()
    {
        var dns = new StaticDnsResolver().AddA("example.com", "192.0.2.1").AddAaaa("example.com", "2001:db8::1");
        var result = await Resolver(dns).ResolveAsync("example.com");
        Assert.Equal(MxResolutionStatus.Ok, result.Status);
        Assert.True(result.UsedImplicitMx);
        var mx = Assert.Single(result.Exchangers);
        Assert.Equal("example.com", mx.Host);
        Assert.Equal((ushort)0, mx.Preference);
        Assert.Equal(2, mx.Addresses.Count);
    }

    [Fact]
    public async Task Existing_domain_without_mx_or_addresses_has_no_mail_host()
    {
        var dns = new StaticDnsResolver().AddTxt("example.com", "v=spf1 -all");
        var result = await Resolver(dns).ResolveAsync("example.com");
        Assert.Equal(MxResolutionStatus.NoMailHost, result.Status);
        Assert.False(result.UsedImplicitMx);
    }

    [Fact]
    public async Task Missing_domain_is_non_existent()
    {
        var result = await Resolver(new StaticDnsResolver()).ResolveAsync("nope.example");
        Assert.Equal(MxResolutionStatus.NonExistentDomain, result.Status);
    }

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("bad domain")]
    [InlineData("a..b")]
    public async Task Invalid_domains_are_non_existent_without_any_lookup(string domain)
    {
        var dns = new StaticDnsResolver();
        var result = await Resolver(dns).ResolveAsync(domain);
        Assert.Equal(MxResolutionStatus.NonExistentDomain, result.Status);
        Assert.Equal(0, dns.QueryCount);
    }

    [Fact]
    public async Task Idna_domains_are_looked_up_as_punycode()
    {
        var dns = new StaticDnsResolver().AddMx("xn--bcher-kva.example", 10, "mail.example.net").AddA("mail.example.net", "192.0.2.1");
        var result = await Resolver(dns).ResolveAsync("Bücher.example");
        Assert.Equal(MxResolutionStatus.Ok, result.Status);
    }

    [Fact]
    public async Task Servfail_on_the_mx_lookup_is_a_temporary_failure()
    {
        var dns = new StaticDnsResolver().Fail("example.com", DnsRecordType.MX);
        var result = await Resolver(dns).ResolveAsync("example.com");
        Assert.Equal(MxResolutionStatus.TempFail, result.Status);
    }

    private sealed class ThrowingResolver : IDnsResolver
    {
        public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default) =>
            throw new DnsException("timeout", DnsFailureReason.Timeout);
    }

    [Fact]
    public async Task A_dns_exception_is_a_temporary_failure_not_an_exception()
    {
        var result = await new MxResolver(new ThrowingResolver()).ResolveAsync("example.com");
        Assert.Equal(MxResolutionStatus.TempFail, result.Status);
        Assert.Contains("timeout", result.Detail);
    }

    [Fact]
    public async Task Temporary_address_failure_of_every_mx_host_is_a_temporary_failure()
    {
        var dns = new StaticDnsResolver().AddMx("example.com", 10, "mail.example.com")
            .Fail("mail.example.com", DnsRecordType.A).Fail("mail.example.com", DnsRecordType.AAAA);
        Assert.Equal(MxResolutionStatus.TempFail, (await Resolver(dns).ResolveAsync("example.com")).Status);
    }

    [Fact]
    public async Task One_resolvable_host_is_enough_even_if_another_fails()
    {
        var dns = new StaticDnsResolver().AddMx("example.com", 10, "broken.example.com").AddMx("example.com", 20, "ok.example.com")
            .AddA("ok.example.com", "192.0.2.2").Fail("broken.example.com", DnsRecordType.A).Fail("broken.example.com", DnsRecordType.AAAA);
        var result = await Resolver(dns).ResolveAsync("example.com");
        Assert.Equal(MxResolutionStatus.Ok, result.Status);
        Assert.Equal("ok.example.com", Assert.Single(result.Exchangers).Host);
    }

    [Fact]
    public async Task Mx_hosts_without_any_address_are_no_mail_host()
    {
        var dns = new StaticDnsResolver().AddMx("example.com", 10, "mail.example.com").AddTxt("mail.example.com", "x");
        Assert.Equal(MxResolutionStatus.NoMailHost, (await Resolver(dns).ResolveAsync("example.com")).Status);
        var missing = new StaticDnsResolver().AddMx("example.com", 10, "gone.example.com");
        Assert.Equal(MxResolutionStatus.NoMailHost, (await Resolver(missing).ResolveAsync("example.com")).Status);
    }

    [Fact]
    public async Task A_temporary_ipv6_failure_does_not_hide_working_ipv4()
    {
        var dns = new StaticDnsResolver().AddMx("example.com", 10, "mail.example.com").AddA("mail.example.com", "192.0.2.1").Fail("mail.example.com", DnsRecordType.AAAA);
        var result = await Resolver(dns).ResolveAsync("example.com");
        Assert.Equal(MxResolutionStatus.Ok, result.Status);
        Assert.Equal([IPAddress.Parse("192.0.2.1")], result.Exchangers[0].Addresses);
    }

    [Fact]
    public async Task A_cname_target_is_tolerated_and_flagged()
    {
        var dns = new StaticDnsResolver().AddMx("example.com", 10, "mail.example.com")
            .AddCname("mail.example.com", "real.example.net").AddA("real.example.net", "192.0.2.4");
        var result = await Resolver(dns).ResolveAsync("example.com");
        Assert.Equal(MxResolutionStatus.Ok, result.Status);
        var mx = Assert.Single(result.Exchangers);
        Assert.Equal("mail.example.com", mx.Host);
        Assert.True(mx.ResolvedViaCname);
        Assert.Equal([IPAddress.Parse("192.0.2.4")], mx.Addresses);
    }

    [Fact]
    public async Task A_cname_target_can_be_refused_by_option()
    {
        var dns = new StaticDnsResolver().AddMx("example.com", 10, "mail.example.com")
            .AddCname("mail.example.com", "real.example.net").AddA("real.example.net", "192.0.2.4");
        var result = await Resolver(dns, new MxResolverOptions { AllowCnameExchanger = false }).ResolveAsync("example.com");
        Assert.Equal(MxResolutionStatus.NoMailHost, result.Status);
    }

    [Fact]
    public async Task A_cname_loop_in_an_mx_host_is_a_failure_not_a_hang()
    {
        var dns = new StaticDnsResolver().AddMx("example.com", 10, "a.example.com").AddCname("a.example.com", "b.example.com").AddCname("b.example.com", "a.example.com");
        var result = await Resolver(dns).ResolveAsync("example.com");
        Assert.NotEqual(MxResolutionStatus.Ok, result.Status);
    }

    [Fact]
    public async Task Number_of_mx_hosts_is_limited_after_sorting()
    {
        var dns = new StaticDnsResolver();
        for (int i = 0; i < 30; i++)
        {
            dns.AddMx("example.com", (ushort)i, $"mx{i}.example.com").AddA($"mx{i}.example.com", $"192.0.2.{i + 1}");
        }

        var result = await Resolver(dns, new MxResolverOptions { MaxMxHosts = 3 }).ResolveAsync("example.com");
        Assert.Equal(["mx0.example.com", "mx1.example.com", "mx2.example.com"], result.Exchangers.Select(e => e.Host));
        Assert.Equal(0, dns.GetQueryCount("mx3.example.com", DnsRecordType.A));
    }

    [Fact]
    public async Task Address_preference_controls_order_and_families()
    {
        StaticDnsResolver Build() => new StaticDnsResolver().AddMx("example.com", 10, "mail.example.com")
            .AddA("mail.example.com", "192.0.2.1").AddA("mail.example.com", "192.0.2.2").AddAaaa("mail.example.com", "2001:db8::1");

        var v4First = (await Resolver(Build()).ResolveAsync("example.com")).Exchangers[0].Addresses;
        Assert.Equal(["192.0.2.1", "192.0.2.2", "2001:db8::1"], v4First.Select(a => a.ToString()));

        var v6First = (await Resolver(Build(), new MxResolverOptions { AddressPreference = MxAddressPreference.Ipv6First }).ResolveAsync("example.com")).Exchangers[0].Addresses;
        Assert.Equal(["2001:db8::1", "192.0.2.1", "192.0.2.2"], v6First.Select(a => a.ToString()));

        var v4Only = Build();
        var onlyV4 = (await Resolver(v4Only, new MxResolverOptions { AddressPreference = MxAddressPreference.Ipv4Only }).ResolveAsync("example.com")).Exchangers[0].Addresses;
        Assert.Equal(["192.0.2.1", "192.0.2.2"], onlyV4.Select(a => a.ToString()));
        Assert.Equal(0, v4Only.GetQueryCount("mail.example.com", DnsRecordType.AAAA));

        var onlyV6 = (await Resolver(Build(), new MxResolverOptions { AddressPreference = MxAddressPreference.Ipv6Only }).ResolveAsync("example.com")).Exchangers[0].Addresses;
        Assert.Equal(["2001:db8::1"], onlyV6.Select(a => a.ToString()));
    }

    [Fact]
    public async Task Addresses_per_host_are_limited_and_deduplicated()
    {
        var dns = new StaticDnsResolver().AddMx("example.com", 10, "mail.example.com");
        for (int i = 1; i <= 12; i++)
        {
            dns.AddA("mail.example.com", $"192.0.2.{i}");
        }

        dns.AddA("mail.example.com", "192.0.2.1");
        var result = await Resolver(dns, new MxResolverOptions { MaxAddressesPerHost = 5 }).ResolveAsync("example.com");
        Assert.Equal(5, result.Exchangers[0].Addresses.Count);
        Assert.Equal(5, result.Exchangers[0].Addresses.Distinct().Count());
    }

    [Fact]
    public async Task Loopback_multicast_and_unspecified_addresses_are_dropped_by_default()
    {
        var dns = new StaticDnsResolver().AddMx("example.com", 10, "evil.example.com").AddMx("example.com", 20, "good.example.com")
            .AddA("evil.example.com", "127.0.0.1").AddA("evil.example.com", "0.0.0.0").AddA("evil.example.com", "224.0.0.1").AddA("evil.example.com", "255.255.255.255")
            .AddAaaa("evil.example.com", "::1").AddAaaa("evil.example.com", "::").AddAaaa("evil.example.com", "ff02::1")
            .AddA("good.example.com", "10.1.2.3");
        var result = await Resolver(dns).ResolveAsync("example.com");
        var mx = Assert.Single(result.Exchangers);
        Assert.Equal("good.example.com", mx.Host);
        Assert.Equal([IPAddress.Parse("10.1.2.3")], mx.Addresses);   // private ranges are the delivery policy's business

        var permissive = await Resolver(dns, new MxResolverOptions { ExcludeSpecialAddresses = false }).ResolveAsync("example.com");
        Assert.Equal(2, permissive.Exchangers.Count);
    }

    [Fact]
    public async Task Resolve_host_reports_its_status()
    {
        var dns = new StaticDnsResolver().AddA("h.example.com", "192.0.2.1").AddTxt("t.example.com", "x").Fail("f.example.com", DnsRecordType.A);
        var resolver = Resolver(dns);
        Assert.Equal(MxResolutionStatus.Ok, (await resolver.ResolveHostAsync("h.example.com")).Status);
        Assert.Equal(MxResolutionStatus.NoMailHost, (await resolver.ResolveHostAsync("t.example.com")).Status);
        Assert.Equal(MxResolutionStatus.NonExistentDomain, (await resolver.ResolveHostAsync("nope.example.com")).Status);
        Assert.Equal(MxResolutionStatus.TempFail, (await resolver.ResolveHostAsync("f.example.com")).Status);
        Assert.Equal(MxResolutionStatus.NonExistentDomain, (await resolver.ResolveHostAsync("")).Status);
    }

    [Fact]
    public void Constructor_validates()
    {
        Assert.Throws<ArgumentNullException>(() => new MxResolver(null!));
        Assert.Throws<ArgumentException>(() => new MxResolver(new StaticDnsResolver(), new MxResolverOptions { MaxMxHosts = 0 }));
    }

    [Fact]
    public async Task Works_end_to_end_on_top_of_dns_client()
    {
        using var server = new LoopbackDnsServer(q =>
        {
            var parsed = DnsMessageReader.Parse(q.Bytes);
            var b = PacketBuilder.ReplyTo(q.Bytes);
            switch ((parsed.QuestionName, parsed.QuestionType))
            {
                case ("example.com", DnsRecordType.MX):
                    b.Mx("example.com", 20, "b.example.com").Mx("example.com", 10, "a.example.com");
                    break;
                case ("a.example.com", DnsRecordType.A):
                    b.A("a.example.com", "192.0.2.1");
                    break;
                case ("b.example.com", DnsRecordType.AAAA):
                    b.Aaaa("b.example.com", "2001:db8::2");
                    break;
                case ("a.example.com" or "b.example.com", _):
                    b.Soa("example.com", 60, 60);
                    break;
                default:
                    b.Rcode = 3;
                    break;
            }

            return LoopbackDnsServer.Reply(b.Build());
        });
        var client = DnsClient.Create(new DnsResolverOptions { Servers = [server.Endpoint], AttemptTimeout = TimeSpan.FromSeconds(2) });
        var result = await new MxResolver(client).ResolveAsync("example.com");
        Assert.Equal(MxResolutionStatus.Ok, result.Status);
        Assert.Equal(["a.example.com", "b.example.com"], result.Exchangers.Select(e => e.Host));
        Assert.Equal([IPAddress.Parse("2001:db8::2")], result.Exchangers[1].Addresses);
    }
}

public class StaticDnsResolverTests
{
    [Fact]
    public async Task Counts_calls_per_question()
    {
        var dns = new StaticDnsResolver().AddA("a.example", "192.0.2.1");
        await dns.QueryAsync("A.example.", DnsRecordType.A);
        await dns.QueryAsync("a.example", DnsRecordType.A);
        await dns.QueryAsync("a.example", DnsRecordType.TXT);
        Assert.Equal(3, dns.QueryCount);
        Assert.Equal(2, dns.GetQueryCount("a.example", DnsRecordType.A));
        Assert.Equal(0, dns.GetQueryCount("b.example", DnsRecordType.A));
    }

    [Fact]
    public async Task Ptr_tlsa_cname_helpers_work()
    {
        var dns = new StaticDnsResolver()
            .AddPtr(IPAddress.Parse("192.0.2.9"), "mail.example.com")
            .AddPtr(IPAddress.Parse("2001:db8::9"), "mail6.example.com")
            .AddTlsa("mail.example.com", 25, 3, 1, 1, [1, 2, 3])
            .AddCname("www.example.com", "example.com").AddA("example.com", "192.0.2.1");
        Assert.Equal(["mail.example.com"], await dns.GetPtrNamesAsync(IPAddress.Parse("192.0.2.9")));
        Assert.Equal(["mail6.example.com"], await dns.GetPtrNamesAsync(IPAddress.Parse("2001:db8::9")));
        var tlsa = Assert.Single(await dns.GetTlsaAsync("Mail.Example.com"));
        Assert.Equal(new byte[] { 1, 2, 3 }, tlsa.Data);
        Assert.Equal(2, (await dns.QueryAsync("www.example.com", DnsRecordType.A)).Answers.Count);
        Assert.Single(await dns.GetAddressesAsync("example.com"));
    }

    [Fact]
    public async Task A_cname_loop_terminates()
    {
        var dns = new StaticDnsResolver().AddCname("a.example", "b.example").AddCname("b.example", "a.example");
        var r = await dns.QueryAsync("a.example", DnsRecordType.A);
        Assert.Equal(DnsRcode.ServerFailure, r.Rcode);
    }

    [Fact]
    public async Task Txt_conveniences_return_strings()
    {
        var dns = new StaticDnsResolver().AddTxt("example.com", "v=spf1 -all").AddTxt("example.com", "other");
        Assert.Equal(["v=spf1 -all", "other"], await dns.GetTxtTextsAsync("example.com"));
        Assert.Equal(2, (await dns.GetTxtAsync("example.com")).Count);
        Assert.Empty(await dns.GetTxtTextsAsync("missing.example"));
    }
}

public class LiveDnsTests
{
    private static bool Enabled => Environment.GetEnvironmentVariable("EGGMAIL_TEST_LIVE_DNS") == "1";

    [Fact]
    [Trait("Category", "LiveDns")]
    public async Task Resolves_real_names_through_the_system_resolver()
    {
        if (!Enabled)
        {
            return; // opt-in only: set EGGMAIL_TEST_LIVE_DNS=1 (needs internet access)
        }

        var client = DnsClient.Create(DnsResolverOptions.FromSystemConfiguration(allowPublicResolverFallback: true));
        var mx = await new MxResolver(client).ResolveAsync("gmail.com");
        Assert.Equal(MxResolutionStatus.Ok, mx.Status);
        var nx = await client.QueryAsync("this-name-does-not-exist-eggmail.example.com", DnsRecordType.A);
        Assert.True(nx.IsNxDomain);
        var txt = await client.GetTxtTextsAsync("google.com");
        Assert.Contains(txt, t => t.StartsWith("v=spf1", StringComparison.Ordinal));
    }
}

public class MxAuthenticatedTests
{
    [Fact]
    public async Task Exposes_the_ad_bit_of_the_mx_answer()
    {
        var dns = new StaticDnsResolver { AuthenticatedData = true };
        dns.AddMx("example.com", 10, "mx.example.com").AddA("mx.example.com", "192.0.2.10");
        var r = await new MxResolver(dns).ResolveAsync("example.com");
        Assert.True(r.IsOk);
        Assert.True(r.MxAuthenticated);

        var plain = new StaticDnsResolver();
        plain.AddMx("example.com", 10, "mx.example.com").AddA("mx.example.com", "192.0.2.10");
        Assert.False((await new MxResolver(plain).ResolveAsync("example.com")).MxAuthenticated);
    }
}
