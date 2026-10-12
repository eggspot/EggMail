using Mta.Dns;
using Mta.Tls.Dane;
using Mta.Tls.Tests.Support;

namespace Mta.Tls.Tests;

public class DaneTlsaLookupTests
{
    private const string Mx = "mx.example.com";
    private const string TlsaName = "_25._tcp.mx.example.com";

    private static TlsaRecord Record(byte usage = 3, byte selector = 1, byte matching = 1, string name = TlsaName) =>
        new(name, 300, usage, selector, matching, new byte[matching == 2 ? 64 : 32]);

    private static DnsResponse Answer(bool ad, params DnsRecord[] records) => new() { AuthenticatedData = ad, Answers = records };

    [Fact]
    public async Task Secure_usable_records_are_returned_for_the_25_tcp_name()
    {
        var dns = new ScriptedDnsResolver().Set(TlsaName, DnsRecordType.TLSA, Answer(true, Record()));
        var result = await new DaneTlsaLookup(dns).LookupAsync("MX.Example.com.");

        Assert.Equal(DaneStatus.Usable, result.Status);
        Assert.True(result.RequiresDane);
        Assert.Equal(TlsaName, result.TlsaName);
        Assert.Single(result.UsableRecords);
        Assert.Empty(result.IgnoredRecords);
        Assert.Equal([Mx], result.ReferenceNames);
        Assert.Null(result.Failure);
    }

    [Fact]
    public async Task Port_is_part_of_the_query_name()
    {
        var dns = new ScriptedDnsResolver().Set("_587._tcp.mx.example.com", DnsRecordType.TLSA, Answer(true, Record(name: "_587._tcp.mx.example.com")));
        var result = await new DaneTlsaLookup(dns).LookupAsync(Mx, port: 587);
        Assert.Equal(DaneStatus.Usable, result.Status);
    }

    [Fact]
    public async Task Records_without_the_ad_bit_are_ignored_as_insecure()
    {
        var dns = new ScriptedDnsResolver().Set(TlsaName, DnsRecordType.TLSA, Answer(false, Record()));
        var result = await new DaneTlsaLookup(dns).LookupAsync(Mx);

        Assert.Equal(DaneStatus.NotApplicable, result.Status);
        Assert.False(result.RequiresDane);
        Assert.Empty(result.UsableRecords);
        Assert.Contains(result.Notes, n => n.Contains("not DNSSEC-authenticated"));
    }

    [Theory]
    [InlineData(DnsRcode.NameError, true)]
    [InlineData(DnsRcode.NameError, false)]
    [InlineData(DnsRcode.NoError, true)]
    [InlineData(DnsRcode.NoError, false)]
    public async Task Absent_records_mean_dane_does_not_apply(DnsRcode rcode, bool ad)
    {
        var dns = new ScriptedDnsResolver().Set(TlsaName, DnsRecordType.TLSA, new DnsResponse { Rcode = rcode, AuthenticatedData = ad });
        var result = await new DaneTlsaLookup(dns).LookupAsync(Mx);
        Assert.Equal(DaneStatus.NotApplicable, result.Status);
        Assert.False(result.RequiresDane);
    }

    [Fact]
    public async Task Unknown_name_is_not_applicable()
    {
        var result = await new DaneTlsaLookup(new ScriptedDnsResolver()).LookupAsync(Mx);
        Assert.Equal(DaneStatus.NotApplicable, result.Status);
    }

    [Fact]
    public async Task Servfail_is_a_dnssec_failure_that_must_not_downgrade()
    {
        var dns = new ScriptedDnsResolver().Set(TlsaName, DnsRecordType.TLSA, new DnsResponse { Rcode = DnsRcode.ServerFailure });
        var result = await new DaneTlsaLookup(dns).LookupAsync(Mx);

        Assert.Equal(DaneStatus.LookupFailed, result.Status);
        Assert.True(result.RequiresDane);
        Assert.Equal(TlsResultType.DnssecInvalid, result.Failure);
    }

    [Fact]
    public async Task Refused_is_a_lookup_failure()
    {
        var dns = new ScriptedDnsResolver().Set(TlsaName, DnsRecordType.TLSA, new DnsResponse { Rcode = DnsRcode.Refused });
        var result = await new DaneTlsaLookup(dns).LookupAsync(Mx);
        Assert.Equal(DaneStatus.LookupFailed, result.Status);
        Assert.Equal(TlsResultType.ValidationFailure, result.Failure);
    }

    [Fact]
    public async Task Transport_errors_are_a_lookup_failure_not_an_exception()
    {
        var result = await new DaneTlsaLookup(new ThrowingDnsResolver()).LookupAsync(Mx);
        Assert.Equal(DaneStatus.LookupFailed, result.Status);
        Assert.True(result.RequiresDane);
    }

    [Fact]
    public async Task Secure_records_that_are_all_unusable_are_an_authenticated_failure()
    {
        var dns = new ScriptedDnsResolver().Set(TlsaName, DnsRecordType.TLSA, Answer(true, Record(usage: 0), Record(usage: 1), Record(usage: 9)));
        var result = await new DaneTlsaLookup(dns).LookupAsync(Mx);

        Assert.Equal(DaneStatus.Unusable, result.Status);
        Assert.True(result.RequiresDane);
        Assert.Equal(TlsResultType.TlsaInvalid, result.Failure);
        Assert.Equal(3, result.IgnoredRecords.Count);
        Assert.Empty(result.UsableRecords);
    }

    [Fact]
    public async Task Usable_records_survive_next_to_ignored_pkix_records()
    {
        var dns = new ScriptedDnsResolver().Set(TlsaName, DnsRecordType.TLSA, Answer(true, Record(usage: 1), Record(usage: 3), Record(usage: 2, matching: 2)));
        var result = await new DaneTlsaLookup(dns).LookupAsync(Mx);

        Assert.Equal(DaneStatus.Usable, result.Status);
        Assert.Equal(2, result.UsableRecords.Count);
        Assert.Single(result.IgnoredRecords);
    }

    [Fact]
    public async Task Insecure_mx_rrset_disables_dane_without_querying()
    {
        var dns = new ScriptedDnsResolver().Set(TlsaName, DnsRecordType.TLSA, Answer(true, Record()));
        var result = await new DaneTlsaLookup(dns).LookupAsync(Mx, mxRrsetAuthenticated: false);
        Assert.Equal(DaneStatus.NotApplicable, result.Status);
        Assert.Equal(0, dns.Queries);
    }

    [Theory]
    [InlineData("")]
    [InlineData("bad host")]
    [InlineData("192.0.2.1")]
    public async Task Invalid_host_names_are_not_applicable(string host)
    {
        var dns = new ScriptedDnsResolver();
        var result = await new DaneTlsaLookup(dns).LookupAsync(host);
        Assert.Equal(DaneStatus.NotApplicable, result.Status);
        Assert.Equal(0, dns.Queries);
    }

    [Fact]
    public async Task Authenticated_cname_makes_the_target_the_tlsa_base_domain_and_adds_reference_names()
    {
        var dns = new ScriptedDnsResolver()
            .Set(Mx, DnsRecordType.A, Answer(true, new CnameRecord(Mx, 300, "real.example.net")))
            .Set("_25._tcp.real.example.net", DnsRecordType.TLSA, Answer(true, Record(name: "_25._tcp.real.example.net")));
        var result = await new DaneTlsaLookup(dns).LookupAsync(Mx);

        Assert.Equal(DaneStatus.Usable, result.Status);
        Assert.Equal("_25._tcp.real.example.net", result.TlsaName);
        Assert.Equal(["real.example.net", Mx], result.ReferenceNames);
    }

    [Fact]
    public async Task Cname_falls_back_to_the_original_name_when_the_target_has_no_tlsa()
    {
        var dns = new ScriptedDnsResolver()
            .Set(Mx, DnsRecordType.A, Answer(true, new CnameRecord(Mx, 300, "real.example.net")))
            .Set(TlsaName, DnsRecordType.TLSA, Answer(true, Record()));
        var result = await new DaneTlsaLookup(dns).LookupAsync(Mx);

        Assert.Equal(DaneStatus.Usable, result.Status);
        Assert.Equal(TlsaName, result.TlsaName);
        Assert.Equal([Mx], result.ReferenceNames);
    }

    [Fact]
    public async Task Insecure_cname_is_not_followed()
    {
        var dns = new ScriptedDnsResolver()
            .Set(Mx, DnsRecordType.A, Answer(false, new CnameRecord(Mx, 300, "real.example.net")))
            .Set("_25._tcp.real.example.net", DnsRecordType.TLSA, Answer(true, Record(name: "_25._tcp.real.example.net")));
        var result = await new DaneTlsaLookup(dns).LookupAsync(Mx);
        Assert.Equal(DaneStatus.NotApplicable, result.Status);
    }

    [Fact]
    public async Task Cname_following_can_be_disabled_and_loops_are_bounded()
    {
        var loop = new ScriptedDnsResolver()
            .Set("a.example.com", DnsRecordType.A, Answer(true, new CnameRecord("a.example.com", 300, "b.example.com"), new CnameRecord("b.example.com", 300, "a.example.com")))
            .Set("_25._tcp.a.example.com", DnsRecordType.TLSA, Answer(true, Record(name: "_25._tcp.a.example.com")));
        var result = await new DaneTlsaLookup(loop).LookupAsync("a.example.com");
        Assert.Equal(DaneStatus.Usable, result.Status); // terminated; resolved via the original name or a bounded alias

        var off = new ScriptedDnsResolver()
            .Set(Mx, DnsRecordType.A, Answer(true, new CnameRecord(Mx, 300, "real.example.net")))
            .Set(TlsaName, DnsRecordType.TLSA, Answer(true, Record()));
        var plain = await new DaneTlsaLookup(off, new DaneLookupOptions { FollowAddressCname = false }).LookupAsync(Mx);
        Assert.Equal(TlsaName, plain.TlsaName);
    }

    [Fact]
    public async Task Works_with_the_static_resolver_contract()
    {
        var dns = new StaticDnsResolver { AuthenticatedData = true };
        dns.Add(new TlsaRecord(TlsaName, 300, 3, 1, 1, new byte[32]));
        var result = await new DaneTlsaLookup(dns).LookupAsync(Mx);
        Assert.Equal(DaneStatus.Usable, result.Status);

        var insecure = new StaticDnsResolver { AuthenticatedData = false };
        insecure.Add(new TlsaRecord(TlsaName, 300, 3, 1, 1, new byte[32]));
        Assert.Equal(DaneStatus.NotApplicable, (await new DaneTlsaLookup(insecure).LookupAsync(Mx)).Status);
    }
}
