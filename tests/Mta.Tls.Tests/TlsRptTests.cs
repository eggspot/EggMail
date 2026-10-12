using System.Net;
using System.Text.Json;
using Mta.Dns;
using Mta.Tls.MtaSts;
using Mta.Tls.TlsRpt;
using Mta.Tls.Tests.Support;

namespace Mta.Tls.Tests;

public class TlsRptRecordParserTests
{
    [Fact]
    public void Parses_mailto_and_https_endpoints()
    {
        Assert.True(TlsRptRecordParser.TryParse("v=TLSRPTv1; rua=mailto:reports@example.com,https://reports.example.com/v1/tlsrpt", out var record));
        Assert.Equal(2, record!.Endpoints.Count);
        Assert.Equal(TlsRptEndpointKind.Mailto, record.Endpoints[0].Kind);
        Assert.Equal("reports@example.com", record.Endpoints[0].MailtoAddress);
        Assert.Equal("mailto:reports@example.com", record.Endpoints[0].Uri);
        Assert.Equal(TlsRptEndpointKind.Https, record.Endpoints[1].Kind);
        Assert.Equal("https://reports.example.com/v1/tlsrpt", record.Endpoints[1].Uri);
    }

    [Fact]
    public void Tolerates_whitespace_case_unknown_tags_and_trailing_semicolon()
    {
        Assert.True(TlsRptRecordParser.TryParse(" v=TLSRPTv1 ;  RUA = mailto:a@example.com , mailto:B@Example.com ; ext=1; ", out var record));
        Assert.Equal(["a@example.com", "B@Example.com"], record!.Endpoints.Select(e => e.MailtoAddress));
    }

    [Fact]
    public void Mailto_query_parts_are_dropped_and_unsupported_schemes_skipped()
    {
        Assert.True(TlsRptRecordParser.TryParse("v=TLSRPTv1; rua=ftp://x.example.com/a,http://x.example.com/a,mailto:a@example.com?subject=x", out var record));
        var only = Assert.Single(record!.Endpoints);
        Assert.Equal("mailto:a@example.com", only.Uri);
    }

    [Theory]
    [InlineData("")]
    [InlineData("v=TLSRPTv1")]
    [InlineData("v=TLSRPTv1;")]
    [InlineData("v=TLSRPTv1; rua=")]
    [InlineData("v=TLSRPTv1; rua=ftp://x.example.com")]
    [InlineData("v=TLSRPTv2; rua=mailto:a@example.com")]
    [InlineData("rua=mailto:a@example.com; v=TLSRPTv1")]
    [InlineData("v=TLSRPTv1; rua=mailto:a@example.com; rua=mailto:b@example.com")]
    [InlineData("v=TLSRPTv1; rua=mailto:not-an-address")]
    [InlineData("v=TLSRPTv1; rua=mailto:@example.com")]
    [InlineData("v=TLSRPTv1; rua=mailto:a@b@example.com")]
    [InlineData("v=TLSRPTv1; rua=mailto:a b@example.com")]
    [InlineData("v=TLSRPTv1; rua=mailto:a@bad host")]
    [InlineData("v=TLSRPTv1; rua=https://user:pw@reports.example.com/x")]
    [InlineData("v=TLSRPTv1; rua=https://localhost/x")]
    [InlineData("v=TLSRPTv1; rua=https://192.0.2.7/x")]
    [InlineData("v=TLSRPTv1; rua=https://[::1]/x")]
    [InlineData("v=TLSRPTv1; rua=https:///x")]
    [InlineData("v=TLSRPTv1; garbage")]
    public void Invalid_records_are_rejected(string text)
    {
        Assert.False(TlsRptRecordParser.TryParse(text, out var record));
        Assert.Null(record);
    }

    [Fact]
    public void Endpoint_count_is_bounded()
    {
        string rua = string.Join(",", Enumerable.Range(0, 20).Select(i => $"mailto:r{i}@example.com"));
        Assert.True(TlsRptRecordParser.TryParse("v=TLSRPTv1; rua=" + rua, out var record));
        Assert.Equal(TlsRptRecordParser.MaxEndpoints, record!.Endpoints.Count);
    }

    [Fact]
    public void Null_and_huge_input_are_rejected()
    {
        Assert.False(TlsRptRecordParser.TryParse(null, out _));
        Assert.False(TlsRptRecordParser.TryParse("v=TLSRPTv1; rua=mailto:a@example.com; x=" + new string('a', 5000), out _));
    }

    [Fact]
    public void Select_requires_exactly_one_tlsrpt_record()
    {
        TxtRecord T(string s) => new("_smtp._tls.example.com", 60, s);
        Assert.NotNull(TlsRptRecordParser.Select([T("unrelated"), T("v=TLSRPTv1; rua=mailto:a@example.com")]));
        Assert.Null(TlsRptRecordParser.Select([T("v=TLSRPTv1; rua=mailto:a@example.com"), T("v=TLSRPTv1; rua=mailto:b@example.com")]));
        Assert.Null(TlsRptRecordParser.Select([T("v=TLSRPTv1; rua=junk")]));
        Assert.Null(TlsRptRecordParser.Select([]));
    }

    [Fact]
    public async Task Lookup_queries_smtp_tls_and_never_throws()
    {
        var dns = new ScriptedDnsResolver().SetTxt("_smtp._tls.example.com", "v=TLSRPTv1; rua=mailto:a@example.com");
        var found = await new TlsRptRecordLookup(dns).LookupAsync("Example.com.");
        Assert.NotNull(found);

        Assert.Null(await new TlsRptRecordLookup(dns).LookupAsync("other.example"));
        Assert.Null(await new TlsRptRecordLookup(dns).LookupAsync("bad domain"));
        Assert.Null(await new TlsRptRecordLookup(new ThrowingDnsResolver()).LookupAsync("example.com"));
    }
}

public class TlsRptCollectorTests
{
    private static readonly TlsRptPolicyDescriptor Sts = new(TlsPolicyType.Sts, ["version: STSv1", "mode: enforce", "mx: mail.example.com", "max_age: 86400"], ["mail.example.com"]);

    [Fact]
    public void Counts_successes_and_failures_per_policy()
    {
        var clock = new TestClock();
        var collector = new TlsRptCollector(clock);
        for (int i = 0; i < 5; i++)
        {
            collector.RecordSuccess("example.com", Sts, "mail.example.com");
        }

        collector.RecordFailure("example.com", Sts, "mail.example.com", TlsResultType.CertificateExpired, sendingMtaIp: "192.0.2.1", receivingIp: "198.51.100.5");
        collector.RecordFailure("example.com", Sts, "mail.example.com", TlsResultType.CertificateExpired, sendingMtaIp: "192.0.2.1", receivingIp: "198.51.100.5");
        collector.RecordFailure("example.com", Sts, "mail.example.com", TlsResultType.StarttlsNotSupported);
        collector.RecordSuccess("example.com", TlsRptPolicyDescriptor.NoPolicy, "mail.example.com");

        var data = Assert.Single(collector.Snapshot());
        Assert.Equal("example.com", data.PolicyDomain);
        Assert.Equal(2, data.Policies.Count);
        var sts = data.Policies.Single(p => p.Policy.Type == TlsPolicyType.Sts);
        Assert.Equal(5, sts.SuccessCount);
        Assert.Equal(3, sts.FailureCount);
        Assert.Equal(2, sts.FailureDetails.Count);
        Assert.Equal(2, sts.FailureDetails[0].FailedSessionCount); // most frequent first
        Assert.Equal(TlsResultType.CertificateExpired, sts.FailureDetails[0].ResultType);
        var none = data.Policies.Single(p => p.Policy.Type == TlsPolicyType.NoPolicyFound);
        Assert.Equal(1, none.SuccessCount);
    }

    [Fact]
    public void Domains_are_normalised_and_invalid_ones_are_dropped_and_counted()
    {
        var collector = new TlsRptCollector(new TestClock());
        collector.RecordSuccess("EXAMPLE.com.", Sts, "mx");
        collector.RecordSuccess("example.com", Sts, "mx");
        collector.RecordSuccess("not a domain", Sts, "mx");

        Assert.Equal(2, Assert.Single(collector.Snapshot()).Policies.Single().SuccessCount);
        Assert.Equal(1, collector.DroppedSessionCount);
    }

    [Fact]
    public void Day_boundaries_split_buckets_and_only_completed_days_are_drained()
    {
        var clock = new TestClock(new DateTimeOffset(2026, 10, 11, 23, 59, 0, TimeSpan.Zero));
        var collector = new TlsRptCollector(clock);
        collector.RecordSuccess("example.com", Sts, "mx");
        clock.Advance(TimeSpan.FromMinutes(2)); // now 2026-10-12
        collector.RecordSuccess("example.com", Sts, "mx");
        collector.RecordSuccess("example.com", Sts, "mx");

        Assert.Equal(2, collector.Snapshot().Count);
        var drained = Assert.Single(collector.DrainCompletedDays());
        Assert.Equal(new DateOnly(2026, 10, 11), drained.Day);
        Assert.Equal(1, drained.Policies.Single().SuccessCount);

        Assert.Empty(collector.DrainCompletedDays());
        var today = Assert.Single(collector.Snapshot());
        Assert.Equal(2, today.Policies.Single().SuccessCount);
        Assert.Single(collector.Drain(new DateOnly(2026, 10, 12)));
        Assert.Empty(collector.Snapshot());
    }

    [Fact]
    public void Bounds_cap_memory_without_losing_counts()
    {
        var collector = new TlsRptCollector(new TestClock(), new TlsRptCollectorOptions { MaxDomainDays = 2, MaxPoliciesPerDomain = 2, MaxFailureDetailsPerPolicy = 3, MaxTextLength = 10 });

        for (int i = 0; i < 10; i++)
        {
            collector.RecordFailure("example.com", Sts, $"mx{i}.example.com", TlsResultType.ValidationFailure, additionalInformation: new string('x', 100));
        }

        var policy = Assert.Single(collector.Snapshot().Single().Policies);
        Assert.Equal(10, policy.FailureCount);
        Assert.Equal(3, policy.FailureDetails.Count);
        Assert.Equal(7, policy.DroppedFailureDetailCount);
        Assert.All(policy.FailureDetails, d => Assert.Equal(10, d.AdditionalInformation!.Length));

        collector.RecordSuccess("example.com", TlsRptPolicyDescriptor.NoPolicy, "mx");
        collector.RecordSuccess("example.com", new TlsRptPolicyDescriptor(TlsPolicyType.Tlsa, ["x"], []), "mx"); // third policy: dropped
        collector.RecordSuccess("a.example", Sts, "mx");
        collector.RecordSuccess("b.example", Sts, "mx"); // third domain-day: dropped
        Assert.Equal(2, collector.DroppedSessionCount);
    }

    [Fact]
    public async Task Is_thread_safe()
    {
        var collector = new TlsRptCollector(new TestClock());
        const int Threads = 8;
        const int PerThread = 5000;
        await Task.WhenAll(Enumerable.Range(0, Threads).Select(t => Task.Run(() =>
        {
            for (int i = 0; i < PerThread; i++)
            {
                if (i % 2 == 0)
                {
                    collector.RecordSuccess("example.com", Sts, "mx");
                }
                else
                {
                    collector.RecordFailure("example.com", Sts, $"mx{i % 7}", TlsResultType.CertificateHostMismatch);
                }
            }
        })));

        var policy = collector.Snapshot().Single().Policies.Single();
        Assert.Equal(Threads * PerThread / 2, policy.SuccessCount);
        Assert.Equal(Threads * PerThread / 2, policy.FailureCount);
        Assert.Equal(policy.FailureCount, policy.FailureDetails.Sum(d => d.FailedSessionCount));
    }

    [Fact]
    public void Descriptors_are_built_from_policies()
    {
        Assert.True(MtaStsPolicyParser.TryParse("version: STSv1\nmode: testing\nmx: *.example.com\nmax_age: 60\n", out var policy, out _));
        var sts = TlsRptPolicyDescriptor.FromMtaSts(policy!);
        Assert.Equal(TlsPolicyType.Sts, sts.Type);
        Assert.Equal(["*.example.com"], sts.MxHosts);
        Assert.Equal(4, sts.PolicyString.Count);

        var tlsa = TlsRptPolicyDescriptor.FromTlsa([new TlsaRecord("_25._tcp.mx.example.com", 60, 3, 1, 1, new byte[32])]);
        Assert.Equal(TlsPolicyType.Tlsa, tlsa.Type);
        Assert.StartsWith("_25._tcp.mx.example.com. IN TLSA ( 3 1 1 ", Assert.Single(tlsa.PolicyString));
    }
}

public class TlsRptReportTests
{
    private static readonly TlsRptReportOptions Options = new()
    {
        OrganizationName = "EggMail Test Org",
        ContactInfo = "tls-reports@sender.example",
        SubmitterDomain = "sender.example",
        ReportIdFactory = () => "report-123",
    };

    private static TlsRptDomainReportData Sample()
    {
        var clock = new TestClock(new DateTimeOffset(2026, 10, 11, 8, 0, 0, TimeSpan.Zero));
        var collector = new TlsRptCollector(clock);
        MtaStsPolicyParser.TryParse("version: STSv1\nmode: enforce\nmx: *.mail.company-y.example\nmax_age: 86400\n", out var policy, out _);
        var sts = TlsRptPolicyDescriptor.FromMtaSts(policy!);
        for (int i = 0; i < 5326; i++)
        {
            collector.RecordSuccess("company-y.example", sts, "mx1.mail.company-y.example");
        }

        for (int i = 0; i < 100; i++)
        {
            collector.RecordFailure("company-y.example", sts, "mx1.mail.company-y.example", TlsResultType.CertificateExpired, sendingMtaIp: "2001:db8:abcd:12::1", receivingIp: "203.0.113.5", receivingMxHelo: "mx1.mail.company-y.example");
        }

        collector.RecordFailure("company-y.example", sts, "mx2.mail.company-y.example", TlsResultType.StarttlsNotSupported, additionalInformation: "https://example.com/details", failureReasonCode: "STARTTLS-503");
        collector.RecordSuccess("company-y.example", TlsRptPolicyDescriptor.FromTlsa([new TlsaRecord("_25._tcp.mx1.company-y.example", 60, 3, 1, 1, new byte[32])]), "mx1.company-y.example");
        return Assert.Single(collector.Snapshot());
    }

    [Fact]
    public void Json_round_trip_has_the_rfc_8460_structure()
    {
        var report = new TlsRptReportBuilder(Options).Build(Sample());

        using var doc = JsonDocument.Parse(TlsRptReportBuilder.Decompress(report.GzipPayload));
        var root = doc.RootElement;
        Assert.Equal("EggMail Test Org", root.GetProperty("organization-name").GetString());
        Assert.Equal("tls-reports@sender.example", root.GetProperty("contact-info").GetString());
        Assert.Equal("report-123", root.GetProperty("report-id").GetString());
        var range = root.GetProperty("date-range");
        Assert.Equal("2026-10-11T00:00:00Z", range.GetProperty("start-datetime").GetString());
        Assert.Equal("2026-10-11T23:59:59Z", range.GetProperty("end-datetime").GetString());

        var policies = root.GetProperty("policies").EnumerateArray().ToList();
        Assert.Equal(2, policies.Count);

        var sts = policies.Single(p => p.GetProperty("policy").GetProperty("policy-type").GetString() == "sts");
        var stsPolicy = sts.GetProperty("policy");
        Assert.Equal("company-y.example", stsPolicy.GetProperty("policy-domain").GetString());
        Assert.Equal(["version: STSv1", "mode: enforce", "mx: *.mail.company-y.example", "max_age: 86400"], stsPolicy.GetProperty("policy-string").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["*.mail.company-y.example"], stsPolicy.GetProperty("mx-host").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(5326, sts.GetProperty("summary").GetProperty("total-successful-session-count").GetInt64());
        Assert.Equal(101, sts.GetProperty("summary").GetProperty("total-failure-session-count").GetInt64());

        var details = sts.GetProperty("failure-details").EnumerateArray().ToList();
        Assert.Equal(2, details.Count);
        var expired = details[0];
        Assert.Equal("certificate-expired", expired.GetProperty("result-type").GetString());
        Assert.Equal("2001:db8:abcd:12::1", expired.GetProperty("sending-mta-ip").GetString());
        Assert.Equal("mx1.mail.company-y.example", expired.GetProperty("receiving-mx-hostname").GetString());
        Assert.Equal("mx1.mail.company-y.example", expired.GetProperty("receiving-mx-helo").GetString());
        Assert.Equal("203.0.113.5", expired.GetProperty("receiving-ip").GetString());
        Assert.Equal(100, expired.GetProperty("failed-session-count").GetInt64());
        Assert.False(expired.TryGetProperty("additional-information", out _));
        var starttls = details[1];
        Assert.Equal("starttls-not-supported", starttls.GetProperty("result-type").GetString());
        Assert.Equal("https://example.com/details", starttls.GetProperty("additional-information").GetString());
        Assert.Equal("STARTTLS-503", starttls.GetProperty("failure-reason-code").GetString());

        var tlsa = policies.Single(p => p.GetProperty("policy").GetProperty("policy-type").GetString() == "tlsa");
        Assert.Contains("IN TLSA", tlsa.GetProperty("policy").GetProperty("policy-string")[0].GetString());
        Assert.False(tlsa.TryGetProperty("failure-details", out _));
        Assert.Equal(1, tlsa.GetProperty("summary").GetProperty("total-successful-session-count").GetInt64());
        Assert.Equal(0, tlsa.GetProperty("summary").GetProperty("total-failure-session-count").GetInt64());
    }

    [Fact]
    public void No_policy_found_has_neither_policy_string_nor_mx_host()
    {
        var collector = new TlsRptCollector(new TestClock());
        collector.RecordSuccess("example.com", TlsRptPolicyDescriptor.NoPolicy, "mx.example.com");
        var report = new TlsRptReportBuilder(Options).Build(collector.Snapshot().Single());

        using var doc = JsonDocument.Parse(report.Json);
        var policy = doc.RootElement.GetProperty("policies")[0].GetProperty("policy");
        Assert.Equal("no-policy-found", policy.GetProperty("policy-type").GetString());
        Assert.False(policy.TryGetProperty("policy-string", out _));
        Assert.False(policy.TryGetProperty("mx-host", out _));
    }

    [Fact]
    public void File_name_follows_rfc_8460_section_5_1()
    {
        var data = Sample();
        var report = new TlsRptReportBuilder(Options).Build(data);

        long begin = new DateTimeOffset(2026, 10, 11, 0, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();
        Assert.Equal($"sender.example!company-y.example!{begin}!{begin + 86399}!report-123.json.gz", report.FileName);
        Assert.Equal("application/tlsrpt+gzip", TlsRptReport.GzipMediaType);
        Assert.Equal(new DateTimeOffset(2026, 10, 11, 23, 59, 59, TimeSpan.Zero), report.End);
    }

    [Fact]
    public void File_name_parts_cannot_inject_separators()
    {
        var options = new TlsRptReportOptions { OrganizationName = "o", ContactInfo = "c", SubmitterDomain = "se!nder/..", ReportIdFactory = () => "a!b" };
        var collector = new TlsRptCollector(new TestClock());
        collector.RecordSuccess("example.com", TlsRptPolicyDescriptor.NoPolicy, "mx.example.com");
        var report = new TlsRptReportBuilder(options).Build(collector.Snapshot().Single());
        Assert.Equal(5, report.FileName.Split('!').Length);
        Assert.DoesNotContain('/', report.FileName);
    }

    [Fact]
    public void Default_report_ids_are_unique_and_json_special_characters_are_escaped()
    {
        var options = new TlsRptReportOptions { OrganizationName = "Org \"Quoted\" \\ <x>", ContactInfo = "c@example.com", SubmitterDomain = "sender.example" };
        var data = Sample();
        var a = new TlsRptReportBuilder(options).Build(data);
        var b = new TlsRptReportBuilder(options).Build(data);
        Assert.NotEqual(a.ReportId, b.ReportId);

        using var doc = JsonDocument.Parse(a.Json);
        Assert.Equal("Org \"Quoted\" \\ <x>", doc.RootElement.GetProperty("organization-name").GetString());
    }

    [Fact]
    public void Gzip_round_trip_and_decompression_bomb_guard()
    {
        byte[] payload = new byte[2_000_000];
        byte[] gz = TlsRptReportBuilder.Compress(payload);
        Assert.True(gz.Length < 10_000);
        Assert.Equal(payload, TlsRptReportBuilder.Decompress(gz));
        Assert.Throws<InvalidDataException>(() => TlsRptReportBuilder.Decompress(gz, maxBytes: 1000));
    }
}

public class TlsRptHttpsSenderTests
{
    private static readonly TlsRptEndpoint Https = new(TlsRptEndpointKind.Https, "https://reports.example.com/tlsrpt", null);

    private static TlsRptReport Report()
    {
        var collector = new TlsRptCollector(new TestClock());
        collector.RecordSuccess("example.com", TlsRptPolicyDescriptor.NoPolicy, "mx.example.com");
        return new TlsRptReportBuilder(new TlsRptReportOptions { OrganizationName = "o", ContactInfo = "c@example.com", SubmitterDomain = "s.example" }).Build(collector.Snapshot().Single());
    }

    [Fact]
    public async Task Posts_the_gzip_payload_with_the_tlsrpt_content_type()
    {
        var handler = new FakeHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        using var sender = new TlsRptHttpsSender(handler);
        var report = Report();
        var result = await sender.SendAsync(Https, report);

        Assert.True(result.Success);
        Assert.Equal(200, result.StatusCode);
        Assert.Equal(HttpMethod.Post, Assert.Single(handler.Requests).Method);
        Assert.Equal("https://reports.example.com/tlsrpt", Assert.Single(handler.RequestUris).ToString());
        Assert.Equal("application/tlsrpt+gzip", handler.LastRequestContentType);
        Assert.Equal(report.GzipPayload, handler.LastRequestBody);
    }

    [Theory]
    [InlineData(HttpStatusCode.Accepted, true)]
    [InlineData(HttpStatusCode.NoContent, true)]
    [InlineData(HttpStatusCode.BadRequest, false)]
    [InlineData(HttpStatusCode.InternalServerError, false)]
    [InlineData(HttpStatusCode.Found, false)]
    public async Task Status_classes_are_mapped(HttpStatusCode status, bool success)
    {
        using var sender = new TlsRptHttpsSender(new FakeHttpHandler(_ => new HttpResponseMessage(status)));
        var result = await sender.SendAsync(Https, Report());
        Assert.Equal(success, result.Success);
        Assert.Equal((int)status, result.StatusCode);
    }

    [Fact]
    public async Task Failures_do_not_throw()
    {
        using var refused = new TlsRptHttpsSender(new FakeHttpHandler((_, _) => throw new HttpRequestException("refused")));
        Assert.False((await refused.SendAsync(Https, Report())).Success);

        using var slow = new TlsRptHttpsSender(
            new FakeHttpHandler(async (_, ct) =>
            {
                await Task.Delay(Timeout.Infinite, ct);
                return new HttpResponseMessage();
            }),
            new TlsRptHttpsSenderOptions { Timeout = TimeSpan.FromMilliseconds(50) });
        var timedOut = await slow.SendAsync(Https, Report());
        Assert.False(timedOut.Success);
        Assert.Contains("timed out", timedOut.Error);
    }

    [Fact]
    public async Task Non_https_endpoints_and_oversized_payloads_are_refused_without_a_request()
    {
        var handler = new FakeHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        using var sender = new TlsRptHttpsSender(handler, new TlsRptHttpsSenderOptions { MaxPayloadBytes = 10 });

        Assert.False((await sender.SendAsync(new TlsRptEndpoint(TlsRptEndpointKind.Mailto, "mailto:a@example.com", "a@example.com"), Report())).Success);
        Assert.False((await sender.SendAsync(new TlsRptEndpoint(TlsRptEndpointKind.Https, "http://insecure.example.com/x", null), new byte[1])).Success);
        Assert.False((await sender.SendAsync(Https, new byte[11])).Success);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public void Default_handler_can_be_created()
    {
        using var sender = new TlsRptHttpsSender();
        Assert.NotNull(sender);
    }
}

public class PublicAddressGuardTests
{
    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("93.184.216.34", true)]
    [InlineData("2606:4700:4700::1111", true)]
    [InlineData("127.0.0.1", false)]
    [InlineData("10.1.2.3", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("172.31.255.255", false)]
    [InlineData("172.32.0.1", true)]
    [InlineData("192.168.1.1", false)]
    [InlineData("169.254.169.254", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("0.0.0.0", false)]
    [InlineData("224.0.0.1", false)]
    [InlineData("255.255.255.255", false)]
    [InlineData("198.18.0.1", false)]
    [InlineData("::1", false)]
    [InlineData("::", false)]
    [InlineData("fe80::1", false)]
    [InlineData("fc00::1", false)]
    [InlineData("fd12:3456::1", false)]
    [InlineData("ff02::1", false)]
    [InlineData("2001:db8::1", false)]
    [InlineData("::ffff:10.0.0.1", false)]
    [InlineData("::ffff:127.0.0.1", false)]
    [InlineData("::ffff:8.8.8.8", true)]
    public void Classifies_addresses(string address, bool isPublic)
    {
        Assert.Equal(isPublic, PublicAddressGuard.IsPublic(IPAddress.Parse(address)));
    }
}
