using System.Net;
using System.Text.Json;
using Mta.Host.Api;
using Mta.Host.Domains;

namespace Mta.Host.Tests.Api;

/// <summary>
/// The records endpoint and the check of a domain with the whole record set configured: host name, sending IP, MTA-STS serving. DNS is the fixture's
/// controllable resolver; every record is published, broken in one specific way, or left out.
/// </summary>
[Collection("api")]
public class ApiDomainOnboardingTests : IAsyncLifetime
{
    private const string Server = "mta.egg.test";
    private const string SendingIp = "192.0.2.10";

    private ApiFixture _f = null!;
    private ApiClient _a = null!;

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync(new ApiFixtureOptions
        {
            ConfigureApi = o => o.DomainRecords = new DomainRecordOptions
            {
                BounceDomain = "bounces.egg.test",
                ServerHostname = Server,
                PublicSendingIp = SendingIp,
                MtaStsMode = MtaStsServingMode.Testing,
            },
        });
        _a = await _f.KeyClientAsync(ApiFixture.TenantAId);
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private async Task<JsonElement> CreateAsync(string name)
    {
        Reply r = await _a.PostAsync("/api/v1/domains", new { name });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        return r.Json.Clone();
    }

    private async Task<JsonElement> CheckAsync(JsonElement domain)
    {
        _f.Clock.Advance(TimeSpan.FromSeconds(31));   // "Check DNS" is limited to once per 30 seconds per domain
        Reply r = await _a.PostAsync($"/api/v1/domains/{domain.GetProperty("id").GetString()}/verify");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        return r.Json.Clone();
    }

    private static JsonElement Record(JsonElement domain, string purpose) =>
        domain.GetProperty("records").EnumerateArray().Single(r => r.GetProperty("purpose").GetString() == purpose);

    private static string StatusOf(JsonElement domain, string purpose) => Record(domain, purpose).GetProperty("status").GetString()!;

    /// <summary>Publishes what the domain asks for (all of it, or only <paramref name="purposes"/>), the way a correct DNS setup would.</summary>
    private void Publish(JsonElement domain, params string[] purposes)
    {
        if (purposes.Length == 0)
        {
            _f.Dns.AddA(Server, SendingIp);
            _f.Dns.AddPtr(IPAddress.Parse(SendingIp), Server);
        }

        foreach (JsonElement rec in domain.GetProperty("records").EnumerateArray())
        {
            string purpose = rec.GetProperty("purpose").GetString()!;
            if (purposes.Length > 0 && !purposes.Contains(purpose))
            {
                continue;
            }

            string host = rec.GetProperty("host").GetString()!;
            string value = rec.GetProperty("value").GetString()!;
            switch (rec.GetProperty("type").GetString())
            {
                case "CNAME":
                    _f.Dns.AddCname(host, value);
                    break;
                case "MX":
                    _f.Dns.AddMx(host, ushort.Parse(value.Split(' ')[0]), value.Split(' ')[1]);
                    break;
                case "TXT":
                    _f.Dns.AddTxt(host, value);
                    break;
            }
        }
    }

    [Fact]
    public async Task A_new_domain_lists_every_record_to_publish_with_the_purpose_and_whether_it_is_required()
    {
        JsonElement d = await CreateAsync("onboard.example");
        Assert.Equal(
            ["dkim", "return_path", "spf", "dmarc", "tls_rpt", "mta_sts", "mta_sts_host", "bounce_mx", "ptr"],
            d.GetProperty("records").EnumerateArray().Select(r => r.GetProperty("purpose").GetString()!));
        Assert.Equal(["dkim", "return_path"], d.GetProperty("records").EnumerateArray().Where(r => r.GetProperty("required").GetBoolean()).Select(r => r.GetProperty("purpose").GetString()!));

        Assert.Equal($"v=spf1 ip4:{SendingIp} ~all", Record(d, "spf").GetProperty("value").GetString());
        Assert.Equal("v=DMARC1; p=none; rua=mailto:dmarc@onboard.example", Record(d, "dmarc").GetProperty("value").GetString());
        Assert.Equal("_smtp._tls.onboard.example", Record(d, "tls_rpt").GetProperty("host").GetString());
        Assert.Equal("_mta-sts.onboard.example", Record(d, "mta_sts").GetProperty("host").GetString());
        Assert.Matches("^v=STSv1; id=[0-9a-f]{16}$", Record(d, "mta_sts").GetProperty("value").GetString());
        Assert.Equal(("CNAME", "mta-sts.onboard.example", Server), (Record(d, "mta_sts_host").GetProperty("type").GetString()!, Record(d, "mta_sts_host").GetProperty("host").GetString()!, Record(d, "mta_sts_host").GetProperty("value").GetString()!));
        Assert.Equal(("MX", "bounces.egg.test", "10 " + Server), (Record(d, "bounce_mx").GetProperty("type").GetString()!, Record(d, "bounce_mx").GetProperty("host").GetString()!, Record(d, "bounce_mx").GetProperty("value").GetString()!));
        Assert.Equal(("PTR", "10.2.0.192.in-addr.arpa", Server), (Record(d, "ptr").GetProperty("type").GetString()!, Record(d, "ptr").GetProperty("host").GetString()!, Record(d, "ptr").GetProperty("value").GetString()!));
    }

    [Fact]
    public async Task The_records_endpoint_returns_all_records_a_zone_file_and_the_mta_sts_policy()
    {
        JsonElement d = await CreateAsync("onboard.example");
        string id = d.GetProperty("id").GetString()!;
        Reply r = await _a.GetAsync($"/api/v1/domains/{id}/records");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal(id, r.Str("id"));
        Assert.Equal("onboard.example", r.Str("name"));
        Assert.False(r["readyToSend"].GetBoolean());
        Assert.Equal(9, r["records"].GetArrayLength());

        string zone = r.Str("zoneFile");
        Assert.Contains("; DNS records for onboard.example", zone);
        Assert.Contains("; DKIM (required):", zone);
        Assert.Contains("; DMARC (recommended):", zone);
        Assert.Contains("onboard.example. 3600 IN TXT \"v=spf1 ip4:192.0.2.10 ~all\"", zone);
        Assert.Contains("_dmarc.onboard.example. 3600 IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc@onboard.example\"", zone);
        Assert.Contains("bounce.onboard.example. 3600 IN CNAME bounces.egg.test.", zone);
        Assert.Contains("; MX bounces.egg.test -> 10 mta.egg.test (published once by whoever runs EggMail, not in this zone)", zone);   // the bounce domain is outside the customer's zone
        Assert.Contains("mta-sts.onboard.example. 3600 IN CNAME mta.egg.test.", zone);
        Assert.Contains("_smtp._tls.onboard.example. 3600 IN TXT \"v=TLSRPTv1; rua=mailto:tls-rpt@onboard.example\"", zone);
        Assert.Contains("; PTR 10.2.0.192.in-addr.arpa -> mta.egg.test", zone);   // reverse DNS is advice, not a zone line
        // The DKIM key is longer than 255 characters, so it is written as several quoted strings.
        string dkimLine = zone.Split('\n').Single(l => l.Contains("._domainkey.onboard.example. 3600 IN TXT"));
        Assert.Matches("\"v=DKIM1; k=rsa; p=[^\"]+\" \"[^\"]+\"$", dkimLine);

        JsonElement policy = r["mtaStsPolicy"];
        Assert.Equal("https://mta-sts.onboard.example/.well-known/mta-sts.txt", policy.GetProperty("url").GetString());
        Assert.Equal("mta-sts.onboard.example", policy.GetProperty("host").GetString());
        Assert.Equal("version: STSv1\r\nmode: testing\r\nmx: mta.egg.test\r\nmax_age: 604800\r\n", policy.GetProperty("content").GetString());
    }

    [Fact]
    public async Task Records_the_customer_cannot_publish_in_the_zone_are_marked_so()
    {
        JsonElement d = await CreateAsync("onboard.example");
        Assert.All(d.GetProperty("records").EnumerateArray(), rec =>
        {
            string purpose = rec.GetProperty("purpose").GetString()!;
            Assert.Equal(purpose is not ("bounce_mx" or "ptr"), rec.GetProperty("publishable").GetBoolean());   // the operator's bounce MX and the reverse DNS are advice
        });
    }

    [Fact]
    public async Task A_huge_record_found_in_dns_is_stored_and_shown_truncated()
    {
        JsonElement d = await CreateAsync("onboard.example");
        _f.Dns.AddTxt("_dmarc.onboard.example", "v=DMARC1; p=none; rua=mailto:" + new string('a', 6000) + "@x.test");
        JsonElement c = await CheckAsync(d);
        string found = Record(c, "dmarc").GetProperty("found").GetString()!;
        Assert.Equal("ok", StatusOf(c, "dmarc"));
        Assert.True(found.Length <= DomainVerificationService.MaxFoundLength + 32, found.Length.ToString());
        Assert.EndsWith("... (truncated)", found);
        Assert.StartsWith("v=DMARC1; p=none; rua=mailto:aaaa", found);
    }

    [Fact]
    public async Task The_zone_format_answers_plain_text()
    {
        JsonElement d = await CreateAsync("onboard.example");
        Reply r = await _a.GetAsync($"/api/v1/domains/{d.GetProperty("id").GetString()}/records?format=zone");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("text/plain", r.ContentType);
        Assert.StartsWith("; DNS records for onboard.example", r.Body);
    }

    [Fact]
    public async Task The_records_endpoint_is_scoped_to_the_tenant_and_the_domains_scope()
    {
        JsonElement d = await CreateAsync("onboard.example");
        string path = $"/api/v1/domains/{d.GetProperty("id").GetString()}/records";
        ApiClient other = await _f.KeyClientAsync(ApiFixture.TenantBId);
        (await other.GetAsync(path)).Problem(HttpStatusCode.NotFound, "not_found");
        ApiClient sendOnly = await _f.KeyClientAsync(ApiFixture.TenantAId, "send");
        (await sendOnly.GetAsync(path)).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await _f.NewClient().GetAsync(path)).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        (await _a.GetAsync("/api/v1/domains/not-an-id/records")).Problem(HttpStatusCode.NotFound, "not_found");
    }

    [Fact]
    public async Task Check_dns_with_everything_published_is_ready_to_send_and_every_record_is_ok()
    {
        JsonElement d = await CreateAsync("onboard.example");
        Publish(d);
        JsonElement checkedDomain = await CheckAsync(d);
        Assert.Equal("verified", checkedDomain.GetProperty("status").GetString());
        Assert.True(checkedDomain.GetProperty("readyToSend").GetBoolean());
        Assert.All(checkedDomain.GetProperty("records").EnumerateArray(), rec => Assert.Equal("ok", rec.GetProperty("status").GetString()));
        Assert.Equal(Server, Record(checkedDomain, "mta_sts_host").GetProperty("found").GetString());
        Assert.Equal("10 " + Server, Record(checkedDomain, "bounce_mx").GetProperty("found").GetString());
        Assert.Contains(Server, Record(checkedDomain, "ptr").GetProperty("found").GetString());

        // The records endpoint reports the same state without another lookup.
        Reply records = await _a.GetAsync($"/api/v1/domains/{d.GetProperty("id").GetString()}/records");
        Assert.True(records["readyToSend"].GetBoolean());
        Assert.All(records["records"].EnumerateArray(), rec => Assert.Equal("ok", rec.GetProperty("status").GetString()));
    }

    [Fact]
    public async Task Only_the_required_records_are_needed_to_send_the_recommended_ones_show_what_is_still_missing()
    {
        JsonElement d = await CreateAsync("onboard.example");
        Publish(d, "dkim", "return_path");
        JsonElement c = await CheckAsync(d);
        Assert.True(c.GetProperty("readyToSend").GetBoolean());
        Assert.Equal("ok", StatusOf(c, "dkim"));
        foreach (string purpose in new[] { "spf", "dmarc", "tls_rpt", "mta_sts", "mta_sts_host", "bounce_mx" })
        {
            Assert.Equal("missing", StatusOf(c, purpose));
            Assert.Equal(JsonValueKind.Null, Record(c, purpose).GetProperty("found").ValueKind);
        }
    }

    [Fact]
    public async Task Each_record_type_reports_a_mismatch_or_invalid_value_with_what_was_found()
    {
        JsonElement d = await CreateAsync("onboard.example");
        Publish(d, "dkim", "return_path");
        _f.Dns.AddA(Server, SendingIp);
        _f.Dns.AddTxt("onboard.example", "v=spf1 include:_spf.elsewhere.test ~all");      // another sender only: ours is missing from it
        _f.Dns.AddTxt("_dmarc.onboard.example", "v=DMARC1; p=banana");                     // not a policy
        _f.Dns.AddTxt("_smtp._tls.onboard.example", "v=TLSRPTv1; rua=ftp://nope.test");     // not a mailto: or https: destination
        _f.Dns.AddTxt("_mta-sts.onboard.example", "v=STSv1; id=oldoldold");                // older policy id
        _f.Dns.AddCname("mta-sts.onboard.example", "elsewhere.test");                      // leads to another server
        _f.Dns.AddMx("bounces.egg.test", 10, "mx.elsewhere.test");                        // bounces go elsewhere
        _f.Dns.AddPtr(IPAddress.Parse(SendingIp), "ptr.elsewhere.test");                   // wrong reverse name

        JsonElement c = await CheckAsync(d);
        Assert.Equal("mismatch", StatusOf(c, "spf"));
        Assert.Equal("v=spf1 include:_spf.elsewhere.test ~all", Record(c, "spf").GetProperty("found").GetString());
        Assert.Equal("invalid", StatusOf(c, "dmarc"));
        Assert.Equal("invalid", StatusOf(c, "tls_rpt"));
        Assert.Equal("mismatch", StatusOf(c, "mta_sts"));
        Assert.Equal("v=STSv1; id=oldoldold", Record(c, "mta_sts").GetProperty("found").GetString());
        Assert.Equal("mismatch", StatusOf(c, "mta_sts_host"));
        Assert.Equal("elsewhere.test", Record(c, "mta_sts_host").GetProperty("found").GetString());
        Assert.Equal("mismatch", StatusOf(c, "bounce_mx"));
        Assert.Equal("10 mx.elsewhere.test", Record(c, "bounce_mx").GetProperty("found").GetString());
        Assert.Equal("mismatch", StatusOf(c, "ptr"));
        Assert.Contains("ptr.elsewhere.test", Record(c, "ptr").GetProperty("found").GetString());
        // Advice never blocks sending.
        Assert.True(c.GetProperty("readyToSend").GetBoolean());
        Assert.Equal("verified", c.GetProperty("status").GetString());
    }

    [Fact]
    public async Task A_wrong_required_record_blocks_sending_and_says_which()
    {
        JsonElement d = await CreateAsync("onboard.example");
        Publish(d, "dkim");
        _f.Dns.AddCname("bounce.onboard.example", "someone-else.test");
        JsonElement c = await CheckAsync(d);
        Assert.False(c.GetProperty("readyToSend").GetBoolean());
        Assert.Equal("mismatch", StatusOf(c, "return_path"));
        Assert.Equal("someone-else.test", Record(c, "return_path").GetProperty("found").GetString());
        Assert.Contains("ReturnPath record bounce.onboard.example does not have the expected value", c.GetProperty("lastError").GetString());
    }

    [Fact]
    public async Task A_domain_in_temporary_failure_is_still_ready_to_send()
    {
        JsonElement d = await CreateAsync("onboard.example");
        Publish(d, "dkim", "return_path");
        await CheckAsync(d);
        _f.Dns.RemoveAll("onboard.example");
        _f.Dns.RemoveAll("bounce.onboard.example");
        _f.Dns.RemoveAll(Record(d, "dkim").GetProperty("host").GetString()!);
        JsonElement first = await CheckAsync(d);
        JsonElement second = await CheckAsync(d);
        Assert.Equal("temporary_failure", second.GetProperty("status").GetString());
        Assert.True(second.GetProperty("readyToSend").GetBoolean());
        Assert.Equal("verified", first.GetProperty("status").GetString());   // the first failure is only confirmed later (design §8)
    }
}
