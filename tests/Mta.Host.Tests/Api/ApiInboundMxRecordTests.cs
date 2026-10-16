using System.Net;
using System.Text.Json;

namespace Mta.Host.Tests.Api;

/// <summary>The inbound MX in the records of a domain (design section 11.3).</summary>
[Collection("api")]
public class ApiInboundMxRecordTests
{
    [Fact]
    public async Task The_records_gain_the_inbound_mx_when_inbound_is_enabled_for_the_domain_and_lose_it_when_it_is_disabled()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.DomainRecords = new Mta.Host.Domains.DomainRecordOptions { ServerHostname = "mta.egg.test" } });
        ApiClient a = await f.KeyClientAsync(ApiFixture.TenantAId);
        Reply created = await a.PostAsync("/api/v1/domains", new { name = "inbound.example" });
        string id = created.Str("id");
        Assert.DoesNotContain(created["records"].EnumerateArray(), r => r.GetProperty("purpose").GetString() == "inbound_mx");

        // Make the domain verified, then enable inbound.
        var domain = (await f.Storage.Config.GetDomainAsync(Guid.ParseExact(id, "N"), default))!;
        await f.Storage.Config.UpsertDomainAsync(domain with { Status = Mta.Storage.DomainStatus.Verified }, default);
        Reply enabled = await a.PatchAsync($"/api/v1/domains/{id}/inbound", new { enabled = true });
        Assert.Equal(HttpStatusCode.OK, enabled.Status);

        Reply records = await a.GetAsync($"/api/v1/domains/{id}/records");
        JsonElement mx = records["records"].EnumerateArray().Single(r => r.GetProperty("purpose").GetString() == "inbound_mx");
        Assert.Equal("MX", mx.GetProperty("type").GetString());
        Assert.Equal("inbound.example", mx.GetProperty("host").GetString());
        Assert.Equal("10 mta.egg.test", mx.GetProperty("value").GetString());
        Assert.False(mx.GetProperty("required").GetBoolean());
        Assert.True(mx.GetProperty("publishable").GetBoolean());
        Assert.Equal("pending", mx.GetProperty("status").GetString());

        f.Dns.AddMx("inbound.example", 10, "mta.egg.test");
        f.Clock.Advance(TimeSpan.FromSeconds(31));
        Reply checkedDomain = await a.PostAsync($"/api/v1/domains/{id}/verify");
        Assert.Equal("ok", checkedDomain["records"].EnumerateArray().Single(r => r.GetProperty("purpose").GetString() == "inbound_mx").GetProperty("status").GetString());

        await a.PatchAsync($"/api/v1/domains/{id}/inbound", new { enabled = false });
        Reply after = await a.GetAsync($"/api/v1/domains/{id}/records");
        Assert.DoesNotContain(after["records"].EnumerateArray(), r => r.GetProperty("purpose").GetString() == "inbound_mx");
    }
}
