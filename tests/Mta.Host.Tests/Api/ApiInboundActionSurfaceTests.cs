using System.Net;

namespace Mta.Host.Tests.Api;

/// <summary>What the route actions add to the public API: the capability flag and the webhook event type for a failed action.</summary>
[Collection("api")]
public class ApiInboundActionSurfaceTests
{
    [Fact]
    public async Task Capabilities_report_the_master_switch_of_inbound_mail()
    {
        await using ApiFixture off = await ApiFixture.StartAsync();
        Reply defaultReply = await off.NewClient().GetAsync("/api/v1/capabilities");
        Assert.False(defaultReply["inbound"].GetProperty("enabled").GetBoolean());

        await using ApiFixture on = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.InboundEnabled = true });
        Reply enabled = await on.NewClient().GetAsync("/api/v1/capabilities");
        Assert.True(enabled["inbound"].GetProperty("enabled").GetBoolean());
    }

    [Fact]
    public async Task A_webhook_can_subscribe_to_failed_inbound_actions_and_to_nothing_else_inbound()
    {
        await using ApiFixture f = await ApiFixture.StartAsync();
        ApiClient c = await f.KeyClientAsync(ApiFixture.TenantAId);

        Reply ok = await c.PostAsync("/api/v1/webhooks", new { url = "https://hooks.acme.example/eggmail", event_types = new[] { "inbound.action.failed" } });
        Assert.Equal(HttpStatusCode.Created, ok.Status);

        // inbound.message.received is the body of a route's webhook, not an event an endpoint subscribes to.
        Reply refused = await c.PostAsync("/api/v1/webhooks", new { url = "https://hooks.acme.example/eggmail2", event_types = new[] { "inbound.message.received" } });
        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
    }
}
