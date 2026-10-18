using System.Net;

namespace Mta.Host.Tests.Api;

/// <summary>
/// Found by the API leak check: ids come from URLs. A GUID whose first 48 bits read as a time beyond the year 9999 (about one random GUID in ten) made the
/// history lookup throw and the API answer 500 instead of 404 (the storage conformance suite holds the same fact for every backend).
/// </summary>
[Collection("api")]
public class ApiUnknownMessageIdTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task An_id_that_is_not_a_uuid_v7_is_not_found_and_not_a_server_error(bool sqlite)
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { Sqlite = sqlite });
        ApiClient key = await f.KeyClientAsync(ApiFixture.TenantAId);
        foreach (string id in new[] { "ffffffffffffffffffffffffffffffff", "f82354e1c8e34b2e82dad07d476795df", "00000000000000000000000000000000" })
        {
            (await key.GetAsync("/api/v1/messages/" + id)).Problem(HttpStatusCode.NotFound, "message_not_found");
            (await key.GetAsync($"/api/v1/messages/{id}/events")).Problem(HttpStatusCode.NotFound, "message_not_found");
            (await key.GetAsync($"/api/v1/messages/{id}/content")).Problem(HttpStatusCode.NotFound, "message_not_found");
            (await key.PostAsync($"/api/v1/messages/{id}/resend")).Problem(HttpStatusCode.NotFound, "message_not_found");
            (await key.PostAsync($"/api/v1/messages/{id}/cancel")).Problem(HttpStatusCode.NotFound, "message_not_found");
        }
    }
}
