using System.Net;
using System.Text.Json;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

/// <summary>POST /messages/{id}/cancel (decision 80): authorization, validation, the per-recipient answer and the in-flight rule.</summary>
[Collection("api")]
public class ApiCancelTests : IAsyncLifetime
{
    private ApiFixture _f = null!;
    private ApiClient _a = null!;

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync();
        _a = await _f.KeyClientAsync(ApiFixture.TenantAId);
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private static Dictionary<string, object?> Body(params string[] to) => new()
    {
        ["from"] = "Acme <noreply@example.com>",
        ["to"] = to.Length == 0 ? new[] { "alex@gmail.test" } : to,
        ["subject"] = "Hello",
        ["text"] = "plain body",
    };

    private async Task<string> SendAsync(ApiClient client, params string[] to)
    {
        Reply r = await client.PostAsync("/api/v1/messages", Body(to));
        Assert.Equal(HttpStatusCode.Accepted, r.Status);
        return r.Str("id");
    }

    private static string[] Strings(JsonElement array) => array.EnumerateArray().Select(x => x.GetString()!).ToArray();

    private async Task<IReadOnlyList<ClaimedDelivery>> ClaimAsync(int max = 100, TimeSpan? lease = null) =>
        await _f.Storage.Deliveries.ClaimAsync("test", max, _f.Clock.UtcNow, lease ?? TimeSpan.FromMinutes(5), default);

    [Fact]
    public async Task Without_a_body_every_waiting_recipient_is_cancelled_and_never_delivered()
    {
        string id = await SendAsync(_a, "b@gmail.test", "a@gmail.test");

        Reply r = await _a.PostAsync($"/api/v1/messages/{id}/cancel");

        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal(id, r.Str("id"));
        Assert.Equal("cancelled", r.Str("status"));
        Assert.Equal(["a@gmail.test", "b@gmail.test"], Strings(r["cancelled"]));
        Assert.Equal(0, r["inFlight"].GetArrayLength());
        Assert.Equal(0, r["notWaiting"].GetArrayLength());
        Assert.Empty(await ClaimAsync());
        Reply events = await _a.GetAsync($"/api/v1/messages/{id}/events");
        Assert.Equal(2, events.Json.EnumerateArray().Count(e => e.GetProperty("type").GetString() == "cancelled"));
        Assert.Equal("cancelled", (await _a.GetAsync($"/api/v1/messages/{id}")).Str("status"));
        Assert.Equal("cancelled", (await _a.GetAsync("/api/v1/messages?status=cancelled"))["items"][0].GetProperty("status").GetString());
    }

    [Fact]
    public async Task Naming_recipients_cancels_only_those_and_reports_the_rest()
    {
        string id = await SendAsync(_a, "a@gmail.test", "b@gmail.test");

        Reply r = await _a.PostAsync($"/api/v1/messages/{id}/cancel", new { recipients = new[] { "B@Gmail.test", "stranger@gmail.test" } });

        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal(["b@gmail.test"], Strings(r["cancelled"]));
        Assert.Equal(["stranger@gmail.test"], Strings(r["notWaiting"]));
        Assert.Equal("queued", r.Str("status"));
        ClaimedDelivery left = Assert.Single(await ClaimAsync());
        Assert.Equal("a@gmail.test", left.Recipient.ToString());
    }

    [Fact]
    public async Task A_recipient_that_is_being_delivered_is_reported_in_flight_and_left_alone()
    {
        string id = await SendAsync(_a, "a@gmail.test", "b@gmail.test");
        ClaimedDelivery held = Assert.Single(await ClaimAsync(max: 1));

        Reply r = await _a.PostAsync($"/api/v1/messages/{id}/cancel");

        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal([held.Recipient.ToString()], Strings(r["inFlight"]));
        Assert.Single(Strings(r["cancelled"]));

        // Only in-flight recipients are left: nothing to cancel is a conflict that names them.
        Reply again = await _a.PostAsync($"/api/v1/messages/{id}/cancel");
        again.Problem(HttpStatusCode.Conflict, "conflict");
        Assert.Equal([held.Recipient.ToString()], Strings(again["inFlight"]));

        // The worker finishes as usual.
        await _f.Storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = held.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = _f.Clock.UtcNow, SmtpCode = 250 }, default);
        Assert.Equal("partial", (await _a.GetAsync($"/api/v1/messages/{id}")).Str("status"));
    }

    [Fact]
    public async Task Nothing_waiting_is_a_conflict_not_a_success()
    {
        string id = await SendAsync(_a);
        ClaimedDelivery d = Assert.Single(await ClaimAsync());
        await _f.Storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = _f.Clock.UtcNow, SmtpCode = 250 }, default);

        Reply r = await _a.PostAsync($"/api/v1/messages/{id}/cancel", new { recipients = new[] { "alex@gmail.test" } });

        r.Problem(HttpStatusCode.Conflict, "conflict");
        Assert.Equal(["alex@gmail.test"], Strings(r["notWaiting"]));
        Assert.Equal("delivered", (await _a.GetAsync($"/api/v1/messages/{id}")).Str("status"));
    }

    [Fact]
    public async Task Recipients_are_validated_and_an_empty_list_never_means_all()
    {
        string id = await SendAsync(_a);

        (await _a.PostAsync($"/api/v1/messages/{id}/cancel", new { recipients = Array.Empty<string>() })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        Reply bad = await _a.PostAsync($"/api/v1/messages/{id}/cancel", new { recipients = new[] { "alex@gmail.test", "not an address" } });
        bad.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal("recipients[1]", bad["errors"][0].GetProperty("field").GetString());
        (await _a.PostAsync($"/api/v1/messages/{id}/cancel", new { recipients = new[] { new string('a', 400) + "@x.test" } })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _a.PostAsync($"/api/v1/messages/{id}/cancel", "{\"recipients\":\"alex@gmail.test\"}")).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _a.PostAsync($"/api/v1/messages/{id}/cancel", "{\"all\":true}")).Problem(HttpStatusCode.BadRequest, "validation_failed");

        Assert.Single(await ClaimAsync());   // nothing was cancelled by any of the refused requests
    }

    [Fact]
    public async Task An_empty_json_object_cancels_everything_like_no_body()
    {
        string id = await SendAsync(_a);
        Assert.Equal(HttpStatusCode.OK, (await _a.PostAsync($"/api/v1/messages/{id}/cancel", "{}")).Status);
    }

    [Fact]
    public async Task Another_tenants_message_is_not_found_and_stays_deliverable()
    {
        ApiClient b = await _f.KeyClientAsync(ApiFixture.TenantBId);
        string idB = (await b.PostAsync("/api/v1/messages", new Dictionary<string, object?> { ["from"] = "me@globex.test", ["to"] = new[] { "x@y.test" }, ["subject"] = "B", ["text"] = "b" })).Str("id");

        (await _a.PostAsync($"/api/v1/messages/{idB}/cancel")).Problem(HttpStatusCode.NotFound, "message_not_found");
        (await _a.PostAsync($"/api/v1/messages/{idB}/cancel", new { recipients = new[] { "x@y.test" } })).Problem(HttpStatusCode.NotFound, "message_not_found");
        (await _a.PostAsync($"/api/v1/messages/{Guid.NewGuid():N}/cancel")).Problem(HttpStatusCode.NotFound, "message_not_found");
        (await _a.PostAsync("/api/v1/messages/not-an-id/cancel")).Problem(HttpStatusCode.NotFound, "message_not_found");

        Assert.Equal(1, (await _f.Storage.Deliveries.GetQueueStatsAsync(default)).Queued);   // the other tenant's message was not touched
        // An administrator acts on a tenant with X-Tenant-Id like for every tenant endpoint.
        ApiClient admin = (await _f.SignedInAsync("root")).ActingAs(ApiFixture.TenantBId);
        Reply r = await admin.PostAsync($"/api/v1/messages/{idB}/cancel");
        Assert.Equal(HttpStatusCode.OK, r.Status);
    }

    [Fact]
    public async Task Cancelling_needs_the_send_scope_and_a_csrf_token_for_a_session()
    {
        string id = await SendAsync(_a);
        ApiClient readOnly = await _f.KeyClientAsync(ApiFixture.TenantAId, "read");
        (await readOnly.PostAsync($"/api/v1/messages/{id}/cancel")).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await _f.NewClient().PostAsync($"/api/v1/messages/{id}/cancel")).Problem(HttpStatusCode.Unauthorized, "unauthorized");

        ApiClient session = await _f.SignedInAsync("alice");
        session.SendCsrf = false;
        (await session.PostAsync($"/api/v1/messages/{id}/cancel")).Problem(HttpStatusCode.Forbidden, "forbidden");
        Assert.Equal(1, (await _f.Storage.Deliveries.GetQueueStatsAsync(default)).Queued);   // still queued

        session.SendCsrf = true;
        Assert.Equal(HttpStatusCode.OK, (await session.PostAsync($"/api/v1/messages/{id}/cancel")).Status);

        ApiClient sendOnly = await _f.KeyClientAsync(ApiFixture.TenantAId, "send");
        string other = await SendAsync(sendOnly);
        Assert.Equal(HttpStatusCode.OK, (await sendOnly.PostAsync($"/api/v1/messages/{other}/cancel")).Status);
    }

    [Fact]
    public async Task Cancelling_works_without_history_and_an_unknown_or_finished_message_is_simply_not_found()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { History = HistoryMode.StatsOnly });
        ApiClient c = await f.KeyClientAsync(ApiFixture.TenantAId);
        string id = (await c.PostAsync("/api/v1/messages", Body("a@gmail.test", "b@gmail.test"))).Str("id");

        Reply r = await c.PostAsync($"/api/v1/messages/{id}/cancel", new { recipients = new[] { "a@gmail.test" } });

        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal(["a@gmail.test"], Strings(r["cancelled"]));
        Assert.False(r.Json.TryGetProperty("status", out _));   // no per-message status is recorded
        Assert.Equal("b@gmail.test", Assert.Single(await f.Storage.Deliveries.ClaimAsync("test", 10, f.Clock.UtcNow, TimeSpan.FromMinutes(1), default)).Recipient.ToString());

        // Nothing waiting any more: without history that cannot be told from an unknown message, so the answer is the 404 of an unknown one.
        string gone = (await c.PostAsync("/api/v1/messages", Body("c@gmail.test"))).Str("id");
        Assert.Equal(HttpStatusCode.OK, (await c.PostAsync($"/api/v1/messages/{gone}/cancel")).Status);
        (await c.PostAsync($"/api/v1/messages/{gone}/cancel")).Problem(HttpStatusCode.NotFound, "message_not_found");
        (await c.PostAsync($"/api/v1/messages/{Guid.NewGuid():N}/cancel")).Problem(HttpStatusCode.NotFound, "message_not_found");
        // Per-message reads stay unavailable.
        (await c.GetAsync($"/api/v1/messages/{id}")).Problem(HttpStatusCode.Gone, "history_not_recorded");
    }

    [Fact]
    public async Task Repeating_a_cancel_whose_work_is_done_is_a_success_with_nothing_cancelled()
    {
        string id = await SendAsync(_a, "a@gmail.test", "b@gmail.test");
        Assert.Equal(HttpStatusCode.OK, (await _a.PostAsync($"/api/v1/messages/{id}/cancel", new { recipients = new[] { "a@gmail.test" } })).Status);

        // Named recipient already cancelled (another one still waits): idempotent.
        Reply again = await _a.PostAsync($"/api/v1/messages/{id}/cancel", new { recipients = new[] { "A@Gmail.test" } });
        Assert.Equal(HttpStatusCode.OK, again.Status);
        Assert.Equal(0, again["cancelled"].GetArrayLength());
        Assert.Equal("queued", again.Str("status"));

        // A recipient that was not cancelled (never existed here) is still a conflict, also when mixed with a cancelled one.
        (await _a.PostAsync($"/api/v1/messages/{id}/cancel", new { recipients = new[] { "stranger@gmail.test" } })).Problem(HttpStatusCode.Conflict, "conflict");
        (await _a.PostAsync($"/api/v1/messages/{id}/cancel", new { recipients = new[] { "a@gmail.test", "stranger@gmail.test" } })).Problem(HttpStatusCode.Conflict, "conflict");

        // Without names: idempotent once the whole message is cancelled, a conflict when it ended any other way.
        Assert.Equal(HttpStatusCode.OK, (await _a.PostAsync($"/api/v1/messages/{id}/cancel")).Status);
        Reply whole = await _a.PostAsync($"/api/v1/messages/{id}/cancel");
        Assert.Equal(HttpStatusCode.OK, whole.Status);
        Assert.Equal("cancelled", whole.Str("status"));
        Assert.Equal(0, whole["cancelled"].GetArrayLength());

        string delivered = await SendAsync(_a);
        ClaimedDelivery d = Assert.Single(await ClaimAsync());
        await _f.Storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = _f.Clock.UtcNow, SmtpCode = 250 }, default);
        (await _a.PostAsync($"/api/v1/messages/{delivered}/cancel")).Problem(HttpStatusCode.Conflict, "conflict");
    }

    [Fact]
    public async Task A_cancel_publishes_a_message_cancelled_event_to_the_tenants_subscribed_endpoints()
    {
        Reply endpoint = await _a.PostAsync("/api/v1/webhooks", new { url = "https://hooks.example.com/cancel", event_types = new[] { "message.cancelled" } });
        Assert.Equal(HttpStatusCode.Created, endpoint.Status);
        await _a.PostAsync("/api/v1/webhooks", new { url = "https://hooks.example.com/delivered", event_types = new[] { "message.delivered" } });
        ApiClient b = await _f.KeyClientAsync(ApiFixture.TenantBId);
        await b.PostAsync("/api/v1/webhooks", new { url = "https://hooks.example.com/other-tenant", event_types = new[] { "*" } });
        string id = await SendAsync(_a, "a@gmail.test", "b@gmail.test");

        Assert.Equal(HttpStatusCode.OK, (await _a.PostAsync($"/api/v1/messages/{id}/cancel", new { recipients = new[] { "a@gmail.test" } })).Status);

        var items = await _f.Storage.Webhooks.ClaimDueAsync("test", 10, _f.Clock.UtcNow, TimeSpan.FromMinutes(1), default);
        WebhookOutboxItem item = Assert.Single(items);
        Assert.Equal(Guid.Parse(endpoint.Str("id")), item.EndpointId);
        Assert.Equal("message.cancelled", item.EventType);
        using var payload = JsonDocument.Parse(item.PayloadJson);
        Assert.Equal("message.cancelled", payload.RootElement.GetProperty("type").GetString());
        JsonElement data = payload.RootElement.GetProperty("data");
        Assert.Equal(id, data.GetProperty("message_id").GetString());
        Assert.Equal("a@gmail.test", data.GetProperty("recipient").GetString());
        Assert.Equal("noreply@example.com", data.GetProperty("from").GetString());
        Assert.Equal(0, data.GetProperty("attempt").GetInt32());
    }

    [Fact]
    public async Task A_recipient_held_by_a_backend_switch_is_reported_as_held_not_as_being_delivered()
    {
        string id = await SendAsync(_a);
        Guid switchId = Guid.NewGuid();
        Assert.Equal(1, await _f.Storage.Transfer!.MarkQueueTransferredAsync(switchId, default));

        Reply r = await _a.PostAsync($"/api/v1/messages/{id}/cancel");

        r.Problem(HttpStatusCode.Conflict, "conflict");
        Assert.Equal(["alex@gmail.test"], Strings(r["transferHeld"]));
        Assert.Equal(0, r["inFlight"].GetArrayLength());
        Assert.Contains("switch", r.Json.GetProperty("detail").GetString());
        Assert.DoesNotContain("being delivered", r.Json.GetProperty("detail").GetString());
    }
}
