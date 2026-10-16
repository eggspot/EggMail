using System.Net;
using System.Text;
using System.Text.Json;
using Mta.Core;
using Mta.Host.Inbound;
using Mta.Storage;
using Mta.Webhooks;

namespace Mta.Host.Tests.Inbound;

/// <summary>The webhook route action (design section 11.7): payload formats, signing, the retry ladder, deferrals, manual retries and the guards.</summary>
[Collection("inbound-actions")]
public class InboundWebhookActionTests
{
    private static JsonElement Json(FakeReceiver.Request request) => JsonDocument.Parse(request.Body).RootElement;

    [Fact]
    public async Task The_json_format_is_signed_names_the_attachments_by_reference_and_keeps_the_body()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        InboundMessageDraft draft = await h.ReceiveAsync(InboundActionHarness.MessageWithAttachment());

        Assert.Equal(1, await h.RunAsync());

        FakeReceiver.Request sent = Assert.Single(h.Receiver.Requests);
        Assert.Equal("https://hooks.example.test/inbound", sent.Url.ToString());
        string expectedId = "evt_" + Ids.ToCompact(draft.Id);
        Assert.Equal(expectedId, sent.Headers["webhook-id"]);
        Assert.True(StandardWebhooksSigner.Verify(expectedId, sent.Headers["webhook-timestamp"], sent.Headers["webhook-signature"], sent.Body, [InboundActionHarness.Secret], h.Clock.UtcNow));
        Assert.StartsWith("application/json", sent.ContentType, StringComparison.Ordinal);

        JsonElement root = Json(sent);
        Assert.Equal(expectedId, root.GetProperty("id").GetString());
        Assert.Equal("inbound.message.received", root.GetProperty("type").GetString());
        JsonElement data = root.GetProperty("data");
        Assert.Equal(Ids.ToCompact(draft.Id), data.GetProperty("inbound_id").GetString());
        Assert.Equal("example.com", data.GetProperty("domain").GetString());
        Assert.Equal(Ids.ToCompact(h.Route.Id), data.GetProperty("route_id").GetString());
        Assert.Equal("alice@sender.test", data.GetProperty("envelope").GetProperty("from").GetString());
        Assert.Equal("203.0.113.9", data.GetProperty("connection").GetProperty("remote_ip").GetString());
        Assert.True(data.GetProperty("connection").GetProperty("tls").GetBoolean());
        Assert.Equal("pass", data.GetProperty("auth").GetProperty("dkim").GetProperty("result").GetString());
        Assert.Equal("reject", data.GetProperty("auth").GetProperty("dmarc").GetProperty("policy").GetString());
        Assert.False(data.GetProperty("dmarc_flagged").GetBoolean());

        JsonElement message = data.GetProperty("message");
        Assert.Equal("<m2@sender.test>", message.GetProperty("message_id").GetString());
        Assert.Equal("With file", message.GetProperty("subject").GetString());
        Assert.Equal(2, message.GetProperty("to").GetArrayLength());
        Assert.Equal(1, message.GetProperty("cc").GetArrayLength());
        Assert.Contains("See attached.", message.GetProperty("text").GetString(), StringComparison.Ordinal);
        Assert.Contains("<b>attached</b>", message.GetProperty("html").GetString(), StringComparison.Ordinal);
        Assert.False(message.GetProperty("truncated").GetBoolean());

        // Attachments by reference: a path, never the content (and no credential in it).
        JsonElement attachment = Assert.Single(data.GetProperty("attachments").EnumerateArray());
        Assert.Equal("report.pdf", attachment.GetProperty("filename").GetString());
        Assert.Equal("application/pdf", attachment.GetProperty("content_type").GetString());
        Assert.Equal("/api/v1/inbound/messages/" + Ids.ToCompact(draft.Id) + "/attachments/0", attachment.GetProperty("url").GetString());
        Assert.DoesNotContain("SGVsbG8", Encoding.UTF8.GetString(sent.Body), StringComparison.Ordinal);
        Assert.Equal("/api/v1/inbound/messages/" + Ids.ToCompact(draft.Id) + "/raw", data.GetProperty("raw_url").GetString());

        InboundMessage stored = await h.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Done, stored.ActionState);
        Assert.Equal(1, stored.ActionAttempts);
        Assert.True(stored.HasRaw);   // attachments are fetched later: a completed webhook keeps the body until retention
        Assert.Null(stored.ActionLastError);
    }

    [Fact]
    public async Task The_api_base_url_prefixes_the_paths_of_the_payload()
    {
        var options = new InboundActionOptions { ApiBaseUrl = "https://mail.example.com/" };
        await using var h = await new InboundActionHarness(options).InitializeAsync();
        InboundMessageDraft draft = await h.ReceiveAsync();

        await h.RunAsync();

        string url = Json(Assert.Single(h.Receiver.Requests)).GetProperty("data").GetProperty("raw_url").GetString()!;
        Assert.Equal("https://mail.example.com/api/v1/inbound/messages/" + Ids.ToCompact(draft.Id) + "/raw", url);
    }

    [Fact]
    public async Task Text_is_cut_at_the_configured_size_and_the_payload_says_so()
    {
        var options = new InboundActionOptions { WebhookMaxTextBytes = 1024 };
        await using var h = await new InboundActionHarness(options).InitializeAsync();
        await h.ReceiveAsync(InboundActionHarness.SimpleMessage(body: new string('x', 5000) + "\r\n"));

        await h.RunAsync();

        JsonElement message = Json(Assert.Single(h.Receiver.Requests)).GetProperty("data").GetProperty("message");
        Assert.True(message.GetProperty("truncated").GetBoolean());
        Assert.True(Encoding.UTF8.GetByteCount(message.GetProperty("text").GetString()!) <= 1024);
    }

    [Fact]
    public async Task A_hostile_message_cannot_break_the_payload()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        // Raw 8-bit bytes in the headers, a lone surrogate through an encoded word, control characters and quotes in values.
        byte[] raw = [.. Encoding.ASCII.GetBytes("From: \"Mallory\\\" <x@y.test>\r\nSubject: =?utf-16?B?2AA=?= \"quoted\" \u0001\r\nX-Evil: </script>\r\nContent-Type: text/plain\r\n\r\n"), 0xFF, 0xFE, (byte)'\r', (byte)'\n'];
        await h.ReceiveAsync(raw);

        await h.RunAsync();

        FakeReceiver.Request sent = Assert.Single(h.Receiver.Requests);
        using JsonDocument document = JsonDocument.Parse(sent.Body);   // still valid JSON
        Assert.Equal("inbound.message.received", document.RootElement.GetProperty("type").GetString());
        Assert.DoesNotContain("</script>", Encoding.UTF8.GetString(sent.Body), StringComparison.Ordinal);   // the default encoder escapes < and >
    }

    [Fact]
    public async Task The_raw_mime_format_posts_the_stored_bytes_with_percent_encoded_envelope_headers()
    {
        await using var h = await new InboundActionHarness().InitializeAsync(format: InboundWebhookFormat.RawMime);
        byte[] raw = InboundActionHarness.SimpleMessage();
        InboundMessageDraft draft = await h.ReceiveAsync(raw, from: "weird \"name\"\r\nX-Injected: 1<bü@sender.test", to: "support@example.com");

        await h.RunAsync();

        FakeReceiver.Request sent = Assert.Single(h.Receiver.Requests);
        Assert.Equal(raw, sent.Body);
        Assert.StartsWith("message/rfc822", sent.ContentType, StringComparison.Ordinal);
        string expectedId = "evt_" + Ids.ToCompact(draft.Id);
        Assert.True(StandardWebhooksSigner.Verify(expectedId, sent.Headers["webhook-timestamp"], sent.Headers["webhook-signature"], raw, [InboundActionHarness.Secret], h.Clock.UtcNow));
        Assert.Equal(Ids.ToCompact(draft.Id), sent.Headers["EggMail-Inbound-Id"]);
        Assert.Equal("support@example.com", sent.Headers["EggMail-Envelope-To"]);
        Assert.Equal("pass", sent.Headers["EggMail-Dmarc"]);
        Assert.Equal("false", sent.Headers["EggMail-Dmarc-Flagged"]);
        string from = sent.Headers["EggMail-Envelope-From"];
        Assert.All(from, c => Assert.True(c is > ' ' and < '\u007f', $"character {(int)c} in a header value"));
        Assert.DoesNotContain("X-Injected", sent.Headers.Keys);
        Assert.Contains("%20%22name%22", from, StringComparison.Ordinal);   // (the store already removed the control characters; the encoder is pinned for them in the unit test)
        Assert.Contains("%C3%BC", from, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_message_too_large_for_the_raw_format_fails_at_once_without_a_request_and_tells_the_tenant()
    {
        var options = new InboundActionOptions { WebhookMaxRawMessageBytes = 100 };
        await using var h = await new InboundActionHarness(options).InitializeAsync(format: InboundWebhookFormat.RawMime);
        InboundMessageDraft draft = await h.ReceiveAsync(InboundActionHarness.SimpleMessage(body: new string('y', 500)));

        await h.RunAsync();

        Assert.Empty(h.Receiver.Requests);
        InboundMessage stored = await h.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Failed, stored.ActionState);
        Assert.Equal("too_large_for_raw_webhook", stored.ActionLastError);
        (Guid tenant, WebhookEventDraft ev) = Assert.Single(h.Publisher.Published);
        Assert.Equal(h.TenantId, tenant);
        Assert.Equal("inbound.action.failed", ev.EventType);
        JsonElement data = JsonDocument.Parse(ev.PayloadJson).RootElement.GetProperty("data");
        Assert.Equal(Ids.ToCompact(draft.Id), data.GetProperty("inbound_id").GetString());
        Assert.Equal("webhook", data.GetProperty("action").GetString());
        Assert.Equal("too_large_for_raw_webhook", data.GetProperty("error").GetString());
    }

    [Fact]
    public async Task A_failing_receiver_follows_the_ladder_repeats_the_id_and_ends_failed_once()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();   // schedule 10 s, 1 m, 10 m: four attempts
        h.Receiver.Respond(HttpStatusCode.InternalServerError);
        InboundMessageDraft draft = await h.ReceiveAsync();

        Assert.Equal(1, await h.RunAsync());
        InboundMessage afterFirst = await h.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Pending, afterFirst.ActionState);
        Assert.Equal(1, afterFirst.ActionAttempts);
        Assert.Equal(h.Clock.UtcNow + TimeSpan.FromSeconds(10), afterFirst.ActionNextAttemptAt);
        Assert.Equal("webhook_http_500", afterFirst.ActionLastError);

        Assert.Equal(0, await h.RunAsync());   // not due yet
        h.Clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(1, await h.RunAsync());
        InboundMessage afterSecond = await h.GetAsync(draft.Id);
        Assert.Equal(2, afterSecond.ActionAttempts);
        Assert.Equal(h.Clock.UtcNow + TimeSpan.FromMinutes(1), afterSecond.ActionNextAttemptAt);

        h.Clock.Advance(TimeSpan.FromMinutes(1));
        await h.RunAsync();
        h.Clock.Advance(TimeSpan.FromMinutes(10));
        Assert.Equal(1, await h.RunAsync());

        InboundMessage last = await h.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Failed, last.ActionState);
        Assert.Equal(4, last.ActionAttempts);
        Assert.Equal("webhook_http_500", last.ActionLastError);
        Assert.Equal(4, h.Receiver.Requests.Count);
        Assert.All(h.Receiver.Requests, r => Assert.Equal("evt_" + Ids.ToCompact(draft.Id), r.Headers["webhook-id"]));   // automatic retries repeat the id
        Assert.Single(h.Publisher.Published);   // one notice, when it gave up
    }

    [Fact]
    public async Task A_manual_retry_is_a_new_event_for_the_receiver()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        InboundMessageDraft draft = await h.ReceiveAsync();
        await h.RunAsync();
        string first = h.Receiver.Requests.Single().Headers["webhook-id"];

        Assert.Equal(InboundRetryResult.Queued, await h.Storage.Inbound.RetryActionAsync(h.TenantId, draft.Id, h.Clock.UtcNow, default));
        await h.RunAsync();

        string[] ids = h.Receiver.Requests.Select(r => r.Headers["webhook-id"]).ToArray();
        Assert.Equal(["evt_" + Ids.ToCompact(draft.Id), "evt_" + Ids.ToCompact(draft.Id) + "-1"], ids);
        Assert.Equal(first, ids[0]);
        Assert.Equal(1, (await h.GetAsync(draft.Id)).RetryGeneration);
        Assert.Equal(1, Json(h.Receiver.Requests.Last()).GetProperty("data").GetProperty("retry_generation").GetInt32());
    }

    [Fact]
    public async Task A_disabled_endpoint_is_a_deferral_that_counts_and_re_enabling_inside_the_ladder_delivers()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        await h.Storage.Config.DisableWebhookEndpointAsync(h.Endpoint.Id, "off", h.Clock.UtcNow, default);
        InboundMessageDraft draft = await h.ReceiveAsync();

        await h.RunAsync();
        InboundMessage deferred = await h.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Pending, deferred.ActionState);
        Assert.Equal(1, deferred.ActionAttempts);
        Assert.Equal("endpoint_disabled", deferred.ActionLastError);
        Assert.Empty(h.Receiver.Requests);   // nothing was sent

        await h.Storage.Config.UpsertWebhookEndpointAsync(h.Endpoint with { Enabled = true, DisabledReason = null, DisabledAt = null }, default);
        h.Clock.Advance(TimeSpan.FromSeconds(10));
        await h.RunAsync();

        Assert.Equal(InboundActionState.Done, (await h.GetAsync(draft.Id)).ActionState);
        Assert.Single(h.Receiver.Requests);
    }

    [Fact]
    public async Task A_disabled_endpoint_that_stays_off_ends_failed_at_the_end_of_the_ladder()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        await h.Storage.Config.DisableWebhookEndpointAsync(h.Endpoint.Id, "off", h.Clock.UtcNow, default);
        InboundMessageDraft draft = await h.ReceiveAsync();

        for (int i = 0; i < 4; i++)
        {
            await h.RunAsync();
            h.Clock.Advance(TimeSpan.FromMinutes(11));
        }

        InboundMessage stored = await h.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Failed, stored.ActionState);
        Assert.Equal("endpoint_disabled", stored.ActionLastError);
        Assert.Empty(h.Receiver.Requests);

        // The tenant fixes the endpoint and asks again: a new ladder.
        await h.Storage.Config.UpsertWebhookEndpointAsync(h.Endpoint with { Enabled = true, DisabledReason = null, DisabledAt = null }, default);
        Assert.Equal(InboundRetryResult.Queued, await h.Storage.Inbound.RetryActionAsync(h.TenantId, draft.Id, h.Clock.UtcNow, default));
        await h.RunAsync();
        Assert.Equal(InboundActionState.Done, (await h.GetAsync(draft.Id)).ActionState);
    }

    [Fact]
    public async Task A_410_switches_the_endpoint_off_and_the_message_keeps_its_ladder()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        h.Receiver.Respond(HttpStatusCode.Gone);
        InboundMessageDraft draft = await h.ReceiveAsync();

        await h.RunAsync();

        WebhookEndpointRecord endpoint = (await h.Storage.Config.GetWebhookEndpointAsync(h.Endpoint.Id, default))!;
        Assert.False(endpoint.Enabled);
        Assert.Contains("410", endpoint.DisabledReason, StringComparison.Ordinal);
        InboundMessage stored = await h.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Pending, stored.ActionState);
        Assert.Equal("webhook_gone", stored.ActionLastError);
    }

    [Fact]
    public async Task Failures_start_the_endpoint_streak_and_a_success_clears_it()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        h.Receiver.Respond(HttpStatusCode.ServiceUnavailable, HttpStatusCode.OK);
        await h.ReceiveAsync();
        await h.RunAsync();
        Assert.NotNull((await h.Storage.Config.GetWebhookEndpointAsync(h.Endpoint.Id, default))!.FailingSince);

        h.Clock.Advance(TimeSpan.FromSeconds(10));
        await h.RunAsync();
        Assert.Null((await h.Storage.Config.GetWebhookEndpointAsync(h.Endpoint.Id, default))!.FailingSince);
    }

    [Fact]
    public async Task Throttling_adds_the_extra_delay()
    {
        var options = new InboundActionOptions { RetrySchedule = [TimeSpan.FromSeconds(10)], ThrottleExtraDelay = TimeSpan.FromMinutes(1) };
        await using var h = await new InboundActionHarness(options).InitializeAsync();
        h.Receiver.Respond(HttpStatusCode.TooManyRequests);
        InboundMessageDraft draft = await h.ReceiveAsync();

        await h.RunAsync();

        Assert.Equal(h.Clock.UtcNow + TimeSpan.FromSeconds(70), (await h.GetAsync(draft.Id)).ActionNextAttemptAt);
    }

    [Fact]
    public async Task An_endpoint_of_another_tenant_never_receives_the_mail()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        // The route write refuses it; this is the runner's own check (an endpoint edited afterwards, a restore, a bug elsewhere).
        await h.Storage.Config.UpsertWebhookEndpointAsync(h.Endpoint with { TenantId = Ids.New() }, default);
        InboundMessageDraft draft = await h.ReceiveAsync();

        await h.RunAsync();

        Assert.Empty(h.Receiver.Requests);
        Assert.Equal("endpoint_not_of_tenant", (await h.GetAsync(draft.Id)).ActionLastError);
        Assert.Equal(InboundActionState.Failed, (await h.GetAsync(draft.Id)).ActionState);
    }

    [Fact]
    public async Task A_stored_secret_that_cannot_sign_fails_the_action_at_once_instead_of_crashing_every_attempt()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        await h.Storage.Config.UpsertWebhookEndpointAsync(h.Endpoint with { SecretProtected = Encoding.UTF8.GetBytes("whsec_not base64!") }, default);
        InboundMessageDraft draft = await h.ReceiveAsync();

        await h.RunAsync();

        Assert.Empty(h.Receiver.Requests);
        InboundMessage stored = await h.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Failed, stored.ActionState);
        Assert.Equal("secret_unreadable", stored.ActionLastError);
    }

    [Fact]
    public async Task The_ssrf_guard_applies_to_inbound_webhooks_and_the_error_is_a_code_not_an_address()
    {
        // The real handler (no stub), resolving the receiver's name to a loopback address that no allowlist permits.
        await using var h = await new InboundActionHarness(useReceiver: false, resolver: (_, _) => ValueTask.FromResult(new[] { IPAddress.Loopback })).InitializeAsync();
        InboundMessageDraft draft = await h.ReceiveAsync();

        await h.RunAsync();

        InboundMessage stored = await h.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Pending, stored.ActionState);
        Assert.Equal("webhook_ssrf_blocked", stored.ActionLastError);
        Assert.DoesNotContain("127.0.0.1", stored.ActionLastError, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_allowlisted_internal_network_is_reachable_like_for_every_other_event()
    {
        // The guard lets the tenant's allowlist through; the connection then fails because nothing listens, which is a connect failure, not a block.
        await using var h = await new InboundActionHarness(useReceiver: false, resolver: (_, _) => ValueTask.FromResult(new[] { IPAddress.Parse("127.0.0.1") })).InitializeAsync();
        h.Transport.AllowlistProvider = _ => [IpNetwork.Parse("127.0.0.0/8")];
        await h.Storage.Config.UpsertWebhookEndpointAsync(h.Endpoint with { Url = "https://hooks.example.test:1/inbound" }, default);
        InboundMessageDraft draft = await h.ReceiveAsync();

        await h.RunAsync();

        Assert.Equal("webhook_connect_failed", (await h.GetAsync(draft.Id)).ActionLastError);
    }
}
