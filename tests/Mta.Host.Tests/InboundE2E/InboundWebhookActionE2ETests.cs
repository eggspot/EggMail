using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Host.Inbound;
using Mta.Host.Ingest;
using Mta.Host.Tests.Api;
using Mta.Storage;
using Mta.Webhooks;
using MimeKit;

namespace Mta.Host.Tests.InboundE2E;

/// <summary>
/// The webhook action of an inbound route end to end, on SQLite and on PostgreSQL: mail arrives over SMTP, the runtime's runner claims the action from the real store and posts to a real HTTP receiver
/// over a real socket, and an independent Standard Webhooks verifier checks the signature. The payload, the attachments fetched by reference through the API, the raw format, the retry ladder (read off the
/// clock the test moves), the final failure, the guard against internal addresses, and several runners over one database.
/// </summary>
public abstract class InboundWebhookActionE2ETests(LabBackend backend)
{
    private static LabOptions Options(Action<InboundActionSection>? tune = null) => new()
    {
        WithApi = true,
        RunActions = true,
        Inbound = new InboundSection
        {
            Enabled = true,
            CheckSpfForInternalClients = true,
            MaxMessagesPerMinute = 1_000_000,
            MaxMessagesPerMinutePerRemote = 1_000_000,
            Action = new InboundActionSection { PollInterval = TimeSpan.FromMilliseconds(40) },
        },
    };

    private static async Task<InboundMessage> WaitForAsync(InboundLab lab, Guid tenant, Guid id, Func<InboundMessage, bool> predicate)
    {
        DateTime deadline = DateTime.UtcNow.AddSeconds(30);
        while (true)
        {
            InboundMessage? m = await lab.Storage.Inbound.GetAsync(tenant, id, default);
            if (m is not null && predicate(m))
            {
                return m;
            }

            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException($"message {id:N} never reached the awaited state; it is {m?.ActionState} after {m?.ActionAttempts} attempts, error {m?.ActionLastError}");
            }

            await Task.Delay(20);
        }
    }

    private static async Task<(InboundLab Lab, WebhookReceiver Receiver, WebhookEndpointRecord Endpoint, Guid Route)?> SetUpAsync(LabBackend backend, InboundWebhookFormat format = InboundWebhookFormat.Json, LabOptions? options = null)
    {
        InboundLab? lab = await InboundLab.StartAsync(backend, options ?? Options());
        if (lab is null)
        {
            return null;
        }

        WebhookReceiver receiver = await WebhookReceiver.StartAsync();
        WebhookEndpointRecord endpoint = await lab.AddWebhookEndpointAsync(InboundLab.Acme, receiver.Url);
        Guid route = await lab.AddRouteAsync(lab.ExampleOrg, InboundLab.Acme, 5, InboundMatchKind.Address, "hook", InboundActionKind.Webhook, webhookEndpoint: endpoint.Id, format: format);
        await lab.RefreshAsync();
        return (lab, receiver, endpoint, route);
    }

    private static string Wire(MimeMessage message)
    {
        var options = FormatOptions.Default.Clone();
        options.NewLineFormat = NewLineFormat.Dos;
        using var stream = new MemoryStream();
        message.WriteTo(options, stream);
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static async Task<byte[]> FetchAsync(InboundLab lab, ApiClient client, string path)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", client.Bearer);
        using HttpResponseMessage response = await lab.Api!.Http.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsByteArrayAsync();
    }

    // ------------------------------------------------------------------ the json format

    [Fact]
    public async Task The_json_webhook_is_signed_describes_the_message_and_its_attachments_are_fetched_by_reference_through_the_api()
    {
        var setup = await SetUpAsync(backend);
        if (setup is not var (lab, receiver, endpoint, routeId))
        {
            return;
        }

        await using InboundLab labScope = lab;
        await using WebhookReceiver receiverScope = receiver;
        lab.PublishSpf("sender.test");
        lab.PublishDmarc("sender.test", "reject");
        byte[] pdf = RandomNumberGenerator.GetBytes(30_000);
        var mime = new MimeMessage();
        mime.From.Add(new MailboxAddress("Bob", "bob@sender.test"));
        mime.To.Add(new MailboxAddress("Hook", "hook@example.org"));
        mime.Cc.Add(new MailboxAddress("Carol", "carol@sender.test"));
        mime.Subject = "Invoice über alles";
        mime.Date = new DateTimeOffset(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);
        mime.MessageId = "invoice-77@sender.test";
        mime.InReplyTo = "earlier-1@sender.test";
        var body = new BodyBuilder { TextBody = "Please find the invoice.\r\n", HtmlBody = "<p>Please find the <b>invoice</b>.</p>" };
        body.Attachments.Add("invoice.pdf", pdf, ContentType.Parse("application/pdf"));
        body.Attachments.Add("notes.txt", Encoding.UTF8.GetBytes("nötes"), ContentType.Parse("text/plain; charset=utf-8"));
        mime.Body = body.ToMessageBody();
        string wire = Wire(mime);

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "hook@example.org", wire)).Code);
        InboundMessage stored = Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
        Assert.Equal((InboundActionKind.Webhook, routeId), (stored.ActionKind, stored.RouteId.GetValueOrDefault()));
        await receiver.WaitForRequestsAsync(1);
        stored = await WaitForAsync(lab, InboundLab.Acme, stored.Id, m => m.ActionState == InboundActionState.Done);

        ReceivedWebhook request = Assert.Single(receiver.Requests);
        Assert.True(IndependentWebhookVerifier.Verify(request, [lab.Secrets[endpoint.Id]], lab.Clock.UtcNow, TimeSpan.FromMinutes(5), out string reason), reason);
        Assert.Equal("evt_" + ApiJson.Id(stored.Id), request.Id);
        Assert.StartsWith("application/json", request.ContentType, StringComparison.Ordinal);
        Assert.StartsWith("EggMail-Webhooks/", request.Headers["User-Agent"], StringComparison.Ordinal);

        using JsonDocument doc = JsonDocument.Parse(request.Body);
        JsonElement root = doc.RootElement;
        Assert.Equal(("evt_" + ApiJson.Id(stored.Id), "inbound.message.received"), (root.GetProperty("id").GetString(), root.GetProperty("type").GetString()));
        JsonElement data = root.GetProperty("data");
        Assert.Equal(ApiJson.Id(stored.Id), data.GetProperty("inbound_id").GetString());
        Assert.Equal(("example.org", ApiJson.Id(routeId), stored.Size), (data.GetProperty("domain").GetString(), data.GetProperty("route_id").GetString(), data.GetProperty("size").GetInt64()));
        Assert.False(data.GetProperty("dmarc_flagged").GetBoolean());
        Assert.Equal(("127.0.0.1", "mail.sender.test", false), (data.GetProperty("connection").GetProperty("remote_ip").GetString(), data.GetProperty("connection").GetProperty("helo").GetString(), data.GetProperty("connection").GetProperty("tls").GetBoolean()));
        Assert.Equal(("bob@sender.test", "hook@example.org"), (data.GetProperty("envelope").GetProperty("from").GetString(), data.GetProperty("envelope").GetProperty("to").GetString()));
        JsonElement auth = data.GetProperty("auth");
        Assert.Equal(("pass", "sender.test"), (auth.GetProperty("spf").GetProperty("result").GetString(), auth.GetProperty("spf").GetProperty("domain").GetString()));
        Assert.Equal(("pass", "reject"), (auth.GetProperty("dmarc").GetProperty("result").GetString(), auth.GetProperty("dmarc").GetProperty("policy").GetString()));   // SPF passes for sender.test, the domain of the From header
        JsonElement message = data.GetProperty("message");
        Assert.Equal("invoice-77@sender.test", message.GetProperty("message_id").GetString()!.Trim('<', '>'));
        Assert.Equal("Invoice über alles", message.GetProperty("subject").GetString());
        Assert.Contains("Please find the invoice.", message.GetProperty("text").GetString(), StringComparison.Ordinal);
        Assert.Contains("<b>invoice</b>", message.GetProperty("html").GetString(), StringComparison.Ordinal);
        Assert.Contains("carol@sender.test", message.GetProperty("cc")[0].GetString(), StringComparison.Ordinal);
        Assert.False(message.GetProperty("truncated").GetBoolean());
        Assert.Contains(message.GetProperty("headers").EnumerateArray().Select(h => h.GetProperty("name").GetString()), n => n == "Authentication-Results");

        // Attachments are listed with a path and never inlined; the receiver fetches them with a key that has inbound:read.
        JsonElement attachments = data.GetProperty("attachments");
        Assert.Equal(2, attachments.GetArrayLength());
        Assert.DoesNotContain(Convert.ToBase64String(pdf[..64]), request.Text, StringComparison.Ordinal);
        Assert.Equal(("invoice.pdf", "application/pdf", 30_000L, "attachment"), (attachments[0].GetProperty("filename").GetString(), attachments[0].GetProperty("content_type").GetString(), attachments[0].GetProperty("size").GetInt64(), attachments[0].GetProperty("disposition").GetString()));
        ApiClient reader = await lab.Api!.KeyClientAsync(InboundLab.Acme, "inbound:read");
        string url0 = attachments[0].GetProperty("url").GetString()!;
        Assert.Equal($"/api/v1/inbound/messages/{ApiJson.Id(stored.Id)}/attachments/0", url0);
        Assert.Equal(pdf, await FetchAsync(lab, reader, url0));
        Assert.Equal("nötes", Encoding.UTF8.GetString(await FetchAsync(lab, reader, attachments[1].GetProperty("url").GetString()!)));
        Assert.Equal(await lab.Storage.Inbound.GetRawAsync(InboundLab.Acme, stored.Id, default), await FetchAsync(lab, reader, data.GetProperty("raw_url").GetString()!));

        // The URLs carry no credential: another tenant's key gets nothing from them.
        ApiClient stranger = await lab.Api.KeyClientAsync(InboundLab.Globex, "inbound:read");
        using var probe = new HttpRequestMessage(HttpMethod.Get, url0);
        probe.Headers.Authorization = new AuthenticationHeaderValue("Bearer", stranger.Bearer);
        using HttpResponseMessage denied = await lab.Api.Http.SendAsync(probe);
        Assert.Equal(HttpStatusCode.NotFound, denied.StatusCode);
        using var anonymous = new HttpRequestMessage(HttpMethod.Get, url0);
        using HttpResponseMessage noKey = await lab.Api.Http.SendAsync(anonymous);
        Assert.Equal(HttpStatusCode.Unauthorized, noKey.StatusCode);

        Assert.Equal(1, stored.ActionAttempts);
        Assert.Null(stored.ActionLastError);
    }

    // ------------------------------------------------------------------ raw_mime

    [Fact]
    public async Task The_raw_mime_webhook_posts_the_stored_message_byte_for_byte_with_the_verdicts_in_encoded_headers()
    {
        var setup = await SetUpAsync(backend, InboundWebhookFormat.RawMime);
        if (setup is not var (lab, receiver, endpoint, _))
        {
            return;
        }

        await using InboundLab labScope = lab;
        await using WebhookReceiver receiverScope = receiver;
        lab.PublishSpf("sender.test");

        // An envelope sender that is hostile to a header: a quoted local part with spaces, quotes, a percent sign and non-ASCII (SMTPUTF8).
        await using (Host.Tests.Inbound.FakeMta mta = await lab.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.CommandAsync("MAIL FROM:<\"a b\\\"c%0d%0aX-Injected: 1\"@sender.test> SMTPUTF8")).Code);
            Assert.Equal(250, (await mta.RcptAsync("hook@example.org")).Code);
            Assert.Equal(250, (await mta.DataAsync(InboundLab.Message(to: "hook@example.org", subject: "raw one", body: "line\r\n.dot line\r\n\r\ntail\r\n"))).Code);
        }

        InboundMessage stored = Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
        await receiver.WaitForRequestsAsync(1);
        stored = await WaitForAsync(lab, InboundLab.Acme, stored.Id, m => m.ActionState == InboundActionState.Done);

        ReceivedWebhook request = Assert.Single(receiver.Requests);
        Assert.True(IndependentWebhookVerifier.Verify(request, [lab.Secrets[endpoint.Id]], lab.Clock.UtcNow, TimeSpan.FromMinutes(5), out string reason), reason);   // signed over exactly these bytes
        Assert.Equal(await lab.Storage.Inbound.GetRawAsync(InboundLab.Acme, stored.Id, default), request.Body);
        Assert.Equal("message/rfc822", request.ContentType);
        Assert.Equal(ApiJson.Id(stored.Id), request.Headers["EggMail-Inbound-Id"]);
        Assert.Equal(("pass", "none", "none", "none", "false"), (request.Headers["EggMail-Spf"], request.Headers["EggMail-Dkim"], request.Headers["EggMail-Dmarc"], request.Headers["EggMail-Arc"], request.Headers["EggMail-Dmarc-Flagged"]));
        Assert.Equal("127.0.0.1", request.Headers["EggMail-Remote-Ip"]);
        Assert.Equal("hook@example.org", request.Headers["EggMail-Envelope-To"]);
        string from = request.Headers["EggMail-Envelope-From"];
        Assert.DoesNotContain("\r", from, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", from, StringComparison.Ordinal);
        Assert.DoesNotContain(" ", from, StringComparison.Ordinal);
        Assert.False(request.Headers.ContainsKey("X-Injected"));   // nothing the sender wrote became a header of the request
        Assert.Equal(stored.EnvelopeFrom, Uri.UnescapeDataString(from));   // and what is encoded decodes to what was stored
    }

    // ------------------------------------------------------------------ the ladder

    [Fact]
    public async Task A_receiver_that_fails_is_tried_again_on_the_ladder_with_the_same_id_and_a_manual_retry_is_a_new_event()
    {
        // The runner is stepped by hand (RunOnceAsync claims what is due and carries it out before it returns), so what is due is decided by the clock the test moves and nothing waits for real time.
        var setup = await SetUpAsync(backend, options: new LabOptions { WithApi = true, RunActions = false, Inbound = Options().Inbound });
        if (setup is not var (lab, receiver, endpoint, _))
        {
            return;
        }

        await using InboundLab labScope = lab;
        await using WebhookReceiver receiverScope = receiver;
        receiver.Respond(500, 503, 200);
        InboundActionRunner runner = lab.Runtime.InboundActions;

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "hook@example.org", InboundLab.Message(subject: "retry me"))).Code);
        Guid id = Assert.Single(await lab.MessagesAsync(InboundLab.Acme)).Id;

        // Attempt 1 fails with 500: the next rung is 5 seconds on the clock; nothing is tried before it.
        Assert.Equal(1, await runner.RunOnceAsync(default));
        InboundMessage first = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, id, default))!;
        Assert.Equal((InboundActionState.Pending, 1, "webhook_http_500"), (first.ActionState, first.ActionAttempts, first.ActionLastError));
        Assert.Equal(lab.Clock.UtcNow.AddSeconds(5), first.ActionNextAttemptAt);
        Assert.Equal(0, await runner.RunOnceAsync(default));
        Assert.Single(receiver.Requests);

        await lab.AdvanceAsync(TimeSpan.FromSeconds(5));   // exactly due
        Assert.Equal(1, await runner.RunOnceAsync(default));
        InboundMessage second = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, id, default))!;
        Assert.Equal((InboundActionState.Pending, 2, "webhook_http_503"), (second.ActionState, second.ActionAttempts, second.ActionLastError));
        Assert.Equal(lab.Clock.UtcNow.AddMinutes(5), second.ActionNextAttemptAt);
        await lab.AdvanceAsync(TimeSpan.FromMinutes(5) - TimeSpan.FromSeconds(1));   // one second early
        Assert.Equal(0, await runner.RunOnceAsync(default));

        await lab.AdvanceAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(1, await runner.RunOnceAsync(default));
        InboundMessage done = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, id, default))!;
        Assert.Equal((InboundActionState.Done, 3, null), (done.ActionState, done.ActionAttempts, done.ActionLastError));

        // Automatic retries repeat the id (the receiver deduplicates them); every one is signed on its own.
        Assert.Equal(3, receiver.Requests.Count);
        Assert.Single(receiver.Requests.Select(r => r.Id).Distinct());
        Assert.All(receiver.Requests, r => Assert.True(IndependentWebhookVerifier.Verify(r, [lab.Secrets[endpoint.Id]], lab.Clock.UtcNow, TimeSpan.FromHours(1), out _)));

        // A manual retry puts a finished action back: a new generation, a new webhook id.
        ApiClient writer = await lab.Api!.KeyClientAsync(InboundLab.Acme, "inbound:write");
        Reply retried = await writer.PostAsync($"/api/v1/inbound/messages/{ApiJson.Id(id)}/retry");
        Assert.Equal(HttpStatusCode.Accepted, retried.Status);
        Assert.Equal(1, await runner.RunOnceAsync(default));
        InboundMessage again = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, id, default))!;
        Assert.Equal((InboundActionState.Done, 1, 1), (again.ActionState, again.ActionAttempts, again.RetryGeneration));
        Assert.Equal("evt_" + ApiJson.Id(id) + "-1", receiver.Requests.Last().Id);
    }

    [Fact]
    public async Task A_receiver_that_never_works_ends_the_action_failed_after_the_whole_ladder_and_the_tenant_is_told_through_its_endpoints()
    {
        var setup = await SetUpAsync(backend, options: new LabOptions { WithApi = true, RunActions = false, Inbound = Options().Inbound });
        if (setup is not var (lab, receiver, endpoint, _))
        {
            return;
        }

        await using InboundLab labScope = lab;
        await using WebhookReceiver receiverScope = receiver;
        receiver.Respond(500);
        InboundActionRunner runner = lab.Runtime.InboundActions;
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "hook@example.org", InboundLab.Message(subject: "never delivered"))).Code);
        Guid id = Assert.Single(await lab.MessagesAsync(InboundLab.Acme)).Id;

        // The seven rungs of the ladder (5 s, 5 m, 30 m, 2 h, 5 h, 10 h, 10 h): each attempt is made exactly when its rung is due and the eighth is the last.
        TimeSpan[] rungs = [TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(30), TimeSpan.FromHours(2), TimeSpan.FromHours(5), TimeSpan.FromHours(10), TimeSpan.FromHours(10)];
        for (int attempt = 1; attempt <= 8; attempt++)
        {
            Assert.Equal(1, await runner.RunOnceAsync(default));
            InboundMessage m = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, id, default))!;
            Assert.Equal(attempt, m.ActionAttempts);
            if (attempt < 8)
            {
                Assert.Equal(InboundActionState.Pending, m.ActionState);
                Assert.Equal(lab.Clock.UtcNow + rungs[attempt - 1], m.ActionNextAttemptAt);
                await lab.AdvanceAsync(rungs[attempt - 1] - TimeSpan.FromSeconds(1));
                Assert.Equal(0, await runner.RunOnceAsync(default));   // a second early: not yet
                await lab.AdvanceAsync(TimeSpan.FromSeconds(1));
            }
        }

        InboundMessage state = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, id, default))!;
        Assert.Equal((InboundActionState.Failed, 8, "webhook_http_500"), (state.ActionState, state.ActionAttempts, state.ActionLastError));
        Assert.Equal(8, receiver.Requests.Count);
        Assert.NotNull(state.ActionFinishedAt);
        Assert.True(state.HasRaw);   // a failed message keeps its body: it is the source for a retry
        Assert.Equal(0, await runner.RunOnceAsync(default));   // and nothing more is tried

        // The tenant's own endpoints are told: an inbound.action.failed event waits in the outbox of the tenant, with no address or URL in it.
        var queued = await lab.Storage.Webhooks.ClaimDueAsync("check", 50, lab.Clock.UtcNow.AddDays(30), TimeSpan.FromMinutes(1), default);
        WebhookOutboxItem failure = Assert.Single(queued, e => e.EventType == "inbound.action.failed");
        Assert.Equal(InboundLab.Acme, failure.TenantId);
        using JsonDocument payload = JsonDocument.Parse(failure.PayloadJson);
        Assert.Equal(ApiJson.Id(id), payload.RootElement.GetProperty("data").GetProperty("inbound_id").GetString());
        Assert.DoesNotContain("127.0.0.1", failure.PayloadJson, StringComparison.Ordinal);

        // A retry through the API starts a new ladder: the receiver is fine now.
        receiver.Respond(200);
        ApiClient writer = await lab.Api!.KeyClientAsync(InboundLab.Acme, "inbound:write");
        Assert.Equal(HttpStatusCode.Accepted, (await writer.PostAsync($"/api/v1/inbound/messages/{ApiJson.Id(id)}/retry")).Status);
        Assert.Equal(1, await runner.RunOnceAsync(default));
        Assert.Equal(InboundActionState.Done, (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, id, default))!.ActionState);
    }

    // ------------------------------------------------------------------ guards

    [Fact]
    public async Task A_webhook_route_to_an_internal_address_is_not_called_unless_the_tenants_allowlist_says_so()
    {
        var setup = await SetUpAsync(backend);
        if (setup is not var (lab, receiver, _, _))
        {
            return;
        }

        await using InboundLab labScope = lab;
        await using WebhookReceiver receiverScope = receiver;
        lab.Runtime.Webhooks.AllowlistProvider = _ => [];   // no network is allowed to the tenant: the receiver is on loopback

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "hook@example.org", InboundLab.Message(subject: "to loopback"))).Code);
        Guid id = Assert.Single(await lab.MessagesAsync(InboundLab.Acme)).Id;

        InboundMessage blocked = await WaitForAsync(lab, InboundLab.Acme, id, m => m.ActionAttempts == 1 && m.ActionState == InboundActionState.Pending && m.ActionLastError is not null);
        Assert.Equal("webhook_ssrf_blocked", blocked.ActionLastError);
        Assert.Empty(receiver.Requests);   // nothing reached it

        lab.Runtime.Webhooks.AllowlistProvider = _ => [IpNetwork.Parse("127.0.0.0/8")];
        await lab.AdvanceAsync(TimeSpan.FromSeconds(6));
        await WaitForAsync(lab, InboundLab.Acme, id, m => m.ActionState == InboundActionState.Done);
        Assert.Single(receiver.Requests);
    }

    [Fact]
    public async Task A_receiver_that_answers_gone_switches_its_endpoint_off_and_the_message_is_delivered_after_the_tenant_turns_it_back_on()
    {
        var setup = await SetUpAsync(backend);
        if (setup is not var (lab, receiver, endpoint, _))
        {
            return;
        }

        await using InboundLab labScope = lab;
        await using WebhookReceiver receiverScope = receiver;
        receiver.Respond(410);

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "hook@example.org", InboundLab.Message(subject: "gone"))).Code);
        Guid id = Assert.Single(await lab.MessagesAsync(InboundLab.Acme)).Id;
        InboundMessage after = await WaitForAsync(lab, InboundLab.Acme, id, m => m.ActionAttempts == 1 && m.ActionLastError == "webhook_gone");
        Assert.Equal(InboundActionState.Pending, after.ActionState);   // it keeps its ladder
        Assert.False((await lab.Storage.Config.GetWebhookEndpointAsync(endpoint.Id, default))!.Enabled);

        // While the endpoint is off, the next rung is a deferral that sends nothing.
        await lab.AdvanceAsync(TimeSpan.FromSeconds(6));
        await WaitForAsync(lab, InboundLab.Acme, id, m => m.ActionAttempts == 2 && m.ActionLastError == "endpoint_disabled");
        Assert.Single(receiver.Requests);

        receiver.Respond(200);
        await lab.Storage.Config.UpsertWebhookEndpointAsync(endpoint with { Enabled = true, DisabledReason = null, DisabledAt = null }, default);
        await lab.AdvanceAsync(TimeSpan.FromMinutes(6));
        await WaitForAsync(lab, InboundLab.Acme, id, m => m.ActionState == InboundActionState.Done);
        Assert.Equal(2, receiver.Requests.Count);
    }

    [Fact]
    public async Task A_route_changed_to_store_while_the_webhook_waits_completes_without_calling_anybody_and_keeps_the_body()
    {
        var options = Options();
        var setup = await SetUpAsync(backend, options: new LabOptions { WithApi = true, RunActions = false, Inbound = options.Inbound });
        if (setup is not var (lab, receiver, _, routeId))
        {
            return;
        }

        await using InboundLab labScope = lab;
        await using WebhookReceiver receiverScope = receiver;
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "hook@example.org", InboundLab.Message(subject: "waiting"))).Code);   // no runner: it waits
        InboundMessage waiting = Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
        Assert.Equal(InboundActionState.Pending, waiting.ActionState);

        ApiClient writer = await lab.Api!.KeyClientAsync(InboundLab.Acme, "inbound:write", "inbound:read");
        Reply changed = await writer.PatchAsync($"/api/v1/domains/{ApiJson.Id(lab.ExampleOrg)}/inbound/routes/{ApiJson.Id(routeId)}", new { action = new { kind = "store" } });
        Assert.Equal(HttpStatusCode.OK, changed.Status);

        Assert.Equal(1, await lab.Runtime.InboundActions.RunOnceAsync(default));

        InboundMessage done = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, waiting.Id, default))!;
        Assert.Equal((InboundActionState.Done, "route_is_now_store", true), (done.ActionState, done.ActionNote, done.HasRaw));
        Assert.Empty(receiver.Requests);
        Reply detail = await writer.GetAsync("/api/v1/inbound/messages/" + ApiJson.Id(waiting.Id));
        Assert.Equal("webhook", detail["action"].GetProperty("kind").GetString());          // what it was given at receipt
        Assert.Equal("store", detail["action"].GetProperty("currentKind").GetString());     // what its route does now
        Assert.Equal("route_is_now_store", detail["action"].GetProperty("note").GetString());
    }

    // ------------------------------------------------------------------ several runners

    [Fact]
    public async Task Two_runners_over_one_database_deliver_every_message_exactly_once_and_one_tenant_never_takes_every_worker()
    {
        var setup = await SetUpAsync(backend);
        if (setup is not var (lab, receiver, endpoint, _))
        {
            return;
        }

        await using InboundLab labScope = lab;
        await using WebhookReceiver receiverScope = receiver;
        // A second replica: its own runner over the same storage.
        using var transport = new WebhookTransport(lab.Config.Webhooks, lab.Clock) { AllowlistProvider = _ => [IpNetwork.Parse("127.0.0.0/8")] };
        var second = new InboundActionRunner(
            lab.Storage, transport, new WebhookEndpointHealth(lab.Storage.Config, lab.Config.Webhooks, null, null), lab.Runtime.Secrets, new InboundActionOptions { PollInterval = TimeSpan.FromMilliseconds(40) },
            lab.Clock, NullMtaLog.Instance, () => true, new StorageWebhookPublisher(lab.Storage));
        using var stop = new CancellationTokenSource();
        Task secondLoop = second.RunAsync(stop.Token);
        try
        {
            receiver.Gate = async () => await Task.Delay(30);   // a receiver that takes a moment, so claims overlap
            const int Count = 60;
            await using Host.Tests.Inbound.FakeMta mta = await lab.ConnectedAsync();
            for (int i = 0; i < Count; i++)
            {
                Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "hook@example.org", InboundLab.Message(subject: "many " + i))).Code);
                await mta.CommandAsync("RSET");
            }

            await receiver.WaitForRequestsAsync(Count);
            DateTime deadline = DateTime.UtcNow.AddSeconds(30);
            while ((await lab.Storage.Inbound.GetUsageAsync(InboundLab.Acme, null, default)).Pending > 0 && DateTime.UtcNow < deadline)
            {
                await Task.Delay(20);
            }

            IReadOnlyList<InboundMessage> all = await lab.MessagesAsync(InboundLab.Acme, new InboundMessageQuery(InboundLab.Acme, Limit: 200));
            Assert.Equal(Count, all.Count);
            Assert.All(all, m => Assert.Equal((InboundActionState.Done, 1), (m.ActionState, m.ActionAttempts)));   // each claimed once
            Assert.Equal(Count, receiver.Requests.Select(r => r.Id).Distinct().Count());   // each posted once: no failure, no lost lease, so no duplicate
            Assert.Equal(Count, receiver.Requests.Count);
            Assert.InRange(receiver.MaxConcurrent, 1, 4);   // two replicas, two attempts of one tenant each
        }
        finally
        {
            await stop.CancelAsync();
            try { await secondLoop; } catch (OperationCanceledException) { }
        }
    }

    // ------------------------------------------------------------------ suspended tenant

    [Fact]
    public async Task While_the_tenant_is_suspended_its_actions_are_deferred_with_the_reason_and_delivered_after_it_is_back()
    {
        var setup = await SetUpAsync(backend, options: new LabOptions { WithApi = true, RunActions = false, Inbound = Options().Inbound });
        if (setup is not var (lab, receiver, _, _))
        {
            return;
        }

        await using InboundLab labScope = lab;
        await using WebhookReceiver receiverScope = receiver;
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "hook@example.org", InboundLab.Message(subject: "waiting"))).Code);
        Guid id = Assert.Single(await lab.MessagesAsync(InboundLab.Acme)).Id;

        Tenant acme = (await lab.Storage.Config.GetTenantAsync(InboundLab.Acme, default))!;
        await lab.Storage.Config.UpsertTenantAsync(acme with { Enabled = false }, default);
        await lab.RefreshAsync();

        // New mail is told to come back later; the one that is stored waits, and the attempt is a deferral that says why (it counts against the ladder).
        Assert.Equal(450, (await lab.SendAsync("bob@sender.test", "hook@example.org", InboundLab.Message(subject: "during"))).Code);
        Assert.Equal(1, await lab.Runtime.InboundActions.RunOnceAsync(default));
        InboundMessage deferred = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, id, default))!;
        Assert.Equal((InboundActionState.Pending, 1, "tenant_suspended"), (deferred.ActionState, deferred.ActionAttempts, deferred.ActionLastError));
        Assert.Empty(receiver.Requests);

        await lab.Storage.Config.UpsertTenantAsync(acme with { Enabled = true }, default);
        await lab.RefreshAsync();
        await lab.AdvanceAsync(TimeSpan.FromSeconds(6));
        Assert.Equal(1, await lab.Runtime.InboundActions.RunOnceAsync(default));
        InboundMessage delivered = (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, id, default))!;
        Assert.Equal((InboundActionState.Done, 2), (delivered.ActionState, delivered.ActionAttempts));
        Assert.Single(receiver.Requests);
    }
}

public sealed class SqliteInboundWebhookActionE2ETests() : InboundWebhookActionE2ETests(LabBackend.Sqlite);

public sealed class PostgresInboundWebhookActionE2ETests() : InboundWebhookActionE2ETests(LabBackend.Postgres);
