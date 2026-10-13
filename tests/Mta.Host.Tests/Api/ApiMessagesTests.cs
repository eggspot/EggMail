using System.Net;
using System.Text;
using System.Text.Json;
using MimeKit;
using Mta.Core;
using Mta.Host.Api;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

[Collection("api")]
public class ApiMessagesTests : IAsyncLifetime
{
    private ApiFixture _f = null!;
    private ApiClient _a = null!;

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync();
        _a = await _f.KeyClientAsync(ApiFixture.TenantAId);
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private static Dictionary<string, object?> Body(string subject = "Hello", params string[] to) => new()
    {
        ["from"] = "Acme <noreply@example.com>",
        ["to"] = to.Length == 0 ? new[] { "alex@gmail.test" } : to,
        ["subject"] = subject,
        ["text"] = "plain body of " + subject,
        ["html"] = "<p>html body of " + subject + "</p>",
    };

    private static Dictionary<string, object?> WithTags(Dictionary<string, object?> body, params string[] tags)
    {
        body["tags"] = tags;
        return body;
    }

    private async Task<string> SendAsync(ApiClient client, Dictionary<string, object?> body)
    {
        Reply r = await client.PostAsync("/api/v1/messages", body);
        Assert.Equal(HttpStatusCode.Accepted, r.Status);
        return r.Str("id");
    }

    private async Task DeliverAllAsync()
    {
        foreach (ClaimedDelivery d in await _f.Storage.Deliveries.ClaimAsync("test", 100, _f.Clock.UtcNow, TimeSpan.FromMinutes(1), default))
        {
            await _f.Storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt
            {
                DeliveryId = d.DeliveryId,
                Outcome = DeliveryOutcome.Delivered,
                At = _f.Clock.UtcNow,
                SmtpCode = 250,
                EnhancedCode = "2.0.0",
                Message = "250 OK",
                MxHost = "mx.gmail.test",
                Route = "direct",
                Tls = new TlsInfo(true, "TLS 1.3", "TLS_AES_256_GCM_SHA384", "CN=mx.gmail.test", "CN=Test CA", "ABCD", null, true, "mta-sts", null, true, false),
            }, default);
        }
    }

    [Fact]
    public async Task The_list_is_newest_first_with_the_documented_shape()
    {
        string first = await SendAsync(_a, Body("First", "one@gmail.test"));
        _f.Clock.Advance(TimeSpan.FromMinutes(1));
        string second = await SendAsync(_a, Body("Second", "two@gmail.test", "three@gmail.test"));

        Reply r = await _a.GetAsync("/api/v1/messages");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        JsonElement[] items = r["items"].EnumerateArray().ToArray();
        Assert.Equal([second, first], items.Select(i => i.GetProperty("id").GetString()!));
        JsonElement top = items[0];
        Assert.Equal("Second", top.GetProperty("subject").GetString());
        Assert.Equal("noreply@example.com", top.GetProperty("from").GetString());
        Assert.Equal(["three@gmail.test", "two@gmail.test"], top.GetProperty("recipients").EnumerateArray().Select(x => x.GetString()!));
        Assert.Equal(2, top.GetProperty("recipientCount").GetInt32());
        Assert.Equal("queued", top.GetProperty("status").GetString());
        Assert.True(top.GetProperty("size").GetInt64() > 100);
        Assert.Equal("2026-10-12T12:31:00.000Z", top.GetProperty("receivedAt").GetString());
        Assert.Equal(JsonValueKind.Null, r["next_cursor"].ValueKind);
    }

    [Fact]
    public async Task The_list_filters_and_pages()
    {
        await SendAsync(_a, Body("Invoice 1", "alex@gmail.test"));
        _f.Clock.Advance(TimeSpan.FromHours(1));
        await SendAsync(_a, Body("Invoice 2", "pat@outlook.test"));
        _f.Clock.Advance(TimeSpan.FromHours(1));
        await SendAsync(_a, Body("Welcome", "alex@gmail.test"));

        Assert.Equal(2, (await _a.GetAsync("/api/v1/messages?recipient=alex@gmail.test"))["items"].GetArrayLength());
        Assert.Equal(2, (await _a.GetAsync("/api/v1/messages?subject=invoice"))["items"].GetArrayLength());
        Assert.Equal(3, (await _a.GetAsync("/api/v1/messages?sender=NOREPLY@example.com"))["items"].GetArrayLength());
        Assert.Equal(0, (await _a.GetAsync("/api/v1/messages?sender=other@example.com"))["items"].GetArrayLength());
        Assert.Equal(3, (await _a.GetAsync("/api/v1/messages?status=queued"))["items"].GetArrayLength());
        Assert.Equal(0, (await _a.GetAsync("/api/v1/messages?status=delivered"))["items"].GetArrayLength());
        string from = Uri.EscapeDataString(ApiFixture.Start.AddMinutes(30).ToString("O"));
        Assert.Equal(2, (await _a.GetAsync($"/api/v1/messages?from={from}"))["items"].GetArrayLength());
        string to = Uri.EscapeDataString(ApiFixture.Start.AddMinutes(90).ToString("O"));
        Assert.Equal(2, (await _a.GetAsync($"/api/v1/messages?to={to}"))["items"].GetArrayLength());

        var seen = new List<string>();
        string? cursor = null;
        for (int pages = 0; pages < 5; pages++)
        {
            Reply page = await _a.GetAsync("/api/v1/messages?limit=2" + (cursor is null ? "" : "&cursor=" + Uri.EscapeDataString(cursor)));
            seen.AddRange(page["items"].EnumerateArray().Select(i => i.GetProperty("subject").GetString()!));
            cursor = page["next_cursor"].GetString();
            if (cursor is null)
            {
                break;
            }
        }

        Assert.Equal(["Welcome", "Invoice 2", "Invoice 1"], seen);
    }

    [Fact]
    public async Task Bad_list_parameters_are_validation_failed()
    {
        Reply r = await _a.GetAsync("/api/v1/messages?limit=0&from=yesterday&to=nope&cursor=%25%25");
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains("limit", r.ErrorFields);
        Assert.Contains("from", r.ErrorFields);
        Assert.Contains("to", r.ErrorFields);
        Assert.Equal(HttpStatusCode.BadRequest, (await _a.GetAsync("/api/v1/messages?cursor=garbage")).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await _a.GetAsync("/api/v1/messages?limit=1000")).Status);
    }

    [Fact]
    public async Task Detail_events_and_content_of_a_message()
    {
        string id = await SendAsync(_a, Body("Receipt", "alex@gmail.test"));
        await DeliverAllAsync();

        Reply d = await _a.GetAsync("/api/v1/messages/" + id);
        Assert.Equal(HttpStatusCode.OK, d.Status);
        Assert.Equal(id, d.Str("id"));
        Assert.Equal(ApiFixture.TenantAId.ToString("N"), d.Str("tenantId"));
        Assert.Equal("Receipt", d.Str("subject"));
        Assert.Equal("delivered", d.Str("status"));
        Assert.Equal(["alex@gmail.test"], d["recipients"].EnumerateArray().Select(x => x.GetString()!));
        Assert.False(d["rawRetained"].GetBoolean());
        JsonElement content = d["content"];
        Assert.Equal("available", content.GetProperty("state").GetString());
        Assert.Equal("plain body of Receipt", content.GetProperty("text").GetString()!.Trim());
        Assert.Equal("<p>html body of Receipt</p>", content.GetProperty("html").GetString()!.Trim());
        Assert.Equal(0, content.GetProperty("attachments").GetArrayLength());

        Reply events = await _a.GetAsync($"/api/v1/messages/{id}/events");
        Assert.Equal(HttpStatusCode.OK, events.Status);
        Assert.Equal(["queued", "delivered"], events.Json.EnumerateArray().Select(e => e.GetProperty("type").GetString()!));
        JsonElement delivered = events.Json[1];
        Assert.Equal("alex@gmail.test", delivered.GetProperty("recipient").GetString());
        Assert.Equal(250, delivered.GetProperty("smtpCode").GetInt32());
        Assert.Equal("2.0.0", delivered.GetProperty("enhancedCode").GetString());
        Assert.Equal("mx.gmail.test", delivered.GetProperty("mxHost").GetString());
        Assert.Equal("direct", delivered.GetProperty("route").GetString());
        Assert.Matches("^[0-9a-f]{32}$", delivered.GetProperty("id").GetString()!);
        JsonElement tls = delivered.GetProperty("tls");
        Assert.True(tls.GetProperty("used").GetBoolean());
        Assert.Equal("TLS 1.3", tls.GetProperty("version").GetString());
        Assert.Equal("TLS_AES_256_GCM_SHA384", tls.GetProperty("cipher").GetString());
        Assert.Equal("mta-sts", tls.GetProperty("policy").GetString());
        Assert.Equal(JsonValueKind.Null, events.Json[0].GetProperty("tls").ValueKind);

        Reply body = await _a.GetAsync($"/api/v1/messages/{id}/content");
        Assert.Equal(HttpStatusCode.OK, body.Status);
        Assert.Equal("plain body of Receipt", body.Str("text").Trim());
        Assert.Equal("available", body.Str("state"));
    }

    [Fact]
    public async Task Attachments_are_listed_in_the_content_without_their_bytes()
    {
        Dictionary<string, object?> body = Body("Contract");
        body["attachments"] = new[] { new Dictionary<string, object?> { ["filename"] = "c.pdf", ["content_type"] = "application/pdf", ["content"] = Convert.ToBase64String(new byte[5000]) } };
        string id = await SendAsync(_a, body);
        JsonElement att = (await _a.GetAsync("/api/v1/messages/" + id))["content"].GetProperty("attachments")[0];
        Assert.Equal("c.pdf", att.GetProperty("filename").GetString());
        Assert.Equal("application/pdf", att.GetProperty("content_type").GetString());
        Assert.Equal(5000, att.GetProperty("size").GetInt64());
    }

    [Fact]
    public async Task Content_past_its_retention_is_body_expired_but_the_timeline_stays()
    {
        string id = await SendAsync(_a, Body("Old"));
        await DeliverAllAsync();
        _f.Clock.Advance(TimeSpan.FromDays(8));

        Reply d = await _a.GetAsync("/api/v1/messages/" + id);
        Assert.Equal(HttpStatusCode.OK, d.Status);
        Assert.Equal("body_expired", d["content"].GetProperty("state").GetString());
        Assert.False(d["content"].TryGetProperty("text", out _));

        Reply content = await _a.GetAsync($"/api/v1/messages/{id}/content");
        content.Problem(HttpStatusCode.Gone, "body_expired");
        Assert.Equal(7, content["retention_days"].GetInt32());
        Assert.Equal("2026-10-19T12:30:00.000Z", content.Str("expired_at"));

        (await _a.PostAsync($"/api/v1/messages/{id}/resend")).Problem(HttpStatusCode.Gone, "body_expired");
        Assert.Equal(2, (await _a.GetAsync($"/api/v1/messages/{id}/events")).Json.GetArrayLength());
    }

    [Fact]
    public async Task Unknown_ids_are_message_not_found()
    {
        foreach (string id in new[] { Guid.NewGuid().ToString("N"), "not-an-id", Ids.New().ToString("D") })
        {
            (await _a.GetAsync("/api/v1/messages/" + id)).Problem(HttpStatusCode.NotFound, "message_not_found");
            (await _a.GetAsync($"/api/v1/messages/{id}/events")).Problem(HttpStatusCode.NotFound, "message_not_found");
            (await _a.GetAsync($"/api/v1/messages/{id}/content")).Problem(HttpStatusCode.NotFound, "message_not_found");
            (await _a.PostAsync($"/api/v1/messages/{id}/resend")).Problem(HttpStatusCode.NotFound, "message_not_found");
        }
    }

    [Fact]
    public async Task A_message_older_than_the_metadata_retention_is_gone()
    {
        string id = await SendAsync(_a, Body("Ancient"));
        _f.Clock.Advance(TimeSpan.FromDays(31));
        (await _a.GetAsync("/api/v1/messages/" + id)).Problem(HttpStatusCode.NotFound, "message_not_found");
    }

    // StatsOnly

    [Fact]
    public async Task With_stats_only_every_per_message_resource_is_410_history_not_recorded()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { History = HistoryMode.StatsOnly });
        ApiClient c = await f.KeyClientAsync(ApiFixture.TenantAId);
        Reply sent = await c.PostAsync("/api/v1/messages", Body());
        Assert.Equal(HttpStatusCode.Accepted, sent.Status); // sending works; the id is for log correlation only
        string id = sent.Str("id");

        foreach (Func<Task<Reply>> call in new Func<Task<Reply>>[]
        {
            () => c.GetAsync("/api/v1/messages"),
            () => c.GetAsync("/api/v1/messages/" + id),
            () => c.GetAsync($"/api/v1/messages/{id}/events"),
            () => c.GetAsync($"/api/v1/messages/{id}/content"),
            () => c.PostAsync($"/api/v1/messages/{id}/resend"),
            () => c.GetAsync("/api/v1/messages/" + Guid.NewGuid().ToString("N")),
        })
        {
            Reply r = await call();
            r.Problem(HttpStatusCode.Gone, "history_not_recorded");
            Assert.Equal("StatsOnly", r["history_mode"].GetString());
        }

        // Statistics and the recent-events ring work in both modes.
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/api/v1/stats")).Status);
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/api/v1/stats/recent-events")).Status);
    }

    // Tenant isolation

    [Fact]
    public async Task A_tenant_never_sees_or_touches_another_tenants_messages()
    {
        ApiClient b = await _f.KeyClientAsync(ApiFixture.TenantBId);
        string idB = await SendAsync(b, new Dictionary<string, object?> { ["from"] = "me@globex.test", ["to"] = new[] { "x@y.test" }, ["subject"] = "Secret of B", ["text"] = "b only" });
        string idA = await SendAsync(_a, Body("Mine"));

        Reply list = await _a.GetAsync("/api/v1/messages");
        Assert.Equal([idA], list["items"].EnumerateArray().Select(i => i.GetProperty("id").GetString()!));
        Assert.DoesNotContain("Secret of B", list.Body);

        (await _a.GetAsync("/api/v1/messages/" + idB)).Problem(HttpStatusCode.NotFound, "message_not_found");
        (await _a.GetAsync($"/api/v1/messages/{idB}/events")).Problem(HttpStatusCode.NotFound, "message_not_found");
        (await _a.GetAsync($"/api/v1/messages/{idB}/content")).Problem(HttpStatusCode.NotFound, "message_not_found");
        (await _a.PostAsync($"/api/v1/messages/{idB}/resend")).Problem(HttpStatusCode.NotFound, "message_not_found");
        Assert.Equal(0, (await _a.GetAsync("/api/v1/messages?recipient=x@y.test"))["items"].GetArrayLength());
        Assert.Equal(1, (await b.GetAsync("/api/v1/messages?recipient=x@y.test"))["items"].GetArrayLength());
    }

    // Resend

    [Fact]
    public async Task An_attachment_free_message_is_resent_recomposed_from_its_stored_content()
    {
        string id = await SendAsync(_a, Body("Reset your password", "kim@icloud.test"));
        await DeliverAllAsync();

        Reply r = await _a.PostAsync($"/api/v1/messages/{id}/resend");
        Assert.Equal(HttpStatusCode.Accepted, r.Status);
        Assert.True(r["recomposed"].GetBoolean());
        string newId = r.Str("id");
        Assert.NotEqual(id, newId);

        byte[] raw = (await _f.Storage.Deliveries.GetRawAsync(Guid.Parse(newId), default))!;
        MimeMessage message = await MimeMessage.LoadAsync(new MemoryStream(raw));
        Assert.Equal("Reset your password", message.Subject);
        Assert.Equal("kim@icloud.test", message.To.Mailboxes.Single().Address);
        Assert.Equal("plain body of Reset your password", message.TextBody!.Trim());
        Assert.Equal("<p>html body of Reset your password</p>", message.HtmlBody!.Trim());
        Assert.Equal("noreply@example.com", message.From.Mailboxes.Single().Address);

        Reply detail = await _a.GetAsync("/api/v1/messages/" + newId);
        Assert.Equal("queued", detail.Str("status"));
        Assert.Equal(["kim@icloud.test"], detail["recipients"].EnumerateArray().Select(x => x.GetString()!));
    }

    [Fact]
    public async Task A_recomposed_multi_recipient_message_never_reveals_hidden_recipients()
    {
        Dictionary<string, object?> body = Body("Newsletter", "a@gmail.test", "b@gmail.test");
        body["bcc"] = new[] { "hidden@gmail.test" };
        string id = await SendAsync(_a, body);
        Reply r = await _a.PostAsync($"/api/v1/messages/{id}/resend");
        Assert.Equal(HttpStatusCode.Accepted, r.Status);
        string text = Encoding.UTF8.GetString((await _f.Storage.Deliveries.GetRawAsync(Guid.Parse(r.Str("id")), default))!);
        Assert.DoesNotContain("hidden@gmail.test", text);
        Assert.DoesNotContain("b@gmail.test", text);
        var recipients = (await _a.GetAsync("/api/v1/messages/" + r.Str("id")))["recipients"].EnumerateArray().Select(x => x.GetString()!).Order(StringComparer.Ordinal).ToArray();
        Assert.Equal(["a@gmail.test", "b@gmail.test", "hidden@gmail.test"], recipients);
    }

    [Fact]
    public async Task A_message_with_attachments_that_were_not_stored_cannot_be_resent()
    {
        Dictionary<string, object?> body = Body("With file");
        body["attachments"] = new[] { new Dictionary<string, object?> { ["filename"] = "a.bin", ["content_type"] = "application/octet-stream", ["content"] = Convert.ToBase64String([1, 2, 3]) } };
        string id = await SendAsync(_a, body);
        await DeliverAllAsync();
        (await _a.PostAsync($"/api/v1/messages/{id}/resend")).Problem(HttpStatusCode.Conflict, "attachments_not_stored");
    }

    [Fact]
    public async Task A_message_whose_raw_was_retained_is_resent_verbatim()
    {
        Dictionary<string, object?> body = Body("Signed notice");
        body["attachments"] = new[] { new Dictionary<string, object?> { ["filename"] = "a.bin", ["content_type"] = "application/octet-stream", ["content"] = Convert.ToBase64String([9, 8, 7]) } };
        body["store_attachments"] = true;
        string id = await SendAsync(_a, body);
        byte[] original = (await _f.Storage.Deliveries.GetRawAsync(Guid.Parse(id), default))!;
        await DeliverAllAsync();

        Reply detail = await _a.GetAsync("/api/v1/messages/" + id);
        Assert.True(detail["rawRetained"].GetBoolean());

        Reply r = await _a.PostAsync($"/api/v1/messages/{id}/resend");
        Assert.Equal(HttpStatusCode.Accepted, r.Status);
        Assert.False(r["recomposed"].GetBoolean());
        byte[] resent = (await _f.Storage.Deliveries.GetRawAsync(Guid.Parse(r.Str("id")), default))!;
        MimeMessage a = await MimeMessage.LoadAsync(new MemoryStream(original));
        MimeMessage b = await MimeMessage.LoadAsync(new MemoryStream(resent));
        Assert.Equal(a.MessageId, b.MessageId);
        Assert.Equal(a.Attachments.Count(), b.Attachments.Count());
    }

    [Fact]
    public async Task Truncated_stored_content_is_not_recomposed()
    {
        Dictionary<string, object?> body = Body("Huge");
        body["text"] = new string('x', 300_000);
        string id = await SendAsync(_a, body);
        Assert.True((await _a.GetAsync($"/api/v1/messages/{id}/content"))["truncated"].GetBoolean());
        (await _a.PostAsync($"/api/v1/messages/{id}/resend")).Problem(HttpStatusCode.Conflict, "conflict");
    }

    [Fact]
    public async Task Resend_needs_the_send_scope_and_reading_needs_the_read_scope()
    {
        string id = await SendAsync(_a, Body());
        ApiClient readOnly = await _f.KeyClientAsync(ApiFixture.TenantAId, "read");
        (await readOnly.PostAsync($"/api/v1/messages/{id}/resend")).Problem(HttpStatusCode.Forbidden, "forbidden");
        ApiClient sendOnly = await _f.KeyClientAsync(ApiFixture.TenantAId, "send");
        (await sendOnly.GetAsync("/api/v1/messages")).Problem(HttpStatusCode.Forbidden, "forbidden");
        Assert.Equal(HttpStatusCode.Accepted, (await sendOnly.PostAsync($"/api/v1/messages/{id}/resend")).Status);
    }

    [Fact]
    public async Task Resending_runs_the_sender_policy_again()
    {
        string id = await SendAsync(_a, Body());
        var domain = (await _f.Storage.Config.FindDomainByNameAsync("example.com", default))!;
        await _f.Storage.Config.UpsertDomainAsync(domain with { SendingPaused = true }, default);
        (await _a.PostAsync($"/api/v1/messages/{id}/resend")).Problem(HttpStatusCode.Forbidden, "domain_not_verified");
    }

    [Fact]
    public async Task Tags_given_at_send_time_are_stored_and_returned_by_the_list_the_detail_and_the_tag_filter()
    {
        string welcome = await SendAsync(_a, WithTags(Body("Welcome", "alex@gmail.test"), "welcome", "autumn", "welcome"));
        _f.Clock.Advance(TimeSpan.FromMinutes(1));
        string plain = await SendAsync(_a, Body("Plain", "alex@gmail.test"));
        _f.Clock.Advance(TimeSpan.FromMinutes(1));
        string other = await SendAsync(_a, WithTags(Body("Other", "pat@outlook.test"), "welcome-back"));

        Reply detail = await _a.GetAsync("/api/v1/messages/" + welcome);
        Assert.Equal(["welcome", "autumn"], detail["tags"].EnumerateArray().Select(t => t.GetString()!));   // a repeated tag is stored once
        Assert.Equal(0, (await _a.GetAsync("/api/v1/messages/" + plain))["tags"].GetArrayLength());

        Reply all = await _a.GetAsync("/api/v1/messages");
        JsonElement[] items = all["items"].EnumerateArray().ToArray();
        Assert.Equal([1, 0, 2], items.Select(i => i.GetProperty("tags").GetArrayLength()));
        Assert.Equal(["welcome-back"], items[0].GetProperty("tags").EnumerateArray().Select(t => t.GetString()!));

        Reply byTag = await _a.GetAsync("/api/v1/messages?tag=welcome");
        Assert.Equal([welcome], byTag["items"].EnumerateArray().Select(i => i.GetProperty("id").GetString()!));   // whole tag, not welcome-back
        Assert.Equal([other], (await _a.GetAsync("/api/v1/messages?tag=welcome-back"))["items"].EnumerateArray().Select(i => i.GetProperty("id").GetString()!));
        Assert.Empty((await _a.GetAsync("/api/v1/messages?tag=nothing"))["items"].EnumerateArray());
        Assert.Equal(HttpStatusCode.BadRequest, (await _a.GetAsync("/api/v1/messages?tag=" + new string('x', 65))).Status);
    }

    [Fact]
    public async Task Tags_are_not_recorded_with_stats_only_history()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { History = HistoryMode.StatsOnly });
        ApiClient c = await f.KeyClientAsync(ApiFixture.TenantAId);
        string id = await SendAsync(c, WithTags(Body("Tagged", "alex@gmail.test"), "welcome"));
        (await c.GetAsync("/api/v1/messages/" + id)).Problem(HttpStatusCode.Gone, "history_not_recorded");
        (await c.GetAsync("/api/v1/messages?tag=welcome")).Problem(HttpStatusCode.Gone, "history_not_recorded");
        Assert.Empty((await f.Storage.History.SearchAsync(new MessageQuery(Tag: "welcome"), default)).Items);
    }

    [Fact]
    public async Task The_message_endpoints_work_on_sqlite()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { Sqlite = true });
        ApiClient c = await f.KeyClientAsync(ApiFixture.TenantAId);
        string id = await SendAsync(c, Body("On disk", "pat@outlook.test"));
        Reply list = await c.GetAsync("/api/v1/messages");
        Assert.Equal(id, list["items"][0].GetProperty("id").GetString());
        Assert.Equal(["pat@outlook.test"], list["items"][0].GetProperty("recipients").EnumerateArray().Select(x => x.GetString()!));
        Reply d = await c.GetAsync("/api/v1/messages/" + id);
        Assert.Equal("On disk", d.Str("subject"));
        Assert.Equal("available", d["content"].GetProperty("state").GetString());
        Assert.Equal("queued", (await c.GetAsync($"/api/v1/messages/{id}/events")).Json[0].GetProperty("type").GetString());
        Reply resend = await c.PostAsync($"/api/v1/messages/{id}/resend");
        Assert.Equal(HttpStatusCode.Accepted, resend.Status);
        Assert.True(resend["recomposed"].GetBoolean());
    }
}
