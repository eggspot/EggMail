using System.Net;
using System.Text;
using MimeKit;
using Mta.Core;
using Mta.Host.Api;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

[Collection("api")]
public class ApiSendingTests : IAsyncLifetime
{
    private ApiFixture _f = null!;
    private ApiClient _a = null!;

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync();
        _a = await _f.KeyClientAsync(ApiFixture.TenantAId);
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private static object Basic(Action<Dictionary<string, object?>>? tweak = null)
    {
        var body = new Dictionary<string, object?>
        {
            ["from"] = "Acme <noreply@example.com>",
            ["to"] = new[] { "alex@gmail.test" },
            ["subject"] = "Hello",
            ["text"] = "plain body",
        };
        tweak?.Invoke(body);
        return body;
    }

    private async Task<MimeMessage> RawOfAsync(string id)
    {
        byte[]? raw = await _f.Storage.Deliveries.GetRawAsync(Guid.Parse(id), default);
        Assert.NotNull(raw);
        return await MimeMessage.LoadAsync(new MemoryStream(raw));
    }

    [Fact]
    public async Task Sending_composes_the_message_and_queues_one_delivery_per_recipient()
    {
        Reply r = await _a.PostAsync("/api/v1/messages", Basic(b =>
        {
            b["to"] = new[] { "alex@gmail.test", "Pat <pat@outlook.test>" };
            b["cc"] = new[] { "cc@gmail.test" };
            b["bcc"] = new[] { "hidden@gmail.test" };
            b["reply_to"] = "support@example.com";
            b["html"] = "<p>html body</p>";
            b["headers"] = new Dictionary<string, string> { ["X-Campaign"] = "autumn" };
            b["tags"] = new[] { "welcome" };
        }));
        Assert.Equal(HttpStatusCode.Accepted, r.Status);
        Assert.Equal("queued", r.Str("status"));
        Assert.Equal(4, r["recipients"].GetInt32());
        Assert.Matches("^[0-9a-f]{32}$", r.Str("id"));

        var deliveries = await _f.Storage.Deliveries.ClaimAsync("t", 100, _f.Clock.UtcNow, TimeSpan.FromMinutes(1), default);
        Assert.Equal(["alex@gmail.test", "cc@gmail.test", "hidden@gmail.test", "pat@outlook.test"], deliveries.Select(d => d.Recipient.ToString()).Order(StringComparer.Ordinal));
        Assert.All(deliveries, d => Assert.Equal("noreply@example.com", d.EnvelopeFrom.ToString()));
        Assert.All(deliveries, d => Assert.Equal(MessageSource.Api, d.Source));
        Assert.All(deliveries, d => Assert.Equal("example.com", d.SendingDomain));

        MimeMessage message = await RawOfAsync(r.Str("id"));
        Assert.Equal("Hello", message.Subject);
        Assert.Equal("Acme", message.From.Mailboxes.Single().Name);
        Assert.Equal(["alex@gmail.test", "pat@outlook.test"], message.To.Mailboxes.Select(m => m.Address));
        Assert.Equal("cc@gmail.test", message.Cc.Mailboxes.Single().Address);
        Assert.Equal("support@example.com", message.ReplyTo.Mailboxes.Single().Address);
        Assert.Empty(message.Bcc); // Bcc is an envelope matter
        Assert.DoesNotContain("hidden@gmail.test", Encoding.UTF8.GetString((await _f.Storage.Deliveries.GetRawAsync(Guid.Parse(r.Str("id")), default))!));
        Assert.Equal("autumn", message.Headers["X-Campaign"]);
        Assert.Equal("plain body", message.TextBody!.Trim());
        Assert.Equal("<p>html body</p>", message.HtmlBody!.Trim());
        Assert.False(string.IsNullOrEmpty(message.MessageId));
    }

    [Fact]
    public async Task Duplicate_recipients_are_counted_once()
    {
        Reply r = await _a.PostAsync("/api/v1/messages", Basic(b => b["to"] = new[] { "a@gmail.test", "a@GMAIL.test", "a@gmail.test" }));
        Assert.Equal(1, r["recipients"].GetInt32());
    }

    [Fact]
    public async Task Attachments_travel_as_base64_and_inline_resources_keep_their_content_id()
    {
        byte[] pdf = [.. "%PDF-1.4 fake"u8, .. Enumerable.Range(0, 200).Select(i => (byte)i)];
        Reply r = await _a.PostAsync("/api/v1/messages", Basic(b =>
        {
            b["html"] = "<img src=\"cid:logo\">";
            b["attachments"] = new[]
            {
                new Dictionary<string, object?> { ["filename"] = "contract.pdf", ["content_type"] = "application/pdf", ["content"] = Convert.ToBase64String(pdf) },
                new Dictionary<string, object?> { ["filename"] = "logo.png", ["content_type"] = "image/png", ["content"] = Convert.ToBase64String([1, 2, 3, 4]), ["content_id"] = "logo" },
            };
        }));
        Assert.Equal(HttpStatusCode.Accepted, r.Status);

        MimeMessage message = await RawOfAsync(r.Str("id"));
        var parts = message.BodyParts.OfType<MimePart>().Where(p => p.FileName is not null).ToList();
        MimePart attachment = parts.Single(p => p.FileName == "contract.pdf");
        using var ms = new MemoryStream();
        attachment.Content!.DecodeTo(ms);
        Assert.Equal(pdf, ms.ToArray());
        Assert.Equal("application/pdf", attachment.ContentType.MimeType);
        Assert.Equal("logo", parts.Single(p => p.FileName == "logo.png").ContentId);
    }

    [Fact]
    public async Task The_from_domain_must_be_registered_and_verified_for_the_tenant()
    {
        Reply foreign = await _a.PostAsync("/api/v1/messages", Basic(b => b["from"] = "someone@globex.test"));
        foreign.Problem(HttpStatusCode.Forbidden, "domain_not_verified");
        Assert.Equal("sender_domain_not_registered", foreign["reason"].GetString());

        Reply unknown = await _a.PostAsync("/api/v1/messages", Basic(b => b["from"] = "x@unknown.test"));
        unknown.Problem(HttpStatusCode.Forbidden, "domain_not_verified");

        await _f.AddVerifiedDomainAsync(ApiFixture.TenantAId, "pending.test", DomainStatus.Pending);
        Reply pending = await _a.PostAsync("/api/v1/messages", Basic(b => b["from"] = "x@pending.test"));
        pending.Problem(HttpStatusCode.Forbidden, "domain_not_verified");
        Assert.Equal("sender_domain_not_verified", pending["reason"].GetString());

        await _f.AddVerifiedDomainAsync(ApiFixture.TenantAId, "failed.test", DomainStatus.Failed, paused: true);
        (await _a.PostAsync("/api/v1/messages", Basic(b => b["from"] = "x@failed.test"))).Problem(HttpStatusCode.Forbidden, "domain_not_verified");

        await _f.AddVerifiedDomainAsync(ApiFixture.TenantAId, "paused.test", DomainStatus.Verified, paused: true);
        Reply paused = await _a.PostAsync("/api/v1/messages", Basic(b => b["from"] = "x@paused.test"));
        paused.Problem(HttpStatusCode.Forbidden, "domain_not_verified");
        Assert.Equal("sending_paused", paused["reason"].GetString());

        // A domain in temporary failure still sends (design section 8), and subdomains of a verified domain are fine.
        await _f.AddVerifiedDomainAsync(ApiFixture.TenantAId, "flaky.test", DomainStatus.TemporaryFailure);
        Assert.Equal(HttpStatusCode.Accepted, (await _a.PostAsync("/api/v1/messages", Basic(b => b["from"] = "x@flaky.test"))).Status);
        Assert.Equal(HttpStatusCode.Accepted, (await _a.PostAsync("/api/v1/messages", Basic(b => b["from"] = "x@news.example.com"))).Status);
    }

    [Fact]
    public async Task A_suspended_tenant_cannot_send_even_with_a_key_issued_before()
    {
        string token = await _f.AddKeyAsync(ApiFixture.TenantAId, "send");
        await _f.Storage.Config.UpsertTenantAsync(_f.TenantA with { Enabled = false }, default);
        Reply r = await _f.NewClient().WithBearer(token).PostAsync("/api/v1/messages", Basic());
        r.Problem(HttpStatusCode.Forbidden, "tenant_disabled");
    }

    [Fact]
    public async Task Missing_and_invalid_fields_are_reported_per_field()
    {
        Reply empty = await _a.PostAsync("/api/v1/messages", new { });
        empty.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["from", "to", "subject", "text"], empty.ErrorFields);

        Reply bad = await _a.PostAsync("/api/v1/messages", Basic(b =>
        {
            b["to"] = new[] { "ok@x.test", "not an address" };
            b["cc"] = new[] { "@nope" };
            b["reply_to"] = "also bad";
        }));
        bad.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["to[1]", "cc[0]", "reply_to"], bad.ErrorFields);
    }

    [Fact]
    public async Task Header_injection_is_rejected_never_sanitized()
    {
        Reply subject = await _a.PostAsync("/api/v1/messages", Basic(b => b["subject"] = "Hi\r\nBcc: evil@x.test"));
        subject.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains("subject", subject.ErrorFields);

        Reply value = await _a.PostAsync("/api/v1/messages", Basic(b => b["headers"] = new Dictionary<string, string> { ["X-Ok"] = "a\r\nBcc: evil@x.test" }));
        value.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains("headers", value.ErrorFields);

        Reply name = await _a.PostAsync("/api/v1/messages", Basic(b => b["headers"] = new Dictionary<string, string> { ["X-Bad\r\nName"] = "v" }));
        name.Problem(HttpStatusCode.BadRequest, "validation_failed");

        Reply nul = await _a.PostAsync("/api/v1/messages", Basic(b => b["headers"] = new Dictionary<string, string> { ["X-Ok"] = "a\0b" }));
        nul.Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Theory]
    [InlineData("From")]
    [InlineData("Bcc")]
    [InlineData("DKIM-Signature")]
    [InlineData("Received")]
    [InlineData("X-Mta-Anything")]
    [InlineData("Content-Type")]
    public async Task Headers_owned_by_the_server_cannot_be_set(string name)
    {
        Reply r = await _a.PostAsync("/api/v1/messages", Basic(b => b["headers"] = new Dictionary<string, string> { [name] = "x" }));
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains("headers", r.ErrorFields);
    }

    [Fact]
    public async Task At_most_the_configured_number_of_recipients()
    {
        string[] many = Enumerable.Range(0, 51).Select(i => $"u{i}@gmail.test").ToArray();
        Reply r = await _a.PostAsync("/api/v1/messages", Basic(b => b["to"] = many));
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains("to", r.ErrorFields);
        string[] fifty = many.Take(50).ToArray();
        Assert.Equal(HttpStatusCode.Accepted, (await _a.PostAsync("/api/v1/messages", Basic(b => b["to"] = fifty))).Status);
    }

    [Fact]
    public async Task Attachment_problems_name_the_attachment_member()
    {
        Reply r = await _a.PostAsync("/api/v1/messages", Basic(b => b["attachments"] = new object[]
        {
            new Dictionary<string, object?> { ["filename"] = "", ["content_type"] = "application/pdf", ["content"] = "AAAA" },
            new Dictionary<string, object?> { ["filename"] = "x.bin", ["content_type"] = "multipart/mixed", ["content"] = "AAAA" },
            new Dictionary<string, object?> { ["filename"] = "y.bin", ["content_type"] = "application/pdf" },
        }));
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains("attachments[0].filename", r.ErrorFields);
        Assert.Contains("attachments[1].content_type", r.ErrorFields);
        Assert.Contains("attachments[2].content", r.ErrorFields);

        Reply notBase64 = await _a.SendAsync(HttpMethod.Post, "/api/v1/messages", """{"from":"a@example.com","to":["b@x.test"],"subject":"s","text":"t","attachments":[{"filename":"a.txt","content_type":"text/plain","content":"***not base64***"}]}""");
        notBase64.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains("attachments[0].content", notBase64.ErrorFields);
    }

    [Fact]
    public async Task A_message_over_the_size_limit_is_413()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.MaxMessageBytes = 10_000 });
        ApiClient c = await f.KeyClientAsync(ApiFixture.TenantAId);
        string big = Convert.ToBase64String(new byte[20_000]);
        Reply r = await c.PostAsync("/api/v1/messages", Basic(b => b["attachments"] = new[]
        {
            new Dictionary<string, object?> { ["filename"] = "big.bin", ["content_type"] = "application/octet-stream", ["content"] = big },
        }));
        r.Problem(HttpStatusCode.RequestEntityTooLarge, "payload_too_large");
        Assert.Empty(await f.Storage.Deliveries.ClaimAsync("t", 10, f.Clock.UtcNow, TimeSpan.FromMinutes(1), default));
    }

    [Fact]
    public async Task The_json_body_has_its_own_larger_limit()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.MaxSendBodyBytes = 5_000 });
        ApiClient c = await f.KeyClientAsync(ApiFixture.TenantAId);
        string big = Convert.ToBase64String(new byte[20_000]);
        Reply r = await c.PostAsync("/api/v1/messages", Basic(b => b["attachments"] = new[]
        {
            new Dictionary<string, object?> { ["filename"] = "big.bin", ["content_type"] = "application/octet-stream", ["content"] = big },
        }));
        r.Problem(HttpStatusCode.RequestEntityTooLarge, "payload_too_large");
    }

    [Fact]
    public async Task Suppressed_recipients_are_accepted_into_the_response()
    {
        await _f.Storage.Config.AddSuppressionAsync(new SuppressionRecord(ApiFixture.TenantAId, "blocked@gmail.test", SuppressionReason.Manual, null, _f.Clock.UtcNow, null), default);
        Reply r = await _a.PostAsync("/api/v1/messages", Basic(b => b["to"] = new[] { "blocked@gmail.test", "fine@gmail.test" }));
        Assert.Equal(HttpStatusCode.Accepted, r.Status);
        Assert.Equal(2, r["recipients"].GetInt32());
    }

    [Fact]
    public async Task International_addresses_are_composed_with_utf8_headers()
    {
        Reply r = await _a.PostAsync("/api/v1/messages", Basic(b =>
        {
            b["to"] = new[] { "用户@例子.test" };
            b["subject"] = "Grüße";
        }));
        Assert.Equal(HttpStatusCode.Accepted, r.Status);
        var delivery = (await _f.Storage.Deliveries.ClaimAsync("t", 10, _f.Clock.UtcNow, TimeSpan.FromMinutes(1), default)).Single();
        Assert.True(delivery.Recipient.IsInternational);
    }

    // Raw

    private static string RawBody(string from, string[] to, MimeMessage message)
    {
        using var ms = new MemoryStream();
        message.WriteTo(ms);
        return System.Text.Json.JsonSerializer.Serialize(new { from, to, raw = Convert.ToBase64String(ms.ToArray()) });
    }

    private static MimeMessage Mail(string from = "noreply@example.com", string to = "dest@gmail.test", bool signature = false)
    {
        var m = new MimeMessage();
        m.From.Add(MailboxAddress.Parse(from));
        m.To.Add(MailboxAddress.Parse(to));
        m.Subject = "Pre-built";
        m.Body = new TextPart("plain") { Text = "hello raw" };
        if (signature)
        {
            m.Headers.Add("X-Pre-Signed", "yes");
        }

        return m;
    }

    [Fact]
    public async Task A_pre_built_message_is_queued_verbatim()
    {
        Reply r = await _a.SendAsync(HttpMethod.Post, "/api/v1/messages/raw", RawBody("noreply@example.com", ["dest@gmail.test"], Mail(signature: true)));
        Assert.Equal(HttpStatusCode.Accepted, r.Status);
        Assert.Equal(1, r["recipients"].GetInt32());
        MimeMessage stored = await RawOfAsync(r.Str("id"));
        Assert.Equal("yes", stored.Headers["X-Pre-Signed"]);
        Assert.Equal("Pre-built", stored.Subject);
        Assert.Equal("hello raw", stored.TextBody!.Trim());
    }

    [Fact]
    public async Task Raw_messages_are_checked_like_composed_ones()
    {
        // Header From of an unverified domain, although the envelope sender is fine.
        Reply spoof = await _a.SendAsync(HttpMethod.Post, "/api/v1/messages/raw", RawBody("noreply@example.com", ["dest@gmail.test"], Mail(from: "ceo@globex.test")));
        spoof.Problem(HttpStatusCode.Forbidden, "domain_not_verified");

        Reply notBase64 = await _a.SendAsync(HttpMethod.Post, "/api/v1/messages/raw", """{"from":"a@example.com","to":["b@x.test"],"raw":"%%%"}""");
        notBase64.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains("raw", notBase64.ErrorFields);

        Reply noFrom = await _a.SendAsync(HttpMethod.Post, "/api/v1/messages/raw", System.Text.Json.JsonSerializer.Serialize(new
        {
            from = "noreply@example.com",
            to = new[] { "dest@gmail.test" },
            raw = Convert.ToBase64String(Encoding.ASCII.GetBytes("Subject: no from\r\n\r\nbody\r\n")),
        }));
        noFrom.Problem(HttpStatusCode.BadRequest, "validation_failed");

        Reply empty = await _a.SendAsync(HttpMethod.Post, "/api/v1/messages/raw", """{"from":"a@example.com","to":[],"raw":""}""");
        empty.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains("raw", empty.ErrorFields);
        Assert.Contains("to", empty.ErrorFields);
    }

    [Fact]
    public async Task Bare_lf_messages_are_normalized_to_crlf()
    {
        string lf = "From: noreply@example.com\nTo: dest@gmail.test\nSubject: lf\n\nbody\n";
        Reply r = await _a.SendAsync(HttpMethod.Post, "/api/v1/messages/raw", System.Text.Json.JsonSerializer.Serialize(new { from = "noreply@example.com", to = new[] { "dest@gmail.test" }, raw = Convert.ToBase64String(Encoding.ASCII.GetBytes(lf)) }));
        Assert.Equal(HttpStatusCode.Accepted, r.Status);
        byte[] raw = (await _f.Storage.Deliveries.GetRawAsync(Guid.Parse(r.Str("id")), default))!;
        string text = Encoding.ASCII.GetString(raw);
        Assert.DoesNotContain("\n\n", text);
        Assert.DoesNotMatch("[^\r]\n", text);
    }

    // Idempotency

    [Fact]
    public async Task The_same_key_and_body_return_the_original_result_and_queue_nothing_new()
    {
        object body = Basic();
        Reply first = await _a.PostAsync("/api/v1/messages", body, ("Idempotency-Key", "order-1001"));
        Reply again = await _a.PostAsync("/api/v1/messages", body, ("Idempotency-Key", "order-1001"));
        Assert.Equal(HttpStatusCode.Accepted, first.Status);
        Assert.Equal(HttpStatusCode.Accepted, again.Status);
        Assert.Equal(first.Str("id"), again.Str("id"));
        Assert.Equal(first["recipients"].GetInt32(), again["recipients"].GetInt32());
        Assert.Null(first.Header("Idempotent-Replayed"));
        Assert.Equal("true", again.Header("Idempotent-Replayed"));
        Assert.Single(await _f.Storage.Deliveries.ClaimAsync("t", 10, _f.Clock.UtcNow, TimeSpan.FromMinutes(1), default));
    }

    [Fact]
    public async Task The_same_key_with_another_body_is_409_idempotency_conflict()
    {
        await _a.PostAsync("/api/v1/messages", Basic(), ("Idempotency-Key", "k1"));
        Reply conflict = await _a.PostAsync("/api/v1/messages", Basic(b => b["subject"] = "Different"), ("Idempotency-Key", "k1"));
        conflict.Problem(HttpStatusCode.Conflict, "idempotency_conflict");
        Assert.Single(await _f.Storage.Deliveries.ClaimAsync("t", 10, _f.Clock.UtcNow, TimeSpan.FromMinutes(1), default));

        // The other endpoint is a different request, too.
        Reply raw = await _a.SendAsync(HttpMethod.Post, "/api/v1/messages/raw", RawBody("noreply@example.com", ["dest@gmail.test"], Mail()), ("Idempotency-Key", "k1"));
        raw.Problem(HttpStatusCode.Conflict, "idempotency_conflict");
    }

    [Fact]
    public async Task Idempotency_keys_belong_to_a_tenant_and_expire()
    {
        ApiClient b = await _f.KeyClientAsync(ApiFixture.TenantBId);
        Reply a1 = await _a.PostAsync("/api/v1/messages", Basic(), ("Idempotency-Key", "shared"));
        Reply b1 = await b.PostAsync("/api/v1/messages", Basic(x => x["from"] = "me@globex.test"), ("Idempotency-Key", "shared"));
        Assert.Equal(HttpStatusCode.Accepted, b1.Status);
        Assert.NotEqual(a1.Str("id"), b1.Str("id"));

        _f.Clock.Advance(TimeSpan.FromHours(25));
        Reply a2 = await _a.PostAsync("/api/v1/messages", Basic(x => x["subject"] = "Different"), ("Idempotency-Key", "shared"));
        Assert.Equal(HttpStatusCode.Accepted, a2.Status);
        Assert.NotEqual(a1.Str("id"), a2.Str("id"));
    }

    [Fact]
    public async Task Without_a_key_every_request_creates_a_message()
    {
        Reply one = await _a.PostAsync("/api/v1/messages", Basic());
        Reply two = await _a.PostAsync("/api/v1/messages", Basic());
        Assert.NotEqual(one.Str("id"), two.Str("id"));
    }

    [Theory]
    [InlineData("has space")]
    [InlineData("tab\there")]
    public async Task Idempotency_keys_are_printable_ascii(string key)
    {
        Reply r = await _a.PostAsync("/api/v1/messages", Basic(), ("Idempotency-Key", key));
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["Idempotency-Key"], r.ErrorFields);
    }

    [Fact]
    public async Task A_rejected_request_does_not_burn_the_key()
    {
        Reply bad = await _a.PostAsync("/api/v1/messages", Basic(b => b["from"] = "x@unknown.test"), ("Idempotency-Key", "retry-me"));
        bad.Problem(HttpStatusCode.Forbidden, "domain_not_verified");
        Reply good = await _a.PostAsync("/api/v1/messages", Basic(), ("Idempotency-Key", "retry-me"));
        Assert.Equal(HttpStatusCode.Accepted, good.Status);
    }

    [Fact]
    public async Task Idempotency_works_on_sqlite_too()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { Sqlite = true });
        ApiClient c = await f.KeyClientAsync(ApiFixture.TenantAId);
        Reply first = await c.PostAsync("/api/v1/messages", Basic(), ("Idempotency-Key", "sq-1"));
        Reply again = await c.PostAsync("/api/v1/messages", Basic(), ("Idempotency-Key", "sq-1"));
        Assert.Equal(first.Str("id"), again.Str("id"));
        (await c.PostAsync("/api/v1/messages", Basic(b => b["subject"] = "other"), ("Idempotency-Key", "sq-1"))).Problem(HttpStatusCode.Conflict, "idempotency_conflict");
        Assert.Single(await f.Storage.Deliveries.ClaimAsync("t", 10, f.Clock.UtcNow, TimeSpan.FromMinutes(1), default));
    }

    [Fact]
    public async Task Sending_needs_the_send_scope_and_a_tenant()
    {
        ApiClient readOnly = await _f.KeyClientAsync(ApiFixture.TenantAId, "read");
        (await readOnly.PostAsync("/api/v1/messages", Basic())).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await _f.NewClient().PostAsync("/api/v1/messages", Basic())).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        ApiClient admin = await _f.SignedInAsync("root");
        (await admin.PostAsync("/api/v1/messages", Basic())).Problem(HttpStatusCode.BadRequest, "validation_failed");
        admin.TenantId = ApiFixture.TenantAId;
        Assert.Equal(HttpStatusCode.Accepted, (await admin.PostAsync("/api/v1/messages", Basic())).Status);
    }
}
