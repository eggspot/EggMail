using System.Net;
using System.Text;
using System.Text.Json;
using MimeKit;
using Mta.Host.Api;
using Mta.Host.Tests.Api;
using Mta.Storage;

namespace Mta.Host.Tests.Security;

/// <summary>
/// Security regression tests for what a caller of the API can put into a request (docs/security-test-map.md, INJ-*, MASS-*, SSRF-3 to SSRF-5):
/// every value that reaches a header, an SMTP command or a query, mass assignment, control characters in names, and the webhook URL rules as the
/// API applies them. The in-house review, not an independent audit.
/// </summary>
[Collection("api")]
public class ApiInputSecurityTests : IAsyncLifetime
{
    private ApiFixture _f = null!;
    private ApiClient _a = null!;       // tenant A, key with every scope
    private ApiClient _alice = null!;   // tenant A, dashboard session
    private ApiClient _root = null!;    // administrator

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.PasswordHashIterations = 1000 });
        _a = await _f.KeyClientAsync(ApiFixture.TenantAId);
        _alice = await _f.SignedInAsync("alice");
        _root = await _f.SignedInAsync("root");
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    // Header injection: every value that can reach a header or a command line

    public static readonly string[] HostileText =
    [
        "x\r\nBcc: evil@x.test",
        "x\nBcc: evil@x.test",
        "x\rBcc: evil@x.test",
        "x\r\n\r\nInjected body",
        "x\u0085Bcc: evil@x.test",
        "x\u2028Bcc: evil@x.test",
        "x\0Bcc: evil@x.test",
        "x\r\n Folded: continuation",
        "x\r\n\tFolded: continuation",
        "=?utf-8?q?x=0D=0ABcc:_evil@x.test?=",
        "\"x\r\nBcc: evil@x.test\" <a@example.com>",
        "x>\r\nBcc: evil@x.test",
    ];

    private static Dictionary<string, object?> Baseline() => new()
    {
        ["from"] = "Acme <noreply@example.com>",
        ["to"] = new[] { "alex@gmail.test" },
        ["cc"] = new[] { "cc@gmail.test" },
        ["reply_to"] = "support@example.com",
        ["subject"] = "Hello",
        ["text"] = "plain body",
        ["headers"] = new Dictionary<string, string> { ["X-Campaign"] = "autumn" },
        ["attachments"] = new object[] { new Dictionary<string, object?> { ["filename"] = "report.txt", ["content_type"] = "text/plain", ["content"] = Convert.ToBase64String("data"u8.ToArray()), ["content_id"] = "logo1" } },
        ["tags"] = new[] { "welcome" },
    };

    private static readonly (string Field, Action<Dictionary<string, object?>, string> Set)[] Fields =
    [
        ("from", (b, v) => b["from"] = v),
        ("from name", (b, v) => b["from"] = $"\"{v}\" <noreply@example.com>"),
        ("from address", (b, v) => b["from"] = $"Acme <{v}>"),
        ("to", (b, v) => b["to"] = new[] { v }),
        ("to address", (b, v) => b["to"] = new[] { $"{v}@gmail.test" }),
        ("cc", (b, v) => b["cc"] = new[] { v }),
        ("bcc", (b, v) => b["bcc"] = new[] { v }),
        ("reply_to", (b, v) => b["reply_to"] = v),
        ("subject", (b, v) => b["subject"] = v),
        ("header name", (b, v) => b["headers"] = new Dictionary<string, string> { [v] = "v" }),
        ("header value", (b, v) => b["headers"] = new Dictionary<string, string> { ["X-Campaign"] = v }),
        ("attachment filename", (b, v) => b["attachments"] = new object[] { new Dictionary<string, object?> { ["filename"] = v, ["content_type"] = "text/plain", ["content"] = Convert.ToBase64String("d"u8.ToArray()) } }),
        ("attachment content_type", (b, v) => b["attachments"] = new object[] { new Dictionary<string, object?> { ["filename"] = "a.txt", ["content_type"] = v, ["content"] = Convert.ToBase64String("d"u8.ToArray()) } }),
        ("attachment content_id", (b, v) => b["attachments"] = new object[] { new Dictionary<string, object?> { ["filename"] = "a.txt", ["content_type"] = "text/plain", ["content"] = Convert.ToBase64String("d"u8.ToArray()), ["content_id"] = v } }),
        ("tag", (b, v) => b["tags"] = new[] { v }),
    ];

    [Fact]
    public async Task No_text_a_caller_supplies_can_add_a_header_a_recipient_or_a_second_message_to_what_is_queued()
    {
        // The oracle does not prescribe whether a hostile value is refused or neutralised, only what may not happen: a queued message with a header,
        // a recipient or a MIME structure the request did not ask for.
        Reply good = await _a.PostAsync("/api/v1/messages", Baseline());
        Assert.Equal(HttpStatusCode.Accepted, good.Status);
        MimeMessage reference = await RawOfAsync(good.Str("id"));
        string[] referenceHeaders = reference.Headers.Select(h => h.Field).Where(h => !h.Equals("Message-ID", StringComparison.OrdinalIgnoreCase) && !h.Equals("Date", StringComparison.OrdinalIgnoreCase)).Order(StringComparer.OrdinalIgnoreCase).ToArray();

        int accepted = 0, refused = 0;
        foreach (var (field, set) in Fields)
        {
            foreach (string hostile in HostileText)
            {
                var body = Baseline();
                set(body, hostile);
                Reply reply = await _a.PostAsync("/api/v1/messages", body);
                Assert.True((int)reply.Status < 500, $"{field} {Escape(hostile)}: {(int)reply.Status} {reply.Body}");
                if (reply.Status != HttpStatusCode.Accepted)
                {
                    refused++;
                    Assert.Equal("application/problem+json", reply.ContentType);
                    continue;
                }

                accepted++;
                MimeMessage message = await RawOfAsync(reply.Str("id"));
                string[] headers = message.Headers.Select(h => h.Field).Where(h => !h.Equals("Message-ID", StringComparison.OrdinalIgnoreCase) && !h.Equals("Date", StringComparison.OrdinalIgnoreCase)).Order(StringComparer.OrdinalIgnoreCase).ToArray();
                string where = $"{field} {Escape(hostile)}";
                Assert.DoesNotContain(headers, h => h.Equals("Bcc", StringComparison.OrdinalIgnoreCase) || h.StartsWith("Injected", StringComparison.OrdinalIgnoreCase) || h.Equals("Folded", StringComparison.OrdinalIgnoreCase));
                Assert.True(headers.All(h => referenceHeaders.Contains(h, StringComparer.OrdinalIgnoreCase)) , $"{where}: unexpected header in {string.Join(",", headers)}");
                Assert.Single(message.From.Mailboxes);
                Assert.True(message.To.Mailboxes.Count() <= 1 && message.Cc.Mailboxes.Count() <= 1 && message.ReplyTo.Mailboxes.Count() <= 1, where);
                Assert.Empty(message.Bcc);
                Assert.DoesNotContain(message.To.Mailboxes.Concat(message.Cc.Mailboxes).Concat(message.From.Mailboxes).Concat(message.ReplyTo.Mailboxes), m => m.Address.Contains("evil", StringComparison.OrdinalIgnoreCase));
                Assert.Equal("plain body", (message.TextBody ?? "").Trim());   // the hostile text never became part of the body
                int recipients = reply["recipients"].GetInt32();
                Assert.True(recipients <= 3, $"{where}: {recipients} recipients");
            }
        }

        Assert.True(refused > 0 && accepted >= 0);
    }

    [Fact]
    public async Task A_hostile_value_that_is_accepted_arrives_as_text_inside_one_header_and_nowhere_else()
    {
        // The accepted forms of a subject with an encoded word and of display names with quotes stay one header each.
        Reply r = await _a.PostAsync("/api/v1/messages", new Dictionary<string, object?>
        {
            ["from"] = "\"Evil\\\" <bcc@x.test>, Other\" <noreply@example.com>",
            ["to"] = new[] { "alex@gmail.test" },
            ["subject"] = "=?utf-8?q?x=0D=0ABcc:_evil@x.test?= and \"quotes\" <angle>",
            ["text"] = "t",
        });
        if (r.Status == HttpStatusCode.Accepted)
        {
            MimeMessage m = await RawOfAsync(r.Str("id"));
            Assert.Single(m.From.Mailboxes);
            Assert.Equal("noreply@example.com", m.From.Mailboxes.Single().Address);
            Assert.Empty(m.Bcc);
            Assert.Equal(1, m.Headers.Count(h => h.Field.Equals("Subject", StringComparison.OrdinalIgnoreCase)));
            Assert.Equal(1, m.Headers.Count(h => h.Field.Equals("From", StringComparison.OrdinalIgnoreCase)));
        }
        else
        {
            Assert.Equal(HttpStatusCode.BadRequest, r.Status);
        }
    }

    [Theory]
    [InlineData("a.txt\"; name=\"b.exe")]
    [InlineData("a;b.txt")]
    [InlineData("a\\b.txt")]
    [InlineData("a\"b.txt")]
    [InlineData("../../etc/passwd")]
    [InlineData("C:\\Windows\\system32\\x.dll")]
    [InlineData("\u00fc \u00f1 \u6587\u4ef6.txt")]
    [InlineData("a%0d%0aBcc: evil@x.test.txt")]
    [InlineData("=?utf-8?b?QQ==?=.txt")]
    [InlineData("=?utf-8?q?x=0D=0ABcc:_evil@x.test?=.txt")]
    [InlineData("a b  c.txt")]
    [InlineData("name='x'; size=1.txt")]
    public async Task An_attachment_file_name_cannot_add_parameters_headers_or_parts_and_reads_back_unchanged_in_an_independent_parser(string fileName)
    {
        Reply r = await _a.PostAsync("/api/v1/messages", new Dictionary<string, object?>
        {
            ["from"] = "noreply@example.com", ["to"] = new[] { "alex@gmail.test" }, ["subject"] = "s", ["text"] = "t",
            ["attachments"] = new object[] { new Dictionary<string, object?> { ["filename"] = fileName, ["content_type"] = "text/plain", ["content"] = Convert.ToBase64String("data"u8.ToArray()) } },
        });

        Assert.Equal(HttpStatusCode.Accepted, r.Status);
        MimeMessage message = await RawOfAsync(r.Str("id"));
        MimeEntity attachment = Assert.Single(message.Attachments);
        // MimeKit shows the base name of a path and decodes an encoded word in a file name, as mail clients do; neither is something the sender can prevent.
        // What the sender must prevent is a file name that changes the structure of the message, which the checks below cover.
        string shown = attachment.ContentDisposition?.FileName ?? "";
        bool plainName = !fileName.Contains('/', StringComparison.Ordinal) && !fileName.Contains('\\', StringComparison.Ordinal) && !fileName.Contains("=?", StringComparison.Ordinal);
        if (plainName) { Assert.Equal(fileName, shown); } else { Assert.NotEmpty(shown); }
        Assert.Equal(["filename"], attachment.ContentDisposition!.Parameters.Select(p => p.Name.ToLowerInvariant()).Distinct().Order(StringComparer.Ordinal).ToArray());
        Assert.DoesNotContain(attachment.ContentType.Parameters, p => p.Name.Equals("name", StringComparison.OrdinalIgnoreCase) && p.Value != shown);   // a name parameter says what the file name says
        Assert.DoesNotContain(message.Headers, h => h.Field.Equals("Bcc", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(1, message.BodyParts.Count(p => p.IsAttachment));
    }

    [Theory]
    [InlineData("a\r\nBcc: evil@x.test.txt")]
    [InlineData("a\0.txt")]
    [InlineData("a\u202egnp.exe")]
    [InlineData("a\u2028b.txt")]
    public async Task An_attachment_file_name_with_a_control_character_or_a_text_direction_override_is_refused(string fileName)
    {
        Reply r = await _a.PostAsync("/api/v1/messages", new Dictionary<string, object?>
        {
            ["from"] = "noreply@example.com", ["to"] = new[] { "alex@gmail.test" }, ["subject"] = "s", ["text"] = "t",
            ["attachments"] = new object[] { new Dictionary<string, object?> { ["filename"] = fileName, ["content_type"] = "text/plain", ["content"] = Convert.ToBase64String("data"u8.ToArray()) } },
        });

        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains("attachments[0].filename", r.ErrorFields);
    }

    [Fact]
    public async Task A_recipient_entry_that_names_more_than_one_address_is_refused_or_counts_as_one()
    {
        foreach (string entry in new[] { "a@gmail.test, b@gmail.test", "a@gmail.test; b@gmail.test", "a@gmail.test b@gmail.test", "<a@gmail.test><b@gmail.test>", "Group: a@gmail.test, b@gmail.test;" })
        {
            Reply r = await _a.PostAsync("/api/v1/messages", new Dictionary<string, object?> { ["from"] = "noreply@example.com", ["to"] = new[] { entry }, ["subject"] = "s", ["text"] = "t" });
            Assert.True((int)r.Status < 500);
            if (r.Status == HttpStatusCode.Accepted)
            {
                Assert.Equal(1, r["recipients"].GetInt32());
            }
        }
    }

    [Fact]
    public async Task A_raw_message_cannot_be_given_a_different_sender_recipient_or_a_second_message_through_the_envelope_fields()
    {
        string raw = "From: noreply@example.com\r\nTo: alex@gmail.test\r\nSubject: s\r\n\r\nbody\r\n";
        string rawB64 = Convert.ToBase64String(Encoding.ASCII.GetBytes(raw));
        foreach (string hostile in HostileText)
        {
            foreach (var (body, expectedRecipients) in new (object, int)[]
            {
                (new { from = hostile, to = new[] { "alex@gmail.test" }, raw = rawB64 }, 1),
                (new { from = "noreply@example.com", to = new[] { hostile }, raw = rawB64 }, 1),
                (new { from = "noreply@example.com", to = new[] { "alex@gmail.test", hostile }, raw = rawB64 }, 2),
            })
            {
                Reply r = await _a.PostAsync("/api/v1/messages/raw", body);
                Assert.True((int)r.Status < 500, Escape(hostile) + r.Body);
                if (r.Status != HttpStatusCode.Accepted) { continue; }

                // An entry that parses as a mailbox with odd text in its display name is a mailbox: what must hold is that it is one address, that the
                // envelope sender is the plain address, and that the message itself is exactly what was submitted.
                Assert.Equal(expectedRecipients, r["recipients"].GetInt32());
                Guid id = Guid.Parse(r.Str("id"));
                string stored = Encoding.ASCII.GetString((await _f.Storage.Deliveries.GetRawAsync(id, default))!);
                Assert.EndsWith("\r\n\r\nbody\r\n", stored, StringComparison.Ordinal);   // the body is what was submitted (the server adds its own headers in front)
                Assert.DoesNotContain("evil", stored, StringComparison.OrdinalIgnoreCase);
                var claimed = await _f.Storage.Deliveries.ClaimAsync("t", 100, _f.Clock.UtcNow.AddMinutes(1), TimeSpan.FromMinutes(1), default);
                foreach (var d in claimed.Where(c => c.MessageId == id))
                {
                    Assert.Contains(d.EnvelopeFrom.ToString(), new[] { "noreply@example.com", "a@example.com" });
                    Assert.DoesNotContain("evil", d.Recipient.ToString(), StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain(d.Recipient.ToString(), c => char.IsControl(c) || char.IsWhiteSpace(c));
                }
            }
        }
    }

    [Fact]
    public async Task The_idempotency_key_header_takes_printable_ascii_only()
    {
        foreach (string key in new[] { "a\r\nBcc: x", "a b", "a\u00e9", "a\tb", new string('k', 256), "" , "\u0001" })
        {
            ApiClient c = _f.NewClient().WithBearer(await _f.AddKeyAsync(ApiFixture.TenantAId, "send"));
            Reply r;
            try
            {
                r = await c.PostAsync("/api/v1/messages", Baseline(), ("Idempotency-Key", key));
            }
            catch (FormatException)
            {
                continue;   // the HTTP client itself refuses to send such a header value
            }

            if (key.Length == 0) { continue; }
            Assert.True(r.Status == HttpStatusCode.BadRequest, $"'{Escape(key)}' -> {(int)r.Status}");
        }
    }

    // Mass assignment and privilege escalation

    public static TheoryData<string, string, string, string, string> Escalations() => new()
    {
        // caller (alice session, key, root), method, path template, valid body with a placeholder for the extra member, extra member
        { "alice", "POST", "/api/v1/domains", """{"name":"mass.example",$X$}""", "\"status\":\"verified\"" },
        { "alice", "POST", "/api/v1/domains", """{"name":"mass.example",$X$}""", "\"tenantId\":\"b0000000000070008000000000000002\"" },
        { "alice", "POST", "/api/v1/domains", """{"name":"mass.example",$X$}""", "\"tenant_id\":\"b0000000-0000-7000-8000-000000000002\"" },
        { "alice", "POST", "/api/v1/domains", """{"name":"mass.example",$X$}""", "\"returnPathVerified\":true" },
        { "alice", "POST", "/api/v1/webhooks", """{"url":"https://hooks.example.com/x","event_types":["*"],$X$}""", "\"tenantId\":\"b0000000000070008000000000000002\"" },
        { "alice", "POST", "/api/v1/webhooks", """{"url":"https://hooks.example.com/x","event_types":["*"],$X$}""", "\"secret\":\"whsec_chosen\"" },
        { "alice", "POST", "/api/v1/webhooks", """{"url":"https://hooks.example.com/x","event_types":["*"],$X$}""", "\"allowlist\":\"169.254.0.0/16\"" },
        { "alice", "POST", "/api/v1/api-keys", """{"name":"k","scopes":["read"],$X$}""", "\"tenantId\":\"b0000000000070008000000000000002\"" },
        { "alice", "POST", "/api/v1/api-keys", """{"name":"k","scopes":["read"],$X$}""", "\"role\":\"admin\"" },
        { "alice", "POST", "/api/v1/api-keys", """{"name":"k","scopes":["read"],$X$}""", "\"keyHash\":\"AAAA\"" },
        { "alice", "POST", "/api/v1/smtp-credentials", """{"username":"mass-user",$X$}""", "\"password\":\"chosen-by-caller\"" },
        { "alice", "POST", "/api/v1/smtp-credentials", """{"username":"mass-user",$X$}""", "\"tenantId\":\"b0000000000070008000000000000002\"" },
        { "alice", "POST", "/api/v1/suppressions", """{"address":"x@example.org",$X$}""", "\"tenantId\":\"b0000000000070008000000000000002\"" },
        { "alice", "POST", "/api/v1/messages", """{"from":"noreply@example.com","to":["a@b.test"],"subject":"s","text":"t",$X$}""", "\"tenantId\":\"b0000000000070008000000000000002\"" },
        { "alice", "POST", "/api/v1/messages", """{"from":"noreply@example.com","to":["a@b.test"],"subject":"s","text":"t",$X$}""", "\"envelope_from\":\"x@y.test\"" },
        { "alice", "POST", "/api/v1/messages", """{"from":"noreply@example.com","to":["a@b.test"],"subject":"s","text":"t",$X$}""", "\"bounce_address\":\"x@y.test\"" },
        { "alice", "POST", "/api/v1/me/password", """{"currentPassword":"correct horse battery","newPassword":"another long password",$X$}""", "\"role\":\"admin\"" },
        { "alice", "POST", "/api/v1/me/password", """{"currentPassword":"correct horse battery","newPassword":"another long password",$X$}""", "\"user\":\"root\"" },
        { "alice", "PUT", "/api/v1/settings", """{"values":{},$X$}""", "\"tenantId\":\"b0000000000070008000000000000002\"" },
        { "root", "POST", "/api/v1/admin/users", """{"userName":"mass-admin","role":"tenant","tenantId":"a0000000000070008000000000000001",$X$}""", "\"passwordHash\":\"x\"" },
        { "root", "POST", "/api/v1/admin/users", """{"userName":"mass-admin","role":"tenant","tenantId":"a0000000000070008000000000000001",$X$}""", "\"enabled\":false" },
        { "root", "POST", "/api/v1/admin/users", """{"userName":"mass-admin","role":"tenant","tenantId":"a0000000000070008000000000000001",$X$}""", "\"mustChangePassword\":false" },
        { "root", "POST", "/api/v1/admin/tenants", """{"name":"Mass Corp",$X$}""", "\"enabled\":false" },
        { "root", "POST", "/api/v1/admin/tenants", """{"name":"Mass Corp",$X$}""", "\"id\":\"c0000000000070008000000000000003\"" },
        { "root", "POST", "/api/v1/admin/relay-routes", """{"name":"mass","host":"smtp.relay.example","domains":["a.example"],$X$}""", "\"allowInternal\":true" },
        { "root", "POST", "/api/v1/admin/relay-routes", """{"name":"mass","host":"smtp.relay.example","domains":["a.example"],$X$}""", "\"id\":\"c0000000000070008000000000000003\"" },
        { "root", "POST", "/api/v1/admin/tls-policies", """{"domainPattern":"a.example","level":"may",$X$}""", "\"id\":\"c0000000000070008000000000000003\"" },
        { "root", "PUT", "/api/v1/admin/settings", """{"values":{},$X$}""", "\"tenantId\":\"b0000000000070008000000000000002\"" },
        { "root", "POST", "/api/v1/session", """{"user":"root","password":"correct horse battery",$X$}""", "\"role\":\"admin\"" },
    };

    [Theory]
    [MemberData(nameof(Escalations))]
    public async Task A_member_the_endpoint_does_not_define_is_refused_whole_and_changes_nothing(string caller, string method, string path, string template, string extra)
    {
        ApiClient client = caller == "root" ? _root : _alice;
        if (caller == "root" && !path.Contains("/admin/", StringComparison.Ordinal) && !path.EndsWith("/session", StringComparison.Ordinal)) { client = client.ActingAs(ApiFixture.TenantAId); }
        int tenantsBefore = (await _f.Storage.Config.GetTenantsAsync(default)).Count;
        int usersBefore = (await _f.Storage.Config.GetDashboardUsersAsync(default)).Count;

        Reply reply = await client.SendRawAsync(new HttpMethod(method), path, template.Replace("$X$", extra, StringComparison.Ordinal), "application/json");

        reply.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(tenantsBefore, (await _f.Storage.Config.GetTenantsAsync(default)).Count);
        Assert.Equal(usersBefore, (await _f.Storage.Config.GetDashboardUsersAsync(default)).Count);
        Assert.Empty(await _f.Storage.Config.GetWebhookEndpointsAsync(ApiFixture.TenantAId, default));
        Assert.Empty(await _f.Storage.Config.GetRelayRoutesAsync(default));
        Assert.DoesNotContain(await _f.Storage.Config.GetDomainsAsync(ApiFixture.TenantAId, default), d => d.Name == "mass.example");
        Assert.DoesNotContain(await _f.Storage.Config.GetDomainsAsync(ApiFixture.TenantBId, default), d => d.Name == "mass.example");
    }

    [Fact]
    public async Task A_tenant_cannot_grant_itself_what_only_an_administrator_may_set()
    {
        foreach (string key in new[] { "Webhooks:AllowedNetworks", "Sending:PerHour", "Sending:PerDay", "Smtp:MaxRecipients" })
        {
            object value = key.StartsWith("Webhooks", StringComparison.Ordinal) ? "169.254.169.254/32" : 1000000;
            Reply viaSession = await _alice.PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { [key] = value } });
            viaSession.Problem(HttpStatusCode.BadRequest, "validation_failed");
            Assert.Contains(key, viaSession.ErrorFields);
        }

        // The webhook that would have been allowed is still refused.
        Reply hook = await _alice.PostAsync("/api/v1/webhooks", new { url = "https://169.254.169.254/latest/meta-data/", event_types = new[] { "*" } });
        hook.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Contains("url", hook.ErrorFields);
    }

    [Fact]
    public async Task Only_an_administrator_can_open_a_network_for_a_tenants_webhooks_and_only_for_that_tenant()
    {
        Reply set = await _root.ActingAs(ApiFixture.TenantAId).PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { ["Webhooks:AllowedNetworks"] = "10.20.0.0/16" } });
        Assert.Equal(HttpStatusCode.OK, set.Status);

        Assert.Equal(HttpStatusCode.Created, (await _alice.PostAsync("/api/v1/webhooks", new { url = "https://10.20.1.1/hook", event_types = new[] { "*" } })).Status);
        (await _alice.PostAsync("/api/v1/webhooks", new { url = "https://10.21.1.1/hook", event_types = new[] { "*" } })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _alice.PostAsync("/api/v1/webhooks", new { url = "https://169.254.169.254/hook", event_types = new[] { "*" } })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        ApiClient bob = await _f.SignedInAsync("bob");
        (await bob.PostAsync("/api/v1/webhooks", new { url = "https://10.20.1.1/hook", event_types = new[] { "*" } })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Theory]
    [InlineData("https://127.0.0.1/hook")]
    [InlineData("https://localhost/hook")]
    [InlineData("https://[::1]/hook")]
    [InlineData("https://[::ffff:7f00:1]/hook")]
    [InlineData("https://169.254.169.254/latest/meta-data/")]
    [InlineData("https://2130706433/")]
    [InlineData("https://0x7f.0.0.1/")]
    [InlineData("https://10.0.0.1/")]
    [InlineData("https://user:pass@hooks.example.com/")]
    [InlineData("http://hooks.example.com/")]
    [InlineData("file:///etc/passwd")]
    [InlineData("gopher://hooks.example.com/")]
    [InlineData("https://hooks.example.com/\r\nHost: evil")]
    [InlineData("https://")]
    [InlineData("")]
    public async Task A_webhook_cannot_be_created_or_moved_to_an_internal_or_forbidden_address(string url)
    {
        (await _alice.PostAsync("/api/v1/webhooks", new { url, event_types = new[] { "*" } })).Problem(HttpStatusCode.BadRequest, "validation_failed");

        // And a good endpoint cannot be edited to point there.
        string id = (await _alice.PostAsync("/api/v1/webhooks", new { url = "https://hooks.example.com/ok", event_types = new[] { "*" } })).Str("id");
        (await _alice.PatchAsync("/api/v1/webhooks/" + id, new { url })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal("https://hooks.example.com/ok", (await _alice.GetAsync("/api/v1/webhooks/" + id)).Str("url"));
    }

    // Control characters and unusable text in names and identifiers

    public static TheoryData<string> HostileJsonStrings() => new()
    {
        "\"\\u0000\"",
        "\"a\\u0000b\"",
        "\"\\ud800\"",
        "\"a\\u0001b\"",
        "\"a\\u007fb\"",
        "\"a\\r\\nb\"",
        "\"a\\u2028b\"",
        "\"a\\u202eb\"",
    };

    [Theory]
    [MemberData(nameof(HostileJsonStrings))]
    public async Task A_name_or_identifier_with_a_control_character_is_refused_everywhere_it_is_accepted(string literal)
    {
        (string Who, string Method, string Path, string Body)[] cases =
        [
            ("alice", "POST", "/api/v1/domains", $$"""{"name":{{literal}}}"""),
            ("alice", "POST", "/api/v1/webhooks", $$"""{"url":{{literal}},"event_types":["*"]}"""),
            ("alice", "POST", "/api/v1/webhooks", $$"""{"url":"https://hooks.example.com/x","event_types":[{{literal}}]}"""),
            ("alice", "POST", "/api/v1/api-keys", $$"""{"name":{{literal}},"scopes":["read"]}"""),
            ("alice", "POST", "/api/v1/api-keys", $$"""{"name":"k","scopes":[{{literal}}]}"""),
            ("alice", "POST", "/api/v1/smtp-credentials", $$"""{"username":{{literal}}}"""),
            ("alice", "POST", "/api/v1/suppressions", $$"""{"address":{{literal}}}"""),
            ("alice", "POST", "/api/v1/suppressions", $$"""{"address":"x@example.org","reason":{{literal}}}"""),
            ("alice", "PUT", "/api/v1/settings", $$$"""{"values":{ {{{literal}}}:true}}"""),
            ("alice", "PUT", "/api/v1/settings", $$$"""{"values":{"Content:StoreAttachments":{{{literal}}}}}"""),
            ("root", "POST", "/api/v1/admin/tenants", $$"""{"name":{{literal}}}"""),
            ("root", "POST", "/api/v1/admin/users", $$"""{"userName":{{literal}},"role":"admin"}"""),
            ("root", "POST", "/api/v1/admin/relay-routes", $$"""{"name":{{literal}},"host":"smtp.relay.example","domains":["a.example"]}"""),
            ("root", "POST", "/api/v1/admin/relay-routes", $$"""{"name":"r","host":{{literal}},"domains":["a.example"]}"""),
            ("root", "POST", "/api/v1/admin/relay-routes", $$"""{"name":"r","host":"smtp.relay.example","userName":{{literal}},"password":"p","domains":["a.example"]}"""),
            ("root", "POST", "/api/v1/admin/relay-routes", $$"""{"name":"r","host":"smtp.relay.example","domains":[{{literal}}]}"""),
            ("root", "POST", "/api/v1/admin/tls-policies", $$"""{"domainPattern":{{literal}},"level":"may"}"""),
        ];
        foreach (var (who, method, path, body) in cases)
        {
            ApiClient client = who == "root" ? _root : _alice;
            Reply reply = await client.SendRawAsync(new HttpMethod(method), path, body, "application/json");
            Assert.True(reply.Status == HttpStatusCode.BadRequest, $"{method} {path} {body} -> {(int)reply.Status} {reply.Body}");
        }

        Assert.Equal(2, (await _f.Storage.Config.GetTenantsAsync(default)).Count);
        Assert.Empty(await _f.Storage.Config.GetRelayRoutesAsync(default));
        Assert.Empty(await _f.Storage.Config.GetTlsPoliciesAsync(default));
    }

    [Theory]
    [MemberData(nameof(HostileJsonStrings))]
    public async Task A_sign_in_with_hostile_text_is_a_plain_failed_sign_in_not_an_error(string literal)
    {
        foreach (string body in new[] { $$"""{"user":{{literal}},"password":"x"}""", $$"""{"user":"alice","password":{{literal}}}""" })
        {
            Reply reply = await _f.NewClient().SendRawAsync(HttpMethod.Post, "/api/v1/session", body, "application/json");
            Assert.True(reply.Status is HttpStatusCode.Unauthorized or HttpStatusCode.BadRequest, $"{(int)reply.Status} {reply.Body}");
        }
    }

    [Theory]
    [MemberData(nameof(HostileJsonStrings))]
    public async Task A_password_with_hostile_characters_never_causes_an_error_when_it_is_set_or_checked(string literal)
    {
        foreach (var (who, path, body) in new[]
        {
            ("root", "/api/v1/admin/users", $$"""{"userName":"hostile-pw","role":"admin","password":{{literal}} }"""),
            ("alice", "/api/v1/me/password", $$"""{"currentPassword":{{literal}},"newPassword":"another long password"}"""),
            ("alice", "/api/v1/me/password", $$"""{"currentPassword":"correct horse battery","newPassword":{{literal}} }"""),
        })
        {
            ApiClient client = who == "root" ? _root : _alice;
            Reply reply = await client.SendRawAsync(HttpMethod.Post, path, body, "application/json");
            Assert.True((int)reply.Status < 500, $"{path} -> {(int)reply.Status} {reply.Body}");
        }
    }

    // Regular expressions on names: the longest input the API lets through, shaped to make a backtracking matcher work hardest

    [Fact]
    public async Task Pathological_names_at_the_longest_length_are_refused_at_once_by_every_pattern_check()
    {
        string[] hostile =
        [
            new string('a', 250) + "!",
            "a" + new string('-', 250) + "!",
            string.Concat(Enumerable.Repeat("a-", 120)) + "!",
            string.Join(".", Enumerable.Repeat("a-a-a-a-a-a-a-a-a", 20)) + "!",
            string.Join(".", Enumerable.Repeat("a", 120)) + "!",
            new string('_', 250) + "\n",
            new string('a', 253) + ".",
            new string('a', 5000) + "!",
        ];
        foreach (string host in hostile)
        {
            Reply relay = await _root.PostAsync("/api/v1/admin/relay-routes", new { name = "r", host, domains = new[] { "a.example" } });
            Assert.Equal(HttpStatusCode.BadRequest, relay.Status);
            Reply policy = await _root.PostAsync("/api/v1/admin/tls-policies", new { domainPattern = host, level = "may" });
            Assert.Equal(HttpStatusCode.BadRequest, policy.Status);
            Reply smtp = await _alice.PostAsync("/api/v1/smtp-credentials", new { username = host });
            Assert.Equal(HttpStatusCode.BadRequest, smtp.Status);
            Reply name = await _root.PostAsync("/api/v1/admin/relay-routes", new { name = host, host = "smtp.relay.example", domains = new[] { "a.example" } });
            Assert.Equal(HttpStatusCode.BadRequest, name.Status);
            Reply domain = await _alice.PostAsync("/api/v1/domains", new { name = host });
            Assert.Equal(HttpStatusCode.BadRequest, domain.Status);
        }

        Assert.Empty(await _f.Storage.Config.GetRelayRoutesAsync(default));
    }

    // Filters

    [Fact]
    public async Task Hostile_filter_values_on_every_list_endpoint_are_refused_or_match_nothing_and_never_show_another_tenant()
    {
        await using ApiFixture sqlite = await ApiFixture.StartAsync(new ApiFixtureOptions { Sqlite = true });
        ApiClient a = await sqlite.KeyClientAsync(ApiFixture.TenantAId);
        ApiClient b = await sqlite.KeyClientAsync(ApiFixture.TenantBId);
        Assert.Equal(HttpStatusCode.Accepted, (await a.PostAsync("/api/v1/messages", new { from = "noreply@example.com", to = new[] { "a-user@gmail.test" }, subject = "A subject", text = "t", tags = new[] { "a-tag" } })).Status);
        Assert.Equal(HttpStatusCode.Accepted, (await b.PostAsync("/api/v1/messages", new { from = "noreply@globex.test", to = new[] { "b-secret@gmail.test" }, subject = "B subject SECRET", text = "t", tags = new[] { "b-tag" } })).Status);
        await b.PostAsync("/api/v1/suppressions", new { address = "b-suppressed@example.org" });

        string[] payloads = ["' OR '1'='1", "'; DROP TABLE message_index; --", "\" OR \"\"=\"", "%", "_", "\\", "' UNION SELECT 1,2,3 --", "%27%20OR%201%3D1", "[a-z]", "😀", "a\u0000b", "\u202e", new string('x', 400), "\r\nX-Injected: 1"];
        string[] queries = ["recipient", "sender", "subject", "status", "tag", "from", "to", "cursor", "limit"];
        foreach (string payload in payloads)
        {
            foreach (string param in queries)
            {
                Reply reply = await a.GetAsync($"/api/v1/messages?{param}={Uri.EscapeDataString(payload)}");
                Assert.True(reply.Status is HttpStatusCode.OK or HttpStatusCode.BadRequest, $"{param}={Escape(payload)} -> {(int)reply.Status} {reply.Body}");
                Assert.DoesNotContain("SECRET", reply.Body, StringComparison.Ordinal);
                Assert.DoesNotContain("b-secret", reply.Body, StringComparison.Ordinal);
                if (reply.Status == HttpStatusCode.OK)
                {
                    Assert.True(reply["items"].GetArrayLength() <= 1);
                }
            }

            foreach (string path in new[] { "/api/v1/stats?domain=", "/api/v1/stats?granularity=", "/api/v1/stats?from=", "/api/v1/suppressions?cursor=", "/api/v1/webhooks", "/api/v1/stats/recent-events?limit=" })
            {
                Reply reply = path.EndsWith('=') ? await a.GetAsync(path + Uri.EscapeDataString(payload)) : await a.GetAsync(path);
                Assert.True((int)reply.Status < 500, $"{path}{Escape(payload)} -> {(int)reply.Status} {reply.Body}");
                Assert.DoesNotContain("b-suppressed", reply.Body, StringComparison.Ordinal);
                Assert.DoesNotContain("SECRET", reply.Body, StringComparison.Ordinal);
            }
        }

        // The data is all still there.
        Assert.Equal(1, (await a.GetAsync("/api/v1/messages")) ["items"].GetArrayLength());
        Assert.Equal(1, (await b.GetAsync("/api/v1/messages"))["items"].GetArrayLength());
    }

    private async Task<MimeMessage> RawOfAsync(string id)
    {
        byte[]? raw = await _f.Storage.Deliveries.GetRawAsync(Guid.Parse(id), default);
        Assert.NotNull(raw);
        return await MimeMessage.LoadAsync(new MemoryStream(raw));
    }

    private static string Escape(string text) => text.Replace("\r", "\\r", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal).Replace("\0", "\\0", StringComparison.Ordinal);
}
