using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Mta.Host.Api;
using Mta.Host.Tests.Api;
using Mta.Storage;
using MimeKit;

namespace Mta.Host.Tests.InboundE2E;

/// <summary>
/// Mail that really came in by SMTP, read back through the HTTP API on SQLite and on PostgreSQL: the message, the raw download and the attachments byte for byte, hostile MIME that must not hurt the
/// reader, and every inbound endpoint asked by another tenant. The API runs over the very storage the receive path wrote to.
/// </summary>
public abstract class InboundApiEndToEndTests(LabBackend backend)
{
    private static async Task<(HttpResponseMessage Response, byte[] Body)> DownloadAsync(InboundLab lab, ApiClient client, string path)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (client.Bearer is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", client.Bearer);
        }
        else
        {
            request.Headers.TryAddWithoutValidation("Cookie", client.Cookie);
        }

        HttpResponseMessage response = await lab.Api!.Http.SendAsync(request);
        return (response, await response.Content.ReadAsByteArrayAsync());
    }

    private static string Wire(MimeMessage message)
    {
        var options = FormatOptions.Default.Clone();
        options.NewLineFormat = NewLineFormat.Dos;
        using var stream = new MemoryStream();
        message.WriteTo(options, stream);
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static string Id(InboundMessage m) => ApiJson.Id(m.Id);

    [Fact]
    public async Task A_message_with_attachments_comes_back_through_the_api_byte_for_byte_and_only_ever_as_a_download()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { WithApi = true });
        if (lab is null)
        {
            return;
        }

        byte[] pdf = RandomNumberGenerator.GetBytes(40_000);
        pdf[0] = 0; pdf[1] = (byte)'\r'; pdf[2] = (byte)'\n'; pdf[3] = (byte)'.'; pdf[4] = (byte)'\r'; pdf[5] = (byte)'\n';   // bytes that would end a message if anything treated them as text
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress("Bob", "bob@sender.test"));
        message.To.Add(new MailboxAddress("Support", "support@example.org"));
        message.Subject = "Invoice with files";
        message.Date = new DateTimeOffset(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);
        message.MessageId = "invoice-1@sender.test";
        var body = new BodyBuilder { TextBody = "See the attached.\r\n", HtmlBody = "<p>See the <b>attached</b></p><script>alert(1)</script>" };
        body.Attachments.Add("invoice.pdf", pdf, ContentType.Parse("application/pdf"));
        body.Attachments.Add("..\\..\\evil/\u202Egnp.exe", Encoding.UTF8.GetBytes("MZ not really"), ContentType.Parse("text/html"));
        body.Attachments.Add("notes.txt", Encoding.UTF8.GetBytes("plain notes\r\n"), ContentType.Parse("text/plain"));
        message.Body = body.ToMessageBody();
        string wire = Wire(message);

        var (result, _) = await RealMta.SendAsync(lab.Port, "bob@sender.test", ["support@example.org"], wire);
        Assert.True(result.Delivered);

        ApiClient alice = await lab.Api!.SignedInAsync("alice");
        ApiClient key = await lab.Api.KeyClientAsync(InboundLab.Acme, "inbound:read");
        InboundMessage stored = Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
        foreach (ApiClient client in new[] { alice, key })
        {
            Reply list = await client.GetAsync("/api/v1/inbound/messages?subject=invoice");
            Assert.Equal(Id(stored), Assert.Single(list["items"].EnumerateArray()).GetProperty("id").GetString());

            Reply detail = await client.GetAsync("/api/v1/inbound/messages/" + Id(stored));
            Assert.Equal(HttpStatusCode.OK, detail.Status);
            Assert.Equal("available", detail["content"].GetProperty("state").GetString());
            Assert.Contains("See the attached.", detail["content"].GetProperty("text").GetString(), StringComparison.Ordinal);
            var attachments = detail["content"].GetProperty("attachments").EnumerateArray().ToList();
            Assert.Equal(3, attachments.Count);
            Assert.Equal(40_000, attachments[0].GetProperty("size").GetInt64());

            // The raw message: exactly the stored bytes, as a download.
            var (rawResponse, raw) = await DownloadAsync(lab, client, $"/api/v1/inbound/messages/{Id(stored)}/raw");
            using (rawResponse)
            {
                Assert.Equal(HttpStatusCode.OK, rawResponse.StatusCode);
                Assert.Equal(await lab.Storage.Inbound.GetRawAsync(InboundLab.Acme, stored.Id, default), raw);
                Assert.EndsWith(wire, Encoding.UTF8.GetString(raw), StringComparison.Ordinal);
                Assert.Equal("message/rfc822", rawResponse.Content.Headers.ContentType!.MediaType);
                Assert.StartsWith("attachment", rawResponse.Content.Headers.ContentDisposition!.ToString(), StringComparison.Ordinal);
                Assert.Equal("nosniff", rawResponse.Headers.GetValues("X-Content-Type-Options").Single());
                Assert.Equal("no-store", rawResponse.Headers.CacheControl!.ToString());
            }

            // The attachments by reference (what a webhook payload links to): decoded bytes, never served with the type the sender claimed.
            var (first, firstBody) = await DownloadAsync(lab, client, $"/api/v1/inbound/messages/{Id(stored)}/attachments/0");
            using (first)
            {
                Assert.Equal(pdf, firstBody);
                Assert.Equal("application/octet-stream", first.Content.Headers.ContentType!.MediaType);
                Assert.Equal("application/pdf", first.Headers.GetValues("X-Original-Content-Type").Single());
                Assert.Equal("nosniff", first.Headers.GetValues("X-Content-Type-Options").Single());
            }

            var (hostile, hostileBody) = await DownloadAsync(lab, client, $"/api/v1/inbound/messages/{Id(stored)}/attachments/1");
            using (hostile)
            {
                Assert.Equal("MZ not really", Encoding.UTF8.GetString(hostileBody));
                string disposition = string.Concat(hostile.Content.Headers.GetValues("Content-Disposition"));
                Assert.DoesNotContain("..", disposition, StringComparison.Ordinal);
                Assert.DoesNotContain("/", disposition, StringComparison.Ordinal);
                Assert.DoesNotContain("\\", disposition, StringComparison.Ordinal);
                Assert.DoesNotContain("\u202E", disposition, StringComparison.Ordinal);
                Assert.DoesNotContain("\r", disposition, StringComparison.Ordinal);
                Assert.Equal("text/html", hostile.Headers.GetValues("X-Original-Content-Type").Single());   // a type a browser would render: it is only ever a download
            }

            var (missing, _) = await DownloadAsync(lab, client, $"/api/v1/inbound/messages/{Id(stored)}/attachments/3");
            using (missing)
            {
                Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
            }
        }

        // Deleting through the API removes the message and its body from the real store.
        Assert.Equal(HttpStatusCode.NoContent, (await alice.DeleteAsync("/api/v1/inbound/messages/" + Id(stored))).Status);
        Assert.Null(await lab.Storage.Inbound.GetAsync(InboundLab.Acme, stored.Id, default));
        Assert.Null(await lab.Storage.Inbound.GetRawAsync(InboundLab.Acme, stored.Id, default));
    }

    [Fact]
    public async Task Store_keeps_the_mail_discard_keeps_only_the_metadata_and_postmaster_without_a_route_is_stored_with_no_route()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { WithApi = true });
        if (lab is null)
        {
            return;
        }

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "stored"))).Code);
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "old@example.org", InboundLab.Message(subject: "discarded"))).Code);
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "Postmaster@Example.ORG", InboundLab.Message(subject: "to the postmaster"))).Code);

        ApiClient alice = await lab.Api!.SignedInAsync("alice");
        Reply list = await alice.GetAsync("/api/v1/inbound/messages?limit=10");
        var items = list["items"].EnumerateArray().ToDictionary(i => i.GetProperty("subject").GetString()!);
        Assert.Equal(3, items.Count);
        Assert.Equal(("store", "done", true), (items["stored"].GetProperty("action").GetProperty("kind").GetString(), items["stored"].GetProperty("action").GetProperty("state").GetString(), items["stored"].GetProperty("hasRaw").GetBoolean()));
        Assert.Equal(("discard", "done", false), (items["discarded"].GetProperty("action").GetProperty("kind").GetString(), items["discarded"].GetProperty("action").GetProperty("state").GetString(), items["discarded"].GetProperty("hasRaw").GetBoolean()));
        Assert.Equal(("store", JsonValueKind.Null, true), (items["to the postmaster"].GetProperty("action").GetProperty("kind").GetString(), items["to the postmaster"].GetProperty("routeId").ValueKind, items["to the postmaster"].GetProperty("hasRaw").GetBoolean()));

        string discardedId = items["discarded"].GetProperty("id").GetString()!;
        alice.Bearer = null;
        (await alice.GetAsync($"/api/v1/inbound/messages/{discardedId}/raw")).Problem(HttpStatusCode.Gone, "inbound_body_gone");
        Assert.Equal(2, (await alice.GetAsync("/api/v1/inbound/usage"))["messages"].GetInt64() - 1);   // three rows...
        Assert.Equal(2L, await CountBodiesAsync(lab));                                                   // ...two bodies
        await lab.AssertNothingWasSentAsync();
    }

    private static async Task<long> CountBodiesAsync(InboundLab lab) =>
        await lab.Storage.Transfer!.CountAsync(Mta.Storage.Transfer.TransferTables.InboundRaw, Mta.Storage.Transfer.TransferRange.All, default);

    public static IEnumerable<object[]> HostileMessages()
    {
        yield return ["300 levels of nested multiparts", NestedMultipart(300)];
        yield return ["5000 parts", ManyParts(5_000)];
        yield return ["many headers", string.Concat(Enumerable.Range(0, 3_000).Select(i => $"X-H{i}: v{i}\r\n")) + "Subject: many\r\n\r\nbody\r\n"];
        yield return ["a base64 body that is not base64", "Subject: b64\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"a.bin\"\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!!%%%%====\r\n"];
        yield return ["a quoted-printable body that expands", "Subject: qp\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" + string.Concat(Enumerable.Repeat("=C3=A9=\r\n", 4_000))];
        yield return ["an unknown charset", "Subject: =?x-nonexistent?q?hello?=\r\nContent-Type: text/plain; charset=x-nonexistent\r\n\r\nbody\r\n"];
        yield return ["a filename with control characters and a very long name", "Subject: names\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"" + new string('n', 900) + "\\x00\r\n\"\r\n\r\ndata\r\n--B--\r\n"];
        yield return ["a boundary that never closes", "Subject: open\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nnever closed\r\n"];
        yield return ["an html bomb", "Subject: html\r\nContent-Type: text/html\r\n\r\n" + string.Concat(Enumerable.Repeat("<div>", 40_000)) + "\r\n"];
        yield return ["encoded words everywhere", "Subject: =?utf-8?B?" + Convert.ToBase64String(new byte[3000]) + "?=\r\nFrom: =?utf-8?q?=00=ff=fe?= <bob@sender.test>\r\n\r\nbody\r\n"];
    }

    private static string NestedMultipart(int depth)
    {
        var sb = new StringBuilder("Subject: deep\r\nContent-Type: multipart/mixed; boundary=b0\r\n\r\n");
        for (int i = 0; i < depth; i++)
        {
            sb.Append("--b").Append(i).Append("\r\nContent-Type: multipart/mixed; boundary=b").Append(i + 1).Append("\r\n\r\n");
        }

        sb.Append("--b").Append(depth).Append("\r\nContent-Type: text/plain\r\n\r\nleaf\r\n");
        for (int i = depth; i >= 0; i--)
        {
            sb.Append("--b").Append(i).Append("--\r\n");
        }

        return sb.ToString();
    }

    private static string ManyParts(int count)
    {
        var sb = new StringBuilder("Subject: parts\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n");
        for (int i = 0; i < count; i++)
        {
            sb.Append("--B\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"f").Append(i).Append(".txt\"\r\n\r\nx\r\n");
        }

        return sb.Append("--B--\r\n").ToString();
    }

    [Theory]
    [MemberData(nameof(HostileMessages))]
    public async Task Hostile_mime_is_stored_as_it_came_and_the_api_reads_it_with_bounded_work_and_no_server_error(string name, string message)
    {
        _ = name;
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { WithApi = true });
        if (lab is null)
        {
            return;
        }

        FakeMtaReply reply = new(await lab.SendAsync("bob@sender.test", "support@example.org", message));
        Assert.True(reply.Code is 250 or 554 or 552, reply.Text);   // stored, or refused as malformed at the door: never an error of the server
        InboundMessage[] stored = [.. await lab.MessagesAsync(InboundLab.Acme)];
        if (reply.Code != 250)
        {
            Assert.Empty(stored);
            return;
        }

        ApiClient alice = await lab.Api!.SignedInAsync("alice");
        InboundMessage m = Assert.Single(stored);
        Reply detail = await alice.GetAsync("/api/v1/inbound/messages/" + Id(m));
        Assert.Equal(HttpStatusCode.OK, detail.Status);
        Assert.Contains(detail["content"].GetProperty("state").GetString(), new[] { "available", "no_body" });
        var attachments = detail["content"].GetProperty("attachments");
        for (int i = 0; i < Math.Min(attachments.GetArrayLength(), 3); i++)
        {
            var (response, _) = await DownloadAsync(lab, alice, $"/api/v1/inbound/messages/{Id(m)}/attachments/{i}");
            using (response)
            {
                Assert.True((int)response.StatusCode < 500, $"attachment {i}: {response.StatusCode}");
            }
        }

        var (raw, bytes) = await DownloadAsync(lab, alice, $"/api/v1/inbound/messages/{Id(m)}/raw");
        using (raw)
        {
            Assert.Equal(HttpStatusCode.OK, raw.StatusCode);
            Assert.Equal(m.Size, bytes.Length);
        }

        lab.AssertNoErrorsLogged();
    }

    private readonly record struct FakeMtaReply(Host.Tests.Inbound.FakeMta.Reply Inner)
    {
        public int Code => Inner.Code;

        public string Text => Inner.ToString();
    }

    // ------------------------------------------------------------------ tenant isolation

    [Fact]
    public async Task Every_inbound_endpoint_answers_another_tenant_exactly_like_an_id_that_does_not_exist_and_changes_nothing()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { WithApi = true });
        if (lab is null)
        {
            return;
        }

        // Tenant A has a stored message, a pending forward and a route; tenant B (a user, a key with both inbound scopes, and an administrator acting for B) asks for all of it.
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "A's private mail"))).Code);
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "billing-1@example.org", InboundLab.Message(subject: "A's forward"))).Code);
        IReadOnlyList<InboundMessage> mine = await lab.MessagesAsync(InboundLab.Acme);
        InboundMessage stored = mine.Single(m => m.Subject == "A's private mail");
        InboundMessage pending = mine.Single(m => m.Subject == "A's forward");
        string domainA = ApiJson.Id(lab.ExampleOrg);
        string routeA = ApiJson.Id(lab.SupportRoute);

        // B needs a domain of its own to have a valid-looking path to ask with (a made-up id answers 404 as well).
        var outsiders = new List<(string Name, ApiClient Client)>
        {
            ("user", await lab.Api!.SignedInAsync("bob")),
            ("key", await lab.Api.KeyClientAsync(ApiFixture.TenantBId, "inbound:read", "inbound:write", "send", "domains")),
            ("admin acting as B", (await lab.Api.SignedInAsync("root")).ActingAs(ApiFixture.TenantBId)),
        };

        string missing = ApiJson.Id(Guid.NewGuid());
        (string Method, string Path, string? Body)[] routes =
        [
            ("GET", "/api/v1/inbound/messages/{id}", null),
            ("GET", "/api/v1/inbound/messages/{id}/raw", null),
            ("GET", "/api/v1/inbound/messages/{id}/attachments/0", null),
            ("DELETE", "/api/v1/inbound/messages/{id}", null),
            ("POST", "/api/v1/inbound/messages/{id}/retry", "{}"),
            ("GET", "/api/v1/domains/{domain}/inbound", null),
            ("PATCH", "/api/v1/domains/{domain}/inbound", """{"enabled":false}"""),
            ("GET", "/api/v1/domains/{domain}/inbound/routes", null),
            ("POST", "/api/v1/domains/{domain}/inbound/routes", """{"match":{"kind":"catch_all"},"action":{"kind":"store"}}"""),
            ("GET", "/api/v1/domains/{domain}/inbound/routes/{route}", null),
            ("PATCH", "/api/v1/domains/{domain}/inbound/routes/{route}", """{"enabled":false}"""),
            ("DELETE", "/api/v1/domains/{domain}/inbound/routes/{route}", null),
            ("GET", "/api/v1/domains/{domain}/inbound/routes/match?address=support%40example.org", null),
        ];

        foreach ((string who, ApiClient client) in outsiders)
        {
            foreach ((string method, string path, string? body) in routes)
            {
                // The same call for an id that exists in tenant A and for an id that exists nowhere must be indistinguishable.
                string Fill(string p, bool real) => p
                    .Replace("{id}", real ? Id(p.Contains("/retry", StringComparison.Ordinal) ? pending : stored) : missing, StringComparison.Ordinal)
                    .Replace("{domain}", real ? domainA : missing, StringComparison.Ordinal)
                    .Replace("{route}", real ? routeA : missing, StringComparison.Ordinal);
                Reply real = await client.SendAsync(new HttpMethod(method), Fill(path, true), body);
                Reply none = await client.SendAsync(new HttpMethod(method), Fill(path, false), body);
                Assert.True(real.Status == none.Status, $"{who}: {method} {path}: {real.Status} for tenant A's id, {none.Status} for a missing one");
                Assert.Equal(HttpStatusCode.NotFound, real.Status);
                Assert.Equal(none.Json.GetProperty("code").GetString(), real.Json.GetProperty("code").GetString());
                Assert.Equal(none.Json.GetProperty("detail").GetString()!.Replace(missing, "X", StringComparison.Ordinal), real.Json.GetProperty("detail").GetString()!.Replace(Id(stored), "X", StringComparison.Ordinal).Replace(domainA, "X", StringComparison.Ordinal).Replace(routeA, "X", StringComparison.Ordinal));
            }

            // The lists show nothing of A, a filter cannot reach across, and an erasure with every filter of A's data deletes nothing.
            Reply list = await client.GetAsync("/api/v1/inbound/messages?limit=200");
            Assert.Empty(list["items"].EnumerateArray());
            Assert.Empty((await client.GetAsync($"/api/v1/inbound/messages?domainId={domainA}&recipient=support%40example.org&sender=bob%40sender.test&subject=private")).Json.GetProperty("items").EnumerateArray());
            Reply usage = await client.GetAsync("/api/v1/inbound/usage");
            Assert.Equal(0, usage["messages"].GetInt64());
            Reply erase = await client.DeleteAsync($"/api/v1/inbound/messages?domainId={domainA}&recipient=support%40example.org");
            Assert.True(erase.Status == HttpStatusCode.OK && erase["deleted"].GetInt64() == 0, $"{who}: erase answered {erase.Status}");
            Assert.Equal(HttpStatusCode.OK, (await client.DeleteAsync("/api/v1/inbound/messages?subject=private")).Status);
        }

        // Tenant A's data is exactly as it was, in the store and for A.
        Assert.Equal(mine.Select(m => m.Id).Order(), (await lab.MessagesAsync(InboundLab.Acme)).Select(m => m.Id).Order());
        Assert.NotNull(await lab.Storage.Inbound.GetRawAsync(InboundLab.Acme, stored.Id, default));
        Assert.Equal(InboundActionState.Pending, (await lab.Storage.Inbound.GetAsync(InboundLab.Acme, pending.Id, default))!.ActionState);
        Assert.Equal(3, (await lab.Storage.Inbound.GetRoutesAsync(lab.ExampleOrg, default)).Count);
        ApiClient alice = await lab.Api.SignedInAsync("alice");
        Assert.Equal(2, (await alice.GetAsync("/api/v1/inbound/messages")).Json.GetProperty("items").GetArrayLength());
    }

    [Fact]
    public async Task The_scopes_are_separate_and_a_forward_route_needs_the_right_to_send()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { WithApi = true });
        if (lab is null)
        {
            return;
        }

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message())).Code);
        InboundMessage stored = Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
        string domain = ApiJson.Id(lab.ExampleOrg);
        ApiClient read = await lab.Api!.KeyClientAsync(InboundLab.Acme, "inbound:read");
        ApiClient write = await lab.Api.KeyClientAsync(InboundLab.Acme, "inbound:write");
        ApiClient generalRead = await lab.Api.KeyClientAsync(InboundLab.Acme, "read", "send", "domains", "webhooks");
        ApiClient writeAndSend = await lab.Api.KeyClientAsync(InboundLab.Acme, "inbound:write", "send");

        // Reading received mail needs inbound:read: not `read`, not inbound:write. Writing needs inbound:write: not inbound:read.
        Assert.Equal(HttpStatusCode.Forbidden, (await write.GetAsync("/api/v1/inbound/messages/" + Id(stored))).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await generalRead.GetAsync("/api/v1/inbound/messages")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await generalRead.GetAsync($"/api/v1/inbound/messages/{Id(stored)}/raw")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await generalRead.GetAsync($"/api/v1/domains/{domain}/inbound/routes")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await read.DeleteAsync("/api/v1/inbound/messages/" + Id(stored))).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await read.PatchAsync($"/api/v1/domains/{domain}/inbound", new { dmarcAction = "reject" })).Status);
        Assert.NotNull(await lab.Storage.Inbound.GetAsync(InboundLab.Acme, stored.Id, default));

        // inbound:write alone controls where future mail goes, but a forward needs `send` as well: it is the scope that means "this key may make the server send mail".
        string forward = """{"name":"fwd","match":{"kind":"address","localPart":"fwd"},"action":{"kind":"forward","forwardTo":["me@elsewhere.test"]}}""";
        Assert.Equal(HttpStatusCode.Forbidden, (await write.SendAsync(HttpMethod.Post, $"/api/v1/domains/{domain}/inbound/routes", forward)).Status);
        Assert.Equal(HttpStatusCode.Created, (await writeAndSend.SendAsync(HttpMethod.Post, $"/api/v1/domains/{domain}/inbound/routes", forward)).Status);
        // Changing an existing forward route's action to another kind, or another kind to a forward, follows the same rule.
        string store = """{"name":"s","match":{"kind":"address","localPart":"s"},"action":{"kind":"store"}}""";
        Reply made = await write.SendAsync(HttpMethod.Post, $"/api/v1/domains/{domain}/inbound/routes", store);
        Assert.Equal(HttpStatusCode.Created, made.Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await write.SendAsync(HttpMethod.Patch, $"/api/v1/domains/{domain}/inbound/routes/{made.Str("id")}", """{"action":{"kind":"forward","forwardTo":["me@elsewhere.test"]}}""")).Status);
        Assert.Equal(HttpStatusCode.OK, (await writeAndSend.SendAsync(HttpMethod.Patch, $"/api/v1/domains/{domain}/inbound/routes/{made.Str("id")}", """{"action":{"kind":"forward","forwardTo":["me@elsewhere.test"]}}""")).Status);

        // The receive path follows the API at once, on the same process: the new route takes mail without waiting for the interval.
        lab.FollowConfiguration();
        Assert.Equal(HttpStatusCode.Created, (await write.SendAsync(HttpMethod.Post, $"/api/v1/domains/{domain}/inbound/routes", """{"name":"late","order":5,"match":{"kind":"address","localPart":"late"},"action":{"kind":"store"}}""")).Status);
        int code;
        var deadline = DateTime.UtcNow.AddSeconds(30);
        do
        {
            code = (await lab.SendAsync("bob@sender.test", "late@example.org", InboundLab.Message(subject: "late"))).Code;
            if (code != 250)
            {
                await Task.Delay(50);
            }
        }
        while (code != 250 && DateTime.UtcNow < deadline);
        Assert.Equal(250, code);
    }

    // ------------------------------------------------------------------ deleting a domain

    [Fact]
    public async Task A_domain_with_received_mail_is_deleted_only_with_a_purge_that_switches_receiving_off_first_and_leaves_nothing_behind()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { WithApi = true });
        if (lab is null)
        {
            return;
        }

        for (int i = 0; i < 12; i++)
        {
            Assert.Equal(250, (await lab.SendAsync("bob@sender.test", i % 3 == 0 ? "old@example.org" : "support@example.org", InboundLab.Message(subject: "m" + i))).Code);
        }

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "anyone@example.net", InboundLab.Message())).Code);
        string domain = ApiJson.Id(lab.ExampleOrg);
        ApiClient admin = await lab.Api!.KeyClientAsync(InboundLab.Acme, "domains", "inbound:read", "inbound:write");
        ApiClient domainsOnly = await lab.Api.KeyClientAsync(InboundLab.Acme, "domains");

        Reply refused = await domainsOnly.DeleteAsync("/api/v1/domains/" + domain);
        refused.Problem(HttpStatusCode.Conflict, "conflict");
        Assert.Equal("inbound_messages_exist", refused.Json.GetProperty("reason").GetString());
        Assert.False(refused.Body.Contains("12", StringComparison.Ordinal) && refused.Json.TryGetProperty("count", out _), "the count is told only to a key that may read the mail");
        Assert.Equal(HttpStatusCode.Forbidden, (await domainsOnly.DeleteAsync($"/api/v1/domains/{domain}?purgeInbound=true")).Status);
        Assert.Equal(12, (await lab.MessagesAsync(InboundLab.Acme)).Count);

        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/api/v1/domains/{domain}?purgeInbound=true")).Status);

        Assert.Empty(await lab.MessagesAsync(InboundLab.Acme));
        Assert.Null(await lab.Storage.Inbound.GetSettingsAsync(lab.ExampleOrg, default));
        Assert.Empty(await lab.Storage.Inbound.GetRoutesAsync(lab.ExampleOrg, default));
        Assert.Single(await lab.MessagesAsync(InboundLab.Globex));   // another tenant's mail is untouched
        Assert.Equal(0, (await lab.Storage.Inbound.GetUsageAsync(InboundLab.Acme, null, default)).BodyBytes);
        // The receive path stops serving the domain at its next refresh: a name that is no longer ours is relayed to nobody.
        await lab.RefreshAsync();
        Assert.Equal(550, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message())).Code);
    }
}

public sealed class SqliteInboundApiEndToEndTests() : InboundApiEndToEndTests(LabBackend.Sqlite);

public sealed class PostgresInboundApiEndToEndTests() : InboundApiEndToEndTests(LabBackend.Postgres);
