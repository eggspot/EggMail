using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Mta.Core;
using Mta.Dkim;
using Mta.Dsn;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Host.Tests.Api;
using Mta.RemoteMta.Tests.Harness;
using Mta.Storage;
using MimeKit;
using MimeKit.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using PeerMta = Mta.RemoteMta.Tests.Harness.FakeMta;

namespace Mta.Host.Tests.InboundE2E;

/// <summary>
/// The forward action end to end on SQLite and PostgreSQL: mail arrives over SMTP, the runner queues a copy through the outbound queue, the real delivery engine and SMTP client send it to a hand
/// written fake remote MTA from the delivery test harness, and MimeKit (an independent implementation) verifies what arrived: the SRS0 envelope, the original DKIM signature that must stay valid, the signature
/// of the route's domain and never of the From domain, the ARC set, the hop marker and the original bytes. Failures at the destination produce no mail to anybody.
/// </summary>
public abstract class InboundForwardE2ETests(LabBackend backend)
{
    private static readonly FormatOptions Wire = CreateWire();

    private static FormatOptions CreateWire()
    {
        var o = FormatOptions.Default.Clone();
        o.NewLineFormat = NewLineFormat.Dos;
        return o;
    }

    private sealed class Locator(Dictionary<string, RSA> keys) : DkimPublicKeyLocatorBase
    {
        public override AsymmetricKeyParameter LocatePublicKey(string methods, string domain, string selector, CancellationToken cancellationToken = default) =>
            PublicKeyFactory.CreateKey(keys[domain].ExportSubjectPublicKeyInfo());

        public override Task<AsymmetricKeyParameter> LocatePublicKeyAsync(string methods, string domain, string selector, CancellationToken cancellationToken = default) =>
            Task.FromResult(LocatePublicKey(methods, domain, selector, cancellationToken));
    }

    private sealed class Rig : IAsyncDisposable
    {
        public required InboundLab Lab { get; init; }
        public required PeerMta Destination { get; init; }
        public required RSA RouteKey { get; init; }
        public required RSA SenderKey { get; init; }
        public Guid Route { get; init; }

        public Locator Keys() => new(new Dictionary<string, RSA>(StringComparer.OrdinalIgnoreCase) { ["example.org"] = RouteKey, ["sender.test"] = SenderKey });

        /// <summary>A message signed by sender.test (the library signer; MimeKit does the verifying) and sent over SMTP; returns the id of the stored message and the exact bytes that were stored.</summary>
        public async Task<(InboundMessage Stored, byte[] StoredRaw, string Original)> ReceiveAsync(string body = "Hello from Alice\r\n", string subject = "Greetings", string extraHeaders = "", string to = "fwd@example.org")
        {
            string message = $"From: Alice <alice@sender.test>\r\nTo: {to}\r\nSubject: {subject}\r\nDate: Fri, 16 Oct 2026 07:00:00 +0000\r\nMessage-ID: <{Guid.NewGuid():N}@sender.test>\r\n{extraHeaders}MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{body}";
            using var signer = Mta.Dkim.DkimSigner.FromPem(new DkimSignerOptions { Domain = "sender.test", Selector = "sel", Clock = Lab.Clock }, SenderKey.ExportPkcs8PrivateKeyPem());
            string signed = signer.Sign(Encoding.UTF8.GetBytes(message)) + message;
            var (sent, _) = await RealMta.SendAsync(Lab.Port, "alice@sender.test", [to], signed);   // the project's SMTP client sends the UTF-8 bytes that were signed
            Assert.True(sent.Delivered);
            InboundMessage stored = (await Lab.MessagesAsync(InboundLab.Acme)).First(m => m.Subject == subject && m.EnvelopeTo == to);
            byte[] raw = (await Lab.Storage.Inbound.GetRawAsync(InboundLab.Acme, stored.Id, default))!;
            return (stored, raw, signed);
        }

        public async Task<InboundMessage> RunActionAsync(Guid id)
        {
            DateTime deadline = DateTime.UtcNow.AddSeconds(60);
            while (true)
            {
                await Lab.Runtime.InboundActions.RunOnceAsync(default);
                InboundMessage m = (await Lab.Storage.Inbound.GetAsync(InboundLab.Acme, id, default))!;
                if (m.ActionState != InboundActionState.Pending)
                {
                    return m;
                }

                if (DateTime.UtcNow > deadline)
                {
                    throw new TimeoutException($"the forward never completed; {m.ActionLastError}");
                }

                await Task.Delay(20);
            }
        }

        public async ValueTask DisposeAsync()
        {
            await Lab.DisposeAsync();
            await Destination.DisposeAsync();
            RouteKey.Dispose();
            SenderKey.Dispose();
        }
    }

    private async Task<Rig?> StartAsync(MtaPersonality? destination = null, IReadOnlyList<string>? forwardTo = null)
    {
        var options = new LabOptions
        {
            WithApi = true,
            RunDelivery = true,
            Inbound = new InboundSection { Enabled = true, CheckSpfForInternalClients = true, MaxMessagesPerMinute = 1_000_000, MaxMessagesPerMinutePerRemote = 1_000_000 },
        };
        var fake = new PeerMta(destination ?? Personalities.Postfix());
        InboundLab? lab = await InboundLab.StartAsync(backend, options with { RemotePort = fake.Port });
        if (lab is null)
        {
            await fake.DisposeAsync();
            return null;
        }

        lab.Dns.AddMx("dest.example", 10, "mx.dest.example").AddA("mx.dest.example", "127.0.0.1");
        lab.PublishSpf("sender.test");
        lab.PublishDmarc("sender.test", "none");
        RSA routeKey = await lab.AddDkimKeyAsync(lab.ExampleOrg, "example.org");
        RSA senderKey = lab.PublishDkimKey("sender.test", "sel");
        Guid route = await lab.AddRouteAsync(lab.ExampleOrg, InboundLab.Acme, 4, InboundMatchKind.Address, "fwd", InboundActionKind.Forward, forwardTo ?? ["rcpt@dest.example"]);
        await lab.RefreshAsync();
        return new Rig { Lab = lab, Destination = fake, RouteKey = routeKey, SenderKey = senderKey, Route = route };
    }

    private static MimeMessage Load(byte[] raw)
    {
        using var ms = new MemoryStream(raw);
        return MimeMessage.Load(ms);
    }

    // ------------------------------------------------------------------ the happy path

    [Fact]
    public async Task A_forward_arrives_with_an_srs_envelope_a_valid_original_signature_our_own_for_the_route_domain_only_an_arc_set_and_the_original_bytes()
    {
        await using Rig? rig = await StartAsync();
        if (rig is null)
        {
            return;
        }

        var (stored, storedRaw, original) = await rig.ReceiveAsync(body: "Grüße aus München\r\n" + new string('x', 1_000) + "\r\nlast line\r\n");
        Assert.Equal((InboundActionKind.Forward, InboundActionState.Pending), (stored.ActionKind, stored.ActionState));
        Assert.Empty(rig.Destination.Messages);   // received is not forwarded: the action runs after the 250

        InboundMessage done = await rig.RunActionAsync(stored.Id);
        await rig.Destination.WaitForMessagesAsync(1);

        Assert.Equal((InboundActionState.Done, false), (done.ActionState, done.HasRaw));   // the body is freed: the copy lives in the outbound queue now
        Assert.NotNull(done.ForwardMessageId);
        ReceivedMessage mail = Assert.Single(rig.Destination.Messages);
        Assert.Equal(["rcpt@dest.example"], mail.Recipients);
        Assert.StartsWith("SRS0=", mail.Sender, StringComparison.Ordinal);
        Assert.EndsWith("@example.org", mail.Sender, StringComparison.Ordinal);
        string local = mail.Sender[..mail.Sender.IndexOf('@', StringComparison.Ordinal)];
        Assert.InRange(local.Length, 1, 64);
        Assert.True(rig.Lab.Srs.TryVerify(local, rig.Lab.Clock.UtcNow));
        Assert.False(mail.SmtpUtf8);

        // The stored message is a suffix of what arrived, byte for byte: headers were only added on top.
        string delivered = Encoding.UTF8.GetString(mail.Body);
        Assert.EndsWith(Encoding.UTF8.GetString(storedRaw), delivered, StringComparison.Ordinal);
        Assert.Single(Regex.Matches(delivered, "(?im)^X-EggMail-Hops: 1; "));
        Assert.Equal(1, new ForwardHopMarker(rig.Lab.Runtime.Verp).ReadValidHops(mail.Body));

        // MimeKit verifies what arrived.
        MimeMessage parsed = Load(mail.Body);
        var verifier = new MimeKit.Cryptography.DkimVerifier(rig.Keys());
        List<Header> signatures = [.. parsed.Headers.Where(h => h.Id == HeaderId.DkimSignature)];
        Assert.Equal(2, signatures.Count);
        Header ours = signatures.Single(h => h.Value.Contains("d=example.org", StringComparison.Ordinal));
        Header theirs = signatures.Single(h => h.Value.Contains("d=sender.test", StringComparison.Ordinal));
        Assert.True(verifier.Verify(Wire, parsed, ours), "the signature of the route's domain");
        Assert.True(verifier.Verify(Wire, parsed, theirs), "the sender's own signature, which is what carries DMARC for the copy");
        // The sender's signature is the very line it arrived with (nothing rewrapped, reordered or re-signed), and nothing we added claims to be the From domain.
        string theirLine = original[..original.IndexOf("\r\nFrom:", StringComparison.Ordinal)];
        Assert.Contains(theirLine.Replace("\r\n", "\r\n", StringComparison.Ordinal), delivered, StringComparison.Ordinal);
        Assert.Single(Regex.Matches(delivered, @"(?im)^DKIM-Signature:[^\r]*\sd=sender\.test"));
        Assert.Equal(ArcSignatureValidationResult.Pass, new ArcVerifier(rig.Keys()).Verify(Wire, parsed).Chain);
        Assert.Contains("cv=none", delivered, StringComparison.Ordinal);

        // The outbound message is the tenant's own, in its history, and says what it is.
        ApiClient alice = await rig.Lab.Api!.SignedInAsync("alice");
        Reply message = await alice.GetAsync("/api/v1/messages/" + ApiJson.Id(done.ForwardMessageId!.Value));
        Assert.Equal(System.Net.HttpStatusCode.OK, message.Status);
        await rig.Lab.AssertNothingWasSentAsync();   // nothing left in the queue: the copy was delivered, and nothing else was made
    }

    [Fact]
    public async Task A_route_domain_without_a_key_forwards_unsigned_and_unsealed_and_a_bounce_is_forwarded_with_the_null_sender_and_the_route_domains_signature()
    {
        await using Rig? rig = await StartAsync();
        if (rig is null)
        {
            return;
        }

        // A second domain of the tenant with no DKIM key: nothing may be signed or sealed in its place.
        Guid keyless = await rig.Lab.AddDomainAsync(InboundLab.Acme, "keyless.example");
        await rig.Lab.AddRouteAsync(keyless, InboundLab.Acme, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Forward, ["rcpt@dest.example"]);
        await rig.Lab.RefreshAsync();
        var (stored, _, _) = await rig.ReceiveAsync(subject: "no key here", to: "anyone@keyless.example");
        await rig.RunActionAsync(stored.Id);
        await rig.Destination.WaitForMessagesAsync(1);
        string unsigned = Encoding.UTF8.GetString(Assert.Single(rig.Destination.Messages).Body);
        Assert.Single(Regex.Matches(unsigned, @"(?im)^DKIM-Signature:"));            // the sender's own, and nothing of ours
        Assert.DoesNotContain("d=keyless.example", unsigned, StringComparison.Ordinal);
        Assert.DoesNotContain("ARC-Seal:", unsigned, StringComparison.Ordinal);
        Assert.Contains("d=sender.test", unsigned, StringComparison.Ordinal);

        // A message with the null reverse-path (a bounce or an auto-reply to the route's address) goes on with the null reverse-path, never an SRS address, signed by the route's domain.
        Assert.Equal(250, (await rig.Lab.SendAsync("", "fwd@example.org", InboundLab.Message(from: "MAILER-DAEMON@sender.test", to: "fwd@example.org", subject: "a report"))).Code);
        InboundMessage report = (await rig.Lab.MessagesAsync(InboundLab.Acme)).Single(m => m.Subject == "a report");
        await rig.RunActionAsync(report.Id);
        await rig.Destination.WaitForMessagesAsync(2);
        ReceivedMessage second = rig.Destination.Messages.Last();
        Assert.Equal(string.Empty, second.Sender);
        Assert.Contains("d=example.org", Encoding.UTF8.GetString(second.Body), StringComparison.Ordinal);
        Assert.DoesNotContain("d=sender.test", Encoding.UTF8.GetString(second.Body), StringComparison.Ordinal);   // nothing claims the From domain's name
    }

    // ------------------------------------------------------------------ failures at the destination

    [Fact]
    public async Task A_destination_that_refuses_the_forward_makes_no_mail_for_anybody_the_tenant_learns_from_the_outbound_message_and_its_event()
    {
        var refuse = Personalities.Postfix();
        refuse.OnRcpt = (_, to) => to.Contains("rcpt@dest.example", StringComparison.OrdinalIgnoreCase) ? Personalities.PostfixReplies.UserUnknown("rcpt@dest.example") : null;
        await using Rig? rig = await StartAsync(refuse);
        if (rig is null)
        {
            return;
        }

        await rig.Lab.AddWebhookEndpointAsync(InboundLab.Acme, "http://127.0.0.1:9/never-called");   // the tenant's endpoint: its events wait in the outbox (no dispatcher runs)
        var (stored, _, _) = await rig.ReceiveAsync(subject: "refused");
        InboundMessage done = await rig.RunActionAsync(stored.Id);
        Assert.Equal(InboundActionState.Done, done.ActionState);   // handed over to the outbound queue: that is the end of the inbound action

        // The delivery fails for good at the first attempt; the outbound message says so.
        ApiClient alice = await rig.Lab.Api!.SignedInAsync("alice");
        string path = "/api/v1/messages/" + ApiJson.Id(done.ForwardMessageId!.Value);
        DateTime deadline = DateTime.UtcNow.AddSeconds(60);
        Reply outbound;
        do
        {
            await Task.Delay(30);
            outbound = await alice.GetAsync(path);
        }
        while (!outbound.Body.Contains("bounced", StringComparison.OrdinalIgnoreCase) && DateTime.UtcNow < deadline);

        Assert.Contains("bounced", outbound.Body, StringComparison.OrdinalIgnoreCase);
        // No bounce message of any kind: nothing for the original sender (an address on sender.test would have been accepted by this very fake), nothing for the null sender, and the destination never held a message.
        await Task.Delay(300);
        Assert.Empty(rig.Destination.Messages);
        Assert.Empty(await rig.Lab.Storage.Deliveries.ClaimAsync("oracle", 100, rig.Lab.Clock.UtcNow.AddDays(30), TimeSpan.FromMinutes(1), default));
        // The tenant's endpoint was told about the outbound message, not the original sender.
        var events = await rig.Lab.Storage.Webhooks.ClaimDueAsync("oracle", 100, rig.Lab.Clock.UtcNow.AddDays(30), TimeSpan.FromMinutes(1), default);
        Assert.Contains(events, e => e.EventType == "message.bounced" && e.TenantId == InboundLab.Acme);
        Assert.DoesNotContain(events, e => e.PayloadJson.Contains("alice@sender.test", StringComparison.Ordinal) && e.EventType != "message.bounced");
    }

    [Fact]
    public async Task A_destination_that_asks_to_come_back_later_gets_the_same_copy_again_and_stores_it_once()
    {
        int rcpts = 0;
        var greylist = Personalities.Postfix();
        greylist.OnRcpt = (_, to) => Interlocked.Increment(ref rcpts) == 1 ? Personalities.PostfixReplies.Greylisted(to, "dest.example") : null;
        await using Rig? rig = await StartAsync(greylist);
        if (rig is null)
        {
            return;
        }

        var (stored, _, _) = await rig.ReceiveAsync(subject: "greylisted");
        await rig.RunActionAsync(stored.Id);
        await Wait.UntilAsync(() => Volatile.Read(ref rcpts) >= 1, "the first attempt");
        Assert.Empty(rig.Destination.Messages);

        // The retry is on the delivery engine's clock (the lab's): move it, and the engine tries again.
        for (int i = 0; i < 12 && rig.Destination.Messages.Count == 0; i++)
        {
            await rig.Lab.AdvanceAsync(TimeSpan.FromMinutes(20));
            await Task.Delay(120);
        }

        await rig.Destination.WaitForMessagesAsync(1);
        ReceivedMessage mail = Assert.Single(rig.Destination.Messages);
        Assert.StartsWith("SRS0=", mail.Sender, StringComparison.Ordinal);
        string[] envelopes = [.. rig.Destination.Sessions.SelectMany(s => s.Transcript).Where(l => l.StartsWith("C: MAIL FROM:", StringComparison.OrdinalIgnoreCase)).Select(l => l["C: MAIL FROM:".Length..].Split(' ')[0])];
        Assert.Equal(2, envelopes.Length);
        Assert.Single(envelopes.Distinct());   // the same envelope at every attempt
        Assert.Equal($"<{mail.Sender}>", envelopes[0]);
        Assert.Single(Regex.Matches(Encoding.UTF8.GetString(mail.Body), "(?im)^X-EggMail-Hops:"));
    }

    [Fact]
    public async Task A_message_in_eight_bit_is_never_converted_for_a_destination_without_eightbitmime_it_fails_there_and_nothing_is_mailed()
    {
        var old = Personalities.Postfix();
        old.EightBitMime = false;
        await using Rig? rig = await StartAsync(old);
        if (rig is null)
        {
            return;
        }

        var (stored, _, _) = await rig.ReceiveAsync(body: "Grüße über alles\r\n", subject: "eight bit");
        InboundMessage done = await rig.RunActionAsync(stored.Id);

        ApiClient alice = await rig.Lab.Api!.SignedInAsync("alice");
        string path = "/api/v1/messages/" + ApiJson.Id(done.ForwardMessageId!.Value);
        DateTime deadline = DateTime.UtcNow.AddSeconds(60);
        Reply outbound;
        do
        {
            await Task.Delay(30);
            outbound = await alice.GetAsync(path);
        }
        while (!outbound.Body.Contains("bounced", StringComparison.OrdinalIgnoreCase) && DateTime.UtcNow < deadline);

        Assert.Contains("bounced", outbound.Body, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(rig.Destination.Messages);   // not a downgraded copy, not a rewritten one: the original DKIM signature would not have survived either
        Assert.Contains(rig.Destination.Sessions, s => s.Verbs.Contains("EHLO") && !s.Verbs.Contains("DATA"));
    }

    [Fact]
    public async Task A_target_on_the_suppression_list_is_not_mailed_and_a_forward_to_a_local_domain_fails_without_queueing_anything()
    {
        await using Rig? rig = await StartAsync(forwardTo: ["rcpt@dest.example"]);
        if (rig is null)
        {
            return;
        }

        await rig.Lab.Storage.Config.AddSuppressionAsync(new SuppressionRecord(InboundLab.Acme, "rcpt@dest.example", SuppressionReason.Manual, null, rig.Lab.Clock.UtcNow, null), default);
        var (stored, _, _) = await rig.ReceiveAsync(subject: "suppressed");
        InboundMessage done = await rig.RunActionAsync(stored.Id);
        Assert.Equal((InboundActionState.Done, "all_targets_suppressed", true), (done.ActionState, done.ActionNote, done.HasRaw));

        // A route that points at a domain this server receives for: refused at run time, whatever it said when it was written.
        Guid loop = await rig.Lab.AddRouteAsync(rig.Lab.ExampleOrg, InboundLab.Acme, 3, InboundMatchKind.Address, "selfwards", InboundActionKind.Forward, ["someone@example.net"]);
        await rig.Lab.RefreshAsync();
        var (second, _, _) = await rig.ReceiveAsync(subject: "to a local domain", to: "selfwards@example.org");
        InboundMessage failed = await rig.RunActionAsync(second.Id);
        Assert.Equal((InboundActionState.Failed, "forward_target_is_local"), (failed.ActionState, failed.ActionLastError));
        _ = loop;
        Assert.Empty(rig.Destination.Messages);
        await rig.Lab.AssertNothingWasSentAsync();
    }

    [Fact]
    public async Task A_message_claiming_the_tenants_own_domain_without_passing_dmarc_is_not_forwarded_under_its_srs_and_signature()
    {
        await using Rig? rig = await StartAsync();
        if (rig is null)
        {
            return;
        }

        // example.org publishes an SPF record that does not authorize the sender: a spoof of the tenant's own domain.
        rig.Lab.PublishSpf("example.org", authorize: false);
        rig.Lab.PublishDmarc("example.org", "none");
        Assert.Equal(250, (await rig.Lab.SendAsync("ceo@example.org", "fwd@example.org", InboundLab.Message(from: "CEO <ceo@example.org>", to: "fwd@example.org", subject: "spoof"))).Code);
        InboundMessage spoof = (await rig.Lab.MessagesAsync(InboundLab.Acme)).Single(m => m.Subject == "spoof");

        InboundMessage done = await rig.RunActionAsync(spoof.Id);

        Assert.Equal((InboundActionState.Failed, "unauthenticated_local_sender"), (done.ActionState, done.ActionLastError));
        Assert.Empty(rig.Destination.Messages);
    }

    // ------------------------------------------------------------------ loops

    [Fact]
    public async Task Two_servers_that_forward_to_each_other_stop_at_the_received_limit_and_nothing_loops_for_ever_or_comes_back_to_the_sender()
    {
        if (!Mta.TestSupport.PostgresPromise.Available() && backend == LabBackend.Postgres)
        {
            return;
        }

        int portA = InboundLab.ReservePort(), portB = InboundLab.ReservePort();
        InboundSection inbound = new() { Enabled = true, CheckSpfForInternalClients = true, MaxMessagesPerMinute = 1_000_000, MaxMessagesPerMinutePerRemote = 1_000_000, Action = new InboundActionSection { PollInterval = TimeSpan.FromMilliseconds(30) } };
        await using InboundLab? a = await InboundLab.StartAsync(backend, new LabOptions { Seed = false, RunActions = true, RunDelivery = true, Inbound = inbound, ListenerPort = portA, RemotePort = portB });
        if (a is null)
        {
            return;
        }

        await using InboundLab? b = await InboundLab.StartAsync(backend, new LabOptions { Seed = false, RunActions = true, RunDelivery = true, Inbound = inbound, ListenerPort = portB, RemotePort = portA });
        Assert.NotNull(b);

        // Server A receives for a.example and forwards everything to loop@b.example; server B receives for b.example and forwards everything to loop@a.example.
        Guid domainA = await a.AddDomainAsync(InboundLab.Acme, "a.example");
        Guid domainB = await b.AddDomainAsync(InboundLab.Acme, "b.example");
        await a.AddRouteAsync(domainA, InboundLab.Acme, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Forward, ["loop@b.example"]);
        await b.AddRouteAsync(domainB, InboundLab.Acme, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Forward, ["loop@a.example"]);
        using RSA keyA = await a.AddDkimKeyAsync(domainA, "a.example");
        using RSA keyB = await b.AddDkimKeyAsync(domainB, "b.example");
        foreach (InboundLab lab in new[] { a, b })
        {
            lab.Dns.AddMx("a.example", 10, "mx.a.example").AddA("mx.a.example", "127.0.0.1");
            lab.Dns.AddMx("b.example", 10, "mx.b.example").AddA("mx.b.example", "127.0.0.1");
            lab.Dns.AddTxt("a.example", "v=spf1 ip4:127.0.0.1 -all");
            lab.Dns.AddTxt("b.example", "v=spf1 ip4:127.0.0.1 -all");
            lab.Dns.AddTxt("_dmarc.a.example", "v=DMARC1; p=none");
            lab.Dns.AddTxt("_dmarc.b.example", "v=DMARC1; p=none");
            lab.Dns.AddTxt("sender.test", "v=spf1 ip4:127.0.0.1 -all");
        }

        a.Dns.AddTxt(Mta.Dkim.DkimKeyTools.GetDnsName("b.example", "egg1"), Mta.Dkim.DkimKeyTools.FormatDnsTxtValue(keyB));
        b.Dns.AddTxt(Mta.Dkim.DkimKeyTools.GetDnsName("a.example", "egg1"), Mta.Dkim.DkimKeyTools.FormatDnsTxtValue(keyA));
        await a.AddWebhookEndpointAsync(InboundLab.Acme, "http://127.0.0.1:9/never");
        await b.AddWebhookEndpointAsync(InboundLab.Acme, "http://127.0.0.1:9/never");
        await a.RefreshAsync();
        await b.RefreshAsync();

        Assert.Equal(250, (await a.SendAsync("alice@sender.test", "start@a.example", InboundLab.Message(from: "Alice <alice@sender.test>", to: "start@a.example", subject: "round and round"))).Code);

        // Wait until the exchange has died down on both servers: nothing pending, nothing queued, and the counts stopped changing.
        int last = -1, stable = 0;
        DateTime guard = DateTime.UtcNow.AddSeconds(120);
        while (stable < 25 && DateTime.UtcNow < guard)
        {
            await Task.Delay(100);
            int now = (await a.MessagesAsync(InboundLab.Acme)).Count + (await b.MessagesAsync(InboundLab.Acme)).Count;
            long busy = (await a.Storage.Inbound.GetUsageAsync(InboundLab.Acme, null, default)).Pending + (await b.Storage.Inbound.GetUsageAsync(InboundLab.Acme, null, default)).Pending;
            stable = now == last && busy == 0 ? stable + 1 : 0;
            last = now;
        }

        Assert.True(stable >= 25, "the exchange never died down");
        IReadOnlyList<InboundMessage> onA = await a.MessagesAsync(InboundLab.Acme, new InboundMessageQuery(InboundLab.Acme, Limit: 200));
        IReadOnlyList<InboundMessage> onB = await b.MessagesAsync(InboundLab.Acme, new InboundMessageQuery(InboundLab.Acme, Limit: 200));
        Assert.InRange(onA.Count + onB.Count, 20, 60);   // it looped for a good while (about 25 Received headers' worth) and then stopped

        // Every hop kept its envelope within the 64 octets a local part may have, however many times the sender was wrapped.
        foreach (InboundMessage m in onA.Concat(onB))
        {
            int at = m.EnvelopeFrom.LastIndexOf('@');
            if (at > 0)
            {
                Assert.InRange(m.EnvelopeFrom[..at].Length, 1, 64);
            }
        }

        // One Received header is added at every hop, so the number of copies stored by both servers together is the number of hops: the chain stopped where the limit of 25 says it must.
        Assert.InRange(onA.Count + onB.Count, 24, 27);
        var events = new List<WebhookOutboxItem>();
        foreach (InboundLab lab in new[] { a, b })
        {
            events.AddRange(await lab.Storage.Webhooks.ClaimDueAsync("oracle", 200, lab.Clock.UtcNow.AddDays(30), TimeSpan.FromMinutes(1), default));
        }

        Assert.Contains(events, e => e.EventType == "message.bounced" && e.PayloadJson.Contains("5.4.6", StringComparison.Ordinal));   // the tenant learns of it from the failed outbound message

        // And no bounce reached the original sender, who is on neither server: the only mail either server ever sent went to the other.
        Assert.DoesNotContain(events, e => e.EventType == "message.bounced" && e.PayloadJson.Contains("alice@sender.test", StringComparison.Ordinal) && !e.PayloadJson.Contains("loop@", StringComparison.Ordinal));
    }
}

public sealed class SqliteInboundForwardE2ETests() : InboundForwardE2ETests(LabBackend.Sqlite);

public sealed class PostgresInboundForwardE2ETests() : InboundForwardE2ETests(LabBackend.Postgres);
