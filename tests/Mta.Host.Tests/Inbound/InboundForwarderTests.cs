using System.Text;
using Mta.Auth.Arc;
using Mta.Core;
using Mta.Dns;
using Mta.Dsn;
using Mta.Host.Inbound;
using Mta.Storage;
using Mta.Storage.Logic;

namespace Mta.Host.Tests.Inbound;

/// <summary>The forward action (design section 11.7) on the in-memory store: what is queued, and what is refused.</summary>
[Collection("inbound-actions")]
public class InboundForwarderTests
{
    private static readonly VerpCodec Ring = new(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey() }, 1);

    private sealed class Rig : IAsyncDisposable
    {
        public required InboundActionHarness Harness { get; init; }
        public required InboundForwarder Forwarder { get; init; }

        public ValueTask DisposeAsync() => Harness.DisposeAsync();
    }

    private static async Task<Rig> StartAsync(string[]? targets = null, string? bounceDomain = "bounces.egg.test")
    {
        var h = await new InboundActionHarness().InitializeAsync(InboundActionKind.Forward);
        await h.Storage.Inbound.UpsertRouteAsync(h.Route with { ForwardTo = targets ?? ["target@example.org"], UpdatedAt = h.Clock.UtcNow }, default);
        var forwarder = new InboundForwarder(
            h.Storage, new ForwardSrs(Ring), new ForwardHops(Ring), new ArcValidator(new StaticDnsResolver()), null,
            new InboundForwarderOptions { AuthenticationResultsId = "egg.test", BounceDomain = bounceDomain }, h.Clock, NullMtaLog.Instance);
        return new Rig { Harness = h, Forwarder = forwarder };
    }

    private static byte[] Foreign(string from = "alice@sender.test", string extra = "") =>
        Encoding.UTF8.GetBytes($"Received: by egg.test\r\nFrom: Alice <{from}>\r\nTo: support@example.com\r\nSubject: Hi\r\n{extra}\r\nbody\r\n");

    private static async Task<InboundActionResult> ForwardAsync(Rig rig, InboundMessageDraft draft, byte[] raw)
    {
        InboundMessage message = await rig.Harness.GetAsync(draft.Id);
        InboundRouteRecord route = (await rig.Harness.Storage.Inbound.GetRouteAsync(rig.Harness.TenantId, rig.Harness.Route.Id, default))!;
        return await rig.Forwarder.ForwardAsync(message, route, raw, default);
    }

    [Fact]
    public async Task A_forward_is_queued_through_the_runner_with_srs_envelope_idempotency_key_and_the_route_domain()
    {
        await using Rig rig = await StartAsync();
        InboundActionRunner runner = rig.Harness.CreateRunner(forwarder: rig.Forwarder);
        byte[] raw = Foreign();
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(raw);

        await runner.RunOnceAsync(default);

        InboundMessage stored = await rig.Harness.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Done, stored.ActionState);
        Assert.False(stored.HasRaw);   // the copy lives in the outbound queue now
        Guid forwardId = stored.ForwardMessageId!.Value;

        // The queued message is the original with headers on top only, from the tenant's route domain, with an SRS envelope sender.
        byte[] queued = (await rig.Harness.Storage.Deliveries.GetRawAsync(forwardId, default))!;
        string text = Encoding.UTF8.GetString(queued);
        Assert.StartsWith("X-EggMail-Hops: 1; ", text, StringComparison.Ordinal);
        Assert.EndsWith(Encoding.UTF8.GetString(raw), text, StringComparison.Ordinal);
        Assert.Equal(1, new ForwardHops(Ring).ReadValidHops(queued));

        ClaimedDelivery delivery = Assert.Single(await rig.Harness.Storage.Deliveries.ClaimAsync("t", 10, rig.Harness.Clock.UtcNow, TimeSpan.FromMinutes(1), default));
        Assert.Equal(MessageSource.Forward, delivery.Source);
        Assert.Equal("example.com", delivery.SendingDomain);   // the route's domain, never the From domain
        Assert.Equal("target@example.org", delivery.Recipient.ToString());
        string senderLocal = delivery.EnvelopeFrom.LocalPart;
        Assert.EndsWith("@example.com", delivery.EnvelopeFrom.ToString());
        Assert.True(new ForwardSrs(Ring).IsValid(senderLocal, rig.Harness.Clock.UtcNow));
        Assert.True(senderLocal.Length <= 64);
    }

    [Fact]
    public async Task A_retry_after_the_targets_were_edited_returns_the_copy_that_exists()
    {
        await using Rig rig = await StartAsync(["first@example.org"]);
        InboundActionRunner runner = rig.Harness.CreateRunner(forwarder: rig.Forwarder);
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(Foreign());
        await runner.RunOnceAsync(default);
        Guid first = (await rig.Harness.GetAsync(draft.Id)).ForwardMessageId!.Value;

        // The tenant edits the targets and asks again (the body was freed, so the API refuses a retry; the runner is called the way a crash between "queued" and "done" would call it).
        await rig.Harness.Storage.Inbound.UpsertRouteAsync(rig.Harness.Route with { ForwardTo = ["second@example.org"], UpdatedAt = rig.Harness.Clock.UtcNow }, default);
        InboundActionResult again = await ForwardAsync(rig, draft, Foreign());

        Assert.Equal(first, again.ForwardMessageId);   // one copy per received message, ever; the new target is not sent to
        ClaimedDelivery only = Assert.Single(await rig.Harness.Storage.Deliveries.ClaimAsync("t", 10, rig.Harness.Clock.UtcNow, TimeSpan.FromMinutes(1), default));
        Assert.Equal("first@example.org", only.Recipient.ToString());
    }

    [Fact]
    public async Task The_null_reverse_path_stays_null_and_is_never_turned_into_an_srs_address()
    {
        await using Rig rig = await StartAsync();
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(Foreign(), from: "");

        InboundActionResult result = await ForwardAsync(rig, draft, Foreign());

        Assert.NotNull(result.ForwardMessageId);
        Assert.True(Assert.Single(await rig.Harness.Storage.Deliveries.ClaimAsync("t", 10, rig.Harness.Clock.UtcNow, TimeSpan.FromMinutes(1), default)).EnvelopeFrom.IsNull);
    }

    [Theory]
    [InlineData("a-very-long-address-that-goes-on-and-on-and-on@a-domain-name-that-is-also-quite-long.and-has-many-labels.example.org")]
    [InlineData("ünïcode@sender.test")]
    public async Task A_long_or_international_original_address_gives_an_srs_local_part_of_at_most_64_octets(string from)
    {
        await using Rig rig = await StartAsync();
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(Foreign(), from: from);

        await ForwardAsync(rig, draft, Foreign());

        ClaimedDelivery delivery = Assert.Single(await rig.Harness.Storage.Deliveries.ClaimAsync("t", 10, rig.Harness.Clock.UtcNow, TimeSpan.FromMinutes(1), default));
        Assert.InRange(delivery.EnvelopeFrom.LocalPart.Length, 1, 64);
        Assert.True(new ForwardSrs(Ring).IsValid(delivery.EnvelopeFrom.LocalPart, rig.Harness.Clock.UtcNow));
    }

    [Fact]
    public async Task Suppressed_targets_are_left_out_and_when_all_are_suppressed_nothing_is_queued()
    {
        await using Rig rig = await StartAsync(["one@example.org", "two@example.org"]);
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(Foreign());
        await rig.Harness.Storage.Config.AddSuppressionAsync(new SuppressionRecord(rig.Harness.TenantId, "one@example.org", SuppressionReason.HardBounce, null, rig.Harness.Clock.UtcNow, null), default);

        InboundActionResult some = await ForwardAsync(rig, draft, Foreign());
        Assert.NotNull(some.ForwardMessageId);
        Assert.Equal(["two@example.org"], (await rig.Harness.Storage.Deliveries.ClaimAsync("t", 10, rig.Harness.Clock.UtcNow, TimeSpan.FromMinutes(1), default)).Select(d => d.Recipient.ToString()));

        await using Rig all = await StartAsync(["one@example.org"]);
        InboundMessageDraft second = await all.Harness.ReceiveAsync(Foreign());
        await all.Harness.Storage.Config.AddSuppressionAsync(new SuppressionRecord(all.Harness.TenantId, "ONE@example.org", SuppressionReason.Manual, null, all.Harness.Clock.UtcNow, null), default);
        InboundActionResult none = await ForwardAsync(all, second, Foreign());
        Assert.Null(none.ForwardMessageId);
        Assert.Equal("all_targets_suppressed", none.Note);
        Assert.False(none.FreeBody);   // a retry after the tenant lifts the suppression can still forward it
        Assert.Empty(await all.Harness.Storage.Deliveries.ClaimAsync("t", 10, all.Harness.Clock.UtcNow, TimeSpan.FromMinutes(1), default));
    }

    [Theory]
    [InlineData("someone@example.com")]       // the route's own domain
    [InlineData("someone@Example.COM")]
    [InlineData("someone@bounces.egg.test")]  // the bounce domain
    public async Task A_target_that_would_come_back_here_is_refused_at_run_time_whatever_the_route_said(string target)
    {
        await using Rig rig = await StartAsync([target]);
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(Foreign());

        InboundActionResult result = await ForwardAsync(rig, draft, Foreign());

        Assert.Equal("forward_target_is_local", result.Error);
        Assert.Empty(await rig.Harness.Storage.Deliveries.ClaimAsync("t", 10, rig.Harness.Clock.UtcNow, TimeSpan.FromMinutes(1), default));
    }

    [Fact]
    public async Task A_target_in_another_domain_this_server_receives_for_is_refused()
    {
        await using Rig rig = await StartAsync(["someone@other-inbound.test"]);
        var now = rig.Harness.Clock.UtcNow;
        var other = new DomainRecord(Ids.New(), rig.Harness.TenantId, "other-inbound.test", DomainStatus.Verified, null, false, now, null, null, 0, null, false, null);
        await rig.Harness.Storage.Config.UpsertDomainAsync(other, default);
        await rig.Harness.Storage.Inbound.UpsertSettingsAsync(new InboundDomainSettings(other.Id, other.TenantId, true, InboundDmarcAction.RecordOnly, null, null, null, null, null, now), default);
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(Foreign());

        Assert.Equal("forward_target_is_local", (await ForwardAsync(rig, draft, Foreign())).Error);
    }

    [Fact]
    public async Task A_message_forwarded_three_times_already_is_not_forwarded_and_the_loop_is_counted()
    {
        await using Rig rig = await StartAsync();
        var marker = new ForwardHops(Ring);
        byte[] raw = marker.Apply(Foreign(), 3);
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(raw);

        InboundActionResult result = await ForwardAsync(rig, draft, raw);

        Assert.Equal("loop_detected", result.Error);
        Assert.Empty(await rig.Harness.Storage.Deliveries.ClaimAsync("t", 10, rig.Harness.Clock.UtcNow, TimeSpan.FromMinutes(1), default));

        // Two hops are fine; the copy carries three.
        byte[] two = marker.Apply(Foreign(), 2);
        InboundMessageDraft second = await rig.Harness.ReceiveAsync(two);
        InboundActionResult ok = await ForwardAsync(rig, second, two);
        Assert.Equal(3, marker.ReadValidHops((await rig.Harness.Storage.Deliveries.GetRawAsync(ok.ForwardMessageId!.Value, default))!));
    }

    [Fact]
    public async Task A_forged_marker_is_replaced_not_counted_and_two_markers_never_survive()
    {
        await using Rig rig = await StartAsync();
        byte[] raw = Encoding.UTF8.GetBytes("X-EggMail-Hops: 9; 0000000000000000\r\nX-EggMail-Hops: 2; 1111111111111111\r\nFrom: a@sender.test\r\nSubject: s\r\n\r\nbody\r\n");
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(raw);

        InboundActionResult result = await ForwardAsync(rig, draft, raw);

        string queued = Encoding.UTF8.GetString((await rig.Harness.Storage.Deliveries.GetRawAsync(result.ForwardMessageId!.Value, default))!);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(queued, "(?im)^X-EggMail-Hops:"));
        Assert.StartsWith("X-EggMail-Hops: 1; ", queued, StringComparison.Ordinal);   // the count restarts at zero: the safe direction for mail
    }

    [Fact]
    public async Task A_spoof_of_the_routes_own_domain_that_failed_dmarc_is_not_forwarded_but_authenticated_mail_of_it_is()
    {
        await using Rig rig = await StartAsync();
        byte[] spoof = Foreign(from: "ceo@example.com");
        InboundMessageDraft failing = await rig.Harness.ReceiveAsync(spoof);
        InboundMessage message = await rig.Harness.GetAsync(failing.Id);
        InboundRouteRecord route = (await rig.Harness.Storage.Inbound.GetRouteAsync(rig.Harness.TenantId, rig.Harness.Route.Id, default))!;

        // The draft's verdicts say DMARC passed; make it fail for this case.
        InboundMessage notAuthenticated = message with { Auth = message.Auth with { Dmarc = InboundVerdict.Fail } };
        Assert.Equal("unauthenticated_local_sender", (await rig.Forwarder.ForwardAsync(notAuthenticated, route, spoof, default)).Error);
        Assert.Equal("unauthenticated_local_sender", (await rig.Forwarder.ForwardAsync(notAuthenticated, route, Foreign(from: "x@mail.example.com"), default)).Error);   // same organizational domain
        Assert.NotNull((await rig.Forwarder.ForwardAsync(notAuthenticated, route, Foreign(from: "x@sender.test"), default)).ForwardMessageId);   // a foreign From needs no DMARC pass
        Assert.NotNull((await rig.Forwarder.ForwardAsync(message, route, spoof, default)).ForwardMessageId);   // DMARC passed (the sender really is the tenant's)

        // A second From header, a quoted display name or a comment cannot hide the own domain from the check (and a foreign display name does not make it foreign).
        byte[] twoFroms = Encoding.UTF8.GetBytes("Received: by egg.test\r\nFrom: Alice <alice@sender.test>\r\nFrom: CEO <ceo@example.com>\r\nSubject: Hi\r\n\r\nbody\r\n");
        Assert.Equal("unauthenticated_local_sender", (await rig.Forwarder.ForwardAsync(notAuthenticated, route, twoFroms, default)).Error);
        byte[] viaGroup = Encoding.UTF8.GetBytes("From: Team: a@sender.test, ceo@example.com;\r\nSubject: Hi\r\n\r\nbody\r\n");
        Assert.Equal("unauthenticated_local_sender", (await rig.Forwarder.ForwardAsync(notAuthenticated, route, viaGroup, default)).Error);
        byte[] display = Encoding.UTF8.GetBytes("From: \"ceo@example.com\" <mallory@sender.test>\r\nSubject: Hi\r\n\r\nbody\r\n");
        Assert.NotNull((await rig.Forwarder.ForwardAsync(notAuthenticated, route, display, default)).ForwardMessageId);   // the domain is sender.test, whatever the name says
        byte[] garbage = Encoding.UTF8.GetBytes("From: <ceo@example.com\r\nSubject: Hi\r\n\r\nbody\r\n");
        Assert.Equal("unauthenticated_local_sender", (await rig.Forwarder.ForwardAsync(notAuthenticated, route, garbage, default)).Error);
    }

    [Fact]
    public async Task The_forward_does_not_depend_on_anything_in_the_message_for_where_it_goes()
    {
        await using Rig rig = await StartAsync(["target@example.org"]);
        byte[] raw = Foreign(extra: "Reply-To: evil@attacker.test\r\nBcc: evil2@attacker.test\r\nResent-To: evil3@attacker.test\r\nX-Forward-To: evil4@attacker.test\r\n");
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(raw);

        await ForwardAsync(rig, draft, raw);

        Assert.Equal(["target@example.org"], (await rig.Harness.Storage.Deliveries.ClaimAsync("t", 10, rig.Harness.Clock.UtcNow, TimeSpan.FromMinutes(1), default)).Select(d => d.Recipient.ToString()));
    }

    [Fact]
    public void The_forward_key_is_per_received_message()
    {
        Guid id = Ids.New();
        Assert.Equal("inbound:" + id.ToString("N"), InboundRules.ForwardKey(id));
    }
}

/// <summary>The SRS recipient of a forwarded message's bounce (design sections 11.4 and 11.7).</summary>
[Collection("inbound-actions")]
public class SrsBounceHandlerTests
{
    private sealed class Log : IMtaLog
    {
        public List<string> Lines { get; } = [];

        public bool IsEnabled(MtaLogLevel level) => true;

        public void Write(MtaLogLevel level, string source, string message, Exception? exception = null) => Lines.Add(message);
    }

    [Fact]
    public void Only_a_fresh_valid_srs_address_from_the_null_sender_is_accepted_and_dropping_logs_no_address()
    {
        var ring = new VerpCodec(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey() }, 1);
        var srs = new ForwardSrs(ring);
        var clock = new Mta.Host.Tests.Api.TestClock(new DateTimeOffset(2026, 10, 16, 8, 0, 0, TimeSpan.Zero));
        var log = new Log();
        var handler = new SrsBounceHandler(srs, clock, log);
        string local = srs.CreateLocalPart("sender.test", "alice", clock.UtcNow);

        Assert.Equal(SrsRecipientDecision.Accept, handler.Check(local, nullSender: true));
        Assert.Equal(SrsRecipientDecision.Reject, handler.Check(local, nullSender: false));   // only a bounce goes to an SRS address
        Assert.Equal(SrsRecipientDecision.Reject, handler.Check("SRS0=aaaaaaaa=aa=sender.test=alice", nullSender: true));
        Assert.Equal(SrsRecipientDecision.Reject, handler.Check("SRS1=" + local[5..], nullSender: true));
        clock.Advance(TimeSpan.FromDays(22));
        Assert.Equal(SrsRecipientDecision.Reject, handler.Check(local, nullSender: true));

        handler.Drop(1234);
        string line = Assert.Single(log.Lines);
        Assert.DoesNotContain("alice", line, StringComparison.Ordinal);
        Assert.DoesNotContain("sender.test", line, StringComparison.Ordinal);
    }
}
