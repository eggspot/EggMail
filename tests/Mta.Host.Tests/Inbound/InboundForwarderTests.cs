using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Mta.Auth.Arc;
using Mta.Core;
using Mta.Dkim;
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

    private static async Task<Rig> StartAsync(string[]? targets = null, string? bounceDomain = "bounces.egg.test", InboundForwarderOptions? options = null, IForwardArcSealerProvider? sealers = null, ArcValidator? validator = null)
    {
        var h = await new InboundActionHarness().InitializeAsync(InboundActionKind.Forward);
        await h.Storage.Inbound.UpsertRouteAsync(h.Route with { ForwardTo = targets ?? ["target@example.org"], UpdatedAt = h.Clock.UtcNow }, default);
        var forwarder = new InboundForwarder(
            h.Storage, new SrsCodec(Ring), new ForwardHopMarker(Ring), validator ?? new ArcValidator(new StaticDnsResolver()), sealers,
            options ?? new InboundForwarderOptions { AuthenticationResultsId = "egg.test", BounceDomain = bounceDomain }, h.Clock, NullMtaLog.Instance);
        return new Rig { Harness = h, Forwarder = forwarder };
    }

    /// <summary>The sum of what the counter <paramref name="instrument"/> recorded while <paramref name="act"/> ran, by the value of its <c>reason</c> tag ("" for none).</summary>
    private static async Task<Dictionary<string, long>> CountedAsync(string instrument, Func<Task> act)
    {
        var counts = new Dictionary<string, long>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (i, l) =>
        {
            if (i.Meter == InboundActionMetrics.Meter && i.Name == instrument)
            {
                l.EnableMeasurementEvents(i);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
        {
            string reason = "";
            foreach (KeyValuePair<string, object?> tag in tags)
            {
                if (tag.Key == "reason")
                {
                    reason = (string?)tag.Value ?? "";
                }
            }

            lock (counts)
            {
                counts[reason] = counts.GetValueOrDefault(reason) + value;
            }
        });
        listener.Start();
        await act();
        return counts;
    }

    /// <summary>A sealer provider for tests: the tenant's domain with a key we hold.</summary>
    private sealed class FixedSealers(ArcSealer sealer) : IForwardArcSealerProvider
    {
        /// <summary>The tenant that owns the domain (known once the rig exists).</summary>
        public Guid TenantId { get; set; }

        public ValueTask<ArcSealer?> GetSealerAsync(Guid tenant, string domain, CancellationToken cancellationToken) =>
            ValueTask.FromResult<ArcSealer?>(tenant == TenantId && domain.Equals("example.com", StringComparison.OrdinalIgnoreCase) ? sealer : null);
    }

    private static string Text(byte[]? raw) => Encoding.UTF8.GetString(raw!);

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
        Assert.Equal(1, new ForwardHopMarker(Ring).ReadValidHops(queued));

        ClaimedDelivery delivery = Assert.Single(await rig.Harness.Storage.Deliveries.ClaimAsync("t", 10, rig.Harness.Clock.UtcNow, TimeSpan.FromMinutes(1), default));
        Assert.Equal(MessageSource.Forward, delivery.Source);
        Assert.Equal("example.com", delivery.SendingDomain);   // the route's domain, never the From domain
        Assert.Equal("target@example.org", delivery.Recipient.ToString());
        string senderLocal = delivery.EnvelopeFrom.LocalPart;
        Assert.EndsWith("@example.com", delivery.EnvelopeFrom.ToString());
        Assert.True(new SrsCodec(Ring).TryVerify(senderLocal, rig.Harness.Clock.UtcNow));
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
        Assert.True(new SrsCodec(Ring).TryVerify(delivery.EnvelopeFrom.LocalPart, rig.Harness.Clock.UtcNow));
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
        var marker = new ForwardHopMarker(Ring);
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
    public async Task A_from_the_receive_path_judged_unusable_is_never_forwarded_and_is_counted_while_a_foreign_from_that_failed_dmarc_still_is()
    {
        await using Rig rig = await StartAsync();
        InboundRouteRecord route = (await rig.Harness.Storage.Inbound.GetRouteAsync(rig.Harness.TenantId, rig.Harness.Route.Id, default))!;
        byte[] ambiguous = Encoding.UTF8.GetBytes("Received: by egg.test\r\nFrom: ceo@example.com <x@evil.test>\r\nSubject: Hi\r\n\r\nbody\r\n");
        byte[] noFrom = Encoding.UTF8.GetBytes("Received: by egg.test\r\nSubject: Hi\r\n\r\nbody\r\n");
        InboundMessage unusable = await rig.Harness.GetAsync((await rig.Harness.ReceiveAsync(ambiguous)).Id);
        unusable = unusable with { Auth = unusable.Auth with { Dmarc = InboundVerdict.PermError, DmarcPolicy = null } };
        InboundMessage foreign = await rig.Harness.GetAsync((await rig.Harness.ReceiveAsync(Foreign())).Id);
        foreign = foreign with { Auth = foreign.Auth with { Dmarc = InboundVerdict.Fail } };

        var results = new List<InboundActionResult>();
        Dictionary<string, long> refused = await CountedAsync("mta.inbound.forward.refused", async () =>
        {
            results.Add(await rig.Forwarder.ForwardAsync(unusable, route, ambiguous, default));
            results.Add(await rig.Forwarder.ForwardAsync(unusable, route, noFrom, default));
            results.Add(await rig.Forwarder.ForwardAsync(foreign, route, Foreign(), default));
        });

        Assert.Equal(("unusable_from", (Guid?)null), (results[0].Error, results[0].ForwardMessageId));
        Assert.Equal("unusable_from", results[1].Error);
        Assert.NotNull(results[2].ForwardMessageId);
        Assert.Equal(2, refused["unusable_from"]);
        Assert.Single(await rig.Harness.Storage.Deliveries.ClaimAsync("t", 10, rig.Harness.Clock.UtcNow, TimeSpan.FromMinutes(1), default));
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

    // ---- review of the forward (backlog caps, key squatting, internal headers, ARC, SRS)

    [Fact]
    public async Task The_loops_and_the_refusals_are_counted_each_with_its_reason()
    {
        await using Rig rig = await StartAsync();
        var marker = new ForwardHopMarker(Ring);
        byte[] looping = marker.Apply(Foreign(), 3);
        InboundMessageDraft loop = await rig.Harness.ReceiveAsync(looping);
        InboundMessageDraft local = await rig.Harness.ReceiveAsync(Foreign());
        InboundMessageDraft spoof = await rig.Harness.ReceiveAsync(Foreign(from: "ceo@example.com"));
        InboundMessage spoofMessage = (await rig.Harness.GetAsync(spoof.Id)) with { Auth = InboundAuthResults.NotChecked };
        InboundRouteRecord route = (await rig.Harness.Storage.Inbound.GetRouteAsync(rig.Harness.TenantId, rig.Harness.Route.Id, default))!;

        Dictionary<string, long> loops = await CountedAsync("mta.inbound.forward.loops", async () => await ForwardAsync(rig, loop, looping));
        Assert.Equal(1, loops[""]);

        Dictionary<string, long> refused = await CountedAsync("mta.inbound.forward.refused", async () =>
        {
            await rig.Forwarder.ForwardAsync(spoofMessage, route, Foreign(from: "ceo@example.com"), default);
            await rig.Harness.Storage.Inbound.UpsertRouteAsync(route with { ForwardTo = ["someone@example.com"], UpdatedAt = rig.Harness.Clock.UtcNow }, default);
            await rig.Forwarder.ForwardAsync(await rig.Harness.GetAsync(local.Id), route with { ForwardTo = ["someone@example.com"] }, Foreign(), default);
        });
        Assert.Equal(1, refused["unauthenticated_local_sender"]);
        Assert.Equal(1, refused["forward_target_is_local"]);
    }

    [Fact]
    public async Task What_a_tenant_may_have_waiting_in_the_outbound_queue_is_capped_and_a_full_backlog_keeps_the_message_for_later()
    {
        await using Rig rig = await StartAsync(options: new InboundForwarderOptions { AuthenticationResultsId = "egg.test", MaxQueuedMessagesPerTenant = 2, MaxQueuedBytesPerTenant = 0, MaxQueuedMessagesPerDomain = 0 });
        for (int i = 0; i < 2; i++)
        {
            InboundMessageDraft draft = await rig.Harness.ReceiveAsync(Foreign());
            Assert.NotNull((await ForwardAsync(rig, draft, Foreign())).ForwardMessageId);
        }

        InboundMessageDraft third = await rig.Harness.ReceiveAsync(Foreign());
        InboundActionResult full = default!;
        Dictionary<string, long> counted = await CountedAsync("mta.inbound.forward.refused", async () => full = await ForwardAsync(rig, third, Foreign()));

        Assert.Equal(InboundActionResult.Kind.Retry, full.Outcome);   // on the ladder, not a failure: the cause passes when the queue drains
        Assert.Equal("forward_backlog_full", full.Error);
        Assert.False(full.FreeBody);
        Assert.Equal(1, counted["forward_backlog_full"]);
        Assert.Equal(2, (await rig.Harness.Storage.Deliveries.ClaimAsync("t", 10, rig.Harness.Clock.UtcNow, TimeSpan.FromMinutes(1), default)).Count);   // nothing more was queued
    }

    [Fact]
    public async Task The_byte_cap_and_the_domain_cap_hold_and_zero_means_no_cap()
    {
        byte[] raw = Foreign(extra: new string('x', 3000) + "\r\n");
        await using (Rig bytes = await StartAsync(options: new InboundForwarderOptions { AuthenticationResultsId = "egg.test", MaxQueuedMessagesPerTenant = 0, MaxQueuedBytesPerTenant = raw.Length * 2 + 500, MaxQueuedMessagesPerDomain = 0 }))
        {
            Assert.NotNull((await ForwardAsync(bytes, await bytes.Harness.ReceiveAsync(raw), raw)).ForwardMessageId);
            Assert.NotNull((await ForwardAsync(bytes, await bytes.Harness.ReceiveAsync(raw), raw)).ForwardMessageId);
            Assert.Equal("forward_backlog_full", (await ForwardAsync(bytes, await bytes.Harness.ReceiveAsync(raw), raw)).Error);   // two copies and the marker lines fill it
        }

        await using (Rig domain = await StartAsync(options: new InboundForwarderOptions { AuthenticationResultsId = "egg.test", MaxQueuedMessagesPerTenant = 0, MaxQueuedBytesPerTenant = 0, MaxQueuedMessagesPerDomain = 1 }))
        {
            Assert.NotNull((await ForwardAsync(domain, await domain.Harness.ReceiveAsync(Foreign()), Foreign())).ForwardMessageId);
            Assert.Equal("forward_backlog_full", (await ForwardAsync(domain, await domain.Harness.ReceiveAsync(Foreign()), Foreign())).Error);
        }

        await using Rig none = await StartAsync(options: new InboundForwarderOptions { AuthenticationResultsId = "egg.test", MaxQueuedMessagesPerTenant = 0, MaxQueuedBytesPerTenant = 0, MaxQueuedMessagesPerDomain = 0 });
        for (int i = 0; i < 5; i++)
        {
            Assert.NotNull((await ForwardAsync(none, await none.Harness.ReceiveAsync(Foreign()), Foreign())).ForwardMessageId);
        }
    }

    [Fact]
    public async Task The_idempotency_key_of_a_forward_is_remembered_for_30_days_and_not_longer()
    {
        Assert.Equal(TimeSpan.FromDays(30), InboundRules.ForwardKeyLifetime);
        await using Rig rig = await StartAsync();
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(Foreign());
        Guid first = (await ForwardAsync(rig, draft, Foreign())).ForwardMessageId!.Value;

        rig.Harness.Clock.Advance(TimeSpan.FromDays(29));
        Assert.Equal(first, (await ForwardAsync(rig, draft, Foreign())).ForwardMessageId);   // still the same copy

        rig.Harness.Clock.Advance(TimeSpan.FromDays(2));
        Guid later = (await ForwardAsync(rig, draft, Foreign())).ForwardMessageId!.Value;
        Assert.NotEqual(first, later);   // the key has expired: it is a new forward (only a retry of an action older than a month can get here)
    }

    [Fact]
    public async Task A_message_that_holds_the_forwards_key_but_is_not_a_forward_of_this_route_is_a_failure_and_the_body_stays()
    {
        await using Rig rig = await StartAsync();
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(Foreign());
        DateTimeOffset now = rig.Harness.Clock.UtcNow;
        // What POST /api/v1/messages with "Idempotency-Key: inbound:<id>" did before the prefix was reserved.
        await rig.Harness.Storage.Intake.AcceptAsync(new AcceptedMessage
        {
            MessageId = Ids.New(now), TenantId = rig.Harness.TenantId, Source = MessageSource.Api, EnvelopeFrom = EmailAddress.Parse("me@example.com"),
            Recipients = [new AcceptedRecipient(Ids.New(now), EmailAddress.Parse("nobody@dest.example"))], Raw = Encoding.ASCII.GetBytes("From: me@example.com\r\n\r\nx\r\n"),
            ReceivedAt = now, ExpiresAt = now.AddDays(1), IdempotencyKey = InboundRules.ForwardKey(draft.Id), SendingDomain = "example.com",
        }, default);

        InboundActionResult result = default!;
        Dictionary<string, long> counted = await CountedAsync("mta.inbound.forward.refused", async () => result = await ForwardAsync(rig, draft, Foreign()));

        Assert.Equal(InboundActionResult.Kind.Failed, result.Outcome);
        Assert.Equal("forward_key_conflict", result.Error);
        Assert.False(result.FreeBody);
        Assert.Null(result.ForwardMessageId);
        Assert.Equal(1, counted["forward_key_conflict"]);
    }

    [Fact]
    public async Task What_the_receive_path_wrote_for_its_own_use_does_not_leave_with_the_copy()
    {
        await using Rig rig = await StartAsync();
        byte[] raw = Encoding.UTF8.GetBytes("X-EggMail-Dmarc: flagged\r\nx-eggmail-reputation: dnsbl=zone.test\r\nReceived: by egg.test\r\nFrom: a@sender.test\r\nX-Other: kept\r\nSubject: s\r\n\r\nbody\r\n");
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(raw);

        InboundActionResult result = await ForwardAsync(rig, draft, raw);

        string queued = Text(await rig.Harness.Storage.Deliveries.GetRawAsync(result.ForwardMessageId!.Value, default));
        Assert.DoesNotContain("X-EggMail-Dmarc", queued, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("X-EggMail-Reputation", queued, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("X-Other: kept", queued, StringComparison.Ordinal);
        Assert.Contains("Received: by egg.test", queued, StringComparison.Ordinal);
        Assert.EndsWith("Received: by egg.test\r\nFrom: a@sender.test\r\nX-Other: kept\r\nSubject: s\r\n\r\nbody\r\n", queued, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_envelope_sender_that_cannot_be_read_fails_the_forward_instead_of_going_out_with_a_null_sender()
    {
        await using Rig rig = await StartAsync();
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(Foreign());
        InboundMessage message = (await rig.Harness.GetAsync(draft.Id)) with { EnvelopeFrom = "this is <not an address" };
        InboundRouteRecord route = (await rig.Harness.Storage.Inbound.GetRouteAsync(rig.Harness.TenantId, rig.Harness.Route.Id, default))!;

        InboundActionResult result = await rig.Forwarder.ForwardAsync(message, route, Foreign(), default);

        Assert.Equal("srs_failed", result.Error);
        Assert.Null(result.ForwardMessageId);
        Assert.Empty(await rig.Harness.Storage.Deliveries.ClaimAsync("t", 10, rig.Harness.Clock.UtcNow, TimeSpan.FromMinutes(1), default));
    }

    [Fact]
    public async Task A_dmarc_result_that_could_not_be_settled_for_the_own_domain_waits_on_the_ladder_instead_of_failing_for_good()
    {
        await using Rig rig = await StartAsync();
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(Foreign(from: "ceo@example.com"));
        InboundMessage message = await rig.Harness.GetAsync(draft.Id);
        InboundRouteRecord route = (await rig.Harness.Storage.Inbound.GetRouteAsync(rig.Harness.TenantId, rig.Harness.Route.Id, default))!;

        InboundActionResult unsettled = await rig.Forwarder.ForwardAsync(message with { Auth = message.Auth with { Dmarc = InboundVerdict.TempError } }, route, Foreign(from: "ceo@example.com"), default);
        Assert.Equal(InboundActionResult.Kind.Retry, unsettled.Outcome);
        Assert.Equal("dmarc_unsettled", unsettled.Error);

        // A foreign From needs no DMARC pass at all, settled or not; a settled failure for the own domain is still final.
        Assert.NotNull((await rig.Forwarder.ForwardAsync(message with { Auth = message.Auth with { Dmarc = InboundVerdict.TempError } }, route, Foreign(), default)).ForwardMessageId);
        InboundActionResult failed = await rig.Forwarder.ForwardAsync(message with { Auth = message.Auth with { Dmarc = InboundVerdict.Fail } }, route, Foreign(from: "ceo@example.com"), default);
        Assert.Equal(InboundActionResult.Kind.Failed, failed.Outcome);
    }

    // ---- ARC

    private sealed class ArcRig : IDisposable
    {
        public ArcRig(TimeSpan? timeout = null, IDnsResolver? dns = null)
        {
            Key = DkimKeyTools.GenerateRsa2048();
            Dns = new StaticDnsResolver().AddTxt("s1._domainkey.example.com", DkimKeyTools.FormatDnsTxtValue(Key));
            Sealer = new ArcSealer(new ArcSealerOptions { Domain = "example.com", Selector = "s1" }, Key);
            Sealers = new FixedSealers(Sealer);
            Validator = new ArcValidator(dns ?? Dns, new ArcValidatorOptions { MaxInstances = 10 });
            Timeout = timeout ?? TimeSpan.FromSeconds(5);
        }

        public RSA Key { get; }
        public StaticDnsResolver Dns { get; }
        public ArcSealer Sealer { get; }
        public FixedSealers Sealers { get; }
        public ArcValidator Validator { get; }
        public TimeSpan Timeout { get; }

        public void Dispose()
        {
            Sealer.Dispose();
            Key.Dispose();
        }
    }

    private static string[] ArcSeals(string message) => Regex.Matches(message, @"(?im)^ARC-Seal:(?:[^\r\n]|\r\n[ \t])*").Select(m => Regex.Replace(m.Value, @"\s+", " ")).ToArray();

    [Fact]
    public async Task The_arc_set_records_our_own_authentication_results_and_nothing_a_sender_wrote()
    {
        using var arc = new ArcRig();
        await using Rig rig = await StartAsync(sealers: arc.Sealers, validator: arc.Validator);
        arc.Sealers.TenantId = rig.Harness.TenantId;
        // Another host's results, a forged one claiming a pass, and the real one written by this server.
        byte[] raw = Encoding.UTF8.GetBytes(
            "Authentication-Results: other.example; dmarc=pass header.from=sender.test\r\n" +
            "Authentication-Results: egg.test; spf=softfail smtp.mailfrom=sender.test; dkim=none; dmarc=fail header.from=sender.test\r\n" +
            "From: a@sender.test\r\nSubject: s\r\n\r\nbody\r\n");
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(raw);

        InboundActionResult result = await ForwardAsync(rig, draft, raw);

        string queued = Text(await rig.Harness.Storage.Deliveries.GetRawAsync(result.ForwardMessageId!.Value, default));
        string aar = Regex.Replace(Regex.Match(queued, @"(?im)^ARC-Authentication-Results:(?:[^\r\n]|\r\n[ \t])*").Value, @"\s+", " ");
        Assert.Contains("egg.test;", aar, StringComparison.Ordinal);
        Assert.Contains("dmarc=fail", aar, StringComparison.Ordinal);
        Assert.DoesNotContain("other.example", aar, StringComparison.Ordinal);
        Assert.DoesNotContain("dmarc=pass", aar, StringComparison.Ordinal);
        Assert.Contains("d=example.com", Regex.Replace(queued, @"\s+", ""), StringComparison.Ordinal);   // sealed with the route domain's key
    }

    [Fact]
    public async Task Without_authentication_results_of_ours_the_arc_set_is_built_from_the_verdicts_not_from_a_header_of_the_sender()
    {
        using var arc = new ArcRig();
        await using Rig rig = await StartAsync(sealers: arc.Sealers, validator: arc.Validator);
        arc.Sealers.TenantId = rig.Harness.TenantId;
        byte[] raw = Encoding.UTF8.GetBytes("Authentication-Results: EGG.TEST.evil.example; dmarc=pass\r\nFrom: a@sender.test\r\nSubject: s\r\n\r\nbody\r\n");
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(raw);
        InboundMessage message = (await rig.Harness.GetAsync(draft.Id)) with { Auth = new InboundAuthResults(InboundVerdict.Fail, "sender.test", InboundVerdict.None, InboundVerdict.None, null, InboundVerdict.Fail, "none", InboundVerdict.None) };
        InboundRouteRecord route = (await rig.Harness.Storage.Inbound.GetRouteAsync(rig.Harness.TenantId, rig.Harness.Route.Id, default))!;

        InboundActionResult result = await rig.Forwarder.ForwardAsync(message, route, raw, default);

        string queued = Regex.Replace(Text(await rig.Harness.Storage.Deliveries.GetRawAsync(result.ForwardMessageId!.Value, default)), @"\s+", " ");
        string aar = Regex.Match(queued, @"ARC-Authentication-Results:[^:]*?(?= [A-Z][A-Za-z-]+:)").Value;
        Assert.Contains("egg.test; spf=fail", aar, StringComparison.Ordinal);
        Assert.Contains("dmarc=fail", aar, StringComparison.Ordinal);
        Assert.DoesNotContain("evil.example; dmarc=pass", aar, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_chain_whose_newest_seal_already_says_cv_fail_is_not_sealed_over_and_the_message_still_goes()
    {
        using var arc = new ArcRig();
        await using Rig rig = await StartAsync(sealers: arc.Sealers, validator: arc.Validator);
        arc.Sealers.TenantId = rig.Harness.TenantId;
        // Another hop broke the chain and said so with a cv=fail seal.
        byte[] plain = Encoding.UTF8.GetBytes("From: a@sender.test\r\nSubject: s\r\n\r\nbody\r\n");
        using var other = DkimKeyTools.GenerateRsa2048();
        using var otherSealer = new ArcSealer(new ArcSealerOptions { Domain = "relay.test", Selector = "r1" }, other);
        ArcSealResult broken = otherSealer.Seal(plain, "relay.test; spf=pass", new ArcChainResult(ArcChainStatus.Fail, "broken earlier", ArcFailure.SealMismatch));
        Assert.True(broken.IsSealed);
        byte[] raw = [.. broken.HeaderBytes.ToArray(), .. plain];
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(raw);

        InboundActionResult result = await ForwardAsync(rig, draft, raw);

        Assert.NotNull(result.ForwardMessageId);
        string queued = Text(await rig.Harness.Storage.Deliveries.GetRawAsync(result.ForwardMessageId!.Value, default));
        Assert.Single(ArcSeals(queued));   // the relay's seal only: nothing of ours was added over a failed chain
        Assert.DoesNotContain("d=example.com", Regex.Replace(queued, @"\s+", ""), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_chain_of_more_than_ten_sets_is_not_vouched_for_it_is_sealed_over_as_cv_fail()
    {
        using var arc = new ArcRig();
        // Eleven hops that each validated the one before: a real chain, longer than the forwarder accepts.
        var longDns = new StaticDnsResolver().AddTxt("s1._domainkey.example.com", DkimKeyTools.FormatDnsTxtValue(arc.Key));
        var builder = new ArcValidator(longDns);
        byte[] message = Encoding.UTF8.GetBytes("From: a@sender.test\r\nSubject: s\r\n\r\nbody\r\n");
        for (int i = 0; i < 11; i++)
        {
            ArcChainResult chain = await builder.ValidateAsync(message, default);
            ArcSealResult sealed1 = arc.Sealer.Seal(message, "relay.test; spf=pass", chain);
            Assert.True(sealed1.IsSealed);
            message = [.. sealed1.HeaderBytes.ToArray(), .. message];
        }

        await using Rig rig = await StartAsync(sealers: arc.Sealers, validator: new ArcValidator(longDns, new ArcValidatorOptions { MaxInstances = 10 }));
        arc.Sealers.TenantId = rig.Harness.TenantId;
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(message);

        InboundActionResult result = await ForwardAsync(rig, draft, message);

        Assert.NotNull(result.ForwardMessageId);
        string[] seals = ArcSeals(Text(await rig.Harness.Storage.Deliveries.GetRawAsync(result.ForwardMessageId!.Value, default)));
        Assert.Equal(12, seals.Length);
        Assert.Contains("i=12;", seals[0], StringComparison.Ordinal);
        Assert.Contains("cv=fail", seals[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_chain_that_cannot_be_validated_in_time_costs_the_runner_slot_only_the_time_limit_and_is_sealed_over_as_cv_fail()
    {
        using var arc = new ArcRig();
        byte[] plain = Encoding.UTF8.GetBytes("From: a@sender.test\r\nSubject: s\r\n\r\nbody\r\n");
        ArcSealResult first = arc.Sealer.Seal(plain, "relay.test; spf=pass", new ArcChainResult(ArcChainStatus.None, "none"));
        byte[] raw = [.. first.HeaderBytes.ToArray(), .. plain];
        var hanging = new HangingResolver();
        await using Rig rig = await StartAsync(
            options: new InboundForwarderOptions { AuthenticationResultsId = "egg.test", ArcValidationTimeout = TimeSpan.FromMilliseconds(200) },
            sealers: arc.Sealers, validator: new ArcValidator(hanging, new ArcValidatorOptions { MaxInstances = 10 }));
        arc.Sealers.TenantId = rig.Harness.TenantId;
        InboundMessageDraft draft = await rig.Harness.ReceiveAsync(raw);

        InboundActionResult result = await ForwardAsync(rig, draft, raw).WaitAsync(TimeSpan.FromSeconds(30));

        Assert.True(hanging.Asked > 0, "the validator never looked up a key");
        Assert.NotNull(result.ForwardMessageId);
        string[] seals = ArcSeals(Text(await rig.Harness.Storage.Deliveries.GetRawAsync(result.ForwardMessageId!.Value, default)));
        Assert.Contains("cv=fail", seals[0], StringComparison.Ordinal);
        Assert.Contains("i=2;", seals[0], StringComparison.Ordinal);
    }

    /// <summary>A resolver that never answers until it is cancelled (a name server that does not respond).</summary>
    private sealed class HangingResolver : IDnsResolver
    {
        private int _asked;

        public int Asked => Volatile.Read(ref _asked);

        public async ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _asked);
            await Task.Delay(Timeout.Infinite, cancellationToken);
            throw new InvalidOperationException("unreachable");
        }
    }

    [Fact]
    public async Task A_sealer_is_only_ever_taken_from_the_tenant_that_owns_the_domain()
    {
        await using Rig rig = await StartAsync();
        using var rsa = DkimKeyTools.GenerateRsa2048();
        var protector = new PlainProtector();
        DomainRecord domain = (await rig.Harness.Storage.Config.FindDomainByNameAsync("example.com", default))!;
        await rig.Harness.Storage.Config.AddDkimKeyAsync(new Mta.Storage.DkimKeyRecord(Ids.New(), domain.Id, "s1", protector.Protect(rsa.ExportPkcs8PrivateKey(), SecretPurposes.DkimKey), DkimKeyTools.ExportPublicKeyBase64(rsa), rig.Harness.Clock.UtcNow, true, null), default);
        using var provider = new ConfigArcSealerProvider(rig.Harness.Storage.Config, protector, rig.Harness.Clock);

        Assert.NotNull(await provider.GetSealerAsync(rig.Harness.TenantId, "example.com", default));
        Assert.NotNull(await provider.GetSealerAsync(rig.Harness.TenantId, "EXAMPLE.com.", default));
        Assert.Null(await provider.GetSealerAsync(Ids.New(), "example.com", default));   // another tenant's message with a route in this domain name: no key of ours on it
        Assert.Null(await provider.GetSealerAsync(rig.Harness.TenantId, "sub.example.com", default));   // a parent's key never signs a sub-domain
    }

    [Fact]
    public void The_forward_key_is_per_received_message()
    {
        Guid id = Ids.New();
        Assert.Equal("inbound:" + id.ToString("N"), InboundRules.ForwardKey(id));
    }
}
