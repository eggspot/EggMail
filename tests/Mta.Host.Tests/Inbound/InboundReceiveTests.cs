using Mta.Storage;
using Mta.Storage.Logic;

namespace Mta.Host.Tests.Inbound;

/// <summary>Recipients, routes and storage of the inbound receive path against a real listener and the in-memory store (design section 11.4).</summary>
public class InboundReceiveTests : IAsyncLifetime
{
    private InboundFixture _f = null!;

    public async Task InitializeAsync() => _f = await InboundFixture.CreateAsync();

    public async Task DisposeAsync() => await _f.DisposeAsync();

    [Fact]
    public async Task A_message_for_a_routed_recipient_is_stored_with_its_verdicts_headers_and_route()
    {
        _f.PublishSpf("sender.test");
        await using FakeMta mta = await _f.ConnectedAsync("mail.sender.test");

        var reply = await mta.SendAsync("bob@sender.test", "Support@Example.ORG", InboundFixture.Message(subject: "Invoice =?utf-8?Q?caf=C3=A9?="));

        Assert.Equal(250, reply.Code);
        InboundMessage m = Assert.Single(await _f.StoredAsync(InboundFixture.Acme));
        Assert.Equal("support@example.org", m.EnvelopeTo);
        Assert.Equal("bob@sender.test", m.EnvelopeFrom);
        Assert.Equal("example.org", m.Domain);
        Assert.Equal(_f.ExampleOrg, m.DomainId);
        Assert.Equal(InboundActionKind.Store, m.ActionKind);
        Assert.Equal(InboundActionState.Done, m.ActionState);
        Assert.NotNull(m.RouteId);
        Assert.Equal("203.0.113.9", m.RemoteAddress);
        Assert.Equal("mail.sender.test", m.Helo);
        Assert.False(m.TlsUsed);
        Assert.Equal("Invoice café", m.Subject);
        Assert.Equal(InboundVerdict.Pass, m.Auth.Spf);
        Assert.Equal("sender.test", m.Auth.SpfDomain);
        Assert.Equal(InboundVerdict.None, m.Auth.Dkim);
        Assert.Equal(InboundVerdict.None, m.Auth.Dmarc);
        Assert.Equal(InboundVerdict.None, m.Auth.Arc);
        Assert.Equal(InboundDmarcDisposition.None, m.Disposition);

        string raw = await _f.RawAsync(m);
        Assert.StartsWith("Received: from mail.sender.test ([127.0.0.1])", raw);   // the trace header shows the connection; the verdicts used the client address the fixture chose
        Assert.Contains("for <Support@example.org>", raw);   // exactly one recipient: the clause is allowed
        Assert.Contains("\r\nAuthentication-Results: mx.egg.test;", raw);
        Assert.Contains("spf=pass", raw);
        Assert.Contains("smtp.mailfrom=bob@sender.test", raw);
        Assert.Contains("smtp.helo=mail.sender.test", raw);
        Assert.Contains("dkim=none", raw);
        Assert.Contains("arc=none", raw);
        Assert.True(raw.IndexOf("Received:", StringComparison.Ordinal) < raw.IndexOf("Authentication-Results:", StringComparison.Ordinal));
        Assert.EndsWith("Hi there.\r\n", raw);
        Assert.True(_f.Accepted >= 1);
    }

    [Fact]
    public async Task The_domain_and_the_local_part_are_matched_ignoring_case_and_the_reply_to_the_message_is_a_plain_acceptance()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        var reply = await mta.SendAsync("bob@sender.test", "SUPPORT@EXAMPLE.ORG", InboundFixture.Message());
        Assert.Equal(250, reply.Code);
        Assert.Equal("2.0.0 Accepted", reply.Text);   // no internal ids in the reply
    }

    [Fact]
    public async Task Unknown_domains_and_registered_domains_without_inbound_are_refused_at_rcpt_with_nothing_stored()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);

        foreach (string stranger in new[] { "someone@gmail.com", "x@unknown.example", "x@registered-only.example", "x@sub.example.org", "x@example.org.evil.test" })
        {
            var r = await mta.RcptAsync(stranger);
            Assert.Equal((550, "5.7.1"), (r.Code, r.Enhanced));
            Assert.Contains("Relaying denied", r.Text);
        }

        Assert.Empty(await _f.StoredAsync(InboundFixture.Acme));
        Assert.Empty(await _f.StoredAsync(InboundFixture.Globex));
    }

    [Fact]
    public async Task An_enabled_domain_without_a_matching_route_is_550_5_1_1_and_a_disabled_route_does_not_match()
    {
        Guid disabled = await _f.AddRouteAsync(_f.ExampleOrg, InboundFixture.Acme, 5, InboundMatchKind.Address, "closed", InboundActionKind.Store, enabled: false);
        await _f.RefreshConfigAsync();
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);

        var nobody = await mta.RcptAsync("nobody@example.org");
        Assert.Equal((550, "5.1.1"), (nobody.Code, nobody.Enhanced));
        var closed = await mta.RcptAsync("closed@example.org");
        Assert.Equal((550, "5.1.1"), (closed.Code, closed.Enhanced));
        Assert.NotEqual(Guid.Empty, disabled);
    }

    [Fact]
    public async Task Postmaster_is_accepted_without_a_route_and_stored_with_the_store_action_and_no_route_id()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        var reply = await mta.SendAsync("bob@sender.test", "Postmaster@example.org", InboundFixture.Message(to: "postmaster@example.org"));

        Assert.Equal(250, reply.Code);
        InboundMessage m = Assert.Single(await _f.StoredAsync(InboundFixture.Acme));
        Assert.Equal("postmaster@example.org", m.EnvelopeTo);
        Assert.Null(m.RouteId);
        Assert.Equal(InboundActionKind.Store, m.ActionKind);
        Assert.Equal(InboundActionState.Done, m.ActionState);
        Assert.True(m.HasRaw);
    }

    [Fact]
    public async Task An_explicit_route_for_postmaster_wins_over_the_implicit_delivery()
    {
        Guid route = await _f.AddRouteAsync(_f.ExampleOrg, InboundFixture.Acme, 1, InboundMatchKind.Address, "postmaster", InboundActionKind.Discard);
        await _f.RefreshConfigAsync();
        await using FakeMta mta = await _f.ConnectedAsync();

        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "postmaster@example.org", InboundFixture.Message())).Code);

        InboundMessage m = Assert.Single(await _f.StoredAsync(InboundFixture.Acme));
        Assert.Equal(route, m.RouteId);
        Assert.Equal(InboundActionKind.Discard, m.ActionKind);
        Assert.False(m.HasRaw);
    }

    [Fact]
    public async Task The_first_matching_route_decides_the_action_wildcards_and_plus_addressing_included()
    {
        Guid plusRoute = await _f.AddRouteAsync(_f.ExampleOrg, InboundFixture.Acme, 40, InboundMatchKind.Address, "sales", InboundActionKind.Store, plus: true);
        await _f.RefreshConfigAsync();
        await using FakeMta mta = await _f.ConnectedAsync();

        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "billing-2026@example.org", InboundFixture.Message())).Code);
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "sales+promo@example.org", InboundFixture.Message())).Code);
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "old@example.org", InboundFixture.Message())).Code);

        IReadOnlyList<InboundMessage> stored = await _f.StoredAsync(InboundFixture.Acme);
        InboundMessage forward = Assert.Single(stored, m => m.EnvelopeTo == "billing-2026@example.org");
        Assert.Equal((InboundActionKind.Forward, InboundActionState.Pending, _f.ForwardRouteId), (forward.ActionKind, forward.ActionState, forward.RouteId));
        Assert.Equal(plusRoute, Assert.Single(stored, m => m.EnvelopeTo == "sales+promo@example.org").RouteId);
        InboundMessage discarded = Assert.Single(stored, m => m.EnvelopeTo == "old@example.org");
        Assert.Equal((InboundActionKind.Discard, InboundActionState.Done, false), (discarded.ActionKind, discarded.ActionState, discarded.HasRaw));
    }

    [Fact]
    public async Task A_domain_that_is_not_verified_or_a_suspended_tenant_gets_450_not_550()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);

        var pending = await mta.RcptAsync("anyone@pending.example");
        Assert.Equal((450, "4.2.1"), (pending.Code, pending.Enhanced));
        var suspended = await mta.RcptAsync("anyone@suspended.example");
        Assert.Equal((450, "4.2.1"), (suspended.Code, suspended.Enhanced));

        // temporary_failure keeps receiving, as it keeps sending.
        await _f.Storage.Config.UpsertDomainAsync(new DomainRecord(_f.PendingDomain, InboundFixture.Acme, "pending.example", DomainStatus.TemporaryFailure, null, false, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, 0, null, false, null), default);
        await _f.RefreshConfigAsync();
        Assert.Equal(250, (await mta.RcptAsync("anyone@pending.example")).Code);
    }

    [Fact]
    public async Task The_null_sender_is_accepted_for_an_inbound_recipient()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.SendAsync("", "support@example.org", InboundFixture.Message(from: "MAILER-DAEMON@sender.test"))).Code);
        Assert.Equal("", Assert.Single(await _f.StoredAsync(InboundFixture.Acme)).EnvelopeFrom);
    }

    [Fact]
    public async Task One_transaction_for_recipients_of_two_tenants_stores_a_separate_row_and_body_for_each_and_names_no_recipient_in_the_received_header()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        Assert.Equal(250, (await mta.RcptAsync("anyone@example.net")).Code);
        Assert.Equal(250, (await mta.RcptAsync("SUPPORT@example.org")).Code);   // the same address twice is one delivery
        Assert.Equal(250, (await mta.DataAsync(InboundFixture.Message())).Code);

        InboundMessage acme = Assert.Single(await _f.StoredAsync(InboundFixture.Acme));
        InboundMessage globex = Assert.Single(await _f.StoredAsync(InboundFixture.Globex));
        Assert.NotEqual(acme.Id, globex.Id);
        Assert.Equal("anyone@example.net", globex.EnvelopeTo);
        string acmeRaw = await _f.RawAsync(acme);
        string globexRaw = await _f.RawAsync(globex);
        Assert.DoesNotContain("for <", acmeRaw.Split("\r\n\r\n")[0], StringComparison.Ordinal);
        Assert.DoesNotContain("example.net", acmeRaw.Split("\r\n\r\n")[0].Split("Authentication-Results")[0], StringComparison.Ordinal);
        Assert.Equal(acmeRaw, globexRaw);   // same stamped bytes here (no per-domain difference), still two bodies in the store
    }

    [Fact]
    public async Task A_second_message_on_the_same_connection_does_not_see_the_recipients_of_the_first()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message(subject: "first"))).Code);
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "anyone@example.net", InboundFixture.Message(subject: "second"))).Code);

        Assert.Equal("first", Assert.Single(await _f.StoredAsync(InboundFixture.Acme)).Subject);
        Assert.Equal("second", Assert.Single(await _f.StoredAsync(InboundFixture.Globex)).Subject);
        await mta.QuitAsync();
    }

    [Fact]
    public async Task A_configuration_that_was_never_loaded_or_is_too_old_answers_451_never_unknown_domain()
    {
        await using InboundFixture cold = await InboundFixture.CreateAsync(loadConfiguration: false);
        await using (FakeMta mta = await cold.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
            var r = await mta.RcptAsync("support@example.org");
            Assert.Equal((451, "4.3.0"), (r.Code, r.Enhanced));
        }

        await cold.RefreshConfigAsync();
        await using (FakeMta mta = await cold.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message())).Code);
        }

        cold.Clock.Advance(TimeSpan.FromMinutes(6));   // the refreshes stopped: do not decide on data this old
        await using (FakeMta mta = await cold.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
            Assert.Equal(451, (await mta.RcptAsync("support@example.org")).Code);
        }
    }

    [Fact]
    public async Task A_change_of_the_routes_is_seen_after_the_next_refresh()
    {
        await using FakeMta mta = await _f.ConnectedAsync();
        Assert.Equal(550, (await mta.SendAsync("bob@sender.test", "new@example.org", InboundFixture.Message())).Code);
        await mta.CommandAsync("RSET");
        await _f.AddRouteAsync(_f.ExampleOrg, InboundFixture.Acme, 50, InboundMatchKind.Address, "new", InboundActionKind.Store);
        Assert.Equal(550, (await mta.SendAsync("bob@sender.test", "new@example.org", InboundFixture.Message())).Code);   // cached
        await mta.CommandAsync("RSET");
        _f.Config.RequestRefresh();
        await _f.RefreshConfigAsync();
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "new@example.org", InboundFixture.Message())).Code);
    }

    [Fact]
    public async Task The_storage_failing_gives_451_and_a_full_disk_452_and_nothing_is_stored()
    {
        await using InboundFixture failing = await InboundFixture.CreateAsync(wrapStore: s => new FailingStore(s, new InvalidOperationException("boom")));
        await using (FakeMta mta = await failing.ConnectedAsync())
        {
            var r = await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message());
            Assert.Equal((451, "4.3.0"), (r.Code, r.Enhanced));
        }

        await using InboundFixture full = await InboundFixture.CreateAsync(wrapStore: s => new FailingStore(s, new StorageFullException("disk full")));
        await using (FakeMta mta = await full.ConnectedAsync())
        {
            var r = await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message());
            Assert.Equal((452, "4.3.1"), (r.Code, r.Enhanced));
        }

        Assert.Empty(await failing.StoredAsync(InboundFixture.Acme));
    }

    /// <summary>An inbound store whose writes fail, for the replies to a storage problem.</summary>
    private sealed class FailingStore(IInboundStore inner, Exception failure) : IInboundStore
    {
        public ValueTask AcceptAsync(IReadOnlyList<InboundMessageDraft> drafts, CancellationToken cancellationToken) => throw failure;
        public ValueTask<InboundDomainSettings?> GetSettingsAsync(Guid domainId, CancellationToken cancellationToken) => inner.GetSettingsAsync(domainId, cancellationToken);
        public ValueTask UpsertSettingsAsync(InboundDomainSettings settings, CancellationToken cancellationToken) => inner.UpsertSettingsAsync(settings, cancellationToken);
        public ValueTask<IReadOnlyList<InboundRouteRecord>> GetRoutesAsync(Guid domainId, CancellationToken cancellationToken) => inner.GetRoutesAsync(domainId, cancellationToken);
        public ValueTask<InboundRouteRecord?> GetRouteAsync(Guid tenantId, Guid routeId, CancellationToken cancellationToken) => inner.GetRouteAsync(tenantId, routeId, cancellationToken);
        public ValueTask UpsertRouteAsync(InboundRouteRecord route, CancellationToken cancellationToken) => inner.UpsertRouteAsync(route, cancellationToken);
        public ValueTask<bool> DeleteRouteAsync(Guid tenantId, Guid routeId, CancellationToken cancellationToken) => inner.DeleteRouteAsync(tenantId, routeId, cancellationToken);
        public ValueTask<IReadOnlyList<InboundRouteRecord>> GetRoutesUsingWebhookEndpointAsync(Guid endpointId, CancellationToken cancellationToken) => inner.GetRoutesUsingWebhookEndpointAsync(endpointId, cancellationToken);
        public ValueTask<IReadOnlyList<InboundDomainConfiguration>> LoadEnabledDomainsAsync(CancellationToken cancellationToken) => inner.LoadEnabledDomainsAsync(cancellationToken);
        public ValueTask<Page<InboundMessage>> SearchAsync(InboundMessageQuery query, CancellationToken cancellationToken) => inner.SearchAsync(query, cancellationToken);
        public ValueTask<InboundMessage?> GetAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken) => inner.GetAsync(tenantId, messageId, cancellationToken);
        public ValueTask<byte[]?> GetRawAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken) => inner.GetRawAsync(tenantId, messageId, cancellationToken);
        public ValueTask<bool> DeleteAsync(Guid tenantId, Guid messageId, CancellationToken cancellationToken) => inner.DeleteAsync(tenantId, messageId, cancellationToken);
        public ValueTask<long> DeleteMatchingAsync(InboundMessageQuery query, CancellationToken cancellationToken) => inner.DeleteMatchingAsync(query, cancellationToken);
        public ValueTask<InboundRetryResult> RetryActionAsync(Guid tenantId, Guid messageId, DateTimeOffset now, CancellationToken cancellationToken) => inner.RetryActionAsync(tenantId, messageId, now, cancellationToken);
        public ValueTask<IReadOnlyList<ClaimedInboundAction>> ClaimActionsAsync(string owner, int max, DateTimeOffset now, TimeSpan lease, CancellationToken cancellationToken, InboundClaimLimits? limits = null) => inner.ClaimActionsAsync(owner, max, now, lease, cancellationToken, limits);
        public ValueTask<long> CountActionsAsync(InboundActionState state, CancellationToken cancellationToken) => inner.CountActionsAsync(state, cancellationToken);
        public ValueTask<ForwardBacklog> GetForwardBacklogAsync(Guid tenantId, string sendingDomain, CancellationToken cancellationToken) => inner.GetForwardBacklogAsync(tenantId, sendingDomain, cancellationToken);
        public ValueTask<bool> ExtendActionLeaseAsync(Guid messageId, string owner, DateTimeOffset until, CancellationToken cancellationToken) => inner.ExtendActionLeaseAsync(messageId, owner, until, cancellationToken);
        public ValueTask<bool> CompleteActionAsync(Guid messageId, string owner, InboundActionOutcome outcome, CancellationToken cancellationToken) => inner.CompleteActionAsync(messageId, owner, outcome, cancellationToken);
        public ValueTask<int> ReleaseOwnedActionLeasesAsync(string owner, CancellationToken cancellationToken) => inner.ReleaseOwnedActionLeasesAsync(owner, cancellationToken);
        public ValueTask<InboundUsage> GetUsageAsync(Guid? tenantId, Guid? domainId, CancellationToken cancellationToken) => inner.GetUsageAsync(tenantId, domainId, cancellationToken);
    }
}
