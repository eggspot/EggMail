using Mta.Core;

namespace Mta.Storage.Tests;

/// <summary>
/// Inbound mail (<see cref="IStorage.Inbound"/>, decision 95): per-domain settings and routes, received messages, route action claims and the retention job.
/// Identical on every backend and in both history modes; the backends' own tests cover restarts, the schema upgrade and the backend switch.
/// </summary>
public abstract class InboundConformance : StorageTestBase
{
    private const string Owner = "worker-1";

    private IInboundStore Inbound => Storage.Inbound;

    // Builders

    private async Task<DomainRecord> AddDomainAsync(Guid tenant, string name, DomainStatus status = DomainStatus.Verified, bool tenantEnabled = true)
    {
        if (await Storage.Config.GetTenantAsync(tenant, default) is null)
        {
            await Storage.Config.UpsertTenantAsync(new Tenant(tenant, "Tenant " + tenant.ToString("N")[..4], "t" + tenant.ToString("N")[..8], tenantEnabled, Clock.UtcNow, false), default);
        }

        var domain = new DomainRecord(Ids.New(), tenant, name, status, null, false, Clock.UtcNow, null, null, 0, null, false, null);
        await Storage.Config.UpsertDomainAsync(domain, default);
        return domain;
    }

    private InboundDomainSettings Settings(DomainRecord domain, bool enabled = true, InboundDmarcAction action = InboundDmarcAction.RecordOnly, int? retentionDays = null, long? maxStored = null) =>
        new(domain.Id, domain.TenantId, enabled, action, null, null, null, maxStored, retentionDays, Clock.UtcNow);

    private InboundRouteRecord Route(DomainRecord domain, string name = "r", int order = 100, bool enabled = true, InboundMatchKind kind = InboundMatchKind.CatchAll, string? local = null,
        bool plus = false, InboundActionKind action = InboundActionKind.Store, Guid? endpoint = null, string[]? forward = null, Guid? id = null) =>
        new(id ?? Ids.New(), domain.TenantId, domain.Id, name, order, enabled, kind, local, plus, action, endpoint, InboundWebhookFormat.Json, forward ?? [], Clock.UtcNow, Clock.UtcNow);

    private InboundMessageDraft Draft(DomainRecord domain, Guid routeId, InboundActionKind kind = InboundActionKind.Webhook, string to = "Support@Example.com", string from = "Alice@Sender.Test",
        string? subject = "Hello", int size = 1500, DateTimeOffset? at = null, InboundAuthResults? auth = null, InboundDmarcDisposition disposition = InboundDmarcDisposition.None, Guid? id = null)
    {
        DateTimeOffset received = at ?? Clock.UtcNow;
        byte[] raw = new byte[size];
        new Random(size).NextBytes(raw);
        return new InboundMessageDraft
        {
            Id = id ?? Ids.New(received),
            TenantId = domain.TenantId,
            DomainId = domain.Id,
            Domain = domain.Name,
            ReceivedAt = received,
            RemoteAddress = "203.0.113.9",
            Helo = "mail.sender.test",
            TlsUsed = true,
            EnvelopeFrom = from,
            EnvelopeTo = to,
            Subject = subject,
            Auth = auth ?? new InboundAuthResults(InboundVerdict.Pass, "sender.test", InboundVerdict.None, InboundVerdict.Pass, "sender.test", InboundVerdict.Pass, "reject", InboundVerdict.None),
            Disposition = disposition,
            RouteId = routeId,
            ActionKind = kind,
            Raw = raw,
        };
    }

    private async Task<InboundMessageDraft> StoreAsync(InboundMessageDraft draft)
    {
        await Inbound.AcceptAsync([draft], default);
        return draft;
    }

    private Task<IReadOnlyList<ClaimedInboundAction>> ClaimActionsAsync(int max = 10, TimeSpan? lease = null, string owner = Owner, DateTimeOffset? now = null) =>
        Inbound.ClaimActionsAsync(owner, max, now ?? Clock.UtcNow, lease ?? TimeSpan.FromMinutes(1), default).AsTask();

    // Settings

    [Fact]
    public async Task A_domain_without_settings_has_none_and_settings_are_stored_and_replaced()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        Assert.Null(await Inbound.GetSettingsAsync(domain.Id, default));

        var first = new InboundDomainSettings(domain.Id, TenantA, true, InboundDmarcAction.Flag, 5_000_000, 100, 10, 1L << 30, 30, Clock.UtcNow);
        await Inbound.UpsertSettingsAsync(first, default);
        Assert.Equal(first, await Inbound.GetSettingsAsync(domain.Id, default));

        Clock.Advance(TimeSpan.FromMinutes(5));
        var second = first with { Enabled = false, DmarcAction = InboundDmarcAction.Reject, MaxMessageBytes = null, RetentionDays = 0, UpdatedAt = Clock.UtcNow };
        await Inbound.UpsertSettingsAsync(second, default);
        Assert.Equal(second, await Inbound.GetSettingsAsync(domain.Id, default));
    }

    [Fact]
    public async Task Settings_and_routes_need_a_domain_of_the_same_tenant()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        await Assert.ThrowsAsync<StorageConflictException>(async () => await Inbound.UpsertSettingsAsync(Settings(domain) with { DomainId = Ids.New() }, default));
        await Assert.ThrowsAsync<StorageConflictException>(async () => await Inbound.UpsertSettingsAsync(Settings(domain) with { TenantId = TenantB }, default));
        await Assert.ThrowsAsync<StorageConflictException>(async () => await Inbound.UpsertRouteAsync(Route(domain) with { TenantId = TenantB }, default));
        await Assert.ThrowsAsync<StorageConflictException>(async () => await Inbound.UpsertRouteAsync(Route(domain) with { DomainId = Ids.New() }, default));

        // A route id belongs to one tenant and domain.
        DomainRecord other = await AddDomainAsync(TenantB, "example.net");
        InboundRouteRecord route = Route(domain);
        await Inbound.UpsertRouteAsync(route, default);
        await Assert.ThrowsAsync<StorageConflictException>(async () => await Inbound.UpsertRouteAsync(Route(other, id: route.Id), default));
        Assert.Equal(route, await Inbound.GetRouteAsync(TenantA, route.Id, default));
    }

    // Routes

    [Fact]
    public async Task Routes_are_listed_in_evaluation_order_and_read_back_exactly()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        Guid endpoint = await AddEndpointAsync(TenantA, true, "*");
        Guid low = Guid.Parse("00000000-0000-7000-8000-00000000000a");
        Guid high = Guid.Parse("00000000-0000-7000-8000-00000000000b");
        InboundRouteRecord catchAll = Route(domain, "catch-all", 1000, kind: InboundMatchKind.CatchAll, action: InboundActionKind.Discard);
        InboundRouteRecord hook = Route(domain, "hook", 20, kind: InboundMatchKind.Wildcard, local: "billing-*", plus: true, action: InboundActionKind.Webhook, endpoint: endpoint) with { WebhookFormat = InboundWebhookFormat.RawMime };
        InboundRouteRecord fwdHigh = Route(domain, "fwd-high", 10, kind: InboundMatchKind.Address, local: "support", action: InboundActionKind.Forward, forward: ["a@example.org", "b@example.org"], id: high);
        InboundRouteRecord fwdLow = Route(domain, "fwd-low", 10, kind: InboundMatchKind.Address, local: "sales", action: InboundActionKind.Store, id: low);
        foreach (InboundRouteRecord r in new[] { catchAll, hook, fwdHigh, fwdLow })
        {
            await Inbound.UpsertRouteAsync(r, default);
        }

        var routes = await Inbound.GetRoutesAsync(domain.Id, default);
        Assert.Equal(["fwd-low", "fwd-high", "hook", "catch-all"], routes.Select(r => r.Name));
        Assert.Equal(hook, routes.Single(r => r.Name == "hook"));
        Assert.Equal(fwdHigh, routes.Single(r => r.Name == "fwd-high"));
        Assert.Equal(["a@example.org", "b@example.org"], routes.Single(r => r.Name == "fwd-high").ForwardTo);
        Assert.Equal(catchAll, routes.Single(r => r.Name == "catch-all"));

        // The first enabled match wins, whichever backend ordered the list.
        Assert.Equal("fwd-low", Logic.InboundRules.MatchRoute(routes, "sales")!.Name);
        Assert.Equal("catch-all", Logic.InboundRules.MatchRoute(routes, "nobody")!.Name);
    }

    [Fact]
    public async Task A_route_can_be_replaced_and_is_deleted_only_by_its_tenant()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundRouteRecord route = Route(domain, "one", kind: InboundMatchKind.Address, local: "info");
        await Inbound.UpsertRouteAsync(route, default);

        InboundRouteRecord changed = route with { Name = "two", Enabled = false, Order = 5, UpdatedAt = Clock.UtcNow.AddMinutes(1) };
        await Inbound.UpsertRouteAsync(changed, default);
        Assert.Equal(changed, Assert.Single(await Inbound.GetRoutesAsync(domain.Id, default)));

        Assert.Null(await Inbound.GetRouteAsync(TenantB, route.Id, default));
        Assert.False(await Inbound.DeleteRouteAsync(TenantB, route.Id, default));
        Assert.NotNull(await Inbound.GetRouteAsync(TenantA, route.Id, default));
        Assert.True(await Inbound.DeleteRouteAsync(TenantA, route.Id, default));
        Assert.False(await Inbound.DeleteRouteAsync(TenantA, route.Id, default));
        Assert.Empty(await Inbound.GetRoutesAsync(domain.Id, default));
    }

    [Fact]
    public async Task Routes_that_use_a_webhook_endpoint_are_found_for_the_delete_guard()
    {
        DomainRecord a = await AddDomainAsync(TenantA, "example.com");
        DomainRecord b = await AddDomainAsync(TenantB, "example.net");
        Guid endpoint = await AddEndpointAsync(TenantA, true, "*");
        Guid otherEndpoint = await AddEndpointAsync(TenantB, true, "*");
        InboundRouteRecord one = Route(a, "one", action: InboundActionKind.Webhook, endpoint: endpoint, kind: InboundMatchKind.Address, local: "x");
        InboundRouteRecord two = Route(a, "two", order: 200, action: InboundActionKind.Webhook, endpoint: endpoint, kind: InboundMatchKind.Address, local: "y");
        InboundRouteRecord unrelated = Route(b, "unrelated", action: InboundActionKind.Webhook, endpoint: otherEndpoint);
        InboundRouteRecord store = Route(a, "store", order: 300, kind: InboundMatchKind.Address, local: "z");
        foreach (InboundRouteRecord r in new[] { one, two, unrelated, store })
        {
            await Inbound.UpsertRouteAsync(r, default);
        }

        var using_ = await Inbound.GetRoutesUsingWebhookEndpointAsync(endpoint, default);
        Assert.Equal(["one", "two"], using_.Select(r => r.Name));
        Assert.Empty(await Inbound.GetRoutesUsingWebhookEndpointAsync(Ids.New(), default));
    }

    [Fact]
    public async Task The_receive_path_configuration_holds_enabled_domains_with_their_enabled_routes_in_order()
    {
        DomainRecord on = await AddDomainAsync(TenantA, "on.example", DomainStatus.Verified);
        DomainRecord off = await AddDomainAsync(TenantA, "off.example");
        DomainRecord pending = await AddDomainAsync(TenantB, "pending.example", DomainStatus.Pending, tenantEnabled: false);
        DomainRecord never = await AddDomainAsync(TenantA, "never.example");
        await Inbound.UpsertSettingsAsync(Settings(on, action: InboundDmarcAction.Reject, retentionDays: 14), default);
        await Inbound.UpsertSettingsAsync(Settings(off, enabled: false), default);
        await Inbound.UpsertSettingsAsync(Settings(pending), default);
        await Inbound.UpsertRouteAsync(Route(on, "late", 900), default);
        await Inbound.UpsertRouteAsync(Route(on, "early", 10, kind: InboundMatchKind.Address, local: "a"), default);
        await Inbound.UpsertRouteAsync(Route(on, "disabled", 20, enabled: false, kind: InboundMatchKind.Address, local: "b"), default);
        await Inbound.UpsertRouteAsync(Route(off, "ignored"), default);

        var all = await Inbound.LoadEnabledDomainsAsync(default);
        Assert.Equal(["on.example", "pending.example"], all.Select(d => d.DomainName));

        InboundDomainConfiguration first = all[0];
        Assert.Equal((on.Id, TenantA, true, DomainStatus.Verified), (first.DomainId, first.TenantId, first.TenantEnabled, first.DomainStatus));
        Assert.Equal((InboundDmarcAction.Reject, 14), (first.Settings.DmarcAction, first.Settings.RetentionDays));
        Assert.Equal(["early", "late"], first.Routes.Select(r => r.Name));

        InboundDomainConfiguration second = all[1];
        Assert.Equal((false, DomainStatus.Pending), (second.TenantEnabled, second.DomainStatus));
        Assert.Empty(second.Routes);
        Assert.DoesNotContain(all, d => d.DomainId == never.Id);
    }

    [Fact]
    public async Task Deleting_a_domain_deletes_its_inbound_settings_and_routes_but_not_the_received_mail()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundRouteRecord route = Route(domain);
        await Inbound.UpsertSettingsAsync(Settings(domain), default);
        await Inbound.UpsertRouteAsync(route, default);
        InboundMessageDraft kept = await StoreAsync(Draft(domain, route.Id, InboundActionKind.Store));

        await Storage.Config.DeleteDomainAsync(domain.Id, default);
        Assert.Null(await Inbound.GetSettingsAsync(domain.Id, default));
        Assert.Empty(await Inbound.GetRoutesAsync(domain.Id, default));
        Assert.Null(await Inbound.GetRouteAsync(TenantA, route.Id, default));
        Assert.Empty(await Inbound.LoadEnabledDomainsAsync(default));
        Assert.NotNull(await Inbound.GetAsync(TenantA, kept.Id, default));
    }

    // Accepting messages

    [Fact]
    public async Task A_stored_message_is_normalized_and_starts_in_the_state_its_action_implies()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        Guid route = Ids.New();
        var auth = new InboundAuthResults(InboundVerdict.SoftFail, "sender.test", InboundVerdict.None, InboundVerdict.None, null, InboundVerdict.Fail, "quarantine", InboundVerdict.Pass);
        InboundMessageDraft webhook = Draft(domain, route, InboundActionKind.Webhook, auth: auth, disposition: InboundDmarcDisposition.Flagged, subject: "Hel\u0001lo\r\nthere");
        InboundMessageDraft forward = Draft(domain, route, InboundActionKind.Forward, size: 1600);
        InboundMessageDraft store = Draft(domain, route, InboundActionKind.Store, size: 1700);
        InboundMessageDraft discard = Draft(domain, route, InboundActionKind.Discard, size: 1800, subject: null);
        await Inbound.AcceptAsync([webhook, forward, store, discard], default);

        InboundMessage w = (await Inbound.GetAsync(TenantA, webhook.Id, default))!;
        Assert.Equal(("example.com", "support@example.com", "alice@sender.test", "Hello there", 1500L), (w.Domain, w.EnvelopeTo, w.EnvelopeFrom, w.Subject, w.Size));
        Assert.Equal(("203.0.113.9", "mail.sender.test", true, Clock.UtcNow), (w.RemoteAddress, w.Helo, w.TlsUsed, w.ReceivedAt));
        Assert.Equal(new InboundAuthResults(InboundVerdict.SoftFail, "sender.test", InboundVerdict.None, InboundVerdict.None, null, InboundVerdict.Fail, "quarantine", InboundVerdict.Pass), w.Auth);
        Assert.Equal((InboundDmarcDisposition.Flagged, route, InboundActionKind.Webhook), (w.Disposition, w.RouteId, w.ActionKind));
        Assert.Equal((InboundActionState.Pending, 0, Clock.UtcNow, null, null, null, true), (w.ActionState, w.ActionAttempts, w.ActionNextAttemptAt, w.ActionFinishedAt, w.ActionLastError, w.ForwardMessageId, w.HasRaw));

        InboundMessage f = (await Inbound.GetAsync(TenantA, forward.Id, default))!;
        Assert.Equal((InboundActionState.Pending, true), (f.ActionState, f.HasRaw));

        InboundMessage s = (await Inbound.GetAsync(TenantA, store.Id, default))!;
        Assert.Equal((InboundActionState.Done, null, Clock.UtcNow, true), (s.ActionState, s.ActionNextAttemptAt, s.ActionFinishedAt, s.HasRaw));
        Assert.Equal(store.Raw.ToArray(), await Inbound.GetRawAsync(TenantA, store.Id, default));

        InboundMessage d = (await Inbound.GetAsync(TenantA, discard.Id, default))!;
        Assert.Equal((InboundActionState.Done, false, 1800L, null), (d.ActionState, d.HasRaw, d.Size, d.Subject));
        Assert.Null(await Inbound.GetRawAsync(TenantA, discard.Id, default));
    }

    [Fact]
    public async Task The_stored_body_is_a_copy_the_caller_may_reuse()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundMessageDraft draft = Draft(domain, Ids.New(), InboundActionKind.Store, size: 64);
        byte[] expected = draft.Raw.ToArray();
        await Inbound.AcceptAsync([draft], default);
        System.Runtime.InteropServices.MemoryMarshal.AsMemory(draft.Raw).Span.Fill(0xFF);

        Assert.Equal(expected, await Inbound.GetRawAsync(TenantA, draft.Id, default));
    }

    [Fact]
    public async Task One_transaction_stores_all_its_recipients_or_none()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        Guid route = Ids.New();
        InboundMessageDraft first = Draft(domain, route, to: "one@example.com", size: 100);
        InboundMessageDraft second = Draft(domain, route, to: "two@example.com", size: 101);
        await Inbound.AcceptAsync([first, second], default);
        Assert.Equal(2, (await Inbound.SearchAsync(new InboundMessageQuery(TenantId: TenantA), default)).Items.Count);

        InboundMessageDraft fresh = Draft(domain, route, to: "three@example.com", size: 102);
        InboundMessageDraft duplicate = Draft(domain, route, to: "four@example.com", size: 103, id: first.Id);
        await Assert.ThrowsAsync<StorageConflictException>(async () => await Inbound.AcceptAsync([fresh, duplicate], default));
        Assert.Null(await Inbound.GetAsync(TenantA, fresh.Id, default));
        Assert.Equal(2, (await Inbound.SearchAsync(new InboundMessageQuery(TenantId: TenantA), default)).Items.Count);

        await Assert.ThrowsAsync<ArgumentException>(async () => await Inbound.AcceptAsync([], default));
    }

    [Fact]
    public async Task Messages_are_only_visible_to_their_tenant()
    {
        DomainRecord a = await AddDomainAsync(TenantA, "example.com");
        InboundMessageDraft draft = await StoreAsync(Draft(a, Ids.New(), InboundActionKind.Store));

        Assert.NotNull(await Inbound.GetAsync(TenantA, draft.Id, default));
        Assert.Null(await Inbound.GetAsync(TenantB, draft.Id, default));
        Assert.Null(await Inbound.GetRawAsync(TenantB, draft.Id, default));
        Assert.False(await Inbound.DeleteAsync(TenantB, draft.Id, default));
        Assert.Equal(InboundRetryResult.NotFound, await Inbound.RetryActionAsync(TenantB, draft.Id, Clock.UtcNow, default));
        Assert.Empty((await Inbound.SearchAsync(new InboundMessageQuery(TenantId: TenantB), default)).Items);
        Assert.NotNull(await Inbound.GetRawAsync(TenantA, draft.Id, default));
    }

    // Search

    [Fact]
    public async Task Search_filters_and_pages_newest_first()
    {
        DomainRecord a = await AddDomainAsync(TenantA, "example.com");
        DomainRecord b = await AddDomainAsync(TenantA, "example.net");
        DomainRecord other = await AddDomainAsync(TenantB, "other.test");
        Guid routeOne = Ids.New();
        Guid routeTwo = Ids.New();
        var fail = new InboundAuthResults(InboundVerdict.Fail, "x.test", InboundVerdict.None, InboundVerdict.Fail, null, InboundVerdict.Fail, "reject", InboundVerdict.None);

        var drafts = new List<InboundMessageDraft>();
        for (int i = 0; i < 6; i++)
        {
            Clock.Advance(TimeSpan.FromMinutes(1));
            drafts.Add(await StoreAsync(Draft(a, i % 2 == 0 ? routeOne : routeTwo, i % 2 == 0 ? InboundActionKind.Webhook : InboundActionKind.Store, to: i < 3 ? "sales@example.com" : "info@example.com",
                from: i == 5 ? "Bob@Other.Test" : "alice@sender.test", subject: i == 4 ? "Invoice 42" : "Hello " + i, size: 200 + i)));
        }

        Clock.Advance(TimeSpan.FromMinutes(1));
        InboundMessageDraft quarantined = await StoreAsync(Draft(b, routeOne, auth: fail, disposition: InboundDmarcDisposition.Flagged, size: 300));
        InboundMessageDraft foreign = await StoreAsync(Draft(other, routeOne, size: 301));

        async Task<List<Guid>> Ids_(InboundMessageQuery q) => (await Inbound.SearchAsync(q, default)).Items.Select(m => m.Id).ToList();

        // Newest first, tenant always.
        Assert.Equal([quarantined.Id, .. drafts.AsEnumerable().Reverse().Select(d => d.Id)], await Ids_(new InboundMessageQuery(TenantId: TenantA)));
        Assert.Equal([foreign.Id], await Ids_(new InboundMessageQuery(TenantId: TenantB)));

        Assert.Equal([quarantined.Id], await Ids_(new InboundMessageQuery(TenantId: TenantA, DomainId: b.Id)));
        Assert.Equal([drafts[2].Id, drafts[1].Id, drafts[0].Id], await Ids_(new InboundMessageQuery(TenantId: TenantA, Recipient: " Sales@EXAMPLE.com ")));
        Assert.Equal([drafts[5].Id], await Ids_(new InboundMessageQuery(TenantId: TenantA, Sender: "BOB@other.test")));
        Assert.Equal([drafts[4].Id], await Ids_(new InboundMessageQuery(TenantId: TenantA, SubjectContains: "voice 4")));
        Assert.Equal([drafts[4].Id], await Ids_(new InboundMessageQuery(TenantId: TenantA, SubjectContains: "INVOICE")));
        Assert.Empty(await Ids_(new InboundMessageQuery(TenantId: TenantA, SubjectContains: "%")));
        Assert.Equal(3, (await Ids_(new InboundMessageQuery(TenantId: TenantA, RouteId: routeTwo))).Count);
        Assert.Equal(3, (await Ids_(new InboundMessageQuery(TenantId: TenantA, ActionKind: InboundActionKind.Store))).Count);
        Assert.Equal(4, (await Ids_(new InboundMessageQuery(TenantId: TenantA, ActionState: InboundActionState.Pending))).Count);
        Assert.Equal([quarantined.Id], await Ids_(new InboundMessageQuery(TenantId: TenantA, Dmarc: InboundVerdict.Fail)));
        Assert.Equal([quarantined.Id], await Ids_(new InboundMessageQuery(TenantId: TenantA, DmarcFlagged: true)));
        Assert.Equal(6, (await Ids_(new InboundMessageQuery(TenantId: TenantA, DmarcFlagged: false))).Count);
        Assert.Equal([drafts[2].Id, drafts[3].Id], (await Ids_(new InboundMessageQuery(TenantId: TenantA, From: drafts[2].ReceivedAt, To: drafts[4].ReceivedAt))).AsEnumerable().Reverse());

        // Paging by cursor.
        var page1 = await Inbound.SearchAsync(new InboundMessageQuery(TenantId: TenantA, Limit: 3), default);
        Assert.Equal(3, page1.Items.Count);
        Assert.NotNull(page1.NextCursor);
        var page2 = await Inbound.SearchAsync(new InboundMessageQuery(TenantId: TenantA, Limit: 3, Cursor: page1.NextCursor), default);
        var page3 = await Inbound.SearchAsync(new InboundMessageQuery(TenantId: TenantA, Limit: 3, Cursor: page2.NextCursor), default);
        Assert.Equal([quarantined.Id, .. drafts.AsEnumerable().Reverse().Select(d => d.Id)], page1.Items.Concat(page2.Items).Concat(page3.Items).Select(m => m.Id));
        Assert.Null(page3.NextCursor);
        Assert.Empty((await Inbound.SearchAsync(new InboundMessageQuery(TenantId: TenantA, Cursor: "not a cursor"), default)).Items);
    }

    // Claiming and completing the route actions

    [Fact]
    public async Task Only_due_pending_actions_are_claimed_oldest_first_with_their_body()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        Guid route = Ids.New();
        InboundMessageDraft late = await StoreAsync(Draft(domain, route, at: Clock.UtcNow.AddMinutes(10), size: 111));
        InboundMessageDraft second = await StoreAsync(Draft(domain, route, at: Clock.UtcNow.AddMinutes(-1), size: 112));
        InboundMessageDraft first = await StoreAsync(Draft(domain, route, at: Clock.UtcNow.AddMinutes(-2), size: 113));
        await StoreAsync(Draft(domain, route, InboundActionKind.Store));
        await StoreAsync(Draft(domain, route, InboundActionKind.Discard));

        var claimed = await ClaimActionsAsync(max: 10, lease: TimeSpan.FromHours(1));
        Assert.Equal([first.Id, second.Id], claimed.Select(c => c.Message.Id));
        Assert.Equal(first.Raw.ToArray(), claimed[0].Raw);
        Assert.Equal(second.Raw.ToArray(), claimed[1].Raw);
        Assert.All(claimed, c => Assert.Equal(InboundActionState.Pending, c.Message.ActionState));

        // Leased rows are not handed out again; a row that is not due yet is claimed when it is.
        Assert.Empty(await ClaimActionsAsync(max: 10));
        var later = await ClaimActionsAsync(max: 10, now: Clock.UtcNow.AddMinutes(11), owner: "worker-2");
        Assert.Equal([late.Id], later.Select(c => c.Message.Id));
    }

    [Fact]
    public async Task The_claim_honors_the_maximum_and_a_lease_that_ran_out_can_be_claimed_again()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        Guid route = Ids.New();
        for (int i = 0; i < 5; i++)
        {
            Clock.Advance(TimeSpan.FromSeconds(1));
            await StoreAsync(Draft(domain, route, size: 100 + i));
        }

        Assert.Equal(2, (await ClaimActionsAsync(max: 2, lease: TimeSpan.FromMinutes(1))).Count);
        Assert.Equal(3, (await ClaimActionsAsync(max: 10, owner: "worker-2")).Count);
        Assert.Empty(await ClaimActionsAsync(max: 10, owner: "worker-3"));
        Assert.Empty(await Inbound.ClaimActionsAsync("worker-3", 0, Clock.UtcNow, TimeSpan.FromMinutes(1), default));

        // worker-1 died: after its lease ran out the two rows go to someone else.
        var again = await ClaimActionsAsync(max: 10, owner: "worker-3", now: Clock.UtcNow.AddMinutes(2));
        Assert.Equal(5, again.Count);
    }

    [Fact]
    public async Task A_successful_completion_ends_the_action_and_a_forward_frees_the_body_while_a_webhook_keeps_it()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        Guid route = Ids.New();
        InboundMessageDraft hook = await StoreAsync(Draft(domain, route, InboundActionKind.Webhook, size: 120));
        Clock.Advance(TimeSpan.FromSeconds(1));
        InboundMessageDraft forward = await StoreAsync(Draft(domain, route, InboundActionKind.Forward, size: 121));
        var claimed = await ClaimActionsAsync();
        Assert.Equal(2, claimed.Count);

        Clock.Advance(TimeSpan.FromSeconds(5));
        Guid outbound = Ids.New();
        Assert.True(await Inbound.CompleteActionAsync(hook.Id, Owner, new InboundActionOutcome(InboundActionState.Done, Clock.UtcNow, null, "ignored"), default));
        Assert.True(await Inbound.CompleteActionAsync(forward.Id, Owner, new InboundActionOutcome(InboundActionState.Done, Clock.UtcNow, null, null, outbound, FreeBody: true), default));

        InboundMessage h = (await Inbound.GetAsync(TenantA, hook.Id, default))!;
        Assert.Equal((InboundActionState.Done, 1, null, Clock.UtcNow, null, true), (h.ActionState, h.ActionAttempts, h.ActionNextAttemptAt, h.ActionFinishedAt, h.ActionLastError, h.HasRaw));
        Assert.NotNull(await Inbound.GetRawAsync(TenantA, hook.Id, default));

        InboundMessage f = (await Inbound.GetAsync(TenantA, forward.Id, default))!;
        Assert.Equal((InboundActionState.Done, outbound, false), (f.ActionState, f.ForwardMessageId, f.HasRaw));
        Assert.Null(await Inbound.GetRawAsync(TenantA, forward.Id, default));

        // Finished rows are never claimed again.
        Assert.Empty(await ClaimActionsAsync(now: Clock.UtcNow.AddDays(1), owner: "worker-2"));
    }

    [Fact]
    public async Task A_retry_schedules_the_next_attempt_and_a_failure_is_final_with_its_error()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundMessageDraft draft = await StoreAsync(Draft(domain, Ids.New(), InboundActionKind.Webhook));
        Assert.Single(await ClaimActionsAsync());

        DateTimeOffset next = Clock.UtcNow.AddMinutes(5);
        Assert.True(await Inbound.CompleteActionAsync(draft.Id, Owner, new InboundActionOutcome(InboundActionState.Pending, Clock.UtcNow, next, "HTTP 503\r\nfrom receiver"), default));
        InboundMessage retrying = (await Inbound.GetAsync(TenantA, draft.Id, default))!;
        Assert.Equal((InboundActionState.Pending, 1, next, null, "HTTP 503  from receiver"), (retrying.ActionState, retrying.ActionAttempts, retrying.ActionNextAttemptAt, retrying.ActionFinishedAt, retrying.ActionLastError));

        Assert.Empty(await ClaimActionsAsync(owner: "worker-2", now: next.AddSeconds(-1)));
        Assert.Single(await ClaimActionsAsync(owner: "worker-2", now: next));

        Clock.Advance(TimeSpan.FromMinutes(6));
        Assert.True(await Inbound.CompleteActionAsync(draft.Id, "worker-2", new InboundActionOutcome(InboundActionState.Failed, Clock.UtcNow, null, new string('x', 5000)), default));
        InboundMessage failed = (await Inbound.GetAsync(TenantA, draft.Id, default))!;
        Assert.Equal((InboundActionState.Failed, 2, null, Clock.UtcNow), (failed.ActionState, failed.ActionAttempts, failed.ActionNextAttemptAt, failed.ActionFinishedAt));
        Assert.Equal(1000, failed.ActionLastError!.Length);
        Assert.True(failed.HasRaw);
    }

    [Fact]
    public async Task Only_the_lease_holder_can_complete_and_a_pending_outcome_needs_a_time()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundMessageDraft draft = await StoreAsync(Draft(domain, Ids.New(), InboundActionKind.Webhook));
        var done = new InboundActionOutcome(InboundActionState.Done, Clock.UtcNow, null, null);

        Assert.False(await Inbound.CompleteActionAsync(draft.Id, Owner, done, default)); // never claimed
        Assert.Single(await ClaimActionsAsync());
        Assert.False(await Inbound.CompleteActionAsync(draft.Id, "worker-2", done, default));
        Assert.False(await Inbound.CompleteActionAsync(Ids.New(), Owner, done, default));
        await Assert.ThrowsAsync<ArgumentException>(async () => await Inbound.CompleteActionAsync(draft.Id, Owner, new InboundActionOutcome(InboundActionState.Pending, Clock.UtcNow, null, "x"), default));

        Assert.True(await Inbound.CompleteActionAsync(draft.Id, Owner, done, default));
        Assert.False(await Inbound.CompleteActionAsync(draft.Id, Owner, done, default)); // the lease is gone with the first completion
    }

    [Fact]
    public async Task A_lease_can_be_extended_by_its_holder_and_released_without_counting_an_attempt()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundMessageDraft draft = await StoreAsync(Draft(domain, Ids.New(), InboundActionKind.Webhook));
        Assert.False(await Inbound.ExtendActionLeaseAsync(draft.Id, Owner, Clock.UtcNow.AddMinutes(10), default)); // not leased yet
        Assert.Single(await ClaimActionsAsync(lease: TimeSpan.FromMinutes(1)));

        Assert.False(await Inbound.ExtendActionLeaseAsync(draft.Id, "worker-2", Clock.UtcNow.AddMinutes(10), default));
        Assert.True(await Inbound.ExtendActionLeaseAsync(draft.Id, Owner, Clock.UtcNow.AddMinutes(10), default));
        Assert.Empty(await ClaimActionsAsync(owner: "worker-2", now: Clock.UtcNow.AddMinutes(5))); // extended past the original minute

        Assert.Equal(0, await Inbound.ReleaseOwnedActionLeasesAsync("worker-2", default));
        Assert.Equal(1, (await Inbound.GetAsync(TenantA, draft.Id, default))!.ActionAttempts);   // the claim counted it
        Assert.Equal(1, await Inbound.ReleaseOwnedActionLeasesAsync(Owner, default));
        Assert.Equal(0, (await Inbound.GetAsync(TenantA, draft.Id, default))!.ActionAttempts);   // a graceful release gives the attempt back
        Assert.Equal(1, Assert.Single(await ClaimActionsAsync(owner: "worker-2")).Message.ActionAttempts);
    }

    [Fact]
    public async Task The_claim_counts_the_attempt_so_a_message_that_crashes_its_runner_every_time_reaches_the_end_of_the_ladder()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundMessageDraft draft = await StoreAsync(Draft(domain, Ids.New(), InboundActionKind.Webhook));

        // Three runners claim it and die without completing or releasing: the leases run out, the attempts stay used up.
        long claimedToken = 0;
        for (int attempt = 1; attempt <= 3; attempt++)
        {
            var claimed = Assert.Single(await ClaimActionsAsync(owner: "runner-" + attempt, lease: TimeSpan.FromMinutes(1), now: Clock.UtcNow.AddMinutes(attempt * 2)));
            Assert.Equal(attempt, claimed.Message.ActionAttempts);
            claimedToken = claimed.ClaimToken;
        }

        Assert.Equal(3, (await Inbound.GetAsync(TenantA, draft.Id, default))!.ActionAttempts);

        // Completing does not count a second time; a manual retry starts the count again.
        Assert.True(await Inbound.CompleteActionAsync(draft.Id, "runner-3", new InboundActionOutcome(InboundActionState.Failed, Clock.UtcNow, null, "attempts used up", ClaimToken: claimedToken), default));
        Assert.Equal(3, (await Inbound.GetAsync(TenantA, draft.Id, default))!.ActionAttempts);
        Assert.Equal(InboundRetryResult.Queued, await Inbound.RetryActionAsync(TenantA, draft.Id, Clock.UtcNow, default));
        Assert.Equal(0, (await Inbound.GetAsync(TenantA, draft.Id, default))!.ActionAttempts);
    }

    [Fact]
    public async Task A_completion_from_an_earlier_claim_is_refused_even_when_the_same_owner_claimed_the_row_again()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundMessageDraft draft = await StoreAsync(Draft(domain, Ids.New(), InboundActionKind.Webhook));
        var first = Assert.Single(await ClaimActionsAsync(lease: TimeSpan.FromMinutes(1)));
        var second = Assert.Single(await ClaimActionsAsync(lease: TimeSpan.FromMinutes(1), now: Clock.UtcNow.AddMinutes(5)));   // the lease ran out: the same owner name claims it again
        Assert.Equal((1, 2), (first.Message.ActionAttempts, second.Message.ActionAttempts));

        var done = new InboundActionOutcome(InboundActionState.Done, Clock.UtcNow, null, null);
        Assert.False(await Inbound.CompleteActionAsync(draft.Id, Owner, done with { ClaimToken = first.ClaimToken }, default));   // the stale attempt
        Assert.Equal(InboundActionState.Pending, (await Inbound.GetAsync(TenantA, draft.Id, default))!.ActionState);
        Assert.False(await Inbound.CompleteActionAsync(draft.Id, "someone-else", done with { ClaimToken = second.ClaimToken }, default));
        Assert.True(await Inbound.CompleteActionAsync(draft.Id, Owner, done with { ClaimToken = second.ClaimToken }, default));
        Assert.Equal(InboundActionState.Done, (await Inbound.GetAsync(TenantA, draft.Id, default))!.ActionState);
    }

    [Fact]
    public async Task A_completion_after_the_lease_ran_out_is_accepted_while_nobody_claimed_the_row_since()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundMessageDraft draft = await StoreAsync(Draft(domain, Ids.New(), InboundActionKind.Webhook));
        var claim = Assert.Single(await ClaimActionsAsync(lease: TimeSpan.FromSeconds(30)));
        Clock.Advance(TimeSpan.FromMinutes(10));   // the attempt took longer than its lease, but no other runner took the row

        Assert.True(await Inbound.CompleteActionAsync(draft.Id, Owner, new InboundActionOutcome(InboundActionState.Done, Clock.UtcNow, null, null, ClaimToken: claim.ClaimToken), default));
    }

    [Fact]
    public async Task A_search_page_is_never_larger_than_200()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        for (int i = 0; i < 205; i++)
        {
            await StoreAsync(Draft(domain, Ids.New(), InboundActionKind.Store, size: 40, at: Clock.UtcNow.AddMilliseconds(i)));
        }

        var page = await Inbound.SearchAsync(new InboundMessageQuery(TenantA, Limit: 1000), default);
        Assert.Equal(200, page.Items.Count);
        Assert.NotNull(page.NextCursor);
        Assert.Equal(5, (await Inbound.SearchAsync(new InboundMessageQuery(TenantA, Limit: 1000, Cursor: page.NextCursor), default)).Items.Count);
    }

    [Fact]
    public async Task Retry_puts_a_failed_or_finished_webhook_or_forward_back_to_pending()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        Guid route = Ids.New();
        InboundMessageDraft failedHook = await StoreAsync(Draft(domain, route, InboundActionKind.Webhook, size: 130));
        InboundMessageDraft doneHook = await StoreAsync(Draft(domain, route, InboundActionKind.Webhook, size: 131));
        InboundMessageDraft doneForward = await StoreAsync(Draft(domain, route, InboundActionKind.Forward, size: 132));
        InboundMessageDraft store = await StoreAsync(Draft(domain, route, InboundActionKind.Store, size: 133));
        InboundMessageDraft discard = await StoreAsync(Draft(domain, route, InboundActionKind.Discard, size: 134));
        Assert.Equal(3, (await ClaimActionsAsync()).Count);
        await Inbound.CompleteActionAsync(failedHook.Id, Owner, new InboundActionOutcome(InboundActionState.Failed, Clock.UtcNow, null, "gone"), default);
        await Inbound.CompleteActionAsync(doneHook.Id, Owner, new InboundActionOutcome(InboundActionState.Done, Clock.UtcNow, null, null), default);
        await Inbound.CompleteActionAsync(doneForward.Id, Owner, new InboundActionOutcome(InboundActionState.Done, Clock.UtcNow, null, null, Ids.New(), FreeBody: true), default);

        Clock.Advance(TimeSpan.FromHours(1));
        Assert.Equal(InboundRetryResult.Queued, await Inbound.RetryActionAsync(TenantA, failedHook.Id, Clock.UtcNow, default));
        Assert.Equal(InboundRetryResult.AlreadyPending, await Inbound.RetryActionAsync(TenantA, failedHook.Id, Clock.UtcNow, default));
        Assert.Equal(InboundRetryResult.Queued, await Inbound.RetryActionAsync(TenantA, doneHook.Id, Clock.UtcNow, default));
        Assert.Equal(InboundRetryResult.NotRetryable, await Inbound.RetryActionAsync(TenantA, doneForward.Id, Clock.UtcNow, default)); // its body is gone
        Assert.Equal(InboundRetryResult.NotRetryable, await Inbound.RetryActionAsync(TenantA, store.Id, Clock.UtcNow, default));
        Assert.Equal(InboundRetryResult.NotRetryable, await Inbound.RetryActionAsync(TenantA, discard.Id, Clock.UtcNow, default));
        Assert.Equal(InboundRetryResult.NotFound, await Inbound.RetryActionAsync(TenantA, Ids.New(), Clock.UtcNow, default));

        InboundMessage again = (await Inbound.GetAsync(TenantA, failedHook.Id, default))!;
        Assert.Equal((InboundActionState.Pending, 0, Clock.UtcNow, null), (again.ActionState, again.ActionAttempts, again.ActionNextAttemptAt, again.ActionFinishedAt));
        Assert.Equal(2, (await ClaimActionsAsync(owner: "worker-2")).Count);
    }

    [Fact]
    public async Task Deleting_a_message_removes_the_body_and_a_late_completion_is_harmless()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundMessageDraft draft = await StoreAsync(Draft(domain, Ids.New(), InboundActionKind.Webhook));
        Assert.Single(await ClaimActionsAsync());

        Assert.True(await Inbound.DeleteAsync(TenantA, draft.Id, default));
        Assert.False(await Inbound.DeleteAsync(TenantA, draft.Id, default));
        Assert.Null(await Inbound.GetAsync(TenantA, draft.Id, default));
        Assert.Null(await Inbound.GetRawAsync(TenantA, draft.Id, default));
        Assert.False(await Inbound.CompleteActionAsync(draft.Id, Owner, new InboundActionOutcome(InboundActionState.Done, Clock.UtcNow, null, null), default));
        Assert.Empty(await ClaimActionsAsync(owner: "worker-2", now: Clock.UtcNow.AddDays(1)));
    }

    // Usage

    [Fact]
    public async Task Usage_counts_messages_stored_bytes_and_actions_by_tenant_and_domain()
    {
        DomainRecord a = await AddDomainAsync(TenantA, "example.com");
        DomainRecord b = await AddDomainAsync(TenantA, "example.net");
        DomainRecord c = await AddDomainAsync(TenantB, "other.test");
        Guid route = Ids.New();
        Assert.Equal(new InboundUsage(0, 0, 0, 0, null), await Inbound.GetUsageAsync(null, null, default));

        InboundMessageDraft oldestPending = await StoreAsync(Draft(a, route, InboundActionKind.Webhook, size: 1000, at: Clock.UtcNow.AddHours(-3)));
        await StoreAsync(Draft(a, route, InboundActionKind.Webhook, size: 2000, at: Clock.UtcNow.AddHours(-1)));
        await StoreAsync(Draft(a, route, InboundActionKind.Store, size: 3000));
        await StoreAsync(Draft(a, route, InboundActionKind.Discard, size: 4000));
        await StoreAsync(Draft(b, route, InboundActionKind.Store, size: 500));
        await StoreAsync(Draft(c, route, InboundActionKind.Store, size: 700));
        var claimed = await ClaimActionsAsync();
        InboundMessage toFail = claimed.Select(x => x.Message).Single(m => m.Id == oldestPending.Id);
        await Inbound.CompleteActionAsync(toFail.Id, Owner, new InboundActionOutcome(InboundActionState.Failed, Clock.UtcNow, null, "x"), default);

        Assert.Equal(new InboundUsage(6, 1000 + 2000 + 3000 + 500 + 700, 1, 1, claimed.Select(x => x.Message).Where(m => m.Id != oldestPending.Id && m.ActionState == InboundActionState.Pending).Min(m => m.ReceivedAt)), await Inbound.GetUsageAsync(null, null, default));
        Assert.Equal(5, (await Inbound.GetUsageAsync(TenantA, null, default)).Messages);
        Assert.Equal(1, (await Inbound.GetUsageAsync(TenantB, null, default)).Messages);
        InboundUsage forA = await Inbound.GetUsageAsync(TenantA, a.Id, default);
        Assert.Equal((4L, 1000 + 2000 + 3000L, 1L, 1L), (forA.Messages, forA.BodyBytes, forA.Pending, forA.Failed));
        InboundUsage none = await Inbound.GetUsageAsync(TenantB, a.Id, default);
        Assert.Equal(new InboundUsage(0, 0, 0, 0, null), none);
    }

    // Retention

    [Fact]
    public async Task Retention_deletes_old_messages_by_the_server_default_the_domain_setting_and_never_pending_actions()
    {
        await OpenAsync(WithInbound(Opts(), 7));
        DomainRecord defaultDomain = await AddDomainAsync(TenantA, "default.example");
        DomainRecord shortDomain = await AddDomainAsync(TenantA, "short.example");
        DomainRecord foreverDomain = await AddDomainAsync(TenantA, "forever.example");
        DomainRecord longDomain = await AddDomainAsync(TenantB, "long.example");
        await Inbound.UpsertSettingsAsync(Settings(shortDomain, retentionDays: 2), default);
        await Inbound.UpsertSettingsAsync(Settings(foreverDomain, retentionDays: 0), default);
        await Inbound.UpsertSettingsAsync(Settings(longDomain, retentionDays: 30), default);
        Guid route = Ids.New();

        async Task<InboundMessageDraft> AtAgeAsync(DomainRecord d, double days, InboundActionKind kind = InboundActionKind.Store, int size = 100) =>
            await StoreAsync(Draft(d, route, kind, at: Clock.UtcNow.AddDays(-days), size: size));

        InboundMessageDraft defaultOld = await AtAgeAsync(defaultDomain, 8);
        InboundMessageDraft defaultNew = await AtAgeAsync(defaultDomain, 6);
        InboundMessageDraft shortOld = await AtAgeAsync(shortDomain, 3);
        InboundMessageDraft shortNew = await AtAgeAsync(shortDomain, 1);
        InboundMessageDraft foreverOld = await AtAgeAsync(foreverDomain, 400);
        InboundMessageDraft longMid = await AtAgeAsync(longDomain, 20);
        InboundMessageDraft longOld = await AtAgeAsync(longDomain, 31);
        InboundMessageDraft pendingOld = await AtAgeAsync(defaultDomain, 40, InboundActionKind.Webhook);
        InboundMessageDraft discardOld = await AtAgeAsync(defaultDomain, 9, InboundActionKind.Discard);

        var reports = await Storage.Maintenance.RunAsync(Clock.UtcNow, default);
        MaintenanceReport job = Assert.Single(reports, r => r.Job == "inbound_retention");
        Assert.Equal(4, job.RowsAffected);

        foreach (InboundMessageDraft gone in new[] { defaultOld, shortOld, longOld, discardOld })
        {
            Assert.Null(await Inbound.GetAsync(gone.TenantId, gone.Id, default));
            Assert.Null(await Inbound.GetRawAsync(gone.TenantId, gone.Id, default));
        }

        foreach (InboundMessageDraft kept in new[] { defaultNew, shortNew, foreverOld, longMid, pendingOld })
        {
            Assert.NotNull(await Inbound.GetAsync(kept.TenantId, kept.Id, default));
        }

        Assert.NotNull(await Inbound.GetRawAsync(TenantA, foreverOld.Id, default));

        // The cutoff is read from the settings when the job runs: shortening a domain's retention frees what is now too old, a pending action that finished is no longer protected.
        await Inbound.UpsertSettingsAsync(Settings(longDomain, retentionDays: 10), default);
        Assert.Single(await ClaimActionsAsync(now: Clock.UtcNow));
        await Inbound.CompleteActionAsync(pendingOld.Id, Owner, new InboundActionOutcome(InboundActionState.Failed, Clock.UtcNow, null, "gave up"), default);
        var second = await Storage.Maintenance.RunAsync(Clock.UtcNow, default);
        Assert.Equal(2, Assert.Single(second, r => r.Job == "inbound_retention").RowsAffected);
        Assert.Null(await Inbound.GetAsync(TenantB, longMid.Id, default));
        Assert.Null(await Inbound.GetAsync(TenantA, pendingOld.Id, default));
        Assert.NotNull(await Inbound.GetAsync(TenantA, foreverOld.Id, default));
    }

    [Fact]
    public async Task A_server_default_of_zero_keeps_everything_and_the_job_is_repeatable()
    {
        await OpenAsync(WithInbound(Opts(), 0));
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundMessageDraft old = await StoreAsync(Draft(domain, Ids.New(), InboundActionKind.Store, at: Clock.UtcNow.AddDays(-1000)));

        var first = await Storage.Maintenance.RunAsync(Clock.UtcNow, default);
        var second = await Storage.Maintenance.RunAsync(Clock.UtcNow, default);
        Assert.Equal(0, Assert.Single(first, r => r.Job == "inbound_retention").RowsAffected);
        Assert.Equal(first.Select(r => r.Job), second.Select(r => r.Job));
        Assert.NotNull(await Inbound.GetAsync(TenantA, old.Id, default));

        StorageHealth health = await Storage.Maintenance.GetHealthAsync(default);
        Assert.Contains("retention_unlimited:Inbound:RetentionDays", health.Warnings);
    }

    // Operator ceilings, erasure, retry generation, HELO verdict, the implicit postmaster delivery

    [Fact]
    public async Task The_operators_retention_ceiling_cuts_what_a_domain_chose_and_forever_becomes_the_ceiling()
    {
        await OpenAsync(WithInbound(Opts(), 7, maxRetentionDays: 10));
        DomainRecord longDomain = await AddDomainAsync(TenantA, "long.example");
        DomainRecord foreverDomain = await AddDomainAsync(TenantA, "forever.example");
        DomainRecord plain = await AddDomainAsync(TenantB, "plain.example");
        await Inbound.UpsertSettingsAsync(Settings(longDomain, retentionDays: 90), default);
        await Inbound.UpsertSettingsAsync(Settings(foreverDomain, retentionDays: 0), default);
        Guid route = Ids.New();

        InboundMessageDraft longOld = await StoreAsync(Draft(longDomain, route, InboundActionKind.Store, at: Clock.UtcNow.AddDays(-11)));
        InboundMessageDraft longNew = await StoreAsync(Draft(longDomain, route, InboundActionKind.Store, at: Clock.UtcNow.AddDays(-9)));
        InboundMessageDraft foreverOld = await StoreAsync(Draft(foreverDomain, route, InboundActionKind.Store, at: Clock.UtcNow.AddDays(-400)));
        InboundMessageDraft plainOld = await StoreAsync(Draft(plain, route, InboundActionKind.Store, at: Clock.UtcNow.AddDays(-8)));   // the default (7) applies
        InboundMessageDraft plainNew = await StoreAsync(Draft(plain, route, InboundActionKind.Store, at: Clock.UtcNow.AddDays(-6)));

        MaintenanceReport job = Assert.Single(await Storage.Maintenance.RunAsync(Clock.UtcNow, default), r => r.Job == "inbound_retention");
        Assert.Equal(3, job.RowsAffected);
        foreach (InboundMessageDraft gone in new[] { longOld, foreverOld, plainOld })
        {
            Assert.Null(await Inbound.GetAsync(gone.TenantId, gone.Id, default));
        }

        Assert.NotNull(await Inbound.GetAsync(TenantA, longNew.Id, default));
        Assert.NotNull(await Inbound.GetAsync(TenantB, plainNew.Id, default));
    }

    [Fact]
    public async Task An_erasure_deletes_everything_of_the_tenant_that_matches_and_needs_a_filter()
    {
        DomainRecord a = await AddDomainAsync(TenantA, "example.com");
        DomainRecord b = await AddDomainAsync(TenantA, "example.net");
        DomainRecord other = await AddDomainAsync(TenantB, "other.test");
        Guid route = Ids.New();
        var victims = new List<InboundMessageDraft>();
        for (int i = 0; i < 5; i++)
        {
            victims.Add(await StoreAsync(Draft(a, route, i % 2 == 0 ? InboundActionKind.Webhook : InboundActionKind.Store, from: "Victim@Sender.Test", to: "x" + i + "@example.com", size: 300 + i)));
        }

        InboundMessageDraft bystander = await StoreAsync(Draft(a, route, InboundActionKind.Store, from: "friend@sender.test"));
        InboundMessageDraft otherDomain = await StoreAsync(Draft(b, route, InboundActionKind.Store, from: "friend@sender.test"));
        InboundMessageDraft theirs = await StoreAsync(Draft(other, route, InboundActionKind.Store, from: "victim@sender.test"));

        await Assert.ThrowsAsync<ArgumentException>(async () => await Inbound.DeleteMatchingAsync(new InboundMessageQuery(TenantA), default));
        await Assert.ThrowsAsync<ArgumentException>(async () => await Inbound.DeleteMatchingAsync(new InboundMessageQuery(TenantA, Limit: 5, Cursor: "x"), default));   // paging is not a filter

        Assert.Equal(5, await Inbound.DeleteMatchingAsync(new InboundMessageQuery(TenantA, Sender: "victim@sender.test"), default));
        foreach (InboundMessageDraft victim in victims)
        {
            Assert.Null(await Inbound.GetAsync(TenantA, victim.Id, default));
            Assert.Null(await Inbound.GetRawAsync(TenantA, victim.Id, default));
        }

        Assert.NotNull(await Inbound.GetAsync(TenantA, bystander.Id, default));
        Assert.NotNull(await Inbound.GetAsync(TenantA, otherDomain.Id, default));
        Assert.NotNull(await Inbound.GetRawAsync(TenantB, theirs.Id, default));   // another tenant's mail is never touched, whatever it matches

        Assert.Equal(1, await Inbound.DeleteMatchingAsync(new InboundMessageQuery(TenantA, DomainId: b.Id), default));
        Assert.Equal(0, await Inbound.DeleteMatchingAsync(new InboundMessageQuery(TenantA, DomainId: b.Id), default));
        Assert.Equal(new InboundUsage(1, bystander.Raw.Length, 0, 0, null), await Inbound.GetUsageAsync(TenantA, null, default));
    }

    [Fact]
    public async Task An_erasure_removes_many_batches_and_pending_actions_too()
    {
        DomainRecord a = await AddDomainAsync(TenantA, "example.com");
        Guid route = Ids.New();
        for (int i = 0; i < 1100; i++)
        {
            await StoreAsync(Draft(a, route, InboundActionKind.Webhook, from: "bulk@sender.test", size: 64, at: Clock.UtcNow.AddMilliseconds(i)));
        }

        Assert.Equal(1100, await Inbound.DeleteMatchingAsync(new InboundMessageQuery(TenantA, Sender: "bulk@sender.test"), default));
        Assert.Equal(new InboundUsage(0, 0, 0, 0, null), await Inbound.GetUsageAsync(TenantA, null, default));
        Assert.Empty(await ClaimActionsAsync(max: 10));
    }

    [Fact]
    public async Task Every_retry_is_a_new_generation_and_the_helo_verdict_and_the_implicit_route_are_kept()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        var auth = new InboundAuthResults(InboundVerdict.Pass, "sender.test", InboundVerdict.SoftFail, InboundVerdict.Pass, "sender.test", InboundVerdict.Pass, "none", InboundVerdict.None);
        InboundMessageDraft draft = Draft(domain, Ids.New(), InboundActionKind.Webhook, to: "postmaster@example.com", auth: auth);
        draft.RouteId = null;   // the implicit postmaster delivery has no route
        await StoreAsync(draft);

        InboundMessage stored = (await Inbound.GetAsync(TenantA, draft.Id, default))!;
        Assert.Equal((auth, null, 0), (stored.Auth, stored.RouteId, stored.RetryGeneration));

        for (int generation = 1; generation <= 3; generation++)
        {
            Assert.Single(await ClaimActionsAsync(now: Clock.UtcNow.AddHours(generation)));
            await Inbound.CompleteActionAsync(draft.Id, Owner, new InboundActionOutcome(InboundActionState.Failed, Clock.UtcNow, null, "x"), default);
            Assert.Equal(InboundRetryResult.Queued, await Inbound.RetryActionAsync(TenantA, draft.Id, Clock.UtcNow.AddHours(generation), default));
            Assert.Equal(generation, (await Inbound.GetAsync(TenantA, draft.Id, default))!.RetryGeneration);
        }
    }

    [Fact]
    public async Task A_webhook_endpoint_that_a_route_uses_cannot_be_deleted_by_the_store_itself()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        Guid endpoint = await AddEndpointAsync(TenantA, true, "*");
        InboundRouteRecord route = Route(domain, action: InboundActionKind.Webhook, endpoint: endpoint);
        await Inbound.UpsertRouteAsync(route, default);

        var inUse = await Assert.ThrowsAsync<StorageConflictException>(async () => await Storage.Config.DeleteWebhookEndpointAsync(TenantA, endpoint, default));
        Assert.Equal(StorageConflictReasons.WebhookEndpointInUse, inUse.Reason);
        Assert.NotNull(await Storage.Config.GetWebhookEndpointAsync(endpoint, default));

        // Another tenant's delete of the same id does nothing and does not fail; once the route is gone the delete works.
        await Storage.Config.DeleteWebhookEndpointAsync(TenantB, endpoint, default);
        await Inbound.DeleteRouteAsync(TenantA, route.Id, default);
        await Storage.Config.DeleteWebhookEndpointAsync(TenantA, endpoint, default);
        Assert.Null(await Storage.Config.GetWebhookEndpointAsync(endpoint, default));
    }

    [Fact]
    public async Task A_search_needs_the_tenant_and_a_query_of_one_tenant_never_sees_another()
    {
        DomainRecord a = await AddDomainAsync(TenantA, "example.com");
        DomainRecord b = await AddDomainAsync(TenantB, "other.test");
        InboundMessageDraft mine = await StoreAsync(Draft(a, Ids.New(), InboundActionKind.Store));
        InboundMessageDraft theirs = await StoreAsync(Draft(b, Ids.New(), InboundActionKind.Store));

        // Naming the other tenant's domain, route, recipient or sender does not reach their mail.
        var page = await Inbound.SearchAsync(new InboundMessageQuery(TenantA, DomainId: b.Id), default);
        Assert.Empty(page.Items);
        Assert.Equal([mine.Id], (await Inbound.SearchAsync(new InboundMessageQuery(TenantA), default)).Items.Select(m => m.Id));
        Assert.Equal([theirs.Id], (await Inbound.SearchAsync(new InboundMessageQuery(TenantB), default)).Items.Select(m => m.Id));
    }

    // Review round: completion notes, the retention/retry guard, literal search characters, cleaned client text, route endpoint check

    [Fact]
    public async Task A_done_action_can_carry_a_note_that_a_retry_clears_and_other_states_never_keep_one()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundMessageDraft draft = await StoreAsync(Draft(domain, Ids.New(), InboundActionKind.Forward));
        Assert.Single(await ClaimActionsAsync());

        Assert.True(await Inbound.CompleteActionAsync(draft.Id, Owner, new InboundActionOutcome(InboundActionState.Done, Clock.UtcNow, null, null, Note: "all targets_suppressed!"), default));
        InboundMessage done = (await Inbound.GetAsync(TenantA, draft.Id, default))!;
        Assert.Equal(("alltargets_suppressed", InboundActionState.Done), (done.ActionNote, done.ActionState));   // a code: letters, digits and underscore only

        Assert.Equal(InboundRetryResult.Queued, await Inbound.RetryActionAsync(TenantA, draft.Id, Clock.UtcNow, default));
        Assert.Null((await Inbound.GetAsync(TenantA, draft.Id, default))!.ActionNote);

        Assert.Single(await ClaimActionsAsync(now: Clock.UtcNow.AddMinutes(1)));
        await Inbound.CompleteActionAsync(draft.Id, Owner, new InboundActionOutcome(InboundActionState.Failed, Clock.UtcNow, null, "gave up", Note: "ignored"), default);
        Assert.Null((await Inbound.GetAsync(TenantA, draft.Id, default))!.ActionNote);
    }

    [Fact]
    public async Task A_second_retry_of_a_pending_action_is_refused_without_a_new_generation_or_a_lost_lease()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundMessageDraft draft = await StoreAsync(Draft(domain, Ids.New(), InboundActionKind.Webhook));
        Assert.Single(await ClaimActionsAsync());
        await Inbound.CompleteActionAsync(draft.Id, Owner, new InboundActionOutcome(InboundActionState.Failed, Clock.UtcNow, null, "x"), default);

        Assert.Equal(InboundRetryResult.Queued, await Inbound.RetryActionAsync(TenantA, draft.Id, Clock.UtcNow, default));
        Assert.Single(await ClaimActionsAsync(owner: "worker-2"));   // leased by worker-2 now
        Assert.Equal(InboundRetryResult.AlreadyPending, await Inbound.RetryActionAsync(TenantA, draft.Id, Clock.UtcNow, default));

        InboundMessage message = (await Inbound.GetAsync(TenantA, draft.Id, default))!;
        Assert.Equal(1, message.RetryGeneration);
        Assert.True(await Inbound.ExtendActionLeaseAsync(draft.Id, "worker-2", Clock.UtcNow.AddMinutes(5), default));   // still worker-2's
    }

    [Fact]
    public async Task Retention_never_deletes_a_message_that_a_retry_made_pending_and_never_its_body()
    {
        await OpenAsync(WithInbound(Opts(), 7));
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundMessageDraft old = await StoreAsync(Draft(domain, Ids.New(), InboundActionKind.Webhook, at: Clock.UtcNow.AddDays(-30)));
        Assert.Single(await ClaimActionsAsync());
        await Inbound.CompleteActionAsync(old.Id, Owner, new InboundActionOutcome(InboundActionState.Failed, Clock.UtcNow, null, "x"), default);

        // The operator retries the failed action just before the retention job runs: the old message is pending again and keeps its body.
        Assert.Equal(InboundRetryResult.Queued, await Inbound.RetryActionAsync(TenantA, old.Id, Clock.UtcNow, default));
        var reports = await Storage.Maintenance.RunAsync(Clock.UtcNow, default);
        Assert.Equal(0, Assert.Single(reports, r => r.Job == "inbound_retention").RowsAffected);
        Assert.NotNull(await Inbound.GetAsync(TenantA, old.Id, default));
        Assert.NotNull(await Inbound.GetRawAsync(TenantA, old.Id, default));
    }

    [Fact]
    public async Task Retention_and_erasure_work_through_many_batches()
    {
        await OpenAsync(WithInbound(Opts(), 7));
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        Guid route = Ids.New();
        for (int i = 0; i < 260; i++)
        {
            await StoreAsync(Draft(domain, route, InboundActionKind.Store, from: i % 2 == 0 ? "even@sender.test" : "odd@sender.test", size: 64, at: Clock.UtcNow.AddDays(-20).AddMilliseconds(i)));
        }

        InboundMessageDraft fresh = await StoreAsync(Draft(domain, route, InboundActionKind.Store, size: 64));

        // A sparse filter finds its rows among many that do not match.
        Assert.Equal(130, await Inbound.DeleteMatchingAsync(new InboundMessageQuery(TenantA, Sender: "odd@sender.test"), default));
        var reports = await Storage.Maintenance.RunAsync(Clock.UtcNow, default);
        Assert.Equal(130, Assert.Single(reports, r => r.Job == "inbound_retention").RowsAffected);
        InboundUsage usage = await Inbound.GetUsageAsync(TenantA, null, default);
        Assert.Equal((1L, (long)fresh.Raw.Length), (usage.Messages, usage.BodyBytes));
    }

    [Fact]
    public async Task A_search_takes_percent_underscore_and_backslash_literally_and_folds_only_ascii_letters()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        Guid route = Ids.New();
        async Task<Guid> Add(string subject) => (await StoreAsync(Draft(domain, route, InboundActionKind.Store, subject: subject, size: 100 + subject.Length))).Id;
        Guid percent = await Add("100% sure");
        Guid plain = await Add("1000 sure");
        Guid underscore = await Add("file_name.txt");
        Guid lookalike = await Add("fileXname.txt");
        Guid backslash = await Add(@"C:\temp\x");
        Guid umlaut = await Add("Äpfel Test");
        Guid upper = await Add("ÄPFEL");

        async Task<List<Guid>> Find(string term) => (await Inbound.SearchAsync(new InboundMessageQuery(TenantA, SubjectContains: term), default)).Items.Select(m => m.Id).OrderBy(x => x).ToList();
        static List<Guid> Sorted(params Guid[] ids) => [.. ids.OrderBy(x => x)];

        Assert.Equal(Sorted(percent), await Find("0% s"));
        Assert.Equal(Sorted(percent), await Find("%"));
        Assert.Equal(Sorted(underscore), await Find("e_n"));
        Assert.Equal(Sorted(backslash), await Find(@"\temp"));
        Assert.Equal(Sorted(plain), await Find("1000"));
        Assert.Empty(await Find("nothing like it"));

        // ASCII letters fold, everything else is compared as it is, the same on every backend.
        Assert.Equal(Sorted(upper, umlaut), await Find("Äpfel"));
        Assert.Equal(Sorted(umlaut), await Find("ÄPFEL te"));
        Assert.Empty(await Find("äpfel"));
        Assert.Equal(Sorted(upper, umlaut), await Find("ÄPFEL"));   // the term is folded like the column: "Äpfel" matches both
        Assert.Equal(Sorted(lookalike), await Find("FILEXNAME"));
    }

    [Fact]
    public async Task Client_supplied_text_is_cleaned_and_bounded()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundMessageDraft draft = Draft(domain, Ids.New(), InboundActionKind.Store);
        draft.Helo = "mail.\u0001sender\r\n.test" + new string('x', 400);
        draft.RemoteAddress = "203.0.113.9\u0000";
        draft.Auth = draft.Auth with { SpfDomain = new string('d', 300), DkimDomain = "sender\u0007.test", DmarcPolicy = " reject\n " };
        await StoreAsync(draft);

        InboundMessage stored = (await Inbound.GetAsync(TenantA, draft.Id, default))!;
        Assert.Equal(255, stored.Helo!.Length);
        Assert.StartsWith("mail.sender.testx", stored.Helo);
        Assert.Equal("203.0.113.9", stored.RemoteAddress);
        Assert.Equal((new string('d', 255), "sender.test", "reject"), (stored.Auth.SpfDomain, stored.Auth.DkimDomain, stored.Auth.DmarcPolicy));
    }

    [Fact]
    public async Task A_webhook_route_must_name_an_endpoint_of_its_tenant_in_the_same_write()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        Guid mine = await AddEndpointAsync(TenantA, true, "*");
        Guid theirs = await AddEndpointAsync(TenantB, true, "*");

        var unknown = await Assert.ThrowsAsync<StorageConflictException>(async () => await Inbound.UpsertRouteAsync(Route(domain, action: InboundActionKind.Webhook, endpoint: Ids.New()), default));
        var foreign = await Assert.ThrowsAsync<StorageConflictException>(async () => await Inbound.UpsertRouteAsync(Route(domain, action: InboundActionKind.Webhook, endpoint: theirs), default));
        Assert.Equal((StorageConflictReasons.WebhookEndpointMissing, StorageConflictReasons.WebhookEndpointMissing), (unknown.Reason, foreign.Reason));
        Assert.Empty(await Inbound.GetRoutesAsync(domain.Id, default));

        await Inbound.UpsertRouteAsync(Route(domain, action: InboundActionKind.Webhook, endpoint: mine), default);
        Assert.Single(await Inbound.GetRoutesAsync(domain.Id, default));
    }

    [Fact]
    public async Task Bidirectional_controls_are_removed_and_addresses_are_cut_at_the_path_limit()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundMessageDraft draft = Draft(domain, Ids.New(), InboundActionKind.Store, subject: "invoice \u202Efdp.exe\u2028second line\u2029third");
        draft.Helo = "good\u202E.test\u2066\u2028";
        draft.EnvelopeFrom = new string('A', 400) + "@sender.test";
        draft.EnvelopeTo = "Support@Example.com";
        await StoreAsync(draft);

        InboundMessage stored = (await Inbound.GetAsync(TenantA, draft.Id, default))!;
        Assert.Equal("good.test", stored.Helo);
        Assert.Equal("invoice fdp.exe second line third", stored.Subject);   // U+2028 and U+2029 break a line like a newline does: a space in a subject, nothing in a name
        Assert.Equal(320, stored.EnvelopeFrom.Length);
        Assert.Equal(new string('a', 320), stored.EnvelopeFrom);
        Assert.Equal("support@example.com", stored.EnvelopeTo);
    }

    [Fact]
    public async Task A_stale_completion_is_refused_after_a_release_or_a_retry_took_the_attempt_count_back_down()
    {
        DomainRecord domain = await AddDomainAsync(TenantA, "example.com");
        InboundMessageDraft draft = await StoreAsync(Draft(domain, Ids.New(), InboundActionKind.Webhook));

        // Claimed (attempt 1), released (attempt 0), claimed again by the same owner (attempt 1 again): the counts match, the tokens do not.
        var first = Assert.Single(await ClaimActionsAsync());
        Assert.Equal(1, await Inbound.ReleaseOwnedActionLeasesAsync(Owner, default));
        var second = Assert.Single(await ClaimActionsAsync());
        Assert.Equal((1, 1), (first.Message.ActionAttempts, second.Message.ActionAttempts));
        Assert.True(second.ClaimToken > first.ClaimToken);
        var done = new InboundActionOutcome(InboundActionState.Done, Clock.UtcNow, null, null);
        Assert.False(await Inbound.CompleteActionAsync(draft.Id, Owner, done with { ClaimToken = first.ClaimToken }, default));
        Assert.True(await Inbound.CompleteActionAsync(draft.Id, Owner, done with { ClaimToken = second.ClaimToken }, default));

        // A retry resets the count to 0 and the next claim of the same owner counts 1 again; the old token is still stale.
        Assert.Equal(InboundRetryResult.Queued, await Inbound.RetryActionAsync(TenantA, draft.Id, Clock.UtcNow, default));
        var third = Assert.Single(await ClaimActionsAsync());
        Assert.Equal(1, third.Message.ActionAttempts);
        Assert.True(third.ClaimToken > second.ClaimToken);
        Assert.False(await Inbound.CompleteActionAsync(draft.Id, Owner, done with { ClaimToken = second.ClaimToken }, default));
        Assert.True(await Inbound.CompleteActionAsync(draft.Id, Owner, done with { ClaimToken = third.ClaimToken }, default));
    }
}
