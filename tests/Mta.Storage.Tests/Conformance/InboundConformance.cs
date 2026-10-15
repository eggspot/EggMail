using Mta.Core;

namespace Mta.Storage.Tests;

/// <summary>
/// Inbound mail (<see cref="IStorage.Inbound"/>, decision 92): per-domain settings and routes, received messages, route action claims and the retention job.
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
            Auth = auth ?? new InboundAuthResults(InboundVerdict.Pass, "sender.test", InboundVerdict.Pass, "sender.test", InboundVerdict.Pass, "reject", InboundVerdict.None),
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

        var first = new InboundDomainSettings(domain.Id, TenantA, true, InboundDmarcAction.QuarantineFlag, 5_000_000, 100, 10, 1L << 30, 30, Clock.UtcNow);
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
        Guid endpoint = Ids.New();
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
        Guid otherEndpoint = await AddEndpointAsync(TenantA, true, "*");
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
        var auth = new InboundAuthResults(InboundVerdict.SoftFail, "sender.test", InboundVerdict.None, null, InboundVerdict.Fail, "quarantine", InboundVerdict.Pass);
        InboundMessageDraft webhook = Draft(domain, route, InboundActionKind.Webhook, auth: auth, disposition: InboundDmarcDisposition.QuarantineFlagged, subject: "Hel\u0001lo\r\nthere");
        InboundMessageDraft forward = Draft(domain, route, InboundActionKind.Forward, size: 1600);
        InboundMessageDraft store = Draft(domain, route, InboundActionKind.Store, size: 1700);
        InboundMessageDraft discard = Draft(domain, route, InboundActionKind.Discard, size: 1800, subject: null);
        await Inbound.AcceptAsync([webhook, forward, store, discard], default);

        InboundMessage w = (await Inbound.GetAsync(TenantA, webhook.Id, default))!;
        Assert.Equal(("example.com", "support@example.com", "alice@sender.test", "Hello there", 1500L), (w.Domain, w.EnvelopeTo, w.EnvelopeFrom, w.Subject, w.Size));
        Assert.Equal(("203.0.113.9", "mail.sender.test", true, Clock.UtcNow), (w.RemoteAddress, w.Helo, w.TlsUsed, w.ReceivedAt));
        Assert.Equal(new InboundAuthResults(InboundVerdict.SoftFail, "sender.test", InboundVerdict.None, null, InboundVerdict.Fail, "quarantine", InboundVerdict.Pass), w.Auth);
        Assert.Equal((InboundDmarcDisposition.QuarantineFlagged, route, InboundActionKind.Webhook), (w.Disposition, w.RouteId, w.ActionKind));
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
        var fail = new InboundAuthResults(InboundVerdict.Fail, "x.test", InboundVerdict.Fail, null, InboundVerdict.Fail, "reject", InboundVerdict.None);

        var drafts = new List<InboundMessageDraft>();
        for (int i = 0; i < 6; i++)
        {
            Clock.Advance(TimeSpan.FromMinutes(1));
            drafts.Add(await StoreAsync(Draft(a, i % 2 == 0 ? routeOne : routeTwo, i % 2 == 0 ? InboundActionKind.Webhook : InboundActionKind.Store, to: i < 3 ? "sales@example.com" : "info@example.com",
                from: i == 5 ? "Bob@Other.Test" : "alice@sender.test", subject: i == 4 ? "Invoice 42" : "Hello " + i, size: 200 + i)));
        }

        Clock.Advance(TimeSpan.FromMinutes(1));
        InboundMessageDraft quarantined = await StoreAsync(Draft(b, routeOne, auth: fail, disposition: InboundDmarcDisposition.QuarantineFlagged, size: 300));
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
        Assert.Equal([quarantined.Id], await Ids_(new InboundMessageQuery(TenantId: TenantA, Quarantined: true)));
        Assert.Equal(6, (await Ids_(new InboundMessageQuery(TenantId: TenantA, Quarantined: false))).Count);
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
        Assert.Equal(1, await Inbound.ReleaseOwnedActionLeasesAsync(Owner, default));
        Assert.Single(await ClaimActionsAsync(owner: "worker-2"));
        Assert.Equal(0, (await Inbound.GetAsync(TenantA, draft.Id, default))!.ActionAttempts);
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
}
