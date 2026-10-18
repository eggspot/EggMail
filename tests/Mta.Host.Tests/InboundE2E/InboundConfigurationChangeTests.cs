using Mta.Host.Tests.Inbound;
using Mta.Storage;

namespace Mta.Host.Tests.InboundE2E;

/// <summary>
/// Changes of the configuration the receive path decides on, made in the real stores and picked up by the cache: a suspended tenant, a domain whose verification lapses and comes back, a settings change,
/// a route that is disabled, reordered or deleted, a domain that is deleted. The cache compares a tag per domain before it rebuilds anything, so each of these must change the tag.
/// </summary>
public abstract class InboundConfigurationChangeTests(LabBackend backend)
{
    private static async Task<FakeMta.Reply> TryAsync(InboundLab lab, string recipient)
    {
        await using FakeMta mta = await lab.ConnectedAsync();
        await mta.MailFromAsync("bob@sender.test");
        return await mta.RcptAsync(recipient);
    }

    private static string Of(FakeMta.Reply r) => r.Code == 250 ? "250" : $"{r.Code} {r.Enhanced}";

    [Fact]
    public async Task Each_change_of_a_tenant_a_domain_its_settings_or_its_routes_is_seen_at_the_next_refresh_and_never_before()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { Inbound = new Mta.Host.Configuration.InboundSection { Enabled = true, CheckSpfForInternalClients = true, MaxMessagesPerMinute = 1_000_000, MaxMessagesPerMinutePerRemote = 1_000_000 } });
        if (lab is null)
        {
            return;
        }

        Assert.Equal("250", Of(await TryAsync(lab, "support@example.org")));

        // The cache is a copy: a change in the store alone is not seen until it reloads (the interval, or the API's signal).
        Tenant acme = (await lab.Storage.Config.GetTenantAsync(InboundLab.Acme, default))!;
        await lab.Storage.Config.UpsertTenantAsync(acme with { Enabled = false }, default);
        Assert.Equal("250", Of(await TryAsync(lab, "support@example.org")));
        await lab.RefreshAsync();
        Assert.Equal("450 4.2.1", Of(await TryAsync(lab, "support@example.org")));       // a suspended tenant: senders keep the mail
        Assert.Equal("250", Of(await TryAsync(lab, "anyone@example.net")));              // another tenant is not affected
        await lab.Storage.Config.UpsertTenantAsync(acme with { Enabled = true }, default);
        await lab.RefreshAsync();
        Assert.Equal("250", Of(await TryAsync(lab, "support@example.org")));

        // A domain that stops being verified: 450 for a failed or pending one, mail is kept for a domain in its grace period.
        DomainRecord org = (await lab.Storage.Config.GetDomainAsync(lab.ExampleOrg, default))!;
        foreach ((DomainStatus status, string expected) in new[] { (DomainStatus.Failed, "450 4.2.1"), (DomainStatus.TemporaryFailure, "250"), (DomainStatus.Pending, "450 4.2.1"), (DomainStatus.Verified, "250") })
        {
            await lab.Storage.Config.UpsertDomainAsync(org with { Status = status }, default);
            await lab.RefreshAsync();
            Assert.True(expected == Of(await TryAsync(lab, "support@example.org")), $"{status}");
        }

        // The settings of the domain.
        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { Enabled = false });
        Assert.Equal("550 5.7.1", Of(await TryAsync(lab, "support@example.org")));
        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { Enabled = true, MaxMessagesPerMinute = 1, MaxMessagesPerMinutePerRemote = 1 });
        await lab.AdvanceAsync(TimeSpan.FromSeconds(61));   // every accepted recipient above was counted in this minute, as a real sender's would be: start a new one
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message())).Code);
        Assert.Equal("450 4.7.1", Of(await TryAsync(lab, "support@example.org")));        // the lowered limit applies at once
        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { MaxMessagesPerMinute = null, MaxMessagesPerMinutePerRemote = null });
        await lab.AdvanceAsync(TimeSpan.FromSeconds(61));
        Assert.Equal("250", Of(await TryAsync(lab, "support@example.org")));

        // Routes: disabled, then enabled; a more specific one in front of a catch-all; a deleted one.
        InboundRouteRecord support = (await lab.Storage.Inbound.GetRouteAsync(InboundLab.Acme, lab.SupportRoute, default))!;
        await lab.Storage.Inbound.UpsertRouteAsync(support with { Enabled = false }, default);
        await lab.RefreshAsync();
        Assert.Equal("550 5.1.1", Of(await TryAsync(lab, "support@example.org")));
        await lab.Storage.Inbound.UpsertRouteAsync(support, default);
        Guid catchAll = await lab.AddRouteAsync(lab.ExampleOrg, InboundLab.Acme, 1, InboundMatchKind.CatchAll, null, InboundActionKind.Discard);   // order 1: in front of "support" (10)
        await lab.RefreshAsync();
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "caught"))).Code);
        Assert.Equal(("caught", catchAll, InboundActionKind.Discard), (await lab.MessagesAsync(InboundLab.Acme)).Where(m => m.Subject == "caught").Select(m => (m.Subject, m.RouteId.GetValueOrDefault(), m.ActionKind)).Single());
        Assert.True(await lab.Storage.Inbound.DeleteRouteAsync(InboundLab.Acme, catchAll, default));
        await lab.RefreshAsync();
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "back to support"))).Code);
        Assert.Equal(lab.SupportRoute, (await lab.MessagesAsync(InboundLab.Acme)).Single(m => m.Subject == "back to support").RouteId);

        // A deleted domain is not served at all: a name that is nobody's.
        await lab.Storage.Inbound.UpsertSettingsAsync(new InboundDomainSettings(lab.ExampleNet, InboundLab.Globex, false, InboundDmarcAction.RecordOnly, null, null, null, null, null, lab.Clock.UtcNow), default);
        await lab.Storage.Config.DeleteDomainAsync(lab.ExampleNet, default);
        await lab.RefreshAsync();
        Assert.Equal("550 5.7.1", Of(await TryAsync(lab, "anyone@example.net")));
    }

    [Fact]
    public async Task A_refresh_that_fails_keeps_the_cached_configuration_for_a_while_and_then_the_listener_answers_451_never_unknown_domain()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        Assert.Equal("250", Of(await TryAsync(lab, "support@example.org")));

        // Time passes with no refresh at all (the loop has stopped, as it would if storage were down): the cache is used for a few minutes, then the listener stops deciding on stale data.
        lab.Clock.Advance(TimeSpan.FromMinutes(4));
        Assert.Equal("250", Of(await TryAsync(lab, "support@example.org")));
        lab.Clock.Advance(TimeSpan.FromMinutes(2));
        FakeMta.Reply stale = await TryAsync(lab, "support@example.org");
        Assert.Equal((451, "4.3.0"), (stale.Code, stale.Enhanced));
        FakeMta.Reply unknown = await TryAsync(lab, "x@gmail.test");
        Assert.Equal((451, "4.3.0"), (unknown.Code, unknown.Enhanced));   // not "relay denied": a domain is never reported unknown because the list could not be loaded

        await lab.RefreshAsync();
        Assert.Equal("250", Of(await TryAsync(lab, "support@example.org")));
        Assert.Equal("550 5.7.1", Of(await TryAsync(lab, "x@gmail.test")));
    }
}

public sealed class SqliteInboundConfigurationChangeTests() : InboundConfigurationChangeTests(LabBackend.Sqlite);

public sealed class PostgresInboundConfigurationChangeTests() : InboundConfigurationChangeTests(LabBackend.Postgres);
