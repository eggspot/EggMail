using Mta.Host.Tests.Inbound;
using Mta.Storage;

namespace Mta.Host.Tests.InboundE2E;

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

        Tenant acme = (await lab.Storage.Config.GetTenantAsync(InboundLab.Acme, default))!;
        await lab.Storage.Config.UpsertTenantAsync(acme with { Enabled = false }, default);
        Assert.Equal("250", Of(await TryAsync(lab, "support@example.org")));
        await lab.RefreshAsync();
        Assert.Equal("450 4.2.1", Of(await TryAsync(lab, "support@example.org")));
        Assert.Equal("250", Of(await TryAsync(lab, "anyone@example.net")));
        await lab.Storage.Config.UpsertTenantAsync(acme with { Enabled = true }, default);
        await lab.RefreshAsync();
        Assert.Equal("250", Of(await TryAsync(lab, "support@example.org")));

        DomainRecord org = (await lab.Storage.Config.GetDomainAsync(lab.ExampleOrg, default))!;
        foreach ((DomainStatus status, string expected) in new[] { (DomainStatus.Failed, "450 4.2.1"), (DomainStatus.TemporaryFailure, "250"), (DomainStatus.Pending, "450 4.2.1"), (DomainStatus.Verified, "250") })
        {
            await lab.Storage.Config.UpsertDomainAsync(org with { Status = status }, default);
            await lab.RefreshAsync();
            Assert.True(expected == Of(await TryAsync(lab, "support@example.org")), $"{status}");
        }

        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { Enabled = false });
        Assert.Equal("550 5.7.1", Of(await TryAsync(lab, "support@example.org")));
        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { Enabled = true, MaxMessagesPerMinute = 1, MaxMessagesPerMinutePerRemote = 1 });
        await lab.AdvanceAsync(TimeSpan.FromSeconds(61));
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message())).Code);
        Assert.Equal("450 4.7.1", Of(await TryAsync(lab, "support@example.org")));
        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { MaxMessagesPerMinute = null, MaxMessagesPerMinutePerRemote = null });
        await lab.AdvanceAsync(TimeSpan.FromSeconds(61));
        Assert.Equal("250", Of(await TryAsync(lab, "support@example.org")));

        InboundRouteRecord support = (await lab.Storage.Inbound.GetRouteAsync(InboundLab.Acme, lab.SupportRoute, default))!;
        await lab.Storage.Inbound.UpsertRouteAsync(support with { Enabled = false }, default);
        await lab.RefreshAsync();
        Assert.Equal("550 5.1.1", Of(await TryAsync(lab, "support@example.org")));
        await lab.Storage.Inbound.UpsertRouteAsync(support, default);
        Guid catchAll = await lab.AddRouteAsync(lab.ExampleOrg, InboundLab.Acme, 1, InboundMatchKind.CatchAll, null, InboundActionKind.Discard);
        await lab.RefreshAsync();
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "caught"))).Code);
        Assert.Equal(("caught", catchAll, InboundActionKind.Discard), (await lab.MessagesAsync(InboundLab.Acme)).Where(m => m.Subject == "caught").Select(m => (m.Subject, m.RouteId.GetValueOrDefault(), m.ActionKind)).Single());
        Assert.True(await lab.Storage.Inbound.DeleteRouteAsync(InboundLab.Acme, catchAll, default));
        await lab.RefreshAsync();
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "back to support"))).Code);
        Assert.Equal(lab.SupportRoute, (await lab.MessagesAsync(InboundLab.Acme)).Single(m => m.Subject == "back to support").RouteId);

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

        lab.Clock.Advance(TimeSpan.FromMinutes(4));
        Assert.Equal("250", Of(await TryAsync(lab, "support@example.org")));
        lab.Clock.Advance(TimeSpan.FromMinutes(2));
        FakeMta.Reply stale = await TryAsync(lab, "support@example.org");
        Assert.Equal((451, "4.3.0"), (stale.Code, stale.Enhanced));
        FakeMta.Reply unknown = await TryAsync(lab, "x@gmail.test");
        Assert.Equal((451, "4.3.0"), (unknown.Code, unknown.Enhanced));

        await lab.RefreshAsync();
        Assert.Equal("250", Of(await TryAsync(lab, "support@example.org")));
        Assert.Equal("550 5.7.1", Of(await TryAsync(lab, "x@gmail.test")));
    }
}

public sealed class SqliteInboundConfigurationChangeTests() : InboundConfigurationChangeTests(LabBackend.Sqlite);

public sealed class PostgresInboundConfigurationChangeTests() : InboundConfigurationChangeTests(LabBackend.Postgres);
