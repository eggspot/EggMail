using Mta.Core;
using Mta.TestSupport;

namespace Mta.Storage.Tests;

// Inbound mail (decision 95): retention of received messages over many virtual days. A backend that does not implement inbound mail yet
// (IStorage.Inbound throws NotSupportedException) returns at once; the shared InboundConformance has the single-boundary facts.

public abstract partial class LifecycleConformance
{
    private bool SupportsInbound()
    {
        try
        {
            _ = Storage.Inbound;
            return true;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }

    private async Task<DomainRecord> InboundDomainAsync(string name, int? retentionDays)
    {
        if (await Storage.Config.GetTenantAsync(TenantA, default) is null)
        {
            await Storage.Config.UpsertTenantAsync(new Tenant(TenantA, "Tenant A", "tenant-a", true, Clock.UtcNow, false), default);
        }

        var domain = new DomainRecord(Ids.New(), TenantA, name, DomainStatus.Verified, null, false, Clock.UtcNow, null, null, 0, null, false, null);
        await Storage.Config.UpsertDomainAsync(domain, default);
        await Storage.Inbound.UpsertSettingsAsync(
            new InboundDomainSettings(domain.Id, TenantA, true, InboundDmarcAction.RecordOnly, null, null, null, null, retentionDays, Clock.UtcNow), default);
        return domain;
    }

    private InboundMessageDraft InboundDraft(DomainRecord domain, DateTimeOffset at, InboundActionKind kind) => new()
    {
        Id = Ids.New(at),
        TenantId = domain.TenantId,
        DomainId = domain.Id,
        Domain = domain.Name,
        ReceivedAt = at,
        RemoteAddress = "203.0.113.9",
        Helo = "mail.sender.test",
        TlsUsed = true,
        EnvelopeFrom = "alice@sender.test",
        EnvelopeTo = "support@" + domain.Name,
        Subject = "Hello",
        Auth = new InboundAuthResults(InboundVerdict.Pass, "sender.test", InboundVerdict.None, InboundVerdict.Pass, "sender.test", InboundVerdict.Pass, "reject", InboundVerdict.None),
        Disposition = InboundDmarcDisposition.None,
        RouteId = Guid.Empty,
        ActionKind = kind,
        Raw = new byte[512],
    };

    private async Task<int> InboundCountAsync(DomainRecord domain)
    {
        int count = 0;
        string? cursor = null;
        do
        {
            Page<InboundMessage> page = await Storage.Inbound.SearchAsync(new InboundMessageQuery(TenantA, DomainId: domain.Id, Limit: 200, Cursor: cursor), default);
            count += page.Items.Count;
            cursor = page.NextCursor;
        }
        while (cursor is not null);

        return count;
    }

    [Fact]
    public async Task Lifecycle_inbound_mail_is_kept_for_the_domain_setting_the_default_and_the_ceiling_and_a_pending_action_is_never_removed()
    {
        await OpenAsync(WithInbound(Opts(), retentionDays: 7, maxRetentionDays: 10));
        if (!SupportsInbound())
        {
            return;
        }

        DomainRecord byDefault = await InboundDomainAsync("default.example", null);   // 7 days
        DomainRecord shortLived = await InboundDomainAsync("short.example", 2);
        DomainRecord forever = await InboundDomainAsync("forever.example", 0);        // "forever" becomes the 10 day ceiling
        DomainRecord tooLong = await InboundDomainAsync("long.example", 30);          // cut to the ceiling
        (DomainRecord Domain, int Days)[] rules = [(byDefault, 7), (shortLived, 2), (forever, 10), (tooLong, 10)];

        int days = Accelerated.Scaled(40);
        var arrivals = new List<DateTimeOffset>();
        InboundMessageDraft pending = InboundDraft(byDefault, Clock.UtcNow.AddMinutes(-1), InboundActionKind.Webhook);   // its webhook never runs
        await Storage.Inbound.AcceptAsync([pending], default);

        for (int day = 0; day < days; day++)
        {
            // One message per domain a minute before the daily run, so its age is a whole number of days plus a minute at every later run.
            DateTimeOffset arrived = Clock.UtcNow.AddMinutes(-1);
            await Storage.Inbound.AcceptAsync(rules.Select(r => InboundDraft(r.Domain, arrived, InboundActionKind.Store)).ToList(), default);
            arrivals.Add(arrived);
            await MaintainAsync();

            foreach ((DomainRecord domain, int keepDays) in rules)
            {
                int expected = arrivals.Count(a => Clock.UtcNow - a <= TimeSpan.FromDays(keepDays));
                int actual = await InboundCountAsync(domain);
                if (domain == byDefault)
                {
                    expected += 1;   // the pending webhook is protected whatever its age
                }

                Assert.True(expected == actual, $"{domain.Name} on day {day}: expected {expected} messages, found {actual}");
            }

            Clock.Advance(Day);
        }

        Assert.NotNull(await Storage.Inbound.GetAsync(TenantA, pending.Id, default));
        Assert.True(JobRows.GetValueOrDefault("inbound_retention") > 0);
    }

    [Fact]
    public async Task Lifecycle_inbound_mail_is_kept_forever_when_neither_the_default_nor_a_ceiling_is_set()
    {
        await OpenAsync(WithInbound(Opts(), retentionDays: 0));
        if (!SupportsInbound())
        {
            return;
        }

        DomainRecord domain = await InboundDomainAsync("keep.example", null);
        int days = Accelerated.Scaled(60);
        for (int day = 0; day < days; day++)
        {
            await Storage.Inbound.AcceptAsync([InboundDraft(domain, Clock.UtcNow.AddMinutes(-1), InboundActionKind.Store)], default);
            await MaintainAsync();
            Clock.Advance(Day);
        }

        Assert.Equal(days, await InboundCountAsync(domain));
        Assert.Equal(0, JobRows.GetValueOrDefault("inbound_retention"));
        StorageHealth health = await Storage.Maintenance.GetHealthAsync(default);
        Assert.Contains("retention_unlimited:Inbound:RetentionDays", health.Warnings);
    }
}
