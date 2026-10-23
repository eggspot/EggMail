using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Tests.Api;
using Mta.Storage;
using Mta.Storage.Transfer;

namespace Mta.Host.Tests.InboundE2E;

public abstract class InboundRetentionTests(LabBackend backend)
{
    private static readonly TimeSpan Day = TimeSpan.FromDays(1);

    private static long BodyRows(InboundLab lab) =>
        lab.Storage.Transfer!.CountAsync(TransferTables.InboundRaw, TransferRange.All, default).GetAwaiter().GetResult();

    private static async Task MaintainAsync(InboundLab lab)
    {
        IReadOnlyList<MaintenanceReport> reports = await lab.Storage.Maintenance.RunAsync(lab.Clock.UtcNow, default);
        Assert.Contains(reports, r => r.Job == "inbound_retention" && r.Detail is null);
    }

    private static LabOptions Options(int defaultDays, int ceilingDays) => new()
    {
        InboundStorage = new InboundStorageOptions { RetentionDays = defaultDays, MaxRetentionDays = ceilingDays },
        Inbound = new Mta.Host.Configuration.InboundSection { Enabled = true, CheckSpfForInternalClients = true, MaxMessagesPerMinute = 1_000_000, MaxMessagesPerMinutePerRemote = 1_000_000 },
        WithApi = true,
    };

    [Fact]
    public async Task Mail_that_arrived_over_many_days_is_kept_exactly_as_long_as_the_setting_the_default_and_the_ceiling_say_and_a_pending_action_is_never_deleted()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, Options(defaultDays: 7, ceilingDays: 10));
        if (lab is null)
        {
            return;
        }

        (string Name, int? Days, int Kept)[] rules = [("default.example", null, 7), ("short.example", 2, 2), ("forever.example", 0, 10), ("long.example", 30, 10)];
        var domains = new Dictionary<string, Guid>();
        foreach ((string name, int? days, _) in rules)
        {
            Guid id = await lab.AddDomainAsync(InboundLab.Acme, name, change: s => s with { RetentionDays = days });
            await lab.AddRouteAsync(id, InboundLab.Acme, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
            domains[name] = id;
        }

        Guid waiting = await lab.AddDomainAsync(InboundLab.Acme, "waiting.example");
        await lab.AddRouteAsync(waiting, InboundLab.Acme, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Forward, ["archive@elsewhere.test"]);
        await lab.RefreshAsync();

        ApiClient api = await lab.Api!.SignedInAsync("alice");
        foreach ((string name, int? days, int kept) in rules)
        {
            Reply settings = await api.GetAsync($"/api/v1/domains/{ApiJson.Id(domains[name])}/inbound");
            Assert.Equal(kept, settings["effective"].GetProperty("retentionDays").GetInt32());
        }

        var arrivals = new Dictionary<string, List<DateTimeOffset>>();
        foreach ((string name, _, _) in rules)
        {
            arrivals[name] = [];
        }

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "x@waiting.example", InboundLab.Message(subject: "waiting"))).Code);
        int days25 = 25;
        for (int day = 0; day < days25; day++)
        {
            foreach ((string name, _, _) in rules)
            {
                DateTimeOffset arrived = lab.Clock.UtcNow;
                Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "x@" + name, InboundLab.Message(subject: $"{name} day {day}"))).Code);
                arrivals[name].Add(arrived);
            }

            await lab.AdvanceAsync(TimeSpan.FromMinutes(1));
            await MaintainAsync(lab);

            foreach ((string name, _, int kept) in rules)
            {
                int expected = arrivals[name].Count(a => lab.Clock.UtcNow - a <= TimeSpan.FromDays(kept));
                int actual = (await lab.MessagesAsync(InboundLab.Acme, new InboundMessageQuery(InboundLab.Acme, DomainId: domains[name], Limit: 200))).Count;
                Assert.True(expected == actual, $"{name} on day {day}: expected {expected} messages, found {actual}");
            }

            await lab.AdvanceAsync(Day - TimeSpan.FromMinutes(1));
        }

        InboundMessage pending = Assert.Single(await lab.MessagesAsync(InboundLab.Acme, new InboundMessageQuery(InboundLab.Acme, DomainId: waiting)));
        Assert.Equal((InboundActionState.Pending, true), (pending.ActionState, pending.HasRaw));
        Assert.NotNull(await lab.Storage.Inbound.GetRawAsync(InboundLab.Acme, pending.Id, default));
        long withBody = 0;
        foreach (InboundMessage m in await lab.MessagesAsync(InboundLab.Acme, new InboundMessageQuery(InboundLab.Acme, Limit: 200)))
        {
            withBody += m.HasRaw ? 1 : 0;
        }

        Assert.Equal(withBody, BodyRows(lab));
    }

    [Fact]
    public async Task Zero_keeps_mail_forever_when_the_operator_sets_no_ceiling_and_the_warning_says_so()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, Options(defaultDays: 7, ceilingDays: 0));
        if (lab is null)
        {
            return;
        }

        Guid forever = await lab.AddDomainAsync(InboundLab.Acme, "forever.example", change: s => s with { RetentionDays = 0 });
        await lab.AddRouteAsync(forever, InboundLab.Acme, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
        await lab.RefreshAsync();
        ApiClient api = await lab.Api!.SignedInAsync("alice");
        Reply settings = await api.GetAsync($"/api/v1/domains/{ApiJson.Id(forever)}/inbound");
        Assert.Equal(0, settings["effective"].GetProperty("retentionDays").GetInt32());
        Assert.True(settings.Json.TryGetProperty("warnings", out _), "keeping forever comes with a warning");
        Assert.Contains("forever", settings["warnings"].ToString(), StringComparison.OrdinalIgnoreCase);

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "x@forever.example", InboundLab.Message(subject: "very old"))).Code);
        for (int year = 0; year < 3; year++)
        {
            await lab.AdvanceAsync(TimeSpan.FromDays(365));
            await MaintainAsync(lab);
        }

        InboundMessage kept = Assert.Single(await lab.MessagesAsync(InboundLab.Acme, new InboundMessageQuery(InboundLab.Acme, DomainId: forever)));
        Assert.NotNull(await lab.Storage.Inbound.GetRawAsync(InboundLab.Acme, kept.Id, default));

        ApiClient later = await lab.Api.SignedInAsync("alice");
        Assert.Equal(System.Net.HttpStatusCode.OK, (await later.PatchAsync($"/api/v1/domains/{ApiJson.Id(forever)}/inbound", new { retentionDays = 1 })).Status);
        await MaintainAsync(lab);
        Assert.Empty(await lab.MessagesAsync(InboundLab.Acme, new InboundMessageQuery(InboundLab.Acme, DomainId: forever)));
        Assert.Equal(0, BodyRows(lab));
    }

    [Fact]
    public async Task A_large_purge_runs_in_batches_deletes_only_what_is_old_and_settled_and_leaves_no_body_without_a_message()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, Options(defaultDays: 7, ceilingDays: 0));
        if (lab is null)
        {
            return;
        }

        DateTimeOffset now = lab.Clock.UtcNow;
        int Count(InboundActionKind kind, int total, int ageDays, string prefix, List<InboundMessageDraft> into)
        {
            for (int i = 0; i < total; i++)
            {
                DateTimeOffset at = now.AddDays(-ageDays).AddSeconds(i);
                into.Add(new InboundMessageDraft
                {
                    Id = Ids.New(at), TenantId = InboundLab.Acme, DomainId = lab.ExampleOrg, Domain = "example.org", ReceivedAt = at, RemoteAddress = "203.0.113.9", Helo = "mail.sender.test",
                    EnvelopeFrom = "bob@sender.test", EnvelopeTo = "support@example.org", Subject = prefix + i, Auth = InboundAuthResults.NotChecked,
                    RouteId = kind == InboundActionKind.Forward ? lab.BillingRoute : lab.SupportRoute, ActionKind = kind, Raw = new byte[600 + i % 50],
                });
            }

            return total;
        }

        var drafts = new List<InboundMessageDraft>();
        Count(InboundActionKind.Store, 1_050, 30, "old stored ", drafts);
        Count(InboundActionKind.Forward, 130, 30, "old pending ", drafts);
        Count(InboundActionKind.Store, 120, 2, "recent ", drafts);
        for (int i = 0; i < drafts.Count; i += 200)
        {
            await lab.Storage.Inbound.AcceptAsync(drafts.Skip(i).Take(200).ToList(), default);
        }

        Assert.Equal(1_300, BodyRows(lab));
        await MaintainAsync(lab);

        IReadOnlyList<InboundMessage> left = await AllAsync(lab);
        Assert.Equal(130 + 120, left.Count);
        Assert.Equal(130, left.Count(m => m.Subject!.StartsWith("old pending ", StringComparison.Ordinal)));
        Assert.Equal(120, left.Count(m => m.Subject!.StartsWith("recent ", StringComparison.Ordinal)));
        Assert.Equal(left.Count, BodyRows(lab));

        await MaintainAsync(lab);
        Assert.Equal(250, (await AllAsync(lab)).Count);

        InboundUsage usage = await lab.Storage.Inbound.GetUsageAsync(InboundLab.Acme, null, default);
        Assert.Equal((250L, 130L), (usage.Messages, usage.Pending));
        Assert.Equal(left.Sum(m => m.Size), usage.BodyBytes);
    }

    private static async Task<IReadOnlyList<InboundMessage>> AllAsync(InboundLab lab)
    {
        var all = new List<InboundMessage>();
        string? cursor = null;
        do
        {
            Page<InboundMessage> page = await lab.Storage.Inbound.SearchAsync(new InboundMessageQuery(InboundLab.Acme, Limit: 200, Cursor: cursor), default);
            all.AddRange(page.Items);
            cursor = page.NextCursor;
        }
        while (cursor is not null);

        return all;
    }
}

public sealed class SqliteInboundRetentionTests() : InboundRetentionTests(LabBackend.Sqlite);

public sealed class PostgresInboundRetentionTests() : InboundRetentionTests(LabBackend.Postgres);
