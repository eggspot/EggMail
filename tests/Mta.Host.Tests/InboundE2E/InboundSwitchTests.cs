using System.Security.Cryptography;
using System.Text;
using Mta.Core;
using Mta.Host.Hosting;
using Mta.Host.Secrets;
using Mta.Host.Configuration;
using Mta.Host.Switching;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.Portability;
using Mta.Storage.Postgres;
using Mta.Storage.Postgres.Tests;
using Mta.Storage.Sqlite;
using Mta.Storage.Transfer;
using Mta.TestSupport;
using Mta.Host.Tests.Inbound;

namespace Mta.Host.Tests.InboundE2E;

public sealed class InboundSwitchTests : IAsyncLifetime
{
    private const string Passphrase = "correct horse battery staple";
    private readonly string _ownTemporaryRoot = Directory.CreateTempSubdirectory("eggmail-inbound-switch-").FullName;
    private readonly List<IAsyncDisposable> _owned = [];

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        foreach (IAsyncDisposable owned in _owned.AsEnumerable().Reverse())
        {
            await owned.DisposeAsync();
        }

        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_ownTemporaryRoot, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private sealed class Target(IStorage storage, StorageOptions options, ISecretProtector secrets, IAsyncDisposable? owner) : IAsyncDisposable
    {
        public IStorage Storage { get; } = storage;
        public StorageOptions Options { get; } = options;
        public ISecretProtector Secrets { get; } = secrets;
        public SwitchEndpoint Endpoint => new() { Storage = Storage, Secrets = Secrets, Options = Options };

        public async ValueTask DisposeAsync()
        {
            await Storage.DisposeAsync();
            if (owner is not null)
            {
                await owner.DisposeAsync();
            }
        }
    }

    private async Task<Target> NewTargetAsync(LabBackend backend, string name)
    {
        IStorage storage;
        StorageOptions options;
        IAsyncDisposable? owner = null;
        if (backend == LabBackend.Sqlite)
        {
            options = new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = Path.Combine(_ownTemporaryRoot, name), ConfigSyncMode = SqliteSyncMode.Off, StatsFlushInterval = TimeSpan.Zero } };
            storage = SqliteStorage.Create(options);
        }
        else
        {
            TestDatabase database = await PostgresTestServer.Instance.CreateDatabaseAsync();
            owner = database;
            options = new StorageOptions { Backend = StorageBackend.Postgres, Postgres = new PostgresOptions { OwnerConnectionString = database.ConnectionString, RuntimeConnectionString = database.ConnectionString, StatsFlushInterval = TimeSpan.Zero } };
            storage = PostgresStorage.Create(options, SystemClock.Instance);
        }

        await storage.InitializeAsync(default);
        var target = new Target(storage, options, SecretsFactory.Create(new SecretsSection(), storage.Config), owner);
        _owned.Add(target);
        return target;
    }

    private sealed class NoopActivator : ISwitchActivator
    {
        public Task<SwitchActivation> ActivateAsync(SwitchActivationRequest request, CancellationToken cancellationToken) =>
            Task.FromResult(new SwitchActivation(ActivationKind.CutoverPatch, "patch", "Storage__Backend=Sqlite", null));

        public Task RestoreAsync(Guid switchId, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task ForgetAsync(Guid switchId, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private static async Task<StorageSwitchEngine> SwitchAsync(SwitchEndpoint source, SwitchEndpoint target, string bundle, ISwitchHostControl? host = null)
    {
        var engine = new StorageSwitchEngine(source, target, host, new NoopActivator(), SystemClock.Instance, null, new SwitchOptions { ChunkRows = 5, DrainPollInterval = TimeSpan.FromMilliseconds(50) });
        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = bundle, Passphrase = Passphrase, QuiesceTimeout = TimeSpan.FromMilliseconds(200) }, null, default);
        await engine.ExportAsync(new BundleRequest { BundlePath = bundle, Passphrase = Passphrase }, null, default);
        await engine.ImportAsync(new ImportRequest { BundlePath = bundle, Passphrase = Passphrase }, null, default);
        VerifyReport report = await engine.VerifyAsync(new BundleRequest { BundlePath = bundle, Passphrase = Passphrase }, null, default);
        Assert.True(report.Ok, string.Join("; ", report.Problems));
        await engine.ConfirmAsync(default);
        Assert.True(await TargetActivation.ActivateAsync(target.Storage.Transfer!, SystemClock.Instance, default));
        return engine;
    }

    private sealed record Snapshot(IReadOnlyList<string> Messages, IReadOnlyList<string> Settings, IReadOnlyList<string> Routes, long BodyBytes, long Pending);

    private static async Task<Snapshot> SnapshotAsync(IStorage storage, params (Guid Tenant, Guid[] Domains)[] tenants)
    {
        var messages = new List<string>();
        var settings = new List<string>();
        var routes = new List<string>();
        long bytes = 0, pending = 0;
        foreach ((Guid tenant, Guid[] domains) in tenants)
        {
            string? cursor = null;
            do
            {
                Page<InboundMessage> page = await storage.Inbound.SearchAsync(new InboundMessageQuery(tenant, Limit: 200, Cursor: cursor), default);
                foreach (InboundMessage m in page.Items)
                {
                    byte[]? raw = await storage.Inbound.GetRawAsync(tenant, m.Id, default);
                    string digest = raw is null ? "no body" : Convert.ToHexString(SHA256.HashData(raw));
                    messages.Add($"{m.Id:N}|{m.DomainId:N}|{m.Domain}|{m.ReceivedAt:O}|{m.RemoteAddress}|{m.Helo}|{m.TlsUsed}|{m.EnvelopeFrom}|{m.EnvelopeTo}|{m.Subject}|{m.Size}|{m.Auth}|{m.Disposition}|{m.RouteId:N}|{m.ActionKind}|{m.ActionState}|{m.ActionAttempts}|{m.RetryGeneration}|{m.HasRaw}|{digest}");
                }

                cursor = page.NextCursor;
            }
            while (cursor is not null);

            foreach (Guid domain in domains)
            {
                InboundDomainSettings? s = await storage.Inbound.GetSettingsAsync(domain, default);
                settings.Add($"{domain:N}|{s}");
                foreach (InboundRouteRecord r in await storage.Inbound.GetRoutesAsync(domain, default))
                {
                    routes.Add($"{r.Id:N}|{r.Name}|{r.Order}|{r.Enabled}|{r.MatchKind}|{r.LocalPart}|{r.PlusAddressing}|{r.ActionKind}|{r.WebhookFormat}|{string.Join(',', r.ForwardTo)}");
                }
            }

            InboundUsage usage = await storage.Inbound.GetUsageAsync(tenant, null, default);
            bytes += usage.BodyBytes;
            pending += usage.Pending;
        }

        return new Snapshot(messages, settings, routes, bytes, pending);
    }

    private static async Task ReceiveManyAsync(InboundLab lab)
    {
        lab.PublishSpf("sender.test");
        lab.PublishDmarc("sender.test", "reject");
        lab.PublishSpf("other.test", authorize: false);
        lab.PublishDmarc("other.test", "reject");
        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { RetentionDays = 30, MaxMessagesPerMinute = 500, DmarcAction = InboundDmarcAction.Flag });
        string unicodeSubject = "Grüße – 日本語 😀";
        string[] bodies = [new string('a', 300_000), "plain\r\n", string.Concat(Enumerable.Range(0, 2_000).Select(i => $"line {i}\r\n"))];
        int n = 0;
        foreach (string body in bodies)
        {
            Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "support " + n++, body: body + "\r\n"))).Code);
        }

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "billing-1@example.org", InboundLab.Message(subject: "to be forwarded"))).Code);
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "old@example.org", InboundLab.Message(subject: "discarded"))).Code);
        Assert.Equal(250, (await lab.SendAsync("eve@other.test", "support@example.org", InboundLab.Message(from: "eve@other.test", subject: "flagged"))).Code);
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "anyone@example.net", InboundLab.Message(subject: unicodeSubject))).Code);
        Assert.Equal(250, (await lab.SendAsync("", "postmaster@example.org", InboundLab.Message(from: "MAILER-DAEMON@sender.test", subject: "postmaster, null sender"))).Code);
        await using FakeMta both = await lab.ConnectedAsync();
        Assert.Equal(250, (await both.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await both.RcptAsync("support@example.org")).Code);
        Assert.Equal(250, (await both.RcptAsync("anyone@example.net")).Code);
        Assert.Equal(250, (await both.DataAsync(InboundLab.Message(subject: "two tenants"))).Code);
    }

    [Fact]
    public async Task Received_mail_makes_the_round_trip_sqlite_postgresql_sqlite_unchanged_and_its_pending_action_runs_only_on_the_active_side()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(LabBackend.Sqlite);
        if (lab is null || !PostgresPromise.Available())
        {
            return;
        }

        await ReceiveManyAsync(lab);
        var tenants = new (Guid, Guid[])[] { (InboundLab.Acme, [lab.ExampleOrg]), (InboundLab.Globex, [lab.ExampleNet]) };
        Snapshot original = await SnapshotAsync(lab.Storage, tenants);
        Assert.Equal(1, original.Pending);
        Assert.Equal(10, original.Messages.Count);

        Target postgres = await NewTargetAsync(LabBackend.Postgres, "pg");
        var source = new SwitchEndpoint { Storage = lab.Storage, Secrets = lab.Runtime.Secrets, Options = lab.StorageOptions };
        await SwitchAsync(source, postgres.Endpoint, Path.Combine(_ownTemporaryRoot, "bundle1"));

        Snapshot onPostgres = await SnapshotAsync(postgres.Storage, tenants);
        Assert.Equal(original.Messages, onPostgres.Messages);
        Assert.Equal(original.Settings, onPostgres.Settings);
        Assert.Equal(original.Routes, onPostgres.Routes);
        Assert.Equal((original.BodyBytes, original.Pending), (onPostgres.BodyBytes, onPostgres.Pending));
        Assert.Empty(await lab.Storage.Inbound.ClaimActionsAsync("old-side", 10, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default));
        InboundDraftProbe.AssertFenced(lab);
        var claimed = await postgres.Storage.Inbound.ClaimActionsAsync("new-side", 10, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default);
        ClaimedInboundAction action = Assert.Single(claimed);
        Assert.Equal(("to be forwarded", InboundActionKind.Forward), (action.Message.Subject, action.Message.ActionKind));
        Assert.NotNull(action.Raw);
        Assert.Empty(await postgres.Storage.Inbound.ClaimActionsAsync("new-side-2", 10, DateTimeOffset.UtcNow.AddDays(3), TimeSpan.FromMinutes(1), default));
        Assert.True(await postgres.Storage.Inbound.ReleaseOwnedActionLeasesAsync("new-side", default) >= 1);

        Target back = await NewTargetAsync(LabBackend.Sqlite, "back");
        await SwitchAsync(postgres.Endpoint, back.Endpoint, Path.Combine(_ownTemporaryRoot, "bundle2"));
        Snapshot afterwards = await SnapshotAsync(back.Storage, tenants);
        Assert.Equal(original.Messages, afterwards.Messages);
        Assert.Equal(original.Settings, afterwards.Settings);
        Assert.Equal(original.Routes, afterwards.Routes);
        Assert.Equal((original.BodyBytes, original.Pending), (afterwards.BodyBytes, afterwards.Pending));

        Assert.Equal(1, await back.Storage.Inbound.DeleteMatchingAsync(new InboundMessageQuery(InboundLab.Acme, SubjectContains: "discarded"), default));
    }

    private static class InboundDraftProbe
    {
        public static void AssertFenced(InboundLab lab)
        {
            var draft = new InboundMessageDraft
            {
                Id = Ids.New(), TenantId = InboundLab.Acme, DomainId = lab.ExampleOrg, Domain = "example.org", ReceivedAt = DateTimeOffset.UtcNow, RemoteAddress = "203.0.113.9",
                EnvelopeFrom = "a@b.test", EnvelopeTo = "support@example.org", Auth = InboundAuthResults.NotChecked, ActionKind = InboundActionKind.Store, Raw = new byte[10],
            };
            Assert.ThrowsAsync<StorageFencedException>(async () => await lab.Storage.Inbound.AcceptAsync([draft], default)).GetAwaiter().GetResult();
        }
    }

    [Fact]
    public async Task A_switch_in_the_middle_of_traffic_tells_senders_to_come_back_and_loses_and_doubles_nothing()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(LabBackend.Sqlite);
        if (lab is null)
        {
            return;
        }

        var state = new SwitchRuntimeState(StartupDecision.Normal);
        var control = new HostSwitchControl(lab.Runtime, state);
        Target target = await NewTargetAsync(LabBackend.Sqlite, "target");
        var source = new SwitchEndpoint { Storage = lab.Storage, Secrets = lab.Runtime.Secrets, Options = lab.StorageOptions };
        var engine = new StorageSwitchEngine(source, target.Endpoint, control, new NoopActivator(), SystemClock.Instance, null, new SwitchOptions { ChunkRows = 5, DrainPollInterval = TimeSpan.FromMilliseconds(50) });

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "before"))).Code);

        await using FakeMta inFlight = await lab.ConnectedAsync();
        Assert.Equal(250, (await inFlight.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await inFlight.RcptAsync("support@example.org")).Code);
        string message = InboundLab.Message(subject: "during the switch");

        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, BundlePath = Path.Combine(_ownTemporaryRoot, "bundle"), Passphrase = Passphrase, QuiesceTimeout = TimeSpan.FromMilliseconds(200) }, null, default);

        FakeMta.Reply deferred = await inFlight.DataAsync(message);
        Assert.Equal(4, deferred.Code / 100);
        await using (FakeMta late = await FakeMta.ConnectAsync(lab.Port, expectGreeting: false))
        {
            Assert.Equal(421, (await late.ReadReplyAsync()).Code);
        }

        Assert.Equal(["before"], (await lab.MessagesAsync(InboundLab.Acme)).Select(m => m.Subject!).ToArray());

        await engine.RollbackAsync(sourceOnly: true, default);
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", message)).Code);
        Assert.Equal(["before", "during the switch"], (await lab.MessagesAsync(InboundLab.Acme)).Select(m => m.Subject!).Order(StringComparer.Ordinal).ToArray());
        Assert.True(state.AcceptingApi);
    }
}
