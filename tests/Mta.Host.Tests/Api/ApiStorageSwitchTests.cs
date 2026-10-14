using System.Net;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Host.Switching;
using Mta.Storage;
using Mta.Storage.Portability;

namespace Mta.Host.Tests.Api;

/// <summary>The admin switch endpoints over the real <see cref="StorageSwitchService"/> and engine, SQLite to SQLite in temp directories.</summary>
[Collection("api")]
public class ApiStorageSwitchTests : IAsyncLifetime
{
    private const string Base = "/api/v1/admin/storage/switch";
    private readonly string _root = Directory.CreateTempSubdirectory("eggmail-api-switch-").FullName;
    private ApiFixture _f = null!;
    private ApiClient _admin = null!;
    private string TargetPath(string name = "target") => Path.Combine(_root, name);

    private sealed class Resolver : ISwitchTargetResolver
    {
        public ResolvedSwitchTarget Resolve(SwitchRequestModel request) =>
            request.To == "sqlite"
                ? new ResolvedSwitchTarget(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = request.Target!.Path!, StatsFlushInterval = TimeSpan.Zero } }, new SecretsSection())
                : throw new StorageSwitchException(StorageSwitchError.Invalid, "Only sqlite targets exist in this test.", "to");

        public ResolvedSwitchTarget? ResolveFormerSource(StorageBackend formerBackend) => null;
    }

    private sealed class Activator : ISwitchActivator
    {
        public Task<SwitchActivation> ActivateAsync(SwitchActivationRequest request, CancellationToken cancellationToken) =>
            Task.FromResult(new SwitchActivation(ActivationKind.CutoverPatch, "apply the patch", "Storage__Backend=Sqlite\nSqlite__DataDirectory=" + request.Target.Sqlite.DataDirectory, null));

        public Task RestoreAsync(Guid switchId, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task ForgetAsync(Guid switchId, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync(new ApiFixtureOptions
        {
            ConfigureServices = s =>
            {
                s.AddSingleton<ISwitchTargetResolver, Resolver>();
                s.AddSingleton<ISwitchActivator, Activator>();
                s.AddSingleton<IStorageSwitchService>(sp => new StorageSwitchService(
                    sp.GetRequiredService<IStorage>(), sp.GetRequiredService<StorageOptions>(), sp.GetRequiredService<ISecretProtector>(), sp.GetRequiredService<IClock>(),
                    sp.GetRequiredService<ISwitchTargetResolver>(), sp.GetRequiredService<ISwitchActivator>(), null,
                    new StorageSwitchServiceOptions { BundleDirectory = Path.Combine(_root, "bundles"), SourceKeysProtectedAtRest = false, QuiesceTimeout = TimeSpan.FromMilliseconds(100), DrainPollInterval = TimeSpan.FromMilliseconds(50) }));
            },
        });
        _admin = await _f.SignedInAsync("root");

        // Something to move: a DKIM key (a secret), a queued message.
        DomainRecord domain = (await _f.Storage.Config.GetDomainsAsync(null, default))[0];
        await _f.Storage.Config.AddDkimKeyAsync(new DkimKeyRecord(Ids.New(), domain.Id, "egg1", _f.Protector.Protect("dkim"u8, SecretPurposes.DkimKey), "PUB", _f.Clock.UtcNow, true, null), default);
        await _f.Storage.Intake.AcceptAsync(new AcceptedMessage
        {
            MessageId = Ids.New(_f.Clock.UtcNow), TenantId = ApiFixture.TenantAId, Source = MessageSource.Api, EnvelopeFrom = EmailAddress.Parse("a@example.com"),
            Recipients = [new AcceptedRecipient(Ids.New(_f.Clock.UtcNow), EmailAddress.Parse("b@example.org"))], Raw = "Subject: x\r\n\r\nbody\r\n"u8.ToArray(),
            ReceivedAt = _f.Clock.UtcNow, ExpiresAt = _f.Clock.UtcNow.AddDays(5), Content = new MessageContent("x", "body", null, [], false),
        }, default);
    }

    public async Task DisposeAsync()
    {
        await _f.DisposeAsync();
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    private object Body(string name = "target", string mode = "quiesce", bool start = false)
    {
        object target = new { path = TargetPath(name) };
        string[] include = mode == "quiesce" ? ["queue", "history"] : ["history"];
        return start
            ? new { to = "sqlite", target, include, mode, exportPassphrase = "correct horse battery", confirmation = "switch to sqlite" }
            : new { to = "sqlite", target, include, mode };
    }

    private async Task MakeBusyTargetAsync(string name)
    {
        await using var busy = Mta.Storage.Sqlite.SqliteStorage.Create(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = TargetPath(name), StatsFlushInterval = TimeSpan.Zero } });
        await busy.InitializeAsync(default);
        await busy.Config.UpsertTenantAsync(new Tenant(Ids.New(), "Existing", "existing", true, DateTimeOffset.UtcNow, false), default);
    }

    // Generous: a switch is CPU-bound (RSA key, PKCS#12 with 600,000 iterations, three times) and shares a two-core CI runner with other test projects.
    private async Task<Reply> UntilAsync(string state, int seconds = 180)
    {
        DateTime deadline = DateTime.UtcNow.AddSeconds(seconds);
        Reply last;
        do
        {
            last = await _admin.GetAsync(Base);
            if (last.Str("state") == state || last.Str("state") == "failed")
            {
                break;
            }

            await Task.Delay(100);
        }
        while (DateTime.UtcNow < deadline);
        Assert.True(last.Str("state") == state, $"state {last.Str("state")}: {last.Body}");
        return last;
    }

    [Fact]
    public async Task Only_administrators_may_use_the_switch_endpoints()
    {
        ApiClient alice = await _f.SignedInAsync("alice");
        (await alice.GetAsync(Base)).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await alice.PostAsync(Base + "/preflight", Body())).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await alice.PostAsync(Base + "/start", Body(start: true))).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await alice.PostAsync(Base + "/rollback")).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await _f.NewClient().GetAsync(Base)).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        (await (await _f.KeyClientAsync(ApiFixture.TenantAId)).PostAsync(Base + "/preflight", Body())).Problem(HttpStatusCode.Forbidden, "forbidden");
    }

    [Fact]
    public async Task Preflight_reports_the_checks_counts_and_what_does_not_carry_over()
    {
        Reply pre = await _admin.PostAsync(Base + "/preflight", Body());
        Assert.Equal(HttpStatusCode.OK, pre.Status);
        Assert.True(pre["ok"].GetBoolean());
        Assert.Contains(pre["checks"].EnumerateArray(), c => c.GetProperty("name").GetString() == "target-empty" && c.GetProperty("ok").GetBoolean());
        Assert.Equal(1, pre["counts"].GetProperty("queuedMessages").GetInt64());
        Assert.NotEmpty(pre["notCarried"].EnumerateArray());
        Assert.True(pre["estimate"].GetProperty("unverified").GetBoolean());

        // A target that already holds data is reported, not refused with an exception.
        await MakeBusyTargetAsync("busy");
        Reply own = await _admin.PostAsync(Base + "/preflight", Body("busy"));
        Assert.False(own["ok"].GetBoolean());
        Assert.Contains(own["checks"].EnumerateArray(), c => !c.GetProperty("ok").GetBoolean() && c.GetProperty("severity").GetString() == "error");

        (await _admin.PostAsync(Base + "/preflight", new { to = "postgres", target = new { host = "db", database = "egg" }, include = new[] { "history" }, mode = "quiesce" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task The_whole_switch_runs_through_the_api_and_a_rollback_leaves_the_source_working()
    {
        Assert.Equal("none", (await _admin.GetAsync(Base)).Str("state"));

        Reply start = await _admin.PostAsync(Base + "/start", Body(start: true));
        Assert.Equal(HttpStatusCode.Accepted, start.Status);
        Assert.Contains(start.Str("state"), new[] { "quiescing", "exporting", "importing", "verified" });
        Assert.Equal("sqlite", start["direction"].GetProperty("to").GetString());
        Assert.DoesNotContain("correct horse battery", start.Body);

        Reply verified = await UntilAsync("verified");
        Assert.True(verified["verifyReport"].GetProperty("ok").GetBoolean());
        Assert.True(verified["verifyReport"].GetProperty("checksumsOk").GetBoolean());
        Assert.Contains(verified["verifyReport"].GetProperty("tables").EnumerateArray(), t => t.GetProperty("table").GetString() == "dkim_key" && t.GetProperty("expected").GetInt64() == 1 && t.GetProperty("actual").GetInt64() == 1);
        Assert.DoesNotContain("correct horse battery", verified.Body);

        // The instance is closed to new mail while the switch is pending.
        await Assert.ThrowsAsync<Mta.Storage.Transfer.StorageFencedException>(async () => await _f.Storage.Intake.AcceptAsync(new AcceptedMessage
        {
            MessageId = Ids.New(_f.Clock.UtcNow), TenantId = ApiFixture.TenantAId, Source = MessageSource.Api, EnvelopeFrom = EmailAddress.Parse("a@example.com"),
            Recipients = [new AcceptedRecipient(Ids.New(_f.Clock.UtcNow), EmailAddress.Parse("c@example.org"))], Raw = "Subject: y\r\n\r\n"u8.ToArray(), ReceivedAt = _f.Clock.UtcNow, ExpiresAt = _f.Clock.UtcNow.AddDays(5),
        }, default));

        Assert.Equal("confirmed", (await _admin.PostAsync(Base + "/confirm")).Str("state"));
        Reply activated = await _admin.PostAsync(Base + "/activate");
        Assert.Equal("active", activated.Str("state"));
        Assert.Contains("Sqlite__DataDirectory=" + TargetPath(), activated["cutoverPatch"].GetProperty("text").GetString());
        Assert.True(activated["orchestratorManaged"].GetBoolean());

        // The target is not active before the application restarts on it: finalize and a second start are refused.
        (await _admin.PostAsync(Base + "/finalize")).Problem(HttpStatusCode.Conflict, "conflict");
        (await _admin.PostAsync(Base + "/start", Body(name: "other", start: true))).Problem(HttpStatusCode.Conflict, "conflict");

        Reply rolled = await _admin.PostAsync(Base + "/rollback");
        Assert.Equal("rolled_back", rolled.Str("state"));
        Assert.Single(await _f.Storage.Deliveries.ClaimAsync("w", 10, _f.Clock.UtcNow.AddMinutes(1), TimeSpan.FromMinutes(1), default));
        await _f.Storage.Intake.AcceptAsync(new AcceptedMessage
        {
            MessageId = Ids.New(_f.Clock.UtcNow), TenantId = ApiFixture.TenantAId, Source = MessageSource.Api, EnvelopeFrom = EmailAddress.Parse("a@example.com"),
            Recipients = [new AcceptedRecipient(Ids.New(_f.Clock.UtcNow), EmailAddress.Parse("d@example.org"))], Raw = "Subject: z\r\n\r\n"u8.ToArray(), ReceivedAt = _f.Clock.UtcNow, ExpiresAt = _f.Clock.UtcNow.AddDays(5),
        }, default); // accepts again

        // Afterwards a new switch can be started.
        Assert.Equal(HttpStatusCode.Accepted, (await _admin.PostAsync(Base + "/start", Body(name: "second", start: true))).Status);
        await UntilAsync("verified");
    }

    [Fact]
    public async Task Steps_in_the_wrong_state_are_conflicts_and_bad_targets_are_validation_errors()
    {
        foreach (string step in new[] { "confirm", "activate", "rollback", "finalize" })
        {
            Reply r = await _admin.PostAsync(Base + "/" + step);
            r.Problem(HttpStatusCode.Conflict, "conflict");
            Assert.Matches("no backend switch is in progress|not running on the target", r.Json.GetProperty("detail").GetString());
        }

        // A target that is not empty is refused at start with the reason (400, field target), and nothing is changed.
        await MakeBusyTargetAsync("busy");
        Reply refused = await _admin.PostAsync(Base + "/start", Body("busy", start: true));
        refused.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["target"], refused.ErrorFields);
        Assert.Equal("none", (await _admin.GetAsync(Base)).Str("state"));

        Assert.Equal(HttpStatusCode.Accepted, (await _admin.PostAsync(Base + "/start", Body(start: true))).Status);
        await UntilAsync("verified");
        (await _admin.PostAsync(Base + "/activate")).Problem(HttpStatusCode.Conflict, "conflict"); // not confirmed yet
        Assert.Equal(HttpStatusCode.OK, (await _admin.PostAsync(Base + "/confirm")).Status);
        (await _admin.PostAsync(Base + "/confirm")).Problem(HttpStatusCode.Conflict, "conflict"); // twice
        Reply start2 = await _admin.PostAsync(Base + "/start", Body(name: "x", start: true));
        start2.Problem(HttpStatusCode.Conflict, "conflict");
        Assert.Contains("already in progress", start2.Json.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task A_drain_waits_for_the_queue_and_the_status_shows_it()
    {
        Reply start = await _admin.PostAsync(Base + "/start", Body(mode: "drain", start: true));
        Assert.Equal(HttpStatusCode.Accepted, start.Status);
        await UntilAsync("draining");   // one message is still queued, so the switch stays in this state
        Assert.Equal("draining", (await _admin.GetAsync(Base)).Str("state"));

        // Deliver it (what the scheduler would do), and the switch continues by itself.
        foreach (ClaimedDelivery d in await _f.Storage.Deliveries.ClaimAsync("w", 10, _f.Clock.UtcNow.AddMinutes(1), TimeSpan.FromMinutes(1), default))
        {
            await _f.Storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = _f.Clock.UtcNow, SmtpCode = 250 }, default);
        }

        await UntilAsync("verified");
        Assert.Equal("drain", (await _admin.GetAsync(Base)).Str("mode"));
    }

    [Fact]
    public async Task A_closed_instance_answers_mail_requests_with_503_and_retry_after()
    {
        Assert.Equal(HttpStatusCode.Accepted, (await _admin.PostAsync(Base + "/start", Body(start: true))).Status);
        await UntilAsync("verified");
        ApiClient key = await _f.KeyClientAsync(ApiFixture.TenantAId);
        Reply send = await key.PostAsync("/api/v1/messages", new { from = "news@example.com", to = new[] { "someone@example.org" }, subject = "Hi", text = "Hello" });
        send.Problem(HttpStatusCode.ServiceUnavailable, "not_ready");
    }
}

/// <summary>
/// With the real <see cref="SwitchActivator"/> the status says from the start whether the deployment supplies the storage pointer, so the
/// dashboard can tell the operator a cutover patch is coming instead of promising that the bootstrap file will be rewritten.
/// </summary>
[Collection("api")]
public class ApiStorageSwitchManagedTests : IAsyncLifetime
{
    private const string Base = "/api/v1/admin/storage/switch";
    private readonly string _root = Directory.CreateTempSubdirectory("eggmail-api-switch-managed-").FullName;
    private ApiFixture _f = null!;
    private ApiClient _admin = null!;

    private sealed class Resolver : ISwitchTargetResolver
    {
        public ResolvedSwitchTarget Resolve(SwitchRequestModel request) =>
            new(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = request.Target!.Path!, StatsFlushInterval = TimeSpan.Zero } }, new SecretsSection());

        public ResolvedSwitchTarget? ResolveFormerSource(StorageBackend formerBackend) => null;
    }

    public async Task InitializeAsync()
    {
        string bootstrap = Path.Combine(_root, "bootstrap.json");
        _f = await ApiFixture.StartAsync(new ApiFixtureOptions
        {
            ConfigureServices = s =>
            {
                s.AddSingleton<ISwitchTargetResolver, Resolver>();
                // The storage pointer is given on the command line (an orchestrator), or only by the bootstrap file (nothing above it).
                s.AddSingleton<ISwitchActivator>(_ => new SwitchActivator(ConfigLoader.Build(["--Storage:Backend=Sqlite", "--Sqlite:DataDirectory=" + _root], _root), bootstrap));
                s.AddSingleton<IStorageSwitchService>(sp => new StorageSwitchService(
                    sp.GetRequiredService<IStorage>(), sp.GetRequiredService<StorageOptions>(), sp.GetRequiredService<ISecretProtector>(), sp.GetRequiredService<IClock>(),
                    sp.GetRequiredService<ISwitchTargetResolver>(), sp.GetRequiredService<ISwitchActivator>(), null,
                    new StorageSwitchServiceOptions { BundleDirectory = Path.Combine(_root, "bundles"), SourceKeysProtectedAtRest = false, QuiesceTimeout = TimeSpan.FromMilliseconds(100), DrainPollInterval = TimeSpan.FromMilliseconds(50) }));
            },
        });
        _admin = await _f.SignedInAsync("root");
    }

    public async Task DisposeAsync()
    {
        await _f.DisposeAsync();
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    [Fact]
    public async Task The_status_says_before_activation_that_the_pointer_comes_from_the_deployment()
    {
        var body = new { to = "sqlite", target = new { path = Path.Combine(_root, "target") }, include = new[] { "history" }, mode = "drain", exportPassphrase = "correct horse battery", confirmation = "switch to sqlite" };
        Reply start = await _admin.PostAsync(Base + "/start", body);
        Assert.Equal(HttpStatusCode.Accepted, start.Status);
        Assert.True(start["orchestratorManaged"].GetBoolean()); // from the first report on

        DateTime deadline = DateTime.UtcNow.AddSeconds(180);
        Reply status;
        do
        {
            await Task.Delay(100);
            status = await _admin.GetAsync(Base);
        }
        while (status.Str("state") is not ("verified" or "failed") && DateTime.UtcNow < deadline);

        Assert.Equal("verified", status.Str("state"));
        Assert.True(status["orchestratorManaged"].GetBoolean());
        Assert.Equal(JsonValueKind.Null, status["cutoverPatch"].ValueKind); // the patch itself is produced by the activation
    }
}

/// <summary>Nothing in the deployment supplies the storage pointer (only the bootstrap file would): the status says so from the start.</summary>
[Collection("api")]
public class ApiStorageSwitchBootstrapFileTests : IAsyncLifetime
{
    private const string Base = "/api/v1/admin/storage/switch";
    private readonly string _root = Directory.CreateTempSubdirectory("eggmail-api-switch-bootstrap-").FullName;
    private ApiFixture _f = null!;
    private ApiClient _admin = null!;

    private sealed class Resolver : ISwitchTargetResolver
    {
        public ResolvedSwitchTarget Resolve(SwitchRequestModel request) =>
            new(new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = request.Target!.Path!, StatsFlushInterval = TimeSpan.Zero } }, new SecretsSection());

        public ResolvedSwitchTarget? ResolveFormerSource(StorageBackend formerBackend) => null;
    }

    public async Task InitializeAsync()
    {
        string bootstrap = Path.Combine(_root, "bootstrap.json");
        _f = await ApiFixture.StartAsync(new ApiFixtureOptions
        {
            ConfigureServices = s =>
            {
                s.AddSingleton<ISwitchTargetResolver, Resolver>();
                s.AddSingleton<ISwitchActivator>(_ => new SwitchActivator(ConfigLoader.Build([], _root), bootstrap)); // no command line, no environment pointer
                s.AddSingleton<IStorageSwitchService>(sp => new StorageSwitchService(
                    sp.GetRequiredService<IStorage>(), sp.GetRequiredService<StorageOptions>(), sp.GetRequiredService<ISecretProtector>(), sp.GetRequiredService<IClock>(),
                    sp.GetRequiredService<ISwitchTargetResolver>(), sp.GetRequiredService<ISwitchActivator>(), null,
                    new StorageSwitchServiceOptions { BundleDirectory = Path.Combine(_root, "bundles"), SourceKeysProtectedAtRest = false, QuiesceTimeout = TimeSpan.FromMilliseconds(100), DrainPollInterval = TimeSpan.FromMilliseconds(50) }));
            },
        });
        _admin = await _f.SignedInAsync("root");
    }

    public async Task DisposeAsync()
    {
        await _f.DisposeAsync();
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    [Fact]
    public async Task The_status_says_the_bootstrap_file_will_be_written_and_activation_reports_it()
    {
        var body = new { to = "sqlite", target = new { path = Path.Combine(_root, "target") }, include = new[] { "history" }, mode = "drain", exportPassphrase = "correct horse battery", confirmation = "switch to sqlite" };
        Reply start = await _admin.PostAsync(Base + "/start", body);
        Assert.Equal(HttpStatusCode.Accepted, start.Status);
        Assert.False(start["orchestratorManaged"].GetBoolean());

        DateTime deadline = DateTime.UtcNow.AddSeconds(180);
        Reply status;
        do
        {
            await Task.Delay(100);
            status = await _admin.GetAsync(Base);
        }
        while (status.Str("state") is not ("verified" or "failed") && DateTime.UtcNow < deadline);
        Assert.Equal("verified", status.Str("state"));
        Assert.False(status["orchestratorManaged"].GetBoolean());

        Assert.Equal("confirmed", (await _admin.PostAsync(Base + "/confirm")).Str("state"));
        Reply activated = await _admin.PostAsync(Base + "/activate");
        Assert.Equal("active", activated.Str("state"));
        Assert.False(activated["orchestratorManaged"].GetBoolean());
        Assert.Equal("bootstrap", activated["cutoverPatch"].GetProperty("kind").GetString());
        Assert.True(File.Exists(Path.Combine(_root, "bootstrap.json")));
    }
}
