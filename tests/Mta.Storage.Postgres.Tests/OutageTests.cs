using Mta.Core;
using Mta.Storage.Tests;
using Npgsql;

namespace Mta.Storage.Postgres.Tests;

/// <summary>
/// PostgreSQL going away: every method throws <see cref="StorageUnavailableException"/> (the SMTP layer answers 451), health reports
/// not ready instead of throwing, nothing is lost that was buffered, and everything works again when the server returns.
/// </summary>
public class OutageTests : StorageTestBase
{
    private readonly PgHarness _pg = new();
    private TcpProxy? _proxy;

    protected override async Task<IStorage> CreateAsync(StorageOptions options)
    {
        await DisposeProxyAsync();
        await _pg.DisposeAsync();
        TestDatabase db = await PostgresTestServer.Instance.CreateDatabaseAsync();
        var direct = new NpgsqlConnectionStringBuilder(db.ConnectionString);
        _proxy = new TcpProxy(direct.Host!, direct.Port);
        var viaProxy = new NpgsqlConnectionStringBuilder(db.ConnectionString) { Host = "127.0.0.1", Port = _proxy.Port, Timeout = 30, Pooling = true };   // Cut() refuses connections at once, so a long connect timeout costs nothing in an outage; 3 s was exceeded by InitializeAsync on a loaded CI runner
        _pg.Adopt(db);
        return PostgresStorage.Create(PgHarness.WithDatabase(options, viaProxy.ConnectionString), Clock);
    }

    private async Task DisposeProxyAsync()
    {
        if (_proxy is not null)
        {
            await _proxy.DisposeAsync();
            _proxy = null;
        }
    }

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await DisposeProxyAsync();
        await _pg.DisposeAsync();
    }

    [Fact]
    public async Task Every_operation_reports_unavailable_during_an_outage_and_works_again_afterwards()
    {
        await AddEndpointAsync(TenantA, true, "*");
        var m = await AcceptAsync(Msg(to: ["a@example.org", "b@example.org"]));
        var claimed = await ClaimAsync(max: 1);
        Storage.Stats.Add(new StatKey(Start, TenantA, "s.example", "a.example"), StatCounter.Accepted, 5);

        _proxy!.Cut();
        CancellationToken ct = CancellationToken.None;
        await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.Intake.AcceptAsync(Msg(), ct));
        await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.Deliveries.ClaimAsync("w", 5, Clock.UtcNow, TimeSpan.FromMinutes(1), ct));
        await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.Deliveries.GetRawAsync(m.MessageId, ct));
        await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.Deliveries.RecordAttemptAsync(Attempt(claimed[0], DeliveryOutcome.Delivered), ct));
        await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.Deliveries.ExtendLeaseAsync(claimed[0].DeliveryId, "worker-1", Clock.UtcNow, ct));
        await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.Deliveries.GetQueueStatsAsync(ct));
        await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.Deliveries.ReleaseOwnedLeasesAsync("worker-1", ct));
        await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.History.SearchAsync(new MessageQuery(), ct));
        await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.History.GetAsync(TenantA, m.MessageId, ct));
        await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.Webhooks.ClaimDueAsync("d", 5, Clock.UtcNow, TimeSpan.FromMinutes(1), ct));
        await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.Stats.QueryAsync(null, Start, Start.AddDays(1), false, ct));
        await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.Stats.FlushAsync(ct));
        await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.Maintenance.RunAsync(Clock.UtcNow, ct));
        await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.Config.GetTenantsAsync(ct));
        await Assert.ThrowsAsync<StorageUnavailableException>(async () => await Storage.Config.UpsertTenantAsync(new Tenant(Ids.New(), "T", "t", true, Clock.UtcNow, false), ct));

        StorageHealth down = await Storage.Maintenance.GetHealthAsync(ct);
        Assert.False(down.Ready);
        Assert.Contains("postgres_unavailable", down.Warnings);

        _proxy.Restore();

        // The buffered statistics were kept by the failed flush; the delivery that was claimed before the outage can still be reported.
        await RecordAsync(claimed[0], DeliveryOutcome.Delivered);
        await FlushStatsAsync();
        var rows = await Storage.Stats.QueryAsync(TenantA, Start.AddHours(-1), Start.AddHours(1), false, ct);
        Assert.Equal(2 + 5, rows.Sum(r => r.Accepted)); // two recipients accepted plus the five added by hand
        Assert.True((await Storage.Maintenance.GetHealthAsync(ct)).Ready);
        Assert.Single(await ClaimAsync(max: 5, owner: "after"));
    }

    [Fact]
    public async Task Starting_against_an_unreachable_server_fails_with_the_unavailable_exception()
    {
        await Storage.DisposeAsync();
        var builder = new NpgsqlConnectionStringBuilder(Options.Postgres.RuntimeConnectionString ?? "Host=127.0.0.1") { Host = "127.0.0.1", Port = 1, Timeout = 2, Pooling = false, Username = "postgres" };
        PostgresStorage storage = PostgresStorage.Create(PgHarness.WithDatabase(Options, builder.ConnectionString), Clock);
        await Assert.ThrowsAsync<StorageUnavailableException>(async () => await storage.InitializeAsync(CancellationToken.None));
    }

    [Fact]
    public async Task A_constraint_violation_is_not_reported_as_an_outage()
    {
        var m = await AcceptAsync();
        var ex = await Assert.ThrowsAsync<StorageConflictException>(async () => await Storage.Intake.AcceptAsync(m, CancellationToken.None));
        Assert.IsNotType<StorageUnavailableException>(ex);
    }
}
