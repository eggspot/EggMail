using Mta.Core;
using Mta.Storage.Logic;
using Mta.TestSupport;
using Xunit.Abstractions;

namespace Mta.Storage.Tests;

/// <summary>The physical tables a lifecycle suite can ask a backend to count (a backend that cannot count answers null and only the read side is checked).</summary>
public enum LifecycleTable
{
    MessageIndex,
    MessageRecipient,
    MessageEvent,
    MessageContent,
    RawRetained,
    WebhookOutbox,
    WebhookAttempt,
    StatsHourly,
    StatsDaily,
    Idempotency,
    RecentEvent,
    DeliveryQueue,
    MessageSpool,
}

/// <summary>
/// Accelerated lifecycle suite: days of virtual time against a real storage backend in seconds (see docs/testing-offline-coverage.md,
/// "Accelerated lifecycle and leaks"). Every scenario advances the shared <see cref="StorageTestBase.Clock"/> by whole days, produces steady traffic of
/// two tenants, runs <c>Maintenance.RunAsync</c> once per virtual day and checks the retention rules against an independent model, on the read side (what the API
/// can still see) and, where the backend can count its rows (<see cref="CountRowsAsync"/>), on the physical side. It does not replace a wall-clock soak.
/// The class is split by area: <c>.Retention</c>, <c>.Stats</c>, <c>.Queue</c> and <c>.Webhooks</c>.
/// </summary>
public abstract partial class LifecycleConformance(ITestOutputHelper output) : StorageTestBase
{
    /// <summary>Maintenance jobs that delete data by a retention rule: a job added later must be added here and to a scenario, or the guard test fails.</summary>
    public static readonly string[] RetentionJobs =
    [
        "retention.metadata",
        "retention.content",
        "retention.webhook_outbox",
        "retention.webhook_attempts",
        "stats.rollup",
        "stats.retention",
        "idempotency.expired",
        "inbound_retention",
    ];

    /// <summary>Housekeeping jobs that delete nothing a user can see (partition creation, lease cleanup, vacuum).</summary>
    public static readonly string[] HousekeepingJobs =
    [
        "partitions.create",
        "analyze.history",
        "queue.leases",
        "queue.reconcile",
        "vacuum.incremental",
        "wal.checkpoint",
    ];

    private readonly Dictionary<string, long> _jobRows = [];

    protected ITestOutputHelper Output { get; } = output;

    /// <summary>False for the variants that only repeat the cheap scenarios (the SQLite sync modes): the heavy scenarios return at once.</summary>
    protected virtual bool Heavy => true;

    /// <summary>The rows currently in a table, or null when this backend has no way to count them.</summary>
    protected virtual ValueTask<long?> CountRowsAsync(LifecycleTable table) => ValueTask.FromResult<long?>(null);

    /// <summary>The rows deleted so far by each maintenance job over the scenario.</summary>
    protected IReadOnlyDictionary<string, long> JobRows => _jobRows;

    protected static readonly TimeSpan Day = TimeSpan.FromDays(1);

    /// <summary>One maintenance run; fails when it reports a job this suite does not know and remembers the rows each job deleted.</summary>
    protected async Task<IReadOnlyList<MaintenanceReport>> MaintainAsync()
    {
        IReadOnlyList<MaintenanceReport> reports = await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        foreach (MaintenanceReport r in reports)
        {
            Assert.True(
                RetentionJobs.Contains(r.Job) || HousekeepingJobs.Contains(r.Job),
                $"Maintenance job '{r.Job}' is unknown to the lifecycle suite: add it to LifecycleConformance.RetentionJobs (and a scenario that proves its rule) or HousekeepingJobs.");
            _jobRows[r.Job] = _jobRows.GetValueOrDefault(r.Job) + r.RowsAffected;
        }

        return reports;
    }

    protected async Task AssertCountAsync(LifecycleTable table, long expected, string because)
    {
        long? actual = await CountRowsAsync(table);
        if (actual is not null)
        {
            Assert.True(expected == actual, $"{table}: expected {expected} rows but found {actual} ({because}) at {Clock.UtcNow:O}");
        }
    }

    /// <summary>The seed of a randomized interleaving: logged so a failure can be replayed with <c>EGGMAIL_ACCEL_SEED</c>.</summary>
    protected int LogSeed(int fallback)
    {
        int seed = Accelerated.Seed(fallback);
        Output.WriteLine($"seed={seed} (replay with EGGMAIL_ACCEL_SEED={seed}), scale={Accelerated.Scale}");
        return seed;
    }

    /// <summary>True when <paramref name="at"/> is still inside a retention of <paramref name="days"/> measured from <paramref name="from"/> (0 = unlimited).</summary>
    protected static bool Within(DateTimeOffset now, DateTimeOffset from, int days) => days <= 0 || now < from.AddDays(days);

    /// <summary>The day a history row is keyed by (the day of the UUIDv7 message id) must be at or after the day of "now minus the retention": the physical rule.</summary>
    protected static bool DayKeyRetained(DateTimeOffset now, DateTimeOffset receivedAt, int days) =>
        days <= 0 || StorageTime.DayNumber(receivedAt) >= StorageTime.DayNumber(now.AddDays(-days));

    [Fact]
    public async Task Lifecycle_every_maintenance_job_is_known_to_the_suite_and_the_retention_jobs_all_report()
    {
        // A store with a little of everything: the report list is the contract between the backends and this suite.
        await AcceptAsync();
        await FlushStatsAsync();
        IReadOnlyList<MaintenanceReport> first = await MaintainAsync();
        Clock.Advance(Day);
        IReadOnlyList<MaintenanceReport> second = await MaintainAsync();

        bool inbound = SupportsInbound();   // a backend that does not implement inbound mail yet has no inbound retention job
        foreach (string job in RetentionJobs.Where(j => inbound || j != "inbound_retention"))
        {
            Assert.Contains(first, r => r.Job == job);
            Assert.Contains(second, r => r.Job == job);
        }

        Assert.Equal(first.Select(r => r.Job), second.Select(r => r.Job));
        Assert.All(first.Concat(second), r => Assert.True(r.RowsAffected >= 0));
    }
}
