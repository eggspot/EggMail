namespace Mta.Storage.Tests;

/// <summary>Maintenance and health behaviour that must not depend on the backend.</summary>
public abstract class MaintenanceConformance : StorageTestBase
{
    [Fact]
    public async Task Maintenance_can_run_repeatedly_on_an_empty_store()
    {
        var first = await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        var second = await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        Assert.NotEmpty(first);
        Assert.Equal(first.Select(r => r.Job), second.Select(r => r.Job));
        Assert.All(first, r => Assert.True(r.RowsAffected >= 0));
    }

    [Fact]
    public async Task Maintenance_never_removes_live_queue_entries()
    {
        var m = await AcceptAsync();
        Clock.Advance(TimeSpan.FromDays(100));
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);

        Assert.NotNull(await Storage.Deliveries.GetRawAsync(m.MessageId, CancellationToken.None));
        Assert.Single(await Storage.Deliveries.ClaimExpiredAsync("reaper", 10, Clock.UtcNow, CancellationToken.None));
    }

    [Fact]
    public async Task Maintenance_removes_expired_history_and_reports_the_rows()
    {
        if (!IsFull)
        {
            return;
        }

        await AcceptAsync();
        Clock.Advance(TimeSpan.FromDays(40));
        var reports = await Storage.Maintenance.RunAsync(Clock.UtcNow, CancellationToken.None);
        Assert.Contains(reports, r => r.Job.StartsWith("retention", StringComparison.Ordinal) && r.RowsAffected > 0);
        Assert.Empty((await Storage.History.SearchAsync(new MessageQuery(), CancellationToken.None)).Items);
    }

    [Fact]
    public async Task Health_is_ready_and_warns_about_unlimited_retention_only_when_configured()
    {
        StorageHealth healthy = await Storage.Maintenance.GetHealthAsync(CancellationToken.None);
        Assert.True(healthy.Ready);
        Assert.DoesNotContain(healthy.Warnings, w => w.StartsWith("retention_unlimited", StringComparison.Ordinal));

        await OpenAsync(Opts(retention: new RetentionOptions { MetadataDays = 0, StatsDailyDays = 0 }));
        StorageHealth unlimited = await Storage.Maintenance.GetHealthAsync(CancellationToken.None);
        Assert.Contains("retention_unlimited:Retention:MetadataDays", unlimited.Warnings);
        Assert.Contains("retention_unlimited:Stats:DailyRetentionDays", unlimited.Warnings);
        Assert.DoesNotContain("retention_unlimited:Stats:HourlyRetentionDays", unlimited.Warnings);
    }

    [Fact]
    public async Task Disposing_twice_is_harmless()
    {
        Storage.Stats.Add(new StatKey(Start, TenantA, "s.example", "a.example"), StatCounter.Accepted, 3);
        await Storage.DisposeAsync();
        await Storage.DisposeAsync();
    }
}
