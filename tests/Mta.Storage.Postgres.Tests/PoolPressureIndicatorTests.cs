using System.Diagnostics;
using Npgsql;

namespace Mta.Storage.Postgres.Tests;

/// <summary>The advisory pool-pressure figures (decision 109): the judgement over a window of samples, without a server.</summary>
[NoPostgres]
public class PoolPressureMeasureTests
{
    private static readonly long Now = 10_000 * Stopwatch.Frequency;
    private static readonly PostgresOptions Defaults = new();

    private static long SecondsAgo(double seconds) => Now - (long)(seconds * Stopwatch.Frequency);

    private static PoolSample[] Samples(int count, Func<int, long> pending, long timeouts = 0) =>
        Enumerable.Range(0, count).Select(i => new PoolSample(SecondsAgo(5 * (count - i)), pending(i), 8, 32, i == 0 ? timeouts : 0)).ToArray();

    [Fact]
    public void Callers_waiting_in_half_of_the_samples_turn_the_indicator_on()
    {
        PostgresStoragePressure p = PostgresStoragePressure.Measure(Samples(40, i => i % 2), 3, Defaults, Now);
        Assert.Equal(50, p.WaitingPercent);
        Assert.Equal(40, p.Samples);
        Assert.Equal(3, p.PendingRequests); // the live figure, not the last sample's
        Assert.Equal(8, p.ConnectionsInUse);
        Assert.Equal(32, p.MaxPoolSize);
        Assert.True(p.Advisory);
    }

    [Fact]
    public void Waiting_below_the_share_or_over_too_few_samples_stays_quiet()
    {
        Assert.False(PostgresStoragePressure.Measure(Samples(40, i => i < 19 ? 1 : 0), 0, Defaults, Now).Advisory); // 47.5 %
        PostgresStoragePressure young = PostgresStoragePressure.Measure(Samples(19, _ => 4), 0, Defaults, Now); // every sample waited, but only 19 of them
        Assert.Equal(100, young.WaitingPercent);
        Assert.False(young.Advisory);
    }

    [Fact]
    public void A_window_that_holds_fewer_than_the_minimum_needs_half_of_what_it_holds()
    {
        var coarse = new PostgresOptions { PressureWindow = TimeSpan.FromMinutes(1), PressureSampleInterval = TimeSpan.FromSeconds(10) };
        Assert.Equal(6, PostgresStoragePressure.SamplesInWindow(coarse));
        Assert.Equal(3, PostgresStoragePressure.RequiredSamples(coarse));
        Assert.Equal(20, PostgresStoragePressure.RequiredSamples(new PostgresOptions()));
        PoolSample[] three = Enumerable.Range(0, 3).Select(i => new PoolSample(SecondsAgo(10 * (3 - i)), 1, 1, 1, 0)).ToArray();
        Assert.True(PostgresStoragePressure.Measure(three, 0, coarse, Now).Advisory);
        Assert.False(PostgresStoragePressure.Measure(three[..2], 0, coarse, Now).Advisory);
    }

    [Fact]
    public void One_timed_out_request_in_the_window_turns_the_indicator_on()
    {
        PostgresStoragePressure p = PostgresStoragePressure.Measure(Samples(3, _ => 0, timeouts: 1), 0, Defaults, Now);
        Assert.Equal(1, p.Timeouts);
        Assert.Equal(0, p.WaitingPercent);
        Assert.True(p.Advisory);
    }

    [Fact]
    public void Samples_older_than_the_window_and_unwritten_slots_do_not_count()
    {
        PoolSample[] ring =
        [
            new(SecondsAgo(301), 5, 1, 1, 7), // just outside the 5-minute window, with a timeout
            new(SecondsAgo(299), 0, 2, 4, 0),
            default, // not written yet
            new(SecondsAgo(1), 1, 3, 4, 0),
        ];
        PostgresStoragePressure p = PostgresStoragePressure.Measure(ring, 0, Defaults, Now);
        Assert.Equal(2, p.Samples);
        Assert.Equal(0, p.Timeouts);
        Assert.Equal(50, p.WaitingPercent);
        Assert.Equal(3, p.ConnectionsInUse); // from the newest sample, wherever it sits in the ring
        Assert.False(p.Advisory);
    }

    [Theory]
    [InlineData(0.5, 300, 50)] // sample interval under 1 s
    [InlineData(10, 5, 50)] // window shorter than the interval
    [InlineData(5, 300, 0)]
    [InlineData(5, 300, 101)]
    public void Out_of_range_pressure_options_are_refused_when_the_storage_is_created(double intervalSeconds, double windowSeconds, int percent)
    {
        var pg = new PostgresOptions
        {
            RuntimeConnectionString = "Host=127.0.0.1;Port=1;Database=none;Username=none",
            PressureSampleInterval = TimeSpan.FromSeconds(intervalSeconds), PressureWindow = TimeSpan.FromSeconds(windowSeconds), PressureWaitingPercent = percent,
        };
        Assert.Throws<ArgumentException>(() => PostgresStorage.Create(new StorageOptions { Backend = StorageBackend.Postgres, Postgres = pg }));
    }

    [Fact]
    public void A_wait_that_began_before_the_sampler_started_does_not_hide_later_waits()
    {
        using var sampler = new PostgresPoolSampler("eggmail-pressure-unit-" + Guid.NewGuid().ToString("N"), new PostgresOptions(), startTimer: false);
        sampler.AddPending(-1); // its +1 came before the listener started
        sampler.AddPending(1);
        Assert.Equal(1, sampler.Measure().PendingRequests);
        sampler.AddPending(-1);
        Assert.Equal(0, sampler.Measure().PendingRequests);
    }

    [Fact]
    public void An_empty_ring_reports_zeros()
    {
        PostgresStoragePressure p = PostgresStoragePressure.Measure(new PoolSample[60], 0, Defaults, Now);
        Assert.Equal(new PostgresStoragePressure(0, 0, 0, 0, 0, 0, false), p);
    }
}

/// <summary>The sampler against a real pool: Npgsql's pending-request, connection and timeout instruments reach it under the pool's name (decision 109).</summary>
public class PoolPressureSamplerTests
{
    [Fact]
    public async Task The_sampler_sees_a_caller_waiting_for_a_full_pool_and_a_request_that_timed_out()
    {
        string name = "eggmail-pressure-test-" + Guid.NewGuid().ToString("N");
        string cs = new NpgsqlConnectionStringBuilder(PostgresTestServer.Instance.AdminConnectionString) { Pooling = true, MaxPoolSize = 1, Timeout = 2 }.ConnectionString;
        await using NpgsqlDataSource pool = new NpgsqlDataSourceBuilder(cs) { Name = name }.Build();
        await using NpgsqlDataSource other = new NpgsqlDataSourceBuilder(cs) { Name = name + "-other" }.Build();
        using var sampler = new PostgresPoolSampler(name, new PostgresOptions(), startTimer: false);

        NpgsqlConnection held = await pool.OpenConnectionAsync();
        Task<NpgsqlConnection> waiting = pool.OpenConnectionAsync().AsTask();
        NpgsqlConnection elsewhere = await other.OpenConnectionAsync(); // another pool's figures are not ours
        Task<NpgsqlConnection> waitingElsewhere = other.OpenConnectionAsync().AsTask();
        await WaitUntilAsync(() => sampler.Measure().PendingRequests == 1);
        sampler.Sample();
        PostgresStoragePressure p = sampler.Measure();
        Assert.Equal(1, p.PendingRequests);
        Assert.Equal(1, p.ConnectionsInUse);
        Assert.Equal(1, p.MaxPoolSize);
        Assert.Equal(100, p.WaitingPercent);
        Assert.Equal(1, p.Samples);
        Assert.False(p.Advisory); // one sample is not enough to judge

        await held.DisposeAsync();
        await (await waiting).DisposeAsync();
        await elsewhere.DisposeAsync();
        await (await waitingElsewhere).DisposeAsync();
        await WaitUntilAsync(() => sampler.Measure().PendingRequests == 0);
        sampler.Sample();
        p = sampler.Measure();
        Assert.Equal(50, p.WaitingPercent);
        Assert.Equal(0, p.ConnectionsInUse);
        Assert.Equal(0, p.Timeouts);

        await using (NpgsqlConnection hold = await pool.OpenConnectionAsync())
        {
            await Assert.ThrowsAnyAsync<Exception>(() => pool.OpenConnectionAsync().AsTask()); // the pool's 2-second timeout
        }

        sampler.Sample();
        p = sampler.Measure();
        Assert.Equal(1, p.Timeouts);
        Assert.Equal(0, p.PendingRequests);
        Assert.True(p.Advisory);
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = Stopwatch.StartNew();
        while (!condition())
        {
            Assert.True(deadline.Elapsed < TimeSpan.FromSeconds(10), "The pool's instruments did not report in time.");
            await Task.Delay(10);
        }
    }
}
