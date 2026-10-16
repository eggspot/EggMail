using System.Reflection;
using System.Text.Json.Nodes;
using Mta.Core;
using Mta.Dsn;
using Mta.Host.Hosting;
using Mta.Host.Ingest;
using Mta.Storage;
using Mta.TestSupport;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>
/// VERP bounce-address keys over a virtual year and across restarts on both backends. A token carries its key id and the hour it was made; it is accepted for 14 days
/// (<c>BounceProcessor</c>) with the key that made it, so a retired key has to stay in the key set for 14 days after its last token was made and may go after that. The key set
/// lives in the config store (<c>bounce.verp.keys</c>), where every replica reads the same one. There is no automatic rotation: the operator adds a key and moves <c>Active</c>, which
/// is what these tests do.
/// </summary>
public class VerpKeysLifecycleTests
{
    private static readonly Guid DomainId = Guid.Parse("d0000000-0000-7000-8000-000000000001");
    private static readonly TimeSpan MaxTokenAge = TimeSpan.FromDays(14);

    [Fact]
    public async Task Tokens_follow_the_fourteen_day_rule_through_a_year_of_rotations_on_sqlite()
    {
        var clock = new VirtualClock();
        await using HostBackend backend = await HostBackend.SqliteAsync(clock);
        await RotationYearAsync(backend, clock);
    }

    [PostgresFact]
    public async Task Tokens_follow_the_fourteen_day_rule_through_a_year_of_rotations_on_postgres()
    {
        var clock = new VirtualClock();
        await using HostBackend backend = await HostBackend.PostgresAsync(clock);
        await RotationYearAsync(backend, clock);
    }

    [Fact]
    public async Task Replicas_starting_together_on_an_empty_store_end_up_with_one_key_on_sqlite()
    {
        var clock = new VirtualClock();
        await using HostBackend backend = await HostBackend.SqliteAsync(clock);
        await ConcurrentFirstStartAsync(backend);
    }

    [PostgresFact]
    public async Task Replicas_starting_together_on_an_empty_store_end_up_with_one_key_on_postgres()
    {
        var clock = new VirtualClock();
        await using HostBackend backend = await HostBackend.PostgresAsync(clock);
        await ConcurrentFirstStartAsync(backend);
    }

    private static async Task ConcurrentFirstStartAsync(HostBackend backend)
    {
        // Both replicas read the empty key set before either writes: the interleaving that lost a key before the creation was done under a lease.
        var rendezvous = new Rendezvous(2);
        IConfigStore a = RendezvousConfig.Wrap(backend.Storage.Config, rendezvous);
        IConfigStore b = RendezvousConfig.Wrap(backend.Storage.Config, rendezvous);
        var first = VerpKeyStore.LoadOrCreateAsync(a, default);
        var second = VerpKeyStore.LoadOrCreateAsync(b, default);
        VerpCodec[] codecs = await Task.WhenAll(first, second);

        DateTimeOffset now = new(2026, 10, 12, 12, 30, 0, TimeSpan.Zero);
        string tokenFromA = codecs[0].CreateLocalPart(Guid.NewGuid(), DomainId, now, "example.net");
        string tokenFromB = codecs[1].CreateLocalPart(Guid.NewGuid(), DomainId, now, "example.net");
        Assert.True(codecs[1].TryDecode(tokenFromA, now, MaxTokenAge, out _), "a bounce minted by one replica must verify on the other");
        Assert.True(codecs[0].TryDecode(tokenFromB, now, MaxTokenAge, out _));

        // What a later start reads is the same key set again.
        VerpCodec later = await VerpKeyStore.LoadOrCreateAsync(backend.Storage.Config, default);
        Assert.True(later.TryDecode(tokenFromA, now, MaxTokenAge, out _));
        Assert.True(later.TryDecode(tokenFromB, now, MaxTokenAge, out _));
    }

    private sealed class NoWebhooks : IWebhookPublisher
    {
        public ValueTask PublishAsync(Guid tenantId, WebhookEventDraft draft, DateTimeOffset now, CancellationToken cancellationToken) => ValueTask.CompletedTask;
    }

    private static BounceProcessor ProcessorFor(HostBackend backend, VerpCodec codec, IClock clock) =>
        new(codec, backend.Storage.Config, backend.Storage.Stats, new NoWebhooks(), clock);

    private static async Task RotateAsync(IConfigStore config, DateTimeOffset now, bool dropRetiredOlderThanIds = false, int[]? drop = null)
    {
        SettingRecord setting = (await config.GetSettingsAsync(null, default)).Single(s => s.Key == VerpKeyStore.SettingKey && s.TenantId is null);
        JsonNode root = JsonNode.Parse(setting.ValueJson)!;
        JsonObject keys = root["Keys"]!.AsObject();
        int active = root["Active"]!.GetValue<int>();
        int next = Enumerable.Range(0, 16).First(id => id != active && keys[id.ToString()] is null);   // ids are 0..15 and are reused once their key was removed
        keys[next.ToString()] = Convert.ToBase64String(VerpCodec.GenerateKey());
        root["Active"] = next;
        foreach (int id in drop ?? [])
        {
            keys.Remove(id.ToString());
        }

        await config.SetSettingAsync(setting with { ValueJson = root.ToJsonString(), UpdatedAt = now }, default);
    }

    private static async Task<int[]> KeyIdsAsync(IConfigStore config)
    {
        SettingRecord setting = (await config.GetSettingsAsync(null, default)).Single(s => s.Key == VerpKeyStore.SettingKey && s.TenantId is null);
        return [.. JsonNode.Parse(setting.ValueJson)!["Keys"]!.AsObject().Select(p => int.Parse(p.Key)).Order()];
    }

    private sealed record Minted(string Token, DateTimeOffset At, int KeyId);

    private static async Task RotationYearAsync(HostBackend backend, VirtualClock clock)
    {
        int seed = Accelerated.Seed(77);
        var random = new Random(seed);
        Guid tenant = Guid.Parse("a0000000-0000-7000-8000-000000000001");
        DateTimeOffset start = clock.UtcNow;
        VerpCodec codec = await VerpKeyStore.LoadOrCreateAsync(backend.Storage.Config, default);
        Assert.Equal(1, codec.ActiveKeyId);
        await backend.Storage.Config.UpsertTenantAsync(new Tenant(tenant, "T", "t", true, start, false), default);

        var minted = new List<Minted>();
        int rotations = Accelerated.Scaled(12);
        TimeSpan period = TimeSpan.FromDays(365.0 / rotations);
        var keyCounts = new List<int>();

        for (int round = 0; round < rotations; round++)
        {
            // A period of mail: a token every few hours; after every one of them each earlier token is checked at the current virtual time.
            DateTimeOffset roundEnd = start + period * (round + 1);
            while (clock.UtcNow < roundEnd)
            {
                clock.Advance(TimeSpan.FromHours(random.Next(3, 40)));
                string dest = "d" + random.Next(0, 50) + ".example";
                minted.Add(new Minted(codec.CreateLocalPart(tenant, DomainId, clock.UtcNow, dest), clock.UtcNow, codec.ActiveKeyId));
                await CheckAllAsync(backend, codec, clock, minted);
            }

            // The operator rotates: a new key becomes active; the old keys that cannot have a valid token any more (older than 14 days plus an hour of rounding) are dropped.
            var before = await KeyIdsAsync(backend.Storage.Config);
            int[] expired = [.. before.Where(id => id != codec.ActiveKeyId && minted.Where(m => m.KeyId == id).All(m => clock.UtcNow - m.At > MaxTokenAge + TimeSpan.FromHours(1)))];
            await RotateAsync(backend.Storage.Config, clock.UtcNow, drop: expired);
            if (round % 3 == 2)
            {
                await backend.RestartAsync();
            }

            codec = await VerpKeyStore.LoadOrCreateAsync(backend.Storage.Config, default);
            Assert.NotEqual(minted[^1].KeyId, codec.ActiveKeyId);
            int[] after = await KeyIdsAsync(backend.Storage.Config);
            keyCounts.Add(after.Length);
            await CheckAllAsync(backend, codec, clock, minted);
        }

        // Tokens are made every few hours and a period is a month: the old key is needed for 14 days after rotation, so at most two keys, never growing.
        Assert.All(keyCounts, c => Assert.InRange(c, 1, 2));

        // Exactly at the boundary: the last token minted is valid until its hour plus 14 days and not a second longer; a key missing from the set rejects its tokens.
        Minted last = minted[^1];
        DateTimeOffset hour = new(last.At.Year, last.At.Month, last.At.Day, last.At.Hour, 0, 0, TimeSpan.Zero);
        clock.Set(hour + MaxTokenAge);
        Assert.True(ProcessorFor(backend, codec, clock).IsValidBounceAddress(last.Token));
        clock.Set(hour + MaxTokenAge + TimeSpan.FromSeconds(1));
        Assert.False(ProcessorFor(backend, codec, clock).IsValidBounceAddress(last.Token));

        clock.Set(last.At + TimeSpan.FromDays(1));
        Assert.True(ProcessorFor(backend, codec, clock).IsValidBounceAddress(last.Token));
        await RotateAsync(backend.Storage.Config, clock.UtcNow, drop: [last.KeyId]);
        codec = await VerpKeyStore.LoadOrCreateAsync(backend.Storage.Config, default);
        Assert.False(ProcessorFor(backend, codec, clock).IsValidBounceAddress(last.Token), "removing a key early rejects the tokens it made");
    }

    private static async Task CheckAllAsync(HostBackend backend, VerpCodec codec, IClock clock, List<Minted> minted)
    {
        BounceProcessor processor = ProcessorFor(backend, codec, clock);
        DateTimeOffset now = clock.UtcNow;
        foreach (Minted m in minted)
        {
            DateTimeOffset hour = new(m.At.Year, m.At.Month, m.At.Day, m.At.Hour, 0, 0, TimeSpan.Zero);
            bool shouldBeValid = now - hour <= MaxTokenAge;
            bool accepted = processor.IsValidBounceAddress(m.Token);
            if (shouldBeValid)
            {
                Assert.True(accepted, $"a token of key {m.KeyId} made at {m.At:u} was refused at {now:u} (age {now - m.At})");
            }
            else
            {
                Assert.False(accepted, $"a token of key {m.KeyId} made at {m.At:u} was accepted at {now:u} (age {now - m.At})");
            }
        }

        // Tokens older than 14 days are dropped from the list: the check is O(recent), and the list does not grow for the length of the year.
        minted.RemoveAll(m => now - m.At > MaxTokenAge + TimeSpan.FromDays(1));
    }

    // --- a deterministic interleaving of two replicas' first reads

    internal sealed class Rendezvous(int parties)
    {
        private readonly TaskCompletionSource _all = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _arrived;

        /// <summary>Waits until every party has arrived, or two seconds (so that an implementation that serialises the callers, correctly, is not deadlocked by the test).</summary>
        public async Task ArriveAsync()
        {
            if (Interlocked.Increment(ref _arrived) >= parties)
            {
                _all.TrySetResult();
            }

            await Task.WhenAny(_all.Task, Task.Delay(TimeSpan.FromSeconds(2)));
        }
    }
}

internal class RendezvousConfig : DispatchProxy
{
    private IConfigStore _inner = null!;
    private VerpKeysLifecycleTests.Rendezvous _rendezvous = null!;
    private int _firstRead;

    public static IConfigStore Wrap(IConfigStore inner, VerpKeysLifecycleTests.Rendezvous rendezvous)
    {
        IConfigStore proxy = Create<IConfigStore, RendezvousConfig>();
        var self = (RendezvousConfig)(object)proxy;
        self._inner = inner;
        self._rendezvous = rendezvous;
        return proxy;
    }

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        if (targetMethod!.Name == nameof(IConfigStore.GetSettingsAsync) && Interlocked.Exchange(ref _firstRead, 1) == 0)
        {
            return ReadAfterRendezvousAsync((Guid?)args![0], (CancellationToken)args[1]!);
        }

        try
        {
            return targetMethod.Invoke(_inner, args);
        }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
            throw;
        }
    }

    private async ValueTask<IReadOnlyList<SettingRecord>> ReadAfterRendezvousAsync(Guid? tenantId, CancellationToken ct)
    {
        var settings = await _inner.GetSettingsAsync(tenantId, ct);   // read first (an empty store), then let the other replica read too
        await _rendezvous.ArriveAsync();
        return settings;
    }
}
