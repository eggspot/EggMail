using Mta.Core;
using Mta.Storage.Transfer;

namespace Mta.Storage.Portability.Tests;

/// <summary>Remembers what the activation step was asked to do (stands in for the host's bootstrap writer).</summary>
public sealed class RecordingActivator : ISwitchActivator
{
    public SwitchActivationRequest? Request { get; private set; }

    public bool Restored { get; private set; }

    public Task<SwitchActivation> ActivateAsync(SwitchActivationRequest request, CancellationToken cancellationToken)
    {
        Request = request;
        return Task.FromResult(new SwitchActivation(ActivationKind.CutoverPatch, "patch", "Storage__Backend=Sqlite", null));
    }

    public Task RestoreAsync(Guid switchId, CancellationToken cancellationToken)
    {
        Restored = true;
        return Task.CompletedTask;
    }

    public bool Forgotten { get; private set; }

    public Task ForgetAsync(Guid switchId, CancellationToken cancellationToken)
    {
        Forgotten = true;
        return Task.CompletedTask;
    }
}

/// <summary>Cancels a token when a progress notification matches (to kill an operation midway).</summary>
public sealed class CancelOnProgress(CancellationTokenSource cts, Func<SwitchProgress, bool> when) : IProgress<SwitchProgress>
{
    public void Report(SwitchProgress value)
    {
        if (when(value))
        {
            cts.Cancel();
        }
    }
}

/// <summary>Temporary directories, stores and the happy-path flow shared by the switch tests.</summary>
public abstract class SwitchTestBase : IAsyncLifetime
{
    protected const string Pass = "correct horse battery staple";

    private readonly List<TestStore> _stores = [];
    private readonly List<IAsyncDisposable> _disposables = [];

    protected string Root { get; } = Directory.CreateTempSubdirectory("eggmail-switch-").FullName;

    protected string BundleDir(string name = "bundle") => Path.Combine(Root, name);

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        foreach (IAsyncDisposable d in _disposables)
        {
            await d.DisposeAsync();
        }

        foreach (TestStore s in _stores)
        {
            await s.DisposeAsync();
        }

        try
        {
            Directory.Delete(Root, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    protected TestStore Track(TestStore store)
    {
        _stores.Add(store);
        return store;
    }

    protected T Own<T>(T disposable) where T : IAsyncDisposable
    {
        _disposables.Add(disposable);
        return disposable;
    }

    protected async Task<TestStore> NewStoreAsync(StoreKind kind, HistoryMode history, string name, bool certificateRing = true, Func<StorageOptions, StorageOptions>? tweak = null)
    {
        TestStore s = await TestStore.CreateAsync(kind, history, Root, name, certificateRing, tweak: tweak);
        _stores.Add(s);
        return s;
    }

    protected static StorageSwitchEngine NewEngine(TestStore? source, TestStore? target, ISwitchHostControl? host = null, ISwitchActivator? activator = null, SwitchOptions? options = null) =>
        new(source?.Endpoint, target?.Endpoint, host, activator, SystemClock.Instance, null, options ?? new SwitchOptions { ChunkRows = 7, DrainPollInterval = TimeSpan.FromMilliseconds(50) });

    protected static async Task DeliverEverythingAsync(IStorage storage)
    {
        while (true)
        {
            var claimed = await storage.Deliveries.ClaimAsync("drain", 100, DateTimeOffset.UtcNow.AddDays(2), TimeSpan.FromMinutes(1), default);
            if (claimed.Count == 0)
            {
                return;
            }

            foreach (ClaimedDelivery d in claimed)
            {
                await storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = DateTimeOffset.UtcNow, SmtpCode = 250, Duration = TimeSpan.FromMilliseconds(5) }, default);
            }
        }
    }

    /// <summary>Preflight, start (quiesce), export, import, verify and confirm; leaves the target Confirmed.</summary>
    protected async Task<ExportResult> SwitchToConfirmedAsync(StorageSwitchEngine engine, string bundle, SwitchMode mode = SwitchMode.Quiesce, bool skipHistory = false, ImportScope scope = ImportScope.All, TimeSpan? quiesceTimeout = null)
    {
        await engine.StartAsync(new SwitchRequest { Mode = mode, BundlePath = bundle, Passphrase = Pass, SkipHistory = skipHistory, QuiesceTimeout = quiesceTimeout ?? TimeSpan.FromMilliseconds(200) }, null, default);
        ExportResult export = await engine.ExportAsync(new BundleRequest { BundlePath = bundle, Passphrase = Pass, SkipHistory = skipHistory }, null, default);
        await engine.ImportAsync(new ImportRequest { BundlePath = bundle, Passphrase = Pass, Scope = scope }, null, default);
        VerifyReport report = await engine.VerifyAsync(new BundleRequest { BundlePath = bundle, Passphrase = Pass }, null, default);
        Assert.True(report.Ok, string.Join("; ", report.Problems));
        await engine.ConfirmAsync(default);
        return export;
    }

    protected static async Task AssertSameAsync(TestStore source, TestStore target, bool includeHistory = true, params string[] except)
    {
        var a = await Seed.SnapshotAsync(source.Storage, includeHistory);
        var b = await Seed.SnapshotAsync(target.Storage, includeHistory);
        foreach (string table in a.Keys.Where(k => !except.Contains(k)))
        {
            Assert.True(b.ContainsKey(table), $"{table} is missing in the target");
            Assert.Equal(a[table], b[table]);
        }
    }

    protected static async Task AssertSecretsAsync(TestStore source, TestStore target)
    {
        var plainSource = await Seed.PlainSecretsAsync(source.Storage, source.Protector);
        var plainTarget = await Seed.PlainSecretsAsync(target.Storage, target.Protector);
        Assert.NotEmpty(plainSource);
        Assert.Equal(plainSource.OrderBy(kv => kv.Key, StringComparer.Ordinal), plainTarget.OrderBy(kv => kv.Key, StringComparer.Ordinal));
    }

    protected static async Task<List<T>> ReadAsync<T>(TestStore store, TransferTable table) where T : class
    {
        var list = new List<T>();
        await foreach (object row in store.Transfer.ReadAsync(table, TransferRange.All, default))
        {
            list.Add((T)row);
        }

        return list;
    }
}
