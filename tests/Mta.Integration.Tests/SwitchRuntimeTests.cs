using System.Net.Sockets;
using System.Text;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Switching;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.Portability;
using Mta.Storage.Sqlite;
using Mta.Storage.Transfer;

namespace Mta.Integration.Tests;

/// <summary>The process side of a backend switch on a real runtime: listeners, delivery scheduler, API flag, startup gate.</summary>
[Collection("Runtime")]
public sealed class SwitchRuntimeTests : IAsyncLifetime
{
    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-switch-it-").FullName;
    private readonly CancellationTokenSource _stop = new();
    private EggMailRuntime _runtime = null!;
    private Task _engine = Task.CompletedTask;
    private int _port;

    public async Task InitializeAsync()
    {
        var config = new MtaConfig
        {
            Hostname = "egg.test",
            Storage = new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _dir, StatsFlushInterval = TimeSpan.Zero } },
            Smtp = new SmtpSection
            {
                Listeners = new Dictionary<string, ListenerSection>
                {
                    ["submission"] = new() { Port = 0, BindAddress = "127.0.0.1", Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce },
                },
            },
            Delivery = new DeliverySection { PollInterval = TimeSpan.FromMilliseconds(30), AllowPrivateMxAddresses = true },
        };
        var storage = SqliteStorage.Create(config.Storage);
        await storage.InitializeAsync(default);
        _runtime = await EggMailRuntime.CreateAsync(config, storage, SystemClock.Instance, NullMtaLog.Instance, default);
        _runtime.SmtpServer.Start();
        _port = _runtime.SmtpServer.LocalEndPoints["submission"].Port;
        _engine = Task.Run(() => _runtime.Delivery.RunAsync(_stop.Token));
    }

    public async Task DisposeAsync()
    {
        await _stop.CancelAsync();
        try { await _engine; } catch (OperationCanceledException) { }
        await _runtime.SmtpServer.StopAsync(TimeSpan.FromSeconds(2));
        await _runtime.DisposeAsync();
        await _runtime.Storage.DisposeAsync();
        Directory.Delete(_dir, recursive: true);
    }

    private async Task<string> GreetingAsync()
    {
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _port);
        var buffer = new byte[256];
        int n = await client.GetStream().ReadAsync(buffer);
        return Encoding.ASCII.GetString(buffer, 0, n);
    }

    private StorageSwitchEngine Engine(HostSwitchControl control) =>
        new(new SwitchEndpoint { Storage = _runtime.Storage, Secrets = _runtime.Secrets, Options = _runtime.Config.Storage }, null, control, null, SystemClock.Instance, NullMtaLog.Instance);

    [Fact]
    public async Task Quiescing_stops_the_listeners_the_api_and_the_scheduler_and_a_rollback_resumes_them()
    {
        var state = new SwitchRuntimeState(StartupDecision.Normal);
        var control = new HostSwitchControl(_runtime, state);
        StorageSwitchEngine engine = Engine(control);
        Assert.StartsWith("220", await GreetingAsync());

        await engine.StartAsync(new SwitchRequest { Mode = SwitchMode.Quiesce, QuiesceTimeout = TimeSpan.FromMilliseconds(100) }, null, default);

        Assert.StartsWith("421", await GreetingAsync());
        Assert.False(state.AcceptingApi);
        Assert.True(_runtime.Delivery.Paused);
        Assert.True(_runtime.Storage.Transfer!.Gate.IsClosed);

        await engine.RollbackAsync(sourceOnly: true, default);

        Assert.StartsWith("220", await GreetingAsync());
        Assert.True(state.AcceptingApi);
        Assert.False(_runtime.Delivery.Paused);
        Assert.False(_runtime.Storage.Transfer.Gate.IsClosed);
    }

    [Fact]
    public async Task A_state_written_by_another_process_is_followed_by_the_watcher_logic()
    {
        var state = new SwitchRuntimeState(StartupDecision.Normal);
        var control = new HostSwitchControl(_runtime, state);
        IStorageTransfer transfer = _runtime.Storage.Transfer!;
        Guid id = Ids.New();

        await transfer.SetStateAsync(new SwitchStateRecord(id, SwitchRoles.Source, SwitchStates.Draining, DateTimeOffset.UtcNow, null), default);
        await control.ReactAsync(await transfer.GetStateAsync(default), TimeSpan.FromMilliseconds(100), default);
        Assert.StartsWith("421", await GreetingAsync());
        Assert.False(_runtime.Delivery.Paused); // a drain keeps delivering

        await transfer.SetStateAsync(new SwitchStateRecord(id, SwitchRoles.Source, SwitchStates.Fenced, DateTimeOffset.UtcNow, null), default);
        await control.ReactAsync(await transfer.GetStateAsync(default), TimeSpan.FromMilliseconds(100), default);
        Assert.True(_runtime.Delivery.Paused);
        Assert.Contains(id.ToString(), state.Banner);

        await transfer.SetStateAsync(new SwitchStateRecord(id, SwitchRoles.Source, SwitchStates.Active, DateTimeOffset.UtcNow, "rolled back"), default);
        await control.ReactAsync(await transfer.GetStateAsync(default), TimeSpan.FromMilliseconds(100), default);
        Assert.StartsWith("220", await GreetingAsync());
        Assert.False(_runtime.Delivery.Paused);
        Assert.Null(state.Banner);
    }

    [Fact]
    public async Task A_restricted_start_keeps_the_listeners_answering_421()
    {
        var decision = new StartupDecision(StartupMode.Fenced, "fenced", Ids.New(), SwitchRoles.Source, SwitchStates.Fenced, false);
        var state = new SwitchRuntimeState(decision);
        Assert.False(state.AcceptingApi);
        var control = new HostSwitchControl(_runtime, state);
        await control.StopAcceptingAsync(default);
        await control.ResumeAcceptingAsync(default); // a restricted instance never resumes by itself
        Assert.StartsWith("421", await GreetingAsync());
        Assert.False(state.AcceptingApi);
    }
}
