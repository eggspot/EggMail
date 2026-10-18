using System.Net;
using System.Net.Sockets;
using System.Text;
using Mta.Core;
using Mta.Dns;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Ingest;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.Postgres;
using Mta.Storage.Postgres.Tests;
using Mta.Storage.Sqlite;

namespace Mta.Integration.Tests;

/// <summary>
/// The inbound receive path of a real <see cref="EggMailRuntime"/> (configuration, listener role, receiver, store) on SQLite and on PostgreSQL: the same scenario against both backends,
/// through the real listener and the real inbound store (the in-memory store is covered by <c>Mta.Host.Tests</c>). The PostgreSQL case needs a server like the other PostgreSQL tests.
/// </summary>
[Collection("Runtime")]
public sealed class InboundReceiveBackendTests
{
    [Fact]
    public async Task The_receive_path_stores_mail_on_sqlite()
    {
        string dir = Directory.CreateTempSubdirectory("eggmail-inbound-").FullName;
        try
        {
            var options = new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = dir, StatsFlushInterval = TimeSpan.Zero } };
            await InboundScenario.RunAsync(options, o => SqliteStorage.Create(o));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }

    [PostgresFact]
    public async Task The_receive_path_stores_mail_on_postgresql()
    {
        await using TestDatabase database = await PostgresTestServer.Instance.CreateDatabaseAsync();
        var options = new StorageOptions
        {
            Backend = StorageBackend.Postgres,
            Postgres = new PostgresOptions { OwnerConnectionString = database.ConnectionString, RuntimeConnectionString = database.ConnectionString },
        };
        await InboundScenario.RunAsync(options, o => PostgresStorage.Create(o, SystemClock.Instance));
    }
}

internal static class InboundScenario
{
    private static readonly Guid Acme = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    private static readonly Guid Globex = Guid.Parse("a0000000-0000-7000-8000-000000000002");

    public static async Task RunAsync(StorageOptions storageOptions, Func<StorageOptions, IStorage> create)
    {
        var dns = new StaticDnsResolver();
        dns.AddTxt("sender.test", "v=spf1 ip4:127.0.0.1 -all");
        dns.AddTxt("other.test", "v=spf1 -all");
        dns.AddTxt("_dmarc.other.test", "v=DMARC1; p=reject");
        var config = new MtaConfig
        {
            Hostname = "mx.egg.test",
            Storage = storageOptions,
            Inbound = new InboundSection { Enabled = true, CheckSpfForInternalClients = true },   // the test sender is 127.0.0.1
            Smtp = new SmtpSection
            {
                Listeners = new Dictionary<string, ListenerSection>
                {
                    ["bounce"] = new() { Port = 0, BindAddress = "127.0.0.1", Mode = ListenerMode.Plain, Role = ListenerRole.Bounce, AuthRequired = false },
                },
            },
            Delivery = new DeliverySection { BounceDomain = "bounces.egg.test", PollInterval = TimeSpan.FromMilliseconds(50) },
        };
        IStorage storage = create(config.Storage);
        await storage.InitializeAsync(default);
        EggMailRuntime runtime = await EggMailRuntime.CreateAsync(config, storage, SystemClock.Instance, NullMtaLog.Instance, default, dns);
        using var stop = new CancellationTokenSource();
        Task refresh = Task.CompletedTask;
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            await storage.Config.UpsertTenantAsync(new Tenant(Acme, "Acme", "acme", true, now, false), default);
            await storage.Config.UpsertTenantAsync(new Tenant(Globex, "Globex", "globex", true, now, false), default);
            Guid org = await AddDomainAsync(storage, Acme, "example.org");
            Guid net = await AddDomainAsync(storage, Globex, "example.net");
            await storage.Inbound.UpsertSettingsAsync(new InboundDomainSettings(org, Acme, true, InboundDmarcAction.Reject, null, null, null, null, null, now), default);
            await storage.Inbound.UpsertSettingsAsync(new InboundDomainSettings(net, Globex, true, InboundDmarcAction.RecordOnly, null, null, null, null, null, now), default);
            Guid support = await AddRouteAsync(storage, org, Acme, 10, InboundMatchKind.Address, "support", InboundActionKind.Store);
            Guid billing = await AddRouteAsync(storage, org, Acme, 20, InboundMatchKind.Wildcard, "billing-*", InboundActionKind.Forward, ["archive@elsewhere.test"]);
            Guid old = await AddRouteAsync(storage, org, Acme, 30, InboundMatchKind.Address, "old", InboundActionKind.Discard);
            await AddRouteAsync(storage, net, Globex, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
            await runtime.InboundConfiguration!.RefreshAsync(default);
            runtime.SmtpServer.Start();
            int port = runtime.SmtpServer.LocalEndPoints["bounce"].Port;

            // A routed message, one recipient: stored with the verdicts, the route and the stamped copy.
            await using (var mta = await MiniSmtp.ConnectAsync(port))
            {
                Assert.Equal(250, (await mta.SendAsync("bob@sender.test", ["support@example.org"], Message("bob@sender.test", "Invoice"))).Code);
                Assert.Equal(250, (await mta.SendAsync("bob@sender.test", ["billing-7@example.org"], Message("bob@sender.test", "Bill"))).Code);
                Assert.Equal(250, (await mta.SendAsync("bob@sender.test", ["old@example.org"], Message("bob@sender.test", "Old"))).Code);
                Assert.Equal(550, (await mta.SendAsync("bob@sender.test", ["nobody@example.org"], Message("bob@sender.test", "x"))).Code);
                await mta.ResetAsync();
                Assert.Equal(550, (await mta.SendAsync("bob@sender.test", ["x@gmail.com"], Message("bob@sender.test", "x"))).Code);
                await mta.ResetAsync();

                // Two tenants in one transaction: one atomic store, a row and a body each.
                Assert.Equal(250, (await mta.SendAsync("bob@sender.test", ["support@example.org", "anyone@example.net"], Message("bob@sender.test", "Both"))).Code);

                // A DMARC failure under the reject action of the only recipient domain is refused after DATA and stores nothing.
                var refused = await mta.SendAsync("eve@other.test", ["support@example.org"], Message("eve@other.test", "Spoof"));
                Assert.Equal(550, refused.Code);
            }

            IReadOnlyList<InboundMessage> acme = (await storage.Inbound.SearchAsync(new InboundMessageQuery(Acme, Limit: 50), default)).Items;
            Assert.Equal(["Bill", "Both", "Invoice", "Old"], acme.Select(m => m.Subject!).Order().ToArray());   // the refused ones were not stored
            InboundMessage invoice = acme.Single(m => m.Subject == "Invoice");
            Assert.Equal((support, InboundActionKind.Store, InboundActionState.Done, InboundVerdict.Pass), (invoice.RouteId, invoice.ActionKind, invoice.ActionState, invoice.Auth.Spf));
            Assert.Equal("support@example.org", invoice.EnvelopeTo);
            string raw = Encoding.UTF8.GetString((await storage.Inbound.GetRawAsync(Acme, invoice.Id, default))!);
            Assert.StartsWith("Received: from client.test ([127.0.0.1])", raw);
            Assert.Contains("\r\nAuthentication-Results: mx.egg.test;", raw);
            Assert.Contains("spf=pass", raw);
            Assert.EndsWith("body\r\n", raw);
            Assert.Equal(invoice.Size, Encoding.UTF8.GetByteCount(raw));

            InboundMessage forward = acme.Single(m => m.Subject == "Bill");
            Assert.Equal((billing, InboundActionKind.Forward, InboundActionState.Pending), (forward.RouteId, forward.ActionKind, forward.ActionState));
            InboundMessage discarded = acme.Single(m => m.Subject == "Old");
            Assert.Equal((old, false), (discarded.RouteId, discarded.HasRaw));
            Assert.Null(await storage.Inbound.GetRawAsync(Acme, discarded.Id, default));

            InboundMessage globexMessage = Assert.Single((await storage.Inbound.SearchAsync(new InboundMessageQuery(Globex), default)).Items);
            Assert.Equal(("Both", "anyone@example.net"), (globexMessage.Subject, globexMessage.EnvelopeTo));
            Assert.NotEqual(acme[0].Id, globexMessage.Id);
            Assert.Null(await storage.Inbound.GetRawAsync(Acme, globexMessage.Id, default));   // another tenant's message is nobody else's

            // A change through the API signal reaches the running receive path without waiting for the interval.
            refresh = runtime.InboundConfiguration!.RunAsync(stop.Token);
            await AddRouteAsync(storage, org, Acme, 40, InboundMatchKind.Address, "late", InboundActionKind.Store);
            InboundConfigChangeSignal.Bump();
            // (A refusal is an error of the session, and a session ends after ten: every attempt is a connection of its own.)
            var deadline = DateTime.UtcNow.AddSeconds(30);
            int code;
            do
            {
                await using var attempt = await MiniSmtp.ConnectAsync(port);
                code = (await attempt.SendAsync("bob@sender.test", ["late@example.org"], Message("bob@sender.test", "Late"))).Code;
                if (code != 250)
                {
                    await Task.Delay(50);
                }
            }
            while (code != 250 && DateTime.UtcNow < deadline);
            Assert.Equal(250, code);

            // Usage is computed by the store: the bodies that exist.
            InboundUsage usage = await storage.Inbound.GetUsageAsync(Acme, null, default);
            Assert.True(usage.BodyBytes > 0);
            Assert.Equal(1, usage.Pending);   // the forward waits for its action
        }
        finally
        {
            await stop.CancelAsync();
            try { await refresh; } catch (OperationCanceledException) { }
            await runtime.SmtpServer.StopAsync(TimeSpan.FromSeconds(2));
            await runtime.DisposeAsync();
            await storage.DisposeAsync();
        }
    }

    private static string Message(string from, string subject) =>
        $"From: {from}\r\nTo: x@example.org\r\nSubject: {subject}\r\nDate: Fri, 16 Oct 2026 12:00:00 +0000\r\nMessage-ID: <{Guid.NewGuid():N}@sender.test>\r\n\r\nbody\r\n";

    private static async Task<Guid> AddDomainAsync(IStorage storage, Guid tenant, string name)
    {
        Guid id = Ids.New();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await storage.Config.UpsertDomainAsync(new DomainRecord(id, tenant, name, DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        return id;
    }

    private static async Task<Guid> AddRouteAsync(IStorage storage, Guid domain, Guid tenant, int order, InboundMatchKind match, string? local, InboundActionKind action, IReadOnlyList<string>? forwardTo = null)
    {
        Guid id = Ids.New();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await storage.Inbound.UpsertRouteAsync(new InboundRouteRecord(id, tenant, domain, local ?? "catch-all", order, true, match, local, false, action, null, InboundWebhookFormat.Json, forwardTo ?? [], now, now), default);
        return id;
    }
}

/// <summary>A minimal scripted sender.</summary>
internal sealed class MiniSmtp : IAsyncDisposable
{
    private readonly TcpClient _tcp = new();
    private StreamReader _reader = null!;
    private StreamWriter _writer = null!;

    public sealed record Reply(int Code, string Text);

    public static async Task<MiniSmtp> ConnectAsync(int port)
    {
        var c = new MiniSmtp();
        await c._tcp.ConnectAsync(IPAddress.Loopback, port);
        Stream stream = c._tcp.GetStream();
        c._reader = new StreamReader(stream, Encoding.Latin1);
        c._writer = new StreamWriter(stream, Encoding.Latin1) { NewLine = "\r\n", AutoFlush = true };
        Assert.Equal(220, (await c.ReadAsync()).Code);
        Assert.Equal(250, (await c.CommandAsync("EHLO client.test")).Code);
        return c;
    }

    private async Task<Reply> ReadAsync()
    {
        while (true)
        {
            string line = await _reader.ReadLineAsync(new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token) ?? throw new EndOfStreamException();
            if (line.Length >= 4 && line[3] == ' ')
            {
                return new Reply(int.Parse(line[..3]), line[4..]);
            }
        }
    }

    public async Task<Reply> CommandAsync(string command)
    {
        await _writer.WriteLineAsync(command);
        return await ReadAsync();
    }

    public async Task ResetAsync() => await CommandAsync("RSET");

    public async Task<Reply> SendAsync(string from, string[] to, string message)
    {
        Reply r = await CommandAsync($"MAIL FROM:<{from}>");
        if (r.Code != 250)
        {
            return r;
        }

        foreach (string rcpt in to)
        {
            r = await CommandAsync($"RCPT TO:<{rcpt}>");
            if (r.Code != 250)
            {
                return r;
            }
        }

        r = await CommandAsync("DATA");
        if (r.Code != 354)
        {
            return r;
        }

        await _writer.WriteAsync(message + ".\r\n");
        return await ReadAsync();
    }

    public ValueTask DisposeAsync()
    {
        _tcp.Dispose();
        return ValueTask.CompletedTask;
    }
}
