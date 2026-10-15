using System.Net;
using System.Reflection;
using System.Text;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Mta.Core;
using Mta.Dsn;
using Mta.Host.Ingest;
using Mta.Host.Security;
using Mta.Host.Submission;
using Mta.Policy;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.InMemory;
using Mta.Webhooks;

namespace Mta.Host.Tests;

/// <summary>
/// The bounce listener looks a sending domain up only for a valid token at a host other than the shared bounce domain, and remembers the answer for
/// a minute. A storage failure during that lookup is a temporary refusal (451), not a verdict on the address.
/// </summary>
public class ReturnPathLookupTests
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    /// <summary>The real in-memory config store, except that <c>FindDomainByNameAsync</c> is counted and can be made to fail.</summary>
    public class ConfigProxy : DispatchProxy
    {
        public IConfigStore Inner { get; set; } = null!;
        public int Lookups;
        public bool FailLookups;

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            if (targetMethod!.Name == nameof(IConfigStore.FindDomainByNameAsync))
            {
                Interlocked.Increment(ref Lookups);
                if (FailLookups)
                {
                    throw new InvalidOperationException("the config store is down");
                }
            }

            try
            {
                return targetMethod.Invoke(Inner, args);
            }
            catch (TargetInvocationException ex) when (ex.InnerException is not null)
            {
                throw ex.InnerException;
            }
        }
    }

    private sealed class StorageWithConfig(IStorage inner, IConfigStore config) : IStorage
    {
        public StorageBackend Backend => inner.Backend;
        public HistoryMode HistoryMode => inner.HistoryMode;
        public IMessageIntake Intake => inner.Intake;
        public IDeliveryStore Deliveries => inner.Deliveries;
        public IConfigStore Config => config;
        public IStatsStore Stats => inner.Stats;
        public IHistoryStore History => inner.History;
        public IWebhookOutbox Webhooks => inner.Webhooks;
        public IStorageMaintenance Maintenance => inner.Maintenance;
        public Task InitializeAsync(CancellationToken cancellationToken) => inner.InitializeAsync(cancellationToken);
        public ValueTask DisposeAsync() => inner.DisposeAsync();
    }

    private sealed class Rig : IAsyncDisposable
    {
        public required InMemoryStorage Real { get; init; }
        public required ConfigProxy Proxy { get; init; }
        public required SmtpServer Server { get; init; }
        public required VerpCodec Verp { get; init; }
        public int Port => Server.LocalEndPoints["bounce"].Port;

        public static async Task<Rig> CreateAsync()
        {
            var real = new InMemoryStorage(new StorageOptions());
            await real.InitializeAsync(default);
            var now = DateTimeOffset.UtcNow;
            await real.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, now, false), default);
            await real.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), TenantId, "dedicated.example", DomainStatus.Verified, "bounce.dedicated.example", true, now, now, now, 0, null, false, null), default);

            var config = DispatchProxy.Create<IConfigStore, ConfigProxy>();
            var proxy = (ConfigProxy)(object)config;
            proxy.Inner = real.Config;
            var storage = new StorageWithConfig(real, config);
            var verp = new VerpCodec(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey() }, 1);
            var submission = new SubmissionService(storage, SystemClock.Instance, new SenderPolicy(), new StorageOptions(), new SubmissionOptions { MessageIdDomain = "egg.test" });
            var bounces = new BounceProcessor(verp, storage.Config, storage.Stats, new StorageWebhookPublisher(storage), SystemClock.Instance);
            var handler = new IngestHandler(storage, submission, new AuthThrottle(), new IngestOptions { BounceDomain = "bounces.egg.test" }, bounces);
            var server = new SmtpServer(new SmtpServerOptions
            {
                Hostname = "egg.test",
                Listeners = [new SmtpListenerOptions { Name = "bounce", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce }],
            }, handler);
            server.Start();
            return new Rig { Real = real, Proxy = proxy, Server = server, Verp = verp };
        }

        public string Address(string host) => Verp.CreateAddress(TenantId, Ids.New(), host, DateTimeOffset.UtcNow, "dest.example");

        public async Task<int> SendAsync(string to)
        {
            using var client = new SmtpClient();
            await client.ConnectAsync("127.0.0.1", Port, SecureSocketOptions.None);
            var m = new MimeMessage();
            m.From.Add(MailboxAddress.Parse("mailer-daemon@remote.example"));
            m.To.Add(MailboxAddress.Parse(to));
            m.Subject = "Undelivered";
            m.Body = new TextPart("plain") { Text = "not a report" };
            try
            {
                await client.SendAsync(m);
                return 250;
            }
            catch (SmtpCommandException ex)
            {
                return (int)ex.StatusCode;
            }
        }

        public async ValueTask DisposeAsync()
        {
            await Server.DisposeAsync();
            await Real.DisposeAsync();
        }
    }

    [Fact]
    public async Task A_storage_failure_while_checking_a_return_path_host_is_a_temporary_refusal()
    {
        await using var rig = await Rig.CreateAsync();
        rig.Proxy.FailLookups = true;

        Assert.Equal(451, await rig.SendAsync(rig.Address("bounce.dedicated.example")));

        rig.Proxy.FailLookups = false;
        Assert.Equal(250, await rig.SendAsync(rig.Address("bounce.dedicated.example")));   // the failure was not remembered
    }

    [Fact]
    public async Task The_answer_for_a_host_is_remembered_so_the_rcpt_and_the_data_and_the_next_bounce_cost_one_lookup()
    {
        await using var rig = await Rig.CreateAsync();

        Assert.Equal(250, await rig.SendAsync(rig.Address("bounce.dedicated.example")));
        Assert.Equal(250, await rig.SendAsync(rig.Address("bounce.dedicated.example")));
        Assert.Equal(550, await rig.SendAsync(rig.Address("bounce.nosuch.example")));
        Assert.Equal(550, await rig.SendAsync(rig.Address("bounce.nosuch.example")));

        Assert.Equal(2, rig.Proxy.Lookups);   // one per distinct host, however many commands asked
    }

    [Fact]
    public async Task Strangers_addresses_cost_no_lookup_at_all()
    {
        await using var rig = await Rig.CreateAsync();
        var forged = new VerpCodec(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey() }, 1).CreateAddress(TenantId, Ids.New(), "bounce.dedicated.example", DateTimeOffset.UtcNow, "dest.example");

        Assert.Equal(550, await rig.SendAsync(forged));
        Assert.Equal(550, await rig.SendAsync("someone@bounce.dedicated.example"));

        Assert.Equal(0, rig.Proxy.Lookups);
    }
}
