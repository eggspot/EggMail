using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Domains;
using Mta.Host.Hosting;
using Mta.Storage;
using Mta.Storage.Postgres;
using Mta.Storage.Postgres.Tests;

namespace Mta.Integration.Tests;

/// <summary>
/// <c>Domains:Bootstrap</c> on several replicas that start at the same moment over one PostgreSQL database: each replica has its own storage object and connection pool,
/// and each listed domain is registered once, with one DKIM key and one printed set of records.
/// </summary>
public sealed class DomainBootstrapReplicaTests : IAsyncLifetime
{
    private TestDatabase? _database;

    public async Task InitializeAsync() => _database = await PostgresTestServer.Instance.CreateDatabaseAsync();

    public async Task DisposeAsync()
    {
        if (_database is not null)
        {
            await _database.DisposeAsync();
        }
    }

    private sealed class Protector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => plaintext.ToArray();

        public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose) => protectedData.ToArray();
    }

    private sealed class ListLog : IMtaLog
    {
        private readonly object _gate = new();
        private readonly List<string> _lines = [];

        public IReadOnlyList<string> Lines
        {
            get
            {
                lock (_gate)
                {
                    return _lines.ToList();
                }
            }
        }

        public bool IsEnabled(MtaLogLevel level) => true;

        public void Write(MtaLogLevel level, string source, string message, Exception? exception = null)
        {
            lock (_gate)
            {
                _lines.Add(message);
            }
        }
    }

    [PostgresFact]
    public async Task Replicas_starting_together_register_each_domain_once_and_a_later_start_changes_nothing()
    {
        string[] names = Enumerable.Range(1, 5).Select(i => $"d{i}.example.com").ToArray();
        MtaConfig config = new()
        {
            Hostname = "mta.mail.test",
            Storage = ReplicaHarness.StorageFor(_database!),
            Delivery = new DeliverySection { BounceDomain = "bounces.mail.test" },
            Domains = new DomainsSection { Bootstrap = [.. names] },
        };
        var log = new ListLog();
        var replicas = new List<IStorage>();
        try
        {
            for (int i = 0; i < 4; i++)
            {
                var storage = PostgresStorage.Create(config.Storage, SystemClock.Instance, NullMtaLog.Instance);
                await storage.InitializeAsync(default);
                replicas.Add(storage);
            }

            DomainBootstrapResult[] results = await Task.WhenAll(replicas.Select(s => Task.Run(() => DomainBootstrap.RunAsync(config, s, new Protector(), SystemClock.Instance, log, default))));

            Assert.Equal(names.Order(), results.SelectMany(r => r.Registered).Select(r => r.Domain).Order());
            Assert.All(results, r => Assert.Empty(r.Skipped));
            Assert.Equal(1, await ReplicaHarness.CountAsync(_database!, "SELECT count(*) FROM tenant"));
            Assert.Equal(names.Length, await ReplicaHarness.CountAsync(_database!, "SELECT count(*) FROM domain"));
            Assert.Equal(names.Length, await ReplicaHarness.CountAsync(_database!, "SELECT count(*) FROM dkim_key"));
            foreach (string name in names)
            {
                Assert.Single(log.Lines, l => l.StartsWith("DNS records to create for " + name + ".", StringComparison.Ordinal));
            }

            // Another start later: nothing registered, nothing printed.
            int printed = log.Lines.Count;
            DomainBootstrapResult again = await DomainBootstrap.RunAsync(config, replicas[0], new Protector(), SystemClock.Instance, log, default);
            Assert.Empty(again.Registered);
            Assert.Equal(names.Order(), again.AlreadyRegistered.Order());
            Assert.Equal(printed, log.Lines.Count);
        }
        finally
        {
            foreach (IStorage storage in replicas)
            {
                await storage.DisposeAsync();
            }
        }
    }
}
