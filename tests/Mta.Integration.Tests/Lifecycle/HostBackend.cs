using Mta.Core;
using Mta.Dns;
using Mta.Storage;
using Mta.Storage.Postgres;
using Mta.Storage.Postgres.Tests;
using Mta.Storage.Sqlite;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>
/// One storage backend for the accelerated lifecycle tests of the host services (keys, sessions, domain verification, TLS-RPT): a SQLite directory or a PostgreSQL
/// database of its own, opened with the test's virtual clock. <see cref="RestartAsync"/> closes the storage and opens another over the same files or database, which is
/// what a process restart looks like to the services above it.
/// </summary>
internal sealed class HostBackend : IAsyncDisposable
{
    private readonly IClock _clock;
    private readonly StorageOptions _options;
    private readonly string? _directory;
    private readonly TestDatabase? _database;

    private HostBackend(string name, IClock clock, StorageOptions options, string? directory, TestDatabase? database)
    {
        Name = name;
        _clock = clock;
        _options = options;
        _directory = directory;
        _database = database;
    }

    public string Name { get; }

    public IStorage Storage { get; private set; } = null!;

    public static async Task<HostBackend> SqliteAsync(IClock clock)
    {
        string dir = Directory.CreateTempSubdirectory("eggmail-lifecycle-").FullName;
        var options = new StorageOptions
        {
            Backend = StorageBackend.Sqlite,
            // ConfigSyncMode Off: these tests are about time, not about surviving an operating system crash, and an fsync per write only slows the virtual year down.
            Sqlite = new SqliteOptions { DataDirectory = dir, ConfigSyncMode = SqliteSyncMode.Off, StatsFlushInterval = TimeSpan.Zero, RetentionDeletePause = TimeSpan.FromMilliseconds(1) },
        };
        var backend = new HostBackend("sqlite", clock, options, dir, null);
        await backend.OpenAsync();
        return backend;
    }

    public static async Task<HostBackend> PostgresAsync(IClock clock)
    {
        TestDatabase database = await PostgresTestServer.Instance.CreateDatabaseAsync();
        var options = new StorageOptions
        {
            Backend = StorageBackend.Postgres,
            Postgres = new PostgresOptions
            {
                OwnerConnectionString = database.ConnectionString,
                RuntimeConnectionString = database.ConnectionString,
                MaxPoolSize = 8,
                StatsFlushInterval = TimeSpan.Zero,
                RetentionDeletePause = TimeSpan.FromMilliseconds(1),
            },
        };
        var backend = new HostBackend("postgres", clock, options, null, database);
        await backend.OpenAsync();
        return backend;
    }

    private async Task OpenAsync()
    {
        Storage = _options.Backend == StorageBackend.Sqlite ? SqliteStorage.Create(_options, _clock) : PostgresStorage.Create(_options, _clock);
        await Storage.InitializeAsync(CancellationToken.None);
    }

    /// <summary>Closes the storage and opens a new one over the same data (what a restart of the process does).</summary>
    public async Task RestartAsync()
    {
        await Storage.DisposeAsync();
        await OpenAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await Storage.DisposeAsync();
        if (_database is not null)
        {
            await _database.DisposeAsync();
        }

        if (_directory is not null)
        {
            // A directory this backend created itself (a unique name under the temp folder) and the only owner of its files.
            Directory.Delete(_directory, recursive: true);
        }
    }
}

/// <summary>A DNS resolver the test changes while virtual time passes: records come and go, names fail with SERVFAIL, and queries are counted.</summary>
internal sealed class LifecycleDns : IDnsResolver
{
    private readonly object _gate = new();
    private readonly List<DnsRecord> _records = [];
    private readonly HashSet<string> _failing = new(StringComparer.Ordinal);
    private int _queries;

    public int Queries => Volatile.Read(ref _queries);

    public bool ServerFailure { get; set; }

    private static string Normalize(string name) => name.TrimEnd('.').ToLowerInvariant();

    public LifecycleDns SetTxt(string name, string text, uint ttl = 300)
    {
        lock (_gate)
        {
            _records.RemoveAll(r => r is TxtRecord && r.Name == Normalize(name));
            _records.Add(new TxtRecord(Normalize(name), ttl, text));
        }

        return this;
    }

    public LifecycleDns SetCname(string name, string target, uint ttl = 300)
    {
        lock (_gate)
        {
            _records.RemoveAll(r => r is CnameRecord && r.Name == Normalize(name));
            _records.Add(new CnameRecord(Normalize(name), ttl, Normalize(target)));
        }

        return this;
    }

    public LifecycleDns Remove(string name)
    {
        lock (_gate)
        {
            _records.RemoveAll(r => r.Name == Normalize(name));
        }

        return this;
    }

    public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _queries);
        if (ServerFailure)
        {
            return ValueTask.FromResult(new DnsResponse { Rcode = DnsRcode.ServerFailure });
        }

        lock (_gate)
        {
            string n = Normalize(name);
            var named = _records.Where(r => r.Name == n).ToList();
            if (named.Count == 0)
            {
                return ValueTask.FromResult(new DnsResponse { Rcode = DnsRcode.NameError, Ttl = 300 });
            }

            var answers = named.Where(r => r.Type == type).ToArray();
            if (answers.Length == 0 && named.OfType<CnameRecord>().FirstOrDefault() is { } cname && type != DnsRecordType.CNAME)
            {
                var target = _records.Where(r => r.Name == cname.Target && r.Type == type).ToArray();
                return ValueTask.FromResult(new DnsResponse { Rcode = DnsRcode.NoError, Answers = [cname, .. target], Ttl = 300 });
            }

            return ValueTask.FromResult(new DnsResponse { Rcode = DnsRcode.NoError, Answers = answers, Ttl = 300 });
        }
    }
}
