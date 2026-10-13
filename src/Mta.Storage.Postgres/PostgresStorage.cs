using Mta.Core;
using Mta.Storage.Logic;
using Mta.Storage.Model;
using Mta.Storage.Transfer;
using Npgsql;

namespace Mta.Storage.Postgres;

/// <summary>
/// The PostgreSQL backend (design §4.3): one database, one transaction across queue, history, outbox, suppressions and
/// statistics. Behaviour is identical to the SQLite and in-memory backends (decision E); only the characteristics differ:
/// many replicas (claims use <c>FOR UPDATE SKIP LOCKED</c>), day partitions dropped by retention, and WAL synced at commit.
/// <para><b>Roles.</b> <c>Postgres:OwnerConnectionString</c> is the schema owner: it runs migrations
/// (<see cref="PostgresMigrator"/>) and creates and drops day partitions. <c>Postgres:RuntimeConnectionString</c> is the role
/// the application uses for everything else (select, insert, update, delete; no DDL). With only one connection string given it
/// serves both roles (a warning <c>postgres_single_role</c> appears in health). With <c>Postgres:AutoMigrate=false</c> the schema
/// must already be at <see cref="PostgresMigrator.CurrentVersion"/> or <see cref="InitializeAsync"/> fails; produce it with
/// <see cref="PostgresMigrator.GenerateScript"/>.</para>
/// <para><b>Acknowledgement.</b> <see cref="IMessageIntake.AcceptAsync"/> returns after the transaction committed; PostgreSQL's
/// own <c>synchronous_commit</c> decides whether that included an fsync (default: yes).</para>
/// <para><b>Outages.</b> Every method throws <see cref="StorageUnavailableException"/> when the database cannot be reached, so the
/// SMTP layer can answer 451; <see cref="IStorageMaintenance.GetHealthAsync"/> reports <c>Ready=false</c> instead of throwing.</para>
/// <para><b>Backups</b> are the database operator's job (<c>pg_dump</c>, base backups, PITR): <see cref="IStorageMaintenance.BackupAsync"/> returns null.</para>
/// </summary>
public sealed class PostgresStorage : IStorage
{
    private readonly StorageOptions _options;
    private readonly PostgresRuntime _rt;
    private readonly PostgresStatsStore _stats;
    private readonly PostgresQueueStore _queue;
    private readonly PostgresHistoryStore _history;
    private CancellationTokenSource? _flushCts;
    private Task? _flushLoop;
    private PostgresMaintenance? _maintenance;
    private EfStorageTransfer? _transfer;
    private int _initialized;
    private int _disposed;

    private PostgresStorage(StorageOptions options, IClock clock, IMtaLog log)
    {
        StorageOptionsValidation.Validate(options);
        PostgresOptions pg = options.Postgres;
        if (pg.MaxPoolSize < 1 || pg.PartitionsAheadDays < 0 || pg.RetentionDeleteBatchSize < 1 || pg.StatsFlushInterval < TimeSpan.Zero || pg.CommandTimeoutSeconds < 1)
        {
            throw new ArgumentException("Postgres options out of range (pool size, partitions ahead, batch size, flush interval, command timeout).");
        }

        if (pg.ReadOnlyStatementTimeoutSeconds < 1 || pg.ReadOnlyIdleInTransactionTimeoutSeconds < 1 || pg.ReadOnlyMaxPoolSize < 1)
        {
            throw new ArgumentException("Postgres read-only options out of range (statement timeout, idle-in-transaction timeout, pool size must each be at least 1).");
        }

        _options = options;
        _rt = new PostgresRuntime(options, clock, log);
        _stats = new PostgresStatsStore(_rt);
        _history = new PostgresHistoryStore(_rt);
        _queue = new PostgresQueueStore(_rt, _history);
    }

    /// <summary>Creates the storage. Call <see cref="InitializeAsync"/> before use.</summary>
    public static PostgresStorage Create(StorageOptions options, IClock? clock = null, IMtaLog? log = null) =>
        new(options, clock ?? SystemClock.Instance, log ?? NullMtaLog.Instance);

    public StorageBackend Backend => StorageBackend.Postgres;

    public HistoryMode HistoryMode => _options.History.Mode;

    public IMessageIntake Intake => _queue;

    public IDeliveryStore Deliveries => _queue;

    public IConfigStore Config => _rt.ConfigStore ?? throw NotInitialized();

    public IStatsStore Stats => _stats;

    public IHistoryStore History => _history;

    public IWebhookOutbox Webhooks => _queue;

    public IStorageMaintenance Maintenance => _maintenance ?? throw NotInitialized();

    public IStorageTransfer Transfer => _transfer ?? throw NotInitialized();

    /// <summary>The shared runtime state (data sources, partition manager) for the PostgreSQL-specific tests.</summary>
    internal PostgresRuntime Runtime => _rt;

    private static InvalidOperationException NotInitialized() => new("Call InitializeAsync before using the storage.");

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _initialized, 1) != 0)
        {
            return;
        }

        try
        {
            if (_options.Postgres.AutoMigrate)
            {
                string? runtimeRole = _rt.SingleRole ? null : _rt.RuntimeRole;
                await using NpgsqlConnection owner = await _rt.Owner.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
                await using var cmd = new NpgsqlCommand(PostgresMigrator.GenerateScript(runtimeRole, _rt.ReadOnlyRoleToGrant), owner) { CommandTimeout = 300 };
                try
                {
                    await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (PostgresException ex) when (ex.SqlState == "42704" && _rt.ReadOnlyRoleToGrant is { } missing)
                {
                    // undefined_object: the GRANT names a role that does not exist
                    throw new InvalidOperationException(
                        $"The migration could not grant the read-only role '{missing}' (Postgres:ReadOnlyConnectionString): it does not exist ({ex.MessageText}). " +
                        $"Create it first, as a login role (CREATE ROLE {missing} LOGIN PASSWORD '...'), or remove Postgres:ReadOnlyConnectionString.", ex);
                }
            }

            int version = await PostgresMigrator.GetDatabaseVersionAsync(_rt.Data, cancellationToken).ConfigureAwait(false);
            if (version != PostgresMigrator.CurrentVersion)
            {
                throw new InvalidOperationException(
                    $"The database schema is at version {version} but this build needs version {PostgresMigrator.CurrentVersion}. " +
                    "Enable Postgres:AutoMigrate or apply PostgresMigrator.GenerateScript() as the owner role.");
            }

            await CheckReadOnlyRoleAsync(cancellationToken).ConfigureAwait(false);
            _rt.ConfigStore = new EfConfigStore<PostgresDbContext>(new PostgresConfigAccess(_rt.Data, PostgresModelHooks.Instance, _options.Postgres.MaxPoolSize));
            if (_rt.IsFull)
            {
                int today = StorageTime.DayNumber(_rt.Clock.UtcNow);
                await _rt.Partitions.EnsureRangeAsync(today - 1, today + Math.Max(1, _options.Postgres.PartitionsAheadDays), cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            await DisposeAsync().ConfigureAwait(false);
            throw _rt.Unavailable(ex);
        }
        catch
        {
            await DisposeAsync().ConfigureAwait(false);
            throw;
        }

        _maintenance = new PostgresMaintenance(_rt, _queue, _stats);
        try
        {
            // A backend switch may have closed this store (a fenced source, a target that is not activated yet); the state is persisted.
            _transfer = new EfStorageTransfer(new PostgresTransferAccess(_rt, PostgresModelHooks.Instance), _rt.ConfigStore, _rt.Fence, _rt.Clock);
            _rt.Fence.Apply(await _rt.ConfigStore.GetSwitchStateAsync(cancellationToken).ConfigureAwait(false));
            if (_rt.Fence.IsClosed)
            {
                _rt.Log.Write(MtaLogLevel.Warning, "storage.postgres", _rt.Fence.Reason!);
            }
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex))
        {
            await DisposeAsync().ConfigureAwait(false);
            throw _rt.Unavailable(ex);
        }

        if (_rt.SingleRole)
        {
            _rt.Log.Write(MtaLogLevel.Warning, "storage.postgres", "One PostgreSQL connection string serves as both owner and runtime role. Use separate roles (Postgres:OwnerConnectionString / RuntimeConnectionString) so the application cannot alter the schema.");
        }

        if (_options.Postgres.StatsFlushInterval > TimeSpan.Zero)
        {
            _flushCts = new CancellationTokenSource();
            _flushLoop = FlushLoopAsync(_options.Postgres.StatsFlushInterval, _flushCts.Token);
        }
    }

    /// <summary>
    /// With a read-only connection string: opens it once and reads a history table, so a wrong password, a role without the grants (the schema was migrated by a script made
    /// without the read-only role) or a role that was never created stops the start with that explanation, not on the first dashboard query.
    /// </summary>
    private async Task CheckReadOnlyRoleAsync(CancellationToken cancellationToken)
    {
        if (!_rt.SeparateReader)
        {
            return;
        }

        try
        {
            await using NpgsqlConnection connection = await _rt.Reader.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var cmd = new NpgsqlCommand("SELECT 1 FROM message_index LIMIT 1", connection);
            await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrors.InsufficientPrivilege)
        {
            throw new InvalidOperationException(
                $"The read-only role '{_rt.ReadOnlyRole}' (Postgres:ReadOnlyConnectionString) cannot read the history tables. Apply the migration with the read-only role named " +
                "(Postgres:AutoMigrate, or mta migrate-db with the same configuration, or PostgresMigrator.GenerateScript(runtimeRole, readOnlyRole) as the owner).", ex);
        }
        catch (Exception ex) when (PostgresErrors.IsUnavailable(ex) || ex is PostgresException)
        {
            throw new InvalidOperationException($"The read-only connection (Postgres:ReadOnlyConnectionString, role '{_rt.ReadOnlyRole}') cannot be used: {ex.Message}", ex);
        }
    }

    private async Task FlushLoopAsync(TimeSpan interval, CancellationToken ct)
    {
        using var timer = new PeriodicTimer(interval);
        try
        {
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            {
                try
                {
                    await _stats.FlushAsync(ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _rt.Log.Write(MtaLogLevel.Error, "storage.postgres", "Statistics flush failed; the counters are kept and retried.", ex);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        if (_flushCts is not null)
        {
            await _flushCts.CancelAsync().ConfigureAwait(false);
            if (_flushLoop is not null)
            {
                await _flushLoop.ConfigureAwait(false);
            }

            _flushCts.Dispose();
        }

        if (_maintenance is not null)
        {
            try
            {
                await _stats.FlushAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _rt.Log.Write(MtaLogLevel.Error, "storage.postgres", "Final statistics flush failed.", ex);
            }
        }

        await _rt.Data.DisposeAsync().ConfigureAwait(false);
        if (_rt.SeparateReader)
        {
            await _rt.Reader.DisposeAsync().ConfigureAwait(false);
        }

        await _rt.Owner.DisposeAsync().ConfigureAwait(false);
    }
}
