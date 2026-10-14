using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Mta.Storage.Sqlite;

internal enum SqliteFileKind
{
    Queue,
    Stats,
    Config,
    History,
}

/// <summary>One SQLite database file (queue.db, stats.db, config.db, history.db): its settings, connections, schema and integrity.</summary>
internal sealed class SqliteFile
{
    /// <summary>
    /// Bumped when a schema change needs a migration step (stored in <c>PRAGMA user_version</c>). Version 2 added the dashboard user and
    /// session tables (config.db) and <c>api_idempotency_key.fingerprint</c> (queue.db); version 3 added the backend switch hold column
    /// and progress tables; version 4 the persisted runtime state tables (config.db) and the Message-ID header and tags of <c>message_index</c>
    /// (history.db). <see cref="UpgradeFromV1"/>, <see cref="UpgradeFromV2"/> and <see cref="UpgradeFromV3"/> apply them in turn.
    /// </summary>
    public const int SchemaVersion = Model.StorageModel.SchemaVersion;

    private readonly SqliteOptions _options;
    private readonly Func<string> _createScript;
    private readonly string _readerConnectionString;
    private readonly string _writerConnectionString;

    public SqliteFile(SqliteFileKind kind, SqliteOptions options, SqliteSyncMode sync, bool inMemory, Func<string> createScript, IReadOnlyCollection<string> withoutRowIdTables)
    {
        Kind = kind;
        Sync = sync;
        IsMemory = inMemory;
        _options = options;
        _createScript = createScript;
        WithoutRowIdTables = withoutRowIdTables;
        Name = kind.ToString().ToLowerInvariant();
        ReadSessions = new SqliteReadSessionPool(this);
        FileName = Name + ".db";
        Path = inMemory ? null : System.IO.Path.Combine(options.DataDirectory, FileName);
        int timeoutSeconds = Math.Max(1, (int)Math.Ceiling(options.BusyTimeout.TotalSeconds));
        string source = inMemory ? ":memory:" : Path!;
        _writerConnectionString = new SqliteConnectionStringBuilder
        {
            DataSource = source,
            Mode = inMemory ? SqliteOpenMode.Memory : SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            DefaultTimeout = timeoutSeconds,
        }.ToString();
        _readerConnectionString = new SqliteConnectionStringBuilder
        {
            DataSource = source,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = true,
            DefaultTimeout = timeoutSeconds,
        }.ToString();
    }

    public SqliteFileKind Kind { get; }

    /// <summary>Open read connections with prepared statements for the reads on the delivery path (not used for the in-memory queue, whose reads run on its writer).</summary>
    public SqliteReadSessionPool ReadSessions { get; }

    public string Name { get; }

    public string FileName { get; }

    public string? Path { get; }

    public bool IsMemory { get; }

    public SqliteSyncMode Sync { get; }

    public IReadOnlyCollection<string> WithoutRowIdTables { get; }

    /// <summary>The connection string used by EF read contexts (pooled connections).</summary>
    public string ReaderConnectionString => _readerConnectionString;

    /// <summary>
    /// Opens the single write connection of this file. Pragmas (what each means):
    /// <list type="bullet">
    /// <item><c>auto_vacuum=INCREMENTAL</c> (new files only, before any table exists): freed pages go on a free list and are
    /// returned to the OS by <c>incremental_vacuum</c> after retention deletes; a plain file never shrinks.</item>
    /// <item><c>journal_mode=WAL</c>: writers append to a write-ahead log, so readers never block the writer and the writer
    /// never blocks readers. Persistent in the file. (Not available on network file systems.)</item>
    /// <item><c>synchronous</c>: <c>OFF</c> never fsyncs (a process kill is safe, an OS crash or power loss can corrupt);
    /// <c>NORMAL</c> fsyncs the WAL only at checkpoints (no corruption, recent commits may roll back on power loss);
    /// <c>FULL</c> fsyncs the WAL on every commit (durable). Per connection.</item>
    /// <item><c>busy_timeout</c>: how long a statement waits for a lock (checkpoints, other connections) before SQLITE_BUSY.</item>
    /// <item><c>journal_size_limit</c>: after a checkpoint the WAL file is truncated to at most this size instead of staying
    /// at its high-water mark.</item>
    /// <item><c>cache_size</c>: page cache of the writer (negative = KiB).</item>
    /// </list>
    /// </summary>
    public SqliteConnection OpenWriter()
    {
        var connection = new SqliteConnection(_writerConnectionString);
        connection.Open();
        try
        {
            if (!IsMemory && IsEmptyDatabase(connection))
            {
                // Only effective before the first table is created.
                Execute(connection, "PRAGMA auto_vacuum=INCREMENTAL");
            }

            if (!IsMemory)
            {
                Execute(connection, "PRAGMA journal_mode=WAL");
            }

            Execute(connection, "PRAGMA synchronous=" + Sync.ToString().ToUpperInvariant());
            Execute(connection, "PRAGMA busy_timeout=" + ((long)_options.BusyTimeout.TotalMilliseconds).ToString(CultureInfo.InvariantCulture));
            Execute(connection, "PRAGMA journal_size_limit=" + _options.JournalSizeLimitBytes.ToString(CultureInfo.InvariantCulture));
            Execute(connection, "PRAGMA cache_size=-16384");
            EnsureSchema(connection);
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    /// <summary>Opens a short-lived (pooled) read connection.</summary>
    public SqliteConnection OpenReader()
    {
        var connection = new SqliteConnection(_readerConnectionString);
        connection.Open();
        return connection;
    }

    /// <summary>Releases pooled connections so the files can be moved or deleted.</summary>
    public void ClearPool()
    {
        ReadSessions.Clear();
        if (IsMemory)
        {
            return;
        }

        using var probe = new SqliteConnection(_readerConnectionString);
        SqliteConnection.ClearPool(probe);
    }

    private static bool IsEmptyDatabase(SqliteConnection connection)
    {
        object? tables = Scalar(connection, "SELECT count(*) FROM sqlite_master WHERE type='table'");
        return Convert.ToInt64(tables, CultureInfo.InvariantCulture) == 0;
    }

    private void EnsureSchema(SqliteConnection connection)
    {
        long version = Convert.ToInt64(Scalar(connection, "PRAGMA user_version"), CultureInfo.InvariantCulture);
        if (version > SchemaVersion)
        {
            throw new InvalidOperationException($"{FileName} has schema version {version}, newer than this build supports ({SchemaVersion}). Refusing to open it.");
        }

        if (version == SchemaVersion)
        {
            return;
        }

        if (version >= 1)
        {
            // One step per version, each in its own transaction: a file at 1 goes through 2, 3 and 4 to 5, a file at 3 goes through 4 to 5.
            if (version == 1)
            {
                UpgradeFromV1(connection);
            }

            if (version <= 2)
            {
                UpgradeFromV2(connection);
            }

            if (version <= 3)
            {
                UpgradeFromV3(connection);
            }

            UpgradeFromV4(connection);
            return;
        }

        if (!IsEmptyDatabase(connection))
        {
            throw new InvalidOperationException($"{FileName} contains tables but no schema version; refusing to modify an unknown database.");
        }

        string script = ApplyWithoutRowId(_createScript(), WithoutRowIdTables);
        using var tx = connection.BeginTransaction();
        using (var cmd = connection.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = script;
            cmd.ExecuteNonQuery();
        }

        using (var cmd = connection.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "PRAGMA user_version=" + SchemaVersion.ToString(CultureInfo.InvariantCulture);
            cmd.ExecuteNonQuery();
        }

        tx.Commit();
    }

    /// <summary>Version 1 to 2: adds what the HTTP API introduced, taking the statements from the generated schema so they cannot drift from the model.</summary>
    private void UpgradeFromV1(SqliteConnection connection)
    {
        string script = ApplyWithoutRowId(_createScript(), WithoutRowIdTables);
        var statements = new List<string>();
        if (Kind == SqliteFileKind.Config)
        {
            foreach (string table in new[] { "dashboard_user", "dashboard_session" })
            {
                statements.Add(Regex.Match(script, "CREATE TABLE \"" + table + "\" \\(.*?\\r?\\n\\);", RegexOptions.Singleline).Value);
                foreach (Match index in Regex.Matches(script, "CREATE (?:UNIQUE )?INDEX \"[^\"]+\" ON \"" + table + "\" [^;]*;"))
                {
                    statements.Add(index.Value);
                }
            }
        }
        else if (Kind == SqliteFileKind.Queue)
        {
            statements.Add("ALTER TABLE \"api_idempotency_key\" ADD COLUMN \"fingerprint\" TEXT NULL;");
        }

        if (statements.Any(string.IsNullOrEmpty))
        {
            throw new InvalidOperationException($"Could not derive the version 2 upgrade of {FileName} from the generated schema script.");
        }

        using var tx = connection.BeginTransaction();
        foreach (string statement in statements)
        {
            using var cmd = connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = statement;
            cmd.ExecuteNonQuery();
        }

        using (var cmd = connection.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "PRAGMA user_version=2";
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    /// <summary>
    /// Version 3 added the backend switch columns and progress table (design §4.6): <c>transfer_switch_id</c> on the queue and
    /// outbox rows (a transfer mark or activation hold) and one <c>transfer_chunk_*</c> table per file.
    /// </summary>
    private void UpgradeFromV2(SqliteConnection connection)
    {
        string chunkTable = "transfer_chunk_" + Name;
        var regex = new Regex("CREATE TABLE \"" + chunkTable + "\" \\(.*?\\r?\\n\\);", RegexOptions.Singleline);
        Match create = regex.Match(_createScript());
        if (!create.Success)
        {
            throw new InvalidOperationException($"Could not find CREATE TABLE for {chunkTable} in the generated schema script.");
        }

        using var tx = connection.BeginTransaction();

        void Run(string sql)
        {
            using var cmd = connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = sql;
            cmd.ExecuteNonQuery();
        }

        if (Kind == SqliteFileKind.Queue)
        {
            Run("ALTER TABLE \"delivery_queue\" ADD COLUMN \"transfer_switch_id\" TEXT NULL");
            Run("ALTER TABLE \"webhook_outbox\" ADD COLUMN \"transfer_switch_id\" TEXT NULL");
        }

        Run(create.Value);
        Run("PRAGMA user_version=3");
        tx.Commit();
    }

    /// <summary>
    /// Version 4 added the persisted runtime state (<c>domain_record_check</c>, <c>tls_rpt_bucket</c>, <c>sending_counter</c> in config.db) and the
    /// <c>message_id_header</c> and <c>tags</c> columns with the header index on <c>message_index</c> (history.db). The statements come from the generated schema
    /// script so they cannot drift from the model, and each is skipped when its table, column or index already exists (a file taken back to an older version by hand).
    /// </summary>
    private void UpgradeFromV3(SqliteConnection connection)
    {
        string script = ApplyWithoutRowId(_createScript(), WithoutRowIdTables);
        var statements = new List<string>();
        if (Kind == SqliteFileKind.Config)
        {
            foreach (string table in new[] { "domain_record_check", "tls_rpt_bucket", "sending_counter" })
            {
                statements.Add(IfNotExists(Regex.Match(script, "CREATE TABLE \"" + table + "\" \\(.*?\\r?\\n\\)(?: WITHOUT ROWID)?;", RegexOptions.Singleline).Value));
                foreach (Match index in Regex.Matches(script, "CREATE (?:UNIQUE )?INDEX \"[^\"]+\" ON \"" + table + "\" [^;]*;"))
                {
                    statements.Add(IfNotExists(index.Value));
                }
            }
        }
        else if (Kind == SqliteFileKind.History)
        {
            statements.Add("ALTER TABLE \"message_index\" ADD COLUMN \"message_id_header\" TEXT NULL;");
            statements.Add("ALTER TABLE \"message_index\" ADD COLUMN \"tags\" TEXT NULL;");
            statements.Add(IfNotExists(Regex.Match(script, "CREATE INDEX \"[^\"]*message_id_header\" ON \"message_index\" [^;]*;").Value));
        }

        if (statements.Any(string.IsNullOrEmpty))
        {
            throw new InvalidOperationException($"Could not derive the version 4 upgrade of {FileName} from the generated schema script.");
        }

        using var tx = connection.BeginTransaction();

        void Run(string sql)
        {
            using var cmd = connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = sql;
            cmd.ExecuteNonQuery();
        }

        foreach (string statement in statements)
        {
            if (statement.StartsWith("ALTER TABLE", StringComparison.Ordinal) && ColumnExists(connection, tx, "message_index", statement.Split('"')[3]))
            {
                continue;
            }

            Run(statement);
        }

        Run("PRAGMA user_version=4");
        tx.Commit();
    }

    private static string IfNotExists(string statement) =>
        statement.Length == 0 ? statement : Regex.Replace(statement, "^CREATE (UNIQUE )?(TABLE|INDEX) ", "CREATE $1$2 IF NOT EXISTS ");

    private static bool ColumnExists(SqliteConnection connection, SqliteTransaction tx, string table, string column)
    {
        using var cmd = connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "SELECT count(*) FROM pragma_table_info('" + table + "') WHERE name = '" + column + "'";
        return Convert.ToInt64(cmd.ExecuteScalar(), CultureInfo.InvariantCulture) > 0;
    }

    /// <summary>Version 5 added <c>delivery_queue.headers_utf8</c> (the message's headers are internationalized); existing rows get false. Skipped when the column already exists (a file taken back to an older version by hand).</summary>
    private void UpgradeFromV4(SqliteConnection connection)
    {
        using var tx = connection.BeginTransaction();
        if (Kind == SqliteFileKind.Queue && !ColumnExists(connection, tx, "delivery_queue", "headers_utf8"))
        {
            using var alter = connection.CreateCommand();
            alter.Transaction = tx;
            alter.CommandText = "ALTER TABLE \"delivery_queue\" ADD COLUMN \"headers_utf8\" INTEGER NOT NULL DEFAULT 0";
            alter.ExecuteNonQuery();
        }

        using var cmd = connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "PRAGMA user_version=5";
        cmd.ExecuteNonQuery();
        tx.Commit();
    }

    /// <summary>Turns <c>CREATE TABLE "t" (...);</c> into a <c>WITHOUT ROWID</c> table for the listed tables.</summary>
    internal static string ApplyWithoutRowId(string script, IEnumerable<string> tables)
    {
        foreach (string table in tables)
        {
            var regex = new Regex("(CREATE TABLE \"" + Regex.Escape(table) + "\" \\(.*?\\r?\\n\\));", RegexOptions.Singleline);
            if (!regex.IsMatch(script))
            {
                throw new InvalidOperationException($"Could not find CREATE TABLE for {table} in the generated schema script.");
            }

            script = regex.Replace(script, "$1 WITHOUT ROWID;", 1);
        }

        return script;
    }

    /// <summary>Runs <c>PRAGMA quick_check</c> or <c>integrity_check</c>. Any exception while reading counts as corruption.</summary>
    public (bool Ok, string Detail) CheckIntegrity(bool quick)
    {
        if (IsMemory || !File.Exists(Path!))
        {
            return (true, "");
        }

        try
        {
            var cs = new SqliteConnectionStringBuilder { DataSource = Path, Mode = SqliteOpenMode.ReadWrite, Pooling = false, Cache = SqliteCacheMode.Private }.ToString();
            using var connection = new SqliteConnection(cs);
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = quick ? "PRAGMA quick_check" : "PRAGMA integrity_check";
            var problems = new List<string>();
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    string line = reader.GetString(0);
                    if (!string.Equals(line, "ok", StringComparison.OrdinalIgnoreCase))
                    {
                        problems.Add(line);
                        if (problems.Count >= 5)
                        {
                            break;
                        }
                    }
                }
            }

            return problems.Count == 0 ? (true, "") : (false, string.Join("; ", problems));
        }
        catch (SqliteException ex)
        {
            return (false, ex.Message);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            return (false, ex.Message);
        }
    }

    /// <summary>
    /// Moves the database and its <c>-wal</c>/<c>-shm</c> files into <paramref name="quarantineDirectory"/>. Nothing is deleted.
    /// </summary>
    public string Quarantine(string quarantineDirectory)
    {
        ClearPool();
        Directory.CreateDirectory(quarantineDirectory);
        foreach (string suffix in new[] { "", "-wal", "-shm", "-journal" })
        {
            string source = Path + suffix;
            if (File.Exists(source))
            {
                File.Move(source, System.IO.Path.Combine(quarantineDirectory, FileName + suffix));
            }
        }

        return quarantineDirectory;
    }

    /// <summary>Size in bytes of the -wal file (0 when absent).</summary>
    public long WalSize()
    {
        if (IsMemory)
        {
            return 0;
        }

        var info = new FileInfo(Path + "-wal");
        return info.Exists ? info.Length : 0;
    }

    internal static void Execute(SqliteConnection connection, string sql)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    internal static object? Scalar(SqliteConnection connection, string sql)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = sql;
        return cmd.ExecuteScalar();
    }

    /// <summary>EF entity table names of a context that carry the WITHOUT ROWID annotation.</summary>
    internal static IReadOnlyCollection<string> WithoutRowIdTablesOf(DbContext context) =>
        context.Model.GetEntityTypes()
            .Where(e => e.FindAnnotation(Model.StorageModel.WithoutRowIdAnnotation) is not null)
            .Select(e => e.GetTableName()!)
            .ToList();
}
