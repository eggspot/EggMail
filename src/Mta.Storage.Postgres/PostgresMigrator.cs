using System.Reflection;
using System.Text;
using Npgsql;

namespace Mta.Storage.Postgres;

/// <summary>Advisory lock keys. One number space per database; the prefix spells "EGML" so they are recognisable in <c>pg_locks</c>.</summary>
internal static class AdvisoryLocks
{
    private const long Prefix = 0x4547_4D4C_0000_0000L;

    /// <summary>Serializes schema migration across replicas.</summary>
    public const long Migrate = Prefix + 1;

    /// <summary>Serializes creation of day partitions.</summary>
    public const long PartitionDdl = Prefix + 2;

    /// <summary>Serializes configuration writes (makes lease acquisition read-modify-write atomic across replicas).</summary>
    public const long ConfigWrite = Prefix + 3;

    /// <summary>Maintenance jobs, one key per job name; <c>pg_try_advisory_xact_lock</c> so only one replica runs a job at a time.</summary>
    public static long Job(string name)
    {
        // FNV-1a over the name: stable across processes and versions (string.GetHashCode is randomized).
        ulong h = 14695981039346656037UL;
        foreach (char c in name)
        {
            h = (h ^ c) * 1099511628211UL;
        }

        return Prefix + 0x1000 + (long)(h & 0xFFFF_FFFFUL);
    }
}

/// <summary>
/// The schema migrator (design §4.3): hand-written, versioned, idempotent SQL run as the schema <b>owner</b> role. The same
/// text is what <see cref="GenerateScript"/> returns for locked-down setups where the application never gets the owner
/// credentials (<c>Mail__Database__Migrate=Never</c>, then <c>mta migrate-db</c> or <c>psql -f</c>).
/// <para>A script is one <c>DO</c> block, hence one transaction: it takes <c>pg_advisory_xact_lock</c> first (concurrent
/// replicas queue up and then find the version recorded), creates <c>eggmail_schema_version</c>, applies every version not yet
/// recorded and finally grants the runtime role its table privileges.</para>
/// </summary>
public static class PostgresMigrator
{
    /// <summary>The schema version this build expects (the highest embedded <c>V###__*.sql</c>).</summary>
    public static int CurrentVersion => Steps.Value[^1].Version;

    private static readonly Lazy<(int Version, string Description, string Sql)[]> Steps = new(LoadSteps);

    /// <summary>
    /// The idempotent migration script. <paramref name="runtimeRole"/> (when not null) gets <c>SELECT/INSERT/UPDATE/DELETE</c> on
    /// all tables and <c>USAGE</c> on sequences, plus default privileges for objects the owner creates later (partitions).
    /// </summary>
    public static string GenerateScript(string? runtimeRole = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("-- EggMail schema migration. Idempotent: safe to run repeatedly and from several nodes at once.");
        sb.AppendLine("-- Run as the schema owner role.");
        sb.AppendLine("DO $eggmail_migrate$");
        sb.AppendLine("BEGIN");
        sb.Append("  PERFORM pg_advisory_xact_lock(").Append(AdvisoryLocks.Migrate).AppendLine(");");
        sb.AppendLine("  CREATE TABLE IF NOT EXISTS eggmail_schema_version (version integer PRIMARY KEY, description text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());");
        foreach (var step in Steps.Value)
        {
            sb.Append("  IF NOT EXISTS (SELECT 1 FROM eggmail_schema_version WHERE version = ").Append(step.Version).AppendLine(") THEN");
            sb.AppendLine(step.Sql);
            sb.Append("    INSERT INTO eggmail_schema_version (version, description) VALUES (").Append(step.Version).Append(", '").Append(step.Description.Replace("'", "''", StringComparison.Ordinal)).AppendLine("');");
            sb.AppendLine("  END IF;");
        }

        if (!string.IsNullOrWhiteSpace(runtimeRole))
        {
            string role = QuoteIdentifier(runtimeRole);
            string roleInFormat = role.Replace("%", "%%", StringComparison.Ordinal); // the name is embedded in a format() template below
            sb.AppendLine($"  GRANT USAGE ON SCHEMA public TO {role};");
            sb.AppendLine($"  GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role};");
            sb.AppendLine($"  GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO {role};");
            sb.AppendLine($"  EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {roleInFormat}', current_user);");
            sb.AppendLine($"  EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {roleInFormat}', current_user);");
        }

        sb.AppendLine("END");
        sb.AppendLine("$eggmail_migrate$;");
        return sb.ToString();
    }

    /// <summary>Applies the migrations with the given (owner) connection string. Idempotent; concurrent callers are serialized by an advisory lock.</summary>
    public static async Task MigrateAsync(string ownerConnectionString, string? runtimeRole, CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(ownerConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = new NpgsqlCommand(GenerateScript(runtimeRole), connection) { CommandTimeout = 300 };
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The version recorded in the database, or 0 when the schema was never migrated.</summary>
    public static async Task<int> GetDatabaseVersionAsync(NpgsqlDataSource dataSource, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var exists = new NpgsqlCommand("SELECT to_regclass('public.eggmail_schema_version') IS NOT NULL", connection);
        if (!(bool)(await exists.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false))!)
        {
            return 0;
        }

        await using var cmd = new NpgsqlCommand("SELECT COALESCE(MAX(version), 0) FROM eggmail_schema_version", connection);
        return Convert.ToInt32(await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture);
    }

    internal static string QuoteIdentifier(string name) => "\"" + name.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";

    private static (int Version, string Description, string Sql)[] LoadSteps()
    {
        Assembly asm = typeof(PostgresMigrator).Assembly;
        var steps = new List<(int, string, string)>();
        foreach (string resource in asm.GetManifestResourceNames().Where(n => n.EndsWith(".sql", StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            string file = resource[(resource.LastIndexOf(".Schema.", StringComparison.Ordinal) + ".Schema.".Length)..];
            // V001__initial.sql
            int sep = file.IndexOf("__", StringComparison.Ordinal);
            int version = int.Parse(file.AsSpan(1, sep - 1), System.Globalization.CultureInfo.InvariantCulture);
            string description = file[(sep + 2)..^".sql".Length].Replace('_', ' ');
            using var reader = new StreamReader(asm.GetManifestResourceStream(resource)!, Encoding.UTF8);
            string sql = reader.ReadToEnd();
            if (sql.Contains("$eggmail_migrate$", StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"{file} must not contain the script's dollar-quote tag.");
            }

            steps.Add((version, description, sql));
        }

        return [.. steps.OrderBy(s => s.Item1)];
    }
}
