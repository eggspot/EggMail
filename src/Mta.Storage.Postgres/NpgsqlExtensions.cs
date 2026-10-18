using System.Net.Sockets;
using Mta.Storage.Logic;
using Npgsql;
using NpgsqlTypes;

namespace Mta.Storage.Postgres;

/// <summary>Classification of PostgreSQL errors: what means "database unreachable" and what means a constraint.</summary>
internal static class PostgresErrors
{
    public const string UniqueViolation = "23505";
    public const string CheckViolation = "23514";
    public const string InsufficientPrivilege = "42501";
    public const string DeadlockDetected = "40P01";
    public const string SerializationFailure = "40001";

    /// <summary>
    /// True when the failure means the server cannot be reached or refuses work right now (down, restarting, shutting down,
    /// out of connections, network or pool timeout). These become <see cref="StorageUnavailableException"/> so the SMTP layer
    /// can answer 451; everything else (constraints, bugs, bad SQL) keeps its own type.
    /// </summary>
    public static bool IsUnavailable(Exception exception)
    {
        for (Exception? e = exception; e is not null; e = e.InnerException)
        {
            switch (e)
            {
                case PostgresException pg:
                    return pg.SqlState is { } state
                        && (state.StartsWith("08", StringComparison.Ordinal)
                            || state is "25006" or "53300" or "53400" or "57P01" or "57P02" or "57P03" or "58000" or "58030");
                case SocketException:
                case IOException:
                case TimeoutException:
                    return true;
                case NpgsqlException n when n.IsTransient:
                    return true;
            }
        }

        return false;
    }

    /// <summary>The server has no room to write (SQLSTATE 53100, disk full): the receive path answers <c>452 4.3.1</c>, like a full SQLite disk.</summary>
    public static bool IsDiskFull(Exception exception)
    {
        for (Exception? e = exception; e is not null; e = e.InnerException)
        {
            if (e is PostgresException { SqlState: "53100" })
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>A failure that will probably not repeat: a serialization failure, a deadlock or a statement timeout. The caller retries later (<c>451</c>).</summary>
    public static bool IsRetryable(Exception exception)
    {
        // A statement the caller cancelled is reported by the server as 57014 too, but it surfaces as an OperationCanceledException: that is the caller's decision and stays one.
        for (Exception? e = exception; e is not null; e = e.InnerException)
        {
            if (e is OperationCanceledException)
            {
                return false;
            }
        }

        for (Exception? e = exception; e is not null; e = e.InnerException)
        {
            if (e is PostgresException { SqlState: SerializationFailure or DeadlockDetected or "57014" })
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>A constraint violation (SQLSTATE class 23: unique, foreign key, check, not null).</summary>
    public static bool IsConstraint(Exception exception)
    {
        for (Exception? e = exception; e is not null; e = e.InnerException)
        {
            if (e is PostgresException { SqlState: { } state })
            {
                return state.StartsWith("23", StringComparison.Ordinal);
            }
        }

        return false;
    }

    /// <summary>
    /// True when the server stopped a statement because it ran past <c>statement_timeout</c> (SQLSTATE 57014, as on the read-only role). A statement the <i>caller</i> cancelled
    /// (a cancelled token, a closed request) is also reported by the server as 57014 but surfaces as an <see cref="OperationCanceledException"/>: that is the caller's decision
    /// and stays one, it is neither a timeout nor an outage.
    /// </summary>
    public static bool IsStatementTimeout(Exception exception, CancellationToken cancellationToken = default)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return false;
        }

        for (Exception? e = exception; e is not null; e = e.InnerException)
        {
            if (e is OperationCanceledException)
            {
                return false;
            }
        }

        for (Exception? e = exception; e is not null; e = e.InnerException)
        {
            if (e is PostgresException { SqlState: "57014" })
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>True when the failure shows that established connections broke (not a mere timeout).</summary>
    public static bool IsBrokenConnection(Exception exception)
    {
        for (Exception? e = exception; e is not null; e = e.InnerException)
        {
            if (e is SocketException or IOException or PostgresException)
            {
                return true;
            }
        }

        return false;
    }

    public static StorageUnavailableException Unavailable(Exception inner) =>
        new("PostgreSQL is unavailable: " + Describe(inner), inner);

    /// <summary>Converts an exception to <see cref="StorageUnavailableException"/> when it is an availability failure; null otherwise.</summary>
    public static Exception? Translate(Exception exception) => exception is StorageUnavailableException || !IsUnavailable(exception) ? null : Unavailable(exception);

    public static bool IsSqlState(Exception exception, string sqlState) => exception is PostgresException pg && pg.SqlState == sqlState;

    private static string Describe(Exception ex)
    {
        Exception e = ex;
        while (e.InnerException is not null && e is not PostgresException)
        {
            e = e.InnerException;
        }

        return e.Message;
    }
}

/// <summary>Typed parameter helpers. Parameters are positional (<c>$1</c>…), so statements never go through name parsing.</summary>
internal static class NpgsqlParameterExtensions
{
    public static NpgsqlParameterCollection Uuid(this NpgsqlParameterCollection p, Guid value) =>
        Add(p, NpgsqlDbType.Uuid, value);

    public static NpgsqlParameterCollection Uuid(this NpgsqlParameterCollection p, Guid? value) =>
        Add(p, NpgsqlDbType.Uuid, value is { } v ? v : DBNull.Value);

    // PostgreSQL text cannot hold NUL, and UTF-8 cannot encode an unpaired surrogate: text from a client or a remote server is written with U+FFFD in their place
    // (StorageText), so a hostile character is never an exception in the middle of recording a delivery result.
    public static NpgsqlParameterCollection Text(this NpgsqlParameterCollection p, string? value) =>
        Add(p, NpgsqlDbType.Text, (object?)StorageText.Clean(value) ?? DBNull.Value);

    /// <summary>Text for a WHERE clause: exactly as given (never cleaned, so it cannot come to equal stored text it differs from; callers refuse unstorable filters first).</summary>
    public static NpgsqlParameterCollection TextExact(this NpgsqlParameterCollection p, string? value) =>
        Add(p, NpgsqlDbType.Text, (object?)value ?? DBNull.Value);

    public static NpgsqlParameterCollection Int(this NpgsqlParameterCollection p, int value) =>
        Add(p, NpgsqlDbType.Integer, value);

    public static NpgsqlParameterCollection Int(this NpgsqlParameterCollection p, int? value) =>
        Add(p, NpgsqlDbType.Integer, value is { } v ? v : DBNull.Value);

    public static NpgsqlParameterCollection Small(this NpgsqlParameterCollection p, int value) =>
        Add(p, NpgsqlDbType.Smallint, (short)value);

    public static NpgsqlParameterCollection Long(this NpgsqlParameterCollection p, long value) =>
        Add(p, NpgsqlDbType.Bigint, value);

    public static NpgsqlParameterCollection Bool(this NpgsqlParameterCollection p, bool value) =>
        Add(p, NpgsqlDbType.Boolean, value);

    /// <summary>A UTC instant at millisecond precision (Npgsql refuses a non-zero offset).</summary>
    public static NpgsqlParameterCollection Time(this NpgsqlParameterCollection p, DateTimeOffset value) =>
        Add(p, NpgsqlDbType.TimestampTz, StorageTime.Normalize(value));

    public static NpgsqlParameterCollection Time(this NpgsqlParameterCollection p, DateTimeOffset? value) =>
        Add(p, NpgsqlDbType.TimestampTz, value is { } v ? StorageTime.Normalize(v) : DBNull.Value);

    public static NpgsqlParameterCollection Bytes(this NpgsqlParameterCollection p, ReadOnlyMemory<byte> value) =>
        Add(p, NpgsqlDbType.Bytea, value);

    public static NpgsqlParameterCollection Bytes(this NpgsqlParameterCollection p, byte[] value) =>
        Add(p, NpgsqlDbType.Bytea, value);

    public static NpgsqlParameterCollection UuidArray(this NpgsqlParameterCollection p, Guid[] value) =>
        Add(p, NpgsqlDbType.Array | NpgsqlDbType.Uuid, value);

    public static NpgsqlParameterCollection TextArray(this NpgsqlParameterCollection p, string?[] value) =>
        Add(p, NpgsqlDbType.Array | NpgsqlDbType.Text, CleanedIfNeeded(value));

    /// <summary>The same array when every element can be stored (the usual case allocates nothing), otherwise a copy with the elements cleaned.</summary>
    internal static string?[] CleanedIfNeeded(string?[] values)
    {
        foreach (string? v in values)
        {
            if (!StorageText.IsStorable(v))
            {
                return values.Select(StorageText.Clean).ToArray();
            }
        }

        return values;
    }

    public static NpgsqlParameterCollection IntArray(this NpgsqlParameterCollection p, int[] value) =>
        Add(p, NpgsqlDbType.Array | NpgsqlDbType.Integer, value);

    public static NpgsqlParameterCollection LongArray(this NpgsqlParameterCollection p, long[] value) =>
        Add(p, NpgsqlDbType.Array | NpgsqlDbType.Bigint, value);

    public static NpgsqlParameterCollection TimeArray(this NpgsqlParameterCollection p, DateTimeOffset[] value) =>
        Add(p, NpgsqlDbType.Array | NpgsqlDbType.TimestampTz, value.Select(v => StorageTime.Normalize(v).UtcDateTime).ToArray());

    private static NpgsqlParameterCollection Add(NpgsqlParameterCollection p, NpgsqlDbType type, object value)
    {
        p.Add(new NpgsqlParameter { NpgsqlDbType = type, Value = value });
        return p;
    }
}

internal static class NpgsqlReaderExtensions
{
    public static DateTimeOffset GetInstant(this NpgsqlDataReader r, int ordinal) => StorageTime.Normalize(r.GetFieldValue<DateTimeOffset>(ordinal));

    public static DateTimeOffset? GetNullableInstant(this NpgsqlDataReader r, int ordinal) => r.IsDBNull(ordinal) ? null : r.GetInstant(ordinal);

    public static string? GetNullableString(this NpgsqlDataReader r, int ordinal) => r.IsDBNull(ordinal) ? null : r.GetString(ordinal);

    public static int? GetNullableInt(this NpgsqlDataReader r, int ordinal) => r.IsDBNull(ordinal) ? null : r.GetInt32(ordinal);

    public static Guid? GetNullableGuid(this NpgsqlDataReader r, int ordinal) => r.IsDBNull(ordinal) ? null : r.GetGuid(ordinal);
}
