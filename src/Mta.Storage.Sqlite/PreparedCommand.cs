using System.Buffers;
using System.Text;
using Microsoft.Data.Sqlite;
using Mta.Core;
using Mta.Storage.Logic;
using SQLitePCL;

namespace Mta.Storage.Sqlite;

/// <summary>
/// A statement prepared once on the writer's connection and executed through the native SQLite API directly. Compared with
/// <see cref="SqliteCommand"/> this avoids, per execution, the statement enumerators, the parameter binder objects, the data reader and the
/// boxing of every value (about 1.5 KB and several microseconds per statement), and it never compiles the SQL again.
/// <para>
/// Same contract as before: parameters keep their value until they are set again (so a loop may set only the columns that change), values
/// are bound by the declared order of <see cref="Stmt.Parameters"/>, and Guids are stored as upper-case text like the rest of the schema
/// (<c>Microsoft.Data.Sqlite</c> and EF Core read them back). Not thread-safe: one writer thread owns the connection and every command on it.
/// </para>
/// </summary>
internal sealed class PreparedCommand : IDisposable
{
    private const int StackTextBytes = 256;

    private readonly sqlite3 _db;
    private readonly sqlite3_stmt _stmt;
    private readonly int[] _slots;
    private readonly RawReader _reader;
    private bool _active;

    public PreparedCommand(sqlite3 db, Stmt statement)
    {
        _db = db;
        int rc = raw.sqlite3_prepare_v2(db, statement.Sql, out _stmt);
        if (rc != raw.SQLITE_OK)
        {
            SqliteException.ThrowExceptionForRC(rc, db);
        }

        _slots = new int[statement.Parameters.Length];
        for (int i = 0; i < _slots.Length; i++)
        {
            int slot = raw.sqlite3_bind_parameter_index(_stmt, statement.Parameters[i]);
            if (slot == 0)
            {
                raw.sqlite3_finalize(_stmt);
                throw new InvalidOperationException($"The statement has no parameter {statement.Parameters[i]}: {statement.Sql}");
            }

            _slots[i] = slot;
        }

        _reader = new RawReader(this);
    }

    internal sqlite3_stmt Handle => _stmt;

    internal sqlite3 Database => _db;

    public PreparedCommand SetNull(int index)
    {
        Check(raw.sqlite3_bind_null(_stmt, _slots[index]));
        return this;
    }

    public PreparedCommand Set(int index, long value)
    {
        Check(raw.sqlite3_bind_int64(_stmt, _slots[index], value));
        return this;
    }

    public PreparedCommand Set(int index, int value) => Set(index, (long)value);

    public PreparedCommand Set(int index, bool value) => Set(index, value ? 1L : 0L);

    public PreparedCommand Set(int index, long? value) => value is { } v ? Set(index, v) : SetNull(index);

    public PreparedCommand Set(int index, Guid value)
    {
        Span<byte> text = stackalloc byte[36];
        value.TryFormat(text, out _, "D");
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] is >= (byte)'a' and <= (byte)'f')
            {
                text[i] -= 32;
            }
        }

        BindText(index, text);
        return this;
    }

    public PreparedCommand Set(int index, Guid? value) => value is { } v ? Set(index, v) : SetNull(index);

    public PreparedCommand Set(int index, string? value)
    {
        if (value is null)
        {
            return SetNull(index);
        }

        if (value.Length <= StackTextBytes / 3)
        {
            Span<byte> buffer = stackalloc byte[StackTextBytes];
            BindText(index, buffer[..Encoding.UTF8.GetBytes(value, buffer)]);
            return this;
        }

        byte[] rented = ArrayPool<byte>.Shared.Rent(Encoding.UTF8.GetMaxByteCount(value.Length));
        try
        {
            BindText(index, rented.AsSpan(0, Encoding.UTF8.GetBytes(value, rented)));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }

        return this;
    }

    /// <summary>
    /// Binds <see cref="AddressText.Format"/> of the address (optionally lower-cased, like <c>Format(a).ToLowerInvariant()</c>) without building the string.
    /// </summary>
    public PreparedCommand SetAddress(int index, in EmailAddress address, bool lowerCase = false)
    {
        if (address.IsNull)
        {
            BindText(index, default);
            return this;
        }

        int length = address.LocalPart.Length + 1 + address.Domain.Length;
        if (length > 512)
        {
            string text = AddressText.Format(address);
            return Set(index, lowerCase ? text.ToLowerInvariant() : text);
        }

        Span<char> chars = stackalloc char[length];
        address.LocalPart.CopyTo(chars);
        chars[address.LocalPart.Length] = '@';
        address.Domain.CopyTo(chars[(address.LocalPart.Length + 1)..]);
        if (lowerCase)
        {
            Span<char> lower = stackalloc char[length];   // the span overload refuses to convert in place
            chars.ToLowerInvariant(lower);
            chars = lower;
        }

        Span<byte> utf8 = stackalloc byte[length * 3];
        BindText(index, utf8[..Encoding.UTF8.GetBytes(chars, utf8)]);
        return this;
    }

    /// <summary>Binds text that is already UTF-8 (an empty span is the empty string).</summary>
    public PreparedCommand SetUtf8Text(int index, ReadOnlySpan<byte> utf8)
    {
        BindText(index, utf8);
        return this;
    }

    public PreparedCommand Set(int index, byte[]? value) => value is null ? SetNull(index) : SetBlob(index, value);

    public PreparedCommand SetBlob(int index, ReadOnlySpan<byte> value)
    {
        // An empty span has a null pointer, which SQLite would store as NULL: bind a zero-length blob explicitly.
        Check(value.IsEmpty ? raw.sqlite3_bind_zeroblob(_stmt, _slots[index], 0) : raw.sqlite3_bind_blob(_stmt, _slots[index], value));
        return this;
    }

    public PreparedCommand Set(int index, double value)
    {
        Check(raw.sqlite3_bind_double(_stmt, _slots[index], value));
        return this;
    }

    // There is deliberately no overload for object: a value of a type that is not listed here (DateTimeOffset, decimal, ...) is a compile
    // error at the call site, because Microsoft.Data.Sqlite stores each of those in a specific way and a silent guess would write
    // data the readers do not expect. Convert to one of the types above first (the schema stores instants as Unix milliseconds).

    /// <summary>Runs the statement to completion and returns the number of rows changed (0 for a statement that reads).</summary>
    public int ExecuteNonQuery()
    {
        try
        {
            int rc = raw.sqlite3_step(_stmt);
            while (rc == raw.SQLITE_ROW)
            {
                rc = raw.sqlite3_step(_stmt);
            }

            if (rc != raw.SQLITE_DONE)
            {
                SqliteException.ThrowExceptionForRC(rc, _db);
            }

            return raw.sqlite3_stmt_readonly(_stmt) != 0 ? 0 : raw.sqlite3_changes(_db);
        }
        finally
        {
            raw.sqlite3_reset(_stmt);
        }
    }

    /// <summary>Starts the statement; read the rows with <see cref="RawReader.Read"/> and dispose the reader to release the statement.</summary>
    public RawReader ExecuteReader()
    {
        if (_active)
        {
            throw new InvalidOperationException("The statement is already executing.");
        }

        _active = true;
        _reader.Begin();
        return _reader;
    }

    internal void EndRead()
    {
        raw.sqlite3_reset(_stmt);
        _active = false;
    }

    private void BindText(int index, ReadOnlySpan<byte> utf8)
    {
        // Same null-pointer pitfall as for blobs: the empty string must stay an empty string.
        Check(utf8.IsEmpty ? raw.sqlite3_bind_text(_stmt, _slots[index], string.Empty) : raw.sqlite3_bind_text(_stmt, _slots[index], utf8));
    }

    private void Check(int rc)
    {
        if (rc != raw.SQLITE_OK)
        {
            SqliteException.ThrowExceptionForRC(rc, _db);
        }
    }

    public void Dispose() => raw.sqlite3_finalize(_stmt);
}

/// <summary>
/// The rows of a started <see cref="PreparedCommand"/> (one reusable instance per command). Disposing releases the statement; read
/// all rows of a statement that changes data (<c>UPDATE ... RETURNING</c>) before disposing, as with a data reader.
/// </summary>
internal sealed class RawReader : IDisposable
{
    private readonly PreparedCommand _command;
    private bool _done;

    internal RawReader(PreparedCommand command) => _command = command;

    internal void Begin() => _done = false;

    public bool Read()
    {
        if (_done)
        {
            return false;
        }

        int rc = raw.sqlite3_step(_command.Handle);
        if (rc == raw.SQLITE_ROW)
        {
            return true;
        }

        _done = true;
        if (rc != raw.SQLITE_DONE)
        {
            _command.EndRead();
            SqliteException.ThrowExceptionForRC(rc, _command.Database);
        }

        return false;
    }

    public bool IsDBNull(int ordinal) => raw.sqlite3_column_type(_command.Handle, ordinal) == raw.SQLITE_NULL;

    // Reading a NULL column as a value is an error, as it is with SqliteDataReader (check IsDBNull, or use the Get...Nullable methods).

    public long GetInt64(int ordinal) => raw.sqlite3_column_int64(_command.Handle, NotNull(ordinal));

    public int GetInt32(int ordinal) => (int)raw.sqlite3_column_int64(_command.Handle, NotNull(ordinal));

    public bool GetFlag(int ordinal) => raw.sqlite3_column_int64(_command.Handle, NotNull(ordinal)) != 0;

    public string GetString(int ordinal) => raw.sqlite3_column_text(_command.Handle, NotNull(ordinal)).utf8_to_string();

    private int NotNull(int ordinal) =>
        raw.sqlite3_column_type(_command.Handle, ordinal) == raw.SQLITE_NULL
            ? throw new InvalidOperationException($"Column {ordinal} is NULL.")
            : ordinal;

    public string? GetNullableString(int ordinal) => IsDBNull(ordinal) ? null : GetString(ordinal);

    /// <summary>
    /// <see cref="GetString"/> for a column that repeats from row to row (the sender, the domains of a batch): when the text equals <paramref name="previous"/> that
    /// string is returned and nothing is allocated; otherwise the new string is made and remembered in <paramref name="previous"/>.
    /// </summary>
    public string GetStringReusing(int ordinal, ref string? previous)
    {
        if (previous is { } last && last.Length <= 256)
        {
            ReadOnlySpan<byte> utf8 = raw.sqlite3_column_blob(_command.Handle, NotNull(ordinal));
            Span<char> chars = stackalloc char[256];
            if (System.Text.Unicode.Utf8.ToUtf16(utf8, chars, out _, out int written, replaceInvalidSequences: true) == System.Buffers.OperationStatus.Done
                && chars[..written].SequenceEqual(last))
            {
                return last;
            }
        }

        return previous = GetString(ordinal);
    }

    /// <summary>Like <see cref="GetStringReusing"/> for a column that may be NULL.</summary>
    public string? GetNullableStringReusing(int ordinal, ref string? previous) => IsDBNull(ordinal) ? null : GetStringReusing(ordinal, ref previous);

    public int? GetNullableInt(int ordinal) => IsDBNull(ordinal) ? null : GetInt32(ordinal);

    public DateTimeOffset GetInstant(int ordinal) => StorageTime.FromUnixMs(GetInt64(ordinal));

    public DateTimeOffset? GetNullableInstant(int ordinal) => IsDBNull(ordinal) ? null : GetInstant(ordinal);

    public byte[] GetBytes(int ordinal) => raw.sqlite3_column_blob(_command.Handle, NotNull(ordinal)).ToArray();

    public Guid GetGuid(int ordinal)
    {
        sqlite3_stmt stmt = _command.Handle;
        NotNull(ordinal);
        if (raw.sqlite3_column_type(stmt, ordinal) == raw.SQLITE_BLOB)
        {
            return new Guid(raw.sqlite3_column_blob(stmt, ordinal));
        }

        ReadOnlySpan<byte> text = raw.sqlite3_column_blob(stmt, ordinal);   // the UTF-8 bytes of a TEXT value
        return System.Buffers.Text.Utf8Parser.TryParse(text, out Guid guid, out int consumed, 'D') && consumed == text.Length
            ? guid
            : Guid.Parse(GetString(ordinal));
    }

    public Guid? GetNullableGuid(int ordinal) => IsDBNull(ordinal) ? null : GetGuid(ordinal);

    public void Dispose() => _command.EndRead();
}
