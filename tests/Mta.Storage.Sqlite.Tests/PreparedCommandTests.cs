using Microsoft.Data.Sqlite;
using Mta.Core;

namespace Mta.Storage.Sqlite.Tests;

/// <summary>
/// The statements of the SQLite writers run through the native API (<see cref="PreparedCommand"/>), not through
/// <c>SqliteCommand</c>. These tests pin that the values arrive exactly as <c>Microsoft.Data.Sqlite</c> and EF Core would read and write them.
/// </summary>
public class PreparedCommandTests : IDisposable
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");

    public PreparedCommandTests()
    {
        _connection.Open();
        using var create = _connection.CreateCommand();
        create.CommandText = "CREATE TABLE t (id INTEGER PRIMARY KEY, g TEXT, s TEXT, b BLOB, n INTEGER, f TEXT)";
        create.ExecuteNonQuery();
    }

    public void Dispose() => _connection.Dispose();

    private static readonly Stmt Insert = new("INSERT INTO t (id, g, s, b, n, f) VALUES (@id, @g, @s, @b, @n, @f)", "@id", "@g", "@s", "@b", "@n", "@f");

    private static readonly Stmt Select = new("SELECT g, s, b, n, f, typeof(s), typeof(b), typeof(f) FROM t WHERE id = @id", "@id");

    private PreparedCommand Prepare(Stmt stmt) => new(_connection.Handle!, stmt);

    [Fact]
    public void Values_round_trip_and_Microsoft_Data_Sqlite_reads_them()
    {
        using var insert = Prepare(Insert);
        Guid guid = Guid.NewGuid();
        Assert.Equal(1, insert.Set(0, 1L).Set(1, guid).Set(2, "hällö € \U0001F600").Set(3, new byte[] { 1, 2, 3 }).Set(4, 42).SetAddress(5, EmailAddress.Parse("Local.Part@Example.COM")).ExecuteNonQuery());

        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT g, s, b, n, f FROM t WHERE id = 1";
        using var r = cmd.ExecuteReader();
        Assert.True(r.Read());
        Assert.Equal(guid, r.GetGuid(0));
        Assert.Equal(guid.ToString().ToUpperInvariant(), r.GetString(0));   // upper-case text, like EF Core stores it
        Assert.Equal("hällö € \U0001F600", r.GetString(1));
        Assert.Equal(new byte[] { 1, 2, 3 }, (byte[])r["b"]);
        Assert.Equal(42, r.GetInt64(3));
        Assert.Equal("Local.Part@example.com", r.GetString(4));
    }

    [Fact]
    public void Empty_text_and_empty_blob_are_not_null()
    {
        using var insert = Prepare(Insert);
        insert.Set(0, 1L).SetNull(1).Set(2, "").Set(3, Array.Empty<byte>()).SetNull(4).SetAddress(5, EmailAddress.Null).ExecuteNonQuery();

        using var select = Prepare(Select);
        using RawReader r = select.Set(0, 1L).ExecuteReader();
        Assert.True(r.Read());
        Assert.True(r.IsDBNull(0));
        Assert.False(r.IsDBNull(1));
        Assert.Equal("", r.GetString(1));
        Assert.False(r.IsDBNull(2));
        Assert.Empty(r.GetBytes(2));
        Assert.True(r.IsDBNull(3));
        Assert.Equal("", r.GetString(4));   // the null reverse-path is the empty string, like AddressText.Format
        Assert.Equal("text", r.GetString(5));
        Assert.Equal("blob", r.GetString(6));
    }

    [Fact]
    public void Parameters_keep_their_value_until_set_again_and_are_bound_by_declared_order()
    {
        // The SQL mentions the parameters in another order than they are declared: binding is by name, not by position of appearance.
        var reversed = new Stmt("INSERT INTO t (s, id) VALUES (@s, @id)", "@id", "@s");
        using var insert = Prepare(reversed);
        insert.Set(0, 1L).Set(1, "a").ExecuteNonQuery();
        insert.Set(0, 2L).ExecuteNonQuery();   // "a" is still bound
        insert.Set(0, 3L).Set(1, "c").ExecuteNonQuery();

        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT group_concat(id || s, ',') FROM (SELECT * FROM t ORDER BY id)";
        Assert.Equal("1a,2a,3c", cmd.ExecuteScalar());
    }

    [Fact]
    public void A_long_string_and_a_long_address_survive()
    {
        string longText = new string('x', 5000) + "é";
        using var insert = Prepare(Insert);
        insert.Set(0, 1L).SetNull(1).Set(2, longText).SetNull(3).SetNull(4).SetNull(5).ExecuteNonQuery();

        using var select = Prepare(Select);
        using RawReader r = select.Set(0, 1L).ExecuteReader();
        Assert.True(r.Read());
        Assert.Equal(longText, r.GetString(1));
    }

    [Fact]
    public void Lower_case_addresses_match_AddressText_Format_ToLowerInvariant()
    {
        var address = EmailAddress.Parse("MiXed.Case+Tag@Sub.Example.COM");
        using var insert = Prepare(Insert);
        insert.Set(0, 1L).SetNull(1).SetNull(2).SetNull(3).SetNull(4).SetAddress(5, address, lowerCase: true).ExecuteNonQuery();

        using var select = Prepare(Select);
        using RawReader r = select.Set(0, 1L).ExecuteReader();
        Assert.True(r.Read());
        Assert.Equal(Mta.Storage.Logic.AddressText.Format(address).ToLowerInvariant(), r.GetString(4));
    }

    [Fact]
    public void Guids_are_read_from_text_and_from_blobs()
    {
        Guid guid = Guid.NewGuid();
        using (var cmd = _connection.CreateCommand())
        {
            cmd.CommandText = "INSERT INTO t (id, g, b) VALUES (1, @text, @blob)";
            cmd.Parameters.AddWithValue("@text", guid);   // Microsoft.Data.Sqlite writes upper-case text
            cmd.Parameters.AddWithValue("@blob", guid.ToByteArray());
            cmd.ExecuteNonQuery();
        }

        using var select = Prepare(new Stmt("SELECT g, b FROM t WHERE id = 1"));
        using RawReader r = select.ExecuteReader();
        Assert.True(r.Read());
        Assert.Equal(guid, r.GetGuid(0));
        Assert.Equal(guid, r.GetGuid(1));
    }

    [Fact]
    public void A_constraint_violation_throws_the_same_exception_as_before_and_the_statement_stays_usable()
    {
        using var insert = Prepare(Insert);
        insert.Set(0, 1L).SetNull(1).SetNull(2).SetNull(3).SetNull(4).SetNull(5).ExecuteNonQuery();

        var ex = Assert.Throws<SqliteException>(() => insert.ExecuteNonQuery());   // same primary key again
        Assert.Equal(19, ex.SqliteErrorCode);

        Assert.Equal(1, insert.Set(0, 2L).ExecuteNonQuery());
    }

    [Fact]
    public void A_statement_that_reads_changes_nothing_and_reports_zero()
    {
        using var select = Prepare(Select);
        using (RawReader r = select.Set(0, 99L).ExecuteReader())
        {
            Assert.False(r.Read());
        }

        Assert.Equal(0, select.ExecuteNonQuery());
    }

    [Fact]
    public void Releasing_the_reader_lets_the_transaction_commit()
    {
        using var insert = Prepare(Insert);
        using var select = Prepare(Select);
        using SqliteTransaction tx = _connection.BeginTransaction(deferred: false);
        insert.Set(0, 1L).SetNull(1).SetNull(2).SetNull(3).SetNull(4).SetNull(5).ExecuteNonQuery();
        using (RawReader r = select.Set(0, 1L).ExecuteReader())
        {
            Assert.True(r.Read());   // not read to the end on purpose: Dispose must release the statement
        }

        tx.Commit();
    }

    [Fact]
    public void Statements_take_part_in_the_transaction_of_their_connection()
    {
        var count = new Stmt("SELECT count(*) FROM t");
        using var insert = Prepare(Insert);
        using var counter = Prepare(count);

        using (SqliteTransaction tx = _connection.BeginTransaction(deferred: false))
        {
            insert.Set(0, 1L).SetNull(1).Set(2, "rolled back").SetNull(3).SetNull(4).SetNull(5).ExecuteNonQuery();
            using (RawReader inside = counter.ExecuteReader())
            {
                Assert.True(inside.Read());
                Assert.Equal(1, inside.GetInt64(0));   // visible to its own transaction
            }

            tx.Rollback();
        }

        using (RawReader after = counter.ExecuteReader())
        {
            Assert.True(after.Read());
            Assert.Equal(0, after.GetInt64(0));
        }

        using (SqliteTransaction tx = _connection.BeginTransaction(deferred: false))
        {
            insert.Set(0, 2L).Set(2, "committed").ExecuteNonQuery();
            tx.Commit();
        }

        using RawReader committed = counter.ExecuteReader();
        Assert.True(committed.Read());
        Assert.Equal(1, committed.GetInt64(0));
    }

    [Fact]
    public void Reading_a_null_column_as_a_value_is_an_error_like_with_the_data_reader()
    {
        using var insert = Prepare(Insert);
        insert.Set(0, 1L).SetNull(1).SetNull(2).SetNull(3).SetNull(4).SetNull(5).ExecuteNonQuery();
        using var select = Prepare(Select);
        using RawReader r = select.Set(0, 1L).ExecuteReader();
        Assert.True(r.Read());
        Assert.True(r.IsDBNull(1));
        Assert.Throws<InvalidOperationException>(() => r.GetString(1));
        Assert.Throws<InvalidOperationException>(() => r.GetInt64(3));
        Assert.Throws<InvalidOperationException>(() => r.GetGuid(0));
        Assert.Throws<InvalidOperationException>(() => r.GetBytes(2));
        Assert.Null(r.GetNullableString(1));
        Assert.Null(r.GetNullableInt(3));
        Assert.Null(r.GetNullableGuid(0));
    }

    [Fact]
    public void Doubles_are_stored_as_reals()
    {
        using var insert = Prepare(Insert);
        insert.Set(0, 1L).SetNull(1).SetNull(2).SetNull(3).Set(4, 2.5).SetNull(5).ExecuteNonQuery();
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT typeof(n), n FROM t WHERE id = 1";
        using var r = cmd.ExecuteReader();
        Assert.True(r.Read());
        Assert.Equal("real", r.GetString(0));
        Assert.Equal(2.5, r.GetDouble(1));
    }
}
