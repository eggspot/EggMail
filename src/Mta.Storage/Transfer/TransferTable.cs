using System.Globalization;
using System.Linq.Expressions;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Microsoft.EntityFrameworkCore;

namespace Mta.Storage.Transfer;

/// <summary>The four parts of the storage model (config, stats, queue, history); on SQLite each is its own file.</summary>
public enum TransferPart : byte
{
    Config = 0,
    Stats,
    Queue,
    History,
}

/// <summary>An inclusive range of history day keys (days since 1970-01-01, UTC). Both ends null means every row.</summary>
public readonly record struct TransferRange(int? FromDay, int? ToDay)
{
    public static TransferRange All => default;

    public static TransferRange Day(int day) => new(day, day);
}

/// <summary>A column that holds a secret protected with Data Protection (DKIM keys, webhook secrets, TLS and ACME keys, relay passwords).</summary>
public interface ITransferSecret
{
    string Column { get; }

    /// <summary>The <see cref="Mta.Core.SecretPurposes"/> purpose the value is protected with.</summary>
    string Purpose { get; }

    byte[]? Get(object row);

    void Set(object row, byte[]? value);
}

/// <summary>The large binary value of a row (the raw message of a spool or retained-raw row), carried in a body pack, not in the NDJSON row.</summary>
public interface ITransferBody
{
    string Column { get; }

    byte[] Get(object row);

    void Set(object row, byte[] value);
}

public sealed class TransferSecret<T>(string column, string purpose, Func<T, byte[]?> get, Action<T, byte[]?> set) : ITransferSecret
{
    public string Column { get; } = column;

    public string Purpose { get; } = purpose;

    public byte[]? Get(object row) => get((T)row);

    public void Set(object row, byte[]? value) => set((T)row, value);
}

public sealed class TransferBody<T>(string column, Func<T, byte[]> get, Action<T, byte[]> set) : ITransferBody
{
    public string Column { get; } = column;

    public byte[] Get(object row) => get((T)row);

    public void Set(object row, byte[] value) => set((T)row, value);
}

/// <summary>How a table holds rows back from dispatch: a transfer mark on the source, an activation hold on the target.</summary>
public sealed class TransferHold<T> where T : class
{
    /// <summary>The CLR property name of the hold column.</summary>
    public required string Property { get; init; }

    public required Action<T, Guid?> Set { get; init; }

    public required Func<IQueryable<T>, Guid, CancellationToken, Task<int>> HoldAll { get; init; }

    public required Func<IQueryable<T>, Guid, CancellationToken, Task<int>> Release { get; init; }

    public required Func<IQueryable<T>, Guid, CancellationToken, Task<long>> CountHeld { get; init; }
}

/// <summary>The settings of a <see cref="TransferTable{T}"/>.</summary>
public sealed class TransferTableSpec<T> where T : class
{
    /// <summary>The key order rows are exported in (deterministic, index-backed).</summary>
    public required Func<IQueryable<T>, IOrderedQueryable<T>> Order { get; init; }

    /// <summary>Restricts the table to the rows that move (for example settings without the Data Protection key ring).</summary>
    public Func<IQueryable<T>, IQueryable<T>>? Scope { get; init; }

    /// <summary>The history day key; set for per-day tables.</summary>
    public Expression<Func<T, int>>? Day { get; init; }

    public TransferHold<T>? Hold { get; init; }

    /// <summary>Existing rows with the same key are replaced on import.</summary>
    public bool Upsert { get; init; }

    public IReadOnlyList<ITransferSecret> Secrets { get; init; } = [];

    public ITransferBody? Body { get; init; }

    /// <summary>Applied to every imported row before it is added (for example resetting a sequence number the target assigns).</summary>
    public Action<T>? PrepareImport { get; init; }

    /// <summary>Applied to a copy of every exported row (for example dropping in-flight ACME challenge state).</summary>
    public Action<T>? PrepareExport { get; init; }

    /// <summary>Properties left out of the canonical text (re-assigned sequence numbers).</summary>
    public IReadOnlyList<string> CanonicalExcludes { get; init; } = [];
}

/// <summary>
/// Describes one table of the shared model for the backend switch: where it lives, how its rows are serialized into a bundle
/// and compared, and which of its columns are secrets. The registry is <see cref="TransferTables"/>: adding a table to the
/// bundle means adding one entry there (design §4.6, "adds it to the bundle in one place"). The rows are the provider-neutral
/// EF entities, so every relational provider reads and writes them the same way.
/// </summary>
public abstract class TransferTable
{
    private static readonly Func<object, object> ShallowCopy = (Func<object, object>)Delegate.CreateDelegate(
        typeof(Func<object, object>), null, typeof(object).GetMethod("MemberwiseClone", BindingFlags.Instance | BindingFlags.NonPublic)!);

    /// <summary>The database table name (snake_case), also the file stem in the bundle.</summary>
    public abstract string Name { get; }

    public abstract TransferPart Part { get; }

    public abstract Type EntityType { get; }

    /// <summary>Existing rows with the same key are replaced on import (small tables a fresh target may already hold a row of).</summary>
    public abstract bool Upsert { get; }

    /// <summary>History tables carry a leading <c>day</c> key and are exported and imported day by day.</summary>
    public abstract bool PerDay { get; }

    /// <summary>The table has a column that holds a switch hold (a transfer mark on the source, an activation hold on the target).</summary>
    public abstract bool HasHold { get; }

    public abstract IReadOnlyList<ITransferSecret> Secrets { get; }

    public abstract ITransferBody? Body { get; }

    /// <summary>The bundle directory (<c>config</c>, <c>stats</c>, <c>queue</c> or <c>history</c>).</summary>
    public string Directory => Part.ToString().ToLowerInvariant();

    public override string ToString() => Name;

    /// <summary>Serializes a row the way it is written to a bundle (no body, no hold).</summary>
    public abstract string Serialize(object row);

    public abstract object Deserialize(string json);

    /// <summary>
    /// The canonical text of a row used for the verification checksum: independent of the provider (UTC millisecond
    /// instants), of the secrets' protection (secret columns are left out and compared separately), of re-assigned sequence
    /// numbers and of switch holds. A body contributes its SHA-256.
    /// </summary>
    public abstract string Canonical(object row);

    /// <summary>A shallow copy that may be modified (secret columns and holds are replaced on the copy, never in place).</summary>
    public static object Clone(object row) => ShallowCopy(row);

    /// <summary>Applies the export-time normalization to a copy of a row (for example dropping in-flight ACME challenge state).</summary>
    public abstract void PrepareForExport(object row);

    // ---- EF operations, used by EfStorageTransfer

    public abstract IAsyncEnumerable<object> ReadAsync(DbContext context, TransferRange range, CancellationToken cancellationToken);

    /// <summary>One page of rows in key order, for stores whose reads cannot stream (an in-memory SQLite queue reads on its writer thread).</summary>
    public abstract List<object> ReadPage(DbContext context, TransferRange range, int skip, int take);

    public abstract Task<long> CountAsync(DbContext context, TransferRange range, CancellationToken cancellationToken);

    public abstract Task<bool> AnyAsync(DbContext context, CancellationToken cancellationToken);

    public abstract Task<int> DeleteAllAsync(DbContext context, CancellationToken cancellationToken);

    public abstract Task<IReadOnlyList<int>> DaysAsync(DbContext context, CancellationToken cancellationToken);

    /// <summary>Adds the rows to the context (the caller saves). <paramref name="hold"/> is stored in the hold column of tables that have one.</summary>
    public abstract void AddRows(DbContext context, IReadOnlyList<object> rows, Guid? hold);

    /// <summary>Marks every row without a hold as held by <paramref name="switchId"/>; returns the number of rows marked.</summary>
    public abstract Task<int> HoldAllAsync(DbContext context, Guid switchId, CancellationToken cancellationToken);

    /// <summary>Releases the rows held by <paramref name="switchId"/>; returns the number of rows released.</summary>
    public abstract Task<int> ReleaseAsync(DbContext context, Guid switchId, CancellationToken cancellationToken);

    public abstract Task<long> CountHeldAsync(DbContext context, Guid switchId, CancellationToken cancellationToken);
}

/// <summary>The typed description of a table; see <see cref="TransferTable"/>.</summary>
public sealed class TransferTable<T> : TransferTable where T : class, new()
{
    private readonly TransferTableSpec<T> _spec;
    private readonly JsonSerializerOptions _bundleJson;
    private readonly JsonSerializerOptions _canonicalJson;

    public TransferTable(string name, TransferPart part, TransferTableSpec<T> spec)
    {
        Name = name;
        Part = part;
        _spec = spec;
        var bundleExcludes = new List<string>();
        if (spec.Hold is not null)
        {
            bundleExcludes.Add(spec.Hold.Property);
        }

        if (spec.Body is not null)
        {
            bundleExcludes.Add(spec.Body.Column);
        }

        var canonicalExcludes = new List<string>(bundleExcludes);
        canonicalExcludes.AddRange(spec.Secrets.Select(s => s.Column));
        canonicalExcludes.AddRange(spec.CanonicalExcludes);
        _bundleJson = BuildOptions(bundleExcludes);
        _canonicalJson = BuildOptions(canonicalExcludes);
    }

    public override string Name { get; }

    public override TransferPart Part { get; }

    public override Type EntityType => typeof(T);

    public override bool Upsert => _spec.Upsert;

    public override bool PerDay => _spec.Day is not null;

    public override bool HasHold => _spec.Hold is not null;

    public override IReadOnlyList<ITransferSecret> Secrets => _spec.Secrets;

    public override ITransferBody? Body => _spec.Body;

    private static JsonSerializerOptions BuildOptions(List<string> excludes)
    {
        var names = new HashSet<string>(excludes.Select(JsonNamingPolicy.CamelCase.ConvertName), StringComparer.Ordinal);
        return new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase), new UtcMillisecondConverter() },
            WriteIndented = false,
            TypeInfoResolver = new DefaultJsonTypeInfoResolver
            {
                Modifiers =
                {
                    info =>
                    {
                        if (info.Type != typeof(T))
                        {
                            return;
                        }

                        for (int i = info.Properties.Count - 1; i >= 0; i--)
                        {
                            if (names.Contains(info.Properties[i].Name))
                            {
                                info.Properties.RemoveAt(i);
                            }
                        }
                    },
                },
            },
        };
    }

    public override string Serialize(object row) => JsonSerializer.Serialize((T)row, _bundleJson);

    public override object Deserialize(string json) => JsonSerializer.Deserialize<T>(json, _bundleJson) ?? throw new JsonException($"{Name}: a row is null");

    public override string Canonical(object row)
    {
        string json = JsonSerializer.Serialize((T)row, _canonicalJson);
        if (_spec.Body is { } body)
        {
            json += "|" + Convert.ToHexString(SHA256.HashData(body.Get(row)));
        }

        return json;
    }

    public override void PrepareForExport(object row) => _spec.PrepareExport?.Invoke((T)row);

    private IQueryable<T> Scoped(DbContext context, TransferRange range)
    {
        IQueryable<T> q = context.Set<T>().AsNoTracking();
        if (_spec.Scope is { } scope)
        {
            q = scope(q);
        }

        if (_spec.Day is { } day && (range.FromDay is not null || range.ToDay is not null))
        {
            Expression body = Expression.Constant(true);
            if (range.FromDay is { } from)
            {
                body = Expression.AndAlso(body, Expression.GreaterThanOrEqual(day.Body, Expression.Constant(from)));
            }

            if (range.ToDay is { } to)
            {
                body = Expression.AndAlso(body, Expression.LessThanOrEqual(day.Body, Expression.Constant(to)));
            }

            q = q.Where(Expression.Lambda<Func<T, bool>>(body, day.Parameters));
        }

        return q;
    }

    public override async IAsyncEnumerable<object> ReadAsync(DbContext context, TransferRange range, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (T row in _spec.Order(Scoped(context, range)).AsAsyncEnumerable().WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            yield return row;
        }
    }

    public override List<object> ReadPage(DbContext context, TransferRange range, int skip, int take) =>
        _spec.Order(Scoped(context, range)).Skip(skip).Take(take).ToList().ConvertAll(static r => (object)r);

    public override async Task<long> CountAsync(DbContext context, TransferRange range, CancellationToken cancellationToken) =>
        await Scoped(context, range).LongCountAsync(cancellationToken).ConfigureAwait(false);

    public override async Task<bool> AnyAsync(DbContext context, CancellationToken cancellationToken) =>
        await Scoped(context, TransferRange.All).AnyAsync(cancellationToken).ConfigureAwait(false);

    public override async Task<int> DeleteAllAsync(DbContext context, CancellationToken cancellationToken)
    {
        IQueryable<T> q = context.Set<T>();
        if (_spec.Scope is { } scope)
        {
            q = scope(q);
        }

        return await q.ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
    }

    public override async Task<IReadOnlyList<int>> DaysAsync(DbContext context, CancellationToken cancellationToken)
    {
        if (_spec.Day is not { } day)
        {
            return [];
        }

        return await context.Set<T>().AsNoTracking().Select(day).Distinct().OrderBy(d => d).ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    public override void AddRows(DbContext context, IReadOnlyList<object> rows, Guid? hold)
    {
        EntityKeys? keys = null;
        foreach (object r in rows)
        {
            var row = (T)r;
            _spec.PrepareImport?.Invoke(row);
            if (hold is not null)
            {
                _spec.Hold?.Set(row, hold);
            }

            if (!_spec.Upsert)
            {
                context.Set<T>().Add(row);
                continue;
            }

            keys ??= EntityKeys.For(context, typeof(T));
            T? existing = (T?)context.Set<T>().Find(keys.KeyOf(context, row));
            if (existing is null)
            {
                context.Set<T>().Add(row);
            }
            else
            {
                context.Entry(existing).CurrentValues.SetValues(row);
            }
        }
    }

    public override async Task<int> HoldAllAsync(DbContext context, Guid switchId, CancellationToken cancellationToken) =>
        _spec.Hold is { } h ? await h.HoldAll(context.Set<T>(), switchId, cancellationToken).ConfigureAwait(false) : 0;

    public override async Task<int> ReleaseAsync(DbContext context, Guid switchId, CancellationToken cancellationToken) =>
        _spec.Hold is { } h ? await h.Release(context.Set<T>(), switchId, cancellationToken).ConfigureAwait(false) : 0;

    public override async Task<long> CountHeldAsync(DbContext context, Guid switchId, CancellationToken cancellationToken) =>
        _spec.Hold is { } h ? await h.CountHeld(context.Set<T>().AsNoTracking(), switchId, cancellationToken).ConfigureAwait(false) : 0;
}

/// <summary>Primary-key values of an entity, read through the EF model so upserts need no per-table key code.</summary>
internal sealed class EntityKeys
{
    private readonly string[] _properties;

    private EntityKeys(string[] properties) => _properties = properties;

    public static EntityKeys For(DbContext context, Type entityType)
    {
        var key = context.Model.FindEntityType(entityType)?.FindPrimaryKey() ?? throw new InvalidOperationException($"{entityType.Name} has no primary key.");
        return new EntityKeys(key.Properties.Select(p => p.Name).ToArray());
    }

    public object?[] KeyOf(DbContext context, object row)
    {
        var entry = context.Entry(row);
        return _properties.Select(p => entry.Property(p).CurrentValue).ToArray();
    }
}

internal sealed class UtcMillisecondConverter : JsonConverter<DateTimeOffset>
{
    private const string Format = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'";

    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        DateTimeOffset.Parse(reader.GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value.ToUniversalTime().ToString(Format, CultureInfo.InvariantCulture));
}
