using System.Runtime.CompilerServices;
using Microsoft.EntityFrameworkCore;
using Mta.Core;
using Mta.Storage.Model;

namespace Mta.Storage.Transfer;

/// <summary>
/// How <see cref="EfStorageTransfer"/> reaches the database of each model part. SQLite serializes writes through the file's
/// writer thread (one context bound to the writer's connection and transaction); PostgreSQL opens a context and a transaction
/// per call.
/// </summary>
public interface ITransferDbAccess
{
    bool HasPart(TransferPart part);

    /// <summary>False when reads of the part cannot stream on a separate connection and must be paged through <see cref="WriteAsync{T}"/> (an in-memory SQLite queue).</summary>
    bool StreamsReads(TransferPart part);

    /// <summary>A short-lived no-tracking context for one read or enumeration; the caller disposes it.</summary>
    DbContext CreateReadContext(TransferPart part);

    /// <summary>
    /// Runs <paramref name="work"/> with a context joined to an open transaction on the part's database and commits when it
    /// returns. The work may run more than once when a batch is retried, so it must be repeatable; it saves its own changes.
    /// </summary>
    ValueTask<T> WriteAsync<T>(TransferPart part, Func<DbContext, CancellationToken, Task<T>> work, CancellationToken cancellationToken);

    /// <summary>
    /// Called before history rows of the days <paramref name="firstDay"/> to <paramref name="lastDay"/> are written. A provider whose
    /// history tables are partitioned by day (PostgreSQL) makes sure the partitions exist, including old days that the
    /// application would no longer create. The default does nothing.
    /// </summary>
    ValueTask PrepareHistoryDaysAsync(int firstDay, int lastDay, CancellationToken cancellationToken) => default;
}

/// <summary>
/// <see cref="IStorageTransfer"/> over EF Core, implemented once for every relational provider (design §4.6: "one
/// implementation for both"). The tables and columns come from <see cref="TransferTables"/>; the database access from
/// <see cref="ITransferDbAccess"/>.
/// </summary>
public sealed class EfStorageTransfer(ITransferDbAccess access, IConfigStore config, SwitchGate gate, IClock clock) : IStorageTransfer
{
    private const int PageSize = 500;

    public SwitchGate Gate => gate;

    public bool HasPart(TransferPart part) => access.HasPart(part);

    private void Require(TransferPart part)
    {
        if (!access.HasPart(part))
        {
            throw new StorageTransferException($"This store has no {part.ToString().ToLowerInvariant()} part (history is not recorded under History:Mode=StatsOnly).");
        }
    }

    public async IAsyncEnumerable<object> ReadAsync(TransferTable table, TransferRange range, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        Require(table.Part);
        if (!access.StreamsReads(table.Part))
        {
            int skip = 0;
            while (true)
            {
                int offset = skip;
                List<object> page = await access.WriteAsync(table.Part, (ctx, _) => Task.FromResult(table.ReadPage(ctx, range, offset, PageSize)), cancellationToken).ConfigureAwait(false);
                foreach (object row in page)
                {
                    yield return row;
                }

                if (page.Count < PageSize)
                {
                    yield break;
                }

                skip += page.Count;
            }
        }

        using DbContext context = access.CreateReadContext(table.Part);
        await foreach (object row in table.ReadAsync(context, range, cancellationToken).ConfigureAwait(false))
        {
            yield return row;
        }
    }

    public async ValueTask<long> CountAsync(TransferTable table, TransferRange range, CancellationToken cancellationToken)
    {
        Require(table.Part);
        if (!access.StreamsReads(table.Part))
        {
            return await access.WriteAsync(table.Part, (ctx, ct) => table.CountAsync(ctx, range, ct), cancellationToken).ConfigureAwait(false);
        }

        using DbContext context = access.CreateReadContext(table.Part);
        return await table.CountAsync(context, range, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<int>> GetHistoryDaysAsync(CancellationToken cancellationToken)
    {
        if (!access.HasPart(TransferPart.History))
        {
            return [];
        }

        using DbContext context = access.CreateReadContext(TransferPart.History);
        var days = new SortedSet<int>();
        foreach (TransferTable table in TransferTables.Of(TransferPart.History))
        {
            foreach (int d in await table.DaysAsync(context, cancellationToken).ConfigureAwait(false))
            {
                days.Add(d);
            }
        }

        return days.ToList();
    }

    public async ValueTask<IReadOnlyList<string>> GetNonEmptyTablesAsync(CancellationToken cancellationToken)
    {
        var result = new List<string>();
        foreach (TransferPart part in Enum.GetValues<TransferPart>().Where(access.HasPart))
        {
            bool streams = access.StreamsReads(part);
            foreach (TransferTable table in TransferTables.Of(part))
            {
                bool any;
                if (streams)
                {
                    using DbContext context = access.CreateReadContext(part);
                    any = await table.AnyAsync(context, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    any = await access.WriteAsync(part, (ctx, ct) => table.AnyAsync(ctx, ct), cancellationToken).ConfigureAwait(false);
                }

                if (any)
                {
                    result.Add(table.Name);
                }
            }
        }

        return result;
    }

    public async ValueTask<ChunkApplyOutcome> ApplyChunkAsync(TransferChunk chunk, IReadOnlyList<object> rows, CancellationToken cancellationToken)
    {
        TransferPart part = chunk.Table.Part;
        Require(part);
        ChunkRecords records = ChunkRecords.For(part);
        DateTimeOffset now = clock.UtcNow;
        if (chunk.Table.PerDay && rows.Count > 0)
        {
            int first = int.MaxValue, last = int.MinValue;
            foreach (object row in rows)
            {
                int day = chunk.Table.DayOf(row);
                first = Math.Min(first, day);
                last = Math.Max(last, day);
            }

            await access.PrepareHistoryDaysAsync(first, last, cancellationToken).ConfigureAwait(false);
        }

        return await access.WriteAsync(part, async (ctx, ct) =>
        {
            TransferChunkEntity? existing = await records.FindAsync(ctx, chunk.SwitchId, chunk.ChunkId, ct).ConfigureAwait(false);
            if (existing is not null)
            {
                if (!string.Equals(existing.Checksum, chunk.Checksum, StringComparison.OrdinalIgnoreCase))
                {
                    throw new StorageTransferException($"Chunk {chunk.ChunkId} was applied before with a different checksum ({existing.Checksum}, now {chunk.Checksum}); the bundle changed after the import started.");
                }

                return ChunkApplyOutcome.AlreadyApplied;
            }

            // Adding thousands of entities one by one would re-run change detection each time; detect once, before saving.
            ctx.ChangeTracker.AutoDetectChangesEnabled = false;
            chunk.Table.AddRows(ctx, rows, chunk.HoldRows ? chunk.SwitchId : null);
            records.Add(ctx, new TransferChunkRecord(chunk.SwitchId, chunk.ChunkId, chunk.Table.Name, rows.Count, chunk.Checksum, StorageTimeOf(now)));
            ctx.ChangeTracker.DetectChanges();
            await ctx.SaveChangesAsync(ct).ConfigureAwait(false);
            ctx.ChangeTracker.Clear();
            return ChunkApplyOutcome.Applied;
        }, cancellationToken).ConfigureAwait(false);
    }

    private static DateTimeOffset StorageTimeOf(DateTimeOffset value) => DateTimeOffset.FromUnixTimeMilliseconds(value.ToUnixTimeMilliseconds());

    public async ValueTask<IReadOnlyList<TransferChunkRecord>> GetAppliedChunksAsync(Guid switchId, TransferPart part, CancellationToken cancellationToken)
    {
        if (!access.HasPart(part))
        {
            return [];
        }

        ChunkRecords records = ChunkRecords.For(part);
        if (!access.StreamsReads(part))
        {
            return await access.WriteAsync(part, (ctx, ct) => records.ListAsync(ctx, switchId, ct), cancellationToken).ConfigureAwait(false);
        }

        using DbContext context = access.CreateReadContext(part);
        return await records.ListAsync(context, switchId, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DiscardImportedAsync(Guid switchId, CancellationToken cancellationToken)
    {
        foreach (TransferPart part in Enum.GetValues<TransferPart>().Where(access.HasPart))
        {
            ChunkRecords records = ChunkRecords.For(part);
            await access.WriteAsync(part, async (ctx, ct) =>
            {
                foreach (TransferTable table in TransferTables.Of(part).Reverse())
                {
                    await table.DeleteAllAsync(ctx, ct).ConfigureAwait(false);
                }

                await records.DeleteAsync(ctx, switchId, ct).ConfigureAwait(false);
                return 0;
            }, cancellationToken).ConfigureAwait(false);
        }
    }

    public async ValueTask<SwitchStateRecord?> GetStateAsync(CancellationToken cancellationToken)
    {
        SwitchStateRecord? state = await config.GetSwitchStateAsync(cancellationToken).ConfigureAwait(false);

        // Another process (the CLI, another replica) may have changed the state: whoever reads it keeps this process's gate current.
        gate.Apply(state);
        return state;
    }

    public async ValueTask SetStateAsync(SwitchStateRecord state, CancellationToken cancellationToken)
    {
        await config.SetSwitchStateAsync(state, cancellationToken).ConfigureAwait(false);
        gate.Apply(state);
    }

    public async ValueTask ClearStateAsync(CancellationToken cancellationToken)
    {
        await access.WriteAsync(TransferPart.Config, async (ctx, ct) => await ctx.Set<SwitchStateEntity>().ExecuteDeleteAsync(ct).ConfigureAwait(false), cancellationToken).ConfigureAwait(false);
        gate.Apply(null);
    }

    public async ValueTask<long> MarkQueueTransferredAsync(Guid switchId, CancellationToken cancellationToken)
    {
        long marked = 0;
        foreach (TransferTable table in TransferTables.Of(TransferPart.Queue).Where(t => t.HasHold))
        {
            marked += await access.WriteAsync(TransferPart.Queue, (ctx, ct) => table.HoldAllAsync(ctx, switchId, ct), cancellationToken).ConfigureAwait(false);
        }

        return marked;
    }

    public async ValueTask<long> ReleaseQueueAsync(Guid switchId, CancellationToken cancellationToken)
    {
        long released = 0;
        foreach (TransferTable table in TransferTables.Of(TransferPart.Queue).Where(t => t.HasHold))
        {
            released += await access.WriteAsync(TransferPart.Queue, (ctx, ct) => table.ReleaseAsync(ctx, switchId, ct), cancellationToken).ConfigureAwait(false);
        }

        return released;
    }

    public async ValueTask<long> CountHeldQueueRowsAsync(Guid switchId, CancellationToken cancellationToken)
    {
        long held = 0;
        foreach (TransferTable table in TransferTables.Of(TransferPart.Queue).Where(t => t.HasHold))
        {
            held += await access.WriteAsync(TransferPart.Queue, (ctx, ct) => table.CountHeldAsync(ctx, switchId, ct), cancellationToken).ConfigureAwait(false);
        }

        return held;
    }
}

/// <summary>Access to the per-part progress table through the typed chunk entity of that part.</summary>
internal abstract class ChunkRecords
{
    public static ChunkRecords For(TransferPart part) => part switch
    {
        TransferPart.Config => ChunkRecords<ConfigTransferChunkEntity>.Instance,
        TransferPart.Stats => ChunkRecords<StatsTransferChunkEntity>.Instance,
        TransferPart.Queue => ChunkRecords<QueueTransferChunkEntity>.Instance,
        TransferPart.History => ChunkRecords<HistoryTransferChunkEntity>.Instance,
        _ => throw new ArgumentOutOfRangeException(nameof(part)),
    };

    public abstract Task<TransferChunkEntity?> FindAsync(DbContext context, Guid switchId, string chunkId, CancellationToken cancellationToken);

    public abstract void Add(DbContext context, TransferChunkRecord record);

    public abstract Task<IReadOnlyList<TransferChunkRecord>> ListAsync(DbContext context, Guid switchId, CancellationToken cancellationToken);

    public abstract Task<int> DeleteAsync(DbContext context, Guid switchId, CancellationToken cancellationToken);
}

internal sealed class ChunkRecords<T> : ChunkRecords where T : TransferChunkEntity, new()
{
    public static readonly ChunkRecords<T> Instance = new();

    public override async Task<TransferChunkEntity?> FindAsync(DbContext context, Guid switchId, string chunkId, CancellationToken cancellationToken) =>
        await context.Set<T>().AsNoTracking().Where(x => x.SwitchId == switchId && x.ChunkId == chunkId).FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);

    public override void Add(DbContext context, TransferChunkRecord record) => context.Set<T>().Add(new T
    {
        SwitchId = record.SwitchId,
        ChunkId = record.ChunkId,
        TableName = record.Table,
        Rows = record.Rows,
        Checksum = record.Checksum,
        AppliedAt = record.AppliedAt,
    });

    public override async Task<IReadOnlyList<TransferChunkRecord>> ListAsync(DbContext context, Guid switchId, CancellationToken cancellationToken)
    {
        List<T> rows = await context.Set<T>().AsNoTracking().Where(x => x.SwitchId == switchId).ToListAsync(cancellationToken).ConfigureAwait(false);
        return rows.OrderBy(x => x.ChunkId, StringComparer.Ordinal).Select(x => new TransferChunkRecord(x.SwitchId, x.ChunkId, x.TableName, x.Rows, x.Checksum, x.AppliedAt)).ToList();
    }

    public override async Task<int> DeleteAsync(DbContext context, Guid switchId, CancellationToken cancellationToken) =>
        await context.Set<T>().Where(x => x.SwitchId == switchId).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
}
