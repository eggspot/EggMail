using Mta.Core;

namespace Mta.Dns;

/// <summary>
/// A bounded TTL cache of resolved answers. Sixteen independently locked shards, each an LRU list, so contention
/// stays low and the total size can never exceed the configured capacity. Expiry uses the injected clock's wall time.
/// </summary>
internal sealed class DnsCache
{
    internal readonly record struct Key(string Name, DnsRecordType Type);

    private sealed class Entry
    {
        public required Key Key { get; init; }

        public required DnsResponse Response { get; init; }

        public required DateTimeOffset StoredAt { get; init; }

        public required TimeSpan Lifetime { get; init; }
    }

    private const int ShardCount = 16;

    private readonly Shard[] _shards;
    private readonly IClock _clock;

    public DnsCache(int capacity, IClock clock)
    {
        _clock = clock;
        int shards = capacity >= ShardCount * 2 ? ShardCount : 1;
        _shards = new Shard[shards];
        int per = Math.Max(1, capacity / shards);
        for (int i = 0; i < shards; i++)
        {
            _shards[i] = new Shard(per);
        }
    }

    public int Count
    {
        get
        {
            int total = 0;
            foreach (var shard in _shards)
            {
                lock (shard.Gate)
                {
                    total += shard.Map.Count;
                }
            }

            return total;
        }
    }

    public bool TryGet(in Key key, out DnsResponse response)
    {
        var shard = ShardFor(key);
        DateTimeOffset now = _clock.UtcNow;
        Entry entry;
        lock (shard.Gate)
        {
            if (!shard.Map.TryGetValue(key, out var node))
            {
                response = null!;
                return false;
            }

            entry = node.Value;
            TimeSpan age = now - entry.StoredAt;
            if (age < TimeSpan.Zero || age >= entry.Lifetime)
            {
                // Expired (or the clock went backwards: do not trust the entry).
                shard.Lru.Remove(node);
                shard.Map.Remove(key);
                response = null!;
                return false;
            }

            shard.Lru.Remove(node);
            shard.Lru.AddFirst(node);
            response = Decay(entry.Response, (uint)Math.Min(age.TotalSeconds, uint.MaxValue));
            return true;
        }
    }

    public void Set(in Key key, DnsResponse response, TimeSpan lifetime)
    {
        if (lifetime <= TimeSpan.Zero)
        {
            return;
        }

        var shard = ShardFor(key);
        var entry = new Entry { Key = key, Response = response, StoredAt = _clock.UtcNow, Lifetime = lifetime };
        lock (shard.Gate)
        {
            if (shard.Map.TryGetValue(key, out var existing))
            {
                shard.Lru.Remove(existing);
                shard.Map.Remove(key);
            }

            while (shard.Map.Count >= shard.Capacity && shard.Lru.Last is { } victim)
            {
                shard.Lru.RemoveLast();
                shard.Map.Remove(victim.Value.Key);
            }

            shard.Map[key] = shard.Lru.AddFirst(entry);
        }
    }

    private Shard ShardFor(in Key key) =>
        _shards[(int)((uint)HashCode.Combine(key.Name, key.Type) % (uint)_shards.Length)];

    /// <summary>Returns the response with TTLs reduced by the time spent in the cache (never below zero).</summary>
    private static DnsResponse Decay(DnsResponse response, uint elapsedSeconds)
    {
        if (elapsedSeconds == 0)
        {
            return response;
        }

        var answers = new DnsRecord[response.Answers.Count];
        for (int i = 0; i < answers.Length; i++)
        {
            var record = response.Answers[i];
            answers[i] = record with { Ttl = record.Ttl > elapsedSeconds ? record.Ttl - elapsedSeconds : 0 };
        }

        return new DnsResponse
        {
            Rcode = response.Rcode,
            AuthenticatedData = response.AuthenticatedData,
            Answers = answers,
            Ttl = response.Ttl > elapsedSeconds ? response.Ttl - elapsedSeconds : 0,
        };
    }

    private sealed class Shard(int capacity)
    {
        public readonly object Gate = new();
        public readonly Dictionary<Key, LinkedListNode<Entry>> Map = new();
        public readonly LinkedList<Entry> Lru = new();
        public readonly int Capacity = capacity;
    }
}
