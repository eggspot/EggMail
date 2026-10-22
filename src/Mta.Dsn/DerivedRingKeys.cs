namespace Mta.Dsn;

/// <summary>
/// The keys derived from a <see cref="VerpCodec"/> ring for one purpose (SRS, the forward hop marker), kept until the ring's key set is replaced: then they are derived again on the next use, so a
/// rotated or pruned key reaches every derived secret without rebuilding its owner.
/// </summary>
internal sealed class DerivedRingKeys
{
    /// <summary>The derived keys of one key set, with the id of the key that signs.</summary>
    public sealed class Snapshot(VerpCodec.KeySet source, Dictionary<int, byte[]> keys)
    {
        public VerpCodec.KeySet Source { get; } = source;

        /// <summary>The concrete type on purpose: a verifier loops over every key, and the dictionary's own enumerator does not allocate.</summary>
        public Dictionary<int, byte[]> Keys { get; } = keys;

        public int ActiveKeyId => Source.ActiveKeyId;

        public byte[] ActiveKey => Keys[Source.ActiveKeyId];
    }

    private readonly VerpCodec _ring;
    private readonly string _purpose;
    private volatile Snapshot _current;

    public DerivedRingKeys(VerpCodec ring, string purpose)
    {
        ArgumentNullException.ThrowIfNull(ring);
        _ring = ring;
        _purpose = purpose;
        _current = Derive(ring.Current);
    }

    /// <summary>The keys of the ring's current key set (derived once per set; two threads that see a new set at the same time may both derive it, with the same result).</summary>
    public Snapshot Current
    {
        get
        {
            Snapshot snapshot = _current;
            VerpCodec.KeySet set = _ring.Current;
            if (!ReferenceEquals(snapshot.Source, set))
            {
                snapshot = Derive(set);
                _current = snapshot;
            }

            return snapshot;
        }
    }

    private Snapshot Derive(VerpCodec.KeySet set)
    {
        var keys = new Dictionary<int, byte[]>();
        foreach (int id in set.Keys.Keys)
        {
            keys[id] = VerpCodec.DeriveKey(set, id, _purpose);
        }

        return new Snapshot(set, keys);
    }
}
