using System.Net;

namespace Mta.Host.Ingest;

/// <summary>
/// The verification slots of the receive path (design section 11.5): at most <c>Inbound:Verification:MaxConcurrency</c> verifications run at once, and one network (an IPv4 /24 or an IPv6 /64) holds
/// at most <c>MaxConcurrencyPerRemote</c> of them. A slot is taken after the end of DATA and held only for the verification (bounded by its timeout); nobody waits for one: when none is free the
/// message gets <c>451</c> at once, because a message that waits holds its connection, its buffers and the in-flight bytes budget, which is what a flood is after.
/// </summary>
public sealed class VerificationSlots
{
    private readonly object _gate = new();
    private readonly Dictionary<string, int> _perNetwork = new(StringComparer.Ordinal);
    private readonly int _max;
    private readonly int _maxPerNetwork;
    private int _inUse;

    public VerificationSlots(int maxConcurrency, int maxPerNetwork)
    {
        if (maxConcurrency < 1 || maxPerNetwork < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxConcurrency), "Both limits must be at least 1.");
        }

        _max = maxConcurrency;
        _maxPerNetwork = maxPerNetwork;
    }

    public int InUse
    {
        get
        {
            lock (_gate)
            {
                return _inUse;
            }
        }
    }

    /// <summary>Whether a slot would be free for this client now: a look, nothing is reserved (the start-of-DATA check).</summary>
    public bool HasFreeSlotFor(IPAddress client)
    {
        string network = NetworkKey.Slot(client);
        lock (_gate)
        {
            return _inUse < _max && (!_perNetwork.TryGetValue(network, out int held) || held < _maxPerNetwork);
        }
    }

    /// <summary>Takes a slot for this client, or returns null when all slots (or the client's network's share) are in use. Dispose the lease to give it back.</summary>
    public Lease? TryAcquire(IPAddress client)
    {
        string network = NetworkKey.Slot(client);
        lock (_gate)
        {
            _perNetwork.TryGetValue(network, out int held);
            if (_inUse >= _max || held >= _maxPerNetwork)
            {
                return null;
            }

            _inUse++;
            _perNetwork[network] = held + 1;
        }

        InboundMetrics.VerificationSlotsInUse.Add(1);
        return new Lease(this, network);
    }

    private void Release(string network)
    {
        lock (_gate)
        {
            _inUse--;
            if (_perNetwork.TryGetValue(network, out int held))
            {
                if (held <= 1)
                {
                    _perNetwork.Remove(network);
                }
                else
                {
                    _perNetwork[network] = held - 1;
                }
            }
        }

        InboundMetrics.VerificationSlotsInUse.Add(-1);
    }

    public sealed class Lease : IDisposable
    {
        private VerificationSlots? _owner;
        private readonly string _network;

        internal Lease(VerificationSlots owner, string network)
        {
            _owner = owner;
            _network = network;
        }

        public void Dispose() => Interlocked.Exchange(ref _owner, null)?.Release(_network);
    }
}
