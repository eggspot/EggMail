namespace Mta.Policy;

/// <summary>Injectable source of randomness so jitter is deterministic in tests.</summary>
public interface IRandomSource
{
    /// <summary>A uniformly distributed value in [0, 1). Must be thread-safe.</summary>
    double NextDouble();
}

/// <summary>Production random source backed by <see cref="Random.Shared"/> (thread-safe, lock-free).</summary>
public sealed class SystemRandomSource : IRandomSource
{
    /// <summary>The shared instance.</summary>
    public static readonly SystemRandomSource Instance = new();

    /// <inheritdoc />
    public double NextDouble() => Random.Shared.NextDouble();
}

/// <summary>Seeded, thread-safe (locked) random source for deterministic tests and benchmarks.</summary>
public sealed class SeededRandomSource : IRandomSource
{
    private readonly Random _random;
    private readonly object _gate = new();

    /// <summary>Creates a source with a fixed seed.</summary>
    public SeededRandomSource(int seed) => _random = new Random(seed);

    /// <inheritdoc />
    public double NextDouble()
    {
        lock (_gate)
        {
            return _random.NextDouble();
        }
    }
}
