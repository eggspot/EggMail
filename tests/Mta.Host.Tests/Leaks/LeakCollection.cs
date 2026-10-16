namespace Mta.Host.Tests.Leaks;

/// <summary>
/// The leak checks measure process-wide numbers (managed heap, threads, descriptors, timers), so they must not run next to other tests: this
/// collection is never run in parallel with another collection of the assembly.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class LeakCollection
{
    public const string Name = "Leak (process-wide measurements)";
}
