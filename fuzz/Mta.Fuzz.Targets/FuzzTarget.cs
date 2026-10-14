using System.Diagnostics.CodeAnalysis;

namespace Mta.Fuzz;

/// <summary>The body of a fuzz target: feed the input to a parser and check its invariants. Anything thrown is a finding.</summary>
public delegate void FuzzAction(ReadOnlySpan<byte> input);

/// <summary>An invariant of a parser was violated (the parser itself did not crash).</summary>
public sealed class FuzzFindingException : Exception
{
    public FuzzFindingException(string message) : base(message)
    {
    }

    public FuzzFindingException(string message, Exception inner) : base(message, inner)
    {
    }
}

/// <summary>One fuzzed parser (or group of parsers sharing an input format).</summary>
public sealed class FuzzTarget
{
    public FuzzTarget(string name, string description, FuzzAction run, IReadOnlyList<byte[]> seeds)
    {
        Name = name;
        Description = description;
        Run = run;
        Seeds = seeds;
    }

    /// <summary>The short name used on the command line, in <c>fuzz/corpus/&lt;name&gt;</c> and in the workflow.</summary>
    public string Name { get; }

    public string Description { get; }

    public FuzzAction Run { get; }

    /// <summary>Small valid (and nearly valid) inputs; also written to <c>fuzz/corpus/&lt;name&gt;</c> by the harness.</summary>
    public IReadOnlyList<byte[]> Seeds { get; }

    /// <summary>Byte strings the mutator splices in (protocol keywords, delimiters, interesting values).</summary>
    public IReadOnlyList<byte[]> Tokens { get; init; } = [];

    /// <summary>How many mutated inputs the deterministic regression test runs (a few seconds in total per target).</summary>
    public int MutationIterations { get; init; } = 3000;

    /// <summary>
    /// Whether the regression test measures the managed allocation of <see cref="Run"/> on the calling thread. Turn it off for
    /// targets that do their work on other threads (the SMTP session), where the number would be meaningless.
    /// </summary>
    public bool MeasureAllocation { get; init; } = true;

    /// <summary>Allocation ceiling for one run: generous (a fixed allowance plus a multiple of the input) because it only has to catch unbounded growth.</summary>
    public long AllocationBudget(int inputLength) => (256L * inputLength) + (64L << 20);

    /// <summary>Largest input the mutator produces for this target.</summary>
    public int MaxInputLength { get; init; } = 256 * 1024;
}

internal static class Guard
{
    public static void Check([DoesNotReturnIf(false)] bool condition, string what)
    {
        if (!condition)
        {
            throw new FuzzFindingException(what);
        }
    }
}
