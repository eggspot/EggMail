using System.Security.Cryptography;
using Mta.Fuzz;
using SharpFuzz;

namespace Mta.Fuzz.Harness;

/// <summary>
/// Command line driver.
/// <code>
///   Mta.Fuzz.Harness list
///   Mta.Fuzz.Harness libfuzzer                       # target from EGGMAIL_FUZZ_TARGET; started by libfuzzer-dotnet (see .github/workflows/fuzz.yml)
///   Mta.Fuzz.Harness replay  &lt;target&gt; &lt;file|dir&gt;...   # runs inputs once each (crash artifacts, the checked-in corpus); exit code 1 on a finding
///   Mta.Fuzz.Harness export-corpus &lt;dir&gt;             # writes the built-in seeds as fuzz/corpus/&lt;target&gt;/&lt;hash&gt;
///   Mta.Fuzz.Harness export-dict   &lt;dir&gt;             # writes libFuzzer dictionaries (&lt;target&gt;.dict) from the mutator tokens
///   Mta.Fuzz.Harness mutate  &lt;target&gt; &lt;iterations&gt; [seed]
/// </code>
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            return Usage();
        }

        // Assemblies instrumented by SharpFuzz write coverage into a shared buffer that only the fuzzing entry points set up. Give every other
        // mode (list, replay, mutate: reproducing a finding with the instrumented build) a private one, or the first instrumented call
        // dies with an access violation.
        if (args[0] != "libfuzzer")
        {
            EnsureTraceBuffer();
        }

        switch (args[0])
        {
            case "list":
                foreach (var t in FuzzTargets.All)
                {
                    Console.WriteLine($"{t.Name,-16} {t.Description}");
                }

                return 0;

            case "libfuzzer":
                return LibFuzzer();

            case "replay" when args.Length >= 3:
                return Replay(args[1], args.Skip(2));

            case "export-corpus" when args.Length == 2:
                return ExportCorpus(args[1]);

            case "export-dict" when args.Length == 2:
                return ExportDictionaries(args[1]);

            case "mutate" when args.Length >= 3:
                return Mutate(args[1], int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture), args.Length > 3 ? int.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture) : 1);

            default:
                return Usage();
        }
    }

    private static unsafe void EnsureTraceBuffer()
    {
        if (SharpFuzz.Common.Trace.SharedMem == null)
        {
            SharpFuzz.Common.Trace.SharedMem = (byte*)System.Runtime.InteropServices.NativeMemory.AllocZeroed(1 << 16);
        }
    }

    private static int Usage()
    {
        Console.Error.WriteLine("usage: Mta.Fuzz.Harness list | libfuzzer | replay <target> <file|dir>... | export-corpus <dir> | export-dict <dir> | mutate <target> <iterations> [seed]");
        return 2;
    }

    private static int LibFuzzer()
    {
        string name = Environment.GetEnvironmentVariable("EGGMAIL_FUZZ_TARGET") ?? throw new InvalidOperationException("set EGGMAIL_FUZZ_TARGET to one of: " + string.Join(", ", FuzzTargets.All.Select(t => t.Name)));
        var run = FuzzTargets.Get(name).Run;

        // libfuzzer-dotnet cannot save the input when this process dies without an exception (stack overflow, kill): it only prints
        // "The child process terminated unexpectedly". Keeping the current input in a file makes such a finding reproducible.
        string? lastInputPath = Environment.GetEnvironmentVariable("EGGMAIL_FUZZ_LASTINPUT");
        FileStream? lastInput = lastInputPath is { Length: > 0 } ? new FileStream(lastInputPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite) : null;
        Fuzzer.LibFuzzer.Run(span =>
        {
            if (lastInput is not null)
            {
                lastInput.SetLength(0);
                lastInput.Write(span);
                lastInput.Flush();
            }

            run(span);
        });
        return 0;
    }

    private static int Replay(string target, IEnumerable<string> paths)
    {
        var run = FuzzTargets.Get(target).Run;
        int failures = 0;
        int count = 0;
        foreach (string path in paths)
        {
            foreach (string file in Directory.Exists(path) ? Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToArray() : new[] { path })
            {
                count++;
                try
                {
                    run(File.ReadAllBytes(file));
                }
                catch (Exception ex)
                {
                    failures++;
                    Console.Error.WriteLine($"FINDING {file}: {ex}");
                }
            }
        }

        Console.WriteLine($"{target}: {count} inputs, {failures} findings");
        return failures == 0 ? 0 : 1;
    }

    private static int ExportCorpus(string directory)
    {
        foreach (var t in FuzzTargets.All)
        {
            string dir = Path.Combine(directory, t.Name);
            Directory.CreateDirectory(dir);
            foreach (byte[] seed in t.Seeds)
            {
                File.WriteAllBytes(Path.Combine(dir, CorpusName(seed)), seed);
            }
        }

        return 0;
    }

    private static int ExportDictionaries(string directory)
    {
        Directory.CreateDirectory(directory);
        foreach (var t in FuzzTargets.All)
        {
            var lines = new List<string>();
            for (int i = 0; i < t.Tokens.Count; i++)
            {
                lines.Add($"t{i}=\"{string.Concat(t.Tokens[i].Select(b => $"\\x{b:x2}"))}\"");
            }

            File.WriteAllLines(Path.Combine(directory, t.Name + ".dict"), lines);
        }

        return 0;
    }

    /// <summary>Content-addressed file names (the first 40 hex digits of the SHA-256), so merged corpora never collide and identical inputs are stored once.</summary>
    public static string CorpusName(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data))[..40];

    private static int Mutate(string target, int iterations, int seed)
    {
        var t = FuzzTargets.Get(target);
        var mutator = new Mutator(seed, t.Seeds, t.Tokens, t.MaxInputLength);
        var slowest = new List<(double Ms, int Index, int Length)>();
        for (int i = 0; i < iterations; i++)
        {
            byte[] input = mutator.Next();
            try
            {
                long started = System.Diagnostics.Stopwatch.GetTimestamp();
                t.Run(input);
                slowest.Add((System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds, i, input.Length));
                if (slowest.Count > 64)
                {
                    slowest = slowest.OrderByDescending(x => x.Ms).Take(3).ToList();
                }
            }
            catch (Exception ex)
            {
                string file = $"crash-{CorpusName(input)}";
                File.WriteAllBytes(file, input);
                Console.Error.WriteLine($"FINDING after {i} inputs, saved {file}: {ex}");
                return 1;
            }
        }

        Console.WriteLine($"{target}: {iterations} mutated inputs, no findings; slowest (for tuning only, nothing asserts time): " + string.Join(", ", slowest.OrderByDescending(x => x.Ms).Take(3).Select(x => $"#{x.Index} {x.Length} bytes {x.Ms:F1} ms")));
        return 0;
    }
}
