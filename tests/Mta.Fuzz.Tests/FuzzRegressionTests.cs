using System.Security.Cryptography;
using Mta.Fuzz;
using Xunit.Sdk;

namespace Mta.Fuzz.Tests;

/// <summary>
/// The deterministic slice of the fuzzers that runs in every <c>dotnet test</c>: the built-in seeds, the checked-in corpus
/// (<c>fuzz/corpus</c>), every input that ever crashed a parser (<c>fuzz/regressions</c>), all prefixes of each seed, and a fixed
/// number of seeded mutations. Nothing here asserts elapsed time. A hang is caught by a limit far above any plausible load, unbounded
/// allocation by a generous byte budget measured on the running thread, and a crash or a broken invariant by the exception itself.
/// The coverage-guided search (libFuzzer) runs in .github/workflows/fuzz.yml.
/// </summary>
public class FuzzRegressionTests
{
    /// <summary>Fixed so that every machine and every run replays exactly the same inputs. Change it (or add one) to widen the search.</summary>
    private const int MutationSeed = 20261013;

    private static readonly TimeSpan HangLimit = TimeSpan.FromMinutes(10);

    public static IEnumerable<object[]> Targets() => FuzzTargets.All.Select(t => new object[] { t.Name });

    [Fact]
    public void The_required_parsers_are_all_covered()
    {
        string[] required = ["smtp-protocol", "smtp-session", "smtp-client", "mime", "dkim", "spf", "dns-message", "dsn-arf", "mta-sts", "tls-rpt", "verp", "dane", "eightbit-downgrade", "message-builder"];
        foreach (string name in required)
        {
            Assert.Contains(FuzzTargets.All, t => t.Name == name);
        }

        Assert.Equal(FuzzTargets.All.Count, FuzzTargets.All.Select(t => t.Name).Distinct().Count());
    }

    [Fact]
    public void The_session_target_really_talks_to_the_server()
    {
        // Without this the session target could pass vacuously (a connection that is refused at once also "runs clean").
        string transcript = System.Text.Encoding.Latin1.GetString(FuzzTargets.SmtpSessionTranscript(
            System.Text.Encoding.Latin1.GetBytes("\0EHLO fuzz.example\r\nMAIL FROM:<a@example.com>\r\nRCPT TO:<b@example.net>\r\nDATA\r\nSubject: x\r\n\r\n..dot\r\n.\r\nQUIT\r\n")));
        Assert.StartsWith("220 ", transcript);
        Assert.Contains("250 2.0.0 Queued", transcript);
        Assert.Contains("221 ", transcript);

        // A smuggling attempt (bare LF before the dot) is refused, not accepted.
        string smuggled = System.Text.Encoding.Latin1.GetString(FuzzTargets.SmtpSessionTranscript(
            System.Text.Encoding.Latin1.GetBytes("\0EHLO x\r\nMAIL FROM:<a@b.example>\r\nRCPT TO:<c@d.example>\r\nDATA\r\nx\r\n.\n\r\nMAIL FROM:<smuggled@x.example>\r\n")));
        Assert.DoesNotContain("250 2.0.0 Queued", smuggled);
    }

    [Fact]
    public void The_client_target_really_drives_the_client()
    {
        // Without this the client target could pass vacuously (a client that never gets past the banner also "runs clean").
        var target = FuzzTargets.Get("smtp-client");
        var (outcome, sent) = FuzzTargets.SmtpClientExchange(target.Seeds[0]);
        string transcript = System.Text.Encoding.Latin1.GetString(sent);
        Assert.Equal("delivered", outcome);
        Assert.Contains("EHLO client.example.com\r\n", transcript);
        Assert.Contains("RCPT TO:<c@example.net>", transcript);
        Assert.Contains("\r\n..leading dot\r\n.\r\n", transcript);

        // A server that refuses the greeting ends in the documented exception, not a crash.
        Assert.Equal("SmtpGreetingRejectedException", FuzzTargets.SmtpClientExchange(System.Text.Encoding.Latin1.GetBytes("\u0000554 5.7.1 Go away\r\n")).Outcome);
    }

    [Theory]
    [MemberData(nameof(Targets))]
    public void Built_in_seeds_run_clean(string name)
    {
        var target = FuzzTargets.Get(name);
        Assert.NotEmpty(target.Seeds);
        Guarded(target, progress =>
        {
            foreach (byte[] seed in target.Seeds)
            {
                RunOne(target, progress, seed, "seed");
            }
        });
    }

    [Theory]
    [MemberData(nameof(Targets))]
    public void Checked_in_corpus_and_regression_inputs_run_clean(string name)
    {
        var target = FuzzTargets.Get(name);
        Guarded(target, progress =>
        {
            foreach (string directory in new[] { Path.Combine(RepoRoot(), "fuzz", "corpus", name), Path.Combine(RepoRoot(), "fuzz", "regressions", name) })
            {
                if (!Directory.Exists(directory))
                {
                    continue;
                }

                foreach (string file in Directory.EnumerateFiles(directory).Order(StringComparer.Ordinal))
                {
                    RunOne(target, progress, File.ReadAllBytes(file), Path.GetRelativePath(RepoRoot(), file));
                }
            }
        });
    }

    [Theory]
    [MemberData(nameof(Targets))]
    public void Checked_in_corpus_contains_every_built_in_seed(string name)
    {
        // The corpus is what the coverage-guided fuzzers start from. If a seed is added or changed in code, regenerate it with:
        //   dotnet run --project fuzz/Mta.Fuzz.Harness -c Release -- export-corpus fuzz/corpus
        string directory = Path.Combine(RepoRoot(), "fuzz", "corpus", name);
        Assert.True(Directory.Exists(directory), $"missing {directory}; run the export-corpus command of Mta.Fuzz.Harness");
        var present = Directory.EnumerateFiles(directory).Select(Path.GetFileName).ToHashSet(StringComparer.Ordinal);
        foreach (byte[] seed in FuzzTargets.Get(name).Seeds)
        {
            Assert.True(present.Contains(CorpusName(seed)), $"fuzz/corpus/{name} lacks a built-in seed ({seed.Length} bytes, {CorpusName(seed)}); run the export-corpus command of Mta.Fuzz.Harness");
        }
    }

    [Theory]
    [MemberData(nameof(Targets))]
    public void Every_prefix_of_every_seed_runs_clean(string name)
    {
        var target = FuzzTargets.Get(name);
        if (!target.MeasureAllocation)
        {
            return;   // the session target opens a connection per input; its seeds are covered by the mutation run
        }

        Guarded(target, progress =>
        {
            foreach (byte[] seed in target.Seeds)
            {
                int step = Math.Max(1, seed.Length / 200);   // at most about 200 prefixes per seed
                for (int length = 0; length < seed.Length; length += step)
                {
                    RunOne(target, progress, seed[..length], $"prefix {length} of a seed");
                }
            }
        });
    }

    [Theory]
    [MemberData(nameof(Targets))]
    public void Seeded_mutations_run_clean(string name)
    {
        var target = FuzzTargets.Get(name);
        var mutator = new Mutator(MutationSeed, target.Seeds, target.Tokens, target.MaxInputLength);
        Guarded(target, progress =>
        {
            for (int i = 0; i < target.MutationIterations; i++)
            {
                RunOne(target, progress, mutator.Next(), $"mutation {i} (seed {MutationSeed})");
            }
        });
    }

    /// <summary>What the guarded worker is doing right now, so that a hang can name the input.</summary>
    private sealed class Progress
    {
        public volatile string Origin = "start";
        public volatile byte[] Input = [];
    }

    /// <summary>
    /// Runs the whole body on one dedicated thread (so allocation can be measured on that thread) and fails if it does not finish within a
    /// limit far above any plausible load. One watchdog per test, not per input: a thread per input made this suite slow on small CI runners.
    /// </summary>
    private static void Guarded(FuzzTarget target, Action<Progress> body)
    {
        var progress = new Progress();
        var worker = Task.Factory.StartNew(() => body(progress), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        if (!worker.Wait(HangLimit))
        {
            throw new XunitException($"{target.Name}: hang (or far too slow) on {progress.Origin}. {Describe(progress.Input)}");
        }

        worker.GetAwaiter().GetResult();
    }

    private static void RunOne(FuzzTarget target, Progress progress, byte[] input, string origin)
    {
        progress.Origin = origin;
        progress.Input = input;
        long before = GC.GetAllocatedBytesForCurrentThread();
        try
        {
            target.Run(input);
        }
        catch (Exception ex)
        {
            throw new XunitException($"{target.Name}: {ex.GetType().Name}: {ex.Message} on {origin}. {Describe(input)}\n{ex}");
        }

        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        if (target.MeasureAllocation && allocated > target.AllocationBudget(input.Length))
        {
            throw new XunitException($"{target.Name}: allocated {allocated / 1024} KiB for {input.Length} input bytes on {origin} (budget {target.AllocationBudget(input.Length) / 1024} KiB). {Describe(input)}");
        }
    }

    private static string Describe(byte[] input)
    {
        if (input.Length <= 4096)
        {
            return $"Input ({input.Length} bytes) as base64, to be saved under fuzz/regressions/<target>/: {Convert.ToBase64String(input)}";
        }

        string file = Path.Combine(Path.GetTempPath(), "mta-fuzz-failures", CorpusName(input));
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllBytes(file, input);
        return $"Input is {input.Length} bytes, written to {file} (copy it to fuzz/regressions/<target>/ once fixed).";
    }

    private static string CorpusName(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data))[..40];

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "EggMail.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("EggMail.slnx not found above " + AppContext.BaseDirectory);
    }
}
