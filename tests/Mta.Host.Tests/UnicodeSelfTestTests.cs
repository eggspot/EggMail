using System.Diagnostics;
using Microsoft.Extensions.Configuration;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Hosting;

namespace Mta.Host.Tests;

public class UnicodeSelfTestTests
{
    private sealed class RecordingLog : IMtaLog
    {
        public List<(MtaLogLevel Level, string Message)> Entries { get; } = [];

        public bool IsEnabled(MtaLogLevel level) => true;

        public void Write(MtaLogLevel level, string source, string message, Exception? exception = null) => Entries.Add((level, message));
    }

    [Fact]
    public void On_a_normal_runtime_the_probes_agree_and_in_invariant_mode_they_do_not()
    {
        UnicodeSelfTestResult result = UnicodeSelfTest.Run();
        // With ICU every probe is right; in invariant mode the runtime silently gives other answers (that is what the test exists to catch).
        Assert.True(result.Passed != result.InvariantMode, result.Describe());
    }

    [Fact]
    public void Wrong_answers_are_reported_with_what_was_expected_and_what_to_do()
    {
        // What an invariant-mode runtime does: no case mapping, no normalization.
        UnicodeSelfTestResult result = UnicodeSelfTest.Run(toAscii: text => text, toUnicode: text => text, normalizeNfc: text => text);

        Assert.False(result.Passed);
        Assert.Contains(result.Failures, f => f.Contains("decomposed", StringComparison.Ordinal) && f.Contains("xn--bcher-kva.example", StringComparison.Ordinal));
        Assert.Contains(result.Failures, f => f.Contains("NFC", StringComparison.Ordinal));
        string message = result.Describe();
        Assert.Contains("Unicode self-test failed", message, StringComparison.Ordinal);
        Assert.Contains("libicu", message, StringComparison.Ordinal);
        Assert.Contains("Startup:RequireUnicodeSupport", message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_probe_that_throws_is_a_failure_not_a_crash()
    {
        UnicodeSelfTestResult result = UnicodeSelfTest.Run(
            toAscii: _ => throw new PlatformNotSupportedException("no idn"),
            toUnicode: text => text,
            normalizeNfc: _ => throw new PlatformNotSupportedException("no normalization"));

        Assert.False(result.Passed);
        Assert.Contains(result.Failures, f => f.Contains("PlatformNotSupportedException", StringComparison.Ordinal));
    }

    [Fact]
    public void Startup_is_refused_when_the_test_fails_unless_the_operator_opted_out()
    {
        UnicodeSelfTestResult failing = UnicodeSelfTest.Run(text => text, text => text, text => text);
        var log = new RecordingLog();
        var error = new StringWriter();

        Assert.False(UnicodeSelfTest.Enforce(required: true, log, error, () => failing));
        Assert.Contains("Unicode self-test failed", error.ToString(), StringComparison.Ordinal);
        Assert.Contains(log.Entries, e => e.Level == MtaLogLevel.Error);

        var optOutLog = new RecordingLog();
        var optOutError = new StringWriter();
        Assert.True(UnicodeSelfTest.Enforce(required: false, optOutLog, optOutError, () => failing));
        Assert.StartsWith("warning: Unicode self-test failed", optOutError.ToString(), StringComparison.Ordinal);   // still said out loud on the console
        Assert.Contains(optOutLog.Entries, e => e.Level == MtaLogLevel.Warning && e.Message.Contains("failed", StringComparison.Ordinal));
    }

    [Fact]
    public void Startup_proceeds_when_the_test_passes()
    {
        var log = new RecordingLog();
        var error = new StringWriter();

        Assert.True(UnicodeSelfTest.Enforce(required: true, log, error, () => new UnicodeSelfTestResult([], InvariantMode: false)));

        Assert.Equal(string.Empty, error.ToString());
        Assert.DoesNotContain(log.Entries, e => e.Level is MtaLogLevel.Error or MtaLogLevel.Warning);
    }

    [Fact]
    public void The_requirement_is_on_by_default_and_can_be_switched_off_in_configuration()
    {
        Assert.True(ConfigLoader.Load(new ConfigurationBuilder().Build()).Config.Startup.RequireUnicodeSupport);
        var off = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Startup:RequireUnicodeSupport"] = "false" }).Build();
        Assert.False(ConfigLoader.Load(off).Config.Startup.RequireUnicodeSupport);
    }

    // The real process, in invariant globalization mode: it must refuse to run and say why.

    private static readonly Dictionary<string, string> Invariant = new() { ["DOTNET_SYSTEM_GLOBALIZATION_INVARIANT"] = "1" };

    private static (int ExitCode, string Output, string Error) RunMta(Dictionary<string, string> environment, params string[] args)
    {
        string mta = Path.Combine(AppContext.BaseDirectory, "mta.dll");
        string dotnet = Environment.ProcessPath is { } p && Path.GetFileNameWithoutExtension(p) == "dotnet" ? p : "dotnet";
        var info = new ProcessStartInfo(dotnet) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        info.ArgumentList.Add(mta);
        foreach (string a in args)
        {
            info.ArgumentList.Add(a);
        }

        foreach (var (key, value) in environment)
        {
            info.Environment[key] = value;
        }

        using Process process = Process.Start(info)!;
        Task<string> output = process.StandardOutput.ReadToEndAsync();
        Task<string> error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(TimeSpan.FromSeconds(120)))
        {
            process.Kill(entireProcessTree: true);   // never leave a server that started after all running behind the test run
            process.WaitForExit();
            Assert.Fail($"mta {string.Join(' ', args)} did not exit within 120 s (it should have been refused at start). Output: {output.Result} {error.Result}");
        }

        return (process.ExitCode, output.Result, error.Result);
    }

    /// <summary>
    /// The refusal can only be observed where the runtime really gives wrong answers in invariant mode (true for .NET 10 today). If a future runtime passes
    /// every probe there, the process tests have nothing to refuse, so they return without asserting (xUnit 2 cannot report a skip from inside a test).
    /// </summary>
    private static bool InvariantModeStillFails()
    {
        var (exit, _, _) = RunMta(Invariant, "self-test");
        return exit == UnicodeSelfTest.FailedExitCode;
    }

    [Fact]
    public void The_self_test_command_fails_in_invariant_mode_and_passes_with_ICU()
    {
        var (badExit, _, badError) = RunMta(Invariant, "self-test");
        if (badExit == 0)
        {
            return;   // see InvariantModeStillFails
        }

        Assert.Equal(UnicodeSelfTest.FailedExitCode, badExit);
        Assert.Contains("Unicode self-test failed", badError, StringComparison.Ordinal);
        Assert.Contains("invariant globalization mode", badError, StringComparison.Ordinal);

        var (goodExit, goodOutput, _) = RunMta(new Dictionary<string, string> { ["DOTNET_SYSTEM_GLOBALIZATION_INVARIANT"] = "0" }, "self-test");
        Assert.Equal(0, goodExit);
        Assert.Contains("Unicode self-test passed", goodOutput, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_command_that_handles_mail_or_accounts_refuses_to_run_in_invariant_mode_before_it_touches_any_storage()
    {
        if (!InvariantModeStillFails())
        {
            return;
        }

        string data = Directory.CreateTempSubdirectory("eggmail-unicode-").FullName;
        try
        {
            foreach (string[] command in new[]
            {
                new[] { "serve" },
                new[] { "migrate-db" },
                new[] { "migrate-storage", "preflight", "--to", "postgres" },
                new[] { "admin", "create", "--user", "root" },
                new[] { "secrets", "rewrap" },
            })
            {
                var (exit, _, error) = RunMta(Invariant, [.. command, $"--Sqlite:DataDirectory={data}"]);

                Assert.True(exit == UnicodeSelfTest.FailedExitCode, $"{string.Join(' ', command)} exited {exit}: {error}");
                Assert.Contains("Unicode self-test failed", error, StringComparison.Ordinal);
                Assert.Empty(Directory.GetFileSystemEntries(data));
            }
        }
        finally
        {
            Directory.Delete(data, recursive: true);
        }
    }

    [Fact]
    public void Version_and_the_health_check_do_not_need_Unicode_and_the_opt_out_lets_serve_past_the_check()
    {
        if (!InvariantModeStillFails())
        {
            return;
        }

        var (versionExit, versionOutput, _) = RunMta(Invariant, "--version");
        Assert.Equal(0, versionExit);
        Assert.NotEmpty(versionOutput.Trim());

        // --healthcheck only asks the local port, which nobody serves here: it fails with 1 (unhealthy), not with 71.
        var (healthExit, _, _) = RunMta(Invariant, "--healthcheck", "--Dashboard:HttpPort=1");
        Assert.Equal(1, healthExit);
    }
}
