using System.Globalization;
using System.Text;
using Mta.Core;

namespace Mta.Host.Hosting;

/// <summary>What the Unicode self-test found.</summary>
/// <param name="Failures">One line per probe that gave a wrong answer; empty when everything is right.</param>
/// <param name="InvariantMode">The process was asked to run in invariant globalization mode (<c>DOTNET_SYSTEM_GLOBALIZATION_INVARIANT</c> or the runtime setting).</param>
public sealed record UnicodeSelfTestResult(IReadOnlyList<string> Failures, bool InvariantMode)
{
    public bool Passed => Failures.Count == 0;

    /// <summary>The message for the log and the console; says what is wrong and what to do about it.</summary>
    public string Describe()
    {
        if (Passed)
        {
            return InvariantMode
                ? "Unicode self-test passed, but the process runs in invariant globalization mode; a different runtime build may not give the same answers."
                : "Unicode self-test passed (internationalized domain names and normalization work).";
        }

        return "Unicode self-test failed: " + string.Join("; ", Failures) + ". "
            + (InvariantMode ? "The process runs in invariant globalization mode (DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 or InvariantGlobalization=true). " : "The ICU library may be missing. ")
            + "Internationalized domain names and Unicode normalization would give wrong results without any error. "
            + "Use the EggMail image (it ships ICU), or install libicu and unset the invariant switch. "
            + "To start anyway (not recommended), set Startup:RequireUnicodeSupport=false.";
    }
}

/// <summary>
/// Startup self-test for Unicode support (design section 10, plan risk 5). In invariant globalization mode (a common container default, or a missing ICU library)
/// <see cref="IdnMapping"/> and <see cref="string.Normalize()"/> silently give wrong answers for anything outside ASCII: a decomposed or upper case IDN would be
/// turned into the wrong A-label, and a sender domain would not match the one that was registered. The test checks the answers the mail pipeline depends on.
/// </summary>
public static class UnicodeSelfTest
{
    /// <summary>Process exit code of <c>mta serve</c> and <c>mta self-test</c> when the test fails (<c>EX_OSERR</c>: the environment is unfit).</summary>
    public const int FailedExitCode = 71;

    public static UnicodeSelfTestResult Run() => Run(
        text => new IdnMapping { UseStd3AsciiRules = false, AllowUnassigned = false }.GetAscii(text),
        text => new IdnMapping { UseStd3AsciiRules = false, AllowUnassigned = false }.GetUnicode(text),
        text => text.Normalize(NormalizationForm.FormC));

    /// <summary>The probes with replaceable implementations, so the failure path can be tested without a process in invariant mode.</summary>
    public static UnicodeSelfTestResult Run(Func<string, string> toAscii, Func<string, string> toUnicode, Func<string, string> normalizeNfc)
    {
        var failures = new List<string>();
        Probe(failures, "IDN A-label of a precomposed name", () => toAscii("bücher.example"), "xn--bcher-kva.example");
        Probe(failures, "IDN A-label of an upper case name", () => toAscii("BÜCHER.example"), "xn--bcher-kva.example");
        Probe(failures, "IDN A-label of a decomposed name", () => toAscii("bücher.example"), "xn--bcher-kva.example");
        Probe(failures, "IDN U-label of an A-label", () => toUnicode("xn--bcher-kva.example"), "bücher.example");
        Probe(failures, "IDN A-label of a CJK name", () => toAscii("日本語.jp"), "xn--wgv71a119e.jp");
        Probe(failures, "NFC normalization of e + combining acute", () => normalizeNfc("é"), "é");
        return new UnicodeSelfTestResult(failures, InvariantModeRequested());
    }

    /// <summary>Runs the test at startup. Returns false (after writing the reason) when the process must not start.</summary>
    public static bool Enforce(bool required, IMtaLog log, TextWriter error, Func<UnicodeSelfTestResult>? run = null)
    {
        UnicodeSelfTestResult result = run is null ? Run() : run();
        if (result.Passed)
        {
            log.Write(result.InvariantMode ? MtaLogLevel.Warning : MtaLogLevel.Information, "startup", result.Describe());
            return true;
        }

        if (!required)
        {
            log.Write(MtaLogLevel.Warning, "startup", result.Describe());
            return true;
        }

        error.WriteLine(result.Describe());
        log.Write(MtaLogLevel.Error, "startup", result.Describe());
        return false;
    }

    private static void Probe(List<string> failures, string what, Func<string> actual, string expected)
    {
        try
        {
            string got = actual();
            if (!string.Equals(got, expected, StringComparison.Ordinal))
            {
                failures.Add($"{what}: expected '{Printable(expected)}' but got '{Printable(got)}'");
            }
        }
        catch (Exception ex) when (ex is ArgumentException or PlatformNotSupportedException or InvalidOperationException)
        {
            failures.Add($"{what}: {ex.GetType().Name} ({ex.Message})");
        }
    }

    private static string Printable(string text) => string.Concat(text.Select(c => c < 0x7F && c >= 0x20 ? c.ToString() : $"\\u{(int)c:x4}"));

    private static bool InvariantModeRequested()
    {
        if (AppContext.TryGetSwitch("System.Globalization.Invariant", out bool configured) && configured)
        {
            return true;
        }

        string? environment = Environment.GetEnvironmentVariable("DOTNET_SYSTEM_GLOBALIZATION_INVARIANT");
        return string.Equals(environment, "1", StringComparison.Ordinal) || string.Equals(environment, "true", StringComparison.OrdinalIgnoreCase);
    }
}
