namespace Mta.Fuzz;

/// <summary>
/// A target with a planted defect, registered only when <c>EGGMAIL_FUZZ_SELFTEST</c> is <c>crash</c> or <c>hang</c>. The fuzz workflow
/// has a <c>selftest</c> input that fuzzes it, to prove that a real finding fails the run, is uploaded as an artifact and is replayed
/// in the log (a pipeline that has never failed has not been shown to be able to).
/// </summary>
internal static class SelfTestTarget
{
    public static FuzzTarget? CreateIfRequested()
    {
        string? mode = Environment.GetEnvironmentVariable("EGGMAIL_FUZZ_SELFTEST");
        if (mode is not ("crash" or "hang"))
        {
            return null;
        }

        return new FuzzTarget("selftest", $"planted defect ({mode}) for testing the fuzz pipeline", input => Run(mode, input), [[0x41]]) { MeasureAllocation = false };
    }

    private static void Run(string mode, ReadOnlySpan<byte> input)
    {
        if (input.Length > 0 && input[0] == 0x42 && mode == "crash")
        {
            throw new FuzzFindingException("planted crash: input starts with 'B'");
        }

        if (input.Length > 0 && input[0] == 0x42 && mode == "hang")
        {
            Thread.Sleep(Timeout.Infinite);
        }
    }
}
