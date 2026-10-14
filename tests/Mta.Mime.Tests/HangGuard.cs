using Xunit.Sdk;

namespace Mta.Mime.Tests;

/// <summary>
/// Runs a piece of work on a dedicated thread and fails only if it does not finish within a limit that is far above any
/// plausible slowdown of a loaded machine. This replaces assertions such as "took less than 2 s": those measured the
/// load of the test host, not the code. The properties that matter ("not quadratic", "no unbounded allocation") are
/// asserted on the result and on allocated bytes (deterministic), never on elapsed time.
/// </summary>
internal static class HangGuard
{
    public static readonly TimeSpan Limit = TimeSpan.FromMinutes(2);

    public static void Run(Action work, string what = "the operation")
    {
        var task = Task.Factory.StartNew(work, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        if (!task.Wait(Limit))
        {
            throw new XunitException($"{what} did not finish within {Limit.TotalSeconds:F0} s (hang)");
        }

        task.GetAwaiter().GetResult();   // rethrows the original exception
    }

    public static T Run<T>(Func<T> work, string what = "the operation")
    {
        T result = default!;
        Run((Action)(() => { result = work(); }), what);   // the cast picks the Action overload (a plain lambda would bind to this method again)
        return result;
    }
}
