namespace Mta.RemoteMta.Tests.Harness;

/// <summary>Waiting for a condition by polling. The deadline is a hang guard (minutes on a loaded runner), never an assertion about how long something took.</summary>
public static class Wait
{
    public static readonly TimeSpan HangGuard = TimeSpan.FromSeconds(90);

    public static async Task UntilAsync(Func<bool> condition, string what, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? HangGuard);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("gave up waiting for " + what);
            }

            await Task.Delay(10).ConfigureAwait(false);
        }
    }

    public static async Task UntilAsync(Func<Task<bool>> condition, string what, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? HangGuard);
        while (!await condition().ConfigureAwait(false))
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("gave up waiting for " + what);
            }

            await Task.Delay(10).ConfigureAwait(false);
        }
    }
}
