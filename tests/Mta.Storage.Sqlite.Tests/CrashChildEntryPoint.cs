namespace Mta.Storage.Sqlite.Tests;

/// <summary>
/// Entry point used only when the test assembly is started as a child process by the crash-recovery tests
/// (<c>dotnet Mta.Storage.Sqlite.Tests.dll --crash-writer ...</c> or <c>--crash-worker ...</c>). Under the test runner this method is not called.
/// </summary>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length > 0 && args[0] == CrashWriterChild.Argument)
        {
            return await CrashWriterChild.RunAsync(args);
        }

        if (args.Length > 0 && args[0] == CrashWorkerChild.Argument)
        {
            return await CrashWorkerChild.RunAsync(args);
        }

        Console.Error.WriteLine("This assembly contains tests; run it with 'dotnet test'.");
        return 2;
    }
}
