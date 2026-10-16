using Mta.Storage.Postgres.Tests;

namespace Mta.TestSupport;

/// <summary>
/// When a test that needs a PostgreSQL server may be skipped. The server is "promised" under CI (<c>CI</c> is set) or with <c>EGGMAIL_TEST_POSTGRES</c> set: then a missing
/// server is a failure, never a skip, so a broken CI service cannot turn the proof into a pass. Otherwise (a laptop without PostgreSQL binaries) the test is skipped.
/// The file is linked into each test project that uses it, next to <c>PostgresTestServer.cs</c>.
/// </summary>
public static class PostgresPromise
{
    public static bool ServerPromised =>
        !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CI")) || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("EGGMAIL_TEST_POSTGRES"));

    /// <summary>
    /// For test code that cannot be skipped by an attribute (a scenario shared by SQLite and PostgreSQL in one base class): true when the server is there, false when the
    /// scenario has nothing to run on (the test then returns and is reported as passed: xUnit 2 cannot report a skip from inside a test), and throws when the server was promised.
    /// </summary>
    public static bool Available()
    {
        string? reason = PostgresTestServer.UnavailableReason;
        if (reason is null)
        {
            return true;
        }

        if (ServerPromised)
        {
            throw new InvalidOperationException("A PostgreSQL server is promised here (CI or EGGMAIL_TEST_POSTGRES is set) but is not available: " + reason);
        }

        return false;
    }
}

/// <summary>A <c>[Fact]</c> that needs a PostgreSQL server: reported as skipped when there is none and none is promised (see <see cref="PostgresPromise"/>).</summary>
public sealed class PostgresFactAttribute : FactAttribute
{
    public override string Skip
    {
        get => base.Skip ?? (PostgresPromise.ServerPromised ? null : PostgresTestServer.UnavailableReason)!;
        set => base.Skip = value;
    }
}
