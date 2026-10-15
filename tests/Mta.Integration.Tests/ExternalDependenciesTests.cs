using Mta.Integration.Tests.Acme;
using Mta.Storage.Postgres.Tests;

namespace Mta.Integration.Tests;

/// <summary>
/// The PostgreSQL and ACME tests are reported as skipped, not failed, when their server is not there, so that <c>dotnet test</c> works on a
/// laptop with nothing installed. In CI that is a trap: a service container that failed to start would turn hundreds of tests into
/// silent skips and the run would still be green. CI sets <c>EGGMAIL_REQUIRE_EXTERNAL_TESTS=1</c>, and then this test fails when a server is missing.
/// </summary>
public class ExternalDependenciesTests
{
    public const string RequireVariable = "EGGMAIL_REQUIRE_EXTERNAL_TESTS";

    [Fact]
    public void When_required_the_postgres_server_and_the_acme_test_ca_are_configured_so_their_tests_do_not_skip()
    {
        if (Environment.GetEnvironmentVariable(RequireVariable) != "1")
        {
            return;   // a local run may legitimately lack them: those tests are skipped there
        }

        Assert.True(PostgresTestServer.UnavailableReason is null, "PostgreSQL tests would be skipped: " + PostgresTestServer.UnavailableReason);
        Assert.True(Pebble.UnavailableReason is null, "ACME tests would be skipped: " + Pebble.UnavailableReason);
    }
}
