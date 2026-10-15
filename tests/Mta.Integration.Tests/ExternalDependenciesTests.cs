using Mta.Integration.Tests.Acme;
using Mta.Storage.Postgres.Tests;

namespace Mta.Integration.Tests;

/// <summary>
/// Runs only when <c>EGGMAIL_REQUIRE_EXTERNAL_TESTS=1</c> (CI sets it); otherwise it is reported as skipped, with the reason.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class RequiredExternalServicesFactAttribute : FactAttribute
{
    public override string Skip
    {
        get => base.Skip ?? (Environment.GetEnvironmentVariable(ExternalDependenciesTests.RequireVariable) == "1" ? null : $"{ExternalDependenciesTests.RequireVariable}=1 is not set: a local run may lack PostgreSQL and Pebble")!;
        set => base.Skip = value;
    }
}

/// <summary>
/// The PostgreSQL and ACME tests are reported as skipped, not failed, when their server is not there, so that <c>dotnet test</c> works on a
/// laptop with nothing installed. In CI that is a trap: a service container that failed to start would turn hundreds of tests into
/// silent skips and the run would still be green. CI sets <c>EGGMAIL_REQUIRE_EXTERNAL_TESTS=1</c>, and then this test fails when a server is missing.
/// </summary>
public class ExternalDependenciesTests
{
    public const string RequireVariable = "EGGMAIL_REQUIRE_EXTERNAL_TESTS";

    [RequiredExternalServicesFact]
    public void When_required_the_postgres_server_and_the_acme_test_ca_are_configured_so_their_tests_do_not_skip()
    {
        Assert.True(PostgresTestServer.UnavailableReason is null, "PostgreSQL tests would be skipped: " + PostgresTestServer.UnavailableReason);
        Assert.True(Pebble.UnavailableReason is null, "ACME tests would be skipped: " + Pebble.UnavailableReason);
    }
}
