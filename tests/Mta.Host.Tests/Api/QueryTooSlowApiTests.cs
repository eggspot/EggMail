using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Mta.Host.Api;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

/// <summary>A read the database stopped at its statement timeout (the read-only role, design section 4.3) is its own answer, not "not ready" and not a server error.</summary>
[Collection("api")]
public class QueryTooSlowApiTests
{
    private sealed class TooSlow : IStorageSwitchService
    {
        private static StorageQueryTimeoutException Slow() => new("The read-only query ran past statement_timeout (select ... from db.internal)");

        public ValueTask<SwitchPreflightReport> PreflightAsync(SwitchRequestModel request, CancellationToken cancellationToken) => throw Slow();

        public ValueTask<SwitchStatusReport> StartAsync(SwitchStartModel request, CancellationToken cancellationToken) => throw Slow();

        public ValueTask<SwitchStatusReport> GetStatusAsync(CancellationToken cancellationToken) => throw Slow();

        public ValueTask<SwitchStatusReport> ConfirmAsync(CancellationToken cancellationToken) => throw Slow();

        public ValueTask<SwitchStatusReport> ActivateAsync(CancellationToken cancellationToken) => throw Slow();

        public ValueTask<SwitchStatusReport> RollbackAsync(CancellationToken cancellationToken) => throw Slow();

        public ValueTask<SwitchStatusReport> FinalizeAsync(CancellationToken cancellationToken) => throw Slow();
    }

    [Fact]
    public async Task A_query_that_ran_past_the_timeout_is_503_query_too_slow_with_advice_and_without_details()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureServices = s => s.AddSingleton<IStorageSwitchService>(new TooSlow()) });
        ApiClient admin = await f.SignedInAsync("root");

        Reply r = await admin.GetAsync("/api/v1/admin/storage/switch");

        r.Problem(HttpStatusCode.ServiceUnavailable, "query_too_slow");
        Assert.Contains("Narrow it", r.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("db.internal", r.Body, StringComparison.Ordinal);
        Assert.Null(r.Header("Retry-After"));   // the same query will not succeed by waiting
    }
}
