using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Mta.Host.Tests.Api;
using Mta.Observability;
using Mta.Storage.Sqlite;
using Mta.TestSupport;
using Xunit.Abstractions;

namespace Mta.Host.Tests.Leaks;

/// <summary>
/// Accelerated lifecycle, leaks: the HTTP API in-process (TestHost over a SQLite store) with the requests a dashboard and an integration make all
/// day: sending with a key, listing, looking up messages that do not exist, signing in and out, failing to sign in from a new address every time, and
/// scraping <c>/metrics</c>. The number of metric series in the scrape is judged too: an unbounded label (a message id, an address, a path) would
/// show up as series growing batch after batch.
/// </summary>
[Collection(LeakCollection.Name)]
public sealed class ApiLeakTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Leak_api_requests_sessions_failed_sign_ins_and_scrapes_do_not_grow()
    {
        await using ApiFixture fixture = await ApiFixture.StartAsync(new ApiFixtureOptions
        {
            Sqlite = true,
            ConfigureServices = s => s.AddMtaObservability(new ObservabilityOptions()),
        });
        ApiClient key = await fixture.KeyClientAsync(ApiFixture.TenantAId);

        async Task<string> ScrapeAsync()
        {
            ApiClient scraper = fixture.NewClient();
            scraper.RemoteIp = "127.0.0.1";
            Reply reply = await scraper.GetAsync("/metrics");
            Assert.Equal(HttpStatusCode.OK, reply.Status);
            return reply.Body;
        }

        long Series() => ScrapeAsync().GetAwaiter().GetResult().Split('\n').Count(l => l.Length > 0 && l[0] != '#');

        using var probe = new LeakProbe(output.WriteLine);
        probe.TrackArrayPoolBalance(ignoreRentalsFrom: ["Microsoft.EntityFrameworkCore", "Mta.Host.Tests.Api.Reply", "Mta.Host.Tests.Api.ApiClient"]);   // the test client parses every reply with a JsonDocument it never disposes; EF Core does not return its expression-state arrays
        probe.Track("series in the /metrics scrape", Series);
        probe.Track("prepared SQLite statements", () => PreparedCommand.LiveCount, absolute: 2);
        probe.Allow("threads", 12);
        int n = 0;
        LeakReport report = await probe.RunAsync(async _ =>
        {
            int i = Interlocked.Increment(ref n);

            Reply sent = await key.PostAsync("/api/v1/messages", new Dictionary<string, object?>
            {
                ["from"] = "Acme <noreply@example.com>",
                ["to"] = new[] { $"user{i}@domain{i}.test" },
                ["subject"] = "Leak check " + i,
                ["text"] = "plain body",
            });
            Assert.Equal(HttpStatusCode.Accepted, sent.Status);
            Assert.Equal(HttpStatusCode.OK, (await key.GetAsync("/api/v1/messages?limit=5")).Status);
            Reply missing = await key.GetAsync("/api/v1/messages/" + Guid.NewGuid().ToString("N"));
            Assert.True(missing.Status == HttpStatusCode.NotFound, missing.Body);
            Assert.Equal(HttpStatusCode.OK, (await key.GetAsync("/api/v1/stats/recent-events?limit=10")).Status);

            // A dashboard session and a password guesser from a new address with a new name, every 25th round (verifying a password costs the full 600,000 PBKDF2 iterations,
            // about 150 ms, which is the point of it and not what is measured here); the throttle keeps a bounded number of keys.
            if (i % 25 == 0)
            {
                ApiClient browser = await fixture.SignedInAsync("alice");
                Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/v1/me")).Status);
                Assert.Equal(HttpStatusCode.NoContent, (await browser.DeleteAsync("/api/v1/session")).Status);

                ApiClient guesser = fixture.NewClient();
                guesser.RemoteIp = $"198.51.{i % 250}.{i / 250 % 250 + 1}";
                Assert.Equal(HttpStatusCode.Unauthorized, (await guesser.PostAsync("/api/v1/session", new { user = "ghost" + i, password = "nope" })).Status);
            }

            fixture.Clock.Advance(TimeSpan.FromMinutes(1));
        }, Accelerated.Scaled(40));
        report.AssertNoGrowth();
    }
}
