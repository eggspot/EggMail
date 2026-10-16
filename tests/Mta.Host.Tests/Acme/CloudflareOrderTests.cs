using Mta.Host.Tests.Api;
using Mta.Host.Tls;

namespace Mta.Host.Tests.Acme;

/// <summary>
/// The whole DNS-01 path offline: the real <see cref="CertesOrderRunner"/> orders from the mock CA, publishes through the real
/// <see cref="CloudflareDnsChallengeProvider"/> into the fake Cloudflare, and the mock CA validates by looking at what the fake Cloudflare would answer to a resolver
/// once the propagation lag has passed on a clock the runner's waits advance. This is where <c>Acme:PropagationDelay</c> shows its worth, and where the cleanup of the
/// records is observed from the Cloudflare side.
/// </summary>
public class CloudflareOrderTests : IDisposable
{
    private const string Zone = "example.com";
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 10, 15, 8, 0, 0, TimeSpan.Zero));
    private readonly FakeCloudflare _cf;
    private readonly MockAcmeServer _ca;
    private readonly HttpListLog _log = new();
    private readonly List<TimeSpan> _providerPauses = [];

    public CloudflareOrderTests()
    {
        _cf = new FakeCloudflare(() => _clock.UtcNow);
        _ca = new MockAcmeServer(() => _clock.UtcNow);
        _cf.AddZone(Zone);
        _ca.Validator = challenge =>
        {
            string name = "_acme-challenge." + challenge.Identifier;
            var seen = _cf.ResolveTxt(name);
            return seen.Contains(challenge.DnsTxtValue)
                ? ChallengeVerdict.Valid
                : ChallengeVerdict.Invalid("dns", seen.Count == 0 ? $"No TXT record found at {name}" : $"Incorrect TXT record \"{seen[0]}\" found at {name}");
        };
    }

    public void Dispose() => _ca.Dispose();

    private CloudflareDnsChallengeProvider Provider(HttpMessageHandler? handler = null) => new(new HttpClient(handler ?? _cf), FakeCloudflare.ValidToken, pause: (delay, _) =>
    {
        _providerPauses.Add(delay);
        _clock.Advance(delay);
        return Task.CompletedTask;
    });

    /// <summary>A runner whose waits move the shared clock, so a propagation delay really lets the lag pass.</summary>
    private CertesOrderRunner Runner() => new(_ca, _log, (delay, _) =>
    {
        _clock.Advance(delay);
        return Task.CompletedTask;
    });

    private AcmeOrderRequest Order(string[] names, TimeSpan propagation, string? accountKey = null) =>
        new(MockAcmeServer.DirectoryUrl, "ops@example.com", names, accountKey, propagation, null, null, AcmeChallengeType.Dns01, null);

    [Fact]
    public async Task A_certificate_is_issued_through_Cloudflare_and_the_records_are_gone_afterwards()
    {
        var issued = await Runner().IssueAsync(Order(["mx.example.com"], TimeSpan.Zero), Provider(), default);

        Assert.NotNull(issued);
        Assert.Empty(_cf.RecordsIn(Zone));
        Assert.Equal(1, _cf.Count("records.create"));
        Assert.Equal(1, _cf.Count("records.delete"));
        Assert.All(_cf.Requests, r => Assert.Equal("Bearer " + FakeCloudflare.ValidToken, r.Authorization));
    }

    [Fact]
    public async Task A_wildcard_and_its_base_name_put_two_values_at_one_name_and_both_validate_and_are_removed()
    {
        var issued = await Runner().IssueAsync(Order(["example.com", "*.example.com"], TimeSpan.Zero), Provider(), default);

        Assert.NotNull(issued);
        var created = _cf.Requests.Where(r => r.Route == "records.create").Select(r => (r.Body!["name"]!.GetValue<string>(), r.Body["content"]!.GetValue<string>())).ToList();
        Assert.Equal(2, created.Count);
        Assert.Single(created.Select(c => c.Item1).Distinct());
        Assert.Equal(2, created.Select(c => c.Item2).Distinct().Count());
        Assert.Empty(_cf.RecordsIn(Zone));
        Assert.Equal(2, _cf.Count("records.delete"));
    }

    [Fact]
    public async Task A_subdomain_zone_receives_the_records_of_names_below_it()
    {
        _cf.AddZone("sub.example.com");

        await Runner().IssueAsync(Order(["mx.sub.example.com"], TimeSpan.Zero), Provider(), default);

        Assert.Equal(1, _cf.Count("records.create"));
        Assert.Equal(_cf.ZoneId("sub.example.com"), _cf.Requests.Single(r => r.Route == "records.create").PathAndQuery.Split('/')[4]);
        Assert.Empty(_cf.RecordsIn("sub.example.com"));
    }

    [Fact]
    public async Task Without_a_propagation_delay_a_slow_resolver_view_fails_the_order_and_with_enough_delay_it_passes()
    {
        _cf.PropagationLag = TimeSpan.FromSeconds(30);

        var tooEarly = await Assert.ThrowsAsync<AcmeException>(() => Runner().IssueAsync(Order(["mx.example.com"], TimeSpan.Zero), Provider(), default));
        Assert.Contains("No TXT record found at _acme-challenge.mx.example.com", tooEarly.Message);
        Assert.Empty(_cf.RecordsIn(Zone)); // cleaned up even though the order failed
        Assert.Equal("the CA could not validate the challenge", AcmeFailureCategory.Describe(tooEarly.Message));

        var issued = await Runner().IssueAsync(Order(["mx.example.com"], TimeSpan.FromSeconds(30)), Provider(), default);
        Assert.NotNull(issued);
        Assert.Empty(_cf.RecordsIn(Zone));
    }

    [Fact]
    public async Task The_delay_one_second_short_of_the_lag_is_still_too_early()
    {
        _cf.PropagationLag = TimeSpan.FromSeconds(30);

        await Assert.ThrowsAsync<AcmeException>(() => Runner().IssueAsync(Order(["mx.example.com"], TimeSpan.FromSeconds(29)), Provider(), default));
    }

    [Fact]
    public async Task When_Cloudflare_refuses_the_second_record_the_first_is_removed_and_the_CA_is_never_asked_to_validate()
    {
        _cf.FailNth("records.create", 2, 403, 10000, "Authentication error");

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Runner().IssueAsync(Order(["example.com", "*.example.com"], TimeSpan.Zero), Provider(), default));

        Assert.Contains("10000: Authentication error", ex.Message);
        Assert.Empty(_cf.RecordsIn(Zone));
        Assert.Equal(0, _ca.Count("finalize"));
    }

    [Fact]
    public async Task A_delete_that_is_rate_limited_once_is_retried_and_leaves_nothing_behind()
    {
        _cf.Fail("records.delete", 429, 971, "Rate limited", retryAfterSeconds: 1);

        var issued = await Runner().IssueAsync(Order(["mx.example.com"], TimeSpan.Zero), Provider(), default);

        Assert.NotNull(issued);
        Assert.Empty(_cf.RecordsIn(Zone));
        Assert.Equal([TimeSpan.FromSeconds(1)], _providerPauses);
    }

    [Fact]
    public async Task A_delete_that_fails_for_good_leaves_a_record_but_keeps_the_certificate_and_the_log_names_it()
    {
        _cf.Fail("records.delete", 403, 10000, "Authentication error", times: 5);

        var issued = await Runner().IssueAsync(Order(["mx.example.com"], TimeSpan.Zero), Provider(), default);

        Assert.NotNull(issued);
        var leftover = Assert.Single(_cf.RecordsIn(Zone));
        Assert.Contains(_log.Lines, l => l.StartsWith("Warning acme: the DNS-01 TXT record '", StringComparison.Ordinal) && l.Contains(leftover.Id, StringComparison.Ordinal) && l.Contains("HTTP 403", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_record_somebody_else_left_at_the_challenge_name_stays_and_does_not_disturb_the_order()
    {
        string stranger = _cf.AddRecord(Zone, "TXT", "_acme-challenge.mx.example.com", "left-by-another-tool");

        var issued = await Runner().IssueAsync(Order(["mx.example.com"], TimeSpan.Zero), Provider(), default);

        Assert.NotNull(issued);
        Assert.Equal(stranger, Assert.Single(_cf.RecordsIn(Zone)).Id); // only this order's own record was removed
    }

    [Fact]
    public async Task The_token_appears_nowhere_in_what_an_order_logs_or_throws()
    {
        _cf.Fail("zones", 403, 9109, "Invalid access token");

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Runner().IssueAsync(Order(["mx.example.com"], TimeSpan.Zero), Provider(), default));

        Assert.DoesNotContain(FakeCloudflare.ValidToken, ex.Message);
        Assert.DoesNotContain(FakeCloudflare.ValidToken, ex.ToString());
        Assert.All(_log.Lines, l => Assert.DoesNotContain(FakeCloudflare.ValidToken, l));
        Assert.Equal(0, _cf.RecordCount);
    }

    [Fact]
    public async Task A_dead_Cloudflare_is_a_transient_failure_of_the_order_with_no_leftovers_at_the_CA()
    {
        _cf.Throw("*", new HttpRequestException("Connection refused (api.cloudflare.com:443)"), times: 3);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Runner().IssueAsync(Order(["mx.example.com"], TimeSpan.Zero), Provider(), default));

        Assert.True(ex.Transient);
        Assert.Contains("Cloudflare", ex.Message);
        Assert.Equal(0, _ca.Count("finalize"));
    }
}
