using System.Net;
using System.Text;
using Mta.Core;
using Mta.Host.Tls;

namespace Mta.Host.Tests.Acme;

/// <summary>
/// <see cref="CertesOrderRunner"/> against the scriptable <see cref="MockAcmeServer"/>: the failures of a CA that Pebble cannot be told to produce (rate limits,
/// bad nonces in storms, server errors, damaged answers, expired and invalid orders, failed and never-ending validations, slow finalization, wrong chains,
/// accounts that went away). Everything is deterministic: the runner's waits are recorded, never slept.
/// </summary>
public class AcmeRunnerMockCaTests
{
    // ---------------------------------------------------------------------------------------------------------------------------------
    // Refusals, rate limits, server errors

    [Fact]
    public async Task A_rate_limited_order_is_one_refusal_carrying_the_CAs_retry_after_and_nothing_is_hammered()
    {
        using var rig = new AcmeRig();
        rig.Ca.Fail("newOrder", 429, "rateLimited", "too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s", retryAfterSeconds: 5 * 3600);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.StartsWith("ACME server error: too many certificates (5)", ex.Message);
        Assert.EndsWith("(rateLimited)", ex.Message);
        Assert.False(ex.Transient);
        Assert.Equal(TimeSpan.FromHours(5), ex.RetryAfter);
        Assert.Equal(1, rig.Ca.Count("newOrder")); // asked once: the runner does not retry a rate limit by itself
        Assert.Empty(rig.Dns.Created);
    }

    [Fact]
    public async Task A_rate_limited_account_registration_keeps_no_account_and_is_asked_once()
    {
        using var rig = new AcmeRig();
        rig.Ca.Fail("newAccount", 429, "rateLimited", "too many registrations (10) from this IP address in the last 3h0m0s", retryAfterSeconds: 600);
        var saved = new List<AcmeAccountCreated>();

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.Runner.IssueAsync(rig.Order(accountCreated: (a, _) => { saved.Add(a); return Task.CompletedTask; }), rig.Dns, default));

        Assert.Equal(TimeSpan.FromMinutes(10), ex.RetryAfter);
        Assert.Empty(saved);
        Assert.Equal(0, rig.Ca.AccountCount);
        Assert.Equal(1, rig.Ca.Count("newAccount"));
    }

    [Theory]
    [InlineData("soon")]
    [InlineData("-5")]
    [InlineData("99999999999999")]
    [InlineData("Wed, 21 Oct 2099 07:28:00 GMT")]
    [InlineData("")]
    public async Task A_retry_after_nobody_can_use_is_no_retry_after_and_never_breaks_the_refusal(string retryAfter)
    {
        using var rig = new AcmeRig();
        rig.Ca.Fail("newOrder", 429, "rateLimited", "slow down", retryAfterRaw: retryAfter);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Contains("slow down", ex.Message);
        Assert.True(ex.RetryAfter is null or { Ticks: > 0 }, $"RetryAfter was {ex.RetryAfter}");
    }

    [Theory]
    [InlineData(500, "serverInternal", true)]
    [InlineData(503, "serverInternal", true)]
    [InlineData(400, "malformed", false)]
    [InlineData(403, "unauthorized", false)]
    [InlineData(400, "rejectedIdentifier", false)]
    public async Task Server_errors_are_transient_and_refusals_are_not(int status, string type, bool transient)
    {
        using var rig = new AcmeRig();
        rig.Ca.Fail("newOrder", status, type, "scripted");

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Equal(transient, ex.Transient);
        Assert.Contains("scripted", ex.Message);
        Assert.Contains($"({type})", ex.Message);
    }

    [Fact]
    public async Task A_server_error_at_finalize_removes_the_challenge_records_and_leaves_no_answer_behind()
    {
        using var rig = new AcmeRig();
        rig.Ca.Fail("finalize", 500, "serverInternal", "database is down");

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.True(ex.Transient);
        Assert.Equal(0, rig.Dns.LiveRecords);
        Assert.Single(rig.Dns.DeletedHandles);
    }

    [Fact]
    public async Task A_rejected_identifier_stops_before_any_challenge()
    {
        using var rig = new AcmeRig();
        rig.Ca.RejectedNames.Add("forbidden.mock.test");

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync(names: ["forbidden.mock.test"]));

        Assert.Contains("will not issue for \"forbidden.mock.test\"", ex.Message);
        Assert.Empty(rig.Dns.Created);
        Assert.Equal(0, rig.Ca.Count("challenge"));
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // Nonces

    [Fact]
    public async Task A_few_bad_nonces_are_absorbed_and_every_nonce_is_used_once()
    {
        using var rig = new AcmeRig();
        rig.Ca.RejectNonces(2);

        var issued = await rig.IssueAsync();

        Assert.NotNull(issued);
        Assert.Equal(2, rig.Ca.Requests.Count(r => r.Status == 400));
        Assert.All(rig.Ca.Requests.Where(r => r.Status == 400), r => Assert.Equal("newAccount", r.Endpoint)); // Certes signs again with the nonce the refusal brought
    }

    [Fact]
    public async Task More_bad_nonces_than_one_request_retries_repeat_the_whole_order_and_keep_the_account()
    {
        using var rig = new AcmeRig();
        rig.Ca.RejectNonces(5); // four refusals end the first attempt (one try and three retries); the fifth is absorbed by the second

        var issued = await rig.IssueAsync();

        Assert.NotNull(issued);
        Assert.Equal(1, rig.Ca.AccountCount);
        Assert.Equal(5, rig.Ca.Requests.Count(r => r.Status == 400));
    }

    [Fact]
    public async Task A_storm_of_bad_nonces_ends_after_a_bounded_number_of_requests_with_a_refusal_that_says_so()
    {
        using var rig = new AcmeRig();
        rig.Ca.RejectNonces(1000);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Contains("(badNonce)", ex.Message);
        Assert.Equal(8, rig.Ca.Count("newAccount")); // four attempts of two requests (Certes retries a registration once), then it gives up
        Assert.Equal(0, rig.Ca.AccountCount);
        Assert.Equal(0, rig.Ca.Count("newOrder"));
    }

    [Fact]
    public async Task A_bad_nonce_while_downloading_the_certificate_is_retried_with_a_fresh_one()
    {
        using var rig = new AcmeRig();
        rig.Ca.Fail("certificate", 400, "badNonce", "JWS has an invalid anti-replay nonce", times: 2);

        var issued = await rig.IssueAsync();

        Assert.NotNull(issued);
        Assert.Equal(3, rig.Ca.Count("certificate"));
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // Damaged and unexpected answers

    [Fact]
    public async Task A_directory_that_is_not_JSON_is_an_error_that_says_so_not_a_parser_message()
    {
        using var rig = new AcmeRig();
        rig.Ca.Override("directory", _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{not json", Encoding.UTF8, "application/json") }, times: 5);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Contains("cannot read", ex.Message);
        Assert.True(ex.Transient);
    }

    [Fact]
    public async Task A_captive_portal_or_proxy_page_instead_of_the_CA_is_an_error_not_a_crash()
    {
        using var rig = new AcmeRig();
        rig.Ca.Override("directory", _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html>please log in</html>", Encoding.UTF8, "text/html") }, times: 5);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.DoesNotContain("Object reference", ex.Message);
        Assert.True(ex.Transient);
    }

    [Fact]
    public async Task A_bad_gateway_page_at_new_order_is_an_error_naming_the_URL()
    {
        using var rig = new AcmeRig();
        rig.Ca.Override("newOrder", _ => new HttpResponseMessage(HttpStatusCode.BadGateway) { Content = new StringContent("<h1>502</h1>", Encoding.UTF8, "text/html") });

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.StartsWith("ACME error:", ex.Message);
        Assert.Contains("/new-order", ex.Message);
    }

    [Fact]
    public async Task A_truncated_order_answer_is_an_unreadable_answer()
    {
        using var rig = new AcmeRig();
        rig.Ca.Override("newOrder", _ => new HttpResponseMessage(HttpStatusCode.Created) { Content = new StringContent("{\"status\":\"pend", Encoding.UTF8, "application/json") });

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Contains("cannot read", ex.Message);
    }

    [Fact]
    public async Task A_directory_without_the_new_order_endpoint_is_an_error()
    {
        using var rig = new AcmeRig();
        rig.Ca.Override("directory", _ => MockAcmeServer.Json(HttpStatusCode.OK, new System.Text.Json.Nodes.JsonObject
        {
            ["newNonce"] = MockAcmeServer.Base + "/new-nonce",
            ["newAccount"] = MockAcmeServer.Base + "/new-account",
        }));

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.StartsWith("The CA's directory does not offer an endpoint this client needs", ex.Message);
    }

    [Fact]
    public async Task A_timeout_and_a_refused_connection_are_transient_failures_with_the_wording_the_banner_knows()
    {
        using var rig = new AcmeRig();
        rig.Ca.Throw("newOrder", new TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout", new TimeoutException()));
        var timeout = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());
        Assert.True(timeout.Transient);
        Assert.Equal("The ACME server did not answer in time.", timeout.Message);
        Assert.Equal("the CA could not be reached", AcmeFailureCategory.Describe(timeout.Message));

        rig.Ca.Throw("newOrder", new HttpRequestException("Connection refused (acme.mock.test:443)"));
        var refused = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());
        Assert.True(refused.Transient);
        Assert.Contains("could not be reached", refused.Message);
        Assert.Equal("the CA could not be reached", AcmeFailureCategory.Describe(refused.Message));
    }

    [Fact]
    public async Task A_timeout_in_the_middle_of_validation_still_removes_the_records()
    {
        using var rig = new AcmeRig();
        rig.Ca.Throw("authz", new TaskCanceledException("timeout", new TimeoutException()));

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.True(ex.Transient);
        Assert.Equal(0, rig.Dns.LiveRecords);
    }

    [Fact]
    public async Task Cancelling_the_order_is_a_cancellation_not_a_failure_and_still_cleans_up()
    {
        using var rig = new AcmeRig();
        using var cts = new CancellationTokenSource();
        rig.Ca.ValidationPolls = 3;
        rig.Ca.Validator = MockChallengeValidators.Dns(rig.Dns);
        var runner = new CertesOrderRunner(rig.Ca, rig.Log, (_, _) =>
        {
            cts.Cancel(); // shutdown arrives while the order waits for the CA
            cts.Token.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runner.IssueAsync(rig.Order(), rig.Dns, cts.Token));

        Assert.Equal(0, rig.Dns.LiveRecords);
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // Authorizations and challenges

    [Fact]
    public async Task A_failed_dns_challenge_carries_the_CAs_explanation_and_removes_the_record()
    {
        using var rig = new AcmeRig();
        rig.Ca.Validator = _ => ChallengeVerdict.Invalid("dns", "DNS problem: NXDOMAIN looking up TXT for _acme-challenge.mx.mock.test");

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.Runner.IssueAsync(rig.Order(), rig.Dns, default));

        Assert.Equal("Authorization for mx.mock.test ended as Invalid: DNS problem: NXDOMAIN looking up TXT for _acme-challenge.mx.mock.test", ex.Message);
        Assert.Equal("the CA could not validate the challenge", AcmeFailureCategory.Describe(ex.Message));
        Assert.Equal(0, rig.Dns.LiveRecords);
        Assert.Equal(0, rig.Ca.Count("finalize"));
    }

    [Fact]
    public async Task A_failed_http_challenge_names_port_80_and_removes_the_token()
    {
        using var rig = new AcmeRig();
        rig.Ca.Validator = _ => ChallengeVerdict.Invalid("connection", "Fetching http://mx.mock.test/.well-known/acme-challenge/x: Timeout during connect (likely firewall problem)");

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.Runner.IssueAsync(rig.Order(AcmeChallengeType.Http01), rig.Dns, default));

        Assert.Contains("Timeout during connect", ex.Message);
        Assert.Contains("port 80", ex.Message);
        Assert.Contains("Acme:Http01ListenPort", ex.Message);
        Assert.Equal(0, rig.Http.LiveAnswers);
        Assert.Single(rig.Http.Removed);
    }

    [Theory]
    [InlineData("expired")]
    [InlineData("deactivated")]
    [InlineData("revoked")]
    public async Task An_authorization_that_ends_in_another_failed_state_is_named(string status)
    {
        using var rig = new AcmeRig();
        rig.Ca.Validator = _ => ChallengeVerdict.EndsAs(status);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.Runner.IssueAsync(rig.Order(), rig.Dns, default));

        Assert.Contains($"ended as {char.ToUpperInvariant(status[0])}{status[1..]}", ex.Message);
        Assert.Equal(0, rig.Dns.LiveRecords);
    }

    [Fact]
    public async Task A_validation_that_never_finishes_gives_up_after_45_checks_in_about_two_minutes_and_cleans_up()
    {
        using var rig = new AcmeRig();
        rig.Ca.Validator = _ => ChallengeVerdict.PendingForever;

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.Runner.IssueAsync(rig.Order(), rig.Dns, default));

        Assert.Equal("Authorization for mx.mock.test is still Pending after 45 checks", ex.Message);
        Assert.Equal(45, rig.Pauses.Count);
        Assert.Equal([200, 400, 800, 1600, 3000, 3000], rig.Pauses.Take(6).Select(p => (int)p.TotalMilliseconds));
        Assert.Equal(TimeSpan.FromMilliseconds(3000 * 41 + 200 + 400 + 800 + 1600), TimeSpan.FromTicks(rig.Pauses.Sum(p => p.Ticks)));
        Assert.Equal(0, rig.Dns.LiveRecords);
        Assert.Equal(0, rig.Ca.Count("finalize"));
    }

    [Fact]
    public async Task A_slow_validation_is_waited_for_with_the_growing_pause()
    {
        using var rig = new AcmeRig();
        rig.Ca.ValidationPolls = 6;

        var issued = await rig.IssueAsync();

        Assert.NotNull(issued);
        Assert.Equal([200, 400, 800, 1600, 3000], rig.Pauses.Select(p => (int)p.TotalMilliseconds));
    }

    [Fact]
    public async Task The_propagation_delay_is_waited_once_after_the_records_exist_and_only_for_dns()
    {
        using var rig = new AcmeRig();
        rig.Ca.Validator = MockChallengeValidators.Dns(rig.Dns);

        await rig.Runner.IssueAsync(rig.Order(propagation: TimeSpan.FromMinutes(2)), rig.Dns, default);

        Assert.Equal([TimeSpan.FromMinutes(2)], rig.Pauses);

        rig.Pauses.Clear();
        rig.Ca.Validator = MockChallengeValidators.Http(rig.Http);
        await rig.Runner.IssueAsync(rig.Order(AcmeChallengeType.Http01, propagation: TimeSpan.FromMinutes(2)), rig.Dns, default);
        Assert.Empty(rig.Pauses); // the listener answers at once: no propagation
    }

    [Fact]
    public async Task Authorizations_the_CA_already_considers_valid_are_not_challenged_again()
    {
        using var rig = new AcmeRig();
        rig.Ca.ReuseValidAuthorizations = true;
        await rig.IssueAsync();
        int created = rig.Dns.Created.Count;
        int answers = rig.Ca.Count("challenge", "POST");

        await rig.IssueAsync();

        Assert.Equal(created, rig.Dns.Created.Count);
        Assert.Equal(answers, rig.Ca.Count("challenge", "POST"));
    }

    [Fact]
    public async Task When_the_second_record_cannot_be_created_the_first_is_removed()
    {
        using var rig = new AcmeRig();
        rig.Dns.FailCreate[2] = new AcmeException("Cloudflare: could not create TXT record (HTTP 500)");

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync(names: ["mock.test", "*.mock.test"]));

        Assert.Contains("Cloudflare", ex.Message);
        Assert.Single(rig.Dns.Created);
        Assert.Equal(0, rig.Dns.LiveRecords);
    }

    [Theory]
    [MemberData(nameof(DnsCleanupFailures))]
    public async Task A_DNS_provider_that_fails_to_delete_in_any_way_does_not_turn_an_issued_certificate_into_a_failure(Exception failure)
    {
        using var rig = new AcmeRig();
        rig.Dns.FailDelete = failure;

        var issued = await rig.IssueAsync();

        Assert.NotNull(issued);
        Assert.Contains(rig.Log.Lines, l => l.StartsWith("Warning acme: the DNS-01 TXT record 'rec-1' could not be removed", StringComparison.Ordinal));
    }

    public static TheoryData<Exception> DnsCleanupFailures() => new()
    {
        new TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout", new TimeoutException()),
        new System.Text.Json.JsonException("'<' is an invalid start of a value."),
        new InvalidOperationException("the provider is broken"),
        new HttpRequestException("Connection reset"),
        new AcmeException("Cloudflare: deleting the TXT record failed with HTTP 500"),
    };

    [Fact]
    public async Task A_leftover_TXT_record_is_named_in_the_log_so_it_can_be_removed_by_hand()
    {
        using var rig = new AcmeRig();
        rig.Dns.FailDelete = new HttpRequestException("Connection reset");

        await rig.IssueAsync();

        Assert.Contains(rig.Log.Lines, l => l.Contains("'rec-1'", StringComparison.Ordinal) && l.Contains("remove it by hand", StringComparison.Ordinal));
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // Orders: finalize, processing, invalid, expired

    [Fact]
    public async Task A_finalize_answered_with_processing_is_polled_until_valid_following_the_CAs_retry_after()
    {
        using var rig = new AcmeRig();
        rig.Ca.FinalizeProcessingPolls = 3;
        rig.Ca.ProcessingRetryAfterSeconds = 2;

        var issued = await rig.IssueAsync();

        Assert.NotNull(issued);
        Assert.Equal([TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2)], rig.Pauses);
    }

    [Fact]
    public async Task Without_a_retry_after_the_order_is_polled_with_the_usual_growing_pause()
    {
        using var rig = new AcmeRig();
        rig.Ca.FinalizeProcessingPolls = 3;

        await rig.IssueAsync();

        Assert.Equal([200, 400, 800], rig.Pauses.Select(p => (int)p.TotalMilliseconds));
    }

    [Fact]
    public async Task A_retry_after_of_a_quarter_of_an_hour_is_capped_at_ten_seconds_per_poll()
    {
        using var rig = new AcmeRig();
        rig.Ca.FinalizeProcessingPolls = 2;
        rig.Ca.ProcessingRetryAfterSeconds = 900;

        await rig.IssueAsync();

        Assert.Equal([TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10)], rig.Pauses);
    }

    [Fact]
    public async Task An_order_that_stays_processing_is_given_up_after_45_polls()
    {
        using var rig = new AcmeRig();
        rig.Ca.FinalizeProcessingPolls = int.MaxValue;
        rig.Ca.ProcessingRetryAfterSeconds = 1;

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Equal("The order is still Processing after it was finalized after 45 checks", ex.Message);
        Assert.Equal(45, rig.Pauses.Count);
        Assert.Equal(0, rig.Dns.LiveRecords);
    }

    [Fact]
    public async Task An_order_that_turns_invalid_after_finalize_says_why()
    {
        using var rig = new AcmeRig();
        rig.Ca.FinalizeProcessingPolls = 2;
        rig.Ca.FinalizeEndsInvalid = "Error finalizing order :: issuance failed: CAA record for mock.test prohibits issuance";

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Equal("The CA marked the order invalid after it was finalized: Error finalizing order :: issuance failed: CAA record for mock.test prohibits issuance", ex.Message);
        Assert.Equal(0, rig.Ca.Count("certificate"));
    }

    [Theory]
    [InlineData("invalid")]
    [InlineData("expired")]
    public async Task An_order_that_expired_or_was_invalidated_before_finalize_is_an_error_and_nothing_is_finalized(string status)
    {
        using var rig = new AcmeRig();
        rig.Ca.OrderTurnsInsteadOfReady = (status, "order expired while waiting");

        var ex = await Assert.ThrowsAnyAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Equal(0, rig.Ca.Count("finalize"));
        Assert.DoesNotContain("Object reference", ex.Message);
        Assert.Equal(0, rig.Dns.LiveRecords);
    }

    [Fact]
    public async Task A_finalize_refused_because_the_order_is_not_ready_is_the_CAs_refusal()
    {
        using var rig = new AcmeRig();
        rig.Ca.Fail("finalize", 403, "orderNotReady", "Order's status (\"pending\") is not acceptable for finalization");

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Contains("(orderNotReady)", ex.Message);
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // The certificate the CA sends

    [Fact]
    public async Task A_chain_in_the_wrong_order_is_stored_leaf_first_and_the_log_says_so()
    {
        using var rig = new AcmeRig();
        rig.Ca.CertificateMode = MockCertificateMode.WrongOrder;

        var issued = await rig.IssueAsync();

        var chain = Certificates(issued.ChainPem);
        Assert.Equal(2, chain.Count);
        Assert.Equal("CN=mx.mock.test", chain[0].Subject);
        Assert.Equal("CN=Mock Intermediate CA", chain[1].Subject);
        Assert.Contains(rig.Log.Lines, l => l.Contains("unusual order", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_correct_chain_is_stored_as_sent_and_nothing_is_logged()
    {
        using var rig = new AcmeRig();

        var issued = await rig.IssueAsync();

        Assert.Equal(["CN=mx.mock.test", "CN=Mock Intermediate CA"], Certificates(issued.ChainPem).Select(c => c.Subject));
        Assert.DoesNotContain(rig.Log.Lines, l => l.StartsWith("Warning", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_chain_without_the_intermediate_is_kept_with_a_warning_because_refusing_it_would_let_the_old_certificate_expire()
    {
        using var rig = new AcmeRig();
        rig.Ca.CertificateMode = MockCertificateMode.LeafOnly;

        var issued = await rig.IssueAsync();

        Assert.Single(Certificates(issued.ChainPem));
        Assert.Contains(rig.Log.Lines, l => l.StartsWith("Warning acme: the CA's chain does not contain the issuer", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_certificate_for_other_names_is_refused()
    {
        using var rig = new AcmeRig();
        rig.Ca.CertificateMode = MockCertificateMode.WrongNames;

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Equal("The CA issued a certificate that does not cover 'mx.mock.test' (it covers someone-else.mock.test).", ex.Message);
    }

    [Fact]
    public async Task A_wildcard_certificate_for_the_parent_covers_a_host_name_but_not_the_other_way_around()
    {
        Assert.True(AcmeNames.IsCovered(["*.mock.test"], "mx.mock.test"));
        Assert.True(AcmeNames.IsCovered(["*.mock.test"], "*.mock.test"));
        Assert.True(AcmeNames.IsCovered(["MX.mock.test."], "mx.MOCK.test"));
        Assert.False(AcmeNames.IsCovered(["*.mock.test"], "mock.test"));
        Assert.False(AcmeNames.IsCovered(["*.mock.test"], "a.b.mock.test"));
        Assert.False(AcmeNames.IsCovered(["mx.mock.test"], "*.mock.test"));
        Assert.False(AcmeNames.IsCovered([], "mx.mock.test"));
        await Task.CompletedTask;
    }

    [Fact]
    public async Task A_certificate_for_another_key_is_refused()
    {
        using var rig = new AcmeRig();
        rig.Ca.CertificateMode = MockCertificateMode.WrongKey;

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Contains("no certificate for the key of this order", ex.Message);
    }

    [Fact]
    public async Task A_chain_with_only_the_CAs_own_certificates_is_refused()
    {
        using var rig = new AcmeRig();
        rig.Ca.CertificateMode = MockCertificateMode.NoLeaf;

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Contains("no certificate for the key of this order", ex.Message);
    }

    [Theory]
    [InlineData(MockCertificateMode.Truncated, "damaged or cut off")]
    [InlineData(MockCertificateMode.Garbage, "no certificate")]
    [InlineData(MockCertificateMode.Empty, "no certificate")]
    public async Task A_truncated_garbled_or_empty_chain_is_an_error_naming_what_is_wrong(MockCertificateMode mode, string expected)
    {
        using var rig = new AcmeRig();
        rig.Ca.CertificateMode = mode;

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Contains(expected, ex.Message);
        Assert.DoesNotContain("Object reference", ex.Message);
        Assert.Equal(0, rig.Dns.LiveRecords);
    }

    [Fact]
    public async Task A_refused_download_is_the_CAs_refusal_not_a_null_reference()
    {
        using var rig = new AcmeRig();
        rig.Ca.Fail("certificate", 500, "serverInternal", "certificate storage is down");

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Equal("ACME server error: certificate storage is down (serverInternal)", ex.Message);
        Assert.True(ex.Transient);
    }

    [Fact]
    public async Task A_rate_limited_download_carries_the_retry_after()
    {
        using var rig = new AcmeRig();
        rig.Ca.Fail("certificate", 429, "rateLimited", "slow down", retryAfterSeconds: 120);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Equal(TimeSpan.FromMinutes(2), ex.RetryAfter);
    }

    [Fact]
    public async Task A_certificate_the_CA_sends_that_is_expired_already_is_refused_by_the_runners_clock()
    {
        using var rig = new AcmeRig();
        rig.Ca.CertificateMode = MockCertificateMode.AlreadyExpired;

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Contains("already expired", ex.Message);
    }

    private static List<System.Security.Cryptography.X509Certificates.X509Certificate2> Certificates(string pem)
    {
        var all = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection();
        all.ImportFromPem(pem);
        return [.. all];
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // Accounts

    [Fact]
    public async Task External_account_binding_required_without_a_configured_binding_sends_nothing()
    {
        using var rig = new AcmeRig();
        rig.Ca.ExternalAccountRequired = true;

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Contains("Acme:EabKeyId", ex.Message);
        Assert.Equal(0, rig.Ca.Count("newAccount"));
        Assert.Equal("the CA needs or refused external account binding", AcmeFailureCategory.Describe(ex.Message));
    }

    [Fact]
    public async Task A_wrong_binding_is_a_refusal_and_no_account_is_kept()
    {
        using var rig = new AcmeRig();
        rig.Ca.ExternalAccountRequired = true;
        rig.Ca.EabKeys["kid-1"] = System.Buffers.Text.Base64Url.EncodeToString(new byte[16]);
        var saved = new List<AcmeAccountCreated>();

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.Runner.IssueAsync(
            rig.Order(eabKeyId: "kid-1", eabHmacKey: System.Buffers.Text.Base64Url.EncodeToString(new byte[] { 9, 9, 9, 9 }), accountCreated: (a, _) => { saved.Add(a); return Task.CompletedTask; }), rig.Dns, default));

        Assert.Contains("MAC does not verify", ex.Message);
        Assert.Empty(saved);
    }

    [Fact]
    public async Task An_account_the_CA_deactivated_is_a_clear_refusal_and_no_new_account_is_registered_behind_the_operators_back()
    {
        using var rig = new AcmeRig();
        await rig.IssueAsync();
        rig.Ca.DeactivateAccounts();

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.Contains("deactivated", ex.Message);
        Assert.Contains("(unauthorized)", ex.Message);
        Assert.Equal(1, rig.Ca.Count("newAccount", 201));
    }

    [Fact]
    public async Task An_account_key_the_CA_does_not_know_any_more_is_reported_as_an_unknown_account_without_registering_a_new_one_here()
    {
        using var rig = new AcmeRig();
        await rig.IssueAsync();
        rig.Ca.ForgetAccounts(); // a reset test CA, or a CA that lost its database

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.IssueAsync());

        Assert.True(ex.AccountUnknown);
        Assert.Equal(0, rig.Ca.AccountCount); // the service decides to register another (it owns the stored account and the binding)
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // Renewal information endpoint

    [Fact]
    public async Task A_directory_without_renewalInfo_is_never_asked_about_a_certificate_id()
    {
        using var rig = new AcmeRig();
        var issued = await rig.IssueAsync();

        var info = await rig.Runner.GetRenewalInfoAsync(MockAcmeServer.DirectoryUrl, issued.ChainPem, default);

        Assert.Null(info);
        Assert.Equal(0, rig.Ca.Count("renewalInfo"));
    }

    [Fact]
    public async Task A_rate_limited_renewal_information_request_carries_the_CAs_retry_after_and_a_server_error_is_transient()
    {
        using var rig = new AcmeRig();
        rig.Ca.AdvertiseRenewalInfo = true;
        var issued = await rig.IssueAsync();
        rig.Ca.Fail("renewalInfo", 429, "rateLimited", "too many renewal information requests", retryAfterSeconds: 1800);
        rig.Ca.Fail("renewalInfo", 503, "serverInternal", "maintenance");

        var limited = await Assert.ThrowsAsync<AcmeException>(() => rig.Runner.GetRenewalInfoAsync(MockAcmeServer.DirectoryUrl, issued.ChainPem, default));
        var down = await Assert.ThrowsAsync<AcmeException>(() => rig.Runner.GetRenewalInfoAsync(MockAcmeServer.DirectoryUrl, issued.ChainPem, default));

        Assert.Equal(TimeSpan.FromMinutes(30), limited.RetryAfter);
        Assert.False(limited.Transient);
        Assert.True(down.Transient);
        Assert.Null(down.RetryAfter);
    }
}
